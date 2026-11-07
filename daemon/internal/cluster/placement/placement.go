// Package placement chooses a compute node for a cluster workload
// (docs/plans/cluster.md section 6.3). It is a pure function over the
// replicated state and the leader's live health: filter the nodes that can
// take the workload, then score them. The reasons a node was skipped come
// back for the UI.
package placement

import (
	"fmt"
	"slices"
	"sort"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

// Scheduler implements cluster.Scheduler.
type Scheduler struct {
	// ReservedMB is kept free on every node for the host itself (default
	// 2048).
	ReservedMB int
	// Requirements returns what other placed workloads need (memory and
	// CPUs committed on each node); nil counts nothing.
	Requirements func(w cluster.WorkloadRef) *cluster.Requirements
}

var _ cluster.Scheduler = (*Scheduler)(nil)

func (sc *Scheduler) reserved() int {
	if sc.ReservedMB > 0 {
		return sc.ReservedMB
	}
	return 2048
}

// Committed sums what the workloads placed (or being moved) on each node
// need. A workload moving or migrating counts on both nodes.
func (sc *Scheduler) Committed(s *cluster.Snapshot, skip cluster.WorkloadRef) map[cluster.NodeID]cluster.Requirements {
	out := map[cluster.NodeID]cluster.Requirements{}
	if sc.Requirements == nil {
		return out
	}
	for w, p := range s.Placements {
		if w == skip {
			continue
		}
		if p.Requested != cluster.RequestRunning && p.State != cluster.PlacementRunning && p.State != cluster.PlacementMigrating {
			continue
		}
		r := sc.Requirements(w)
		if r == nil {
			continue
		}
		for _, n := range []cluster.NodeID{p.Owner, p.Target} {
			if n == "" {
				continue
			}
			c := out[n]
			c.MemoryMB += r.MemoryMB
			c.CPUs += r.CPUs
			out[n] = c
		}
	}
	return out
}

// Place returns the best node for w, or ErrNoFit with every node's reason.
func (sc *Scheduler) Place(s *cluster.Snapshot, health []cluster.Health, w cluster.WorkloadRef, req cluster.Requirements, exclude []cluster.NodeID) (cluster.NodeID, map[cluster.NodeID]string, error) {
	cands, skipped := sc.Candidates(s, health, w, req, exclude)
	if len(cands) == 0 {
		return "", skipped, fmt.Errorf("%w: %s", cluster.ErrNoFit, summarize(skipped))
	}
	return cands[0], skipped, nil
}

// Candidates lists every node that can take w, best first, and why the
// others can't.
func (sc *Scheduler) Candidates(s *cluster.Snapshot, health []cluster.Health, w cluster.WorkloadRef, req cluster.Requirements, exclude []cluster.NodeID) ([]cluster.NodeID, map[cluster.NodeID]string) {
	hv := map[cluster.NodeID]cluster.Health{}
	for _, h := range health {
		hv[h.Node] = h
	}
	p := s.Placements[w]
	var pol cluster.HAPolicy
	if p != nil {
		pol = p.HA
	}
	committed := sc.Committed(s, w)
	skipped := map[cluster.NodeID]string{}
	type cand struct {
		id    cluster.NodeID
		pref  int // index in Preferred, len() if not listed
		anti  int // workloads of the same anti-affinity group already there
		freeM int
	}
	var cands []cand
	ids := make([]cluster.NodeID, 0, len(s.Nodes))
	for id := range s.Nodes {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		n := s.Nodes[id]
		if n.Role != cluster.RoleCompute {
			continue
		}
		why := sc.unfit(s, n, hv, committed, p, pol, req, exclude)
		if why != "" {
			skipped[id] = why
			continue
		}
		c := cand{id: id, pref: len(pol.Preferred)}
		if i := slices.Index(pol.Preferred, id); i >= 0 {
			c.pref = i
		}
		if pol.AntiAffinity != "" {
			for ow, op := range s.Placements {
				if ow != w && op.HA.AntiAffinity == pol.AntiAffinity && (op.Owner == id || op.Target == id) {
					c.anti++
				}
			}
		}
		c.freeM = n.Compute.MemoryMB - sc.reserved() - committed[id].MemoryMB
		cands = append(cands, c)
	}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.pref != b.pref {
			return a.pref < b.pref
		}
		if a.anti != b.anti {
			return a.anti < b.anti
		}
		if a.freeM != b.freeM {
			return a.freeM > b.freeM
		}
		return a.id < b.id
	})
	out := make([]cluster.NodeID, len(cands))
	for i, c := range cands {
		out[i] = c.id
	}
	return out, skipped
}

func (sc *Scheduler) unfit(s *cluster.Snapshot, n *cluster.Node, hv map[cluster.NodeID]cluster.Health, committed map[cluster.NodeID]cluster.Requirements,
	p *cluster.Placement, pol cluster.HAPolicy, req cluster.Requirements, exclude []cluster.NodeID) string {
	if slices.Contains(exclude, n.ID) {
		return "excluded"
	}
	if n.State != cluster.NodeActive {
		return "it is " + string(n.State)
	}
	if f := s.Fences[n.ID]; f != nil && f.Epoch == n.FenceEpoch && f.Epoch > 0 && !f.Confirmed {
		return "a fence is pending"
	}
	h, ok := hv[n.ID]
	if !ok {
		return "no recent heartbeat"
	}
	if h.Suspect {
		return "it hasn't been heard from lately"
	}
	if !h.Quorate {
		return "it has no quorum"
	}
	if !h.StorageOK {
		return "it can't reach cluster storage"
	}
	if pol.Restricted && !slices.Contains(pol.Preferred, n.ID) {
		return "not one of its preferred servers"
	}
	if p != nil && pol.Enabled {
		if ok, why := state.HAEligible(s, n.ID); !ok {
			return why
		}
	}
	ci := n.Compute
	if ci == nil {
		return "it hasn't reported its hardware"
	}
	if req.KVM && !ci.KVM {
		return "it has no hardware virtualization (KVM)"
	}
	if req.CPUModel != "" && req.CPUModel != ci.CPUModel {
		return "its CPU (" + ci.CPUModel + ") isn't " + req.CPUModel + " (the VM uses the host's exact CPU)"
	}
	for br, vlans := range req.Bridges {
		have, ok := ci.Bridges[br]
		if !ok {
			return "it has no network bridge " + br
		}
		for _, v := range vlans {
			if v != 0 && !slices.Contains(have, v) && !slices.Contains(have, -1) {
				return fmt.Sprintf("its bridge %s doesn't carry VLAN %d", br, v)
			}
		}
	}
	if len(req.Devices) > 0 {
		// Passthrough devices pin a VM (decision 354): an offline move
		// asks the target to check its own devices before anything stops.
		return "the VM has passthrough devices"
	}
	c := committed[n.ID]
	free := ci.MemoryMB - sc.reserved() - c.MemoryMB
	if req.MemoryMB > free {
		return fmt.Sprintf("not enough memory (%d MB free, %d MB needed)", max(free, 0), req.MemoryMB)
	}
	if req.CPUs > ci.CPUs {
		return fmt.Sprintf("it has %d CPUs, %d needed", ci.CPUs, req.CPUs)
	}
	return ""
}

// Fits says why node can't take w ("" when it can), for a move to a node
// the person chose. Passthrough devices aren't judged here: the mover asks
// the node itself (devices.check) before anything stops.
func (sc *Scheduler) Fits(s *cluster.Snapshot, health []cluster.Health, w cluster.WorkloadRef, req cluster.Requirements, node cluster.NodeID) string {
	n, ok := s.Nodes[node]
	if !ok {
		return "it isn't a member"
	}
	if n.Role != cluster.RoleCompute {
		return "it isn't a compute server"
	}
	hv := map[cluster.NodeID]cluster.Health{}
	for _, h := range health {
		hv[h.Node] = h
	}
	p := s.Placements[w]
	var pol cluster.HAPolicy
	if p != nil {
		pol = p.HA
		// A move the person chose may leave the preferred servers.
		pol.Restricted = false
	}
	req.Devices = nil
	return sc.unfit(s, n, hv, sc.Committed(s, w), p, pol, req, nil)
}

func summarize(skipped map[cluster.NodeID]string) string {
	ids := make([]cluster.NodeID, 0, len(skipped))
	for id := range skipped {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += "; "
		}
		out += string(id) + ": " + skipped[id]
	}
	if out == "" {
		return "there are no compute servers"
	}
	return out
}
