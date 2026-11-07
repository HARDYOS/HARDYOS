// Package ha is the cluster's high-availability coordinator
// (docs/plans/cluster.md section 7): it runs on the Raft leader when that is
// a HardyOS node, notices compute nodes that died, lost the storage network
// or the LAN, declares them dead or isolated in the log, waits for the
// storage node to confirm it has cut them off, and only then places their
// HA workloads elsewhere. It never recovers anything before a confirmed
// storage fence, never removes a voter and never forces quorum.
package ha

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/placement"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

// Cluster is what the coordinator uses of part A's Membership.
type Cluster interface {
	Self() (cluster.Node, error)
	State() cluster.State
	Leader() (cluster.NodeID, bool)
	Quorate() (bool, time.Time)
	Health(ctx context.Context) ([]cluster.Health, error)
	Propose(ctx context.Context, t cluster.CommandType, body any, actor cluster.Actor) (uint64, error)
}

// Actions runs each of the coordinator's changes as an audited system job
// (kind, title, target) on this node.
type Actions interface {
	Run(ctx context.Context, kind, title, target string, fn func(ctx context.Context) error) error
}

// LiveMover moves a VM live (LAN isolation, fail back).
type LiveMover interface {
	Move(ctx context.Context, r cluster.MoveRequest, actor cluster.Actor) (*cluster.MoveResult, error)
}

// Job kinds of the coordinator's actions.
const (
	JobDead     = "cluster.ha.dead"
	JobIsolate  = "cluster.ha.isolate"
	JobRecover  = "cluster.ha.recover"
	JobRelocate = "cluster.ha.relocate"
	JobPending  = "cluster.ha.pending"
	JobCollapse = "cluster.ha.migration"
	JobEvacuate = "cluster.ha.evacuate"
	JobFailBack = "cluster.ha.failback"
)

// Status is the coordinator's view, for the HA page.
type Status struct {
	Active      bool                      `json:"active"` // this node coordinates (it is the leader)
	LeaderSince time.Time                 `json:"leaderSince,omitzero"`
	StorageLost bool                      `json:"storageLost"`
	Suspect     []cluster.NodeID          `json:"suspect"`
	LastHeard   map[cluster.NodeID]string `json:"lastHeard"` // ago, for display
	Recent      []Event                   `json:"recent"`
}

// Event is one thing the coordinator did or saw.
type Event struct {
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Target   string    `json:"target"`
	Message  string    `json:"message"`
	Problem  string    `json:"problem,omitempty"`
	Workload string    `json:"workload,omitempty"`
}

// Coordinator is the leader's HA loop.
type Coordinator struct {
	Cluster   Cluster
	Scheduler *placement.Scheduler
	Actions   Actions
	// Requirements is what a workload needs (cached from its owner; nil
	// or a nil answer: nothing known beyond the state).
	Requirements func(w cluster.WorkloadRef) *cluster.Requirements
	// Power powers dead nodes off before they are declared dead (IPMI /
	// Redfish, later); nil or fence.NoPower: storage fencing only.
	Power cluster.PowerFencer
	// Mover moves VMs live off LAN-isolated nodes and for fail back
	// (optional).
	Mover LiveMover
	// EvacuateLANIsolated: live-migrate HA VMs off a node whose LAN alone
	// failed (default on; section 7.4).
	EvacuateLANIsolated *bool
	Now                 func() time.Time
	Log                 *slog.Logger

	mu           sync.Mutex
	leader       bool
	leaderSince  time.Time
	lastHeard    map[cluster.NodeID]time.Time
	storageBad   map[cluster.NodeID]time.Time
	lanBad       map[cluster.NodeID]time.Time
	evacuated    map[cluster.NodeID]bool
	fenceSeen    map[cluster.NodeID]time.Time // first time this leader saw a node's current fence
	relocations  map[cluster.WorkloadRef][]time.Time
	pendingTry   map[cluster.WorkloadRef]time.Time
	failBackTry  map[cluster.WorkloadRef]time.Time
	storageLost  bool
	suspect      []cluster.NodeID
	recent       []Event
	moving       map[cluster.WorkloadRef]bool
	movesRunning sync.WaitGroup
}

func (c *Coordinator) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Coordinator) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

// Status reports the coordinator's view.
func (c *Coordinator) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := Status{Active: c.leader, LeaderSince: c.leaderSince, StorageLost: c.storageLost,
		Suspect: slices.Clone(c.suspect), LastHeard: map[cluster.NodeID]string{}, Recent: slices.Clone(c.recent)}
	now := c.now()
	for n, t := range c.lastHeard {
		st.LastHeard[n] = now.Sub(t).Round(time.Second).String()
	}
	if st.Suspect == nil {
		st.Suspect = []cluster.NodeID{}
	}
	if st.Recent == nil {
		st.Recent = []Event{}
	}
	return st
}

// Run ticks every second until ctx ends.
func (c *Coordinator) Run(ctx context.Context) error {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		c.Tick(ctx)
		select {
		case <-ctx.Done():
			c.movesRunning.Wait()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Wait waits for background moves (tests).
func (c *Coordinator) Wait() { c.movesRunning.Wait() }

func (c *Coordinator) record(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.At = c.now()
	c.recent = append(c.recent, e)
	if len(c.recent) > 100 {
		c.recent = c.recent[len(c.recent)-100:]
	}
}

func (c *Coordinator) actor(self cluster.NodeID) cluster.Actor {
	return cluster.Actor{Kind: "system", Name: "HA", Via: self}
}

func (c *Coordinator) act(ctx context.Context, kind, title, target string, fn func(ctx context.Context) error) error {
	var err error
	if c.Actions != nil {
		err = c.Actions.Run(ctx, kind, title, target, fn)
	} else {
		err = fn(ctx)
	}
	e := Event{Kind: kind, Target: target, Message: title}
	if err != nil {
		e.Problem = err.Error()
		c.log().Warn("ha: action failed", "kind", kind, "target", target, "err", err)
	} else {
		c.log().Info("ha: "+title, "kind", kind, "target", target)
	}
	c.record(e)
	return err
}

func (c *Coordinator) timings(s *cluster.Snapshot) cluster.Timings {
	if s.Timings.Dead == 0 {
		return cluster.DefaultTimings
	}
	return s.Timings
}

// Tick runs one round (the leader only).
func (c *Coordinator) Tick(ctx context.Context) {
	self, err := c.Cluster.Self()
	if err != nil || self.Role == cluster.RoleWitness {
		c.setLeader(false, time.Time{})
		return
	}
	leader, ok := c.Cluster.Leader()
	quorate, _ := c.Cluster.Quorate()
	if !ok || leader != self.ID || !quorate {
		c.setLeader(false, time.Time{})
		return
	}
	now := c.now()
	s := c.Cluster.State().Snapshot()
	if c.setLeader(true, now) {
		// A new coordinator starts every node's clock at its election, so
		// a leader change never shortens the time to "dead".
		c.mu.Lock()
		c.lastHeard = map[cluster.NodeID]time.Time{}
		c.storageBad = map[cluster.NodeID]time.Time{}
		c.lanBad = map[cluster.NodeID]time.Time{}
		c.evacuated = map[cluster.NodeID]bool{}
		c.fenceSeen = map[cluster.NodeID]time.Time{}
		for id := range s.Nodes {
			c.lastHeard[id] = now
		}
		c.mu.Unlock()
	}
	health, err := c.Cluster.Health(ctx)
	if err != nil {
		c.log().Warn("ha: reading health", "err", err)
		return
	}
	t := c.timings(s)
	hv := map[cluster.NodeID]cluster.Health{}
	c.mu.Lock()
	for _, h := range health {
		hv[h.Node] = h
		if h.LastHeard.After(c.lastHeard[h.Node]) {
			c.lastHeard[h.Node] = h.LastHeard
		}
	}
	c.mu.Unlock()

	c.detectDead(ctx, self.ID, s, t, now)
	s = c.Cluster.State().Snapshot()
	c.detectIsolation(ctx, self.ID, s, hv, t, now)
	s = c.Cluster.State().Snapshot()
	c.collapseMigrations(ctx, self.ID, s, hv)
	s = c.Cluster.State().Snapshot()
	c.recover(ctx, self.ID, s, health, t, now)
	s = c.Cluster.State().Snapshot()
	c.failBack(ctx, self.ID, s, health, now)
}

// setLeader records leadership; it reports whether this node just became
// the coordinator.
func (c *Coordinator) setLeader(on bool, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if on == c.leader {
		return false
	}
	c.leader = on
	if on {
		c.leaderSince = now
		c.relocations = map[cluster.WorkloadRef][]time.Time{}
		c.pendingTry = map[cluster.WorkloadRef]time.Time{}
		c.failBackTry = map[cluster.WorkloadRef]time.Time{}
		c.moving = map[cluster.WorkloadRef]bool{}
	}
	return on
}

// computeNodes are the compute members in a stable order.
func computeNodes(s *cluster.Snapshot) []*cluster.Node {
	var out []*cluster.Node
	for _, n := range s.Nodes {
		if n.Role == cluster.RoleCompute {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func watched(n *cluster.Node) bool {
	switch n.State {
	case cluster.NodeActive, cluster.NodeMaintenance, cluster.NodeRejoining, cluster.NodeJoining:
		return true
	}
	return false
}

// detectDead declares compute nodes not heard from for F dead.
func (c *Coordinator) detectDead(ctx context.Context, self cluster.NodeID, s *cluster.Snapshot, t cluster.Timings, now time.Time) {
	var suspect []cluster.NodeID
	for _, n := range computeNodes(s) {
		if !watched(n) || n.ID == self {
			continue
		}
		c.mu.Lock()
		age := now.Sub(c.lastHeard[n.ID])
		c.mu.Unlock()
		if age >= t.Suspect {
			suspect = append(suspect, n.ID)
		}
		if age < t.Dead {
			continue
		}
		n := n
		if c.Power != nil {
			// Out-of-band power off first when configured; never instead
			// of the storage fence (decision 327).
			if err := c.Power.PowerOff(ctx, n.ID); err != nil {
				c.log().Debug("ha: power fencing", "node", n.ID, "err", err)
			}
		}
		body := state.NodeDeadBody{Node: n.ID, Epoch: n.FenceEpoch + 1, Reason: "dead"}
		_ = c.act(ctx, JobDead, fmt.Sprintf("Declare %s dead (not heard for %s)", n.ID, age.Round(time.Second)), string(n.ID), func(ctx context.Context) error {
			_, err := c.Cluster.Propose(ctx, cluster.CmdNodeDead, body, c.actor(self))
			return err
		})
	}
	c.mu.Lock()
	c.suspect = suspect
	c.mu.Unlock()
}

// detectIsolation handles nodes that lost the storage network or the LAN
// while the others didn't, and the storage node being lost.
func (c *Coordinator) detectIsolation(ctx context.Context, self cluster.NodeID, s *cluster.Snapshot, hv map[cluster.NodeID]cluster.Health, t cluster.Timings, now time.Time) {
	var live []cluster.NodeID
	storageOK, lanOK := 0, 0
	for _, n := range computeNodes(s) {
		h, ok := hv[n.ID]
		if !ok || !watched(n) || h.Suspect {
			continue
		}
		live = append(live, n.ID)
		if h.StorageOK {
			storageOK++
		}
		if h.LANOK {
			lanOK++
		}
	}
	c.mu.Lock()
	lost := len(live) > 0 && storageOK == 0
	changed := lost != c.storageLost
	c.storageLost = lost
	c.mu.Unlock()
	if changed && lost {
		// Nowhere to fail over to: placements stay as they are (VMs pause
		// on I/O errors, apps block) until the storage server is back.
		c.record(Event{Kind: "cluster.ha.storage", Target: "storage", Message: "No compute server can reach cluster storage; failover is held"})
	}
	for _, id := range live {
		h := hv[id]
		c.mu.Lock()
		if h.StorageOK || lost {
			delete(c.storageBad, id)
		} else if _, ok := c.storageBad[id]; !ok {
			c.storageBad[id] = now
		}
		since, bad := c.storageBad[id]
		if h.LANOK || lanOK == 0 {
			delete(c.lanBad, id)
			delete(c.evacuated, id)
		} else if _, ok := c.lanBad[id]; !ok {
			c.lanBad[id] = now
		}
		lanSince, lanIsBad := c.lanBad[id]
		evac := c.evacuated[id]
		c.mu.Unlock()
		n := s.Nodes[id]
		if bad && now.Sub(since) >= t.StorageIsolated && n.State == cluster.NodeActive && id != self {
			body := state.NodeDeadBody{Node: id, Epoch: n.FenceEpoch + 1, Reason: "isolated"}
			_ = c.act(ctx, JobIsolate, fmt.Sprintf("Isolate %s (it lost cluster storage for %s)", id, now.Sub(since).Round(time.Second)), string(id), func(ctx context.Context) error {
				_, err := c.Cluster.Propose(ctx, cluster.CmdNodeIsolated, body, c.actor(self))
				return err
			})
		}
		evacOn := c.EvacuateLANIsolated == nil || *c.EvacuateLANIsolated
		if lanIsBad && !evac && evacOn && now.Sub(lanSince) >= t.LANIsolated && c.Mover != nil {
			c.mu.Lock()
			c.evacuated[id] = true
			c.mu.Unlock()
			c.evacuate(ctx, self, s, id)
		}
	}
}

// evacuate live-migrates a LAN-isolated node's running HA VMs away.
func (c *Coordinator) evacuate(ctx context.Context, self cluster.NodeID, s *cluster.Snapshot, node cluster.NodeID) {
	c.record(Event{Kind: JobEvacuate, Target: string(node), Message: fmt.Sprintf("%s lost the LAN; moving its HA VMs away", node)})
	for _, p := range byPriority(s) {
		if p.Owner != node || !p.HA.Enabled || p.Workload.Kind != cluster.KindVM || p.Pinned || p.State != cluster.PlacementRunning {
			continue
		}
		c.background(ctx, self, p, JobEvacuate, "Move "+p.Name+" off "+string(node)+" (LAN isolated)", "")
	}
}

// background starts a live move of p (to, or the scheduler's choice).
func (c *Coordinator) background(ctx context.Context, self cluster.NodeID, p *cluster.Placement, kind, title string, to cluster.NodeID) {
	c.mu.Lock()
	if c.moving[p.Workload] {
		c.mu.Unlock()
		return
	}
	c.moving[p.Workload] = true
	c.mu.Unlock()
	c.movesRunning.Add(1)
	req := cluster.MoveRequest{Workload: p.Workload, To: to, Mode: cluster.MoveLive, Generation: p.Generation}
	go func() {
		defer c.movesRunning.Done()
		defer func() {
			c.mu.Lock()
			delete(c.moving, p.Workload)
			c.mu.Unlock()
		}()
		_ = c.act(context.WithoutCancel(ctx), kind, title, string(p.Workload.Kind)+":"+p.Workload.ID, func(ctx context.Context) error {
			_, err := c.Mover.Move(ctx, req, c.actor(self))
			return err
		})
	}()
}

// fenceHolds: n's current fence is confirmed by the storage node, and for
// an isolated node (which may still be running, stuck in I/O) the
// watchdog has had time to reset it.
func (c *Coordinator) fenceHolds(s *cluster.Snapshot, n cluster.NodeID, t cluster.Timings, now time.Time) bool {
	node, ok := s.Nodes[n]
	if !ok || node.State == cluster.NodeRemoved {
		return true
	}
	f := s.Fences[n]
	if f == nil || !f.Confirmed || f.Epoch != node.FenceEpoch || f.Epoch == 0 {
		return false
	}
	if node.State != cluster.NodeFenced && node.State != cluster.NodeDead && node.State != cluster.NodeRejoining {
		return false
	}
	c.mu.Lock()
	seen, ok := c.fenceSeen[n]
	if !ok {
		seen = now
		c.fenceSeen[n] = now
	}
	c.mu.Unlock()
	if f.Reason == "isolated" {
		return now.Sub(seen) >= t.Watchdog+state.DeadMargin
	}
	return true
}

// collapseMigrations ends live migrations one of whose nodes was fenced:
// the grant collapses onto the node that is still up.
func (c *Coordinator) collapseMigrations(ctx context.Context, self cluster.NodeID, s *cluster.Snapshot, hv map[cluster.NodeID]cluster.Health) {
	t := c.timings(s)
	now := c.now()
	for _, p := range byPriority(s) {
		g := s.Grants[p.Workload]
		if g == nil || g.Mode != cluster.GrantMigration || len(g.Nodes) != 2 {
			continue
		}
		var alive, gone []cluster.NodeID
		for _, n := range g.Nodes {
			if state.MayRun(s, n, p.Workload, p.Generation) == cluster.ErrFenced {
				if c.fenceHolds(s, n, t, now) {
					gone = append(gone, n)
				}
				continue
			}
			alive = append(alive, n)
		}
		if len(gone) == 0 {
			continue
		}
		body := state.PlacementSet{Workload: p.Workload, Expected: p.Generation, Reason: "migration-failed"}
		switch len(alive) {
		case 1:
			body.Owner = alive[0]
			body.State = cluster.PlacementStopped
			if runs(hv[alive[0]], p.Workload, p.Generation) {
				body.State = cluster.PlacementRunning
			} else if p.Requested == cluster.RequestRunning && p.HA.Enabled {
				body.State = cluster.PlacementStarting
			}
		default:
			// Both nodes are fenced: an HA VM waits for a server (the next
			// round places it); any other is left to the person.
			if !p.HA.Enabled {
				continue
			}
			body.Owner, body.State, body.Reason = "", cluster.PlacementPending, "pending"
			body.Problem = "both servers of its live migration are down"
		}
		_ = c.act(ctx, JobCollapse, "End the live migration of "+p.Name+" on "+string(body.Owner), ref(p.Workload), func(ctx context.Context) error {
			_, err := c.Cluster.Propose(ctx, cluster.CmdPlacementSet, body, c.actor(self))
			return err
		})
	}
}

func runs(h cluster.Health, w cluster.WorkloadRef, gen uint64) bool {
	for _, r := range h.Running {
		if r.Workload == w && r.Generation == gen {
			return true
		}
	}
	return false
}

func ref(w cluster.WorkloadRef) string { return string(w.Kind) + ":" + w.ID }

func byPriority(s *cluster.Snapshot) []*cluster.Placement {
	l := state.SortedPlacements(s)
	sort.SliceStable(l, func(i, j int) bool { return l[i].HA.Priority > l[j].HA.Priority })
	return l
}

func (c *Coordinator) req(w cluster.WorkloadRef) cluster.Requirements {
	if c.Requirements != nil {
		if r := c.Requirements(w); r != nil {
			return *r
		}
	}
	return cluster.Requirements{}
}

// recover re-places HA workloads whose owner's fence holds, relocates HA
// workloads in error, and retries pending ones every 30 s.
func (c *Coordinator) recover(ctx context.Context, self cluster.NodeID, s *cluster.Snapshot, health []cluster.Health, t cluster.Timings, now time.Time) {
	c.mu.Lock()
	lost := c.storageLost
	c.mu.Unlock()
	if lost {
		return
	}
	for _, p := range byPriority(s) {
		if !p.HA.Enabled || p.Requested != cluster.RequestRunning {
			continue
		}
		if g := s.Grants[p.Workload]; g != nil && g.Mode == cluster.GrantMigration {
			continue // collapseMigrations handles it
		}
		var kind, title string
		var exclude []cluster.NodeID
		switch p.State {
		case cluster.PlacementRecovering:
			if !c.fenceHolds(s, p.Owner, t, now) {
				continue // never before the storage node confirms the fence
			}
			kind, title = JobRecover, "Recover "+p.Name+" from "+string(p.Owner)
			exclude = []cluster.NodeID{p.Owner}
		case cluster.PlacementError:
			if !c.relocationAllowed(p, now) {
				continue
			}
			kind, title = JobRelocate, "Move "+p.Name+" off "+string(p.Owner)+" (it keeps failing there)"
			exclude = []cluster.NodeID{p.Owner}
		case cluster.PlacementPending:
			c.mu.Lock()
			last := c.pendingTry[p.Workload]
			c.mu.Unlock()
			if now.Sub(last) < 30*time.Second {
				continue
			}
			kind, title = JobRecover, "Start "+p.Name+" (waiting for a server)"
		default:
			continue
		}
		// Placement sees this round's state (an earlier recovery in the
		// same round already committed memory on its node).
		s2 := c.Cluster.State().Snapshot()
		p2 := s2.Placements[p.Workload]
		if p2 == nil || p2.Generation != p.Generation {
			continue
		}
		to, skipped, err := c.Scheduler.Place(s2, health, p.Workload, c.req(p.Workload), exclude)
		body := state.PlacementSet{Workload: p.Workload, Expected: p.Generation, Owner: to, State: cluster.PlacementStarting, Reason: "recover"}
		if kind == JobRelocate {
			body.Reason = "relocate"
		}
		if errors.Is(err, cluster.ErrNoFit) {
			c.mu.Lock()
			c.pendingTry[p.Workload] = now
			c.mu.Unlock()
			if p.State == cluster.PlacementPending {
				continue // still nothing; checked again later
			}
			body.Owner, body.State, body.Reason = "", cluster.PlacementPending, "pending"
			body.Problem = "no server can run it now: " + summarize(skipped)
			kind, title = JobPending, "No server can take "+p.Name+" now"
		} else if err != nil {
			continue
		}
		if kind == JobRelocate {
			c.mu.Lock()
			c.relocations[p.Workload] = append(c.relocations[p.Workload], now)
			c.mu.Unlock()
		}
		_ = c.act(ctx, kind, title, ref(p.Workload), func(ctx context.Context) error {
			_, err := c.Cluster.Propose(ctx, cluster.CmdPlacementSet, body, c.actor(self))
			return err
		})
	}
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
	return out
}

func (c *Coordinator) relocationAllowed(p *cluster.Placement, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	var keep []time.Time
	for _, t := range c.relocations[p.Workload] {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	c.relocations[p.Workload] = keep
	return len(keep) < p.HA.MaxRelocations
}

// failBack moves an HA VM back to its first preferred node once that node
// is active and fits, live, at most every 10 minutes per workload.
func (c *Coordinator) failBack(ctx context.Context, self cluster.NodeID, s *cluster.Snapshot, health []cluster.Health, now time.Time) {
	if c.Mover == nil {
		return
	}
	for _, p := range byPriority(s) {
		if !p.HA.Enabled || !p.HA.FailBack || len(p.HA.Preferred) == 0 || p.Workload.Kind != cluster.KindVM ||
			p.State != cluster.PlacementRunning || p.Target != "" || p.Pinned {
			continue
		}
		home := p.HA.Preferred[0]
		if home == p.Owner {
			continue
		}
		c.mu.Lock()
		last := c.failBackTry[p.Workload]
		c.mu.Unlock()
		if now.Sub(last) < 10*time.Minute {
			continue
		}
		if why := c.Scheduler.Fits(s, health, p.Workload, c.req(p.Workload), home); why != "" {
			continue
		}
		c.mu.Lock()
		c.failBackTry[p.Workload] = now
		c.mu.Unlock()
		c.background(ctx, self, p, JobFailBack, "Move "+p.Name+" back to "+string(home), home)
	}
}
