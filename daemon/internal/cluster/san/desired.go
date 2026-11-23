package san

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Desired is the LIO configuration the storage node should have. hardyd's
// storage agent builds it from the applied cluster state only
// (storagesvc.BuildDesired); root validates it, checks every dataset
// itself and keeps it in its own file (StateFile), from which LIO is
// rebuilt at boot.
type Desired struct {
	Cluster cluster.ClusterID `json:"cluster"`
	// Index is the Raft index of the state it was built from. Root refuses
	// a desired state older than the one it has (a replayed request can't
	// undo a fence).
	Index uint64 `json:"index"`
	// Portals are the storage node's addresses on the storage network
	// (port 3260; two for multipath).
	Portals    []netip.AddrPort `json:"portals"`
	Targets    []Target         `json:"targets"`
	Backstores []Backstore      `json:"backstores"`
}

// Target is one compute node's target.
type Target struct {
	Node cluster.NodeID `json:"node"`
	// Enabled is false while the node is fenced: its TPG is disabled (all
	// sessions dropped) and nothing is mapped.
	Enabled bool `json:"enabled"`
	// FenceEpoch is the fence the target is disabled for (0: none).
	FenceEpoch uint64 `json:"fenceEpoch,omitempty"`
	// LUNs are backstore names mapped into the node's TPG.
	LUNs []string `json:"luns"`
}

// Backstore is one zvol exported as a LUN.
type Backstore struct {
	Name     string              `json:"name"`
	Workload cluster.WorkloadRef `json:"workload"`
	// Dataset is <pool>/vms/<vm>/diskN or <pool>/apps/<app>/block.
	Dataset string `json:"dataset"`
	Disk    string `json:"disk"`
	// Generation is the grant generation it is mapped under.
	Generation uint64 `json:"generation"`
	// Migration: the grant is a live migration's, so the LUN may be in two
	// targets.
	Migration bool `json:"migration,omitempty"`
	// NonRot reports the pool as solid state to initiators (a hint).
	NonRot bool `json:"nonRot,omitempty"`
}

// Pool is the pool part of the backstore's dataset.
func (b Backstore) Pool() string {
	for i := 0; i < len(b.Dataset); i++ {
		if b.Dataset[i] == '/' {
			return b.Dataset[:i]
		}
	}
	return b.Dataset
}

// Validate checks the structure: names, the workload's own dataset, at most
// one target per LUN (two only for a migration grant), fenced targets with
// nothing mapped, and unique entries.
func (d *Desired) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if err := ValidCluster(d.Cluster); err != nil {
		return err
	}
	if len(d.Portals) == 0 && len(d.Targets) > 0 {
		add("the storage node has no portal on the storage network")
	}
	if len(d.Portals) > 2 {
		add("at most two portals")
	}
	for _, p := range d.Portals {
		if !p.IsValid() || p.Addr().IsUnspecified() || p.Addr().IsLoopback() || p.Addr().Zone() != "" || p.Port() != ISCSIPort {
			add("portal %s must be a storage network address on port %d", p, ISCSIPort)
		}
	}
	bs := map[string]Backstore{}
	ds := map[string]bool{}
	for _, b := range d.Backstores {
		if err := b.validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, dup := bs[b.Name]; dup || ds[b.Dataset] {
			add("backstore %s is listed twice", b.Name)
		}
		bs[b.Name] = b
		ds[b.Dataset] = true
	}
	used := map[string][]cluster.NodeID{}
	nodes := map[cluster.NodeID]bool{}
	for _, t := range d.Targets {
		if err := ValidNode(t.Node); err != nil {
			errs = append(errs, err)
			continue
		}
		if nodes[t.Node] {
			add("node %s has two targets", t.Node)
		}
		nodes[t.Node] = true
		if !t.Enabled && len(t.LUNs) > 0 {
			add("%s is fenced, so nothing may be mapped into its target", t.Node)
		}
		seen := map[string]bool{}
		for _, l := range t.LUNs {
			if _, ok := bs[l]; !ok {
				add("%s's target maps %s, which isn't a backstore", t.Node, l)
				continue
			}
			if seen[l] {
				add("%s's target maps %s twice", t.Node, l)
			}
			seen[l] = true
			used[l] = append(used[l], t.Node)
		}
	}
	for name, ns := range used {
		b := bs[name]
		switch {
		case len(ns) == 2 && !b.Migration:
			add("%s is mapped to %s and %s without a live migration grant", name, ns[0], ns[1])
		case len(ns) > 2:
			add("%s is mapped to %d nodes", name, len(ns))
		}
	}
	return errors.Join(errs...)
}

func (b Backstore) validate() error {
	if err := ValidBackstoreName(b.Name); err != nil {
		return err
	}
	if !idRE.MatchString(b.Workload.ID) {
		return fmt.Errorf("backstore %s: workload id %q isn't valid", b.Name, b.Workload.ID)
	}
	if b.Name != BackstoreName(b.Workload, b.Disk) {
		return fmt.Errorf("backstore %s doesn't match %s/%s %s", b.Name, b.Workload.Kind, b.Workload.ID, b.Disk)
	}
	pool := b.Pool()
	if !poolRE.MatchString(pool) {
		return fmt.Errorf("backstore %s: pool %q isn't valid", b.Name, pool)
	}
	switch b.Workload.Kind {
	case cluster.KindVM:
		if !diskRE.MatchString(b.Disk) || b.Dataset != VMDisk(pool, b.Workload.ID, b.Disk) {
			return fmt.Errorf("backstore %s: %q isn't one of VM %s's disks", b.Name, b.Dataset, b.Workload.ID)
		}
	case cluster.KindApp:
		if b.Disk != "block" || b.Dataset != AppBlock(pool, b.Workload.ID) {
			return fmt.Errorf("backstore %s: %q isn't app %s's block volume", b.Name, b.Dataset, b.Workload.ID)
		}
	default:
		return fmt.Errorf("backstore %s: kind %q isn't vm or app", b.Name, b.Workload.Kind)
	}
	return nil
}

// Normalize sorts everything so equal states compare and render equal.
func (d *Desired) Normalize() {
	sort.Slice(d.Portals, func(i, j int) bool { return d.Portals[i].String() < d.Portals[j].String() })
	sort.Slice(d.Backstores, func(i, j int) bool { return d.Backstores[i].Name < d.Backstores[j].Name })
	sort.Slice(d.Targets, func(i, j int) bool { return d.Targets[i].Node < d.Targets[j].Node })
	for i := range d.Targets {
		if d.Targets[i].LUNs == nil {
			d.Targets[i].LUNs = []string{}
		}
		slices.Sort(d.Targets[i].LUNs)
	}
	if d.Targets == nil {
		d.Targets = []Target{}
	}
	if d.Backstores == nil {
		d.Backstores = []Backstore{}
	}
	if d.Portals == nil {
		d.Portals = []netip.AddrPort{}
	}
}

// Target returns a node's target.
func (d *Desired) Target(n cluster.NodeID) (Target, bool) {
	for _, t := range d.Targets {
		if t.Node == n {
			return t, true
		}
	}
	return Target{}, false
}

// Mapped reports the nodes a backstore is mapped to.
func (d *Desired) Mapped(name string) []cluster.NodeID {
	var out []cluster.NodeID
	for _, t := range d.Targets {
		if slices.Contains(t.LUNs, name) {
			out = append(out, t.Node)
		}
	}
	return out
}

// UsesDataset reports whether any backstore is the dataset or under it.
func (d *Desired) UsesDataset(ds string) bool {
	for _, b := range d.Backstores {
		if b.Dataset == ds || len(b.Dataset) > len(ds) && b.Dataset[:len(ds)+1] == ds+"/" {
			if len(d.Mapped(b.Name)) > 0 {
				return true
			}
		}
	}
	return false
}
