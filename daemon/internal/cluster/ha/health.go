package ha

import (
	"context"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// HealthReporter is this node's own report in part A's heartbeats
// (member.Service.Health / cluster.Config.Health): part B's storage paths
// and part C's running workloads. It is refreshed in the background so a
// slow root call never delays a heartbeat.
type HealthReporter struct {
	Cluster interface {
		Self() (cluster.Node, error)
	}
	// Storage reports whether this compute node's iSCSI sessions and NFS
	// mounts answer (part B's StorageAttacher.Healthy); nil: fine.
	Storage func(ctx context.Context) (bool, string)
	// Service is part C on this node (its reconciler lists what runs).
	Service *Service
	// Interval is how often the report is refreshed (default 2 s).
	Interval time.Duration

	mu  sync.Mutex
	cur *cluster.LocalHealth
}

// Get is the heartbeat's report (what the last refresh saw).
func (h *HealthReporter) Get(context.Context) cluster.LocalHealth {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cur == nil {
		return cluster.LocalHealth{StorageOK: true, LANOK: true}
	}
	out := *h.cur
	out.Running = append([]cluster.RunningWorkload(nil), h.cur.Running...)
	return out
}

// Refresh builds the report now.
func (h *HealthReporter) Refresh(ctx context.Context) {
	self, err := h.Cluster.Self()
	if err != nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// LANOK: there is no carrier and gateway probe yet, so the LAN is
	// reported as working (LAN isolation can't trigger).
	rep := cluster.LocalHealth{StorageOK: true, LANOK: true}
	if self.Role == cluster.RoleCompute {
		if h.Storage != nil {
			rep.StorageOK, _ = h.Storage(cctx)
		}
		if h.Service != nil && h.Service.Reconciler != nil {
			if st, err := h.Service.Reconciler.Local(cctx); err == nil {
				for _, w := range st {
					if w.Running {
						rep.Running = append(rep.Running, cluster.RunningWorkload{Workload: w.Workload, Generation: w.Generation})
					}
				}
			}
		}
	}
	h.mu.Lock()
	h.cur = &rep
	h.mu.Unlock()
}

// Run refreshes the report until ctx ends.
func (h *HealthReporter) Run(ctx context.Context) {
	iv := h.Interval
	if iv <= 0 {
		iv = 2 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		h.Refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Announcer keeps a compute node's hardware in the replicated state
// (member.update with ComputeInfo): CPUs, memory, KVM, the VM bridge and
// the watchdog kind, which placement and HA eligibility need. Part A
// announces addresses and versions; nothing else reported these.
type Announcer struct {
	Cluster interface {
		Self() (cluster.Node, error)
		Propose(ctx context.Context, t cluster.CommandType, body any, actor cluster.Actor) (uint64, error)
	}
	Priv interface {
		Call(ctx context.Context, op string, args, out any) error
	}
	// Interval is how often it checks (default 1 minute).
	Interval time.Duration
}

// Compute reads this node's hardware from hardyd-priv.
func (a *Announcer) Compute(ctx context.Context, prev *cluster.ComputeInfo) (*cluster.ComputeInfo, error) {
	var caps struct {
		KVM      bool   `json:"kvm"`
		CPUs     int    `json:"cpus"`
		MemoryMB int    `json:"memoryMB"`
		Bridge   string `json:"bridge"`
	}
	if err := a.Priv.Call(ctx, priv.OpVMsCapabilities, nil, &caps); err != nil {
		return nil, err
	}
	var wd struct {
		Kind string `json:"kind"`
	}
	if err := a.Priv.Call(ctx, priv.OpClusterWatchdogStatus, nil, &wd); err != nil {
		return nil, err
	}
	ci := &cluster.ComputeInfo{CPUs: caps.CPUs, MemoryMB: caps.MemoryMB, KVM: caps.KVM, Watchdog: wd.Kind}
	if prev != nil {
		ci.CPUModel = prev.CPUModel // the baseline job's to set
	}
	if caps.Bridge != "" {
		// The home network's bridge carries every VLAN the VMs tag.
		ci.Bridges = map[string][]int{caps.Bridge: {-1}}
	}
	return ci, nil
}

// Announce proposes member.update when the node's hardware differs from
// what the state says.
func (a *Announcer) Announce(ctx context.Context) error {
	self, err := a.Cluster.Self()
	if err != nil || self.Role != cluster.RoleCompute {
		return err
	}
	ci, err := a.Compute(ctx, self.Compute)
	if err != nil {
		return err
	}
	if sameCompute(self.Compute, ci) {
		return nil
	}
	_, err = a.Cluster.Propose(ctx, cluster.CmdMemberUpdate, state.MemberUpdateBody{Compute: ci},
		cluster.Actor{Kind: "system", Name: "HardyOS", Via: self.ID})
	return err
}

func sameCompute(a, b *cluster.ComputeInfo) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.CPUs != b.CPUs || a.MemoryMB != b.MemoryMB || a.CPUModel != b.CPUModel || a.Watchdog != b.Watchdog || a.KVM != b.KVM ||
		len(a.Bridges) != len(b.Bridges) {
		return false
	}
	for k, v := range a.Bridges {
		w, ok := b.Bridges[k]
		if !ok || len(v) != len(w) {
			return false
		}
		for i := range v {
			if v[i] != w[i] {
				return false
			}
		}
	}
	return true
}

// Run announces now and every Interval until ctx ends.
func (a *Announcer) Run(ctx context.Context) {
	iv := a.Interval
	if iv <= 0 {
		iv = time.Minute
	}
	for {
		wait := iv
		if _, err := a.Cluster.Self(); err != nil || a.Announce(ctx) != nil {
			wait = min(iv, 5*time.Second) // not a member yet, or it failed: soon again
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
