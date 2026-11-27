package convert

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
	"github.com/hardyos/hardyos/daemon/internal/cluster/storagesvc"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// KeptCopy is a parked copy and where it is.
type KeptCopy struct {
	hacopy.Parked
	// Node holds it (this server, or the storage server).
	Node cluster.NodeID `json:"node"`
}

// Kept lists the parked copies on this server and on the storage server.
func (c *Converter) Kept(ctx context.Context) ([]KeptCopy, error) {
	out := []KeptCopy{}
	self, err := c.Cluster.Self()
	if err != nil {
		return out, nil
	}
	var mine struct {
		Parked []hacopy.Parked `json:"parked"`
	}
	if err := c.Priv.Call(ctx, hacopy.OpParkedList, struct{}{}, &mine); err == nil {
		for _, p := range mine.Parked {
			out = append(out, KeptCopy{Parked: p, Node: self.ID})
		}
	}
	if self.Role != cluster.RoleStorage {
		snap := c.snapshot()
		if sn, ok := storagesvc.StorageNode(snap); ok {
			if l, err := c.Storage.HAParked(ctx); err == nil {
				for _, p := range l {
					out = append(out, KeptCopy{Parked: p, Node: sn.ID})
				}
			}
		}
	}
	return out, nil
}

// DropParams delete a kept copy now (Confirm: the workload's id;
// LastCopy: one without an expiry, which may be the only good copy).
type DropParams struct {
	Node     cluster.NodeID `json:"node"`
	Pool     string         `json:"pool"`
	Name     string         `json:"name"`
	Confirm  string         `json:"confirm"`
	LastCopy bool           `json:"lastCopy,omitempty"`
	Actor    cluster.Actor  `json:"actor"`
}

func (c *Converter) runDrop(jc *jobs.Context) (any, error) {
	var p DropParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	self, err := c.Cluster.Self()
	if err != nil {
		return nil, err
	}
	if p.Node == self.ID {
		err = c.Priv.Call(jc, hacopy.OpParkedDestroy, hacopy.ParkedDestroyArgs{Pool: p.Pool, Name: p.Name, Confirm: p.Confirm, LastCopy: p.LastCopy}, nil)
	} else {
		sn, ok := storagesvc.StorageNode(c.snapshot())
		if !ok || sn.ID != p.Node {
			return nil, errors.New("kept copies are deleted on their own server or on the storage server")
		}
		err = c.Storage.HAParkedDestroy(jc, storagesvc.HAParkedDestroy{Pool: p.Pool, Name: p.Name, Confirm: p.Confirm, LastCopy: p.LastCopy, Actor: p.Actor})
	}
	c.audit(p.Actor, "cluster.ha.parked.delete", string(p.Node)+":"+p.Pool+"/"+p.Name, "", err)
	if err != nil {
		return nil, err
	}
	return map[string]bool{"deleted": true}, nil
}

// RegisterJobs registers the conversion jobs.
func (c *Converter) RegisterJobs(m *jobs.Manager) {
	if m == nil {
		return
	}
	lock := func(raw json.RawMessage) string {
		var p struct {
			Workload cluster.WorkloadRef `json:"workload"`
			Conv     string              `json:"conv"`
		}
		_ = json.Unmarshal(raw, &p)
		if p.Workload.ID == "" && p.Conv != "" && c.DB != nil {
			if r, err := c.Get(context.Background(), p.Conv); err == nil {
				p.Workload = r.Ref()
			}
		}
		return ClusterLock(p.Workload)
	}
	reg := func(name string, run jobs.RunFunc) {
		m.Register(jobs.Kind{Name: name, AdminOnly: true, LockKey: lock, Run: run})
	}
	reg(JobToHA, c.runToHA)
	reg(JobToLocal, c.runToLocal)
	reg(JobUndo, c.runUndo)
	reg(JobAbandon, c.runAbandon)
	m.Register(jobs.Kind{Name: JobParkedDrop, AdminOnly: true, Run: c.runDrop})
}

// CleanupInterval is how often expired kept copies are deleted.
var CleanupInterval = 10 * time.Minute

// Run deletes kept copies past their grace period (on whichever server
// holds them) and starts the grace period of copies kept for workloads
// that first ran from their new storage since.
func (c *Converter) Run(ctx context.Context) {
	t := time.NewTicker(CleanupInterval)
	defer t.Stop()
	for {
		c.Cleanup(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Cleanup is one round of Run.
func (c *Converter) Cleanup(ctx context.Context) {
	if c.Priv == nil {
		return
	}
	var mine struct {
		Parked []hacopy.Parked `json:"parked"`
	}
	if err := c.Priv.Call(ctx, hacopy.OpParkedList, struct{}{}, &mine); err != nil {
		return
	}
	now := c.now()
	for _, p := range mine.Parked {
		if p.KeepUntil.IsZero() || now.Before(p.KeepUntil) {
			continue
		}
		err := c.Priv.Call(ctx, hacopy.OpParkedDestroy, hacopy.ParkedDestroyArgs{Pool: p.Pool, Name: p.Name, Confirm: p.ID}, nil)
		c.audit(cluster.Actor{Kind: "system", Name: "HardyOS"}, "cluster.ha.parked.expire", p.Pool+"/"+p.Name,
			"kept since "+p.Created.Format(time.RFC3339), err)
	}
	if !c.Member() || c.DB == nil {
		return
	}
	// Workloads that were off when they moved: their kept copy's grace
	// period starts once they ran from cluster storage.
	l, err := c.List(ctx, 200)
	if err != nil {
		return
	}
	snap := c.snapshot()
	for i := range l {
		r := &l[i]
		if !r.Options.AwaitStart || r.Options.ParkedName == "" || r.Options.ClusterChanged {
			continue
		}
		var ran bool
		switch {
		case r.Direction == DirHA && r.State == StateDone:
			// Made highly available while off: it ran from cluster storage.
			pl := snap.Placements[r.Ref()]
			ran = pl != nil && pl.State == cluster.PlacementRunning
		case (r.Direction == DirHA && r.State == StateUndone) || (r.Direction == DirLocal && r.State == StateDone):
			// Back on this server's own storage: it ran from there.
			ran = c.localRunning(ctx, r.Ref())
		}
		if !ran {
			continue
		}
		if err := c.keepFor(ctx, hacopy.Side(r.Options.ParkedSide), r.Options.ParkedPool, r.Options.ParkedName, c.grace(), cluster.Actor{Kind: "system", Name: "HardyOS"}); err != nil {
			continue
		}
		r.Options.AwaitStart = false
		_ = c.save(ctx, r)
	}
}

// localRunning: this server runs w from its own storage.
func (c *Converter) localRunning(ctx context.Context, w cluster.WorkloadRef) bool {
	if w.Kind == cluster.KindApp {
		var res apps.HACheckResult
		return c.Priv.Call(ctx, priv.OpAppsHACheck, priv.AppRef{ID: w.ID}, &res) == nil && res.Running
	}
	var v vms.VM
	return c.Priv.Call(ctx, priv.OpVMsGet, priv.VMRef{ID: w.ID}, &v) == nil && v.Backend != vms.BackendCluster && v.State == "running"
}
