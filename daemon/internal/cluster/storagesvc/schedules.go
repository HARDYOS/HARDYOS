package storagesvc

// Snapshot schedules of HA VMs (docs/plans/make-ha.md, decision 485,
// amending 471): a cluster VM's schedule is in its settings like any VM's,
// and the storage server, which holds its disks, takes and prunes its
// automatic snapshots by the same rules as a server does for its own VMs
// (vms.ScheduleStep). A running VM is frozen by its owner around each
// snapshot (Snapshot), as for any snapshot of it.

import (
	"context"
	"crypto/subtle"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// ScheduleInterval is how often the storage server looks.
var ScheduleInterval = time.Minute

// RunClusterSchedules runs TickClusterSchedules until ctx ends.
func (s *Service) RunClusterSchedules(ctx context.Context) {
	t := time.NewTicker(ScheduleInterval)
	defer t.Stop()
	for {
		s.TickClusterSchedules(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// TickClusterSchedules takes and prunes the cluster VMs' automatic
// snapshots due at now (the storage server only).
func (s *Service) TickClusterSchedules(ctx context.Context, now time.Time) {
	me, snap, err := s.self()
	if err != nil || me.Role != cluster.RoleStorage {
		return
	}
	var res priv.SchedulesResult
	if err := s.Priv.Call(ctx, priv.OpVMsClusterSchedule, struct{}{}, &res); err != nil {
		s.log().Debug("storage: cluster VMs' schedules", "err", err)
		return
	}
	actor := cluster.Actor{Kind: "system", Name: "snapshot schedule", Via: me.ID}
	for _, sch := range res.Schedules {
		w := cluster.WorkloadRef{Kind: cluster.KindVM, ID: sch.ID}
		p := snap.Placements[w]
		if p == nil || p.Storage.Pool != sch.Pool {
			continue
		}
		if p.SpecHash == "" || subtle.ConstantTimeCompare([]byte(p.SpecHash), []byte(sch.Hash)) != 1 {
			// Only the approved settings' schedule: a vm.json changed on
			// cluster storage behind its owner's back isn't followed.
			s.log().Debug("storage: a cluster VM's stored settings aren't the approved ones; its schedule waits", "vm", sch.ID)
			continue
		}
		have, err := s.Snapshots(ctx, w)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(have))
		for _, h := range have {
			names = append(names, h.Name)
		}
		due, prune := vms.ScheduleStep(sch.Schedule, names, now)
		for _, name := range due {
			if _, err := s.Snapshot(ctx, w, name, actor); err != nil {
				s.log().Warn("storage: a scheduled snapshot of a cluster VM", "vm", sch.ID, "snapshot", name, "err", err)
			}
		}
		for _, name := range prune {
			if err := s.DeleteSnapshot(ctx, w, name, name, actor); err != nil {
				s.log().Warn("storage: pruning a cluster VM's automatic snapshot", "vm", sch.ID, "snapshot", name, "err", err)
			}
		}
	}
}
