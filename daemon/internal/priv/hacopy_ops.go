package priv

import (
	"context"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// "Make highly available" and "Make local again" (docs/plans/make-ha.md,
// decisions 480-486): root's copy of a workload's datasets between this
// server's pool and the storage server's cluster pool (package hacopy),
// with the VM and app engines' own steps: what may move, letting go of a
// stopped workload before its datasets are parked, and the paths and
// pool written into its settings where it lands. Streams travel as file
// descriptors (SCM_RIGHTS), as replication's do. No operation takes a
// command line, a path or a property: names only, checked here and again
// against each dataset's own properties.
const (
	OpVMsHACheck         = "vms.ha.check"
	OpVMsClusterAdopt    = "vms.cluster.adopt"
	OpVMsClusterInstall  = "vms.cluster.installed"
	OpVMsClusterSchedule = "vms.cluster.schedules"
	OpAppsHACheck        = "apps.ha.check"
	OpAppsClusterAdopt   = "apps.cluster.adopt"
)

// HAAdoptArgs is ha.adopt: From is, for an app coming back from cluster
// storage, the folder it was in there (its compose file names it).
type HAAdoptArgs struct {
	hacopy.AdoptArgs
	From string `json:"from,omitempty"`
}

// ParkedListResult lists parked copies.
type ParkedListResult struct {
	Parked []hacopy.Parked `json:"parked"`
}

// InstalledResult lists cluster VMs whose install ended here.
type InstalledResult struct {
	Done []vms.InstallDone `json:"done"`
}

// SchedulesResult lists cluster VMs' snapshot schedules.
type SchedulesResult struct {
	Schedules []vms.ClusterSchedule `json:"schedules"`
}

func haErr(err error) error {
	if err == nil {
		return nil
	}
	var pe *Error
	if errors.As(err, &pe) {
		return pe
	}
	var iv *hacopy.ErrInvalid
	switch {
	case errors.As(err, &iv):
		return Errorf(CodeBadArgs, "%v", err)
	case errors.Is(err, hacopy.ErrNoStream):
		return Errorf(CodeNotFound, "%v", err)
	case errors.Is(err, hacopy.ErrTargetBusy), errors.Is(err, hacopy.ErrTooMany), errors.Is(err, hacopy.ErrBusy):
		return Errorf(CodeBusy, "%v", err)
	case errors.Is(err, vms.ErrNotFound), errors.Is(err, apps.ErrNotInstalled):
		return Errorf(CodeNotFound, "%v", err)
	}
	var vp vms.Problems
	var ap apps.Problems
	if errors.As(err, &vp) || errors.As(err, &ap) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	return Errorf(CodeFailed, "%v", err)
}

// RegisterHACopy adds the conversion operations. vmm and am may be nil
// (the live installer); the storage server's park needs r.Busy.
func RegisterHACopy(s *Server, r *hacopy.Root, vmm *vms.Manager, am *apps.Manager) {
	s.Handle(hacopy.OpTree, typed(func(ctx context.Context, a hacopy.TreeArgs) (any, error) {
		t, err := r.Tree(ctx, a)
		return t, haErr(err)
	}))
	s.Handle(hacopy.OpSnapshot, typed(func(ctx context.Context, a hacopy.SnapArgs) (any, error) {
		return map[string]bool{"ok": true}, haErr(r.Snapshot(ctx, a))
	}))
	s.Handle(hacopy.OpSnapDestroy, typed(func(ctx context.Context, a hacopy.SnapArgs) (any, error) {
		return map[string]bool{"ok": true}, haErr(r.SnapshotDestroy(ctx, a))
	}))
	s.Handle(hacopy.OpSend, typed(func(ctx context.Context, a hacopy.SendArgs) (any, error) {
		st, f, err := r.Send(ctx, a)
		if err != nil {
			return nil, haErr(err)
		}
		return &FileResult{Data: st, File: f}, nil
	}))
	s.Handle(hacopy.OpRecv, typed(func(ctx context.Context, a hacopy.RecvArgs) (any, error) {
		st, f, err := r.Recv(ctx, a)
		if err != nil {
			return nil, haErr(err)
		}
		return &FileResult{Data: st, File: f}, nil
	}))
	s.Handle(hacopy.OpStream, typed(func(ctx context.Context, a hacopy.StreamArgs) (any, error) {
		st, err := r.Stream(a.Stream)
		return st, haErr(err)
	}))
	s.Handle(hacopy.OpCancel, typed(func(ctx context.Context, a hacopy.StreamArgs) (any, error) {
		return map[string]bool{"cancelled": true}, haErr(r.Cancel(a.Stream))
	}))
	s.Handle(hacopy.OpAbort, typed(func(ctx context.Context, a hacopy.AbortArgs) (any, error) {
		return map[string]bool{"aborted": true}, haErr(r.Abort(ctx, a))
	}))
	s.Handle(hacopy.OpAdopt, typed(func(ctx context.Context, a HAAdoptArgs) (any, error) {
		if a.Side == hacopy.SideLocal && a.Kind == cluster.KindApp && a.From == "" {
			return nil, Errorf(CodeBadArgs, "an app coming back needs the folder it was in")
		}
		res, err := r.Adopt(ctx, a.AdoptArgs)
		if err != nil {
			return nil, haErr(err)
		}
		if a.Side == hacopy.SideLocal {
			// The engine's own part: the pool in vm.json, the folder in the
			// app's compose file. On failure the adopted datasets stay
			// (hardyd shows the job failed; nothing runs from them).
			switch {
			case a.Kind == cluster.KindVM && vmm != nil:
				err = vmm.HALocalSpec(ctx, a.ID, a.Pool)
			case a.Kind == cluster.KindApp && am != nil:
				err = am.HALocal(ctx, apps.HAAdoptArgs{ID: a.ID, From: a.From})
			}
		}
		return res, haErr(err)
	}))
	s.Handle(hacopy.OpPark, typed(func(ctx context.Context, a hacopy.ParkArgs) (any, error) {
		if a.Confirm != a.ID {
			return nil, Errorf(CodeBadArgs, "type the name to confirm")
		}
		// Parked by this conversion already (its answer was lost): that
		// copy is the answer, whatever the engine knows of it now.
		if pr, ok := r.ParkedBy(ctx, a.Ref, a.Conv); ok {
			return pr, nil
		}
		var res *hacopy.ParkResult
		park := func() error {
			var err error
			res, err = r.Park(ctx, a)
			return err
		}
		var err error
		switch {
		case a.Side == hacopy.SideCluster:
			err = park()
		case a.Kind == cluster.KindVM && vmm != nil:
			err = vmm.HARelease(ctx, a.ID, park)
		case a.Kind == cluster.KindApp && am != nil:
			err = am.HARelease(ctx, a.ID, park)
		default:
			err = Errorf(CodeBadArgs, "nothing here runs %s %s", a.Kind, a.ID)
		}
		return res, haErr(err)
	}))
	s.Handle(hacopy.OpUnpark, typed(func(ctx context.Context, a hacopy.UnparkArgs) (any, error) {
		if err := r.Unpark(ctx, a); err != nil {
			return nil, haErr(err)
		}
		var err error
		if a.Side == hacopy.SideLocal && a.Kind == cluster.KindVM && vmm != nil {
			err = vmm.HAPutBack(ctx, a.ID)
		}
		return map[string]bool{"ok": true}, haErr(err)
	}))
	s.Handle(hacopy.OpParkedList, typed(func(ctx context.Context, _ struct{}) (any, error) {
		l, err := r.ParkedList(ctx)
		return ParkedListResult{Parked: l}, haErr(err)
	}))
	s.Handle(hacopy.OpParkedDestroy, typed(func(ctx context.Context, a hacopy.ParkedDestroyArgs) (any, error) {
		return map[string]bool{"destroyed": true}, haErr(r.ParkedDestroy(ctx, a))
	}))
	s.Handle(hacopy.OpParkedKeep, typed(func(ctx context.Context, a hacopy.ParkedKeepArgs) (any, error) {
		return map[string]bool{"ok": true}, haErr(r.ParkedKeep(ctx, a))
	}))
	if vmm != nil {
		s.Handle(OpVMsHACheck, typed(func(ctx context.Context, a vms.HACheckArgs) (any, error) {
			res, err := vmm.HACheck(ctx, a)
			return res, haErr(err)
		}))
		s.Handle(OpVMsClusterAdopt, typed(func(ctx context.Context, a vms.ClusterAdoptArgs) (any, error) {
			h, err := vmm.ClusterAdopt(ctx, a)
			return SpecHashResult{Hash: h}, haErr(err)
		}))
		s.Handle(OpVMsClusterInstall, typed(func(ctx context.Context, a vms.InstalledArgs) (any, error) {
			return InstalledResult{Done: vmm.ClusterInstalled(a)}, nil
		}))
		s.Handle(OpVMsClusterSchedule, typed(func(ctx context.Context, _ struct{}) (any, error) {
			l, err := vmm.ClusterSchedules(ctx)
			return SchedulesResult{Schedules: l}, haErr(err)
		}))
	}
	if am != nil {
		s.Handle(OpAppsHACheck, typed(func(ctx context.Context, a AppRef) (any, error) {
			res, err := am.HACheck(ctx, a.ID)
			return res, haErr(err)
		}))
		s.Handle(OpAppsClusterAdopt, typed(func(ctx context.Context, a apps.HAAdoptArgs) (any, error) {
			h, err := am.ClusterAdopt(ctx, a)
			return SpecHashResult{Hash: h}, haErr(err)
		}))
	}
}
