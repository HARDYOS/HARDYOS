package convert

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/cluster/storagesvc"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// Phases of "Make local again", in order.
const (
	PhaseLStop     = "stop"
	PhaseLMode     = "mode"
	PhaseLSnapshot = "snapshot"
	PhaseLCopy     = "copy"
	PhaseLRemove   = "remove"
	PhaseLPark     = "park-storage"
	PhaseLAdopt    = "adopt"
	PhaseLStart    = "start"
)

var localPhases = []string{PhaseCheck, PhaseLStop, PhaseLMode, PhaseLSnapshot, PhaseLCopy, PhaseLRemove, PhaseLPark, PhaseLAdopt, PhaseLStart, PhaseDone}

// ToLocalParams start (or resume) "Make local again" onto this server.
type ToLocalParams struct {
	Conv     string              `json:"conv"`
	Workload cluster.WorkloadRef `json:"workload"`
	// Pool is this server's pool it goes to (an app: the apps' pool).
	Pool  string        `json:"pool"`
	Actor cluster.Actor `json:"actor"`
}

// StartToLocal submits (or resumes) "Make local again" onto this server;
// confirm is the workload's name or id.
func (c *Converter) StartToLocal(ctx context.Context, p ToLocalParams, confirm string, userID *int64) (*jobs.Job, error) {
	_, snap, err := c.hostCheck()
	if err != nil {
		return nil, err
	}
	w := p.Workload
	open, err := c.open(ctx, w)
	if err != nil {
		return nil, err
	}
	name := w.ID
	if pl := snap.Placements[w]; pl != nil {
		name = pl.Name
		if pl.Target != "" {
			return nil, errors.New(pl.Name + " is being moved; wait for the move to end")
		}
	} else if open == nil || open.Direction != DirLocal {
		return nil, errors.New("it isn't a cluster workload")
	}
	if open != nil {
		if open.Direction != DirLocal {
			return nil, fmt.Errorf("the conversion of %s to cluster storage isn't finished; resume or undo it first", name)
		}
		p.Conv, p.Pool = open.ID, open.LocalPool
	}
	if !confirmed(confirm, name, w.ID) {
		return nil, errTyped
	}
	if p.Conv == "" {
		if err := c.localTarget(ctx, w, p.Pool); err != nil {
			return nil, err
		}
		p.Conv = newID()
	}
	return c.Jobs.Submit(ctx, JobToLocal, "Make "+name+" local again", p, userID)
}

// localTarget checks that w can land on this server's pool.
func (c *Converter) localTarget(ctx context.Context, w cluster.WorkloadRef, pool string) error {
	switch w.Kind {
	case cluster.KindVM:
		if pool == "" {
			return errors.New("choose this server's pool for it")
		}
		var v vms.VM
		err := c.Priv.Call(ctx, priv.OpVMsGet, priv.VMRef{ID: w.ID}, &v)
		if err == nil && v.Backend != vms.BackendCluster {
			return fmt.Errorf("this server has a VM called %s already", w.ID)
		}
	case cluster.KindApp:
		var ov apps.Overview
		if err := c.Priv.Call(ctx, priv.OpAppsStatus, nil, &ov); err != nil {
			return err
		}
		if !ov.Configured || ov.Pool == "" {
			return errors.New("apps aren't set up on this server (App Store) yet")
		}
		if pool != "" && pool != ov.Pool {
			return fmt.Errorf("this server's apps live on %s", ov.Pool)
		}
	}
	return nil
}

func (c *Converter) runToLocal(jc *jobs.Context) (any, error) {
	var p ToLocalParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	w := p.Workload
	unlock := jc.Lock(localLock(w))
	defer unlock()
	self, snap, err := c.hostCheck()
	if err != nil {
		return nil, err
	}
	r, err := c.Get(jc, p.Conv)
	if err != nil {
		pool := p.Pool
		if w.Kind == cluster.KindApp {
			var ov apps.Overview
			if err := c.Priv.Call(jc, priv.OpAppsStatus, nil, &ov); err != nil {
				return nil, err
			}
			pool = ov.Pool
		}
		pl := snap.Placements[w]
		if pl == nil {
			return nil, errors.New("it isn't a cluster workload")
		}
		r = &Record{ID: p.Conv, Direction: DirLocal, Kind: w.Kind, Workload: w.ID, Name: pl.Name, Phase: PhaseCheck, Actor: p.Actor.Name,
			Started: c.now().UTC(), LocalPool: pool, StoragePool: pl.Storage.Pool, WasRunning: pl.Requested == cluster.RequestRunning}
		if len(pl.Storage.Exports) > 0 {
			r.Options.Dir = pl.Storage.Exports[0].MountPath
		}
	} else if r.Direction != DirLocal || r.Ref() != w {
		return nil, errors.New("that conversion is of something else")
	}
	r.State, r.Problem, r.JobID = StateRunning, "", jc.ID()
	_ = c.save(jc, r)
	err = c.toLocal(jc, self, r, p.Actor)
	if err != nil {
		c.audit(p.Actor, "cluster.ha.local", refString(w), "phase "+r.Phase, err)
		c.alert("cluster.ha.local", notify.SeverityWarning, r.Name+" wasn't made local again",
			"The conversion stopped at "+r.Phase+": "+err.Error()+".")
		return nil, c.fail(jc, r, err)
	}
	c.audit(p.Actor, "cluster.ha.local", refString(w), "on "+string(self.ID), nil)
	return map[string]any{"conv": r.ID, "started": r.WasRunning}, nil
}

func (c *Converter) toLocal(jc *jobs.Context, self cluster.Node, r *Record, actor cluster.Actor) error {
	w := r.Ref()
	local := hacopy.Ref{Kind: w.Kind, ID: w.ID, Pool: r.LocalPool, Side: hacopy.SideLocal}
	at := max(phaseAt(localPhases, r.Phase), 0)
	if at < phaseAt(localPhases, PhaseLRemove) {
		// Until the cluster forgets it, a failure leaves it a cluster
		// workload, requested as it was.
		err := c.localCopy(jc, r, local, actor)
		if err != nil {
			c.requestAgain(r, actor)
			return err
		}
	}
	if phaseAt(localPhases, r.Phase) <= phaseAt(localPhases, PhaseLRemove) {
		c.phase(jc, jc, r, PhaseLRemove, 86, "Removing it from the cluster")
		pl := c.snapshot().Placements[w]
		if pl != nil {
			if pl.Generation != r.Options.Generation || !pl.Changed.Equal(r.Options.Changed) || pl.Requested != cluster.RequestStopped {
				c.requestAgain(r, actor)
				r.Phase = PhaseLStop
				return errors.New("it changed in the cluster while it was copied; try again")
			}
			if err := c.propose(jc, cluster.CmdWorkloadRemove, state.WorkloadRemove{Workload: w, Generation: pl.Generation}, actor); err != nil {
				c.requestAgain(r, actor)
				return err
			}
			if c.snapshot().Placements[w] != nil {
				c.requestAgain(r, actor)
				return errors.New("the cluster refused to remove it (see the server's log)")
			}
		}
	}
	// From here on only forward: the cluster no longer has it.
	if phaseAt(localPhases, r.Phase) <= phaseAt(localPhases, PhaseLPark) {
		c.phase(jc, jc, r, PhaseLPark, 88, "Putting the cluster copy aside")
		err := c.waitFor(jc, 3*time.Minute, "the storage server letting go of it", func(*cluster.Snapshot) (bool, error) {
			pr, err := c.Storage.HAPark(jc, storagesvc.HARequest{Workload: w, Pool: r.StoragePool, Confirm: w.ID, Actor: actor})
			if err != nil {
				// Still unmapped or unexported moments after the removal:
				// try again.
				c.log().Debug("convert: parking the cluster copy", "err", err)
				return false, nil
			}
			r.Options.ParkedPool, r.Options.ParkedName, r.Options.ParkedSide = pr.Pool, pr.Name, string(hacopy.SideCluster)
			return true, nil
		})
		if err != nil {
			return err
		}
		_ = c.save(jc, r)
	}
	if phaseAt(localPhases, r.Phase) <= phaseAt(localPhases, PhaseLAdopt) {
		c.phase(jc, jc, r, PhaseLAdopt, 92, "Setting it up on this server")
		args := priv.HAAdoptArgs{AdoptArgs: hacopy.AdoptArgs{Ref: local, Conv: r.ID}, From: r.Options.Dir}
		var res hacopy.AdoptResult
		if err := c.Priv.Call(jc, hacopy.OpAdopt, args, &res); err != nil {
			return err
		}
		if w.Kind == cluster.KindApp {
			snap := c.snapshot()
			if u, ok := snap.AppUIDs[w.ID]; ok {
				if err := c.propose(jc, cluster.CmdAppUID, state.AppUIDBody{App: w.ID, UID: u, Release: true}, actor); err != nil {
					c.log().Warn("convert: releasing a local app's cluster user id", "app", w.ID, "err", err)
				}
			}
		}
	}
	c.phase(jc, jc, r, PhaseLStart, 96, "Starting it on this server")
	if r.WasRunning {
		var err error
		if w.Kind == cluster.KindApp {
			err = c.Priv.Call(jc, priv.OpAppsStart, priv.AppRef{ID: w.ID}, nil)
		} else {
			var res vms.Result
			err = c.Priv.Call(jc, priv.OpVMsStart, priv.VMRef{ID: w.ID}, &res)
		}
		if err != nil {
			// The cluster copy stays kept (no expiry) until it runs here.
			return fmt.Errorf("it is on this server now but didn't start: %w", err)
		}
	}
	if err := c.keepFor(jc, hacopy.SideCluster, r.Options.ParkedPool, r.Options.ParkedName, c.grace(), actor); err != nil {
		c.log().Warn("convert: setting the cluster copy's grace period", "err", err)
	}
	r.State, r.Phase, r.Finished = StateDone, PhaseDone, c.now().UTC()
	_ = c.save(jc, r)
	jc.Progress(100, r.Name+" runs from this server's own storage")
	return nil
}

// localCopy stops the cluster workload and copies it here (phases up to
// the copy).
func (c *Converter) localCopy(jc *jobs.Context, r *Record, local hacopy.Ref, actor cluster.Actor) error {
	w := r.Ref()
	c.phase(jc, jc, r, PhaseLStop, 2, "Stopping it")
	snap := c.snapshot()
	pl := snap.Placements[w]
	if pl == nil {
		return errors.New("it isn't a cluster workload")
	}
	if pl.Target != "" {
		return errors.New("it is being moved")
	}
	if err := c.localTarget(jc, w, r.LocalPool); err != nil && phaseAt(localPhases, r.Phase) <= phaseAt(localPhases, PhaseLStop) {
		return err
	}
	if pl.Requested != cluster.RequestStopped {
		if err := c.propose(jc, cluster.CmdRequested, state.RequestedSet{Workload: w, Generation: pl.Generation, Requested: cluster.RequestStopped}, actor); err != nil {
			return err
		}
	}
	if err := c.waitFor(jc, 5*time.Minute, "stopping it", func(s *cluster.Snapshot) (bool, error) {
		p := s.Placements[w]
		if p == nil {
			return false, errors.New("it is no longer a cluster workload")
		}
		return p.State == cluster.PlacementStopped || p.State == cluster.PlacementError || p.State == cluster.PlacementPending, nil
	}); err != nil {
		return err
	}
	if w.Kind == cluster.KindApp {
		pl = c.snapshot().Placements[w]
		if pl.Storage.Mode == cluster.StorageBlock {
			c.phase(jc, jc, r, PhaseLMode, 6, "Moving its data out of its block volume")
			if _, err := c.Storage.SwitchAppMode(jc, storagesvc.ModeRequest{App: w.ID, To: cluster.StorageNFS, Confirm: w.ID, Actor: actor}); err != nil {
				return fmt.Errorf("moving its data out of the block volume: %w", err)
			}
		}
	}
	c.phase(jc, jc, r, PhaseLSnapshot, 8, "Snapshot on the storage server")
	pl = c.snapshot().Placements[w]
	r.Options.Generation, r.Options.Changed = pl.Generation, pl.Changed
	tree, err := c.Storage.HATree(jc, storagesvc.HARequest{Workload: w})
	if err != nil {
		return err
	}
	final := snapName(r.ID, "final")
	has := false
	for _, d := range tree.Datasets {
		if d.Child == "" && slices.ContainsFunc(d.Snaps, func(s hacopy.Snap) bool { return s.Name == final }) {
			has = true
		}
	}
	if !has {
		if err := c.Storage.HASnapshot(jc, storagesvc.HARequest{Workload: w, Name: final, Actor: actor}); err != nil {
			return err
		}
	}
	_ = c.save(jc, r)
	c.phase(jc, jc, r, PhaseLCopy, 10, "Copying it to this server")
	return c.pullFromStorage(jc, r, local, actor, func(done, total int64) {
		r.BytesDone, r.BytesTotal = done, total
		pct := 10.0
		if total > 0 {
			pct = 10 + 75*float64(min(done, total))/float64(total)
		}
		jc.Progress(pct, fmt.Sprintf("Copying: %s of about %s", humanBytes(done), humanBytes(total)))
	})
}

// requestAgain asks for the cluster workload as it was, after a "make
// local" that gave up before removing it.
func (c *Converter) requestAgain(r *Record, actor cluster.Actor) {
	if !r.WasRunning {
		return
	}
	pl := c.snapshot().Placements[r.Ref()]
	if pl == nil || pl.Requested == cluster.RequestRunning {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := c.propose(ctx, cluster.CmdRequested, state.RequestedSet{Workload: r.Ref(), Generation: pl.Generation, Requested: cluster.RequestRunning}, actor); err != nil {
		c.log().Warn("convert: starting the cluster workload again", "workload", r.Workload, "err", err)
	}
}

// ---- undo and abandon ------------------------------------------------------------------

// UndoParams undo a failed "Make highly available": the cluster copy goes
// (kept aside for the grace period) and this server's copy comes back.
type UndoParams struct {
	Conv  string        `json:"conv"`
	Actor cluster.Actor `json:"actor"`
}

// StartUndo submits an undo; confirm is the workload's name or id.
func (c *Converter) StartUndo(ctx context.Context, p UndoParams, confirm string, userID *int64) (*jobs.Job, error) {
	r, err := c.Get(ctx, p.Conv)
	if err != nil {
		return nil, errors.New("there's no such conversion here")
	}
	if r.Direction != DirHA || r.State != StateFailed {
		return nil, errors.New("only a failed conversion to cluster storage is undone")
	}
	if !confirmed(confirm, r.Name, r.Workload) {
		return nil, errTyped
	}
	return c.Jobs.Submit(ctx, JobUndo, "Undo making "+r.Name+" highly available", p, userID)
}

func (c *Converter) runUndo(jc *jobs.Context) (any, error) {
	var p UndoParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	r, err := c.Get(jc, p.Conv)
	if err != nil {
		return nil, err
	}
	w := r.Ref()
	unlock := jc.Lock(localLock(w))
	defer unlock()
	self, _, err := c.hostCheck()
	if err != nil {
		return nil, err
	}
	err = c.undo(jc, self, r, p.Actor)
	c.audit(p.Actor, "cluster.ha.undo", refString(w), r.ID, err)
	if err != nil {
		r.Problem = "undo: " + err.Error()
		_ = c.save(jc, r)
		return nil, err
	}
	r.State, r.Finished = StateUndone, c.now().UTC()
	_ = c.save(jc, r)
	return map[string]string{"conv": r.ID}, nil
}

func (c *Converter) undo(jc *jobs.Context, self cluster.Node, r *Record, actor cluster.Actor) error {
	w := r.Ref()
	if pl := c.snapshot().Placements[w]; pl != nil {
		if pl.Owner != self.ID && pl.Owner != "" {
			return fmt.Errorf("it is placed on %s now; make it local again from there", pl.Owner)
		}
		if pl.State == cluster.PlacementRunning || pl.State == cluster.PlacementStarting || pl.State == cluster.PlacementMigrating {
			return errors.New("it runs from cluster storage; use Make local again instead")
		}
		jc.Progress(10, "Removing it from the cluster")
		if pl.Requested != cluster.RequestStopped {
			if err := c.propose(jc, cluster.CmdRequested, state.RequestedSet{Workload: w, Generation: pl.Generation, Requested: cluster.RequestStopped}, actor); err != nil {
				return err
			}
		}
		if err := c.waitFor(jc, 5*time.Minute, "stopping it", func(s *cluster.Snapshot) (bool, error) {
			p := s.Placements[w]
			return p == nil || p.State == cluster.PlacementStopped || p.State == cluster.PlacementError || p.State == cluster.PlacementPending, nil
		}); err != nil {
			return err
		}
		_ = c.Storage.Detach(jc, w, false)
		pl = c.snapshot().Placements[w]
		if pl != nil {
			if err := c.propose(jc, cluster.CmdWorkloadRemove, state.WorkloadRemove{Workload: w, Generation: pl.Generation}, actor); err != nil {
				return err
			}
			if c.snapshot().Placements[w] != nil {
				return errors.New("the cluster refused to remove it")
			}
		}
	}
	if r.Options.Storage != nil {
		jc.Progress(40, "Putting the cluster copy aside")
		until := c.now().Add(c.grace()).Unix()
		if err := c.waitFor(jc, 3*time.Minute, "the storage server letting go of it", func(*cluster.Snapshot) (bool, error) {
			_, err := c.Storage.HAPark(jc, storagesvc.HARequest{Workload: w, Pool: r.StoragePool, Confirm: w.ID, KeepUntil: until, Actor: actor})
			return err == nil, nil
		}); err != nil {
			return err
		}
		r.Options.Storage = nil
		_ = c.save(jc, r)
	} else {
		_ = c.Storage.HAAbort(jc, storagesvc.HARequest{Workload: w, Pool: r.StoragePool, Conv: r.ID, Actor: actor})
	}
	if r.Options.ParkedName != "" && r.Options.ParkedSide == string(hacopy.SideLocal) {
		jc.Progress(70, "Putting this server's copy back")
		ref := hacopy.Ref{Kind: w.Kind, ID: w.ID, Pool: r.Options.ParkedPool, Side: hacopy.SideLocal}
		if err := c.Priv.Call(jc, hacopy.OpUnpark, hacopy.UnparkArgs{Ref: ref, Name: r.Options.ParkedName}, nil); err != nil {
			return err
		}
		r.Options.ParkedName = ""
		_ = c.save(jc, r)
	}
	c.restartLocal(r)
	jc.Progress(100, r.Name+" is on this server's own storage again")
	return nil
}

// AbandonParams drop what an unfinished conversion copied so far (its
// incoming copy); nothing else changes.
type AbandonParams struct {
	Conv  string        `json:"conv"`
	Actor cluster.Actor `json:"actor"`
}

// StartAbandon submits abandoning a conversion that hasn't changed
// anything yet but copies.
func (c *Converter) StartAbandon(ctx context.Context, p AbandonParams, confirm string, userID *int64) (*jobs.Job, error) {
	r, err := c.Get(ctx, p.Conv)
	if err != nil {
		return nil, errors.New("there's no such conversion here")
	}
	if r.State != StateFailed {
		return nil, errors.New("only a failed or interrupted conversion is abandoned")
	}
	limit := PhasePark
	list := haPhases
	if r.Direction == DirLocal {
		limit, list = PhaseLRemove, localPhases
	}
	if phaseAt(list, r.Phase) >= phaseAt(list, limit) {
		return nil, errors.New("this conversion has gone too far to abandon; undo or resume it")
	}
	if !confirmed(confirm, r.Name, r.Workload) {
		return nil, errTyped
	}
	return c.Jobs.Submit(ctx, JobAbandon, "Abandon converting "+r.Name, p, userID)
}

func (c *Converter) runAbandon(jc *jobs.Context) (any, error) {
	var p AbandonParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	r, err := c.Get(jc, p.Conv)
	if err != nil {
		return nil, err
	}
	w := r.Ref()
	if r.Direction == DirHA {
		err = c.Storage.HAAbort(jc, storagesvc.HARequest{Workload: w, Pool: r.StoragePool, Conv: r.ID, Actor: p.Actor})
		if err == nil {
			// The conversion's own snapshots on this server go too.
			ref := hacopy.Ref{Kind: w.Kind, ID: w.ID, Pool: r.LocalPool, Side: hacopy.SideLocal}
			for _, s := range []string{"pre", "final"} {
				_ = c.Priv.Call(jc, hacopy.OpSnapDestroy, hacopy.SnapArgs{Ref: ref, Name: snapName(r.ID, s)}, nil)
			}
		}
	} else {
		ref := hacopy.Ref{Kind: w.Kind, ID: w.ID, Pool: r.LocalPool, Side: hacopy.SideLocal}
		err = c.Priv.Call(jc, hacopy.OpAbort, hacopy.AbortArgs{Ref: ref, Conv: r.ID}, nil)
		c.requestAgain(r, p.Actor)
	}
	c.audit(p.Actor, "cluster.ha.abandon", refString(w), r.ID, err)
	if err != nil {
		return nil, err
	}
	r.State, r.Finished = StateAbandoned, c.now().UTC()
	_ = c.save(jc, r)
	return map[string]string{"conv": r.ID}, nil
}
