package convert

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
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
		if open.Name != "" {
			name = open.Name
		}
	}
	if !confirmed(confirm, name, w.ID) {
		return nil, errTyped
	}
	if p.Conv == "" {
		if err := c.localTarget(ctx, w, p.Pool); err != nil {
			return nil, err
		}
		if w.Kind == cluster.KindApp {
			// Its shared folders moved to the storage server with it
			// (decision 500); a server's own app can't use them there.
			l, err := c.appShares(ctx, w.ID)
			if err != nil {
				return nil, fmt.Errorf("can't tell whether %s uses shared folders: %w", name, err)
			}
			if len(l) > 0 {
				ids := make([]string, 0, len(l))
				for _, s := range l {
					ids = append(ids, s.ID)
				}
				return nil, fmt.Errorf("%s uses shared folders that are the storage server's now (%s); it stays highly available (take them away from it first to make it local)", name, strings.Join(ids, ", "))
			}
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
		if pl == nil && (!r.Options.Removed || r.Options.RemovedGen != r.Options.Generation) {
			// Gone, but not through this conversion (another server made
			// it local, or it was removed): this copy isn't its latest.
			return errors.New("the cluster no longer has it, and this conversion didn't remove it (another server made it local, or it was removed); this copy isn't used")
		}
		if pl != nil {
			if pl.Generation != r.Options.Generation || !pl.Changed.Equal(r.Options.Changed) || pl.Requested != cluster.RequestStopped {
				c.requestAgain(r, actor)
				r.Phase = PhaseLStop
				return errors.New("it changed in the cluster while it was copied; try again")
			}
			// Saved before the removal is proposed, so a resume after an
			// interruption knows the cluster forgot it through this
			// conversion (while the cluster still has it, the checks above
			// run again).
			r.Options.Removed, r.Options.RemovedGen = true, pl.Generation
			if err := c.save(jc, r); err != nil {
				c.requestAgain(r, actor)
				return err
			}
			err := c.propose(jc, cluster.CmdWorkloadRemove, state.WorkloadRemove{Workload: w, Generation: pl.Generation}, actor)
			if err != nil && c.snapshot().Placements[w] != nil {
				// The removal's outcome isn't known (it may commit later):
				// the record keeps it as this conversion's, so a resume
				// that finds the workload gone goes on; one that finds it
				// still there checks and removes it again.
				return fmt.Errorf("removing it from the cluster (resume to carry on): %w", err)
			}
			if err == nil && c.snapshot().Placements[w] != nil {
				// Applied, and refused.
				r.Options.Removed, r.Options.RemovedGen = false, 0
				_ = c.save(jc, r)
				c.requestAgain(r, actor)
				return errors.New("the cluster refused to remove it (see the server's log)")
			}
		}
	}
	// From here on only forward: the cluster no longer has it.
	if phaseAt(localPhases, r.Phase) <= phaseAt(localPhases, PhaseLPark) {
		c.phase(jc, jc, r, PhaseLPark, 88, "Putting the cluster copy aside")
		err := c.waitFor(jc, 3*time.Minute, "the storage server letting go of it", func(*cluster.Snapshot) (bool, error) {
			pr, err := c.Storage.HAPark(jc, storagesvc.HARequest{Workload: w, Pool: r.StoragePool, Confirm: w.ID, Conv: r.ID, Actor: actor})
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
	if r.WasRunning {
		// It runs from this server's storage: the cluster copy's grace
		// period starts now.
		if err := c.keepFor(jc, hacopy.SideCluster, r.Options.ParkedPool, r.Options.ParkedName, c.grace(), actor); err != nil {
			c.log().Warn("convert: setting the cluster copy's grace period", "err", err)
			r.Options.AwaitStart = true
		}
	} else {
		// Off, as it was: the grace period starts once it first ran here.
		r.Options.AwaitStart = true
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
	// Each attempt its own snapshot: after a failed attempt the workload
	// may have run again (requestAgain).
	r.Options.Attempt++
	final := snapName(r.ID, "final", r.Options.Attempt)
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
	// This server's copy back first, and seen to be there, before the
	// cluster copy is touched: if it can't come back, nothing else
	// changes. Its shared folders come back with it (decision 503), once
	// the storage server's copies of them are out of the cluster and put
	// aside (never two copies anyone can write; putting aside deletes
	// nothing, and one the storage server shared, which may have been
	// written there, is kept until an administrator deletes it).
	if len(r.Options.Shares) > 0 {
		shared := false
		for _, s := range r.Options.Shares {
			shared = shared || s.Released
		}
		if err := c.asideShares(jc, r, actor, true); err != nil {
			_ = c.save(jc, r)
			return fmt.Errorf("putting its shared folders' cluster copies aside: %w", err)
		}
		if shared {
			r.Options.ClusterChanged = true
		}
		_ = c.save(jc, r)
	}
	if err := c.unparkShares(jc, r); err != nil {
		return err
	}
	for i := range r.Options.Shares {
		if s := &r.Options.Shares[i]; !c.localShareThere(jc, s) {
			return fmt.Errorf("this server's shared folder %s isn't here; the cluster copies are left as they are", s.Name)
		}
	}
	if err := c.putLocalBack(jc, r); err != nil {
		return err
	}
	// This server's copy is the workload again (the cluster no longer has
	// it): it runs as it did, whatever becomes of the cluster copy.
	c.releaseLocal(r)
	started := c.restartLocal(r)
	// The cluster copy is put aside with no expiry: it may have run (it
	// is newer than this server's then), and even if not, it is deleted
	// only once this server's copy ran again (Cleanup).
	req := storagesvc.HARequest{Workload: w, Pool: r.StoragePool, Confirm: w.ID, Conv: r.ID,
		Since: snapName(r.ID, "final", r.Options.Attempt), Actor: actor}
	parked := func(pr *hacopy.ParkResult) {
		r.Options.ParkedPool, r.Options.ParkedName, r.Options.ParkedSide = pr.Pool, pr.Name, string(hacopy.SideCluster)
		r.Options.Storage = nil
		// Changed since the final snapshot, or it may have run from there:
		// kept until an administrator deletes it.
		r.Options.ClusterChanged = r.Options.ClusterChanged || pr.Changed || (r.WasRunning && phaseAt(haPhases, r.Phase) >= phaseAt(haPhases, PhaseStart))
		r.Options.AwaitStart = !r.Options.ClusterChanged
		_ = c.save(jc, r)
	}
	if r.Options.Storage != nil {
		jc.Progress(60, "Putting the cluster copy aside")
		var pr *hacopy.ParkResult
		if err := c.waitFor(jc, 3*time.Minute, "the storage server letting go of it", func(*cluster.Snapshot) (bool, error) {
			var err error
			pr, err = c.Storage.HAPark(jc, req)
			return err == nil, nil
		}); err != nil {
			return err
		}
		parked(pr)
	} else {
		// One this conversion adopted and lost track of (its answer was
		// lost), if any; then what it was still receiving.
		req.Expect = r.ID
		if pr, err := c.Storage.HAPark(jc, req); err == nil {
			parked(pr)
		}
		_ = c.Storage.HAAbort(jc, storagesvc.HARequest{Workload: w, Pool: r.StoragePool, Conv: r.ID, Actor: actor})
	}
	if started && r.Options.AwaitStart {
		if err := c.keepFor(jc, hacopy.SideCluster, r.Options.ParkedPool, r.Options.ParkedName, c.grace(), actor); err == nil {
			r.Options.AwaitStart = false
			_ = c.save(jc, r)
			c.keepShares(jc, r, actor)
		}
	}
	if r.Options.ClusterChanged {
		c.alert("cluster.ha.undo", notify.SeverityWarning, r.Name+"'s cluster copy is kept",
			"It may have changed on cluster storage after this server's copy was put aside. That copy is kept until you delete it (Cluster › Workloads and HA › Kept copies).")
	}
	jc.Progress(100, r.Name+" is on this server's own storage again")
	return nil
}

// putLocalBack puts this server's parked copy back (found by the record,
// or by the conversion's mark when the record lost it), and checks that
// the workload's own datasets are there.
func (c *Converter) putLocalBack(jc *jobs.Context, r *Record) error {
	w := r.Ref()
	pool, name := r.Options.ParkedPool, r.Options.ParkedName
	if name == "" || r.Options.ParkedSide != string(hacopy.SideLocal) {
		pool, name = "", ""
		if found, ok := c.parkedHere(jc, w, r.ID); ok {
			pool, name = found.Pool, found.Name
		}
	}
	if name != "" {
		jc.Progress(40, "Putting this server's copy back")
		ref := hacopy.Ref{Kind: w.Kind, ID: w.ID, Pool: pool, Side: hacopy.SideLocal}
		var ur hacopy.UnparkResult
		if err := c.Priv.Call(jc, hacopy.OpUnpark, hacopy.UnparkArgs{Ref: ref, Name: name}, &ur); err != nil {
			return fmt.Errorf("putting this server's copy back: %w", err)
		}
		if ur.Held && ur.WasRunning {
			// The hold recorded that it ran before (decision 504).
			r.WasRunning = true
		}
		r.Options.ParkedPool, r.Options.ParkedName, r.Options.ParkedSide = "", "", ""
		_ = c.save(jc, r)
	}
	var t hacopy.Tree
	local := hacopy.Ref{Kind: w.Kind, ID: w.ID, Pool: r.LocalPool, Side: hacopy.SideLocal}
	if err := c.Priv.Call(jc, hacopy.OpTree, hacopy.TreeArgs{Ref: local}, &t); err != nil || !t.Exists {
		return fmt.Errorf("this server's copy of %s isn't here (%v); the cluster copy is left as it is", r.Name, err)
	}
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
	unlock := jc.Lock(localLock(w))
	defer unlock()
	if r.Direction == DirHA {
		// A copy this conversion adopted (never registered, so never
		// exported) is put aside for an hour; this server's copy is the
		// workload and stays as it is.
		_, perr := c.Storage.HAPark(jc, storagesvc.HARequest{Workload: w, Pool: r.StoragePool, Confirm: w.ID, Conv: r.ID, Expect: r.ID,
			KeepUntil: c.now().Add(time.Hour).Unix(), Actor: p.Actor})
		if perr == nil || r.Options.Storage == nil {
			r.Options.Storage = nil
			err = c.Storage.HAAbort(jc, storagesvc.HARequest{Workload: w, Pool: r.StoragePool, Conv: r.ID, Actor: p.Actor})
		} else {
			err = fmt.Errorf("putting the copy it set up on cluster storage aside: %w", perr)
		}
		if err == nil && len(r.Options.Shares) > 0 {
			// Its shared folders' copies there too: adopted ones (held, never
			// shared) put aside for an hour, what was still arriving dropped.
			if serr := c.asideShares(jc, r, p.Actor, true); serr != nil {
				err = serr
			}
		}
		if err == nil && w.Kind == cluster.KindApp && c.snapshot().Placements[w] == nil {
			if u, ok := c.snapshot().AppUIDs[w.ID]; ok && u == r.Options.UID {
				if uerr := c.propose(jc, cluster.CmdAppUID, state.AppUIDBody{App: w.ID, UID: u, Release: true}, p.Actor); uerr != nil {
					c.log().Warn("convert: releasing an abandoned app's cluster user id", "app", w.ID, "err", uerr)
				}
			}
		}
		if err == nil {
			// The app is this server's again: its hold ends, and its shared
			// folders' holds. It starts again when the hold recorded that it
			// ran before the conversion stopped it (decision 504): a
			// conversion that crashed after the stop leaves it held, and
			// only the hold knows.
			c.releaseShares(r)
			if held := c.releaseLocal(r); held != nil && held.Held && held.WasRunning {
				if serr := c.Priv.Call(jc, priv.OpAppsStart, priv.AppRef{ID: w.ID}, nil); serr != nil {
					c.log().Warn("convert: starting an abandoned conversion's app again", "app", w.ID, "err", serr)
					c.alert("cluster.ha.abandon", notify.SeverityWarning, r.Name+" didn't start again",
						"Its conversion was abandoned, but starting it again failed: "+serr.Error()+". Start it from the App Store.")
				}
			}
			// The conversion's own snapshots on this server go too.
			ref := hacopy.Ref{Kind: w.Kind, ID: w.ID, Pool: r.LocalPool, Side: hacopy.SideLocal}
			for a := 1; a <= r.Options.Attempt; a++ {
				for _, s := range []string{"pre", "final"} {
					_ = c.Priv.Call(jc, hacopy.OpSnapDestroy, hacopy.SnapArgs{Ref: ref, Name: snapName(r.ID, s, a)}, nil)
				}
			}
			c.destroyShareSnaps(jc, r)
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
