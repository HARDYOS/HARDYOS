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

// Phases of "Make highly available", in order.
const (
	PhaseCheck    = "check"
	PhaseCopy     = "copy"
	PhaseStop     = "stop"
	PhaseFinal    = "final"
	PhaseAdopt    = "adopt"
	PhasePark     = "park"
	PhaseRegister = "register"
	PhaseAttach   = "attach"
	PhaseStart    = "start"
	PhaseDone     = "done"
)

var haPhases = []string{PhaseCheck, PhaseCopy, PhaseStop, PhaseFinal, PhaseAdopt, PhasePark, PhaseRegister, PhaseAttach, PhaseStart, PhaseDone}

func phaseAt(list []string, p string) int { return slices.Index(list, p) }

// CPU choices of a VM's conversion.
const (
	CPUBaseline = "baseline" // the cluster's CPU model: live moves between different CPUs
	CPUKeep     = "keep"     // the VM's own setting
)

// ToHAParams start (or resume) "Make highly available".
type ToHAParams struct {
	Conv     string              `json:"conv"`
	Workload cluster.WorkloadRef `json:"workload"`
	Priority int                 `json:"priority,omitempty"`
	CPU      string              `json:"cpu,omitempty"`
	Actor    cluster.Actor       `json:"actor"`
}

// Readiness is what "Make highly available" would do, or why it can't.
type Readiness struct {
	Workload    cluster.WorkloadRef `json:"workload"`
	Name        string              `json:"name"`
	Running     bool                `json:"running"`
	StoragePool string              `json:"storagePool"`
	LocalPool   string              `json:"localPool"`
	SizeBytes   int64               `json:"sizeBytes"`
	MemoryMB    int                 `json:"memoryMB"`
	CPUBaseline string              `json:"cpuBaseline,omitempty"`
	CPUModel    string              `json:"cpuModel,omitempty"`
	// Mode is an app's data mode on cluster storage, and why.
	Mode       string   `json:"mode,omitempty"`
	ModeReason string   `json:"modeReason,omitempty"`
	Problems   []string `json:"problems"`
	// Shares are the shared folders an app takes along to the storage
	// server (decision 500); Notes what changes for the people using them.
	Shares []ReadyShare `json:"shares"`
	Notes  []string     `json:"notes"`
	// Open is a conversion of it that failed or was interrupted.
	Open *Record `json:"open,omitempty"`
}

type localInfo struct {
	name      string
	localPool string
	running   bool
	hash      string
	memoryMB  int
	dir       string
	mode      string
	reason    string
	uid       int
	cpuModel  string
	problems  []string
	shares    []apps.HAShare
	held      string // the conversion holding an app ("" none)
}

func (c *Converter) localCheck(ctx context.Context, w cluster.WorkloadRef, storagePool string, setCPU bool, cpuModel string) (*localInfo, error) {
	switch w.Kind {
	case cluster.KindVM:
		var res vms.HACheckResult
		if err := c.Priv.Call(ctx, priv.OpVMsHACheck, vms.HACheckArgs{ID: w.ID, Pool: storagePool, SetCPU: setCPU, CPUModel: cpuModel}, &res); err != nil {
			return nil, err
		}
		return &localInfo{name: res.Name, localPool: res.LocalPool, running: res.State == "running" || res.State == "paused", hash: res.Hash,
			memoryMB: res.MemoryMB, cpuModel: res.CPUModel, problems: res.Problems}, nil
	case cluster.KindApp:
		var res apps.HACheckResult
		if err := c.Priv.Call(ctx, priv.OpAppsHACheck, priv.AppRef{ID: w.ID}, &res); err != nil {
			return nil, err
		}
		return &localInfo{name: res.Name, localPool: res.Pool, running: res.Running, hash: res.Hash, memoryMB: res.MemoryMB, dir: res.Dir,
			mode: res.Mode, reason: res.ModeReason, uid: res.UID, problems: res.Problems, shares: res.Shares, held: res.HeldBy}, nil
	}
	return nil, fmt.Errorf("unknown kind %q", w.Kind)
}

func cpuChoice(snap *cluster.Snapshot, choice string) (bool, string) {
	if choice == CPUKeep || snap.CPUBaseline == "" {
		return false, ""
	}
	return true, snap.CPUBaseline
}

// Check says whether a local workload can be made highly available now.
func (c *Converter) Check(ctx context.Context, w cluster.WorkloadRef, cpu string) (*Readiness, error) {
	res := &Readiness{Workload: w, Problems: []string{}, Shares: []ReadyShare{}, Notes: []string{}}
	self, snap, err := c.hostCheck()
	if err != nil {
		if errors.Is(err, ErrNotMember) {
			return nil, err
		}
		res.Problems = append(res.Problems, err.Error())
		return res, nil
	}
	res.CPUBaseline = snap.CPUBaseline
	if open, err := c.open(ctx, w); err == nil && open != nil {
		res.Open = open
	}
	if p := snap.Placements[w]; p != nil && (res.Open == nil || res.Open.Direction != DirHA) {
		res.Problems = append(res.Problems, "it is a cluster workload already")
		return res, nil
	}
	if o := res.Open; o != nil && o.Direction == DirHA && phaseAt(haPhases, o.Phase) >= phaseAt(haPhases, PhasePark) {
		// This server's copy is put aside already: what is left is the
		// cluster's part, from the record.
		res.Name, res.Running, res.LocalPool, res.StoragePool = o.Name, o.WasRunning, o.LocalPool, o.StoragePool
		res.SizeBytes, res.CPUModel, res.Mode = o.BytesTotal, o.Options.CPUModel, o.Options.Mode
		return res, nil
	}
	if ok, why := state.HAEligible(snap, self.ID); !ok {
		res.Problems = append(res.Problems, "this server "+why)
	}
	if why := c.networkProblem(ctx, w, haPolicy(&Record{}, self.ID)); why != "" {
		res.Problems = append(res.Problems, why)
	}
	pool, err := c.Storage.HAPool(ctx)
	if err != nil {
		res.Problems = append(res.Problems, "cluster storage: "+err.Error())
		return res, nil
	}
	res.StoragePool = pool
	setCPU, model := cpuChoice(snap, cpu)
	li, err := c.localCheck(ctx, w, pool, setCPU, model)
	if err != nil {
		return nil, err
	}
	res.Name, res.Running, res.LocalPool, res.MemoryMB, res.CPUModel = li.name, li.running, li.localPool, li.memoryMB, li.cpuModel
	res.Mode, res.ModeReason = li.mode, li.reason
	held := res.Open != nil && res.Open.Direction == DirHA && len(res.Open.Options.Shares) > 0 && phaseAt(haPhases, res.Open.Phase) > phaseAt(haPhases, PhaseCopy)
	for _, p := range li.problems {
		if held && strings.HasPrefix(p, "shared folder ") {
			continue // held (unmounted) by the open conversion, which lets go of it first
		}
		res.Problems = append(res.Problems, p)
	}
	if probs, notes, ready := c.shareProblems(ctx, w, li); len(ready) > 0 || len(probs) > 0 {
		res.Shares, res.Notes = ready, append(res.Notes, notes...)
		for _, p := range probs {
			if held && strings.HasSuffix(p, " isn't mounted on this server") {
				continue // held by the open conversion; a resume lets go of it first
			}
			res.Problems = append(res.Problems, p)
		}
		for _, s := range ready {
			res.SizeBytes += s.SizeBytes
		}
	}
	if w.Kind == cluster.KindApp {
		if u, ok := snap.AppUIDs[w.ID]; ok && u != li.uid {
			res.Problems = append(res.Problems, fmt.Sprintf("the cluster gave %s another user id (%d)", w.ID, u))
		}
		for other, u := range snap.AppUIDs {
			if other != w.ID && u == li.uid {
				res.Problems = append(res.Problems, fmt.Sprintf("its user id %d is %s's in the cluster", u, other))
			}
		}
	}
	var t hacopy.Tree
	if err := c.Priv.Call(ctx, hacopy.OpTree, hacopy.TreeArgs{Ref: hacopy.Ref{Kind: w.Kind, ID: w.ID, Pool: li.localPool, Side: hacopy.SideLocal}}, &t); err == nil {
		res.SizeBytes += treeBytes(&t)
		if p := snapsProblem(&t); p != "" {
			res.Problems = append(res.Problems, p)
		}
	} else if res.Open == nil || phaseAt(haPhases, res.Open.Phase) < phaseAt(haPhases, PhasePark) {
		res.Problems = append(res.Problems, "its storage: "+err.Error())
	}
	return res, nil
}

// StartToHA submits (or resumes) a conversion; confirm is the workload's
// name or id, typed.
func (c *Converter) StartToHA(ctx context.Context, p ToHAParams, confirm string, userID *int64) (*jobs.Job, error) {
	rd, err := c.Check(ctx, p.Workload, p.CPU)
	if err != nil {
		return nil, err
	}
	if rd.Open != nil && rd.Open.Direction == DirHA {
		p.Conv = rd.Open.ID
	} else if rd.Open != nil {
		return nil, fmt.Errorf("a conversion of %s back to a server's own storage isn't finished; resume or undo it first", p.Workload.ID)
	}
	resuming := rd.Open != nil && phaseAt(haPhases, rd.Open.Phase) >= phaseAt(haPhases, PhasePark)
	if !resuming {
		// The network's refusal on its own (the API's 409 "network").
		if self, err := c.Cluster.Self(); err == nil {
			if err := c.networkRefusal(ctx, p.Workload, haPolicy(&Record{Options: Options{Priority: p.Priority}}, self.ID)); err != nil {
				return nil, err
			}
		}
	}
	if len(rd.Problems) > 0 && !resuming {
		return nil, &Refused{Problems: rd.Problems}
	}
	if !confirmed(confirm, rd.Name, p.Workload.ID) && !(resuming && confirmed(confirm, rd.Open.Name, p.Workload.ID)) {
		return nil, errTyped
	}
	if p.Conv == "" {
		p.Conv = newID()
	}
	name := rd.Name
	if name == "" && rd.Open != nil {
		name = rd.Open.Name
	}
	return c.Jobs.Submit(ctx, JobToHA, "Make "+name+" highly available", p, userID)
}

// Refused lists why a conversion can't start.
type Refused struct{ Problems []string }

func (e *Refused) Error() string {
	if len(e.Problems) == 1 {
		return e.Problems[0]
	}
	out := "it can't be made highly available now:"
	for _, p := range e.Problems {
		out += " " + p + ";"
	}
	return out[:len(out)-1]
}

func (c *Converter) runToHA(jc *jobs.Context) (any, error) {
	var p ToHAParams
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
		r = &Record{ID: p.Conv, Direction: DirHA, Kind: w.Kind, Workload: w.ID, Phase: PhaseCheck, Actor: p.Actor.Name,
			Started: c.now().UTC(), Options: Options{Priority: p.Priority, CPU: p.CPU}}
	} else if r.Direction != DirHA || r.Ref() != w {
		return nil, errors.New("that conversion is of something else")
	}
	r.State, r.Problem, r.JobID = StateRunning, "", jc.ID()
	_ = c.save(jc, r)
	res, err := c.toHA(jc, self, snap, r, p)
	if err != nil {
		c.audit(p.Actor, "cluster.ha.convert", refString(w), "phase "+r.Phase, err)
		c.alert("cluster.ha.convert", notify.SeverityWarning, r.Name+" wasn't made highly available",
			"The conversion stopped at "+r.Phase+": "+err.Error()+". Resume it or undo it in Cluster › Workloads and HA.")
		return nil, c.fail(jc, r, err)
	}
	c.audit(p.Actor, "cluster.ha.convert", refString(w), "done", nil)
	return res, nil
}

// ToHAResult reports a finished conversion.
type ToHAResult struct {
	Conv       string `json:"conv"`
	Generation uint64 `json:"generation"`
	Started    bool   `json:"started"`
	KeptCopy   string `json:"keptCopy"`
}

func (c *Converter) toHA(jc *jobs.Context, self cluster.Node, snap *cluster.Snapshot, r *Record, p ToHAParams) (*ToHAResult, error) {
	w := r.Ref()
	at := phaseAt(haPhases, r.Phase)
	if at < 0 {
		at = 0
	}
	local := hacopy.Ref{Kind: w.Kind, ID: w.ID, Pool: r.LocalPool, Side: hacopy.SideLocal}
	setCPU, model := r.Options.SetCPU, r.Options.CPUModel
	if r.Options.Generation != 0 && snap.Placements[w] == nil {
		// It was registered once and the cluster has forgotten it since:
		// registering it again would start a second life of it.
		return nil, errors.New("it left the cluster after it was registered; undo this conversion")
	}
	if at < phaseAt(haPhases, PhasePark) {
		// Checks, then the copy while it runs.
		c.phase(jc, jc, r, PhaseCheck, 1, "Checking")
		if snap.Placements[w] != nil {
			return nil, errors.New("it is a cluster workload already")
		}
		if r.Options.Storage != nil {
			// An earlier attempt's adopted copy is still there (its park
			// failed): put aside before copying afresh.
			if _, err := c.Storage.HAPark(jc, c.asideRequest(jc, r, p.Actor)); err != nil {
				return nil, fmt.Errorf("putting the earlier attempt's cluster copy aside: %w", err)
			}
			r.Options.Storage = nil
			_ = c.save(jc, r)
		}
		if len(r.Options.Shares) > 0 {
			// Shared folders the earlier attempt had set up there go aside
			// too (what they were still receiving stays for the resume), and
			// this server's are let go of: this attempt holds them again
			// before its own final snapshot.
			if err := c.asideShares(jc, r, p.Actor, false); err != nil {
				return nil, fmt.Errorf("putting the earlier attempt's shared folders aside: %w", err)
			}
			c.releaseShares(r)
		}
		if ok, why := state.HAEligible(snap, self.ID); !ok {
			return nil, errors.New("this server " + why)
		}
		if err := c.networkRefusal(jc, w, haPolicy(r, self.ID)); err != nil {
			return nil, err
		}
		if r.StoragePool == "" {
			pool, err := c.Storage.HAPool(jc)
			if err != nil {
				return nil, err
			}
			r.StoragePool = pool
		}
		if !r.Options.SetCPU && r.Options.CPUModel == "" {
			setCPU, model = cpuChoice(snap, p.CPU)
			r.Options.SetCPU, r.Options.CPUModel = setCPU, model
		}
		li, err := c.localCheck(jc, w, r.StoragePool, setCPU, model)
		if err != nil {
			return nil, err
		}
		if len(li.problems) > 0 {
			return nil, &Refused{Problems: li.problems}
		}
		if probs, _, _ := c.shareProblems(jc, w, li); len(probs) > 0 {
			return nil, &Refused{Problems: probs}
		}
		if err := c.planShares(jc, r, li); err != nil {
			return nil, err
		}
		r.Name, r.LocalPool, r.Options.Hash, r.Options.Dir, r.Options.Mode, r.Options.UID = li.name, li.localPool, li.hash, li.dir, li.mode, li.uid
		// Every attempt, before its hold (decision 509): running now counts;
		// stopped counts unless this conversion stopped it (it still holds
		// the app, or, a VM, an earlier attempt of it got past the copy).
		switch {
		case li.running || at <= phaseAt(haPhases, PhaseCopy):
			r.WasRunning = li.running
		case w.Kind == cluster.KindApp && li.held != r.ID:
			r.WasRunning = false // let go of since, and off: it stays off
		}
		local.Pool = r.LocalPool
		if w.Kind == cluster.KindApp {
			if err := c.claimUID(jc, w.ID, li.uid, p.Actor); err != nil {
				return nil, err
			}
		}
		r.Options.Attempt++
		attempt := r.Options.Attempt
		_ = c.save(jc, r)
		report := func(lo, hi float64, what string) func(done, total int64) {
			return func(done, total int64) {
				r.BytesDone, r.BytesTotal = done, total
				pct := lo
				if total > 0 {
					pct = lo + (hi-lo)*float64(min(done, total))/float64(total)
				}
				jc.Progress(pct, fmt.Sprintf("%s: %s of about %s", what, humanBytes(done), humanBytes(total)))
			}
		}
		if li.running {
			c.phase(jc, jc, r, PhaseCopy, 3, "Copying while it runs")
			if err := c.ensureSnap(jc, local, snapName(r.ID, "pre", attempt)); err != nil {
				return nil, err
			}
			if err := c.sendToStorage(jc, r, local, p.Actor, report(3, 40, "Copying while it runs")); err != nil {
				return nil, err
			}
			// Its shared folders, while people still use them.
			if err := c.copyShares(jc, r, "pre", attempt, p.Actor, report, 40, 60); err != nil {
				return nil, err
			}
		}
		// Again before it goes down (the copy may have taken hours): past
		// the stop, the workload is registered with HA on.
		if err := c.networkRefusal(jc, w, haPolicy(r, self.ID)); err != nil {
			return nil, err
		}
		c.phase(jc, jc, r, PhaseStop, 61, "Shutting it down")
		if err := c.stopLocal(jc, w); err != nil {
			return nil, err
		}
		if w.Kind == cluster.KindApp {
			// From the final snapshot until its folder is parked (or the
			// conversion gives up and starts it again) nothing starts it or
			// writes its folder: no containers, read-only, starts refused.
			// The state it was in before is recorded with the hold (decision
			// 504): whatever ends the hold starts it again only if it ran.
			if err := c.Priv.Call(jc, priv.OpAppsHAHold, apps.HAHoldArgs{ID: w.ID, Conv: r.ID, WasRunning: r.WasRunning}, nil); err != nil {
				c.restartLocal(r)
				return nil, fmt.Errorf("holding it for the move: %w", err)
			}
			// Its shared folders too: from their final snapshot nobody
			// writes them here (file sharing lets go, read-only, unmounted).
			if err := c.holdShares(jc, r); err != nil {
				c.restartLocal(r)
				return nil, err
			}
		}
		c.phase(jc, jc, r, PhaseFinal, 63, "Copying what changed (it is off now)")
		err = func() error {
			if err := c.ensureSnap(jc, local, snapName(r.ID, "final", attempt)); err != nil {
				return err
			}
			if err := c.sendToStorage(jc, r, local, p.Actor, report(63, 75, "Final copy")); err != nil {
				return err
			}
			return c.copyShares(jc, r, "final", attempt, p.Actor, report, 75, 85)
		}()
		if err != nil {
			// Nothing local changed: it runs again as it did.
			c.restartLocal(r)
			return nil, err
		}
		c.phase(jc, jc, r, PhaseAdopt, 86, "Setting it up on cluster storage")
		ws, err := c.Storage.HAAdopt(jc, storagesvc.HARequest{Workload: w, Pool: r.StoragePool, Conv: r.ID, Actor: p.Actor})
		if err != nil {
			c.restartLocal(r)
			return nil, err
		}
		r.Options.Storage = ws
		_ = c.save(jc, r)
		if err := c.adoptShares(jc, r, p.Actor); err != nil {
			// Set up held there, never shared: the next attempt (or Abandon)
			// puts them aside.
			c.restartLocal(r)
			return nil, err
		}
		c.phase(jc, jc, r, PhasePark, 88, "Putting this server's copy aside")
	}
	if r.Phase == PhasePark || r.Options.ParkedName == "" {
		// Park the local copy (or find it parked: a resume after root's
		// answer, or hardyd itself, was lost). Past this phase only once
		// the parked copy's name is saved.
		if err := c.parkLocal(jc, r, local, p.Actor); err != nil {
			return nil, err
		}
	}
	if r.Options.Storage == nil {
		return nil, errors.New("the conversion lost what the storage server set up; undo it")
	}
	if phaseAt(haPhases, r.Phase) <= phaseAt(haPhases, PhaseAttach) {
		release := c.Specs.Hold(w)
		err := c.register(jc, self, r, p)
		release()
		if err != nil {
			return nil, err
		}
	}
	return c.startHA(jc, self, r, p)
}

// snapsProblem: a dataset has more snapshots than a conversion carries.
func snapsProblem(t *hacopy.Tree) string {
	if child, n, over := hacopy.TooManySnaps(t); over {
		return fmt.Sprintf("%s has %d snapshots; a conversion carries at most %d, so delete some first", childName(child), n, hacopy.MaxSnaps)
	}
	return ""
}

// asideConv marks a cluster copy one attempt put aside (not the
// conversion's own mark: a later park of the copy that stays must never
// find this one in its place).
func asideConv(r *Record) string { return fmt.Sprintf("%sx%d", r.ID, r.Options.Attempt) }

// parkLocal parks this server's copy, refusing when it was written after
// the final snapshot (it ran again: the cluster copy is stale). Root
// answers with the copy this conversion parked when it is parked already,
// and puts everything back when its park fails. On any failure the
// conversion goes back before the park: the local copy runs again if it
// ran, and the adopted cluster copy (never registered, never exported) is
// put aside for an hour, so a retry copies afresh.
func (c *Converter) parkLocal(jc *jobs.Context, r *Record, local hacopy.Ref, actor cluster.Actor) error {
	w := r.Ref()
	// Its shared folders first (each refused when written after its final
	// snapshot; a failure puts back the ones parked), then its own folder.
	var err error
	if len(r.Options.Shares) > 0 {
		refs := make([]hacopy.Ref, len(r.Options.Shares))
		pools, perr := c.sharePools(jc, r)
		err = perr
		for i := range r.Options.Shares {
			refs[i] = r.Options.Shares[i].ref(pools[r.Options.Shares[i].ID], hacopy.SideLocal)
		}
		if err == nil {
			err = c.parkShares(jc, r, refs)
		}
	}
	var pr hacopy.ParkResult
	if err == nil {
		args := hacopy.ParkArgs{Ref: local, Confirm: w.ID, Conv: r.ID, Since: snapName(r.ID, "final", r.Options.Attempt), RefuseChanged: true}
		err = c.Priv.Call(jc, hacopy.OpPark, args, &pr)
		if err != nil {
			// Root may have parked it and its answer got lost: look (only
			// look) for the copy this conversion parked.
			if found, ok := c.parkedHere(context.WithoutCancel(jc), w, r.ID); ok {
				pr, err = *found, nil
			}
		}
		if err == nil && pr.Name == "" {
			err = errors.New("root didn't name the parked copy")
		}
		if err != nil {
			// The shared folders parked above come back (still held).
			if uerr := c.unparkShares(context.WithoutCancel(jc), r); uerr != nil {
				err = errors.Join(err, &stuckParked{uerr})
			}
		}
	}
	var stuck *stuckParked
	if errors.As(err, &stuck) {
		// A shared folder parked here couldn't be put back: nothing goes
		// back before the park (the app stays held, the copies there stay
		// as they are), so the folder is never parked on both servers;
		// Resume carries on, Undo puts everything back (decision 508).
		r.Phase = PhasePark
		_ = c.save(context.WithoutCancel(jc), r)
		return fmt.Errorf("putting this server's copy aside (a shared folder couldn't be put back: resume or undo): %w", err)
	}
	if err != nil {
		ctx := context.WithoutCancel(jc)
		r.Phase = PhaseAdopt
		c.restartLocal(r)
		if _, perr := c.Storage.HAPark(ctx, c.asideRequest(ctx, r, actor)); perr == nil {
			r.Options.Storage = nil
		} else {
			c.log().Warn("convert: putting an unregistered cluster copy aside", "workload", w.ID, "err", perr)
		}
		if serr := c.asideShares(ctx, r, actor, false); serr != nil {
			c.log().Warn("convert: putting unregistered shared folders aside", "workload", w.ID, "err", serr)
		}
		_ = c.save(ctx, r)
		return fmt.Errorf("putting this server's copy aside: %w", err)
	}
	r.Options.ParkedPool, r.Options.ParkedName, r.Options.ParkedSide = pr.Pool, pr.Name, string(hacopy.SideLocal)
	r.Phase = PhaseRegister
	return c.save(jc, r)
}

// asideRequest puts aside the cluster copy this conversion adopted (its
// mark expected, never another server's conversion's copy) under the
// attempt's own mark. It expires in an hour only when this server's copy
// is seen to be there as the workload; otherwise it is kept until an
// administrator deletes it (it may be the only copy).
func (c *Converter) asideRequest(ctx context.Context, r *Record, actor cluster.Actor) storagesvc.HARequest {
	w := r.Ref()
	req := storagesvc.HARequest{Workload: w, Pool: r.StoragePool, Confirm: w.ID, Conv: asideConv(r), Expect: r.ID, Actor: actor}
	var t hacopy.Tree
	local := hacopy.Ref{Kind: w.Kind, ID: w.ID, Pool: r.LocalPool, Side: hacopy.SideLocal}
	if c.Priv.Call(ctx, hacopy.OpTree, hacopy.TreeArgs{Ref: local}, &t) == nil && t.Exists {
		req.KeepUntil = c.now().Add(time.Hour).Unix()
	}
	return req
}

// parkedHere finds this server's copy of w that conversion conv parked.
func (c *Converter) parkedHere(ctx context.Context, w cluster.WorkloadRef, conv string) (*hacopy.ParkResult, bool) {
	var l struct {
		Parked []hacopy.Parked `json:"parked"`
	}
	if err := c.Priv.Call(ctx, hacopy.OpParkedList, struct{}{}, &l); err != nil {
		return nil, false
	}
	for _, p := range l.Parked {
		if p.Conv == conv && p.Kind == w.Kind && p.ID == w.ID && p.Side == hacopy.SideLocal {
			return &hacopy.ParkResult{Pool: p.Pool, Name: p.Name, Existing: true}, true
		}
	}
	return nil, false
}

// claimUID gives an app its own user id cluster-wide (storage.appuid).
func (c *Converter) claimUID(ctx context.Context, app string, uid int, actor cluster.Actor) error {
	snap := c.snapshot()
	if u, ok := snap.AppUIDs[app]; ok {
		if u != uid {
			return fmt.Errorf("the cluster gave %s another user id (%d)", app, u)
		}
		return nil
	}
	if err := c.propose(ctx, cluster.CmdAppUID, state.AppUIDBody{App: app, UID: uid}, actor); err != nil {
		return err
	}
	if u := c.snapshot().AppUIDs[app]; u != uid {
		return fmt.Errorf("the cluster didn't give %s its user id %d (another app has it)", app, uid)
	}
	return nil
}

// ensureSnap takes a conversion snapshot unless the source has it.
func (c *Converter) ensureSnap(ctx context.Context, ref hacopy.Ref, name string) error {
	var t hacopy.Tree
	if err := c.Priv.Call(ctx, hacopy.OpTree, hacopy.TreeArgs{Ref: ref}, &t); err != nil {
		return err
	}
	for _, d := range t.Datasets {
		if d.Child != "" {
			continue
		}
		for _, s := range d.Snaps {
			if s.Name == name {
				return nil
			}
		}
	}
	return c.Priv.Call(ctx, hacopy.OpSnapshot, hacopy.SnapArgs{Ref: ref, Name: name}, nil)
}

// stopLocal shuts a local VM down (the guest, up to three minutes) or
// stops a local app.
func (c *Converter) stopLocal(ctx context.Context, w cluster.WorkloadRef) error {
	if w.Kind == cluster.KindApp {
		return c.Priv.Call(ctx, priv.OpAppsStop, priv.AppRef{ID: w.ID}, nil)
	}
	var v vms.VM
	if err := c.Priv.Call(ctx, priv.OpVMsGet, priv.VMRef{ID: w.ID}, &v); err != nil {
		return err
	}
	if v.State == "stopped" || v.State == "crashed" {
		return nil
	}
	if err := c.Priv.Call(ctx, priv.OpVMsStop, vms.StopArgs{ID: w.ID}, nil); err != nil {
		return err
	}
	deadline := c.now().Add(3 * time.Minute)
	for {
		if err := c.Priv.Call(ctx, priv.OpVMsGet, priv.VMRef{ID: w.ID}, &v); err == nil && (v.State == "stopped" || v.State == "crashed") {
			return nil
		}
		if c.now().After(deadline) {
			return errors.New("it didn't shut down within 3 minutes; shut it down from inside, then resume")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.poll()):
		}
	}
}

// releaseLocal ends an app's hold for this conversion (apps.ha.hold) and
// says what it found: whether the conversion held it, and whether it ran
// before (the state recorded with the hold, decision 504).
func (c *Converter) releaseLocal(r *Record) *apps.HAHoldResult {
	if r.Kind != cluster.KindApp {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var res apps.HAHoldResult
	if err := c.Priv.Call(ctx, priv.OpAppsHAHold, apps.HAHoldArgs{ID: r.Workload, Conv: r.ID, Release: true}, &res); err != nil {
		c.log().Warn("convert: letting go of a local app's hold", "app", r.Workload, "err", err)
		return nil
	}
	return &res
}

// restartLocal starts the local copy again when the conversion stopped it
// and gave up before parking it (ending an app's hold first); true when it
// started.
func (c *Converter) restartLocal(r *Record) bool {
	c.releaseShares(r)
	if held := c.releaseLocal(r); held != nil && held.Held && held.WasRunning {
		r.WasRunning = true
	}
	if !r.WasRunning {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var err error
	if r.Kind == cluster.KindApp {
		err = c.Priv.Call(ctx, priv.OpAppsStart, priv.AppRef{ID: r.Workload}, nil)
	} else {
		err = c.Priv.Call(ctx, priv.OpVMsStart, priv.VMRef{ID: r.Workload}, nil)
	}
	if err != nil {
		c.log().Warn("convert: starting the local copy again", "workload", r.Workload, "err", err)
	}
	return err == nil
}

// register adds the cluster workload (generation 1, this server), attaches
// its storage here, writes the converted settings and approves them.
func (c *Converter) register(jc *jobs.Context, self cluster.Node, r *Record, p ToHAParams) error {
	w := r.Ref()
	if r.Options.ParkedName == "" || r.Options.ParkedSide != string(hacopy.SideLocal) {
		// Never two copies: the cluster workload exists only once this
		// server's copy is known to be parked.
		return errors.New("this server's copy isn't recorded as put aside; resume the conversion")
	}
	snap := c.snapshot()
	pl := snap.Placements[w]
	if pl == nil && r.Options.Generation != 0 {
		return errors.New("it left the cluster after it was registered; undo this conversion")
	}
	if len(r.Options.Shares) > 0 {
		// This server's copies are put aside: the storage server's are the
		// only ones now. They are shared from there and used in the
		// cluster, and mounted here before the app is attached.
		c.phase(jc, jc, r, PhaseRegister, 89, "Sharing its shared folders from the storage server")
		if err := c.shareIntoCluster(jc, r, p.Actor); err != nil {
			return err
		}
	}
	if pl == nil {
		c.phase(jc, jc, r, PhaseRegister, 90, "Registering it in the cluster")
		body := state.WorkloadAdd{Workload: w, Name: r.Name, Owner: self.ID, Requested: cluster.RequestStopped,
			HA: haPolicy(r, self.ID), Storage: *r.Options.Storage, SpecHash: r.Options.Hash}
		if err := c.propose(jc, cluster.CmdWorkloadAdd, body, p.Actor); err != nil {
			return err
		}
		snap = c.snapshot()
		pl = snap.Placements[w]
		if pl == nil {
			return errors.New("the cluster refused to register it (see the server's log)")
		}
	}
	if pl.Owner != self.ID {
		// Ownership lost mid-register (this server failed over meanwhile):
		// it is requested stopped, and until its owner rewrites its
		// settings for cluster storage they don't hash to the approved
		// ones, so no server starts it. The conversion stops here; move it
		// back to this server and resume, or undo it once it's here.
		return fmt.Errorf("the cluster placed it on %s meanwhile; move it back to this server, then resume", pl.Owner)
	}
	r.Options.Generation = pl.Generation
	c.phase(jc, jc, r, PhaseAttach, 92, "Attaching cluster storage")
	if err := c.waitFor(jc, 2*time.Minute, "the storage server granting it to this server", func(s *cluster.Snapshot) (bool, error) {
		g, p := s.Grants[w], s.Placements[w]
		if p == nil {
			return false, errors.New("it is no longer a cluster workload")
		}
		return g != nil && g.Applied && g.Generation == p.Generation && slices.Contains(g.Nodes, self.ID), nil
	}); err != nil {
		return err
	}
	snap = c.snapshot()
	pl, g := snap.Placements[w], snap.Grants[w]
	if _, err := c.Storage.Attach(jc, pl.Storage, *g); err != nil {
		return err
	}
	switch w.Kind {
	case cluster.KindVM:
		var h priv.SpecHashResult
		args := vms.ClusterAdoptArgs{HACheckArgs: vms.HACheckArgs{ID: w.ID, Pool: r.StoragePool, SetCPU: r.Options.SetCPU, CPUModel: r.Options.CPUModel},
			Hash: pl.SpecHash}
		if err := c.Priv.Call(jc, priv.OpVMsClusterAdopt, args, &h); err != nil {
			return err
		}
	case cluster.KindApp:
		var h priv.SpecHashResult
		if err := c.Priv.Call(jc, priv.OpAppsClusterAdopt, apps.HAAdoptArgs{ID: w.ID, From: r.Options.Dir, Shares: sharePaths(r)}, &h); err != nil {
			return err
		}
		// The rewritten compose file (its folder on cluster storage) is
		// what the administrator's conversion approves.
		if err := c.Specs.ApproveSpec(jc, w, p.Actor); err != nil {
			return err
		}
		if r.Options.Mode == apps.StorageModeBlock && pl.Storage.Mode != cluster.StorageBlock {
			jc.Progress(94, "Moving its database to a block volume")
			_ = c.Storage.Detach(jc, w, false)
			if _, err := c.Storage.SwitchAppMode(jc, storagesvc.ModeRequest{App: w.ID, To: cluster.StorageBlock, Confirm: w.ID, RemoveOld: true, Actor: p.Actor}); err != nil {
				return fmt.Errorf("moving its data to a block volume: %w", err)
			}
		}
	}
	return nil
}

// startHA starts the cluster workload (if the local one ran) and gives the
// kept copy its grace period once it runs.
func (c *Converter) startHA(jc *jobs.Context, self cluster.Node, r *Record, p ToHAParams) (*ToHAResult, error) {
	w := r.Ref()
	res := &ToHAResult{Conv: r.ID, KeptCopy: r.Options.ParkedPool + "/" + r.Options.ParkedName}
	pl := c.snapshot().Placements[w]
	if pl == nil {
		return nil, errors.New("it is no longer a cluster workload")
	}
	res.Generation = pl.Generation
	if !r.WasRunning {
		// It was off: it stays off. The kept copy's grace period starts
		// once it first runs from cluster storage (Cleanup).
		r.Options.AwaitStart = true
		r.State, r.Phase, r.Finished = StateDone, PhaseDone, c.now().UTC()
		_ = c.save(jc, r)
		jc.Progress(100, r.Name+" is on cluster storage (off, as it was)")
		return res, nil
	}
	c.phase(jc, jc, r, PhaseStart, 95, "Starting it on cluster storage")
	if pl.Requested != cluster.RequestRunning {
		if err := c.propose(jc, cluster.CmdRequested, state.RequestedSet{Workload: w, Generation: pl.Generation, Requested: cluster.RequestRunning}, p.Actor); err != nil {
			return nil, err
		}
	}
	err := c.waitFor(jc, 10*time.Minute, "starting it on cluster storage", func(s *cluster.Snapshot) (bool, error) {
		p := s.Placements[w]
		if p == nil {
			return false, errors.New("it is no longer a cluster workload")
		}
		if p.State == cluster.PlacementError {
			return false, fmt.Errorf("it didn't start from cluster storage: %s", p.Problem)
		}
		return p.State == cluster.PlacementRunning && p.Owner == self.ID, nil
	})
	if err != nil {
		return nil, err
	}
	res.Started = true
	if err := c.keepFor(jc, hacopy.SideLocal, r.Options.ParkedPool, r.Options.ParkedName, c.grace(), p.Actor); err != nil {
		c.log().Warn("convert: setting the kept copy's grace period", "err", err)
	}
	c.keepShares(jc, r, p.Actor)
	r.State, r.Phase, r.Finished = StateDone, PhaseDone, c.now().UTC()
	_ = c.save(jc, r)
	c.alert("cluster.ha.convert", notify.SeverityInfo, r.Name+" is highly available",
		"It runs from cluster storage now. This server's copy is kept for "+c.grace().String()+" (Cluster › Workloads and HA › Kept copies).")
	jc.Progress(100, r.Name+" runs from cluster storage")
	return res, nil
}

// keepFor gives a parked copy its expiry (0: kept until deleted by hand).
func (c *Converter) keepFor(ctx context.Context, side hacopy.Side, pool, name string, d time.Duration, actor cluster.Actor) error {
	if name == "" {
		return nil
	}
	var until int64
	if d > 0 {
		until = c.now().Add(d).Unix()
	}
	if side == hacopy.SideCluster {
		return c.Storage.HAParkedKeep(ctx, storagesvc.HARequest{Pool: pool, Name: name, KeepUntil: until, Actor: actor})
	}
	return c.Priv.Call(ctx, hacopy.OpParkedKeep, hacopy.ParkedKeepArgs{Pool: pool, Name: name, KeepUntil: until}, nil)
}
