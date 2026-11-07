package runtime

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

// Cluster is what the reconciler uses of part A's Membership.
type Cluster interface {
	Self() (cluster.Node, error)
	State() cluster.State
	Quorate() (bool, time.Time)
	Propose(ctx context.Context, t cluster.CommandType, body any, actor cluster.Actor) (uint64, error)
}

// Reconciler keeps the cluster workloads on this node in line with the
// applied placements (decision 357):
//
//   - anything running here that the state doesn't let this node run (no
//     placement, another owner, another generation, this node fenced) is
//     stopped by force and its storage detached, before anything else;
//   - a workload placed here and asked to run is attached (only with the
//     applied grant of its generation) and started, and reported running;
//   - one that crashed is restarted in place up to its policy's restarts
//     per hour, then reported in error (the HA coordinator relocates it);
//   - a fenced node that has stopped everything asks to rejoin.
//
// Nothing new starts without quorum; a node that lost quorum leaves its
// non-HA workloads running (the fence agent stops the HA ones).
type Reconciler struct {
	Cluster  Cluster
	Attacher cluster.StorageAttacher
	Runtimes []cluster.Runtime
	// BootID is this boot's id (/proc/sys/kernel/random/boot_id). Nothing
	// starts here until the state records it for this node (member.update
	// at every hardyd start), so a fence always knows this boot.
	BootID func() string
	// FenceReady says whether the fence agent has armed the watchdog: an
	// HA workload starts only then (nil: always).
	FenceReady func() bool
	// CleanFence says whether the fence agent obeyed the node's fence of
	// an epoch itself (node.rejoin's Clean; nil: never).
	CleanFence func(epoch uint64) bool
	Now        func() time.Time
	Log        *slog.Logger

	mu        sync.Mutex
	busy      map[cluster.WorkloadRef]int
	leases    map[cluster.WorkloadRef]time.Time
	restarts  map[cluster.WorkloadRef][]time.Time
	started   map[cluster.WorkloadRef]uint64 // generation we last started or adopted
	migrated  map[cluster.WorkloadRef]uint64 // migration generations this node took part in
	reported  map[cluster.WorkloadRef]string // "<gen>/<state>" last proposed
	rejoinTry time.Time
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reconciler) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.Default()
}

func (r *Reconciler) init() {
	if r.busy == nil {
		r.busy = map[cluster.WorkloadRef]int{}
		r.restarts = map[cluster.WorkloadRef][]time.Time{}
		r.started = map[cluster.WorkloadRef]uint64{}
		r.migrated = map[cluster.WorkloadRef]uint64{}
		r.reported = map[cluster.WorkloadRef]string{}
	}
}

// Hold keeps the reconciler's hands off w while a move or migration step
// runs here; the returned func lets go.
func (r *Reconciler) Hold(w cluster.WorkloadRef) func() {
	r.mu.Lock()
	r.init()
	r.busy[w]++
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		r.busy[w]--
		if r.busy[w] <= 0 {
			delete(r.busy, w)
		}
		r.mu.Unlock()
	}
}

// TookPart records that this node is a node of w's live migration at
// generation gen, so the VM it runs (or receives) is adopted when the
// migration's grant collapses to this node.
func (r *Reconciler) TookPart(w cluster.WorkloadRef, gen uint64) {
	r.mu.Lock()
	r.init()
	r.migrated[w] = gen
	r.mu.Unlock()
}

// Started records that w runs here under gen (a move step started it).
func (r *Reconciler) Started(w cluster.WorkloadRef, gen uint64) {
	r.mu.Lock()
	r.init()
	r.started[w] = gen
	r.mu.Unlock()
}

// HoldFor keeps the reconciler's hands off w for d (a move run from
// another node: it lapses by itself if that node goes away).
func (r *Reconciler) HoldFor(w cluster.WorkloadRef, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.init()
	if r.leases == nil {
		r.leases = map[cluster.WorkloadRef]time.Time{}
	}
	r.leases[w] = r.now().Add(d)
}

// Release ends a HoldFor.
func (r *Reconciler) Release(w cluster.WorkloadRef) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.leases, w)
}

func (r *Reconciler) isBusy(w cluster.WorkloadRef) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if until, ok := r.leases[w]; ok {
		if r.now().Before(until) {
			return true
		}
		delete(r.leases, w)
	}
	return r.busy[w] > 0
}

func (r *Reconciler) runtime(k cluster.WorkloadKind) cluster.Runtime {
	for _, rt := range r.Runtimes {
		if rt.Kind() == k {
			return rt
		}
	}
	return nil
}

// Local lists what runs (or is attached) here, from every runtime.
func (r *Reconciler) Local(ctx context.Context) ([]cluster.WorkloadStatus, error) {
	var out []cluster.WorkloadStatus
	for _, rt := range r.Runtimes {
		l, err := rt.Status(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, l...)
	}
	return out, nil
}

// Run reconciles every few seconds and on every state change.
func (r *Reconciler) Run(ctx context.Context, events <-chan cluster.Event) error {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		r.Step(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		case <-events:
		}
	}
}

func actor(self cluster.NodeID) cluster.Actor {
	return cluster.Actor{Kind: "system", Name: "HardyOS", Via: self}
}

// adoptable: w runs here at gen local; the placement now names this node
// at p.Generation right after a live migration this node took part in.
func (r *Reconciler) adoptable(s *cluster.Snapshot, self cluster.NodeID, w cluster.WorkloadRef, local uint64) bool {
	p := s.Placements[w]
	g := s.Grants[w]
	if p == nil || g == nil || p.Owner != self || g.Mode != cluster.GrantExclusive || !g.Applied || g.Generation != p.Generation {
		return false
	}
	r.mu.Lock()
	mig, ok := r.migrated[w]
	r.mu.Unlock()
	return ok && mig+1 == p.Generation && (local == mig || local+1 == mig)
}

// migratingSource: w runs here under the generation just before a live
// migration's (move.begin raised it) and this node is the migration's
// source: the VM keeps running while the mover's hold is on its way.
func migratingSource(s *cluster.Snapshot, self cluster.NodeID, w cluster.WorkloadRef, local uint64) bool {
	p, g := s.Placements[w], s.Grants[w]
	return p != nil && g != nil && g.Mode == cluster.GrantMigration && p.Owner == self &&
		p.State == cluster.PlacementMigrating && local+1 == p.Generation && slices.Contains(g.Nodes, self)
}

// Step runs one round.
func (r *Reconciler) Step(ctx context.Context) {
	r.mu.Lock()
	r.init()
	r.mu.Unlock()
	self, err := r.Cluster.Self()
	if err != nil {
		return
	}
	if self.Role != cluster.RoleCompute {
		return
	}
	s := r.Cluster.State().Snapshot()
	quorate, _ := r.Cluster.Quorate()
	local, err := r.Local(ctx)
	if err != nil {
		r.log().Warn("cluster: listing local workloads", "err", err)
		return
	}
	node := s.Nodes[self.ID]
	fenced := node == nil || node.State == cluster.NodeDead || node.State == cluster.NodeFenced ||
		node.State == cluster.NodeRemoved
	running := map[cluster.WorkloadRef]cluster.WorkloadStatus{}

	// 1. Stop whatever this node may not run.
	for _, st := range local {
		if !st.Running && !st.Paused {
			continue
		}
		w := st.Workload
		if r.isBusy(w) && !fenced {
			// A move or migration step owns it now (never on a fenced
			// node: that one stops everything).
			running[w] = st
			continue
		}
		allowed := !fenced && st.Problem == "" && (state.MayRun(s, self.ID, w, st.Generation) == nil || migratingSource(s, self.ID, w, st.Generation))
		if !allowed && !fenced && st.Problem == "" && r.adoptable(s, self.ID, w, st.Generation) {
			if r.adopt(ctx, s, self.ID, w) == nil {
				st.Generation = s.Placements[w].Generation
				running[w] = st
				continue
			}
		}
		if !allowed && !quorate && !fenced && st.Problem == "" {
			// Without quorum the state may be behind: a workload the last
			// applied state lets this node run keeps running (checked
			// above); one it doesn't is stopped anyway.
			r.log().Warn("cluster: stopping a workload the cluster doesn't place here (no quorum)", "workload", w.ID)
		}
		if allowed {
			running[w] = st
			continue
		}
		r.log().Warn("cluster: stopping a stale workload", "workload", string(w.Kind)+":"+w.ID, "generation", st.Generation, "fenced", fenced)
		r.forceStop(ctx, w)
	}

	if fenced {
		r.fencedNode(ctx, s, self, local)
		return
	}
	if !quorate || (node.State != cluster.NodeActive && node.State != cluster.NodeMaintenance && node.State != cluster.NodeRejoining) {
		return
	}
	bootKnown := r.BootID == nil || r.BootID() == "" || node.BootID == r.BootID()

	// 2. Workloads placed here.
	for _, p := range state.SortedPlacements(s) {
		w := p.Workload
		if p.Owner != self.ID || r.isBusy(w) || p.Target != "" {
			continue
		}
		switch p.State {
		case cluster.PlacementMigrating, cluster.PlacementMoving, cluster.PlacementRecovering, cluster.PlacementPending:
			continue
		}
		st, isRunning := running[w]
		isRunning = isRunning && st.Generation == p.Generation
		switch {
		case p.Requested == cluster.RequestRunning && p.State == cluster.PlacementError:
			// Gave up; the coordinator relocates it or the person retries.
		case p.Requested == cluster.RequestRunning && !isRunning:
			if !bootKnown {
				// The announcer hasn't recorded this boot yet: a fence
				// declared now would remember the previous one.
				continue
			}
			r.startHere(ctx, s, self.ID, p)
		case p.Requested == cluster.RequestRunning && isRunning && p.State != cluster.PlacementRunning:
			r.report(ctx, self.ID, p, cluster.PlacementRunning, "")
		case p.Requested == cluster.RequestStopped && isRunning:
			rt := r.runtime(w.Kind)
			if rt == nil {
				continue
			}
			if err := rt.Stop(ctx, w, cluster.StopGraceful); err != nil {
				r.log().Warn("cluster: stopping a workload", "workload", w.ID, "err", err)
				continue
			}
			r.detach(ctx, w, false)
			r.report(ctx, self.ID, p, cluster.PlacementStopped, "")
		case p.Requested == cluster.RequestStopped && !isRunning && p.State != cluster.PlacementStopped:
			r.report(ctx, self.ID, p, cluster.PlacementStopped, "")
		}
	}

	// 3. Storage attached for workloads no longer placed here.
	if r.Attacher != nil {
		if atts, err := r.Attacher.Attached(ctx); err == nil {
			for _, a := range atts {
				p := s.Placements[a.Workload]
				if r.isBusy(a.Workload) {
					continue
				}
				if p != nil && (p.Owner == self.ID || p.Target == self.ID) {
					continue
				}
				if _, run := running[a.Workload]; run {
					continue
				}
				r.detach(ctx, a.Workload, false)
			}
		}
	}
}

// startHere attaches and starts a workload placed here, counting restarts.
func (r *Reconciler) startHere(ctx context.Context, s *cluster.Snapshot, self cluster.NodeID, p *cluster.Placement) {
	w := p.Workload
	g := s.Grants[w]
	if g == nil || !g.Applied || g.Generation != p.Generation || !slices.Contains(g.Nodes, self) {
		return // the storage server hasn't applied the grant yet
	}
	if state.MayRunFor(s, self, w, p.Generation, state.IntentStart) != nil {
		return // only the owner with an exclusive grant starts from cold
	}
	rt := r.runtime(w.Kind)
	if rt == nil {
		return
	}
	// A workload that was running under this generation and isn't any more
	// crashed (or was killed): count it.
	r.mu.Lock()
	wasStarted := r.started[w] == p.Generation
	r.mu.Unlock()
	if wasStarted || p.State == cluster.PlacementRunning {
		if n := r.countRestart(w); p.HA.Enabled && n > p.HA.MaxRestarts {
			r.report(ctx, self, p, cluster.PlacementError,
				"it stopped more than "+itoa(p.HA.MaxRestarts)+" times in an hour")
			return
		} else if !p.HA.Enabled && n > 10 {
			r.report(ctx, self, p, cluster.PlacementError, "it keeps stopping")
			return
		}
	}
	if r.Attacher == nil {
		return
	}
	att, err := r.Attacher.Attach(ctx, p.Storage, *g)
	if err != nil {
		r.log().Warn("cluster: attaching storage", "workload", w.ID, "err", err)
		return
	}
	if att.Generation != p.Generation {
		r.log().Warn("cluster: the attachment is of another generation", "workload", w.ID, "have", att.Generation, "want", p.Generation)
		return
	}
	if p.State != cluster.PlacementStarting && p.State != cluster.PlacementRunning {
		r.report(ctx, self, p, cluster.PlacementStarting, "")
	}
	if p.HA.Enabled && r.FenceReady != nil && !r.FenceReady() {
		// The fence agent arms the watchdog for a workload placed here
		// first (it sees it starting); the start follows next round.
		return
	}
	if err := rt.Start(ctx, w, att); err != nil {
		r.log().Warn("cluster: starting a workload", "workload", w.ID, "err", err)
		r.countRestart(w)
		return
	}
	r.Started(w, p.Generation)
	r.report(ctx, self, p, cluster.PlacementRunning, "")
}

func (r *Reconciler) adopt(ctx context.Context, s *cluster.Snapshot, self cluster.NodeID, w cluster.WorkloadRef) error {
	p, g := s.Placements[w], s.Grants[w]
	if r.Attacher == nil {
		return errors.New("no attacher")
	}
	att, err := r.Attacher.Attach(ctx, p.Storage, *g)
	if err != nil {
		return err
	}
	if att.Generation != p.Generation {
		return errors.New("attached under another generation")
	}
	r.Started(w, p.Generation)
	r.mu.Lock()
	delete(r.migrated, w)
	r.mu.Unlock()
	r.log().Info("cluster: kept a migrated VM under its new generation", "workload", w.ID, "generation", p.Generation)
	if p.State != cluster.PlacementRunning {
		r.report(ctx, self, p, cluster.PlacementRunning, "")
	}
	return nil
}

func (r *Reconciler) forceStop(ctx context.Context, w cluster.WorkloadRef) {
	rt := r.runtime(w.Kind)
	if rt == nil {
		return
	}
	if err := rt.Stop(ctx, w, cluster.StopForce); err != nil {
		r.log().Error("cluster: a stale workload couldn't be stopped", "workload", w.ID, "err", err)
		return
	}
	r.mu.Lock()
	delete(r.started, w)
	r.mu.Unlock()
	r.detach(ctx, w, true)
}

func (r *Reconciler) detach(ctx context.Context, w cluster.WorkloadRef, force bool) {
	if r.Attacher == nil {
		return
	}
	if err := r.Attacher.Detach(ctx, w, force); err != nil {
		r.log().Warn("cluster: detaching storage", "workload", w.ID, "err", err)
	}
}

// fencedNode: everything was stopped above; detach what is left and, with
// quorum, ask to rejoin once the fence is confirmed.
func (r *Reconciler) fencedNode(ctx context.Context, s *cluster.Snapshot, self cluster.Node, local []cluster.WorkloadStatus) {
	if r.Attacher != nil {
		if atts, err := r.Attacher.Attached(ctx); err == nil {
			for _, a := range atts {
				r.detach(ctx, a.Workload, true)
			}
		}
	}
	quorate, _ := r.Cluster.Quorate()
	node := s.Nodes[self.ID]
	f := s.Fences[self.ID]
	if !quorate || node == nil || node.State != cluster.NodeFenced || f == nil || !f.Confirmed || r.BootID == nil {
		return
	}
	// Only once nothing cluster runs here.
	again, err := r.Local(ctx)
	if err != nil {
		return
	}
	for _, st := range again {
		if st.Running || st.Paused {
			return
		}
	}
	r.mu.Lock()
	if r.now().Sub(r.rejoinTry) < 30*time.Second {
		r.mu.Unlock()
		return
	}
	r.rejoinTry = r.now()
	r.mu.Unlock()
	// Clean only when the fence agent itself obeyed this fence (an
	// isolated node may then rejoin on the same boot).
	clean := r.CleanFence != nil && r.CleanFence(node.FenceEpoch)
	body := state.NodeRejoinBody{Node: self.ID, Epoch: node.FenceEpoch, BootID: r.BootID(), Clean: clean}
	if _, err := r.Cluster.Propose(ctx, cluster.CmdNodeRejoin, body, actor(self.ID)); err != nil {
		r.log().Info("cluster: rejoining isn't possible yet", "err", err)
		return
	}
	r.log().Info("cluster: asked to rejoin after a fence", "epoch", node.FenceEpoch)
}

func (r *Reconciler) countRestart(w cluster.WorkloadRef) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	l := r.restarts[w][:0]
	for _, t := range r.restarts[w] {
		if now.Sub(t) < time.Hour {
			l = append(l, t)
		}
	}
	l = append(l, now)
	r.restarts[w] = l
	return len(l)
}

// report proposes the owner's report of p, once per placement change (a
// proposal in flight isn't repeated; a later change of the placement, say
// a new request, makes it count again).
func (r *Reconciler) report(ctx context.Context, self cluster.NodeID, p *cluster.Placement, st cluster.PlacementState, problem string) {
	if p.State == st && p.Problem == problem {
		return
	}
	w, gen := p.Workload, p.Generation
	key := itoa(int(gen)) + "/" + string(st) + "/" + problem + "/" + p.Changed.String()
	r.mu.Lock()
	if r.reported[w] == key {
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	body := state.WorkloadStateReport{Workload: w, Generation: gen, State: st, Problem: problem}
	if _, err := r.Cluster.Propose(ctx, cluster.CmdWorkloadState, body, actor(self)); err != nil {
		r.log().Warn("cluster: reporting a workload's state", "workload", w.ID, "state", st, "err", err)
		return
	}
	r.mu.Lock()
	r.reported[w] = key
	r.mu.Unlock()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
