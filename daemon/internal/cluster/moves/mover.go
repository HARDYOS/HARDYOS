package moves

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/placement"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

// Cluster is what the mover uses of part A's Membership.
type Cluster interface {
	Self() (cluster.Node, error)
	State() cluster.State
	Leader() (cluster.NodeID, bool)
	Health(ctx context.Context) ([]cluster.Health, error)
	Propose(ctx context.Context, t cluster.CommandType, body any, actor cluster.Actor) (uint64, error)
	WaitApplied(ctx context.Context, index uint64) error
}

// Progress reports how far a move got (the job's progress).
type Progress func(pct float64, msg string)

// Mover implements cluster.Mover.
type Mover struct {
	Cluster   Cluster
	Peers     cluster.PeerClient
	Scheduler *placement.Scheduler
	// GrantWait bounds the wait for the storage node to apply a grant
	// (default 60 s); Poll is how often the state is checked (default
	// 250 ms).
	GrantWait time.Duration
	Poll      time.Duration
	// HoldFor is how long the source and destination keep their hands off
	// the workload while a move runs (default 15 minutes).
	HoldFor time.Duration
	Log     *slog.Logger
	Now     func() time.Time
}

var _ cluster.Mover = (*Mover)(nil)

func (m *Mover) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func (m *Mover) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Mover) poll() time.Duration {
	if m.Poll > 0 {
		return m.Poll
	}
	return 250 * time.Millisecond
}

// Options are what a person adds to a move.
type Options struct {
	// Confirm is the workload's display name, typed: needed to move a VM
	// with passthrough devices, or to start a workload of a server that is
	// down somewhere else.
	Confirm  string
	Progress Progress
}

// Move implements cluster.Mover (no confirmation: forced moves refuse).
func (m *Mover) Move(ctx context.Context, r cluster.MoveRequest, actor cluster.Actor) (*cluster.MoveResult, error) {
	return m.MoveWith(ctx, r, actor, Options{})
}

func (m *Mover) propose(ctx context.Context, t cluster.CommandType, body any, actor cluster.Actor) error {
	idx, err := m.Cluster.Propose(ctx, t, body, actor)
	if err != nil {
		return err
	}
	return m.Cluster.WaitApplied(ctx, idx)
}

func (m *Mover) call(ctx context.Context, node cluster.NodeID, path string, in any) error {
	var res StepResult
	if err := m.Peers.Call(ctx, node, http.MethodPost, cluster.PeerPathPrefix+path, in, &res); err != nil {
		return err
	}
	if !res.OK {
		return errors.New(res.Message)
	}
	return nil
}

// requirements asks the owner what the workload needs.
func (m *Mover) requirements(ctx context.Context, owner cluster.NodeID, w cluster.WorkloadRef) (*cluster.Requirements, json.RawMessage, error) {
	var res struct {
		Requirements cluster.Requirements `json:"requirements"`
		Devices      json.RawMessage      `json:"devices,omitempty"`
	}
	q := url.Values{"kind": {string(w.Kind)}, "id": {w.ID}}
	if err := m.Peers.Call(ctx, owner, http.MethodGet, cluster.PeerPathPrefix+PathRequirements+"?"+q.Encode(), nil, &res); err != nil {
		return nil, nil, err
	}
	return &res.Requirements, res.Devices, nil
}

func (m *Mover) progress(o Options, pct float64, msg string) {
	if o.Progress != nil {
		o.Progress(pct, msg)
	}
}

// MoveWith moves a workload (a job on this node).
func (m *Mover) MoveWith(ctx context.Context, r cluster.MoveRequest, actor cluster.Actor, o Options) (*cluster.MoveResult, error) {
	s := m.Cluster.State().Snapshot()
	p, ok := s.Placements[r.Workload]
	if !ok {
		return nil, fmt.Errorf("%s isn't a cluster workload", r.Workload.ID)
	}
	if r.Generation != 0 && p.Generation != r.Generation {
		return nil, cluster.ErrStaleGeneration
	}
	if p.Target != "" {
		return nil, fmt.Errorf("%s is already moving to %s", p.Name, p.Target)
	}
	if r.Mode == "" {
		r.Mode = cluster.MoveOffline
	}
	// The owner is down: "start elsewhere" (a forced, confirmed move).
	if p.Owner == "" || ownerDown(s, p.Owner) {
		return m.startElsewhere(ctx, s, p, r, actor, o)
	}
	health, err := m.Cluster.Health(ctx)
	if err != nil {
		return nil, err
	}
	req, devs, err := m.requirements(ctx, p.Owner, r.Workload)
	if err != nil {
		return nil, fmt.Errorf("asking %s what %s needs: %w", p.Owner, p.Name, err)
	}
	pinned := p.Pinned || len(req.Devices) > 0
	if pinned {
		if r.Mode == cluster.MoveLive {
			return nil, fmt.Errorf("%w: %s has passthrough devices, which pin it to %s", ErrNotLive, p.Name, p.Owner)
		}
		if r.To == "" {
			return nil, errors.New("choose the server to move it to: it has passthrough devices, which that server must have too")
		}
		if o.Confirm != p.Name {
			return nil, fmt.Errorf("%w: type %s to move it with its passthrough devices to %s", ErrConfirm, p.Name, r.To)
		}
	}
	to := r.To
	if to == "" {
		to, _, err = m.Scheduler.Place(s, health, r.Workload, *req, []cluster.NodeID{p.Owner})
		if err != nil {
			return nil, err
		}
	} else if why := m.Scheduler.Fits(s, health, r.Workload, *req, to); why != "" {
		return nil, fmt.Errorf("%s can't take %s: %s", to, p.Name, why)
	}
	if to == p.Owner {
		return nil, errors.New("it's already there")
	}
	m.log().Info("moves: starting", "workload", r.Workload.ID, "from", p.Owner, "to", to, "mode", r.Mode)
	if r.Mode == cluster.MoveLive {
		if r.Workload.Kind != cluster.KindVM {
			return nil, fmt.Errorf("%w: only VMs move live", ErrNotLive)
		}
		if p.State != cluster.PlacementRunning {
			return nil, fmt.Errorf("%w: it isn't running (move it offline)", ErrNotLive)
		}
		return m.live(ctx, s, p, to, actor, o)
	}
	return m.offline(ctx, p, to, req, devs, pinned, actor, o)
}

func ownerDown(s *cluster.Snapshot, n cluster.NodeID) bool {
	node, ok := s.Nodes[n]
	if !ok {
		return true
	}
	switch node.State {
	case cluster.NodeDead, cluster.NodeFenced, cluster.NodeRejoining, cluster.NodeRemoved:
		return true
	}
	return false
}

// waitPlacement polls the applied state until ok says so or the wait ends.
func (m *Mover) waitPlacement(ctx context.Context, w cluster.WorkloadRef, d time.Duration, ok func(p *cluster.Placement, g *cluster.Grant) bool) (*cluster.Placement, error) {
	deadline := m.now().Add(d)
	for {
		s := m.Cluster.State().Snapshot()
		p := s.Placements[w]
		if p != nil && ok(p, s.Grants[w]) {
			return p, nil
		}
		if m.now().After(deadline) {
			return p, errors.New("timed out")
		}
		select {
		case <-ctx.Done():
			return p, ctx.Err()
		case <-time.After(m.poll()):
		}
	}
}

func (m *Mover) grantWait() time.Duration {
	if m.GrantWait > 0 {
		return m.GrantWait
	}
	return time.Minute
}

func (m *Mover) holdFor() time.Duration {
	if m.HoldFor > 0 {
		return m.HoldFor
	}
	return 15 * time.Minute
}

func (m *Mover) hold(ctx context.Context, w cluster.WorkloadRef, nodes ...cluster.NodeID) func() {
	for _, n := range nodes {
		if err := m.call(ctx, n, PathHold, HoldRequest{Workload: w, Seconds: int(m.holdFor() / time.Second)}); err != nil {
			m.log().Warn("moves: holding", "node", n, "err", err)
		}
	}
	return func() {
		for _, n := range nodes {
			_ = m.call(context.WithoutCancel(ctx), n, PathHold, HoldRequest{Workload: w})
		}
	}
}

// offline: stop on A, hand over in the log, the storage node regrants, B
// attaches and starts.
func (m *Mover) offline(ctx context.Context, p *cluster.Placement, to cluster.NodeID, req *cluster.Requirements, devs json.RawMessage, pinned bool, actor cluster.Actor, o Options) (*cluster.MoveResult, error) {
	from, w, gen := p.Owner, p.Workload, p.Generation
	wasRunning := p.Requested == cluster.RequestRunning
	// The move is in the log first: every step on the two servers is
	// accepted only from the member whose move.begin this is.
	if err := m.propose(ctx, cluster.CmdMoveBegin, state.MoveBegin{Workload: w, Generation: gen, To: to, Mode: cluster.MoveOffline}, actor); err != nil {
		return nil, err
	}
	fail := func(err error) (*cluster.MoveResult, error) {
		// The workload stays on A (its reconciler starts it again if it
		// should run).
		_ = m.propose(context.WithoutCancel(ctx), cluster.CmdMoveEnd, state.MoveEnd{Workload: w, Generation: gen, OK: false, Problem: err.Error()}, actor)
		return nil, err
	}
	m.progress(o, 5, "Getting "+string(to)+" ready")
	prep := PrepareRequest{Workload: w, Mode: cluster.MoveOffline, Images: req.Images}
	if pinned {
		prep.Devices = devs
	}
	if err := m.call(ctx, to, PathPrepare, prep); err != nil {
		return fail(fmt.Errorf("%s isn't ready for %s: %w", to, p.Name, err))
	}
	release := m.hold(ctx, w, from, to)
	defer release()
	started := m.now()
	m.progress(o, 15, "Stopping "+p.Name+" on "+string(from))
	if err := m.call(ctx, from, PathStop, StepRequest{Workload: w, Generation: gen}); err != nil {
		return fail(fmt.Errorf("stopping it on %s: %w", from, err))
	}
	if _, err := m.waitPlacement(ctx, w, m.grantWait(), func(p *cluster.Placement, _ *cluster.Grant) bool {
		return p.Generation == gen && p.State == cluster.PlacementStopped
	}); err != nil {
		return fail(fmt.Errorf("%s didn't report it stopped: %w", from, err))
	}
	m.progress(o, 40, "Handing it over to "+string(to))
	next := cluster.PlacementStopped
	if wasRunning {
		next = cluster.PlacementStarting
	}
	reason := "move"
	if pinned {
		reason = "move-confirmed"
	}
	if err := m.propose(ctx, cluster.CmdPlacementSet, state.PlacementSet{Workload: w, Expected: gen, Owner: to, State: next, Reason: reason}, actor); err != nil {
		return fail(err)
	}
	newGen := gen + 1
	m.progress(o, 55, "Waiting for the storage server to give "+string(to)+" its storage")
	if _, err := m.waitPlacement(ctx, w, m.grantWait(), func(p *cluster.Placement, g *cluster.Grant) bool {
		return p.Generation == newGen && g != nil && g.Generation == newGen && g.Applied
	}); err != nil {
		m.endAfterHandover(ctx, w, newGen, actor, "the storage server hasn't given "+string(to)+" the storage yet")
		return nil, fmt.Errorf("it's now placed on %s, but the storage server hasn't granted its storage there yet (%v); it starts once it does", to, err)
	}
	if w.Kind == cluster.KindApp {
		// The destination fetched the publishing settings from the source
		// while the move was in progress; they take effect there now.
		if err := m.call(ctx, to, PathPublishImport, PublishConfig{App: w.ID}); err != nil {
			m.log().Warn("moves: handing over the app's publishing", "app", w.ID, "err", err)
		}
	}
	m.progress(o, 70, "Starting it on "+string(to))
	if err := m.call(ctx, to, PathStart, StepRequest{Workload: w, Generation: newGen, Start: wasRunning}); err != nil {
		m.endAfterHandover(ctx, w, newGen, actor, err.Error())
		return nil, fmt.Errorf("it's now on %s but didn't start there: %w (Retry, or move it back)", to, err)
	}
	m.endAfterHandover(ctx, w, newGen, actor, "")
	m.progress(o, 100, "Moved to "+string(to))
	return &cluster.MoveResult{Workload: w, From: from, To: to, Mode: cluster.MoveOffline, Downtime: m.now().Sub(started), Generation: newGen}, nil
}

// endAfterHandover: placement.set already cleared Target; nothing to end
// in the log. It records a problem for the UI when there is one.
func (m *Mover) endAfterHandover(ctx context.Context, w cluster.WorkloadRef, gen uint64, actor cluster.Actor, problem string) {
	if problem != "" {
		m.log().Warn("moves: after the hand-over", "workload", w.ID, "generation", gen, "problem", problem)
	}
}

// NewToken makes a migration token.
func NewToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// live migrates a running VM: two-node grant, both attach, the
// destination admits it, the source sends it, the grant collapses.
func (m *Mover) live(ctx context.Context, s *cluster.Snapshot, p *cluster.Placement, to cluster.NodeID, actor cluster.Actor, o Options) (*cluster.MoveResult, error) {
	from, w, gen := p.Owner, p.Workload, p.Generation
	dest := s.Nodes[to]
	if dest == nil || !dest.Addresses.Storage.IsValid() {
		return nil, fmt.Errorf("%s has no storage network address", to)
	}
	if !s.StorageSubnet.IsValid() || !s.StorageSubnet.Contains(dest.Addresses.Storage) {
		return nil, fmt.Errorf("%s's storage address isn't on the cluster's storage network", to)
	}
	m.progress(o, 5, "Giving "+string(to)+" the VM's storage as well")
	if err := m.propose(ctx, cluster.CmdMoveBegin, state.MoveBegin{Workload: w, Generation: gen, To: to, Mode: cluster.MoveLive}, actor); err != nil {
		return nil, err
	}
	release := m.hold(ctx, w, from, to)
	defer release()
	mig := gen + 1
	abort := func(cause error) (*cluster.MoveResult, error) {
		owner, err := m.ResolveMigration(context.WithoutCancel(ctx), w, mig, from, to, actor, "migration-failed")
		if err != nil {
			return nil, fmt.Errorf("%w; ending the migration failed too (the HA coordinator ends it once it can ask both servers): %v", cause, err)
		}
		return nil, fmt.Errorf("%w (it runs on %s)", cause, owner)
	}
	if _, err := m.waitPlacement(ctx, w, m.grantWait(), func(p *cluster.Placement, g *cluster.Grant) bool {
		return p.Generation == mig && g != nil && g.Mode == cluster.GrantMigration && g.Applied
	}); err != nil {
		return abort(fmt.Errorf("the storage server didn't grant both servers the VM's storage: %w", err))
	}
	for _, n := range []cluster.NodeID{from, to} {
		if err := m.call(ctx, n, PathAttach, StepRequest{Workload: w, Generation: mig, Migration: true}); err != nil {
			return abort(fmt.Errorf("attaching the VM's storage on %s: %w", n, err))
		}
	}
	token := NewToken()
	m.progress(o, 20, "Preparing "+string(to))
	if err := m.call(ctx, to, PathAccept, AcceptRequest{VM: w.ID, From: from, Token: token, Generation: mig}); err != nil {
		return abort(fmt.Errorf("%s didn't admit the migration: %w", to, err))
	}
	m.progress(o, 30, "Copying the VM's memory to "+string(to))
	started := m.now()
	uri := "tcp://" + dest.Addresses.Storage.String()
	if dest.Addresses.Storage.Is6() {
		uri = "tcp://[" + dest.Addresses.Storage.String() + "]"
	}
	sendErr := m.call(ctx, from, PathSend, SendRequest{VM: w.ID, To: to, Token: token, Generation: mig, MigrateURI: uri})
	_ = m.call(context.WithoutCancel(ctx), to, PathEnd, EndRequest{VM: w.ID, Token: token})
	if sendErr != nil {
		return abort(fmt.Errorf("the live migration failed: %w", sendErr))
	}
	m.progress(o, 90, "Handing it over to "+string(to))
	if err := m.propose(ctx, cluster.CmdPlacementSet, state.PlacementSet{Workload: w, Expected: mig, Owner: to, State: cluster.PlacementRunning, Reason: "migrated"}, actor); err != nil {
		return nil, fmt.Errorf("the VM runs on %s now, but recording it failed (the HA coordinator ends the migration): %w", to, err)
	}
	_ = m.call(context.WithoutCancel(ctx), from, PathDetach, StepRequest{Workload: w, Generation: mig})
	m.progress(o, 100, "Moved live to "+string(to))
	return &cluster.MoveResult{Workload: w, From: from, To: to, Mode: cluster.MoveLive, Downtime: m.now().Sub(started), Generation: mig + 1}, nil
}

// startElsewhere starts a workload of a server that is down on another
// one: only once that server's fence holds, and only with the person's
// typed confirmation.
func (m *Mover) startElsewhere(ctx context.Context, s *cluster.Snapshot, p *cluster.Placement, r cluster.MoveRequest, actor cluster.Actor, o Options) (*cluster.MoveResult, error) {
	if p.Owner != "" && !ownerFencedConfirmed(s, p.Owner) {
		return nil, fmt.Errorf("%s is down but the storage server hasn't confirmed it is cut off yet; wait for it", p.Owner)
	}
	if o.Confirm != p.Name {
		return nil, fmt.Errorf("%w: type %s to start it on another server", ErrConfirm, p.Name)
	}
	if p.Pinned && r.To == "" {
		return nil, errors.New("choose the server: it has passthrough devices, which that server must have too")
	}
	health, err := m.Cluster.Health(ctx)
	if err != nil {
		return nil, err
	}
	// What the workload needs, as its owner last said (the owner is down).
	req := cluster.Requirements{}
	if m.Scheduler != nil && m.Scheduler.Requirements != nil {
		if r := m.Scheduler.Requirements(p.Workload); r != nil {
			req = *r
		}
	}
	to := r.To
	if to == "" {
		if to, _, err = m.Scheduler.Place(s, health, r.Workload, req, []cluster.NodeID{p.Owner}); err != nil {
			return nil, err
		}
	} else if why := m.Scheduler.Fits(s, health, r.Workload, req, to); why != "" {
		return nil, fmt.Errorf("%s can't take %s: %s", to, p.Name, why)
	}
	from, gen := p.Owner, p.Generation
	if err := m.propose(ctx, cluster.CmdPlacementSet, state.PlacementSet{Workload: p.Workload, Expected: gen, Owner: to,
		State: cluster.PlacementStarting, Reason: "start-elsewhere"}, actor); err != nil {
		return nil, err
	}
	if p.Requested != cluster.RequestRunning {
		if err := m.propose(ctx, cluster.CmdRequested, state.RequestedSet{Workload: p.Workload, Generation: gen + 1, Requested: cluster.RequestRunning}, actor); err != nil {
			return nil, err
		}
	}
	m.progress(o, 100, "Placed on "+string(to)+"; it starts once the storage server gives it the storage")
	return &cluster.MoveResult{Workload: p.Workload, From: from, To: to, Mode: cluster.MoveOffline, Generation: gen + 1}, nil
}

// ResolveMigration ends a live migration that didn't finish cleanly (it
// failed, or its grant stood too long): it asks root on both servers what
// runs, and only then collapses the two-node grant onto one of them. The
// destination's copy is destroyed by its root first when the VM stays on
// the source; when only the destination runs it (the migration finished
// but its end wasn't recorded), it stays there. Without an answer from
// both servers nothing changes (the HA coordinator tries again, or ends it
// once a node's fence holds). It returns the node the VM is placed on.
func (m *Mover) ResolveMigration(ctx context.Context, w cluster.WorkloadRef, gen uint64, from, to cluster.NodeID, actor cluster.Actor, reason string) (cluster.NodeID, error) {
	ask := func(n cluster.NodeID) (StateResult, error) {
		var res struct {
			StateResult
			OK      *bool  `json:"ok,omitempty"`
			Message string `json:"message,omitempty"`
		}
		if err := m.Peers.Call(ctx, n, http.MethodPost, cluster.PeerPathPrefix+PathState, StateRequest{VM: w.ID}, &res); err != nil {
			return StateResult{}, err
		}
		if res.OK != nil && !*res.OK {
			return StateResult{}, errors.New(res.Message)
		}
		return res.StateResult, nil
	}
	src, err := ask(from)
	if err != nil {
		return "", fmt.Errorf("asking %s whether the VM runs there: %w", from, err)
	}
	dst, err := ask(to)
	if err != nil {
		return "", fmt.Errorf("asking %s whether the VM runs there: %w", to, err)
	}
	s := m.Cluster.State().Snapshot()
	p := s.Placements[w]
	if p == nil || p.Generation != gen {
		return "", cluster.ErrStaleGeneration
	}
	body := state.PlacementSet{Workload: w, Expected: gen, Reason: reason}
	if dst.Runs && !src.Runs {
		// The memory arrived and the source stopped: the destination has
		// the only copy.
		body.Owner, body.State = to, cluster.PlacementRunning
		if dst.Paused {
			body.Problem = "it is paused on " + string(to) + " after a live migration that didn't finish cleanly"
		}
	} else {
		// The source keeps (or gets back) the VM: the destination's copy
		// goes first, by its root, whatever the grant says.
		if err := m.call(ctx, to, PathAbort, AbortRequest{VM: w.ID, Generation: gen}); err != nil {
			return "", fmt.Errorf("destroying the copy on %s: %w", to, err)
		}
		if again, err := ask(to); err != nil || again.Runs {
			return "", fmt.Errorf("the copy on %s is still there", to)
		}
		body.Owner = from
		switch {
		case src.Runs:
			body.State = cluster.PlacementRunning
		case p.Requested == cluster.RequestRunning:
			body.State = cluster.PlacementStarting
		default:
			body.State = cluster.PlacementStopped
		}
	}
	if err := m.propose(ctx, cluster.CmdPlacementSet, body, actor); err != nil {
		return "", err
	}
	other := from
	if body.Owner == from {
		other = to
	}
	_ = m.call(ctx, other, PathDetach, StepRequest{Workload: w, Generation: gen + 1, Force: true})
	return body.Owner, nil
}

func ownerFencedConfirmed(s *cluster.Snapshot, n cluster.NodeID) bool {
	node := s.Nodes[n]
	if node == nil || node.State == cluster.NodeRemoved {
		return true
	}
	f := s.Fences[n]
	return f != nil && f.Confirmed && f.Epoch == node.FenceEpoch
}

// Drain implements cluster.Mover: live-migrate what can be, offline-move
// the rest (HA first, by priority), stop the workloads that can't move
// when stopOthers, else report them.
func (m *Mover) Drain(ctx context.Context, node cluster.NodeID, stopOthers bool, actor cluster.Actor) ([]cluster.MoveResult, error) {
	return m.DrainWith(ctx, node, stopOthers, actor, nil)
}

// DrainWith is Drain with progress.
func (m *Mover) DrainWith(ctx context.Context, node cluster.NodeID, stopOthers bool, actor cluster.Actor, progress Progress) ([]cluster.MoveResult, error) {
	s := m.Cluster.State().Snapshot()
	var todo []*cluster.Placement
	for _, p := range state.SortedPlacements(s) {
		if p.Owner == node {
			todo = append(todo, p)
		}
	}
	slices.SortStableFunc(todo, func(a, b *cluster.Placement) int {
		ha := func(p *cluster.Placement) int {
			if p.HA.Enabled {
				return p.HA.Priority
			}
			return -1
		}
		return ha(b) - ha(a)
	})
	var out []cluster.MoveResult
	var problems []string
	for i, p := range todo {
		if progress != nil {
			progress(float64(i)*100/float64(max(len(todo), 1)), "Moving "+p.Name)
		}
		cur := m.Cluster.State().Snapshot().Placements[p.Workload]
		if cur == nil || cur.Owner != node {
			continue
		}
		if cur.Pinned {
			if stopOthers && cur.Requested == cluster.RequestRunning {
				if err := m.propose(ctx, cluster.CmdRequested, state.RequestedSet{Workload: cur.Workload, Generation: cur.Generation, Requested: cluster.RequestStopped}, actor); err != nil {
					problems = append(problems, cur.Name+": "+err.Error())
				}
			} else {
				problems = append(problems, cur.Name+" is pinned to "+string(node)+" (passthrough devices)")
			}
			continue
		}
		mode := cluster.MoveOffline
		if cur.Workload.Kind == cluster.KindVM && cur.State == cluster.PlacementRunning {
			mode = cluster.MoveLive
		}
		res, err := m.Move(ctx, cluster.MoveRequest{Workload: cur.Workload, Mode: mode, Generation: cur.Generation}, actor)
		if err != nil && mode == cluster.MoveLive {
			// Can't move live (CPU, a disc inserted…): offline instead.
			again := m.Cluster.State().Snapshot().Placements[cur.Workload]
			if again != nil && again.Owner == node {
				res, err = m.Move(ctx, cluster.MoveRequest{Workload: cur.Workload, Mode: cluster.MoveOffline, Generation: again.Generation}, actor)
			}
		}
		if err != nil {
			problems = append(problems, cur.Name+": "+err.Error())
			continue
		}
		out = append(out, *res)
	}
	if len(problems) > 0 {
		return out, fmt.Errorf("%d of %d couldn't move: %s", len(problems), len(todo), joinProblems(problems))
	}
	return out, nil
}

func joinProblems(p []string) string {
	out := ""
	for i, x := range p {
		if i > 0 {
			out += "; "
		}
		out += x
	}
	return out
}
