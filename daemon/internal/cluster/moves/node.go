package moves

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/runtime"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/devices"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// PublishHandoff carries an app's NetBird publishing over to its new
// owner (internal/publish; optional).
type PublishHandoff interface {
	Export(ctx context.Context, app string) (json.RawMessage, error)
	Import(ctx context.Context, app string, cfg json.RawMessage) error
}

// StreamDialer opens the relayed libvirt connection of one live migration
// to the destination (the cluster port's hardyos-migrate/1).
type StreamDialer interface {
	DialMigrate(ctx context.Context, node cluster.NodeID, token string) (io.ReadWriteCloser, error)
}

// Node serves the move steps on this node's peer API.
//
// Every step that changes something here is driven only by the member
// whose move.begin started the move (Placement.MoveBy) or by the current
// leader (the HA coordinator), for the generation the step names, and is
// recorded as a finished job and an audit entry on this node (decision
// 387). A step from any other member is refused.
type Node struct {
	Cluster    Cluster
	Reconciler *runtime.Reconciler
	Attacher   cluster.StorageAttacher
	Runtimes   []cluster.Runtime
	Priv       runtime.Priv
	Images     runtime.Images
	Publish    PublishHandoff
	Stream     StreamDialer
	// Peers lets the destination fetch an app's publishing settings from
	// the source during a move (optional).
	Peers cluster.PeerClient
	// Caller is the member that sent a peer request (PeerMux.Caller).
	Caller func(r *http.Request) (cluster.Node, bool)
	// FenceReady says whether this node's fence agent armed the watchdog
	// (HA workloads start or arrive only then; nil: always).
	FenceReady func() bool
	// SpecHash is a workload's approved-settings hash from the placement.
	SpecHash func(w cluster.WorkloadRef) string
	// Actions records each step as a finished job and an audit entry.
	Actions Actions
	// GrantWait bounds the wait for an applied grant (default 60 s).
	GrantWait time.Duration
	// AuthorizeWait bounds the wait for the caller's move.begin to apply
	// here when the step didn't name its index (default 1 s).
	AuthorizeWait time.Duration
	Poll          time.Duration
	Log           *slog.Logger

	mu       sync.Mutex
	admitted map[string]*incoming
	publish  map[string]json.RawMessage // app -> settings fetched for a move here
}

// incoming is a migration this (destination) node admitted.
type incoming struct {
	vm       string
	from     cluster.NodeID
	conn     *os.File
	deadline time.Time
	used     bool
}

func (n *Node) log() *slog.Logger {
	if n.Log != nil {
		return n.Log
	}
	return slog.Default()
}

// Mux is where the handlers go (part A's PeerMux).
type Mux interface {
	Handle(pattern string, h http.Handler)
}

// ErrNotMover: a move step from a member that isn't driving the move.
var ErrNotMover = errors.New("this server isn't the one moving the workload (nor the leader)")

// Register adds the move steps to the peer API.
func (n *Node) Register(mux Mux) {
	h := func(path string, fn func(ctx context.Context, r *http.Request, caller cluster.Node) (any, error)) {
		mux.Handle(cluster.PeerPathPrefix+path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller, ok := n.Caller(r)
			if !ok {
				http.Error(w, "not a member", http.StatusForbidden)
				return
			}
			if idx, err := strconv.ParseUint(r.URL.Query().Get("idx"), 10, 64); err == nil && idx > 0 {
				// The mover's proposals up to idx (its move.begin) apply
				// here first.
				wctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
				_ = n.Cluster.WaitApplied(wctx, idx)
				cancel()
			}
			out, err := fn(r.Context(), r, caller)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				_ = json.NewEncoder(w).Encode(StepResult{OK: false, Message: err.Error()})
				return
			}
			if out == nil {
				out = StepResult{OK: true}
			}
			_ = json.NewEncoder(w).Encode(out)
		}))
	}
	h(PathHold, n.hold)
	h(PathPrepare, n.prepare)
	h(PathStop, n.stop)
	h(PathAttach, n.attach)
	h(PathStart, n.start)
	h(PathDetach, n.detach)
	h(PathAccept, n.accept)
	h(PathSend, n.send)
	h(PathEnd, n.end)
	h(PathAbort, n.abort)
	h(PathState, n.vmState)
	h(PathPublishExport, n.publishExport)
	h(PathPublishImport, n.publishImport)
	h(PathRequirements, n.requirements)
	h(PathImages, n.images)
}

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (n *Node) runtime(k cluster.WorkloadKind) (cluster.Runtime, error) {
	for _, rt := range n.Runtimes {
		if rt.Kind() == k {
			return rt, nil
		}
	}
	return nil, runtime.ErrNoRuntime
}

func (n *Node) self() (cluster.Node, error) { return n.Cluster.Self() }

// authorize: the caller drives the move of w (its move.begin is the
// placement's MoveBy) or is the leader.
func (n *Node) authorize(caller cluster.Node, w cluster.WorkloadRef) (*cluster.Snapshot, *cluster.Placement, error) {
	// The mover's move.begin may not be applied here yet: give this node's
	// log a moment to catch up before refusing.
	poll := n.Poll
	if poll <= 0 {
		poll = 100 * time.Millisecond
	}
	wait := n.AuthorizeWait
	if wait <= 0 {
		wait = time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		s := n.Cluster.State().Snapshot()
		p := s.Placements[w]
		if p != nil && p.MoveBy != "" && caller.ID == p.MoveBy {
			return s, p, nil
		}
		if l, ok := n.Cluster.Leader(); ok && l == caller.ID {
			if p == nil {
				return nil, nil, fmt.Errorf("%s isn't a cluster workload", w.ID)
			}
			return s, p, nil
		}
		if time.Now().After(deadline) {
			if p == nil {
				return nil, nil, fmt.Errorf("%s isn't a cluster workload", w.ID)
			}
			n.log().Warn("moves: refused a move step from a member that isn't moving the workload", "workload", w.ID, "caller", caller.ID, "mover", p.MoveBy)
			return nil, nil, ErrNotMover
		}
		time.Sleep(poll)
	}
}

// act runs a step as a recorded job (and audit entry) on this node.
func (n *Node) act(ctx context.Context, caller cluster.Node, title string, w cluster.WorkloadRef, fn func(ctx context.Context) error) error {
	title += " (asked by " + string(caller.ID) + ")"
	if n.Actions == nil {
		return fn(ctx)
	}
	return n.Actions.Run(ctx, StepKind, title, string(w.Kind)+":"+w.ID, fn)
}

func (n *Node) hold(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	var req HoldRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	if req.Seconds < 0 || req.Seconds > 3600 {
		return nil, errors.New("a hold lasts at most an hour")
	}
	_, p, err := n.authorize(caller, req.Workload)
	if err != nil {
		return nil, err
	}
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	if req.Seconds > 0 && p.Owner != self.ID && p.Target != self.ID {
		return nil, errors.New("the workload isn't moving from or to this server")
	}
	if req.Seconds == 0 {
		n.Reconciler.Release(req.Workload)
	} else {
		n.Reconciler.HoldFor(req.Workload, time.Duration(req.Seconds)*time.Second)
	}
	return nil, nil
}

// prepare (destination): its own devices for a pinned VM, an app's images,
// and an app's publishing settings fetched from the source.
func (n *Node) prepare(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	var req PrepareRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	_, p, err := n.authorize(caller, req.Workload)
	if err != nil {
		return nil, err
	}
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	if p.Target != self.ID {
		return nil, errors.New("the log doesn't hold a move of this workload to this server")
	}
	if len(req.Images) > 64 {
		return nil, errors.New("too many images")
	}
	if len(req.Devices) > 0 && string(req.Devices) != "null" {
		var ds []devices.Device
		if err := json.Unmarshal(req.Devices, &ds); err != nil {
			return nil, err
		}
		if len(ds) > 0 {
			var res priv.DevicesCheckResult
			if err := n.Priv.Call(ctx, priv.OpDevicesCheck, priv.DevicesCheckArgs{VM: req.Workload.ID, Devices: ds}, &res); err != nil {
				return nil, err
			}
			if len(res.Problems) > 0 {
				return nil, res.Problems
			}
		}
	}
	if len(req.Images) > 0 && n.Images != nil {
		have, err := n.Images.Have(ctx, req.Images)
		if err != nil {
			return nil, err
		}
		var missing []string
		for _, img := range req.Images {
			if !slices.Contains(have, img) {
				missing = append(missing, img)
			}
		}
		if len(missing) > 0 {
			failed, err := n.Images.Pull(ctx, missing)
			if err != nil {
				return nil, err
			}
			for img, why := range failed {
				return nil, fmt.Errorf("downloading %s: %s", img, why)
			}
		}
	}
	if req.Workload.Kind == cluster.KindApp && n.Peers != nil && n.Publish != nil {
		var pc PublishConfig
		path := cluster.PeerPathPrefix + PathPublishExport + "?app=" + url.QueryEscape(req.Workload.ID)
		if err := n.Peers.Call(ctx, p.Owner, http.MethodGet, path, nil, &pc); err != nil {
			n.log().Warn("moves: fetching the app's publishing from its server", "app", req.Workload.ID, "err", err)
		} else if len(pc.Config) > 0 {
			n.mu.Lock()
			if n.publish == nil {
				n.publish = map[string]json.RawMessage{}
			}
			n.publish[req.Workload.ID] = pc.Config
			n.mu.Unlock()
		}
	}
	return nil, nil
}

// stop (source of an offline move): stop gracefully, detach, report it
// stopped for the generation.
func (n *Node) stop(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	var req StepRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	_, p, err := n.authorize(caller, req.Workload)
	if err != nil {
		return nil, err
	}
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	if p.Owner != self.ID || p.Generation != req.Generation {
		return nil, cluster.ErrStaleGeneration
	}
	if p.Target == "" {
		return nil, errors.New("no move of this workload is in progress")
	}
	rt, err := n.runtime(req.Workload.Kind)
	if err != nil {
		return nil, err
	}
	return nil, n.act(ctx, caller, "Stop "+p.Name+" for its move to "+string(p.Target), req.Workload, func(ctx context.Context) error {
		release := n.Reconciler.Hold(req.Workload)
		defer release()
		if err := rt.Stop(ctx, req.Workload, cluster.StopGraceful); err != nil {
			return err
		}
		if n.Attacher != nil {
			if err := n.Attacher.Detach(ctx, req.Workload, false); err != nil {
				return fmt.Errorf("detaching its storage: %w", err)
			}
		}
		body := state.WorkloadStateReport{Workload: req.Workload, Generation: req.Generation, State: cluster.PlacementStopped}
		idx, err := n.Cluster.Propose(ctx, cluster.CmdWorkloadState, body, cluster.Actor{Kind: "system", Name: "HardyOS", Via: self.ID})
		if err != nil {
			return err
		}
		return n.Cluster.WaitApplied(ctx, idx)
	})
}

// waitGrant waits until this node may do intent with w at gen with the
// grant applied.
func (n *Node) waitGrant(ctx context.Context, w cluster.WorkloadRef, gen uint64, intent state.Intent) (*cluster.Placement, *cluster.Grant, error) {
	self, err := n.self()
	if err != nil {
		return nil, nil, err
	}
	wait := n.GrantWait
	if wait <= 0 {
		wait = time.Minute
	}
	poll := n.Poll
	if poll <= 0 {
		poll = 250 * time.Millisecond
	}
	deadline := time.Now().Add(wait)
	for {
		s := n.Cluster.State().Snapshot()
		p, g := s.Placements[w], s.Grants[w]
		if err := state.MayRunFor(s, self.ID, w, gen, intent); err == nil {
			return p, g, nil
		} else if !errors.Is(err, cluster.ErrStorageUnavailable) {
			return nil, nil, err
		}
		if time.Now().After(deadline) {
			return nil, nil, cluster.ErrStorageUnavailable
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}

func (n *Node) attachAt(ctx context.Context, w cluster.WorkloadRef, gen uint64, intent state.Intent) (*cluster.Attachment, error) {
	p, g, err := n.waitGrant(ctx, w, gen, intent)
	if err != nil {
		return nil, err
	}
	if n.Attacher == nil {
		return nil, cluster.ErrStorageUnavailable
	}
	a, err := n.Attacher.Attach(ctx, p.Storage, *g)
	if err != nil {
		return nil, err
	}
	if a.Generation != gen {
		return nil, fmt.Errorf("attached under generation %d, not %d", a.Generation, gen)
	}
	return a, nil
}

// fenceReady waits (briefly) for this node's fence agent to arm the
// watchdog for an HA workload placed here: it arms within a second of
// seeing the placement.
func (n *Node) fenceReady(p *cluster.Placement) error {
	if !p.HA.Enabled || n.FenceReady == nil {
		return nil
	}
	deadline := time.Now().Add(10 * time.Second)
	for !n.FenceReady() {
		if time.Now().After(deadline) {
			return errors.New("this server's watchdog isn't armed yet for an HA workload; try again in a moment")
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

// attach: attach under gen as one of a live migration's two nodes.
func (n *Node) attach(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	var req StepRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	_, p, err := n.authorize(caller, req.Workload)
	if err != nil {
		return nil, err
	}
	if !req.Migration {
		return nil, errors.New("a node attaches on request only for a live migration")
	}
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	intent := state.IntentKeep
	if p.Target == self.ID {
		intent = state.IntentReceive
	}
	return nil, n.act(ctx, caller, "Attach "+p.Name+"'s storage for its live migration", req.Workload, func(ctx context.Context) error {
		if _, err := n.attachAt(ctx, req.Workload, req.Generation, intent); err != nil {
			return err
		}
		n.Reconciler.TookPart(req.Workload, req.Generation)
		return nil
	})
}

// start (destination of an offline move): attach, start if asked, report.
// Only the owner with an exclusive grant starts from cold.
func (n *Node) start(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	var req StepRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	_, p, err := n.authorize(caller, req.Workload)
	if err != nil {
		return nil, err
	}
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	if req.Start {
		if err := n.fenceReady(p); err != nil {
			return nil, err
		}
	}
	return nil, n.act(ctx, caller, "Start "+p.Name+" after its move", req.Workload, func(ctx context.Context) error {
		release := n.Reconciler.Hold(req.Workload)
		defer release()
		a, err := n.attachAt(ctx, req.Workload, req.Generation, state.IntentStart)
		if err != nil {
			return err
		}
		if !req.Start {
			return nil
		}
		rt, err := n.runtime(req.Workload.Kind)
		if err != nil {
			return err
		}
		if err := rt.Start(ctx, req.Workload, a); err != nil {
			return err
		}
		n.Reconciler.Started(req.Workload, req.Generation)
		body := state.WorkloadStateReport{Workload: req.Workload, Generation: req.Generation, State: cluster.PlacementRunning}
		if _, err := n.Cluster.Propose(ctx, cluster.CmdWorkloadState, body, cluster.Actor{Kind: "system", Name: "HardyOS", Via: self.ID}); err != nil {
			n.log().Warn("moves: reporting a started workload", "workload", req.Workload.ID, "err", err)
		}
		return nil
	})
}

// detach: let a workload's storage go once this node may no longer run
// it; whatever of it still runs here is stopped first.
func (n *Node) detach(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	var req StepRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	s, p, err := n.authorize(caller, req.Workload)
	if err != nil {
		return nil, err
	}
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	if state.MayRun(s, self.ID, req.Workload, p.Generation) == nil {
		return nil, errors.New("this server still runs the workload under its placement")
	}
	if n.Attacher == nil {
		return nil, nil
	}
	return nil, n.act(ctx, caller, "Let "+p.Name+"'s storage go", req.Workload, func(ctx context.Context) error {
		if rt, err := n.runtime(req.Workload.Kind); err == nil {
			if l, err := rt.Status(ctx); err == nil {
				for _, st := range l {
					if st.Workload == req.Workload && (st.Running || st.Paused) {
						_ = rt.Stop(ctx, req.Workload, cluster.StopForce)
					}
				}
			}
		}
		return n.Attacher.Detach(ctx, req.Workload, req.Force)
	})
}

// accept (destination of a live migration): root admits the VM and hands
// over a libvirt connection as the migration user; it waits here for the
// source's stream.
func (n *Node) accept(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	var req AcceptRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	w := cluster.WorkloadRef{Kind: cluster.KindVM, ID: req.VM}
	s, p, err := n.authorize(caller, w)
	if err != nil {
		return nil, err
	}
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	g := s.Grants[w]
	if g == nil || g.Mode != cluster.GrantMigration || p.Generation != req.Generation || p.Owner != req.From || p.Target != self.ID ||
		state.MayRunFor(s, self.ID, w, req.Generation, state.IntentReceive) != nil {
		return nil, errors.New("the log doesn't hold a live migration of this VM to this server")
	}
	if err := n.fenceReady(p); err != nil {
		return nil, err
	}
	hash := ""
	if n.SpecHash != nil {
		hash = n.SpecHash(w)
	} else {
		hash = p.SpecHash
	}
	const deadline = 2 * time.Minute
	var f *os.File
	err = n.act(ctx, caller, "Admit the live migration of "+p.Name+" from "+string(req.From), w, func(ctx context.Context) error {
		var err error
		f, err = n.Priv.CallFile(ctx, priv.OpVMsMigrateAccept, vms.MigrateAcceptArgs{VM: req.VM, From: string(req.From), Token: req.Token,
			DeadlineSec: int(deadline / time.Second), Generation: req.Generation, SpecHash: hash}, nil)
		return err
	})
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	if n.admitted == nil {
		n.admitted = map[string]*incoming{}
	}
	for t, in := range n.admitted {
		if time.Now().After(in.deadline) {
			in.conn.Close()
			delete(n.admitted, t)
		}
	}
	n.admitted[req.Token] = &incoming{vm: req.VM, from: req.From, conn: f, deadline: time.Now().Add(deadline)}
	n.mu.Unlock()
	return nil, nil
}

// end (destination): the migration is over; drop the admission.
func (n *Node) end(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	var req EndRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	w := cluster.WorkloadRef{Kind: cluster.KindVM, ID: req.VM}
	if _, _, err := n.authorize(caller, w); err != nil {
		return nil, err
	}
	n.mu.Lock()
	if in := n.admitted[req.Token]; in != nil && in.vm == req.VM {
		in.conn.Close()
		delete(n.admitted, req.Token)
	}
	n.mu.Unlock()
	return nil, n.Priv.Call(ctx, priv.OpVMsMigrateEnd, vms.MigrateEndArgs{VM: req.VM, Token: req.Token}, nil)
}

// abort (destination of a failed live migration): whatever of the VM runs
// here is destroyed by root at once, then its storage goes. Unlike
// detach, this doesn't wait for the grant to move away: the mover or the
// leader collapses the migration onto the source right after, and the
// copy here must be gone before the source can be the only runner again.
func (n *Node) abort(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	var req AbortRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	w := cluster.WorkloadRef{Kind: cluster.KindVM, ID: req.VM}
	s, p, err := n.authorize(caller, w)
	if err != nil {
		return nil, err
	}
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	g := s.Grants[w]
	if p.Owner == self.ID || g == nil || g.Mode != cluster.GrantMigration || p.Generation != req.Generation || p.Target != self.ID {
		return nil, errors.New("only the destination of this live migration aborts it")
	}
	return nil, n.act(ctx, caller, "Destroy the incoming copy of "+p.Name+" (its live migration failed)", w, func(ctx context.Context) error {
		release := n.Reconciler.Hold(w)
		defer release()
		if err := n.Priv.Call(ctx, priv.OpVMsClusterStop, vms.ClusterStopArgs{ID: req.VM, Force: true, Undefine: true}, nil); err != nil {
			return fmt.Errorf("destroying the incoming copy: %w", err)
		}
		n.mu.Lock()
		for t, in := range n.admitted {
			if in.vm == req.VM {
				in.conn.Close()
				delete(n.admitted, t)
			}
		}
		n.mu.Unlock()
		if n.Attacher != nil {
			if err := n.Attacher.Detach(ctx, w, true); err != nil {
				n.log().Warn("moves: detaching after an aborted migration", "vm", req.VM, "err", err)
			}
		}
		return nil
	})
}

// vmState (either node of a migration): root's view of the VM here.
func (n *Node) vmState(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	var req StateRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	w := cluster.WorkloadRef{Kind: cluster.KindVM, ID: req.VM}
	if _, _, err := n.authorize(caller, w); err != nil {
		return nil, err
	}
	return LocalVMState(ctx, n.Runtimes, w)
}

// LocalVMState is what root reports of a VM on this node.
func LocalVMState(ctx context.Context, rts []cluster.Runtime, w cluster.WorkloadRef) (StateResult, error) {
	for _, rt := range rts {
		if rt.Kind() != w.Kind {
			continue
		}
		l, err := rt.Status(ctx)
		if err != nil {
			return StateResult{}, err
		}
		for _, st := range l {
			if st.Workload == w && (st.Running || st.Paused) {
				return StateResult{Runs: true, Paused: st.Paused, Generation: st.Generation}, nil
			}
		}
		return StateResult{}, nil
	}
	return StateResult{}, runtime.ErrNoRuntime
}

// send (source of a live migration): root's one-shot socket is relayed to
// the destination while root runs the migration.
func (n *Node) send(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	var req SendRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	w := cluster.WorkloadRef{Kind: cluster.KindVM, ID: req.VM}
	s, p, err := n.authorize(caller, w)
	if err != nil {
		return nil, err
	}
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	g := s.Grants[w]
	if g == nil || g.Mode != cluster.GrantMigration || p.Generation != req.Generation || p.Owner != self.ID || p.Target != req.To {
		return nil, errors.New("the log doesn't hold a live migration of this VM from this server")
	}
	if n.Stream == nil {
		return nil, errors.New("this server can't relay migrations")
	}
	return nil, n.act(ctx, caller, "Send "+p.Name+" live to "+string(req.To), w, func(ctx context.Context) error {
		lf, err := n.Priv.CallFile(ctx, priv.OpVMsMigrateListen, vms.MigrateListenArgs{VM: req.VM, Token: req.Token}, nil)
		if err != nil {
			return err
		}
		ln, err := net.FileListener(lf)
		lf.Close()
		if err != nil {
			return err
		}
		defer ln.Close()
		relayCtx, stopRelay := context.WithCancel(ctx)
		defer stopRelay()
		var relays sync.WaitGroup
		relays.Add(1)
		go func() {
			defer relays.Done()
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				relays.Add(1)
				go func() {
					defer relays.Done()
					defer c.Close()
					up, err := n.Stream.DialMigrate(relayCtx, req.To, req.Token)
					if err != nil {
						n.log().Warn("moves: relaying the migration", "vm", req.VM, "err", err)
						return
					}
					defer up.Close()
					pipe(relayCtx, c, up)
				}()
			}
		}()
		err = n.Priv.Call(ctx, priv.OpVMsMigrateSend, vms.MigrateSendArgs{VM: req.VM, To: string(req.To), Token: req.Token,
			MigrateURI: req.MigrateURI, Generation: req.Generation}, nil)
		ln.Close()
		stopRelay()
		relays.Wait()
		// The destination's migration ports are opened and closed by the
		// mover (see the TODO in Mover.live: storagesvc AllowMigration /
		// RevokeMigration on the destination).
		return err
	})
}

// take claims an admitted migration for its source, once, before the
// deadline.
func (n *Node) take(token string, from cluster.NodeID) *incoming {
	n.mu.Lock()
	defer n.mu.Unlock()
	in := n.admitted[token]
	if in == nil || in.used || in.from != from || time.Now().After(in.deadline) {
		return nil
	}
	in.used = true
	return in
}

// MigrateOK answers a source's first line (MigrateTokenLine) on a
// hardyos-migrate/1 connection; anything else is a refusal.
const MigrateOK = "ok"

// MigrateTokenLine is the source's first line: the admission token.
func MigrateTokenLine(token string) string { return "token " + token + "\n" }

// ServeMigrateConn (destination) takes a live migration's relayed libvirt
// connection on the cluster port's hardyos-migrate/1 (part A's transport
// hands over the connection and the member that dialled it).
func (n *Node) ServeMigrateConn(conn *tls.Conn, from cluster.Node) { n.ServeMigrate(conn, from.ID) }

// ServeMigrate serves one relayed connection: the first line names the
// admission token; the rest is piped to the connection root handed over
// at accept. Only the source named at accept, once, before the deadline.
func (n *Node) ServeMigrate(conn net.Conn, from cluster.NodeID) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(conn, 512)
	line, err := br.ReadString('\n')
	token, ok := strings.CutPrefix(strings.TrimSpace(line), "token ")
	if err != nil || !ok {
		_, _ = io.WriteString(conn, "no bad request\n")
		return
	}
	in := n.take(token, from)
	if in == nil {
		_, _ = io.WriteString(conn, "no such migration\n")
		return
	}
	if _, err := io.WriteString(conn, MigrateOK+"\n"); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	local, err := net.FileConn(in.conn)
	if err != nil {
		return
	}
	src := &bufConn{Conn: conn, r: br}
	pipe(context.Background(), src, local)
}

// bufConn reads through the reader that took the first line.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// pipe copies both ways until either side ends.
func pipe(ctx context.Context, a io.ReadWriteCloser, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	a.Close()
	b.Close()
}

// publishExport (source): an app's publishing settings, to the move's
// destination only, while the move is in progress.
func (n *Node) publishExport(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	app := r.URL.Query().Get("app")
	s := n.Cluster.State().Snapshot()
	p := s.Placements[cluster.WorkloadRef{Kind: cluster.KindApp, ID: app}]
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	if p == nil || p.Owner != self.ID || p.Target == "" || p.Target != caller.ID {
		return nil, errors.New("only the destination of this app's move gets its publishing settings")
	}
	if n.Publish == nil {
		return PublishConfig{App: app}, nil
	}
	cfg, err := n.Publish.Export(ctx, app)
	if err != nil {
		return nil, err
	}
	return PublishConfig{App: app, Config: cfg}, nil
}

// publishImport (destination, after the hand-over): the settings fetched
// from the source during prepare take effect here.
func (n *Node) publishImport(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	var req PublishConfig
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	w := cluster.WorkloadRef{Kind: cluster.KindApp, ID: req.App}
	_, p, err := n.authorize(caller, w)
	if err != nil {
		return nil, err
	}
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	if p.Owner != self.ID {
		return nil, errors.New("the app isn't placed on this server")
	}
	n.mu.Lock()
	cfg := n.publish[req.App]
	delete(n.publish, req.App)
	n.mu.Unlock()
	if n.Publish == nil || len(cfg) == 0 {
		return nil, nil
	}
	return nil, n.act(ctx, caller, "Publish "+p.Name+" from this server", w, func(ctx context.Context) error {
		return n.Publish.Import(ctx, req.App, cfg)
	})
}

// requirements (owner): what a workload needs, and a VM's devices.
func (n *Node) requirements(ctx context.Context, r *http.Request, _ cluster.Node) (any, error) {
	w := cluster.WorkloadRef{Kind: cluster.WorkloadKind(r.URL.Query().Get("kind")), ID: r.URL.Query().Get("id")}
	rt, err := n.runtime(w.Kind)
	if err != nil {
		return nil, err
	}
	req, err := rt.Requirements(ctx, w)
	if err != nil {
		return nil, err
	}
	out := struct {
		Requirements cluster.Requirements `json:"requirements"`
		Devices      json.RawMessage      `json:"devices,omitempty"`
	}{Requirements: *req}
	if w.Kind == cluster.KindVM && len(req.Devices) > 0 {
		var v vms.VM
		if err := n.Priv.Call(ctx, priv.OpVMsGet, priv.VMRef{ID: w.ID}, &v); err == nil {
			out.Devices, _ = json.Marshal(v.Devices)
		}
	}
	return out, nil
}

// images (owner): the images a cluster app uses (for pre-pulling).
func (n *Node) images(ctx context.Context, r *http.Request, _ cluster.Node) (any, error) {
	var res priv.ImagesResult
	if err := n.Priv.Call(ctx, priv.OpAppsClusterImages, priv.AppRef{ID: r.URL.Query().Get("app")}, &res); err != nil {
		return nil, err
	}
	return res, nil
}
