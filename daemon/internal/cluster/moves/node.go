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
	"os"
	"slices"
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
// to the destination (the cluster port's hardyos-migrate/1, or a streamed
// peer request).
type StreamDialer interface {
	DialMigrate(ctx context.Context, node cluster.NodeID, token string) (io.ReadWriteCloser, error)
}

// Node serves the move steps on this node's peer API.
type Node struct {
	Cluster    Cluster
	Reconciler *runtime.Reconciler
	Attacher   cluster.StorageAttacher
	Runtimes   []cluster.Runtime
	Priv       runtime.Priv
	Images     runtime.Images
	Publish    PublishHandoff
	Stream     StreamDialer
	// Caller is the member that sent a peer request (PeerMux.Caller).
	Caller func(r *http.Request) (cluster.Node, bool)
	// GrantWait bounds the wait for an applied grant (default 60 s).
	GrantWait time.Duration
	Poll      time.Duration
	Log       *slog.Logger

	mu       sync.Mutex
	admitted map[string]*incoming
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

// Register adds the move steps to the peer API.
func (n *Node) Register(mux Mux) {
	h := func(path string, fn func(ctx context.Context, r *http.Request, caller cluster.Node) (any, error)) {
		mux.Handle(cluster.PeerPathPrefix+path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			caller, ok := n.Caller(r)
			if !ok {
				http.Error(w, "not a member", http.StatusForbidden)
				return
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
	h(PathPublishExport, n.publishExport)
	h(PathPublishImport, n.publishImport)
	h(PathRequirements, n.requirements)
	h(PathImages, n.images)
	mux.Handle(cluster.PeerPathPrefix+PathStream, http.HandlerFunc(n.stream))
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

func (n *Node) hold(_ context.Context, r *http.Request, _ cluster.Node) (any, error) {
	var req HoldRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	if req.Seconds < 0 || req.Seconds > 3600 {
		return nil, errors.New("a hold lasts at most an hour")
	}
	if req.Seconds == 0 {
		n.Reconciler.Release(req.Workload)
	} else {
		n.Reconciler.HoldFor(req.Workload, time.Duration(req.Seconds)*time.Second)
	}
	return nil, nil
}

// prepare (destination): its own devices for a pinned VM, an app's images.
func (n *Node) prepare(ctx context.Context, r *http.Request, _ cluster.Node) (any, error) {
	var req PrepareRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
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
	return nil, nil
}

// stop (source of an offline move): stop gracefully, detach, report it
// stopped for the generation.
func (n *Node) stop(ctx context.Context, r *http.Request, _ cluster.Node) (any, error) {
	var req StepRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	s := n.Cluster.State().Snapshot()
	p := s.Placements[req.Workload]
	if p == nil || p.Owner != self.ID || p.Generation != req.Generation {
		return nil, cluster.ErrStaleGeneration
	}
	rt, err := n.runtime(req.Workload.Kind)
	if err != nil {
		return nil, err
	}
	release := n.Reconciler.Hold(req.Workload)
	defer release()
	if err := rt.Stop(ctx, req.Workload, cluster.StopGraceful); err != nil {
		return nil, err
	}
	if n.Attacher != nil {
		if err := n.Attacher.Detach(ctx, req.Workload, false); err != nil {
			return nil, fmt.Errorf("detaching its storage: %w", err)
		}
	}
	body := state.WorkloadStateReport{Workload: req.Workload, Generation: req.Generation, State: cluster.PlacementStopped}
	idx, err := n.Cluster.Propose(ctx, cluster.CmdWorkloadState, body, cluster.Actor{Kind: "system", Name: "HardyOS", Via: self.ID})
	if err != nil {
		return nil, err
	}
	return nil, n.Cluster.WaitApplied(ctx, idx)
}

// waitGrant waits until this node's grant for w at gen is applied.
func (n *Node) waitGrant(ctx context.Context, w cluster.WorkloadRef, gen uint64) (*cluster.Placement, *cluster.Grant, error) {
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
		if err := state.MayRun(s, self.ID, w, gen); err == nil {
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

func (n *Node) attachAt(ctx context.Context, w cluster.WorkloadRef, gen uint64) (*cluster.Attachment, error) {
	p, g, err := n.waitGrant(ctx, w, gen)
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

// attach: attach under gen (a live migration's two nodes).
func (n *Node) attach(ctx context.Context, r *http.Request, _ cluster.Node) (any, error) {
	var req StepRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	if _, err := n.attachAt(ctx, req.Workload, req.Generation); err != nil {
		return nil, err
	}
	if req.Migration {
		n.Reconciler.TookPart(req.Workload, req.Generation)
	}
	return nil, nil
}

// start (destination of an offline move): attach, start if asked, report.
func (n *Node) start(ctx context.Context, r *http.Request, _ cluster.Node) (any, error) {
	var req StepRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	release := n.Reconciler.Hold(req.Workload)
	defer release()
	a, err := n.attachAt(ctx, req.Workload, req.Generation)
	if err != nil {
		return nil, err
	}
	if !req.Start {
		return nil, nil
	}
	rt, err := n.runtime(req.Workload.Kind)
	if err != nil {
		return nil, err
	}
	if err := rt.Start(ctx, req.Workload, a); err != nil {
		return nil, err
	}
	n.Reconciler.Started(req.Workload, req.Generation)
	body := state.WorkloadStateReport{Workload: req.Workload, Generation: req.Generation, State: cluster.PlacementRunning}
	if _, err := n.Cluster.Propose(ctx, cluster.CmdWorkloadState, body, cluster.Actor{Kind: "system", Name: "HardyOS", Via: self.ID}); err != nil {
		n.log().Warn("moves: reporting a started workload", "workload", req.Workload.ID, "err", err)
	}
	return nil, nil
}

func (n *Node) detach(ctx context.Context, r *http.Request, _ cluster.Node) (any, error) {
	var req StepRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	if n.Attacher == nil {
		return nil, nil
	}
	if req.Force {
		if rt, err := n.runtime(req.Workload.Kind); err == nil {
			// Whatever a failed migration left here goes first.
			if l, err := rt.Status(ctx); err == nil {
				for _, st := range l {
					if st.Workload == req.Workload && (st.Running || st.Paused) {
						if self, err := n.self(); err == nil && state.MayRun(n.Cluster.State().Snapshot(), self.ID, req.Workload, st.Generation) != nil {
							_ = rt.Stop(ctx, req.Workload, cluster.StopForce)
						}
					}
				}
			}
		}
	}
	return nil, n.Attacher.Detach(ctx, req.Workload, req.Force)
}

// accept (destination of a live migration): root admits the VM and hands
// over a libvirt connection as the migration user; it waits here for the
// source's stream.
func (n *Node) accept(ctx context.Context, r *http.Request, caller cluster.Node) (any, error) {
	var req AcceptRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	s := n.Cluster.State().Snapshot()
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	w := cluster.WorkloadRef{Kind: cluster.KindVM, ID: req.VM}
	p, g := s.Placements[w], s.Grants[w]
	if p == nil || g == nil || g.Mode != cluster.GrantMigration || p.Generation != req.Generation ||
		p.Owner != req.From || p.Target != self.ID || !g.Applied {
		return nil, errors.New("the log doesn't hold a live migration of this VM to this server")
	}
	const deadline = 2 * time.Minute
	f, err := n.Priv.CallFile(ctx, priv.OpVMsMigrateAccept, vms.MigrateAcceptArgs{VM: req.VM, From: string(req.From), Token: req.Token,
		DeadlineSec: int(deadline / time.Second), Generation: req.Generation}, nil)
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
	n.log().Info("moves: admitted a live migration", "vm", req.VM, "from", req.From, "by", caller.ID)
	return nil, nil
}

// stream (destination): the source's relayed libvirt connection, piped to
// the connection root handed over. Only the source named at accept, once,
// before the deadline.
func (n *Node) stream(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex()
	refuse := func(msg string) {
		// Answer at once: the caller's body is a stream that never ends.
		http.Error(w, msg, http.StatusForbidden)
		_ = rc.Flush()
		_ = r.Body.Close()
	}
	caller, ok := n.Caller(r)
	if !ok || r.Method != http.MethodPost {
		refuse("not allowed")
		return
	}
	in := n.take(r.URL.Query().Get("token"), caller.ID)
	if in == nil {
		refuse("no such migration")
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = rc.Flush()
	conn, err := net.FileConn(in.conn)
	if err != nil {
		return
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(conn, r.Body)
		if c, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		}
		close(done)
	}()
	buf := make([]byte, 64<<10)
	for {
		k, err := conn.Read(buf)
		if k > 0 {
			if _, werr := w.Write(buf[:k]); werr != nil {
				break
			}
			_ = rc.Flush()
		}
		if err != nil {
			break
		}
	}
	<-done
}

// end (destination): the migration is over; drop the admission.
func (n *Node) end(ctx context.Context, r *http.Request, _ cluster.Node) (any, error) {
	var req EndRequest
	if err := decodeBody(r, &req); err != nil {
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

// send (source of a live migration): root's one-shot socket is relayed to
// the destination while root runs the migration.
func (n *Node) send(ctx context.Context, r *http.Request, _ cluster.Node) (any, error) {
	var req SendRequest
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	self, err := n.self()
	if err != nil {
		return nil, err
	}
	s := n.Cluster.State().Snapshot()
	w := cluster.WorkloadRef{Kind: cluster.KindVM, ID: req.VM}
	p, g := s.Placements[w], s.Grants[w]
	if p == nil || g == nil || g.Mode != cluster.GrantMigration || p.Generation != req.Generation || p.Owner != self.ID || p.Target != req.To {
		return nil, errors.New("the log doesn't hold a live migration of this VM from this server")
	}
	if n.Stream == nil {
		return nil, errors.New("this server can't relay migrations")
	}
	lf, err := n.Priv.CallFile(ctx, priv.OpVMsMigrateListen, vms.MigrateListenArgs{VM: req.VM, Token: req.Token}, nil)
	if err != nil {
		return nil, err
	}
	ln, err := net.FileListener(lf)
	lf.Close()
	if err != nil {
		return nil, err
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
	if err != nil {
		return nil, err
	}
	return nil, nil
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
// hands over the connection and the member that dialled it): the first
// line names the admission token; the rest is piped to the connection
// root handed over at accept. Only the source named at accept, once,
// before the deadline.
func (n *Node) ServeMigrateConn(conn *tls.Conn, from cluster.Node) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(conn, 512)
	line, err := br.ReadString('\n')
	token, ok := strings.CutPrefix(strings.TrimSpace(line), "token ")
	if err != nil || !ok {
		_, _ = io.WriteString(conn, "no bad request\n")
		return
	}
	in := n.take(token, from.ID)
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

func (n *Node) publishExport(ctx context.Context, r *http.Request, _ cluster.Node) (any, error) {
	app := r.URL.Query().Get("app")
	if n.Publish == nil {
		return PublishConfig{App: app}, nil
	}
	cfg, err := n.Publish.Export(ctx, app)
	if err != nil {
		return nil, err
	}
	return PublishConfig{App: app, Config: cfg}, nil
}

func (n *Node) publishImport(ctx context.Context, r *http.Request, _ cluster.Node) (any, error) {
	var req PublishConfig
	if err := decodeBody(r, &req); err != nil {
		return nil, err
	}
	if n.Publish == nil || len(req.Config) == 0 {
		return nil, nil
	}
	return nil, n.Publish.Import(ctx, req.App, req.Config)
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
