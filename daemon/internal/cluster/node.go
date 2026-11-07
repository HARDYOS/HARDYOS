package cluster

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"golang.org/x/net/http2"
)

// Store keeps a node's membership between restarts (hardyd: its database,
// sealed where secret; the witness: files in its state directory). The
// identity is kept by the caller, not here.
type Store interface {
	// Info is the membership, or nil, nil outside a cluster.
	Info(ctx context.Context) (*Info, error)
	SetInfo(ctx context.Context, i *Info) error
	ClearInfo(ctx context.Context) error
	// Seq is the last sequence number this node signed; SetSeq is called
	// before a command with a new one leaves the node.
	Seq(ctx context.Context) (uint64, error)
	SetSeq(ctx context.Context, seq uint64) error
	JoinCodes
}

// Info is a node's membership.
type Info struct {
	Cluster ClusterID `json:"cluster"`
	Name    string    `json:"name"`
	Node    NodeID    `json:"node"`
	Role    Role      `json:"role"`
	// Peers are the members the join answer named, trusted until the
	// replicated state has members (a new node's first connections).
	Peers []Node `json:"peers,omitempty"`
	// JoinIndex is the member.add entry's index.
	JoinIndex uint64 `json:"joinIndex,omitempty"`
}

// RaftTimings tune Raft (docs/plans/cluster.md 2.1).
type RaftTimings struct {
	Heartbeat, Election, LeaderLease, Commit time.Duration
	SnapshotThreshold, TrailingLogs          uint64
	SnapshotInterval                         time.Duration
}

// DefaultRaftTimings are the plan's LAN values.
var DefaultRaftTimings = RaftTimings{Heartbeat: 2 * time.Second, Election: 3 * time.Second, LeaderLease: time.Second,
	Commit: 50 * time.Millisecond, SnapshotThreshold: 1024, TrailingLogs: 4096, SnapshotInterval: 2 * time.Minute}

// LocalHealth is what this node reports about itself in heartbeats (parts
// B and C fill in storage and workloads).
type LocalHealth struct {
	StorageOK bool
	LANOK     bool
	Running   []RunningWorkload
}

// Config builds a Node.
type Config struct {
	Identity *Identity
	Store    Store
	Machine  StateMachine
	Net      Network
	// Port is the cluster port (Port when 0).
	Port int
	// Dir holds Raft's log and snapshots; "" keeps them in memory (tests).
	Dir string
	// Self is this node's record as it will be announced (id, name, role,
	// version, features, boot id); Addresses its current addresses.
	Version   string
	Features  []string
	BootID    string
	Addresses func() Addresses
	Raft      RaftTimings
	Paths     PathTimings
	// Timings overrides the replicated liveness timings (tests).
	Timings *Timings
	// Health reports this node's own health (nil: storage and LAN fine,
	// nothing running).
	Health func(ctx context.Context) LocalHealth
	// WitnessBinary opens the witness binary members hand to the install
	// script (nil on the witness).
	WitnessBinary func() (io.ReadSeekCloser, error)
	// OnJoin is told about join attempts (audit); OnEvent about every event.
	OnJoin func(ctx context.Context, e JoinEvent)
	Log    *slog.Logger
}

// Core is one member's cluster core: Raft, the stream layer and paths,
// the peer API, heartbeats and the quorum lease. It implements Membership.
type Core struct {
	cfg  Config
	log  *slog.Logger
	tr   *Transport
	mux  *peerMux
	pc   *peerClient
	path *Paths

	mu        sync.Mutex
	info      *Info
	raft      *raft.Raft
	raftTrans *raft.NetworkTransport
	stores    []io.Closer
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	running   bool
	halted    error

	proposeMu sync.Mutex

	applyMu   sync.Mutex
	appliedCh chan struct{}

	events broker

	// Liveness (heartbeat.go).
	live       liveness
	probeMu    sync.Mutex
	probes     map[string]*http2.Transport
	joinLimits joinLimiter
	relay      relayState

	ownMu   sync.Mutex
	own     map[uint64]ownResult
	codesMu sync.Mutex
}

// ErrRefused is an entry the cluster refused (its message says why).
type ErrRefused struct{ Reason string }

func (e *ErrRefused) Error() string { return e.Reason }

// New makes a node from cfg; Start runs it when it is a member.
func New(ctx context.Context, cfg Config) (*Core, error) {
	if cfg.Identity == nil || cfg.Store == nil || cfg.Machine == nil {
		return nil, errors.New("cluster: identity, store and state machine are required")
	}
	if cfg.Net == nil {
		cfg.Net = TCP{}
	}
	if cfg.Raft.Heartbeat == 0 {
		cfg.Raft = DefaultRaftTimings
	}
	if cfg.Addresses == nil {
		cfg.Addresses = func() Addresses { return Addresses{} }
	}
	n := &Core{cfg: cfg, log: cfg.Log, appliedCh: make(chan struct{}), probes: map[string]*http2.Transport{}}
	if n.log == nil {
		n.log = slog.Default()
	}
	info, err := cfg.Store.Info(ctx)
	if err != nil {
		return nil, err
	}
	n.info = info
	n.path = &Paths{Timings: cfg.Paths, Self: cfg.Addresses, Peers: n.peers, Probe: n.probe,
		OnSwitch: n.pathSwitched}
	n.tr = &Transport{ID: cfg.Identity, Net: cfg.Net, Book: n, Paths: n.path, Port: cfg.Port, Log: n.log}
	n.mux = newPeerMux(n)
	n.tr.Peer = n.mux
	if cfg.WitnessBinary != nil {
		n.tr.Bootstrap = n.BootstrapHandler()
	}
	n.pc = newPeerClient(n.tr)
	n.routes()
	return n, nil
}

// Mux is the peer API, for parts B and C to register their endpoints.
func (n *Core) Mux() PeerMux { return n.mux }

// Peers is the client for other members' peer APIs.
func (n *Core) Peers() PeerClient { return n.pc }

// Transport is the cluster listener and dialer (relays use it).
func (n *Core) Transport() *Transport { return n.tr }

// Paths is this node's path table.
func (n *Core) Paths() *Paths { return n.path }

// Identity is this node's cluster key.
func (n *Core) Identity() *Identity { return n.cfg.Identity }

// Machine is the replicated state machine.
func (n *Core) Machine() StateMachine { return n.cfg.Machine }

// Info is this node's membership (nil outside a cluster).
func (n *Core) Info() *Info {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.info == nil {
		return nil
	}
	c := *n.info
	c.Peers = slices.Clone(n.info.Peers)
	return &c
}

// ID is this node's id ("" outside a cluster).
func (n *Core) ID() NodeID {
	if i := n.Info(); i != nil {
		return i.Node
	}
	return ""
}

func (n *Core) role() Role {
	if i := n.Info(); i != nil {
		return i.Role
	}
	return ""
}

// ---- PeerBook ---------------------------------------------------------------

// ByPin finds a member by pin: the state's members, or the join answer's
// before the state has any.
func (n *Core) ByPin(pin string) (Node, bool) {
	if pin == "" {
		return Node{}, false
	}
	idx := n.cfg.Machine.PinIndex()
	if len(idx) > 0 {
		m, ok := idx[pin]
		return m, ok
	}
	if i := n.Info(); i != nil {
		for _, p := range i.Peers {
			if p.Pin == pin {
				return p, true
			}
		}
	}
	return Node{}, false
}

// Member returns a member's record.
func (n *Core) Member(id NodeID) (Node, bool) {
	if m, ok := n.cfg.Machine.Node(id); ok {
		return *m, true
	}
	if len(n.cfg.Machine.PinIndex()) == 0 {
		if i := n.Info(); i != nil {
			for _, p := range i.Peers {
				if p.ID == id {
					return p, true
				}
			}
		}
	}
	return Node{}, false
}

func (n *Core) peers() []Node {
	idx := n.cfg.Machine.PinIndex()
	out := make([]Node, 0, len(idx))
	for _, m := range idx {
		out = append(out, m)
	}
	if len(out) == 0 {
		if i := n.Info(); i != nil {
			out = append(out, i.Peers...)
		}
	}
	slices.SortFunc(out, func(a, b Node) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		}
		return 0
	})
	return out
}

// ---- lifecycle --------------------------------------------------------------

// Running reports whether the node runs (it is a member and started).
func (n *Core) Running() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.running
}

// Start runs the node if it is a member (a no-op otherwise).
func (n *Core) Start(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.startLocked(ctx, nil)
}

func (n *Core) raftConfig() *raft.Config {
	t := n.cfg.Raft
	c := raft.DefaultConfig()
	c.LocalID = raft.ServerID(n.info.Node)
	c.HeartbeatTimeout = t.Heartbeat
	c.ElectionTimeout = t.Election
	c.LeaderLeaseTimeout = t.LeaderLease
	c.CommitTimeout = t.Commit
	if t.SnapshotThreshold > 0 {
		c.SnapshotThreshold = t.SnapshotThreshold
	}
	if t.TrailingLogs > 0 {
		c.TrailingLogs = t.TrailingLogs
	}
	if t.SnapshotInterval > 0 {
		c.SnapshotInterval = t.SnapshotInterval
	}
	c.PreVoteDisabled = false
	c.Logger = hclogFor(n.log)
	return c
}

// startLocked starts Raft (bootstrapping a new cluster when boot is set).
func (n *Core) startLocked(ctx context.Context, boot *raft.Configuration) error {
	if n.running || n.info == nil {
		return nil
	}
	var logs raft.LogStore
	var stable raft.StableStore
	var snaps raft.SnapshotStore
	n.stores = nil
	if n.cfg.Dir == "" {
		m := raft.NewInmemStore()
		logs, stable, snaps = m, m, raft.NewInmemSnapshotStore()
	} else {
		dir := filepath.Join(n.cfg.Dir, "raft")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		b, err := raftboltdb.New(raftboltdb.Options{Path: filepath.Join(dir, "raft.db")})
		if err != nil {
			return fmt.Errorf("cluster log: %w", err)
		}
		n.stores = append(n.stores, b)
		logs, stable = b, b
		fs, err := raft.NewFileSnapshotStoreWithLogger(dir, 3, hclogFor(n.log))
		if err != nil {
			b.Close()
			return err
		}
		snaps = fs
	}
	// Raft replays the log (from its latest snapshot) into a fresh state.
	if err := n.cfg.Machine.Restore([]byte(`{}`)); err != nil {
		n.closeStores()
		return err
	}
	layer := &streamLayer{t: n.tr, ln: n.tr.RaftListener()}
	trans := raft.NewNetworkTransportWithConfig(&raft.NetworkTransportConfig{
		Stream: layer, MaxPool: 3, Timeout: 10 * time.Second, Logger: hclogFor(n.log),
	})
	if boot != nil {
		if err := raft.BootstrapCluster(n.raftConfig(), logs, stable, snaps, trans, *boot); err != nil {
			trans.Close()
			n.closeStores()
			return fmt.Errorf("bootstrap: %w", err)
		}
	}
	r, err := raft.NewRaft(n.raftConfig(), &fsmAdapter{n: n}, logs, stable, snaps, trans)
	if err != nil {
		trans.Close()
		n.closeStores()
		return fmt.Errorf("start the cluster log: %w", err)
	}
	n.raft, n.raftTrans = r, trans
	n.running = true
	rctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	n.cancel = cancel
	n.tr.Self = n.info.Node
	n.listen()
	n.live.reset()
	n.wg.Add(4)
	go func() { defer n.wg.Done(); n.path.Run(rctx, n.info.Node, n.info.Role) }()
	go func() { defer n.wg.Done(); n.heartbeatLoop(rctx) }()
	go func() { defer n.wg.Done(); n.leaderLoop(rctx) }()
	go func() { defer n.wg.Done(); n.listenLoop(rctx) }()
	return nil
}

func (n *Core) closeStores() {
	for _, s := range n.stores {
		s.Close()
	}
	n.stores = nil
}

// listen binds the cluster port on this node's own addresses.
func (n *Core) listen() {
	a := n.cfg.Addresses()
	n.tr.SetListen([]netip.Addr{a.LAN, a.Storage, a.NetBird})
}

func (n *Core) listenLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.listen()
		}
	}
}

// Stop shuts the node down (it stays a member).
func (n *Core) Stop() {
	n.mu.Lock()
	r, cancel := n.raft, n.cancel
	n.raft, n.cancel, n.running = nil, nil, false
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if r != nil {
		_ = r.Shutdown().Error()
	}
	n.tr.Close()
	n.pc.close()
	n.probeMu.Lock()
	for k, t := range n.probes {
		t.CloseIdleConnections()
		delete(n.probes, k)
	}
	n.probeMu.Unlock()
	n.wg.Wait()
	n.mu.Lock()
	if n.raftTrans != nil {
		n.raftTrans.Close()
		n.raftTrans = nil
	}
	n.closeStores()
	// A new transport for a later start (listeners can't be reopened).
	n.tr = &Transport{ID: n.cfg.Identity, Net: n.cfg.Net, Book: n, Paths: n.path, Port: n.cfg.Port, Log: n.log,
		Peer: n.mux, Relay: n.tr.Relay, Bootstrap: n.tr.Bootstrap, Migrate: n.tr.Migrate}
	n.pc = newPeerClient(n.tr)
	n.mu.Unlock()
}

// SetRelay sets the handler for ALPNRelay connections (the API proxy's
// target side). Call before Start.
func (n *Core) SetRelay(h http.Handler) { n.tr.Relay = h }

// SetMigrate sets part C's live migration hook. Call before Start.
func (n *Core) SetMigrate(f func(conn *tls.Conn, from Node)) { n.tr.Migrate = f }

// ---- raft glue ----------------------------------------------------------------

type streamLayer struct {
	t  *Transport
	ln net.Listener
}

func (s *streamLayer) Accept() (net.Conn, error) { return s.ln.Accept() }
func (s *streamLayer) Close() error              { return nil } // the transport owns the queue
func (s *streamLayer) Addr() net.Addr            { return s.ln.Addr() }

func (s *streamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, _, err := s.t.DialNode(ctx, NodeID(address), ALPNRaft)
	return c, err
}

type fsmAdapter struct{ n *Core }

func (a *fsmAdapter) Apply(l *raft.Log) any {
	res := a.n.cfg.Machine.Apply(l.Index, l.Data)
	a.n.applied(res)
	return res
}

type fsmSnapshot struct{ b []byte }

func (s fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	if _, err := sink.Write(s.b); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}
func (fsmSnapshot) Release() {}

func (a *fsmAdapter) Snapshot() (raft.FSMSnapshot, error) {
	b, err := a.n.cfg.Machine.Encode()
	return fsmSnapshot{b}, err
}

func (a *fsmAdapter) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, 256<<20))
	if err != nil {
		return err
	}
	if err := a.n.cfg.Machine.Restore(b); err != nil {
		return err
	}
	a.n.notifyApplied()
	a.n.events.publish(Event{Index: a.n.cfg.Machine.Index()})
	return nil
}

func (n *Core) notifyApplied() {
	n.applyMu.Lock()
	close(n.appliedCh)
	n.appliedCh = make(chan struct{})
	n.applyMu.Unlock()
}

// applied runs after every entry.
func (n *Core) applied(res ApplyResult) {
	n.notifyApplied()
	if h := n.cfg.Machine.Halted(); h != nil {
		n.mu.Lock()
		first := n.halted == nil
		n.halted = h
		n.mu.Unlock()
		if first {
			n.log.Error("cluster: this server can't follow the cluster log any more and stops taking part", "err", h)
			n.events.publish(Event{Index: res.Index})
			go n.Stop()
		}
		return
	}
	if res.Command == nil {
		return
	}
	if res.Command.Proposer == n.ID() {
		n.recordOwn(res.Command.Seq, res.Index, res.Err)
	}
	if res.Err == nil {
		switch res.Command.Type {
		case CmdClusterCreate, CmdMemberAdd, CmdMemberReady, CmdMemberUpdate, CmdMemberRemove, CmdWitnessHello:
			if err := n.savePeers(context.Background()); err != nil {
				n.log.Warn("cluster: recording the members", "err", err)
			}
		}
	}
	e := Event{Index: res.Index, Type: res.Command.Type, Node: res.Command.Proposer}
	if res.Err == nil {
		var b struct {
			Node     json.RawMessage `json:"node"`
			Workload *WorkloadRef    `json:"workload"`
		}
		if json.Unmarshal(res.Command.Body, &b) == nil {
			var id NodeID
			var rec Node
			if json.Unmarshal(b.Node, &id) == nil && id != "" {
				e.Node = id
			} else if json.Unmarshal(b.Node, &rec) == nil && rec.ID != "" {
				e.Node = rec.ID
			}
			e.Workload = b.Workload
		}
	} else {
		n.log.Info("cluster: entry refused", "index", res.Index, "type", res.Command.Type, "proposer", res.Command.Proposer, "err", res.Err)
	}
	n.events.publish(e)
}

// Halted is why this node stopped following the log (an entry it can't
// apply: it needs an update), or nil.
func (n *Core) Halted() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.halted
}

func (n *Core) r() *raft.Raft {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.raft
}

// ---- Membership ----------------------------------------------------------------

// Self implements Membership.
func (n *Core) Self() (Node, error) {
	id := n.ID()
	if id == "" {
		return Node{}, ErrNotMember
	}
	m, ok := n.cfg.Machine.Node(id)
	if !ok {
		return Node{}, ErrNotMember
	}
	return *m, nil
}

// State implements Membership.
func (n *Core) State() State { return n.cfg.Machine }

// Leader implements Membership.
func (n *Core) Leader() (NodeID, bool) {
	r := n.r()
	if r == nil {
		return "", false
	}
	_, id := r.LeaderWithID()
	return NodeID(id), id != ""
}

// IsLeader reports whether this node leads.
func (n *Core) IsLeader() bool {
	r := n.r()
	return r != nil && r.State() == raft.Leader
}

// Register implements Membership.
func (n *Core) Register(a Applier) { n.cfg.Machine.Register(a) }

// WaitApplied implements Membership.
func (n *Core) WaitApplied(ctx context.Context, index uint64) error {
	for {
		n.applyMu.Lock()
		ch := n.appliedCh
		n.applyMu.Unlock()
		if n.cfg.Machine.Index() >= index {
			return nil
		}
		if h := n.Halted(); h != nil {
			return h
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
		case <-time.After(time.Second):
		}
	}
}

// Subscribe implements Membership.
func (n *Core) Subscribe(ctx context.Context) <-chan Event { return n.events.subscribe(ctx) }

// Propose implements Membership.
func (n *Core) Propose(ctx context.Context, t CommandType, body any, actor Actor) (uint64, error) {
	info := n.Info()
	if info == nil {
		return 0, ErrNotMember
	}
	if h := n.Halted(); h != nil {
		return 0, h
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	n.proposeMu.Lock()
	defer n.proposeMu.Unlock()
	seq, err := n.cfg.Store.Seq(ctx)
	if err != nil {
		return 0, err
	}
	if s := n.cfg.Machine.Snapshot().Seq[info.Node]; s > seq {
		seq = s
	}
	seq++
	if err := n.cfg.Store.SetSeq(ctx, seq); err != nil {
		return 0, err
	}
	if actor.Via == "" {
		actor.Via = info.Node
	}
	sc, err := SignCommand(n.cfg.Identity, Command{Type: t, Cluster: info.Cluster, Proposer: info.Node, Seq: seq,
		Actor: actor, Time: time.Now().UTC().Truncate(time.Millisecond), Body: raw})
	if err != nil {
		return 0, err
	}
	return n.submit(ctx, sc)
}

type proposeAnswer struct {
	Index   uint64 `json:"index"`
	Refused string `json:"refused,omitempty"`
}

// submit hands a signed command to the leader (this node or another) and
// waits until it is committed. When the outcome is unknown (leadership
// lost while committing, the connection broke after sending) the same
// signed command is sent again: the sequence check lets at most one copy
// apply, and the outcome is the first copy's, as this node applied it.
func (n *Core) submit(ctx context.Context, sc *SignedCommand) (uint64, error) {
	data, err := json.Marshal(sc)
	if err != nil {
		return 0, err
	}
	var cmd Command
	_ = json.Unmarshal(sc.Command, &cmd)
	deadline := time.Now().Add(15 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	ambiguous := false
	var last error = ErrNoQuorum
	done := func(idx uint64, refused string) (uint64, error) {
		if ambiguous {
			// A resend: what happened to the first copy decides.
			if err := n.WaitApplied(ctx, idx); err != nil {
				return idx, err
			}
			if r, ok := n.ownResult(cmd.Seq); ok {
				if r.err != nil {
					return r.index, &ErrRefused{Reason: r.err.Error()}
				}
				return r.index, nil
			}
		}
		if refused != "" {
			return idx, &ErrRefused{Reason: refused}
		}
		return idx, nil
	}
	for {
		r := n.r()
		if r == nil {
			return 0, ErrNotMember
		}
		if r.State() == raft.Leader {
			f := r.Apply(data, time.Until(deadline))
			err := f.Error()
			switch {
			case err == nil:
				res, _ := f.Response().(ApplyResult)
				if res.Err != nil {
					return done(f.Index(), res.Err.Error())
				}
				return done(f.Index(), "")
			case errors.Is(err, raft.ErrNotLeader):
			default:
				ambiguous, last = true, err
			}
		} else if leader, ok := n.Leader(); ok {
			var ans proposeAnswer
			cctx, cancel := context.WithDeadline(ctx, deadline)
			err := n.pc.Call(cctx, leader, http.MethodPost, "/propose", sc, &ans)
			cancel()
			var pe *PeerError
			switch {
			case err == nil:
				return done(ans.Index, ans.Refused)
			case errors.As(err, &pe) && pe.Status == http.StatusMisdirectedRequest:
				// Not the leader any more: nothing was appended.
			case errors.As(err, &pe) && pe.Status == http.StatusForbidden:
				return 0, err
			case ctx.Err() != nil:
				return 0, ctx.Err()
			default:
				ambiguous, last = true, err
			}
		}
		if time.Now().After(deadline) {
			if ambiguous {
				return 0, fmt.Errorf("%w (%v)", ErrNoQuorum, last)
			}
			return 0, ErrNoQuorum
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type ownResult struct {
	index uint64
	err   error
}

// recordOwn remembers what happened to this node's own entries (the first
// application of each sequence number; a resent copy is a replay).
func (n *Core) recordOwn(seq, index uint64, err error) {
	n.ownMu.Lock()
	defer n.ownMu.Unlock()
	if n.own == nil {
		n.own = map[uint64]ownResult{}
	}
	if _, ok := n.own[seq]; ok {
		return
	}
	n.own[seq] = ownResult{index: index, err: err}
	if len(n.own) > 256 {
		for s := range n.own {
			if s+128 < seq {
				delete(n.own, s)
			}
		}
	}
}

func (n *Core) ownResult(seq uint64) (ownResult, bool) {
	n.ownMu.Lock()
	defer n.ownMu.Unlock()
	r, ok := n.own[seq]
	return r, ok
}

// ---- the peer API: core endpoints ---------------------------------------------

func (n *Core) routes() {
	all := access{fenced: true, witness: true}
	n.mux.handle(withPrefix("GET /ping"), all, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerJSON(w, http.StatusOK, map[string]any{"node": n.ID(), "time": time.Now().UTC()})
	}))
	n.mux.handle(withPrefix("POST /propose"), access{witness: true}, http.HandlerFunc(n.handlePropose))
	n.mux.handle(withPrefix("POST /heartbeat"), access{witness: true, fenced: true}, http.HandlerFunc(n.handleHeartbeat))
	n.mux.handle(withPrefix("GET /health"), access{}, http.HandlerFunc(n.handleHealth))
	n.mux.handle(withPrefix("POST /join"), access{public: true}, http.HandlerFunc(n.handleJoin))
	n.mux.handle(withPrefix("GET /status"), access{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerJSON(w, http.StatusOK, n.Status(r.Context()))
	}))
}

func (n *Core) handlePropose(w http.ResponseWriter, r *http.Request) {
	caller, _ := n.mux.Caller(r)
	var sc SignedCommand
	if err := decodePeer(r, &sc); err != nil {
		peerError(w, http.StatusBadRequest, "invalid command")
		return
	}
	var c Command
	if err := json.Unmarshal(sc.Command, &c); err != nil || c.Proposer != caller.ID {
		// A member forwards only what it signed itself.
		peerError(w, http.StatusForbidden, "a member may only propose its own commands")
		return
	}
	if !n.IsLeader() {
		peerError(w, http.StatusMisdirectedRequest, "not the leader")
		return
	}
	idx, err := n.submitLocal(r.Context(), &sc)
	var re *ErrRefused
	switch {
	case errors.As(err, &re):
		peerJSON(w, http.StatusOK, proposeAnswer{Index: idx, Refused: re.Reason})
	case errors.Is(err, errNotLeader):
		peerError(w, http.StatusMisdirectedRequest, "not the leader")
	case err != nil:
		peerError(w, http.StatusServiceUnavailable, err.Error())
	default:
		peerJSON(w, http.StatusOK, proposeAnswer{Index: idx})
	}
}

var errNotLeader = errors.New("not the leader")

// submitLocal appends on this node, which must lead.
func (n *Core) submitLocal(ctx context.Context, sc *SignedCommand) (uint64, error) {
	r := n.r()
	if r == nil || r.State() != raft.Leader {
		return 0, errNotLeader
	}
	data, err := json.Marshal(sc)
	if err != nil {
		return 0, err
	}
	timeout := 10 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
	}
	f := r.Apply(data, timeout)
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) {
			return 0, errNotLeader
		}
		return 0, err
	}
	res, _ := f.Response().(ApplyResult)
	if res.Err != nil {
		return f.Index(), &ErrRefused{Reason: res.Err.Error()}
	}
	return f.Index(), nil
}

// ---- status ----------------------------------------------------------------------

// NodeStatus is one member as the Cluster app shows it.
type NodeStatus struct {
	Node
	// Live is the suffrage in the Raft configuration (what the state wants
	// may still be on its way).
	Live   Suffrage  `json:"live"`
	Health *Health   `json:"health,omitempty"`
	Path   *PeerPath `json:"path,omitempty"`
}

// Status is this node's view of the cluster.
type Status struct {
	Member       bool         `json:"member"`
	Cluster      ClusterID    `json:"cluster,omitempty"`
	Name         string       `json:"name,omitempty"`
	Self         NodeID       `json:"self,omitempty"`
	Role         Role         `json:"role,omitempty"`
	Leader       NodeID       `json:"leader,omitempty"`
	Quorate      bool         `json:"quorate"`
	QuorateUntil time.Time    `json:"quorateUntil,omitempty"`
	Term         uint64       `json:"term"`
	Index        uint64       `json:"index"`
	FeatureLevel int          `json:"featureLevel"`
	Halted       string       `json:"halted,omitempty"`
	Nodes        []NodeStatus `json:"nodes"`
	Timings      Timings      `json:"timings"`
}

// Status reports this node's view (health from the leader when reachable).
func (n *Core) Status(ctx context.Context) Status {
	st := Status{Nodes: []NodeStatus{}}
	info := n.Info()
	if info == nil {
		return st
	}
	snap := n.cfg.Machine.Snapshot()
	st.Member, st.Cluster, st.Name, st.Self, st.Role = true, info.Cluster, info.Name, info.Node, info.Role
	if snap.Name != "" {
		st.Name = snap.Name
	}
	st.Leader, _ = n.Leader()
	st.Quorate, st.QuorateUntil = n.Quorate()
	st.Index, st.FeatureLevel, st.Timings = snap.Index, snap.FeatureLevel, n.timings()
	if h := n.Halted(); h != nil {
		st.Halted = h.Error()
	}
	live := map[NodeID]Suffrage{}
	if r := n.r(); r != nil {
		if s := r.Stats(); s != nil {
			st.Term, _ = strconv.ParseUint(s["term"], 10, 64)
		}
		if f := r.GetConfiguration(); f.Error() == nil {
			for _, s := range f.Configuration().Servers {
				if s.Suffrage == raft.Voter {
					live[NodeID(s.ID)] = Voter
				} else {
					live[NodeID(s.ID)] = NonVoter
				}
			}
		}
	}
	hctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	health, _ := n.Health(hctx)
	cancel()
	hm := map[NodeID]Health{}
	for _, h := range health {
		hm[h.Node] = h
	}
	pm := map[NodeID]PeerPath{}
	for _, p := range n.path.Status() {
		pm[p.Node] = p
	}
	ids := make([]NodeID, 0, len(snap.Nodes))
	for id := range snap.Nodes {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		ns := NodeStatus{Node: *snap.Nodes[id], Live: live[id]}
		ns.PublicKey = nil
		if h, ok := hm[id]; ok {
			hh := h
			ns.Health = &hh
		}
		if p, ok := pm[id]; ok {
			pp := p
			ns.Path = &pp
		}
		if ns.Live == "" {
			ns.Live = NonVoter
		}
		st.Nodes = append(st.Nodes, ns)
	}
	return st
}

// hclogFor sends Raft's warnings and errors to slog.
func hclogFor(l *slog.Logger) hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{Name: "raft", Level: hclog.Warn, Output: slogWriter{l}, DisableTime: true})
}

type slogWriter struct{ l *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	if w.l != nil {
		w.l.Warn("cluster: raft", "msg", string(p))
	}
	return len(p), nil
}
