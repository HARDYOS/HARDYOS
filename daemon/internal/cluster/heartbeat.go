package cluster

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"golang.org/x/net/http2"
)

// Heartbeats and the quorum lease (docs/plans/cluster.md 2.4). Every node
// sends a heartbeat to the leader each Timings.Heartbeat. The leader
// answers only after confirming it still leads (VerifyLeader, cached for
// the leader lease). A node counts itself quorate until sendTime + Q of
// the last heartbeat that got such an answer (monotonic clock). The leader
// records when it last heard each node; a new leader starts everyone's
// clock at its election, so a leader change never shortens the time to
// declare a node dead, and it changes the voter set only once it has heard
// every voter since its election.

// HeartbeatRequest is a node's heartbeat.
type HeartbeatRequest struct {
	Node      NodeID            `json:"node"`
	BootID    string            `json:"bootId"`
	Version   string            `json:"version"`
	Quorate   bool              `json:"quorate"`
	StorageOK bool              `json:"storageOK"`
	LANOK     bool              `json:"lanOK"`
	Running   []RunningWorkload `json:"running,omitempty"`
	// Sent is the sender's own send time (Unix nanoseconds), echoed in the
	// leader's signed statement so an old answer can't be replayed.
	Sent int64 `json:"sent"`
}

// HeartbeatAnswer is the leader's answer.
type HeartbeatAnswer struct {
	Term   uint64 `json:"term"`
	Leader NodeID `json:"leader"`
	// View is the leader's record of the node.
	View *Node `json:"view,omitempty"`
	// Statement is a LeaderStatement (JSON) and Signature the leader's
	// ES256 signature (ASN.1) over it (decision 367): only this proves the
	// quorum, not the TLS connection alone.
	Statement json.RawMessage `json:"statement"`
	Signature []byte          `json:"signature"`
}

// LeaderStatement is what a leader signs in a heartbeat answer: it leads
// in Term with Commit committed, and heard Node's heartbeat sent at Sent.
// It is also the quorum lease root checks before it pets the watchdog
// (lease.go): Node is quorate until Sent + LeaseMs on its own clock.
type LeaderStatement struct {
	Cluster ClusterID `json:"cluster"`
	Leader  NodeID    `json:"leader"`
	Node    NodeID    `json:"node"`
	Term    uint64    `json:"term"`
	Commit  uint64    `json:"commit"`
	// Sent is the node's own send time of the heartbeat (Unix ns).
	Sent int64 `json:"sent"`
	// LeaseMs is the quorum lease the leader grants from Sent (Q).
	LeaseMs int64 `json:"leaseMs"`
	// Keys is the KeySetHash of the leader's LeaseKeySet: the members that
	// may lead, as the leader knows them.
	Keys string `json:"keys,omitempty"`
}

func signStatement(id *Identity, st LeaderStatement) (json.RawMessage, []byte, error) {
	raw, err := json.Marshal(st)
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256(append([]byte(StatementDomain), raw...))
	sig, err := ecdsa.SignASN1(rand.Reader, id.Key, sum[:])
	return raw, sig, err
}

// statementFor is the statement this node (the leader) signs for node's
// heartbeat sent at sent.
func (n *Core) statementFor(node NodeID, sent int64) LeaderStatement {
	st := LeaderStatement{Leader: n.ID(), Node: node, Sent: sent, LeaseMs: n.timings().QuorumLease.Milliseconds(), Keys: n.keySetHash()}
	if info := n.Info(); info != nil {
		st.Cluster = info.Cluster
	}
	if r := n.r(); r != nil {
		st.Term, _ = strconv.ParseUint(r.Stats()["term"], 10, 64)
		st.Commit = r.CommitIndex()
	}
	return st
}

// keySetHash is the KeySetHash of the current LeaseKeySet, cached per
// applied index.
func (n *Core) keySetHash() string {
	idx := n.cfg.Machine.Index()
	n.live.mu.Lock()
	if n.live.keysAt == idx && n.live.keys != "" {
		h := n.live.keys
		n.live.mu.Unlock()
		return h
	}
	n.live.mu.Unlock()
	h := KeySetHash(LeaseKeySet(n.cfg.Machine.Snapshot()))
	n.live.mu.Lock()
	n.live.keysAt, n.live.keys = idx, h
	n.live.mu.Unlock()
	return h
}

// LeaseStatement implements fence.LeaseSource: the latest leader-signed
// statement for this node's heartbeat (SignedStatement JSON), while the
// lease it grants hasn't run out.
func (n *Core) LeaseStatement() ([]byte, bool) {
	n.live.mu.Lock()
	sst, sent, lease := n.live.statement, n.live.stmtSent, n.live.stmtLease
	n.live.mu.Unlock()
	if sst == nil || time.Now().After(time.Unix(0, sent).Add(lease)) {
		return nil, false
	}
	raw, err := json.Marshal(sst)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// keepStatement remembers a verified statement for this node.
func (n *Core) keepStatement(raw json.RawMessage, sig []byte, st *LeaderStatement) {
	n.live.mu.Lock()
	defer n.live.mu.Unlock()
	if st.Sent < n.live.stmtSent {
		return
	}
	n.live.statement = &SignedStatement{Statement: raw, Signature: sig}
	n.live.stmtSent, n.live.stmtLease = st.Sent, time.Duration(st.LeaseMs)*time.Millisecond
}

// verifyStatement checks a heartbeat answer: signed by the leader that was
// asked, a member that may lead by this node's state (never the witness),
// for this node and this very heartbeat.
func (n *Core) verifyStatement(leader NodeID, sent int64, ans *HeartbeatAnswer) (*LeaderStatement, error) {
	info := n.Info()
	if info == nil {
		return nil, ErrNotMember
	}
	m, ok := n.Member(leader)
	if !ok || !MayLead(m) {
		return nil, fmt.Errorf("%s may not answer heartbeats", leader)
	}
	st, err := VerifyStatement(m.PublicKey, ans.Statement, ans.Signature)
	if err != nil {
		return nil, err
	}
	if st.Cluster != info.Cluster || st.Leader != leader || st.Node != info.Node || st.Sent != sent {
		return nil, errors.New("the leader's statement is for another heartbeat")
	}
	return st, nil
}

type liveness struct {
	mu       sync.Mutex
	lease    time.Time // quorate until (monotonic)
	quorate  bool
	elected  time.Time // when this node last became leader
	verified time.Time // last successful VerifyLeader
	// the latest leader-signed statement for this node (LeaseStatement)
	statement *SignedStatement
	stmtSent  int64
	stmtLease time.Duration
	// the KeySetHash cache (keySetHash)
	keysAt    uint64
	keys      string
	lastHeard map[NodeID]time.Time
	heard     map[NodeID]bool // heard since this node's election
	reports   map[NodeID]Health
}

func (l *liveness) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lease, l.quorate = time.Time{}, false
	l.statement, l.stmtSent, l.stmtLease = nil, 0, 0
	l.lastHeard, l.heard, l.reports = map[NodeID]time.Time{}, map[NodeID]bool{}, map[NodeID]Health{}
}

// timings are the liveness timings in effect.
func (n *Core) timings() Timings {
	if n.cfg.Timings != nil {
		return *n.cfg.Timings
	}
	t := n.cfg.Machine.Snapshot().Timings
	if t.Heartbeat == 0 {
		return DefaultTimings
	}
	return t
}

// Quorate implements Membership.
func (n *Core) Quorate() (bool, time.Time) {
	n.live.mu.Lock()
	defer n.live.mu.Unlock()
	return time.Now().Before(n.live.lease), n.live.lease
}

func (n *Core) extendLease(sent time.Time) {
	q := n.timings().QuorumLease
	n.live.mu.Lock()
	until := sent.Add(q)
	if until.After(n.live.lease) {
		n.live.lease = until
	}
	n.live.mu.Unlock()
}

// checkQuorate publishes a change of the lease's validity.
func (n *Core) checkQuorate() {
	ok, _ := n.Quorate()
	n.live.mu.Lock()
	changed := ok != n.live.quorate
	n.live.quorate = ok
	n.live.mu.Unlock()
	if changed {
		leader, _ := n.Leader()
		n.events.publish(Event{Index: n.cfg.Machine.Index(), Leader: leader, Quorate: ok})
	}
}

func (n *Core) localHealth(ctx context.Context) LocalHealth {
	if n.cfg.Health != nil {
		return n.cfg.Health(ctx)
	}
	return LocalHealth{StorageOK: true, LANOK: true}
}

// verifyLeader confirms leadership, cached within the leader lease.
func (n *Core) verifyLeader() bool {
	r := n.r()
	if r == nil || r.State() != raft.Leader {
		return false
	}
	n.live.mu.Lock()
	fresh := time.Since(n.live.verified) < n.cfg.Raft.LeaderLease
	n.live.mu.Unlock()
	if fresh {
		return true
	}
	if r.VerifyLeader().Error() != nil {
		return false
	}
	n.live.mu.Lock()
	n.live.verified = time.Now()
	n.live.mu.Unlock()
	return true
}

func (n *Core) heartbeatLoop(ctx context.Context) {
	for {
		t := n.timings()
		n.beat(ctx, t)
		n.checkQuorate()
		select {
		case <-ctx.Done():
			return
		case <-time.After(t.Heartbeat):
		}
	}
}

func (n *Core) beat(ctx context.Context, t Timings) {
	self := n.ID()
	sent := time.Now()
	lh := n.localHealth(ctx)
	q, _ := n.Quorate()
	req := HeartbeatRequest{Node: self, BootID: n.cfg.BootID, Version: n.cfg.Version, Quorate: q,
		StorageOK: lh.StorageOK, LANOK: lh.LANOK, Running: lh.Running, Sent: sent.UnixNano()}
	if n.IsLeader() {
		if n.verifyLeader() {
			n.extendLease(sent)
			n.record(req, time.Now())
			// The leader's own lease, signed like every other member's,
			// for its root (fence.LeaseSource).
			st := n.statementFor(self, req.Sent)
			if raw, sig, err := signStatement(n.cfg.Identity, st); err == nil {
				n.keepStatement(raw, sig, &st)
			}
		}
		return
	}
	leader, ok := n.Leader()
	if !ok {
		return
	}
	hctx, cancel := context.WithTimeout(ctx, t.Heartbeat*2)
	defer cancel()
	var ans HeartbeatAnswer
	if err := n.peerc().Call(hctx, leader, http.MethodPost, "/heartbeat", req, &ans); err != nil {
		n.log.Debug("cluster: heartbeat", "leader", leader, "err", err)
		return
	}
	st, err := n.verifyStatement(leader, req.Sent, &ans)
	if err != nil {
		n.log.Debug("cluster: heartbeat answer refused", "leader", leader, "err", err)
		return
	}
	n.extendLease(sent)
	n.keepStatement(ans.Statement, ans.Signature, st)
}

func (n *Core) record(req HeartbeatRequest, at time.Time) {
	n.live.mu.Lock()
	defer n.live.mu.Unlock()
	n.live.lastHeard[req.Node] = at
	n.live.heard[req.Node] = true
	n.live.reports[req.Node] = Health{Node: req.Node, Quorate: req.Quorate, StorageOK: req.StorageOK, LANOK: req.LANOK,
		Running: slices.Clone(req.Running)}
}

func (n *Core) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	caller, _ := n.mux.Caller(r)
	var req HeartbeatRequest
	if err := decodePeer(r, &req); err != nil {
		peerError(w, http.StatusBadRequest, "invalid heartbeat")
		return
	}
	if req.Node != caller.ID {
		peerError(w, http.StatusForbidden, "a member may only send its own heartbeat")
		return
	}
	if !n.verifyLeader() {
		peerError(w, http.StatusMisdirectedRequest, "not the leader")
		return
	}
	n.record(req, time.Now())
	st := n.statementFor(caller.ID, req.Sent)
	ans := HeartbeatAnswer{Leader: n.ID(), Term: st.Term}
	var err error
	if ans.Statement, ans.Signature, err = signStatement(n.cfg.Identity, st); err != nil {
		peerError(w, http.StatusInternalServerError, "couldn't sign the answer")
		return
	}
	if v, ok := n.cfg.Machine.Node(caller.ID); ok {
		v.PublicKey = nil
		ans.View = v
	}
	peerJSON(w, http.StatusOK, ans)

}

// Health implements Membership: the leader's view, from the leader.
func (n *Core) Health(ctx context.Context) ([]Health, error) {
	if n.Info() == nil {
		return nil, ErrNotMember
	}
	if n.IsLeader() {
		return n.leaderHealth(), nil
	}
	leader, ok := n.Leader()
	if !ok {
		return nil, ErrNoQuorum
	}
	var out []Health
	if err := n.peerc().Call(ctx, leader, http.MethodGet, "/health", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (n *Core) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !n.IsLeader() {
		peerError(w, http.StatusMisdirectedRequest, "not the leader")
		return
	}
	peerJSON(w, http.StatusOK, n.leaderHealth())
}

func (n *Core) leaderHealth() []Health {
	t := n.timings()
	now := time.Now()
	snap := n.cfg.Machine.Snapshot()
	n.live.mu.Lock()
	defer n.live.mu.Unlock()
	out := []Health{}
	ids := make([]NodeID, 0, len(snap.Nodes))
	for id := range snap.Nodes {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		h := n.live.reports[id]
		h.Node = id
		last, ok := n.live.lastHeard[id]
		if !ok {
			last = n.live.elected
		}
		h.LastHeard = last
		h.Suspect = now.Sub(last) > t.Suspect
		h.Path = n.path.Current(id)
		if id == n.ID() {
			h.Path = PathLAN
		}
		for _, p := range n.path.Status() {
			if p.Node == id {
				h.RTT = p.RTT
			}
		}
		if h.Path == "" {
			h.Path = PathNone
		}
		out = append(out, h)
	}
	return out
}

// ---- the leader's duties ----------------------------------------------------------

func (n *Core) leaderLoop(ctx context.Context) {
	r := n.r()
	if r == nil {
		return
	}
	obs := make(chan raft.Observation, 16)
	o := raft.NewObserver(obs, false, func(o *raft.Observation) bool {
		_, ok := o.Data.(raft.LeaderObservation)
		return ok
	})
	r.RegisterObserver(o)
	defer r.DeregisterObserver(o)
	tick := time.NewTicker(n.cfg.Raft.Heartbeat / 2)
	defer tick.Stop()
	wasLeader := false
	for {
		select {
		case <-ctx.Done():
			return
		case ob := <-obs:
			if lo, ok := ob.Data.(raft.LeaderObservation); ok {
				q, _ := n.Quorate()
				n.events.publish(Event{Index: n.cfg.Machine.Index(), Leader: NodeID(lo.LeaderID), Quorate: q})
			}
		case <-tick.C:
		}
		leading := r.State() == raft.Leader
		if leading && !wasLeader {
			n.becameLeader()
		}
		wasLeader = leading
		if !leading {
			continue
		}
		if n.role() == RoleWitness {
			// The witness never coordinates (decision 322).
			if err := r.LeadershipTransfer().Error(); err != nil {
				n.log.Debug("cluster: witness handing leadership over", "err", err)
			}
			continue
		}
		n.reconcile(r)
	}
}

func (n *Core) becameLeader() {
	now := time.Now()
	n.live.mu.Lock()
	n.live.elected = now
	n.live.heard = map[NodeID]bool{n.ID(): true}
	for id := range n.cfg.Machine.PinIndex() {
		_ = id
	}
	for _, m := range n.peers() {
		n.live.lastHeard[m.ID] = now
	}
	n.live.mu.Unlock()
	n.log.Info("cluster: this server leads the cluster")
}

// DesiredSuffrage is each member's suffrage as the state wants it: the
// HardyOS voters (decision 322) plus the witness when their count is even.
func DesiredSuffrage(s *Snapshot) map[NodeID]Suffrage {
	out := map[NodeID]Suffrage{}
	voters := 0
	for id, m := range s.Nodes {
		out[id] = NonVoter
		if m.Role == RoleWitness {
			continue
		}
		switch m.State {
		case NodeJoining, NodeMaintenance, NodeRemoved:
			continue
		}
		out[id] = Voter
		voters++
	}
	if voters > 0 && voters%2 == 0 {
		for id, m := range s.Nodes {
			if m.Role == RoleWitness && m.State == NodeActive {
				out[id] = Voter
			}
		}
	}
	return out
}

// reconcile brings Raft's configuration to what the state wants: new
// members join as non-voters, removed ones leave, and voter changes happen
// only while every current voter has been heard since this election and
// within the suspect time (nothing is ever shrunk because a voter is
// unreachable).
func (n *Core) reconcile(r *raft.Raft) {
	f := r.GetConfiguration()
	if f.Error() != nil {
		return
	}
	cfg := f.Configuration()
	snap := n.cfg.Machine.Snapshot()
	if snap.Cluster == "" {
		return
	}
	want := DesiredSuffrage(snap)
	have := map[NodeID]raft.ServerSuffrage{}
	for _, s := range cfg.Servers {
		have[NodeID(s.ID)] = s.Suffrage
	}
	idx := cfg.Servers
	_ = idx
	// Removed members leave the configuration (an administrator's
	// decision, committed in the log).
	for id := range have {
		if _, ok := snap.Nodes[id]; !ok && id != n.ID() {
			if err := r.RemoveServer(raft.ServerID(id), 0, 5*time.Second).Error(); err != nil {
				n.log.Warn("cluster: removing a member from the log's configuration", "node", id, "err", err)
			}
			return
		}
	}
	// New members catch up as non-voters.
	ids := make([]NodeID, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if _, ok := have[id]; !ok {
			if err := r.AddNonvoter(raft.ServerID(id), raft.ServerAddress(id), 0, 5*time.Second).Error(); err != nil {
				n.log.Warn("cluster: adding a member", "node", id, "err", err)
			}
			return
		}
	}
	// Voter changes only with every voter heard.
	t := n.timings()
	now := time.Now()
	n.live.mu.Lock()
	allHeard := true
	for id, s := range have {
		if s != raft.Voter || id == n.ID() {
			continue
		}
		if !n.live.heard[id] || now.Sub(n.live.lastHeard[id]) > t.Suspect {
			allHeard = false
		}
	}
	n.live.mu.Unlock()
	if !allHeard {
		return
	}
	for _, id := range ids {
		cur := have[id]
		switch {
		case want[id] == Voter && cur != raft.Voter:
			if err := r.AddVoter(raft.ServerID(id), raft.ServerAddress(id), 0, 5*time.Second).Error(); err != nil {
				n.log.Warn("cluster: promoting a member", "node", id, "err", err)
			}
			return
		case want[id] == NonVoter && cur == raft.Voter:
			if id == n.ID() {
				// Hand over first; the next leader demotes this node.
				_ = r.LeadershipTransfer().Error()
				return
			}
			if err := r.DemoteVoter(raft.ServerID(id), 0, 5*time.Second).Error(); err != nil {
				n.log.Warn("cluster: demoting a member", "node", id, "err", err)
			}
			return
		}
	}
}

// ---- probes and path switches ---------------------------------------------------

// probe sends GET /ping to a peer over one path, on a kept-alive HTTP/2
// connection per peer and path.
func (n *Core) probe(ctx context.Context, peer Node, p Path) (time.Duration, error) {
	a := pathAddr(peer.Addresses, p)
	if !a.IsValid() {
		return 0, ErrUnreachable
	}
	key := string(peer.ID) + "/" + string(p) + "/" + peer.Pin
	addr := net.JoinHostPort(a.String(), strconv.Itoa(n.trn().port()))
	n.probeMu.Lock()
	t := n.probes[key]
	if t == nil {
		pin := peer.Pin
		tr := n.trn()
		t = &http2.Transport{
			DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
				return tr.DialAddr(ctx, addr, ALPNPeer, pin, nil)
			},
			ReadIdleTimeout: 2 * time.Second,
			PingTimeout:     time.Second,
		}
		n.probes[key] = t
	}
	n.probeMu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+string(peer.ID)+PeerPathPrefix+"ping", nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := t.RoundTrip(req)
	if err != nil {
		t.CloseIdleConnections()
		return 0, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, ErrUnreachable
	}
	return time.Since(start), nil
}

// dropProbes forgets the probe connections to a peer's address on a path
// (after a link cut the next probe dials again).
func (n *Core) pathSwitched(id NodeID, from, to Path) {
	n.log.Info("cluster: control path changed", "node", id, "from", from, "to", to)
	if from != PathNone {
		// Connections on the path left behind are redialled on the new one
		// (the first choice keeps what is already connected).
		n.trn().DropConns(id)
	}
	n.events.publish(Event{Index: n.cfg.Machine.Index(), Node: id})
}

// ---- events -------------------------------------------------------------------------

type broker struct {
	mu   sync.Mutex
	subs map[chan Event]bool
}

func (b *broker) subscribe(ctx context.Context) <-chan Event {
	ch := make(chan Event, 64)
	b.mu.Lock()
	if b.subs == nil {
		b.subs = map[chan Event]bool{}
	}
	b.subs[ch] = true
	b.mu.Unlock()
	go func() {
		<-ctx.Done()
		b.mu.Lock()
		delete(b.subs, ch)
		close(ch)
		b.mu.Unlock()
	}()
	return ch
}

func (b *broker) publish(e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default: // a slow subscriber misses events; it rereads the state
		}
	}
}
