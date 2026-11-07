package cluster

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/go-msgpack/v2/codec"
	"github.com/hashicorp/raft"
)

// The Raft guard (decision 365). Raft's own messages say who sent them
// (the RPC header's ID and address, AppendEntries' leader, RequestVote's
// candidate), and Raft believes them. On the cluster port the sender is
// known for sure: the TLS peer's pinned key. So every accepted Raft
// connection is read by the guard first, one request at a time: it decodes
// the request, refuses it (closing the connection) unless the claimed
// sender is the TLS peer and that member may lead, and hands Raft a
// re-encoded copy. Every request type a server receives on an inbound
// connection is one only a leader or a candidate sends (AppendEntries,
// InstallSnapshot, TimeoutNow, RequestVote, RequestPreVote), so the
// witness, joining, dead and fenced members are refused outright: the
// witness can't win an election any more, and a member that may not lead
// can't make others follow it. The rule is checked again for every request
// (the state may have changed meanwhile), and inbound connections of a
// member that is removed, fenced or declared dead are closed as soon as
// that entry applies (RecheckInbound).
//
// This makes Raft trust only what the TLS layer proves. It doesn't make it
// Byzantine fault tolerant: a compromised member that may lead can still
// misbehave as a leader (send a forged log to a follower, withhold
// entries). Signed commands keep it from putting words in another member's
// mouth; snapshots are checked against the current state (checkSnapshot).

// Raft's wire types (hashicorp/raft net_transport.go; fixed by its
// protocol).
const (
	rpcAppendEntries uint8 = iota
	rpcRequestVote
	rpcInstallSnapshot
	rpcTimeoutNow
	rpcRequestPreVote
)

// RaftRPC is what the guard read of one Raft request.
type RaftRPC struct {
	Type uint8
	// ID and Addr are the RPC header's; Claimed is AppendEntries' and
	// InstallSnapshot's leader or RequestVote's candidate ("" when unset).
	ID, Addr, Claimed string
}

// raftAddr is a net.Addr that is a node id: Raft's local address is its
// server address, the node id the stream layer dials.
type raftAddr NodeID

func (a raftAddr) Network() string { return "hardyos-raft" }
func (a raftAddr) String() string  { return string(a) }

// raftAdmit decides whether a Raft request from peer may reach Raft.
func (n *Core) raftAdmit(peer Node, rpc RaftRPC) error { return n.raftAdmitWith(n, peer, rpc) }

func (n *Core) raftAdmitWith(book PeerBook, peer Node, rpc RaftRPC) error {
	cur, ok := book.ByPin(peer.Pin)
	if !ok || cur.ID != peer.ID {
		return errors.New("no longer a member")
	}
	id := string(cur.ID)
	if rpc.ID != id || rpc.Addr != id || (rpc.Claimed != "" && rpc.Claimed != id) {
		return fmt.Errorf("the request claims to come from %q (%q), the connection is %s's", rpc.ID, rpc.Addr, id)
	}
	if !MayLead(cur) {
		return fmt.Errorf("a %s %s member may not send %s", cur.State, cur.Role, raftRPCName(rpc.Type))
	}
	return nil
}

func raftRPCName(t uint8) string {
	switch t {
	case rpcAppendEntries:
		return "AppendEntries"
	case rpcRequestVote:
		return "RequestVote"
	case rpcInstallSnapshot:
		return "InstallSnapshot"
	case rpcTimeoutNow:
		return "TimeoutNow"
	case rpcRequestPreVote:
		return "RequestPreVote"
	}
	return fmt.Sprintf("raft message %d", t)
}

// raftGuardConn is an accepted Raft connection as Raft sees it: reads come
// from the guard's re-encoded requests, writes (Raft's answers) go to the
// peer unchanged.
type raftGuardConn struct {
	net.Conn
	pr   *io.PipeReader
	peer Node
	t    *Transport
	once sync.Once
}

func (c *raftGuardConn) Read(b []byte) (int, error) { return c.pr.Read(b) }

func (c *raftGuardConn) Close() error {
	c.once.Do(func() {
		c.t.mu.Lock()
		delete(c.t.inbound, c)
		c.t.mu.Unlock()
	})
	_ = c.pr.Close()
	return c.Conn.Close()
}

// guardRaft wraps an accepted Raft connection (nil: the transport is
// closed).
func (t *Transport) guardRaft(c net.Conn, peer Node) *raftGuardConn {
	pr, pw := io.Pipe()
	g := &raftGuardConn{Conn: c, pr: pr, peer: peer, t: t}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		c.Close()
		return nil
	}
	if t.inbound == nil {
		t.inbound = map[*raftGuardConn]bool{}
	}
	t.inbound[g] = true
	t.mu.Unlock()
	go t.filterRaft(g, pw)
	return g
}

// guardHandle is the encoding Raft's network transport uses.
func guardHandle() *codec.MsgpackHandle {
	return &codec.MsgpackHandle{BasicHandle: codec.BasicHandle{TimeNotBuiltin: true}}
}

// filterRaft reads requests from the peer and passes the admitted ones on.
func (t *Transport) filterRaft(g *raftGuardConn, pw *io.PipeWriter) {
	br := bufio.NewReaderSize(g.Conn, 64<<10)
	dec := codec.NewDecoder(br, &codec.MsgpackHandle{})
	bw := bufio.NewWriterSize(pw, 64<<10)
	enc := codec.NewEncoder(bw, guardHandle())
	fail := func(err error) {
		_ = pw.CloseWithError(err)
		_ = g.Conn.Close()
	}
	for {
		typ, err := br.ReadByte()
		if err != nil {
			fail(err)
			return
		}
		var req any
		var hdr raft.RPCHeader
		var claimed []byte
		var size int64
		switch typ {
		case rpcAppendEntries:
			var r raft.AppendEntriesRequest
			err = dec.Decode(&r)
			req, hdr, claimed = &r, r.RPCHeader, r.Leader
		case rpcRequestVote:
			var r raft.RequestVoteRequest
			err = dec.Decode(&r)
			req, hdr, claimed = &r, r.RPCHeader, r.Candidate
		case rpcRequestPreVote:
			var r raft.RequestPreVoteRequest
			err = dec.Decode(&r)
			req, hdr = &r, r.RPCHeader
		case rpcInstallSnapshot:
			var r raft.InstallSnapshotRequest
			err = dec.Decode(&r)
			req, hdr, claimed, size = &r, r.RPCHeader, r.Leader, r.Size
			if err == nil && (size < 0 || size > maxRaftSnapshot) {
				err = fmt.Errorf("a snapshot of %d bytes", size)
			}
		case rpcTimeoutNow:
			var r raft.TimeoutNowRequest
			err = dec.Decode(&r)
			req, hdr = &r, r.RPCHeader
		default:
			err = fmt.Errorf("unknown raft message %d", typ)
		}
		if err == nil {
			admit := t.RaftAdmit
			if admit == nil {
				err = errors.New("the cluster isn't running")
			} else {
				err = admit(g.peer, RaftRPC{Type: typ, ID: string(hdr.ID), Addr: string(hdr.Addr), Claimed: string(claimed)})
			}
		}
		if err != nil {
			t.refusedRaft(g.peer, typ, err)
			fail(err)
			return
		}
		if err := bw.WriteByte(typ); err != nil {
			fail(err)
			return
		}
		if err := enc.Encode(req); err != nil {
			fail(err)
			return
		}
		if size > 0 {
			if _, err := io.CopyN(bw, br, size); err != nil {
				fail(err)
				return
			}
		}
		if err := bw.Flush(); err != nil {
			fail(err)
			return
		}
	}
}

// maxRaftSnapshot bounds an InstallSnapshot's data (the state is small;
// the restore reads at most 256 MiB).
const maxRaftSnapshot = 256 << 20

// refusedRaft logs a refused Raft request, at most once a minute per peer.
func (t *Transport) refusedRaft(peer Node, typ uint8, err error) {
	t.mu.Lock()
	if t.raftLogged == nil {
		t.raftLogged = map[NodeID]time.Time{}
	}
	last := t.raftLogged[peer.ID]
	now := time.Now()
	quiet := now.Sub(last) < time.Minute
	if !quiet {
		t.raftLogged[peer.ID] = now
	}
	t.mu.Unlock()
	if !quiet {
		t.log().Warn("cluster: refused a raft message", "from", peer.ID, "type", raftRPCName(typ), "err", err)
	}
}

// RecheckInbound closes the inbound Raft connections of members that may
// no longer send Raft requests (removed, fenced, declared dead).
func (t *Transport) RecheckInbound() {
	if t == nil || t.Book == nil {
		return
	}
	t.mu.Lock()
	var gone []*raftGuardConn
	for g := range t.inbound {
		cur, ok := t.Book.ByPin(g.peer.Pin)
		if !ok || cur.ID != g.peer.ID || !MayLead(cur) {
			gone = append(gone, g)
		}
	}
	t.mu.Unlock()
	for _, g := range gone {
		g.Close()
	}
}

// ---- snapshots ----------------------------------------------------------------

// checkSnapshot is the restore check (decision 365): a snapshot is for
// this cluster, has this node with its own key, and, against a non-empty
// current state, is further along the log and keeps every existing
// member's key and role. A member that leads can still send a snapshot
// that differs otherwise (Raft isn't Byzantine fault tolerant), but not
// one that swaps a member's key, turns the witness into a server or
// rolls this node back.
func (n *Core) checkSnapshot(cur, next *Snapshot) error {
	// Raft restores its latest snapshot inside startLocked, under n.mu:
	// read the membership it was started with instead.
	info := n.raftSelf.Load()
	if info == nil {
		info = n.Info()
	}
	if info == nil {
		return ErrNotMember
	}

	if next.Cluster != info.Cluster {
		return errors.New("it is another cluster's")
	}
	me := next.Nodes[info.Node]
	if me == nil || me.Pin != n.cfg.Identity.Pin {
		return errors.New("it doesn't have this server with its own key")
	}
	if cur == nil || cur.Cluster == "" {
		return nil
	}
	if next.Cluster != cur.Cluster {
		return errors.New("it is another cluster's")
	}
	if next.Index <= cur.Index {
		return fmt.Errorf("it is at entry %d, this server is at %d", next.Index, cur.Index)
	}
	for id, o := range cur.Nodes {
		m := next.Nodes[id]
		if m == nil {
			continue
		}
		if m.Pin != o.Pin || string(m.PublicKey) != string(o.PublicKey) {
			return fmt.Errorf("it changes %s's key", id)
		}
		if m.Role != o.Role {
			return fmt.Errorf("it changes %s's role", id)
		}
	}
	return nil
}

// ---- proposals ------------------------------------------------------------------

// proposeLimiter is a token bucket per proposer at the leader (decision
// 372): a member can't flood the log. The leader's own proposals (the HA
// coordinator) aren't limited.
type proposeLimiter struct {
	mu      sync.Mutex
	buckets map[NodeID]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Rates: HardyOS members 20 a second (bursts of 200, a drain's reports);
// the witness only says hello when it starts or changes.
const (
	proposeRate    = 20.0
	proposeBurst   = 200.0
	witnessRate    = 0.1
	witnessBurst   = 3.0
	maxLimitedPeer = 1024
)

func (l *proposeLimiter) allow(id NodeID, witness bool, now time.Time) bool {
	rate, burst := proposeRate, proposeBurst
	if witness {
		rate, burst = witnessRate, witnessBurst
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil || len(l.buckets) > maxLimitedPeer {
		l.buckets = map[NodeID]*bucket{}
	}
	b := l.buckets[id]
	if b == nil {
		b = &bucket{tokens: burst, last: now}
		l.buckets[id] = b
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
