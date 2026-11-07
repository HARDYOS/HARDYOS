package cluster_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/go-msgpack/v2/codec"
	"github.com/hashicorp/raft"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// sendRaft writes one Raft request (type byte, msgpack body, snapshot
// data) on c and reports whether the other side closed the connection
// instead of answering.
func sendRaft(t *testing.T, c net.Conn, typ uint8, req any, data []byte) (closed bool) {
	t.Helper()
	// Written while reading: on the fake network's synchronous pipes the
	// other side's close_notify would otherwise wait for the write.
	go func() {
		w := bufio.NewWriter(c)
		_ = w.WriteByte(typ)
		_ = codec.NewEncoder(w, &codec.MsgpackHandle{BasicHandle: codec.BasicHandle{TimeNotBuiltin: true}}).Encode(req)
		_, _ = w.Write(data)
		_ = w.Flush()
	}()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b [1]byte
	_, err := c.Read(b[:])
	return err == io.EOF || (err != nil && !isTimeout(err))
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func term(n *tnode) uint64 { return n.core.Status(context.Background()).Term }

// The witness (and any member) can't make Raft believe it is someone else
// or a leader (decision 365): forged AppendEntries and InstallSnapshot from
// the witness, and an AppendEntries in another member's name, are dropped
// with their connection; nobody's term moves and the leader stays.
func TestForgedRaftMessagesIgnored(t *testing.T) {
	h, nas, c1, c2, w := build4(t)
	l := h.leader(nas, c1, c2)
	before := map[cluster.NodeID]uint64{}
	for _, n := range []*tnode{nas, c1, c2} {
		before[n.id] = term(n)
	}
	high := before[l.id] + 1000
	hdr := func(id string) raft.RPCHeader {
		return raft.RPCHeader{ProtocolVersion: raft.ProtocolVersionMax, ID: []byte(id), Addr: []byte(id)}
	}
	for _, target := range []*tnode{nas, c1, c2} {
		// The witness, as itself: refused at the connection.
		conn, _, err := w.core.Transport().DialNode(ctx(t), target.id, cluster.ALPNRaft)
		if err == nil {
			ae := raft.AppendEntriesRequest{RPCHeader: hdr("witness"), Term: high, Leader: []byte("witness"), LeaderCommitIndex: 1 << 40}
			if !sendRaft(t, conn, 0, &ae, nil) {
				t.Fatalf("%s answered the witness's AppendEntries", target.id)
			}
			conn.Close()
		}
		conn, _, err = w.core.Transport().DialNode(ctx(t), target.id, cluster.ALPNRaft)
		if err == nil {
			data := []byte(`{"cluster":"x","nodes":{}}`)
			is := raft.InstallSnapshotRequest{RPCHeader: hdr("witness"), SnapshotVersion: 1, Term: high, Leader: []byte("witness"),
				LastLogIndex: 1 << 40, LastLogTerm: high, Size: int64(len(data))}
			if !sendRaft(t, conn, 2, &is, data) {
				t.Fatalf("%s answered the witness's InstallSnapshot", target.id)
			}
			conn.Close()
		}
	}
	// A member that may lead, claiming to be another member.
	other := nas
	if l.id == nas.id {
		other = c1
	}
	var victim *tnode
	for _, n := range []*tnode{nas, c1, c2} {
		if n.id != other.id && n.id != l.id {
			victim = n
		}
	}
	conn, _, err := other.core.Transport().DialNode(ctx(t), victim.id, cluster.ALPNRaft)
	if err != nil {
		t.Fatal(err)
	}
	ae := raft.AppendEntriesRequest{RPCHeader: hdr(string(l.id)), Term: high, Leader: []byte(l.id)}
	if !sendRaft(t, conn, 0, &ae, nil) {
		t.Fatal("an AppendEntries in another member's name was answered")
	}
	conn.Close()
	time.Sleep(500 * time.Millisecond)
	for _, n := range []*tnode{nas, c1, c2} {
		if got := term(n); got >= high {
			t.Fatalf("%s's term moved to %d", n.id, got)
		}
	}
	if nl := h.leader(nas, c1, c2); nl == nil {
		t.Fatal("no leader after the forged messages")
	}
	if s := w.core.Status(ctx(t)); s.Leader == "witness" {
		t.Fatal("the witness leads")
	}
}
