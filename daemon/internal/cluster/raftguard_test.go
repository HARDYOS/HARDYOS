package cluster

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/go-msgpack/v2/codec"
	"github.com/hashicorp/raft"
)

type fakeBook struct{ nodes map[string]Node }

func (b fakeBook) ByPin(pin string) (Node, bool) { n, ok := b.nodes[pin]; return n, ok }
func (b fakeBook) Member(id NodeID) (Node, bool) {
	for _, n := range b.nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

// The guard hands Raft exactly what the leader sent (entries, snapshot
// data), one request at a time, and closes the connection at the first
// request it refuses.
func TestRaftGuardPassesAndRefuses(t *testing.T) {
	leader := Node{ID: "nas", Pin: "p1", Role: RoleStorage, State: NodeActive}
	book := fakeBook{nodes: map[string]Node{"p1": leader}}
	n := &Core{info: &Info{Node: "c1"}}
	tr := &Transport{Book: book}
	tr.RaftAdmit = func(p Node, rpc RaftRPC) error { return n.raftAdmitWith(book, p, rpc) }
	a, b := net.Pipe()
	g := tr.guardRaft(b, leader)
	hdr := raft.RPCHeader{ProtocolVersion: raft.ProtocolVersionMax, ID: []byte("nas"), Addr: []byte("nas")}
	at := time.Unix(1700000000, 123).UTC()
	ae := raft.AppendEntriesRequest{RPCHeader: hdr, Term: 7, PrevLogEntry: 3, PrevLogTerm: 6, LeaderCommitIndex: 3,
		Entries: []*raft.Log{{Index: 4, Term: 7, Type: raft.LogCommand, Data: []byte(`{"command":1}`), AppendedAt: at}}}
	data := bytes.Repeat([]byte("snapshot"), 10000)
	is := raft.InstallSnapshotRequest{RPCHeader: hdr, SnapshotVersion: 1, Term: 7, LastLogIndex: 9, LastLogTerm: 7, Size: int64(len(data))}
	bad := raft.AppendEntriesRequest{RPCHeader: raft.RPCHeader{ID: []byte("c2"), Addr: []byte("c2")}, Term: 99}
	go func() {
		w := bufio.NewWriter(a)
		enc := codec.NewEncoder(w, guardHandle())
		_ = w.WriteByte(rpcAppendEntries)
		_ = enc.Encode(&ae)
		_ = w.WriteByte(rpcInstallSnapshot)
		_ = enc.Encode(&is)
		_, _ = w.Write(data)
		_ = w.WriteByte(rpcAppendEntries)
		_ = enc.Encode(&bad)
		_ = w.Flush()
	}()
	br := bufio.NewReader(g)
	dec := codec.NewDecoder(br, &codec.MsgpackHandle{})
	if typ, _ := br.ReadByte(); typ != rpcAppendEntries {
		t.Fatalf("type %d", typ)
	}
	var gotAE raft.AppendEntriesRequest
	if err := dec.Decode(&gotAE); err != nil {
		t.Fatal(err)
	}
	if gotAE.Term != 7 || len(gotAE.Entries) != 1 || string(gotAE.Entries[0].Data) != `{"command":1}` ||
		!gotAE.Entries[0].AppendedAt.Equal(at) || string(gotAE.ID) != "nas" {
		t.Fatalf("append entries %+v", gotAE)
	}
	if typ, _ := br.ReadByte(); typ != rpcInstallSnapshot {
		t.Fatalf("type %d", typ)
	}
	var gotIS raft.InstallSnapshotRequest
	if err := dec.Decode(&gotIS); err != nil || gotIS.Size != int64(len(data)) {
		t.Fatalf("install snapshot %+v %v", gotIS, err)
	}
	got := make([]byte, gotIS.Size)
	if _, err := io.ReadFull(br, got); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("snapshot data: %v", err)
	}
	// The request in c2's name: the connection ends there.
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("a request in another member's name reached raft")
	}
	_ = g.Close()
	if len(tr.inbound) != 0 {
		t.Fatal("the closed connection is still tracked")
	}
}

func TestRaftAdmitRules(t *testing.T) {
	ok := Node{ID: "nas", Pin: "p1", Role: RoleStorage, State: NodeActive}
	n := &Core{info: &Info{Node: "c1"}}
	for _, tc := range []struct {
		name string
		node Node
		rpc  RaftRPC
		want bool
	}{
		{"active", ok, RaftRPC{ID: "nas", Addr: "nas"}, true},
		{"maintenance", Node{ID: "nas", Pin: "p1", Role: RoleStorage, State: NodeMaintenance}, RaftRPC{ID: "nas", Addr: "nas"}, true},
		{"other id", ok, RaftRPC{ID: "c2", Addr: "nas"}, false},
		{"other addr", ok, RaftRPC{ID: "nas", Addr: ":0"}, false},
		{"other leader", ok, RaftRPC{ID: "nas", Addr: "nas", Claimed: "c2"}, false},
		{"witness", Node{ID: "nas", Pin: "p1", Role: RoleWitness, State: NodeActive}, RaftRPC{ID: "nas", Addr: "nas"}, false},
		{"joining", Node{ID: "nas", Pin: "p1", Role: RoleCompute, State: NodeJoining}, RaftRPC{ID: "nas", Addr: "nas"}, false},
		{"dead", Node{ID: "nas", Pin: "p1", Role: RoleCompute, State: NodeDead}, RaftRPC{ID: "nas", Addr: "nas"}, false},
		{"fenced", Node{ID: "nas", Pin: "p1", Role: RoleCompute, State: NodeFenced}, RaftRPC{ID: "nas", Addr: "nas"}, false},
	} {
		book := fakeBook{nodes: map[string]Node{"p1": tc.node}}
		err := n.raftAdmitWith(book, ok, tc.rpc)
		if (err == nil) != tc.want {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// Removed: not in the book any more.
	if err := n.raftAdmitWith(fakeBook{nodes: map[string]Node{}}, ok, RaftRPC{ID: "nas", Addr: "nas"}); err == nil {
		t.Error("removed member admitted")
	}
}
