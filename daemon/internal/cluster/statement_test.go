package cluster

import (
	"testing"
	"time"
)

var testTime = time.Unix(1700000000, 0)

// fakeMachine is enough of a state machine for Member and ByPin.
type fakeMachine struct {
	StateMachine
	nodes map[NodeID]Node
}

func (m fakeMachine) Node(id NodeID) (*Node, bool) {
	n, ok := m.nodes[id]
	return &n, ok
}

func (m fakeMachine) PinIndex() map[string]Node {
	out := map[string]Node{}
	for _, n := range m.nodes {
		out[n.Pin] = n
	}
	return out
}

func testIdentity(t *testing.T, name string) *Identity {
	t.Helper()
	id, err := NewIdentity(name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func nodeOf(id *Identity, nid NodeID, role Role, st NodeState) Node {
	return Node{ID: nid, Role: role, State: st, Pin: id.Pin, PublicKey: id.PublicKey}
}

// Only a leader-signed statement for this very heartbeat extends the
// quorum lease, and never one the witness signed (decision 367).
func TestHeartbeatStatement(t *testing.T) {
	leaderID, witnessID, selfID := testIdentity(t, "nas"), testIdentity(t, "w"), testIdentity(t, "c1")
	nodes := map[NodeID]Node{
		"nas":     nodeOf(leaderID, "nas", RoleStorage, NodeActive),
		"witness": nodeOf(witnessID, "witness", RoleWitness, NodeActive),
		"c1":      nodeOf(selfID, "c1", RoleCompute, NodeActive),
		"c2":      nodeOf(testIdentity(t, "c2"), "c2", RoleCompute, NodeFenced),
	}
	n := &Core{info: &Info{Cluster: "abc", Node: "c1"}, cfg: Config{Identity: selfID, Machine: fakeMachine{nodes: nodes}}}
	answer := func(signer *Identity, st LeaderStatement) *HeartbeatAnswer {
		raw, sig, err := signStatement(signer, st)
		if err != nil {
			t.Fatal(err)
		}
		return &HeartbeatAnswer{Statement: raw, Signature: sig}
	}
	good := LeaderStatement{Cluster: "abc", Leader: "nas", Node: "c1", Term: 3, Commit: 10, Sent: 42}
	if _, err := n.verifyStatement("nas", 42, answer(leaderID, good)); err != nil {
		t.Fatalf("good answer: %v", err)
	}
	if _, err := n.verifyStatement("nas", 43, answer(leaderID, good)); err == nil {
		t.Fatal("an old answer was accepted")
	}
	other := good
	other.Node = "c2"
	if _, err := n.verifyStatement("nas", 42, answer(leaderID, other)); err == nil {
		t.Fatal("another node's answer was accepted")
	}
	if _, err := n.verifyStatement("nas", 42, answer(witnessID, good)); err == nil {
		t.Fatal("an answer signed with another key was accepted")
	}
	w := good
	w.Leader = "witness"
	if _, err := n.verifyStatement("witness", 42, answer(witnessID, w)); err == nil {
		t.Fatal("the witness's answer was accepted")
	}
	if _, err := n.verifyStatement("nas", 42, &HeartbeatAnswer{}); err == nil {
		t.Fatal("an unsigned answer was accepted")
	}
}

// A snapshot can't roll a node back, swap a key, raise a role or drop the
// node itself (decision 365).
func TestCheckSnapshot(t *testing.T) {
	selfID := testIdentity(t, "c1")
	n := &Core{info: &Info{Cluster: "abc", Node: "c1"}, cfg: Config{Identity: selfID}}
	base := func() *Snapshot {
		return &Snapshot{Cluster: "abc", Index: 10, Nodes: map[NodeID]*Node{
			"c1":      {ID: "c1", Role: RoleCompute, Pin: selfID.Pin, PublicKey: selfID.PublicKey},
			"nas":     {ID: "nas", Role: RoleStorage, Pin: "aa"},
			"witness": {ID: "witness", Role: RoleWitness, Pin: "bb"},
		}}
	}
	cur := base()
	next := base()
	next.Index = 20
	if err := n.checkSnapshot(cur, next); err != nil {
		t.Fatalf("good snapshot: %v", err)
	}
	if err := n.checkSnapshot(&Snapshot{}, next); err != nil {
		t.Fatalf("snapshot on an empty state: %v", err)
	}
	for name, f := range map[string]func(s *Snapshot){
		"older":         func(s *Snapshot) { s.Index = 10 },
		"other cluster": func(s *Snapshot) { s.Cluster = "xyz" },
		"no self":       func(s *Snapshot) { delete(s.Nodes, "c1") },
		"self key":      func(s *Snapshot) { s.Nodes["c1"].Pin = "cc" },
		"member key":    func(s *Snapshot) { s.Nodes["nas"].Pin = "cc" },
		"witness role":  func(s *Snapshot) { s.Nodes["witness"].Role = RoleCompute },
	} {
		s := base()
		s.Index = 20
		f(s)
		if err := n.checkSnapshot(cur, s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProposeLimiter(t *testing.T) {
	var l proposeLimiter
	now := testTime
	n := 0
	for l.allow("c1", false, now) {
		n++
	}
	if n != int(proposeBurst) {
		t.Fatalf("burst %d", n)
	}
	if !l.allow("c1", false, now.Add(time.Second)) {
		t.Fatal("no refill")
	}
	w := 0
	for l.allow("witness", true, now) {
		w++
	}
	if w != int(witnessBurst) || l.allow("witness", true, now.Add(time.Second)) {
		t.Fatalf("witness burst %d", w)
	}
}
