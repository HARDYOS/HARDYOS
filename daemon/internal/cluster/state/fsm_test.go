package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

type tnode struct {
	key  *ecdsa.PrivateKey
	node cluster.Node
	seq  uint64
}

func newTNode(t *testing.T, id string, role cluster.Role, lan string) *tnode {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	n := cluster.Node{ID: cluster.NodeID(id), Name: id, Role: role, PublicKey: spki, Pin: PinOfKey(spki)}
	if role == cluster.RoleWitness {
		n.Addresses.NetBird = netip.MustParseAddr(lan)
	} else {
		n.Addresses.LAN = netip.MustParseAddr(lan)
	}
	return &tnode{key: k, node: n}
}

const testCluster = cluster.ClusterID("abcdefghijklmnopqrstuvwxyz")

func (n *tnode) sign(t *testing.T, typ cluster.CommandType, body any) []byte {
	t.Helper()
	n.seq++
	return n.signSeq(t, typ, body, n.seq)
}

func (n *tnode) signSeq(t *testing.T, typ cluster.CommandType, body any, seq uint64) []byte {
	t.Helper()
	b, _ := json.Marshal(body)
	c := cluster.Command{Type: typ, Cluster: testCluster, Proposer: n.node.ID, Seq: seq,
		Actor: cluster.Actor{Kind: "system", Name: "test", Via: n.node.ID}, Time: time.Unix(1700000000, 0).UTC(), Body: b}
	cb, _ := json.Marshal(c)
	sum := sha256.Sum256(cb)
	sig, err := ecdsa.SignASN1(rand.Reader, n.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	e, _ := json.Marshal(cluster.SignedCommand{Command: cb, Signature: sig})
	return e
}

type fsmHarness struct {
	t   *testing.T
	f   *FSM
	idx uint64
	log [][]byte
}

func (h *fsmHarness) apply(entry []byte) Result {
	h.idx++
	h.log = append(h.log, entry)
	return h.f.Apply(h.idx, entry)
}

func (h *fsmHarness) mustApply(entry []byte) {
	h.t.Helper()
	if r := h.apply(entry); r.Err != nil {
		h.t.Fatalf("apply: %v", r.Err)
	}
}

func (h *fsmHarness) mustRefuse(entry []byte, want string) {
	h.t.Helper()
	r := h.apply(entry)
	if r.Err == nil {
		h.t.Fatalf("entry accepted, want refusal %q", want)
	}
	if !errors.Is(r.Err, ErrRefused) || !strings.Contains(r.Err.Error(), want) {
		h.t.Fatalf("refusal %v, want %q", r.Err, want)
	}
}

// cluster with nas (storage) + c1 (compute) active, witness active.
func threeNodes(t *testing.T) (*fsmHarness, *tnode, *tnode, *tnode) {
	h := &fsmHarness{t: t, f: New()}
	nas := newTNode(t, "nas", cluster.RoleStorage, "192.168.1.105")
	c1 := newTNode(t, "c1", cluster.RoleCompute, "192.168.1.21")
	w := newTNode(t, "witness", cluster.RoleWitness, "100.64.0.9")
	h.mustApply(nas.sign(t, cluster.CmdClusterCreate, CreateBody{Cluster: testCluster, Name: "home", Node: nas.node}))
	h.mustApply(nas.sign(t, cluster.CmdMemberAdd, MemberAddBody{Node: c1.node}))
	h.mustApply(c1.sign(t, cluster.CmdMemberReady, MemberReadyBody{}))
	h.mustApply(nas.sign(t, cluster.CmdMemberAdd, MemberAddBody{Node: w.node}))
	h.mustApply(w.sign(t, cluster.CmdWitnessHello, WitnessHelloBody{Addresses: w.node.Addresses, Version: "1.0"}))
	return h, nas, c1, w
}

func TestCreateJoinAndVoters(t *testing.T) {
	h, _, _, _ := threeNodes(t)
	s := h.f.Snapshot()
	if s.Cluster != testCluster || len(s.Nodes) != 3 || s.Index != h.idx {
		t.Fatalf("state: %+v", s)
	}
	for _, id := range []cluster.NodeID{"nas", "c1", "witness"} {
		if s.Nodes[id].State != cluster.NodeActive {
			t.Fatalf("%s is %s", id, s.Nodes[id].State)
		}
	}
	// Two HardyOS voters: the witness votes.
	d := DesiredSuffrage(s)
	if d["nas"] != cluster.Voter || d["c1"] != cluster.Voter || d["witness"] != cluster.Voter {
		t.Fatalf("suffrage %v", d)
	}
}

func TestWitnessStandbyWithThreeServers(t *testing.T) {
	h, nas, _, _ := threeNodes(t)
	c2 := newTNode(t, "c2", cluster.RoleCompute, "192.168.1.22")
	h.mustApply(nas.sign(t, cluster.CmdMemberAdd, MemberAddBody{Node: c2.node}))
	if d := DesiredSuffrage(h.f.Snapshot()); d["c2"] != cluster.NonVoter || d["witness"] != cluster.Voter {
		t.Fatalf("joining c2: %v", d)
	}
	h.mustApply(c2.sign(t, cluster.CmdMemberReady, MemberReadyBody{}))
	if d := DesiredSuffrage(h.f.Snapshot()); d["witness"] != cluster.NonVoter || d["c2"] != cluster.Voter {
		t.Fatalf("3 servers: %v", d)
	}
	// The storage node in maintenance: 2 compute + witness vote.
	h.mustApply(nas.sign(t, cluster.CmdMaintenance, MaintenanceBody{Node: "nas", Enter: true}))
	if d := DesiredSuffrage(h.f.Snapshot()); d["witness"] != cluster.Voter || d["nas"] != cluster.NonVoter {
		t.Fatalf("maintenance: %v", d)
	}
}

func TestForgedAndReplayedEntriesRefused(t *testing.T) {
	h, nas, c1, w := threeNodes(t)
	before, _ := h.f.Encode()

	// c1's key signs an entry claiming to be from nas.
	forged := &tnode{key: c1.key, node: nas.node, seq: 100}
	h.mustRefuse(forged.sign(t, cluster.CmdMemberRemove, MemberRemoveBody{Node: "c1"}), "bad signature")

	// The witness can only say hello.
	h.mustRefuse(w.sign(t, cluster.CmdMemberRemove, MemberRemoveBody{Node: "c1"}), "may not propose")
	h.mustRefuse(w.sign(t, cluster.CmdMaintenance, MaintenanceBody{Node: "c1", Enter: true}), "may not propose")

	// A replayed entry (the same bytes again) and an old sequence number.
	upd := c1.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Version: "1.1"})
	h.mustApply(upd)
	h.mustRefuse(upd, "replayed")
	h.mustRefuse(c1.signSeq(t, cluster.CmdMemberUpdate, MemberUpdateBody{Version: "0.9"}, 1), "replayed")

	// Another cluster's entry.
	other := newTNode(t, "x", cluster.RoleCompute, "10.0.0.1")
	h.mustRefuse(other.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Version: "1"}), "isn't a member")

	// A second cluster.create.
	h.mustRefuse(nas.sign(t, cluster.CmdClusterCreate, CreateBody{Cluster: testCluster, Name: "again", Node: nas.node}), "exists already")

	// Tampered bytes.
	e := c1.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Version: "2"})
	var sc cluster.SignedCommand
	_ = json.Unmarshal(e, &sc)
	sc.Command = []byte(strings.Replace(string(sc.Command), `"2"`, `"3"`, 1))
	e2, _ := json.Marshal(sc)
	h.mustRefuse(e2, "bad signature")

	s := h.f.Snapshot()
	if s.Nodes["c1"].Version != "1.1" || len(s.Nodes) != 3 {
		t.Fatalf("state changed by refused entries: %+v", s.Nodes["c1"])
	}
	_ = before
}

func TestRefusedEntryConsumesSequence(t *testing.T) {
	h, nas, c1, _ := threeNodes(t)
	// Valid signature, failed precondition (c1 isn't in maintenance).
	e := nas.sign(t, cluster.CmdMaintenance, MaintenanceBody{Node: "c1", Enter: false})
	h.mustRefuse(e, "is active")
	// Once the precondition would hold, the same entry still can't be replayed.
	h.mustApply(nas.sign(t, cluster.CmdMaintenance, MaintenanceBody{Node: "c1", Enter: true}))
	h.mustRefuse(e, "replayed")
	_ = c1
}

// signLevel signs a command that says it needs feature level level.
func (n *tnode) signLevel(t *testing.T, typ cluster.CommandType, body any, level int) []byte {
	t.Helper()
	n.seq++
	b, _ := json.Marshal(body)
	c := cluster.Command{Type: typ, Cluster: testCluster, Proposer: n.node.ID, Seq: n.seq, Level: level,
		Actor: cluster.Actor{Kind: "system", Name: "test", Via: n.node.ID}, Time: time.Unix(1700000000, 0).UTC(), Body: b}
	cb, _ := json.Marshal(c)
	sum := sha256.Sum256(cb)
	sig, err := ecdsa.SignASN1(rand.Reader, n.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	e, _ := json.Marshal(cluster.SignedCommand{Command: cb, Signature: sig})
	return e
}

// An unknown type doesn't stop the cluster (decision 366): at a level this
// build supports or one the cluster hasn't enabled, every node refuses it.
func TestUnknownTypeRefusedNotHalted(t *testing.T) {
	h, nas, c1, _ := threeNodes(t)
	h.mustRefuse(nas.sign(t, "future.thing", map[string]int{"x": 1}), "unknown command type")
	h.mustRefuse(nas.signLevel(t, "future.thing", nil, 2), "unknown command type")
	h.mustRefuse(c1.signLevel(t, "future.thing", nil, 9), "unknown command type")
	if h.f.Halted() != nil {
		t.Fatal("an unknown type halted the FSM")
	}
	// The cluster goes on.
	h.mustApply(nas.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Version: "2"}))
	// A known type claiming another level is refused too (no node applies it).
	h.mustRefuse(nas.signLevel(t, cluster.CmdMemberUpdate, MemberUpdateBody{Version: "3"}, 2), "isn't enabled")
	// The leader doesn't even append these.
	var sc cluster.SignedCommand
	_ = json.Unmarshal(nas.sign(t, "future.thing", nil), &sc)
	if err := h.f.Admit(&sc); err == nil || !strings.Contains(err.Error(), "unknown command type") {
		t.Fatalf("admit unknown: %v", err)
	}
	_ = json.Unmarshal(nas.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Version: "4"}), &sc)
	if err := h.f.Admit(&sc); err != nil {
		t.Fatalf("admit known: %v", err)
	}
}

// Only a type at an enabled level above this build's stops the FSM: other
// nodes may apply it.
func TestUnknownTypeAtEnabledLevelHalts(t *testing.T) {
	h, nas, c1, w := threeNodes(t)
	f2 := []string{FeatureName(1), FeatureName(2)}
	h.mustApply(nas.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Features: f2}))
	h.mustApply(c1.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Features: f2}))
	h.mustApply(w.sign(t, cluster.CmdWitnessHello, WitnessHelloBody{Addresses: w.node.Addresses, Version: "1.0", Features: f2}))
	h.mustApply(nas.sign(t, cluster.CmdFeatureLevel, FeatureLevelBody{Level: 2}))
	// An unsigned unknown type from a non-member doesn't halt.
	x := newTNode(t, "x", cluster.RoleCompute, "10.0.0.1")
	h.mustRefuse(x.signLevel(t, "future.thing", nil, 2), "isn't a member")
	if h.f.Halted() != nil {
		t.Fatal("a non-member halted the FSM")
	}
	r := h.apply(nas.signLevel(t, "future.thing", map[string]int{"x": 1}, 2))
	if !errors.Is(r.Err, ErrHalted) || h.f.Halted() == nil {
		t.Fatalf("got %v", r.Err)
	}
	if r := h.apply(nas.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Version: "2"})); !errors.Is(r.Err, ErrHalted) {
		t.Fatalf("after halt: %v", r.Err)
	}
}

type panicApplier struct{}

func (panicApplier) Types() []cluster.CommandType               { return []cluster.CommandType{"test.panic"} }
func (panicApplier) Signers(cluster.CommandType) []cluster.Role { return hardy }
func (panicApplier) Apply(s *cluster.Snapshot, c cluster.Command) error {
	s.Name = "changed"
	var m map[string]int
	m["boom"] = 1 // nil map: panics
	return nil
}

// A panicking applier refuses its entry instead of crashing every node.
func TestApplierPanicRefuses(t *testing.T) {
	h, nas, _, _ := threeNodes(t)
	h.f.Register(panicApplier{})
	h.mustRefuse(nas.sign(t, "test.panic", nil), "internal error")
	if h.f.Halted() != nil || h.f.Snapshot().Name != "home" {
		t.Fatal("the panic changed the state")
	}
	h.mustApply(nas.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Version: "2"}))
}

// The witness may only say hello, even through the leader.
func TestAdmitWitnessOnlyHello(t *testing.T) {
	h, _, _, w := threeNodes(t)
	var sc cluster.SignedCommand
	_ = json.Unmarshal(w.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Version: "x"}), &sc)
	if err := h.f.Admit(&sc); err == nil || !strings.Contains(err.Error(), "only say hello") {
		t.Fatalf("admit: %v", err)
	}
}

// A fenced (or dead) member reaches the leader's /propose only to rejoin:
// the leader admits node.rejoin from it and nothing else (decision 389).
func TestAdmitFencedOnlyRejoin(t *testing.T) {
	h, nas, c1, _ := threeNodes(t)
	h.mustApply(c1.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{BootID: "boot-1"}))
	h.mustApply(nas.sign(t, cluster.CmdNodeDead, NodeDeadBody{Node: "c1", Epoch: 1, Reason: "dead"}))
	admit := func(raw []byte) error {
		var sc cluster.SignedCommand
		if err := json.Unmarshal(raw, &sc); err != nil {
			t.Fatal(err)
		}
		return h.f.Admit(&sc)
	}
	for _, st := range []cluster.NodeState{cluster.NodeDead, cluster.NodeFenced} {
		h.f.mu.Lock()
		h.f.s.Nodes["c1"].State = st
		h.f.mu.Unlock()
		if err := admit(c1.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{BootID: "boot-2"})); err == nil || !strings.Contains(err.Error(), "may only rejoin") {
			t.Fatalf("%s: member.update admitted: %v", st, err)
		}
		if err := admit(c1.sign(t, cluster.CmdNodeRejoin, NodeRejoinBody{Node: "c1", Epoch: 1, BootID: "boot-2"})); err != nil {
			t.Fatalf("%s: node.rejoin refused: %v", st, err)
		}
	}
	// An active member proposes as before.
	if err := admit(nas.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Version: "1.0.1"})); err != nil {
		t.Fatal(err)
	}
}

// Boot ids have one format: the log refuses one the storage node's root
// couldn't verify in a signed rejoin statement.
func TestBootIDFormat(t *testing.T) {
	h, _, c1, _ := threeNodes(t)
	h.mustRefuse(c1.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{BootID: "boot 1+"}), "boot id isn't valid")
	h.mustApply(c1.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{BootID: "6f1d8a52-6c39-4d0e-9a4e-2f8a3c1b7e90"}))
}

func TestMemberRules(t *testing.T) {
	h, nas, c1, _ := threeNodes(t)
	dup := newTNode(t, "c1", cluster.RoleCompute, "192.168.1.30")
	h.mustRefuse(nas.sign(t, cluster.CmdMemberAdd, MemberAddBody{Node: dup.node}), "already called c1")
	st := newTNode(t, "nas2", cluster.RoleStorage, "192.168.1.31")
	h.mustRefuse(nas.sign(t, cluster.CmdMemberAdd, MemberAddBody{Node: st.node}), "already has a storage node")
	bad := newTNode(t, "c9", cluster.RoleCompute, "192.168.1.32")
	bad.node.Pin = strings.Repeat("0", 64)
	h.mustRefuse(nas.sign(t, cluster.CmdMemberAdd, MemberAddBody{Node: bad.node}), "doesn't match its pin")
	// Joining members can't add others.
	c3 := newTNode(t, "c3", cluster.RoleCompute, "192.168.1.33")
	h.mustApply(nas.sign(t, cluster.CmdMemberAdd, MemberAddBody{Node: c3.node}))
	c4 := newTNode(t, "c4", cluster.RoleCompute, "192.168.1.34")
	h.mustRefuse(c3.sign(t, cluster.CmdMemberAdd, MemberAddBody{Node: c4.node}), "only an active server")
	// Storage leaves last.
	h.mustRefuse(c1.sign(t, cluster.CmdMemberRemove, MemberRemoveBody{Node: "nas"}), "leaves last")
	// Workloads block removal.
	s := h.f.Snapshot()
	_ = s
	h.mustApply(c1.sign(t, cluster.CmdMemberRemove, MemberRemoveBody{Node: "c3"}))
	if _, ok := h.f.Node("c3"); ok {
		t.Fatal("c3 still a member")
	}
	// A removed node's entries are refused.
	h.mustRefuse(c3.sign(t, cluster.CmdMemberReady, MemberReadyBody{}), "isn't a member")
}

func TestTimingsInvariant(t *testing.T) {
	h, nas, _, _ := threeNodes(t)
	bad := cluster.DefaultTimings
	bad.Dead = 20 * time.Second
	h.mustRefuse(nas.sign(t, cluster.CmdTimings, bad), "quorum lease + watchdog")
	good := cluster.DefaultTimings
	good.Dead = 60 * time.Second
	h.mustApply(nas.sign(t, cluster.CmdTimings, good))
	if h.f.Snapshot().Timings.Dead != 60*time.Second {
		t.Fatal("timings not applied")
	}
}

func TestFeatureLevelNeedsEveryMember(t *testing.T) {
	h, nas, c1, w := threeNodes(t)
	h.mustApply(nas.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Features: []string{"cluster/1", "cluster/2"}}))
	h.mustApply(c1.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Features: []string{"cluster/1", "cluster/2"}}))
	h.mustRefuse(nas.sign(t, cluster.CmdFeatureLevel, FeatureLevelBody{Level: 2}), "witness doesn't support")
	h.mustApply(w.sign(t, cluster.CmdWitnessHello, WitnessHelloBody{Addresses: w.node.Addresses, Features: []string{"cluster/1", "cluster/2"}}))
	h.mustApply(nas.sign(t, cluster.CmdFeatureLevel, FeatureLevelBody{Level: 2}))
}

func TestSnapshotRoundTripAndDeterminism(t *testing.T) {
	h, _, _, _ := threeNodes(t)
	s := h.f.Snapshot()
	s.Placements[cluster.WorkloadRef{Kind: cluster.KindVM, ID: "b"}] = &cluster.Placement{Workload: cluster.WorkloadRef{Kind: cluster.KindVM, ID: "b"}, Owner: "c1"}
	s.Placements[cluster.WorkloadRef{Kind: cluster.KindApp, ID: "a"}] = &cluster.Placement{Workload: cluster.WorkloadRef{Kind: cluster.KindApp, ID: "a"}}
	a, _ := Encode(s)
	b, _ := Encode(Clone(s))
	if string(a) != string(b) {
		t.Fatal("encoding isn't deterministic")
	}
	f2 := New()
	if err := f2.Restore(a); err != nil {
		t.Fatal(err)
	}
	if p, ok := f2.Placement(cluster.WorkloadRef{Kind: cluster.KindVM, ID: "b"}); !ok || p.Owner != "c1" {
		t.Fatal("placement lost")
	}
	if strings.Contains(string(a), "privateKey") || strings.Contains(string(a), "secret") {
		t.Fatal("secret-looking field in the state")
	}
}

// Every node applying the same log ends in the same state.
func TestReplicasAgree(t *testing.T) {
	h, nas, c1, _ := threeNodes(t)
	h.apply(nas.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Version: "2"}))
	h.apply(c1.sign(t, cluster.CmdMaintenance, MaintenanceBody{Node: "c1", Enter: true}))
	h.apply(c1.signSeq(t, cluster.CmdMemberUpdate, MemberUpdateBody{Version: "x"}, 1)) // refused
	other := New()
	for i, e := range h.log {
		other.Apply(uint64(i+1), e)
	}
	a, _ := h.f.Encode()
	b, _ := other.Encode()
	if string(a) != string(b) {
		t.Fatalf("replicas differ:\n%s\n%s", a, b)
	}
}
