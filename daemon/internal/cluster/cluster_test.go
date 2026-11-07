package cluster_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

// An in-process cluster: three HardyOS cores and a witness on a fake
// network with three networks (LAN, storage, NetBird), real TLS, real Raft
// (bolt stores in temp dirs), short timings.

type tnode struct {
	id    cluster.NodeID
	role  cluster.Role
	core  *cluster.Core
	addrs cluster.Addresses
	store *clustertest.MemStore
	dir   string
	id_   *cluster.Identity
}

type harness struct {
	t     *testing.T
	net   *clustertest.Net
	nodes map[cluster.NodeID]*tnode
	log   *slog.Logger
}

var fastTimings = cluster.Timings{Heartbeat: 50 * time.Millisecond, Suspect: 500 * time.Millisecond, QuorumLease: 800 * time.Millisecond,
	SelfStop: 100 * time.Millisecond, Watchdog: 200 * time.Millisecond, Dead: 2 * time.Second, StorageIsolated: time.Second,
	LANIsolated: 2 * time.Second, FenceAck: time.Second}

func newHarness(t *testing.T) *harness {
	lvl := slog.LevelError
	if os.Getenv("CLUSTER_DEBUG") != "" {
		lvl = slog.LevelDebug
	}
	return &harness{t: t, net: clustertest.NewNet(), nodes: map[cluster.NodeID]*tnode{},
		log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))}
}

func addr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	return netip.MustParseAddr(s)
}

func (h *harness) add(id string, role cluster.Role, lan, stor, nb string) *tnode {
	h.t.Helper()
	ident, err := cluster.NewIdentity(id)
	if err != nil {
		h.t.Fatal(err)
	}
	n := &tnode{id: cluster.NodeID(id), role: role, store: &clustertest.MemStore{}, dir: h.t.TempDir(), id_: ident,
		addrs: cluster.Addresses{LAN: addr(lan), Storage: addr(stor), NetBird: addr(nb)}}
	h.nodes[n.id] = n
	h.build(n)
	return n
}

func (h *harness) build(n *tnode) {
	h.t.Helper()
	timings := fastTimings
	core, err := cluster.New(context.Background(), cluster.Config{
		Identity: n.id_, Store: n.store, Machine: state.New(),
		Net:  h.net.Host(n.addrs.LAN, n.addrs.Storage, n.addrs.NetBird),
		Port: 44500, Dir: n.dir, Version: "1.0.0", Features: state.Features(), BootID: "boot-" + string(n.id),
		Addresses: func() cluster.Addresses { return n.addrs },
		Raft: cluster.RaftTimings{Heartbeat: 300 * time.Millisecond, Election: 300 * time.Millisecond, LeaderLease: 150 * time.Millisecond,
			Commit: 5 * time.Millisecond, SnapshotThreshold: 64, TrailingLogs: 128, SnapshotInterval: time.Second},
		Paths:   cluster.PathTimings{Interval: 30 * time.Millisecond, Timeout: 60 * time.Millisecond, DownAfter: 3, UpAfter: 10},
		Timings: &timings,
		Log:     h.log.With("node", string(n.id)),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	n.core = core
	h.t.Cleanup(core.Stop)
}

func (h *harness) eventually(what string, d time.Duration, f func() error) {
	h.t.Helper()
	deadline := time.Now().Add(d)
	var err error
	for time.Now().Before(deadline) {
		if err = f(); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("%s: %v", what, err)
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

var admin = cluster.Actor{Kind: "local", Name: "admin"}

// joinVia makes a code on member m and joins n with it.
func (h *harness) joinVia(m, n *tnode) {
	h.t.Helper()
	off, err := m.core.OpenJoinCode(ctx(h.t), n.role, "admin")
	if err != nil {
		h.t.Fatalf("join code on %s: %v", m.id, err)
	}
	target := m.addrs.LAN
	if n.role == cluster.RoleWitness {
		target = m.addrs.NetBird
	}
	if _, err := n.core.Join(ctx(h.t), cluster.JoinParams{Address: target.String(), Code: off.Code, Node: n.id, Name: string(n.id), Role: n.role}); err != nil {
		h.t.Fatalf("%s joins via %s: %v", n.id, m.id, err)
	}
	var hello any
	if n.role == cluster.RoleWitness {
		hello = state.WitnessHelloBody{Addresses: n.addrs, Version: "1.0.0", Features: state.Features()}
	}
	if err := n.core.FinishJoin(ctx(h.t), hello); err != nil {
		h.t.Fatalf("%s finishing its join: %v", n.id, err)
	}
}

// liveSuffrage is the leader's Raft configuration as id -> suffrage.
func (h *harness) liveSuffrage(n *tnode) map[cluster.NodeID]cluster.Suffrage {
	out := map[cluster.NodeID]cluster.Suffrage{}
	for _, ns := range n.core.Status(context.Background()).Nodes {
		out[ns.ID] = ns.Live
	}
	return out
}

func (h *harness) leader(among ...*tnode) *tnode {
	for _, n := range among {
		if n.core.Running() && n.core.IsLeader() {
			return n
		}
	}
	return nil
}

// build4 makes nas (storage), c1, c2 (compute) and the witness, all joined.
func build4(t *testing.T) (*harness, *tnode, *tnode, *tnode, *tnode) {
	h := newHarness(t)
	nas := h.add("nas", cluster.RoleStorage, "192.168.1.105", "10.77.0.10", "100.64.0.105")
	c1 := h.add("c1", cluster.RoleCompute, "192.168.1.21", "10.77.0.21", "100.64.0.21")
	c2 := h.add("c2", cluster.RoleCompute, "192.168.1.22", "10.77.0.22", "100.64.0.22")
	w := h.add("witness", cluster.RoleWitness, "", "", "100.64.0.9")
	if _, err := nas.core.Create(ctx(t), cluster.CreateParams{Name: "home", Node: "nas", NodeName: "nas", Role: cluster.RoleStorage,
		StorageSubnet: netip.MustParsePrefix("10.77.0.0/24")}, admin); err != nil {
		t.Fatalf("create: %v", err)
	}
	h.joinVia(nas, c1)
	h.joinVia(c1, c2) // any active member can admit
	h.joinVia(nas, w)
	all := []*tnode{nas, c1, c2, w}
	h.eventually("three voters and a standby witness", 10*time.Second, func() error {
		l := h.leader(all...)
		if l == nil {
			return errors.New("no leader")
		}
		s := h.liveSuffrage(l)
		want := map[cluster.NodeID]cluster.Suffrage{"nas": cluster.Voter, "c1": cluster.Voter, "c2": cluster.Voter, "witness": cluster.NonVoter}
		for id, v := range want {
			if s[id] != v {
				return fmt.Errorf("live suffrage %v", s)
			}
		}
		return nil
	})
	return h, nas, c1, c2, w
}

func TestClusterJoinReplicateAndLeaderLoss(t *testing.T) {
	h, nas, c1, c2, w := build4(t)
	all := []*tnode{nas, c1, c2, w}

	// Every member (the witness too) applied the same state.
	h.eventually("same state everywhere", 5*time.Second, func() error {
		idx := nas.core.Machine().Index()
		for _, n := range all {
			if n.core.Machine().Index() != idx {
				return fmt.Errorf("%s at %d, nas at %d", n.id, n.core.Machine().Index(), idx)
			}
		}
		return nil
	})
	snap := w.core.Machine().Snapshot()
	if len(snap.Nodes) != 4 || snap.Nodes["witness"].State != cluster.NodeActive || snap.Nodes["c2"].State != cluster.NodeActive {
		t.Fatalf("witness's state: %+v", snap.Nodes)
	}

	// A follower proposes; the leader commits; everyone applies.
	var follower *tnode
	for _, n := range []*tnode{nas, c1, c2} {
		if !n.core.IsLeader() {
			follower = n
		}
	}
	idx, err := follower.core.Propose(ctx(t), cluster.CmdMemberUpdate, state.MemberUpdateBody{Version: "1.0.1"}, admin)
	if err != nil {
		t.Fatalf("propose from follower: %v", err)
	}
	for _, n := range all {
		if err := n.core.WaitApplied(ctx(t), idx); err != nil {
			t.Fatal(err)
		}
		if m, _ := n.core.Machine().Node(follower.id); m.Version != "1.0.1" {
			t.Fatalf("%s didn't apply the update", n.id)
		}
	}

	// Quorum leases are valid everywhere.
	h.eventually("quorate", 5*time.Second, func() error {
		for _, n := range all {
			if ok, _ := n.core.Quorate(); !ok {
				return fmt.Errorf("%s not quorate", n.id)
			}
		}
		return nil
	})

	// Leader loss: a new leader among the other two, changes still commit,
	// and the voter set isn't shrunk.
	old := h.leader(nas, c1, c2)
	old.core.Stop()
	rest := []*tnode{}
	for _, n := range []*tnode{nas, c1, c2} {
		if n != old {
			rest = append(rest, n)
		}
	}
	h.eventually("new leader", 10*time.Second, func() error {
		if h.leader(rest...) == nil {
			return errors.New("none yet")
		}
		return nil
	})
	if _, err := rest[0].core.Propose(ctx(t), cluster.CmdMemberUpdate, state.MemberUpdateBody{Version: "1.0.2"}, admin); err != nil {
		t.Fatalf("propose after leader loss: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if s := h.liveSuffrage(h.leader(rest...)); s[old.id] != cluster.Voter || s["witness"] != cluster.NonVoter {
		t.Fatalf("voters changed while a voter was down: %v", s)
	}
	// Health shows the stopped node as suspect.
	h.eventually("old leader suspect", 5*time.Second, func() error {
		hs, err := rest[0].core.Health(ctx(t))
		if err != nil {
			return err
		}
		for _, x := range hs {
			if x.Node == old.id && x.Suspect {
				return nil
			}
		}
		return fmt.Errorf("health %+v", hs)
	})

	// The old leader comes back with its log and catches up.
	h.build(old)
	if err := old.core.Start(ctx(t)); err != nil {
		t.Fatal(err)
	}
	h.eventually("old leader caught up", 10*time.Second, func() error {
		if m, ok := old.core.Machine().Node(rest[0].id); !ok || m.Version != "1.0.2" {
			return errors.New("not yet")
		}
		return nil
	})
}

func TestPartitionedNodeLosesQuorum(t *testing.T) {
	h, nas, c1, c2, w := build4(t)
	// Cut c2 off from everyone on every network.
	for _, o := range []*tnode{nas, c1, w} {
		for _, a := range []netip.Addr{c2.addrs.LAN, c2.addrs.Storage, c2.addrs.NetBird} {
			for _, b := range []netip.Addr{o.addrs.LAN, o.addrs.Storage, o.addrs.NetBird} {
				if a.IsValid() && b.IsValid() {
					h.net.Cut(a, b)
				}
			}
		}
	}
	h.eventually("c2 loses its quorum lease", 5*time.Second, func() error {
		if ok, _ := c2.core.Quorate(); ok {
			return errors.New("still quorate")
		}
		return nil
	})
	// The majority keeps working.
	var l *tnode
	h.eventually("majority leader", 10*time.Second, func() error {
		if l = h.leader(nas, c1); l == nil {
			return errors.New("none")
		}
		return nil
	})
	if _, err := l.core.Propose(ctx(t), cluster.CmdMemberUpdate, state.MemberUpdateBody{Version: "1.0.5"}, admin); err != nil {
		t.Fatalf("majority propose: %v", err)
	}
	// c2 can't commit anything.
	cctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	_, err := c2.core.Propose(cctx, cluster.CmdMemberUpdate, state.MemberUpdateBody{Version: "9"}, admin)
	cancel()
	if err == nil {
		t.Fatal("the minority committed a change")
	}
	// Healing brings it back.
	for _, o := range []*tnode{nas, c1, w} {
		for _, a := range []netip.Addr{c2.addrs.LAN, c2.addrs.Storage, c2.addrs.NetBird} {
			for _, b := range []netip.Addr{o.addrs.LAN, o.addrs.Storage, o.addrs.NetBird} {
				if a.IsValid() && b.IsValid() {
					h.net.Heal(a, b)
				}
			}
		}
	}
	h.eventually("c2 back", 10*time.Second, func() error {
		if ok, _ := c2.core.Quorate(); !ok {
			return errors.New("not quorate")
		}
		if m, _ := c2.core.Machine().Node(l.id); m.Version != "1.0.5" {
			return errors.New("not caught up")
		}
		return nil
	})
}

func TestPathFailoverLANStorageNetBird(t *testing.T) {
	h, nas, c1, _, _ := build4(t)
	path := func() cluster.Path { return c1.core.Paths().Current("nas") }
	h.eventually("LAN in use", 5*time.Second, func() error {
		if p := path(); p != cluster.PathLAN {
			return fmt.Errorf("path %s", p)
		}
		return nil
	})
	// The LAN between c1 and nas fails: the storage network carries control.
	h.net.Cut(c1.addrs.LAN, nas.addrs.LAN)
	h.eventually("storage network in use", 5*time.Second, func() error {
		if p := path(); p != cluster.PathStorage {
			return fmt.Errorf("path %s", p)
		}
		return nil
	})
	propose := func(v string) {
		t.Helper()
		var l *tnode
		h.eventually("leader", 10*time.Second, func() error {
			if l = h.leader(h.nodes["nas"], h.nodes["c1"], h.nodes["c2"]); l == nil {
				return errors.New("none")
			}
			return nil
		})
		idx, err := c1.core.Propose(ctx(t), cluster.CmdMemberUpdate, state.MemberUpdateBody{Version: v}, admin)
		if err != nil {
			t.Fatalf("propose over the failover path: %v", err)
		}
		if err := nas.core.WaitApplied(ctx(t), idx); err != nil {
			t.Fatal(err)
		}
	}
	propose("2.0.0")
	// The storage network fails too: NetBird.
	h.net.Cut(c1.addrs.Storage, nas.addrs.Storage)
	h.eventually("NetBird in use", 5*time.Second, func() error {
		if p := path(); p != cluster.PathNetBird {
			return fmt.Errorf("path %s", p)
		}
		return nil
	})
	propose("2.0.1")
	// The LAN is back: after enough good probes, LAN again.
	h.net.Heal(c1.addrs.LAN, nas.addrs.LAN)
	h.eventually("back to LAN", 5*time.Second, func() error {
		if p := path(); p != cluster.PathLAN {
			return fmt.Errorf("path %s", p)
		}
		return nil
	})
	// The witness is only ever reached over NetBird.
	if p := nas.core.Paths().Current("witness"); p != cluster.PathNetBird {
		t.Fatalf("witness path %s", p)
	}
}

func TestWitnessVotesWhenEvenAndItsLoss(t *testing.T) {
	h, nas, c1, c2, w := build4(t)
	// c2 goes into maintenance: two HardyOS voters, so the witness votes.
	if _, err := c1.core.Propose(ctx(t), cluster.CmdMaintenance, state.MaintenanceBody{Node: "c2", Enter: true}, admin); err != nil {
		t.Fatal(err)
	}
	h.eventually("witness promoted, c2 demoted", 10*time.Second, func() error {
		l := h.leader(nas, c1, c2)
		if l == nil {
			return errors.New("no leader")
		}
		s := h.liveSuffrage(l)
		if s["witness"] != cluster.Voter || s["c2"] != cluster.NonVoter {
			return fmt.Errorf("suffrage %v", s)
		}
		return nil
	})
	// The witness is lost: two of three voters keep quorum.
	for _, o := range []*tnode{nas, c1, c2} {
		h.net.Cut(w.addrs.NetBird, o.addrs.NetBird)
	}
	time.Sleep(300 * time.Millisecond)
	var l *tnode
	h.eventually("leader without the witness", 10*time.Second, func() error {
		if l = h.leader(nas, c1); l == nil {
			return errors.New("none")
		}
		return nil
	})
	if _, err := l.core.Propose(ctx(t), cluster.CmdMemberUpdate, state.MemberUpdateBody{Version: "3"}, admin); err != nil {
		t.Fatalf("propose without the witness: %v", err)
	}
	// The witness never ends up leading.
	if w.core.IsLeader() {
		t.Fatal("the witness leads")
	}
	// c2 leaves maintenance while the witness (a voter) is unreachable
	// (longer than the suspect time): the voter set must not change.
	time.Sleep(2 * fastTimings.Suspect)
	if _, err := c1.core.Propose(ctx(t), cluster.CmdMaintenance, state.MaintenanceBody{Node: "c2", Enter: false}, admin); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if s := h.liveSuffrage(h.leader(nas, c1)); s["witness"] != cluster.Voter || s["c2"] != cluster.NonVoter {
		t.Fatalf("voters changed with a voter unreachable: %v", s)
	}
	// The witness is back: now c2 is promoted and the witness steps down.
	for _, o := range []*tnode{nas, c1, c2} {
		h.net.Heal(w.addrs.NetBird, o.addrs.NetBird)
	}
	h.eventually("c2 voter, witness standby", 10*time.Second, func() error {
		l := h.leader(nas, c1, c2)
		if l == nil {
			return errors.New("no leader")
		}
		s := h.liveSuffrage(l)
		if s["witness"] != cluster.NonVoter || s["c2"] != cluster.Voter {
			return fmt.Errorf("suffrage %v", s)
		}
		return nil
	})
}

func TestForgedAndReplayedProposalsRefused(t *testing.T) {
	h, nas, c1, _, w := build4(t)
	_ = h
	l := h.leader(nas, c1, h.nodes["c2"])
	snap := c1.core.Machine().Snapshot()
	// c1 signs a command claiming nas proposed it: the leader refuses to
	// take it from c1, and the FSM would refuse the signature anyway.
	sc, _ := cluster.SignCommand(c1.core.Identity(), cluster.Command{Type: cluster.CmdMemberRemove, Cluster: snap.Cluster,
		Proposer: "nas", Seq: 1000, Actor: admin, Time: time.Now(), Body: []byte(`{"node":"c2"}`)})
	err := c1.core.Peers().Call(ctx(t), l.id, http.MethodPost, "/propose", sc, nil)
	var pe *cluster.PeerError
	if !errors.As(err, &pe) || pe.Status != http.StatusForbidden {
		t.Fatalf("forged proposal: %v", err)
	}
	// c1 replays its own old command (sequence 1 is long used).
	sc2, _ := cluster.SignCommand(c1.core.Identity(), cluster.Command{Type: cluster.CmdMemberUpdate, Cluster: snap.Cluster,
		Proposer: "c1", Seq: 1, Actor: admin, Time: time.Now(), Body: []byte(`{"version":"evil"}`)})
	var ans struct {
		Index   uint64 `json:"index"`
		Refused string `json:"refused"`
	}
	if l.id == "c1" {
		l = nas
	}
	// (Retried while leadership moves: the replay check doesn't depend on it.)
	h.eventually("replay answered", 10*time.Second, func() error {
		l := h.leader(nas, c1, h.nodes["c2"])
		if l == nil {
			return errors.New("no leader")
		}
		return c1.core.Peers().Call(ctx(t), l.id, http.MethodPost, "/propose", sc2, &ans)
	})
	if !strings.Contains(ans.Refused, "replayed") {
		t.Fatalf("replay answer %+v", ans)
	}
	// The witness can only say hello: anything else it signs is refused.
	if _, err := w.core.Propose(ctx(t), cluster.CmdMemberRemove, state.MemberRemoveBody{Node: "c1"}, admin); err == nil ||
		!strings.Contains(err.Error(), "may only say hello") {
		t.Fatalf("witness command: %v", err)
	}
	// The witness may not call member endpoints.
	err = w.core.Peers().Call(ctx(t), "nas", http.MethodGet, "/health", nil, nil)
	if !errors.As(err, &pe) || pe.Status != http.StatusForbidden {
		t.Fatalf("witness on /health: %v", err)
	}
	if m, _ := nas.core.Machine().Node("c1"); m.Version == "evil" {
		t.Fatal("replayed command applied")
	}
}

func TestJoinCodesOneTimeAndRateLimited(t *testing.T) {
	h := newHarness(t)
	nas := h.add("nas", cluster.RoleStorage, "192.168.1.105", "10.77.0.10", "100.64.0.105")
	if _, err := nas.core.Create(ctx(t), cluster.CreateParams{Name: "home", Node: "nas", NodeName: "nas", Role: cluster.RoleStorage}, admin); err != nil {
		t.Fatal(err)
	}
	c1 := h.add("c1", cluster.RoleCompute, "192.168.1.21", "", "")
	off, err := nas.core.OpenJoinCode(ctx(t), cluster.RoleCompute, "admin")
	if err != nil {
		t.Fatal(err)
	}
	join := func(n *tnode, code string, role cluster.Role) error {
		_, err := n.core.Join(ctx(t), cluster.JoinParams{Address: "192.168.1.105", Code: code, Node: n.id, Name: string(n.id), Role: role})
		return err
	}
	// A wrong code, the right code for the wrong role.
	wrong := cluster.FormatCode([]byte("0123456789abcdef"))
	if err := join(c1, wrong, cluster.RoleCompute); err == nil || !strings.Contains(err.Error(), "doesn't match") {
		t.Fatalf("wrong code: %v", err)
	}
	if err := join(c1, off.Code, cluster.RoleStorage); err == nil {
		t.Fatal("joined with the wrong role")
	}
	// The role check happened after the code matched, so the code is
	// still... no: a refusal after a match doesn't consume it. Join now.
	if err := join(c1, off.Code, cluster.RoleCompute); err != nil {
		t.Fatalf("join: %v", err)
	}
	// One time: the same code doesn't admit another server.
	c2 := h.add("c2", cluster.RoleCompute, "192.168.1.22", "", "")
	if err := join(c2, off.Code, cluster.RoleCompute); err == nil {
		t.Fatal("a code admitted two servers")
	}
	// Rate limit: three wrong codes from one address, then refused even
	// with the right one.
	off2, _ := nas.core.OpenJoinCode(ctx(t), cluster.RoleCompute, "admin")
	for i := 0; i < 3; i++ {
		_ = join(c2, wrong, cluster.RoleCompute)
	}
	if err := join(c2, off2.Code, cluster.RoleCompute); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("after 3 wrong codes: %v", err)
	}
	// Five wrong tries in all close the code (from other addresses).
	off3, _ := nas.core.OpenJoinCode(ctx(t), cluster.RoleCompute, "admin")
	var mu sync.Mutex
	for i := 0; i < 5; i++ {
		x := h.add(fmt.Sprintf("x%d", i), cluster.RoleCompute, fmt.Sprintf("192.168.1.%d", 60+i), "", "")
		mu.Lock()
		_ = join(x, wrong, cluster.RoleCompute)
		mu.Unlock()
	}
	c3 := h.add("c3", cluster.RoleCompute, "192.168.1.23", "", "")
	if err := join(c3, off3.Code, cluster.RoleCompute); err == nil {
		t.Fatal("the code survived five wrong tries")
	}
}

func TestLeaveAndRemove(t *testing.T) {
	h, nas, c1, c2, w := build4(t)
	// c2 leaves: it is out of the state and the configuration, and wiped.
	if err := c2.core.Leave(ctx(t), admin); err != nil {
		t.Fatalf("leave: %v", err)
	}
	if c2.core.Info() != nil {
		t.Fatal("c2 still has cluster info")
	}
	h.eventually("c2 gone", 10*time.Second, func() error {
		l := h.leader(nas, c1)
		if l == nil {
			return errors.New("no leader")
		}
		if _, ok := l.core.Machine().Node("c2"); ok {
			return errors.New("still in the state")
		}
		if _, ok := h.liveSuffrage(l)["c2"]; ok {
			return errors.New("still in the configuration")
		}
		// Two servers left: the witness votes now.
		if h.liveSuffrage(l)["witness"] != cluster.Voter {
			return errors.New("witness not promoted")
		}
		return nil
	})
	// Its key is refused from now on.
	if _, ok := nas.core.ByPin(c2.id_.Pin); ok {
		t.Fatal("a removed node's pin is still accepted")
	}
	// Remove needs the typed name.
	if err := nas.core.Remove(ctx(t), "witness", "nope", admin); err == nil {
		t.Fatal("removed without confirmation")
	}
	if err := nas.core.Remove(ctx(t), "witness", "witness", admin); err != nil {
		t.Fatalf("remove witness: %v", err)
	}
	_ = w
}
