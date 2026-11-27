package netcheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/clustertest"
)

func TestMain(m *testing.M) {
	// The fake network's pipes (and -race) are slower than a LAN.
	MaxRTT = 100 * time.Millisecond
	os.Exit(m.Run())
}

// A static cluster for the probes: members, their keys and transports on
// the fake network.
type book struct {
	mu    sync.Mutex
	nodes map[cluster.NodeID]cluster.Node
}

func (b *book) ByPin(pin string) (cluster.Node, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, n := range b.nodes {
		if n.Pin == pin {
			return n, true
		}
	}
	return cluster.Node{}, false
}

func (b *book) Member(id cluster.NodeID) (cluster.Node, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, ok := b.nodes[id]
	return n, ok
}

type tnode struct {
	node  cluster.Node
	id    *cluster.Identity
	tr    *cluster.Transport
	mtu   map[netip.Addr]int
	mtuMu sync.Mutex
}

func (t *tnode) ifaces() ([]Iface, error) {
	t.mtuMu.Lock()
	defer t.mtuMu.Unlock()
	var out []Iface
	for name, a := range map[string]netip.Addr{"eth0": t.node.Addresses.LAN, "eth1": t.node.Addresses.Storage, "wt0": t.node.Addresses.NetBird} {
		if !a.IsValid() {
			continue
		}
		bits := 24
		if name == "wt0" {
			bits = 16
		}
		mtu := 1500
		if m := t.mtu[a]; m != 0 {
			mtu = m
		}
		out = append(out, Iface{Name: name, MTU: mtu, Prefixes: []netip.Prefix{netip.PrefixFrom(a, bits)}})
	}
	return out, nil
}

type tcluster struct {
	net   *clustertest.Net
	book  *book
	nodes map[cluster.NodeID]*tnode
	snap  *cluster.Snapshot
}

func newTCluster(t *testing.T) *tcluster {
	t.Helper()
	c := &tcluster{net: clustertest.NewNet(), book: &book{nodes: map[cluster.NodeID]cluster.Node{}}, nodes: map[cluster.NodeID]*tnode{},
		snap: &cluster.Snapshot{Nodes: map[cluster.NodeID]*cluster.Node{}}}
	add := func(id string, role cluster.Role, lan, stor, nb string) {
		ident, err := cluster.NewIdentity(id)
		if err != nil {
			t.Fatal(err)
		}
		n := cluster.Node{ID: cluster.NodeID(id), Name: id, Role: role, Pin: ident.Pin, PublicKey: ident.PublicKey, State: cluster.NodeActive,
			Addresses: cluster.Addresses{LAN: netip.MustParseAddr(lan), Storage: netip.MustParseAddr(stor), NetBird: netip.MustParseAddr(nb)}}
		c.book.nodes[n.ID] = n
		nn := n
		c.snap.Nodes[n.ID] = &nn
		c.nodes[n.ID] = &tnode{node: n, id: ident, mtu: map[netip.Addr]int{}}
	}
	add("nas", cluster.RoleStorage, "192.168.1.10", "10.77.0.10", "100.64.0.10")
	add("c1", cluster.RoleCompute, "192.168.1.21", "10.77.0.21", "100.64.0.21")
	add("c2", cluster.RoleCompute, "192.168.1.22", "10.77.0.22", "100.64.0.22")
	for _, tn := range c.nodes {
		tn := tn
		mux := http.NewServeMux()
		rs := &Responder{Identity: func() *cluster.Identity { return tn.id }, Self: func() cluster.NodeID { return tn.node.ID },
			Interfaces: tn.ifaces, Caller: func(r *http.Request) (cluster.Node, bool) {
				if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
					return cluster.Node{}, false
				}
				return c.book.ByPin(cluster.PinOfCert(r.TLS.PeerCertificates[0]))
			}}
		mux.Handle("POST "+cluster.PeerPathPrefix+ProbePath, rs)
		a := tn.node.Addresses
		tn.tr = &cluster.Transport{ID: tn.id, Self: tn.node.ID, Net: c.net.Host(a.LAN, a.Storage, a.NetBird), Book: c.book, Port: 44500, Peer: mux}
		tn.tr.SetListen([]netip.Addr{a.LAN, a.Storage, a.NetBird})
		t.Cleanup(tn.tr.Close)
	}
	return c
}

func (c *tcluster) prober(tn *tnode) *Prober {
	return &Prober{Port: 44500, Interfaces: tn.ifaces, Timeout: 2 * time.Second, BulkTimeout: time.Second,
		Dial: func(ctx context.Context, addr string, peer cluster.Node) (net.Conn, error) {
			return tn.tr.DialAddr(ctx, addr, cluster.ALPNPeer, peer.Pin, nil)
		}}
}

func (c *tcluster) reports(t *testing.T) map[cluster.NodeID]*Report {
	t.Helper()
	out := map[cluster.NodeID]*Report{}
	for id, tn := range c.nodes {
		r := c.prober(tn).Probe(context.Background(), tn.node, Checked(c.snap))
		out[id] = &r
	}
	return out
}

func TestNetcheckAllGood(t *testing.T) {
	c := newTCluster(t)
	res := Evaluate(c.snap, c.reports(t), nil, time.Now())
	if !res.OK || res.Reason != "" || len(res.PerMember) != 3 {
		t.Fatalf("%+v", res)
	}
	for _, m := range res.PerMember {
		if !m.OK || len(m.Paths) != 4 {
			t.Fatalf("%s: %+v", m.Node, m)
		}
		for _, p := range m.Paths {
			if !p.OK || !p.Answered || !p.Bulk || !p.SameSubnet || p.Local != p.Addr || p.SeenAs != p.Addr || p.Arrived != p.PeerAddr || p.MTU != 1500 || p.PeerMTU != 1500 {
				t.Fatalf("%s: %+v", m.Node, p)
			}
		}
	}
	// The JSON shape the API and the other builder use.
	b, _ := json.Marshal(res)
	for _, k := range []string{`"ok":true`, `"perMember"`, `"paths"`} {
		if !strings.Contains(string(b), k) {
			t.Fatalf("%s missing in %s", k, b)
		}
	}
}

func TestNetcheckStorageCutForOneMember(t *testing.T) {
	c := newTCluster(t)
	c2 := c.nodes["c2"].node.Addresses.Storage
	c.net.Isolate(c2, c.nodes["nas"].node.Addresses.Storage, c.nodes["c1"].node.Addresses.Storage)
	res := Evaluate(c.snap, c.reports(t), nil, time.Now())
	if res.OK || !strings.Contains(res.Reason, "storage network") || !strings.Contains(res.Reason, "not reachable") {
		t.Fatalf("%+v", res)
	}
	for _, m := range res.PerMember {
		if m.OK {
			t.Fatalf("%s should fail too (it can't reach c2 on the storage network, or is c2): %+v", m.Node, m)
		}
		for _, p := range m.Paths {
			involves := m.Node == "c2" || p.Peer == "c2"
			if p.Path == cluster.PathLAN && !p.OK {
				t.Fatalf("LAN failed: %+v", p)
			}
			if p.Path == cluster.PathStorage && p.OK == involves {
				t.Fatalf("%s → %s storage ok=%v", m.Node, p.Peer, p.OK)
			}
		}
	}
	// Healed: good again.
	c.net.Rejoin(c2, c.nodes["nas"].node.Addresses.Storage, c.nodes["c1"].node.Addresses.Storage)
	if res := Evaluate(c.snap, c.reports(t), nil, time.Now()); !res.OK {
		t.Fatalf("healed: %+v", res)
	}
}

func TestNetcheckStorageMTUMismatch(t *testing.T) {
	c := newTCluster(t)
	tn := c.nodes["c1"]
	tn.mtuMu.Lock()
	tn.mtu[tn.node.Addresses.Storage] = 9000
	tn.mtuMu.Unlock()
	res := Evaluate(c.snap, c.reports(t), nil, time.Now())
	if res.OK || !strings.Contains(res.Reason, "MTU") {
		t.Fatalf("%+v", res)
	}
}

func TestNetcheckMissingAndStaleReports(t *testing.T) {
	c := newTCluster(t)
	reps := c.reports(t)
	delete(reps, "c2")
	res := Evaluate(c.snap, reps, map[cluster.NodeID]error{"c2": cluster.ErrUnreachable}, time.Now())
	if res.OK || !strings.Contains(res.Reason, "couldn't get c2's check") {
		t.Fatalf("missing: %+v", res)
	}
	reps = c.reports(t)
	reps["c1"].Checked = time.Now().Add(-3 * time.Minute)
	if res := Evaluate(c.snap, reps, nil, time.Now()); res.OK || !strings.Contains(res.Reason, "old") {
		t.Fatalf("stale: %+v", res)
	}
	// A report that names another server.
	reps = c.reports(t)
	reps["c1"] = reps["c2"]
	if res := Evaluate(c.snap, reps, nil, time.Now()); res.OK || !strings.Contains(res.Reason, "another server's") {
		t.Fatalf("swapped: %+v", res)
	}
	// A dead server is skipped, not a failure; a witness isn't checked.
	reps = c.reports(t)
	c.snap.Nodes["c2"].State = cluster.NodeDead
	c.snap.Nodes["w"] = &cluster.Node{ID: "w", Role: cluster.RoleWitness, State: cluster.NodeActive}
	delete(reps, "c2")
	for _, r := range reps {
		var keep []PathResult
		for _, p := range r.Paths {
			if p.Peer != "c2" {
				keep = append(keep, p)
			}
		}
		r.Paths = keep
	}
	res = Evaluate(c.snap, reps, nil, time.Now())
	if !res.OK || len(res.PerMember) != 3 {
		t.Fatalf("dead: %+v", res)
	}
	for _, m := range res.PerMember {
		if m.Node == "c2" && !m.Skipped {
			t.Fatalf("c2 not skipped: %+v", m)
		}
	}
}

func TestJudgeRules(t *testing.T) {
	self := &cluster.Node{ID: "c1", Name: "c1", Addresses: cluster.Addresses{LAN: netip.MustParseAddr("192.168.1.21"), Storage: netip.MustParseAddr("10.77.0.21"), NetBird: netip.MustParseAddr("100.64.0.21")}}
	peer := &cluster.Node{ID: "c2", Name: "c2", Addresses: cluster.Addresses{LAN: netip.MustParseAddr("192.168.1.22"), Storage: netip.MustParseAddr("10.77.0.22")}}
	good := func(p cluster.Path) PathResult {
		return PathResult{Peer: "c2", Path: p, Answered: true, RTT: time.Millisecond, Local: pathAddr(self.Addresses, p), SeenAs: pathAddr(self.Addresses, p),
			Arrived: pathAddr(peer.Addresses, p), Bulk: true, MTU: 9000, PeerMTU: 9000}
	}
	for name, tc := range map[string]struct {
		mod  func(*PathResult)
		want string
	}{
		"ok":       {func(*PathResult) {}, ""},
		"netbird":  {func(p *PathResult) { p.Local = self.Addresses.NetBird }, "over NetBird"},
		"route":    {func(p *PathResult) { p.Local = netip.MustParseAddr("192.168.5.1") }, "another route"},
		"nat":      {func(p *PathResult) { p.SeenAs = netip.MustParseAddr("192.168.1.1") }, "NAT"},
		"arrived":  {func(p *PathResult) { p.Arrived = netip.MustParseAddr("10.77.0.99") }, "arrives at"},
		"slow":     {func(p *PathResult) { p.RTT = MaxRTT + time.Millisecond }, "not a local network"},
		"jumbo":    {func(p *PathResult) { p.Bulk = false }, "jumbo frames"},
		"mtu":      {func(p *PathResult) { p.PeerMTU = 1500 }, "MTU 9000 here but 1500"},
		"noanswer": {func(p *PathResult) { p.Answered, p.Problem = false, "connect: no route to host" }, "no route to host"},
	} {
		pr := good(cluster.PathStorage)
		tc.mod(&pr)
		Judge(&pr, self, peer)
		if (tc.want == "") != pr.OK || !strings.Contains(pr.Reason, tc.want) {
			t.Errorf("%s: ok=%v reason=%q", name, pr.OK, pr.Reason)
		}
	}
	// No storage address on the peer.
	p2 := *peer
	p2.Addresses.Storage = netip.Addr{}
	pr := good(cluster.PathStorage)
	Judge(&pr, self, &p2)
	if pr.OK || !strings.Contains(pr.Reason, "c2 has no address") {
		t.Fatalf("%+v", pr)
	}
	// LAN MTU differences aren't the storage rule.
	pr = good(cluster.PathLAN)
	pr.PeerMTU = 1500
	Judge(&pr, self, peer)
	if !pr.OK {
		t.Fatalf("%+v", pr)
	}
}

func TestProbeSignatures(t *testing.T) {
	a, _ := cluster.NewIdentity("a")
	b, _ := cluster.NewIdentity("b")
	ans, err := Sign(a, Statement{Node: "a", Peer: "b", Nonce: "n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(a.PublicKey, ans); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(b.PublicKey, ans); err == nil {
		t.Fatal("another key verified")
	}
	ans.Statement = json.RawMessage(strings.Replace(string(ans.Statement), `"n"`, `"m"`, 1))
	if _, err := Verify(a.PublicKey, ans); err == nil {
		t.Fatal("a changed statement verified")
	}
	// A heartbeat statement's signature over the same bytes isn't one.
	st, _ := json.Marshal(Statement{Node: "a"})
	sig, _, err := signHeartbeatLike(a, st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(a.PublicKey, &ProbeAnswer{Statement: st, Signature: sig}); err == nil {
		t.Fatal("a signature from another domain verified")
	}
}

func TestResponderRefusesOthers(t *testing.T) {
	c := newTCluster(t)
	tn := c.nodes["nas"]
	// The witness may reach the peer API but never probe.
	w, _ := cluster.NewIdentity("w")
	c.book.mu.Lock()
	c.book.nodes["w"] = cluster.Node{ID: "w", Role: cluster.RoleWitness, Pin: w.Pin, PublicKey: w.PublicKey, State: cluster.NodeActive,
		Addresses: cluster.Addresses{NetBird: netip.MustParseAddr("100.64.0.99")}}
	c.book.mu.Unlock()
	wt := &cluster.Transport{ID: w, Self: "w", Net: c.net.Host(netip.MustParseAddr("100.64.0.99")), Book: c.book, Port: 44500}
	defer wt.Close()
	p := &Prober{Port: 44500, Dial: func(ctx context.Context, addr string, peer cluster.Node) (net.Conn, error) {
		return wt.DialAddr(ctx, addr, cluster.ALPNPeer, peer.Pin, nil)
	}}
	self := c.book.nodes["w"]
	self.Addresses.LAN = netip.MustParseAddr("100.64.0.99") // so it tries
	peer := tn.node
	peer.Addresses.LAN = tn.node.Addresses.NetBird
	pr := p.ProbePath(context.Background(), self, &peer, cluster.PathLAN)
	if pr.Answered || !strings.Contains(pr.Problem, "403") {
		t.Fatalf("%+v", pr)
	}
}

// signHeartbeatLike signs bytes the way heartbeat statements are signed
// (another domain).
func signHeartbeatLike(id *cluster.Identity, raw []byte) ([]byte, []byte, error) {
	sum := sha256.Sum256(append([]byte(cluster.StatementDomain), raw...))
	sig, err := ecdsa.SignASN1(rand.Reader, id.Key, sum[:])
	return sig, nil, err
}
