package netcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// The local-network check between real network stacks (the "Cluster
// (namespaces)" CI job, as root with HARDYOS_NETCHECK_NETNS=1): three
// servers (nas, c1, c2), each in its own network namespace with a LAN port
// and a storage port, plugged into two bridges in a "switch" namespace.
// Each server is this test binary run in its namespace
// (TestNetcheckNamespaceMember) with a real cluster transport on TCP; the
// parent tells them when to probe and judges their reports:
//
//  1. everything connected: OK;
//  2. c2's storage port unplugged at the switch: not OK, the storage
//     network named, the LAN still good;
//  3. jumbo frames (MTU 9000) on every server's storage port behind
//     switch ports of 1500: large frames are lost (the large probe, and
//     already the TLS handshake, whose key shares are over 1500 bytes) and
//     the check says to check the switch's jumbo frames.

type nsConfig struct {
	Nodes []cluster.Node            `json:"nodes"`
	Keys  map[cluster.NodeID][]byte `json:"keys"`
}

var nsMembers = []struct {
	id   cluster.NodeID
	role cluster.Role
	host int
}{{"nas", cluster.RoleStorage, 10}, {"c1", cluster.RoleCompute, 21}, {"c2", cluster.RoleCompute, 22}}

func nsName(id string) string { return "hnc-" + id }

func sh(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func TestNetcheckNamespaces(t *testing.T) {
	if os.Getenv("HARDYOS_NETCHECK_NETNS") != "1" || os.Geteuid() != 0 {
		t.Skip("set HARDYOS_NETCHECK_NETNS=1 and run as root (CI's Cluster (namespaces) job)")
	}
	// Real network stacks: the real rule.
	old := MaxRTT
	MaxRTT = 5 * time.Millisecond
	defer func() { MaxRTT = old }()
	dir := t.TempDir()
	cfg := nsConfig{Keys: map[cluster.NodeID][]byte{}}
	snap := &cluster.Snapshot{Nodes: map[cluster.NodeID]*cluster.Node{}}
	for _, m := range nsMembers {
		id, err := cluster.NewIdentity(string(m.id))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := cluster.MarshalIdentity(id)
		cfg.Keys[m.id] = b
		n := cluster.Node{ID: m.id, Name: string(m.id), Role: m.role, Pin: id.Pin, PublicKey: id.PublicKey, State: cluster.NodeActive,
			Addresses: cluster.Addresses{LAN: netip.MustParseAddr(fmt.Sprintf("192.168.77.%d", m.host)), Storage: netip.MustParseAddr(fmt.Sprintf("10.177.0.%d", m.host))}}
		cfg.Nodes = append(cfg.Nodes, n)
		nn := n
		snap.Nodes[n.ID] = &nn
	}
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, "cluster.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// The switch and the servers' namespaces.
	all := []string{nsName("sw")}
	for _, m := range nsMembers {
		all = append(all, nsName(string(m.id)))
	}
	for _, ns := range all {
		_ = exec.Command("ip", "netns", "del", ns).Run()
	}
	t.Cleanup(func() {
		for _, ns := range all {
			_ = exec.Command("ip", "netns", "del", ns).Run()
		}
	})
	for _, ns := range all {
		sh(t, "ip", "netns", "add", ns)
		sh(t, "ip", "-n", ns, "link", "set", "lo", "up")
	}
	sw := nsName("sw")
	for _, br := range []string{"brlan", "brstor"} {
		sh(t, "ip", "-n", sw, "link", "add", br, "type", "bridge")
		sh(t, "ip", "-n", sw, "link", "set", br, "up")
	}
	for _, m := range nsMembers {
		ns := nsName(string(m.id))
		for _, p := range []struct{ dev, port, br, addr string }{
			{"eth0", "l-" + string(m.id), "brlan", fmt.Sprintf("192.168.77.%d/24", m.host)},
			{"eth1", "s-" + string(m.id), "brstor", fmt.Sprintf("10.177.0.%d/24", m.host)},
		} {
			sh(t, "ip", "link", "add", p.dev, "netns", ns, "type", "veth", "peer", "name", p.port, "netns", sw)
			sh(t, "ip", "-n", sw, "link", "set", p.port, "master", p.br)
			sh(t, "ip", "-n", sw, "link", "set", p.port, "up")
			sh(t, "ip", "-n", ns, "addr", "add", p.addr, "dev", p.dev)
			sh(t, "ip", "-n", ns, "link", "set", p.dev, "up")
		}
	}

	// The servers.
	for _, m := range nsMembers {
		cmd := exec.Command("ip", "netns", "exec", nsName(string(m.id)), os.Args[0], "-test.run", "^TestNetcheckNamespaceMember$", "-test.v")
		cmd.Env = append(os.Environ(), "HARDYOS_NETCHECK_MEMBER="+string(m.id), "HARDYOS_NETCHECK_DIR="+dir)
		logf, _ := os.Create(filepath.Join(dir, string(m.id)+".log"))
		cmd.Stdout, cmd.Stderr = logf, logf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = os.WriteFile(filepath.Join(dir, "stop"), nil, 0o600)
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
			}
			logf.Close()
			if t.Failed() {
				b, _ := os.ReadFile(logf.Name())
				t.Logf("%s's log:\n%s", m.id, b)
			}
		})
	}
	for _, m := range nsMembers {
		waitFile(t, filepath.Join(dir, "ready-"+string(m.id)))
	}

	round := func(n int) Result {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("round-%d", n)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		reps := map[cluster.NodeID]*Report{}
		for _, m := range nsMembers {
			f := filepath.Join(dir, fmt.Sprintf("report-%s-%d.json", m.id, n))
			waitFile(t, f)
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			var r Report
			if err := json.Unmarshal(b, &r); err != nil {
				t.Fatal(err)
			}
			reps[m.id] = &r
		}
		res := Evaluate(snap, reps, nil, time.Now())
		b, _ := json.MarshalIndent(res, "", "  ")
		t.Logf("round %d:\n%s", n, b)
		return res
	}

	// 1. Everything connected.
	if res := round(1); !res.OK {
		t.Fatalf("connected: %s", res.Reason)
	}

	// 2. c2's storage port unplugged at the switch.
	sh(t, "ip", "-n", sw, "link", "set", "s-c2", "down")
	res := round(2)
	if res.OK || !strings.Contains(res.Reason, "storage network") {
		t.Fatalf("storage cut: %+v", res)
	}
	for _, m := range res.PerMember {
		for _, p := range m.Paths {
			if p.Path == cluster.PathLAN && !p.OK {
				t.Fatalf("the LAN failed with the storage network cut: %+v", p)
			}
			involves := m.Node == "c2" || p.Peer == "c2"
			if p.Path == cluster.PathStorage && p.OK == involves {
				t.Fatalf("%s → %s on the storage network: ok=%v %s", m.Node, p.Peer, p.OK, p.Reason)
			}
		}
	}
	sh(t, "ip", "-n", sw, "link", "set", "s-c2", "up")

	// 3. Jumbo frames on the servers, 1500 on the switch: the servers'
	// segmentation offloads off so a 9000-byte frame really is one (with
	// them a veth passes oversized segments through).
	if _, err := exec.LookPath("ethtool"); err != nil {
		t.Log("ethtool isn't installed: the jumbo frame case is skipped")
		return
	}
	for _, m := range nsMembers {
		ns := nsName(string(m.id))
		sh(t, "ip", "netns", "exec", ns, "ethtool", "-K", "eth1", "tso", "off", "gso", "off", "gro", "off")
		sh(t, "ip", "-n", ns, "link", "set", "eth1", "mtu", "9000")
	}
	res = round(3)
	if res.OK || !strings.Contains(res.Reason, "jumbo frames") {
		t.Fatalf("jumbo frames behind a 1500 switch: %+v", res)
	}
	for _, m := range res.PerMember {
		for _, p := range m.Paths {
			// Large frames are lost: the bulk probe always, and the TLS
			// handshake too (its post-quantum key shares are over 1500 bytes).
			if p.Path == cluster.PathStorage && (p.OK || p.Bulk || p.MTU != 9000 || !strings.Contains(p.Reason, "jumbo frames")) {
				t.Fatalf("%s → %s: large frames should be lost and named: %+v", m.Node, p.Peer, p)
			}
			if p.Path == cluster.PathLAN && !p.OK {
				t.Fatalf("LAN: %+v", p)
			}
		}
	}
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s didn't appear", path)
}

// staticBook is the parent's cluster as a member sees it.
type staticBook map[cluster.NodeID]cluster.Node

func (b staticBook) ByPin(pin string) (cluster.Node, bool) {
	for _, n := range b {
		if n.Pin == pin {
			return n, true
		}
	}
	return cluster.Node{}, false
}

func (b staticBook) Member(id cluster.NodeID) (cluster.Node, bool) {
	n, ok := b[id]
	return n, ok
}

// TestNetcheckNamespaceMember is one server of TestNetcheckNamespaces (run
// by it inside a namespace).
func TestNetcheckNamespaceMember(t *testing.T) {
	me := cluster.NodeID(os.Getenv("HARDYOS_NETCHECK_MEMBER"))
	dir := os.Getenv("HARDYOS_NETCHECK_DIR")
	if me == "" || dir == "" {
		t.Skip("run by TestNetcheckNamespaces")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "cluster.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg nsConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	id, err := cluster.UnmarshalIdentity(cfg.Keys[me])
	if err != nil {
		t.Fatal(err)
	}
	bk := staticBook{}
	var peers []*cluster.Node
	for _, n := range cfg.Nodes {
		bk[n.ID] = n
		nn := n
		peers = append(peers, &nn)
	}
	self := bk[me]
	mux := http.NewServeMux()
	mux.Handle("POST "+cluster.PeerPathPrefix+ProbePath, &Responder{Identity: func() *cluster.Identity { return id },
		Self: func() cluster.NodeID { return me }, Interfaces: Interfaces,
		Caller: func(r *http.Request) (cluster.Node, bool) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				return cluster.Node{}, false
			}
			return bk.ByPin(cluster.PinOfCert(r.TLS.PeerCertificates[0]))
		}})
	tr := &cluster.Transport{ID: id, Self: me, Net: cluster.TCP{}, Book: bk, Peer: mux}
	tr.SetListen([]netip.Addr{self.Addresses.LAN, self.Addresses.Storage})
	defer tr.Close()
	p := &Prober{Interfaces: Interfaces, Dial: func(ctx context.Context, addr string, peer cluster.Node) (net.Conn, error) {
		return tr.DialAddr(ctx, addr, cluster.ALPNPeer, peer.Pin, nil)
	}}
	if err := os.WriteFile(filepath.Join(dir, "ready-"+string(me)), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for n := 1; ; n++ {
		for {
			if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
				return
			}
			if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("round-%d", n))); err == nil {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		rep := p.Probe(context.Background(), self, peers)
		b, _ := json.Marshal(rep)
		tmp := filepath.Join(dir, fmt.Sprintf(".report-%s-%d", me, n))
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, fmt.Sprintf("report-%s-%d.json", me, n))); err != nil {
			t.Fatal(err)
		}
		t.Logf("round %d done", n)
	}
}
