package network

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// TestNetIntegration drives the real Manager against ifupdown, bonding and
// VLANs. It reconfigures the machine's network, so it only runs inside a
// throwaway VM with two NICs on QEMU user networking (10.0.2.0/24, gateway
// 10.0.2.2, DHCP gives 10.0.2.15):
//
//	HARDYOS_NET_INTEGRATION=1 ./network.test -test.run TestNetIntegration -test.v
func TestNetIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_NET_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_NET_INTEGRATION=1 inside a throwaway VM")
	}
	ctx := context.Background()
	m := &Manager{Runner: sysexec.Exec{}, Root: "/", StateDir: t.TempDir(), RevertAfter: time.Hour}
	ports := m.PortNames()
	t.Logf("ports: %v", ports)
	if len(ports) < 2 {
		t.Fatalf("need two NICs, have %v", ports)
	}
	p0, p1 := ports[0], ports[1]

	addrs := func(dev string) []string {
		out, _ := exec.Command("ip", "-j", "-4", "addr", "show", "dev", dev).Output()
		var list []ipAddr
		_ = json.Unmarshal(out, &list)
		var a []string
		for _, l := range list {
			for _, ai := range l.AddrInfo {
				a = append(a, ai.Local)
			}
		}
		return a
	}
	waitAddr := func(dev, want string) {
		t.Helper()
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			if slices.Contains(addrs(dev), want) {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
		t.Fatalf("%s never got %s (has %v)", dev, want, addrs(dev))
	}
	noAddr := func(dev string) {
		t.Helper()
		if a := addrs(dev); len(a) > 0 {
			t.Fatalf("%s should have no IPv4 address, has %v", dev, a)
		}
	}
	defaultVia := func() string {
		out, _ := exec.Command("ip", "-j", "route", "show", "default").Output()
		var r []struct {
			Gateway string `json:"gateway"`
			Dev     string `json:"dev"`
		}
		_ = json.Unmarshal(out, &r)
		if len(r) == 0 {
			return ""
		}
		return r[0].Gateway + " dev " + r[0].Dev
	}
	apply := func(name string, c Config) {
		t.Helper()
		t.Logf("--- apply %s", name)
		if _, err := m.Apply(ctx, c); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, _ := os.ReadFile("/etc/network/interfaces")
		t.Logf("interfaces:\n%s", b)
	}
	confirm := func() {
		t.Helper()
		if _, err := m.Confirm(); err != nil {
			t.Fatal(err)
		}
	}

	// Start: what a fresh install has (DHCP on every port).
	start := Default("hardyos", ports)
	apply("dhcp everywhere", start)
	waitAddr(p0, "10.0.2.15")
	waitAddr(p1, "10.0.2.15")
	confirm()

	// A: fixed address on the first port, second port off.
	a := Default("nas", ports)
	a.Interfaces[0].Addressing = Addressing{Mode: ModeStatic, Address: "10.0.2.50/24", Gateway: "10.0.2.2"}
	a.Interfaces[1].Mode = ModeOff
	a.DNS = []string{"10.0.2.3"}
	apply("static", a)
	waitAddr(p0, "10.0.2.50")
	noAddr(p1)
	if got := defaultVia(); got != "10.0.2.2 dev "+p0 {
		t.Fatalf("default route = %q", got)
	}
	if h, _ := os.Hostname(); h != "nas" {
		t.Fatalf("hostname = %q", h)
	}
	if b, _ := os.ReadFile("/etc/resolv.conf"); !strings.Contains(string(b), "nameserver 10.0.2.3") {
		t.Fatalf("resolv.conf:\n%s", b)
	}
	confirm()

	// B: both ports bonded (failover) with a fixed address, plus a VLAN.
	b := Default("nas", ports)
	b.Bonds = []Bond{{Name: "bond0", Members: []string{p0, p1}, Policy: "active-backup", Addressing: Addressing{Mode: ModeStatic, Address: "10.0.2.60/24", Gateway: "10.0.2.2"}}}
	b.VLANs = []VLAN{{Parent: "bond0", ID: 20, Addressing: Addressing{Mode: ModeStatic, Address: "192.168.20.5/24", MTU: 1400}}}
	b.DNS = []string{"10.0.2.3"}
	apply("bond + vlan", b)
	waitAddr("bond0", "10.0.2.60")
	waitAddr("bond0.20", "192.168.20.5")
	noAddr(p0)
	noAddr(p1)
	slaves, _ := os.ReadFile("/sys/class/net/bond0/bonding/slaves")
	if got := strings.Fields(string(slaves)); !slices.Contains(got, p0) || !slices.Contains(got, p1) {
		t.Fatalf("bond slaves = %q", slaves)
	}
	mode, _ := os.ReadFile("/sys/class/net/bond0/bonding/mode")
	if !strings.HasPrefix(string(mode), "active-backup") {
		t.Fatalf("bond mode = %q", mode)
	}
	if mtu, _ := os.ReadFile("/sys/class/net/bond0.20/mtu"); strings.TrimSpace(string(mtu)) != "1400" {
		t.Fatalf("vlan mtu = %q", mtu)
	}
	if got := defaultVia(); got != "10.0.2.2 dev bond0" {
		t.Fatalf("default route = %q", got)
	}

	// Undo B: back to A, bond gone.
	t.Log("--- revert bond + vlan")
	if err := m.Revert(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	waitAddr(p0, "10.0.2.50")
	noAddr(p1)
	if a := addrs("bond0"); len(a) > 0 {
		t.Fatalf("bond0 still has %v after revert", a)
	}
	if _, err := os.Stat("/sys/class/net/bond0.20"); err == nil {
		t.Fatal("bond0.20 still exists after revert")
	}

	// C: VLAN on a plain port that has no address itself, and automatic undo.
	m.RevertAfter = 3 * time.Second
	c := Default("nas", ports)
	c.Interfaces[0].Mode = ModeOff
	c.Interfaces[1].Mode = ModeDHCP
	c.VLANs = []VLAN{{Parent: p0, ID: 30, Addressing: Addressing{Mode: ModeStatic, Address: "192.168.30.5/24"}}}
	apply("vlan on bare port, not confirmed", c)
	waitAddr(p0+".30", "192.168.30.5")
	noAddr(p0)
	waitAddr(p1, "10.0.2.15")
	t.Log("--- waiting for the automatic undo")
	waitAddr(p0, "10.0.2.50")
	noAddr(p1)
	if _, err := os.Stat("/sys/class/net/" + p0 + ".30"); err == nil {
		t.Fatal("vlan still exists after the automatic undo")
	}
	st, err := m.Status(ctx)
	if err != nil || st.Pending != nil || st.LastRevert == nil {
		t.Fatalf("after auto undo: pending=%v lastRevert=%v err=%v", st.Pending, st.LastRevert, err)
	}
	if h, _ := os.Hostname(); h != "nas" {
		t.Fatalf("hostname after undo = %q", h)
	}

	// D: back to DHCP everywhere; DHCP DNS takes over resolv.conf again.
	m.RevertAfter = time.Hour
	apply("dhcp again", Default("nas", ports))
	waitAddr(p0, "10.0.2.15")
	confirm()
	if _, err := os.Stat("/" + DNSHookPath); err == nil {
		t.Fatal("dns hook left behind")
	}
	t.Log("all network scenarios passed")
}
