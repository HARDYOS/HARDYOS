package network

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestBridgeValidation(t *testing.T) {
	c := base()
	c.Interfaces[0].Addressing = Addressing{Mode: ModeBridged}
	c.Bridges = []Bridge{{Name: "br0", Port: "eno1", MAC: "52:54:00:aa:bb:cc", Addressing: Addressing{Mode: ModeDHCP}}}
	valid(t, c)

	// Normalize marks the port, whatever it said.
	c2 := base()
	c2.Bridges = []Bridge{{Name: "br0", Port: "eno1", Addressing: Addressing{Mode: ModeStatic, Address: "192.168.1.20/24", Gateway: "192.168.1.1"}}}
	c2.DNS = []string{"192.168.1.1"}
	c2.Normalize()
	if c2.Interfaces[0].Mode != ModeBridged || c2.Interfaces[0].Address != "" {
		t.Fatalf("port under the bridge = %+v", c2.Interfaces[0])
	}
	valid(t, c2)

	bad := base()
	bad.Bridges = []Bridge{{Name: "bridge0", Port: "eno1", Addressing: Addressing{Mode: ModeDHCP}}}
	invalid(t, bad, "br0 to br9")
	bad.Bridges = []Bridge{{Name: "br0", Port: "nope", Addressing: Addressing{Mode: ModeDHCP}}}
	invalid(t, bad, "not a port or bond")
	bad.Bridges = []Bridge{{Name: "br0", Port: "eno1", Addressing: Addressing{Mode: ModeDHCP}}, {Name: "br1", Port: "eno1", Addressing: Addressing{Mode: ModeOff}}}
	invalid(t, bad, "under both")
	bad.Bridges = []Bridge{{Name: "br0", Port: "eno1", MAC: "nope", Addressing: Addressing{Mode: ModeDHCP}}}
	invalid(t, bad, "isn't a MAC")

	// A bond member can't carry a bridge; the bond can.
	bond := base()
	bond.Bonds = []Bond{{Name: "bond0", Members: []string{"eno1", "eno2"}, Policy: "active-backup", Addressing: Addressing{Mode: ModeOff}}}
	bond.Bridges = []Bridge{{Name: "br0", Port: "eno1", Addressing: Addressing{Mode: ModeDHCP}}}
	invalid(t, bond, "member of bond0")
	bond.Bridges[0].Port = "bond0"
	valid(t, bond)

	// VLANs go on the bridge, not the port under it.
	vl := base()
	vl.Bridges = []Bridge{{Name: "br0", Port: "eno1", Addressing: Addressing{Mode: ModeDHCP}}}
	vl.VLANs = []VLAN{{Parent: "eno1", ID: 20, Addressing: Addressing{Mode: ModeDHCP}}}
	invalid(t, vl, "put the VLAN on br0")
	vl.VLANs[0].Parent = "br0"
	valid(t, vl)

	// Only a bridge's own port can be "bridged".
	stray := base()
	stray.Interfaces[1].Addressing = Addressing{Mode: ModeBridged}
	stray.Normalize()
	if stray.Interfaces[1].Mode != ModeOff {
		t.Fatalf("a bridged port without a bridge = %+v", stray.Interfaces[1])
	}
}

func TestRenderBridge(t *testing.T) {
	c := base()
	c.Bonds = []Bond{{Name: "bond0", Members: []string{"eno1", "eno2"}, Policy: "802.3ad", Addressing: Addressing{Mode: ModeOff}}}
	c.Bridges = []Bridge{{Name: "br0", Port: "bond0", MAC: "52:54:00:aa:bb:cc", Addressing: Addressing{Mode: ModeStatic, Address: "192.168.1.20/24", Gateway: "192.168.1.1"}}}
	c.VLANs = []VLAN{{Parent: "br0", ID: 30, Addressing: Addressing{Mode: ModeDHCP}}}
	c.DNS = []string{"192.168.1.1"}
	c.Normalize()
	if err := c.Validate(ports); err != nil {
		t.Fatal(err)
	}
	got := RenderInterfaces(c)
	for _, want := range []string{
		"auto bond0\niface bond0 inet manual\n\tbond-slaves eno1 eno2",
		"auto br0\niface br0 inet static\n\taddress 192.168.1.20/24\n\tgateway 192.168.1.1\n\tbridge-ports bond0\n\tbridge-stp off\n\tbridge-fd 0\n\tbridge-waitport 0\n\thwaddress ether 52:54:00:aa:bb:cc\n\tpost-up ip link set dev br0 type bridge vlan_filtering 1\n\tpost-up bridge vlan add dev bond0 vid 2-4094\n",
		"auto br0.30\niface br0.30 inet dhcp\n\tvlan-raw-device br0\n\tpre-up bridge vlan add dev br0 vid 30 self\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing:\n%s\nin:\n%s", want, got)
		}
	}
	// The bond comes up before the bridge that uses it.
	if strings.Index(got, "iface bond0") > strings.Index(got, "iface br0 ") {
		t.Errorf("bridge before its bond:\n%s", got)
	}

	p := base()
	p.Bridges = []Bridge{{Name: "br0", Port: "eno1", Addressing: Addressing{Mode: ModeDHCP}}}
	p.Normalize()
	got = RenderInterfaces(p)
	if !strings.Contains(got, "\niface eno1 inet manual\n") || strings.Contains(got, "allow-hotplug eno1") || strings.Contains(got, "auto eno1") {
		t.Errorf("port under the bridge:\n%s", got)
	}
	if !strings.Contains(got, "auto br0\niface br0 inet dhcp\n") {
		t.Errorf("bridge on DHCP:\n%s", got)
	}
}

func TestWithBridgeMovesAddressAndVLANs(t *testing.T) {
	c := base()
	c.Interfaces[0].Addressing = Addressing{Mode: ModeStatic, Address: "192.168.1.20/24", Gateway: "192.168.1.1", MTU: 9000}
	c.DNS = []string{"192.168.1.1"}
	c.VLANs = []VLAN{{Parent: "eno1", ID: 20, Addressing: Addressing{Mode: ModeDHCP}}, {Parent: "eno2", ID: 30, Addressing: Addressing{Mode: ModeOff}}}
	c.Normalize()
	next, err := WithBridge(c, "br0", "eno1", "AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatal(err)
	}
	if err := next.Validate(ports); err != nil {
		t.Fatal(err)
	}
	br := next.Bridges[0]
	if br.Port != "eno1" || br.Mode != ModeStatic || br.Address != "192.168.1.20/24" || br.Gateway != "192.168.1.1" || br.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("bridge = %+v", br)
	}
	if next.Interfaces[0].Mode != ModeBridged || next.Interfaces[0].MTU != 9000 {
		t.Fatalf("port = %+v", next.Interfaces[0])
	}
	if next.VLANs[0].Parent != "br0" || next.VLANs[1].Parent != "eno2" {
		t.Fatalf("vlans = %+v", next.VLANs)
	}
	// The original is untouched.
	if c.Interfaces[0].Mode != ModeStatic || len(c.Bridges) != 0 || c.VLANs[0].Parent != "eno1" {
		t.Fatalf("original changed: %+v", c)
	}
	if _, err := WithBridge(c, "br0", "eno9", ""); !errors.Is(err, ErrNoUplink) {
		t.Fatalf("missing port: %v", err)
	}

	// Taking the bridge away gives the address back to the port.
	back := next
	back.Bridges = []Bridge{}
	back.giveBackAddresses(next)
	back.Normalize()
	if back.Interfaces[0].Mode != ModeStatic || back.Interfaces[0].Address != "192.168.1.20/24" || back.Interfaces[0].MTU != 9000 || back.VLANs[0].Parent != "eno1" {
		t.Fatalf("after removing the bridge: %+v %+v", back.Interfaces[0], back.VLANs)
	}
	if err := back.Validate(ports); err != nil {
		t.Fatal(err)
	}
}

// bridgeManager is a Manager whose fake network gives the bridge the old
// address (ok) or none (not ok).
func bridgeManager(t *testing.T, ok bool) (*Manager, *sysexec.Fake, *eventLog) {
	t.Helper()
	m, fake, root := newManager(t)
	m.BridgeSettle = 300 * time.Millisecond
	mustWrite(t, filepath.Join(root, "sys/class/net/eno1/address"), "AA:BB:CC:00:11:22\n")
	fake.On("ip -j -4 route show default", `[{"dst":"default","gateway":"192.168.1.1","dev":"eno1"}]`)
	fake.On("ip -j route show default", `[{"dst":"default","gateway":"192.168.1.1","dev":"eno1"}]`)
	addr := `[{"ifname":"%s","addr_info":[{"family":"inet","local":"192.168.1.20","prefixlen":24,"scope":"global"}]}]`
	fake.On("ip -j -4 addr show dev eno1", strings.Replace(addr, "%s", "eno1", 1))
	if ok {
		fake.On("ip -j -4 addr show dev br0", strings.Replace(addr, "%s", "br0", 1))
	}
	fake.OnPrefix("arping ", sysexec.Result{})
	events := &eventLog{}
	m.BeforeBridges = func(context.Context) { events.add("before") }
	m.AfterBridges = func(context.Context) { events.add("after") }
	return m, fake, events
}

type eventLog struct {
	mu sync.Mutex
	l  []string
}

func (e *eventLog) add(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.l = append(e.l, s)
}

func waitEvents(t *testing.T, events *eventLog, n int) []string {
	t.Helper()
	for i := 0; i < 100; i++ {
		events.mu.Lock()
		got := append([]string{}, events.l...)
		events.mu.Unlock()
		if len(got) >= n || i == 99 {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func TestEnsureBridge(t *testing.T) {
	m, fake, events := bridgeManager(t, true)
	ctx := context.Background()
	if m.BridgeName() != "" {
		t.Fatal("a bridge before any was made")
	}
	name, err := m.EnsureBridge(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if name != "br0" || m.BridgeName() != "br0" {
		t.Fatalf("bridge = %q / %q", name, m.BridgeName())
	}
	// Confirmed by itself: nothing waits.
	if p, _ := m.loadPending(); p != nil {
		t.Fatal("the bridge is still waiting for confirmation")
	}
	cur := m.Current()
	if len(cur.Bridges) != 1 || cur.Bridges[0].Port != "eno1" || cur.Bridges[0].Mode != ModeDHCP || cur.Bridges[0].MAC != "aa:bb:cc:00:11:22" {
		t.Fatalf("saved = %+v", cur.Bridges)
	}
	if got := read(t, m.Root, InterfacesPath); !strings.Contains(got, "bridge-ports eno1") || !strings.Contains(got, "hwaddress ether aa:bb:cc:00:11:22") {
		t.Fatalf("interfaces:\n%s", got)
	}
	if !strings.Contains(strings.Join(fake.Lines(), "\n"), "arping -q -c 2 -w 3 -I br0 192.168.1.1") {
		t.Fatalf("the gateway wasn't checked:\n%s", strings.Join(fake.Lines(), "\n"))
	}
	if ev := waitEvents(t, events, 2); strings.Join(ev, ",") != "before,after" {
		t.Fatalf("domain hooks = %v", ev)
	}
	// Once there, it's reused.
	n := len(fake.Lines())
	if name, err := m.EnsureBridge(ctx); err != nil || name != "br0" || len(fake.Lines()) != n {
		t.Fatalf("second ensure = %q %v (%d new commands)", name, err, len(fake.Lines())-n)
	}

	// The Control Panel's page saving settings without bridges keeps it.
	c := m.Current()
	c.Bridges = nil
	c.Hostname = "nas2"
	if _, err := m.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	if st, _ := m.Status(ctx); len(st.Config.Bridges) != 1 {
		t.Fatalf("bridges after an unrelated change = %+v", st.Config.Bridges)
	}
	if ev := waitEvents(t, events, 2); len(ev) != 2 {
		t.Fatalf("an unrelated change moved the domain controller: %v", ev)
	}
}

func TestEnsureBridgeRollsBack(t *testing.T) {
	m, _, events := bridgeManager(t, false)
	before := read(t, m.Root, InterfacesPath)
	_, err := m.EnsureBridge(context.Background())
	if err == nil || !strings.Contains(err.Error(), "back as it was") {
		t.Fatalf("err = %v", err)
	}
	if m.BridgeName() != "" {
		t.Fatal("the bridge stayed")
	}
	if got := read(t, m.Root, InterfacesPath); got != before {
		t.Fatalf("interfaces not restored:\n%s", got)
	}
	st, _ := m.Status(context.Background())
	if st.Pending != nil || st.LastRevert == nil || !strings.Contains(st.LastRevert.Reason, "bridge for VMs") {
		t.Fatalf("status = %+v / %+v", st.Pending, st.LastRevert)
	}
	// The domain controller let go and came back twice (apply, undo).
	if ev := waitEvents(t, events, 4); strings.Join(ev, ",") != "before,after,before,after" && strings.Join(ev, ",") != "before,before,after,after" {
		t.Fatalf("domain hooks = %v", ev)
	}
}

func TestEnsureBridgeNeedsAPort(t *testing.T) {
	m, fake, _ := bridgeManager(t, true)
	fake.On("ip -j -4 route show default", `[{"dst":"default","gateway":"192.168.1.1","dev":"eno1.20"}]`)
	if _, err := m.EnsureBridge(context.Background()); !errors.Is(err, ErrNoUplink) {
		t.Fatalf("over a VLAN: %v", err)
	}
	if _, err := os.Stat(m.pendingFile()); err == nil {
		t.Fatal("a change was started")
	}
}
