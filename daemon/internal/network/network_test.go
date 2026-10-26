package network

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

var ports = []string{"eno1", "eno2", "enp3s0"}

func valid(t *testing.T, c Config) {
	t.Helper()
	c.Normalize()
	if err := c.Validate(ports); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
}

func invalid(t *testing.T, c Config, want string) {
	t.Helper()
	c.Normalize()
	err := c.Validate(ports)
	if err == nil {
		t.Fatalf("expected an error containing %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q doesn't mention %q", err, want)
	}
}

func base() Config {
	return Default("nas", ports)
}

func TestValidate(t *testing.T) {
	valid(t, base())

	c := base()
	c.Interfaces[0].Addressing = Addressing{Mode: ModeStatic, Address: "192.168.1.20/24", Gateway: "192.168.1.1"}
	valid(t, c)

	c.Interfaces[0].Gateway = "10.0.0.1"
	invalid(t, c, "outside 192.168.1.0/24")

	c = base()
	c.Interfaces[0].Addressing = Addressing{Mode: ModeStatic, Address: "192.168.1.0/24"}
	invalid(t, c, "network's own address")

	c.Interfaces[0].Address = "192.168.1.255/24"
	invalid(t, c, "broadcast")

	c.Interfaces[0].Address = "192.168.1.20"
	invalid(t, c, "must look like")

	c = base()
	for i := range c.Interfaces {
		c.Interfaces[i].Mode = ModeOff
	}
	invalid(t, c, "at least one")

	// Static everywhere and no DNS: no way to look up names.
	c.Interfaces[0].Addressing = Addressing{Mode: ModeStatic, Address: "10.0.0.5/24", Gateway: "10.0.0.1"}
	invalid(t, c, "add a DNS server")
	c.DNS = []string{"10.0.0.1", " ", "1.1.1.1"}
	valid(t, c)

	c = base()
	c.Hostname = "Bad_Name"
	invalid(t, c, "server name")

	c = base()
	c.Interfaces = c.Interfaces[1:]
	invalid(t, c, "port eno1 is missing")

	c = base()
	c.Interfaces[0].MTU = 20000
	invalid(t, c, "MTU")

	c = base()
	c.Interfaces[0].Addressing = Addressing{Mode: ModeStatic, Address: "10.0.0.5/24", Gateway: "10.0.0.1"}
	c.Interfaces[1].Addressing = Addressing{Mode: ModeStatic, Address: "10.0.1.5/24", Gateway: "10.0.1.1"}
	invalid(t, c, "only one interface can have a gateway")
}

func TestValidateBondsAndVLANs(t *testing.T) {
	c := base()
	c.Bonds = []Bond{{Name: "bond0", Members: []string{"eno2", "eno1"}, Policy: "802.3ad", Addressing: Addressing{Mode: ModeDHCP}}}
	c.VLANs = []VLAN{{Parent: "bond0", ID: 20, Addressing: Addressing{Mode: ModeStatic, Address: "10.20.0.5/24"}}}
	valid(t, c)
	c.Normalize()
	if c.Interfaces[0].Mode != ModeMember || c.Interfaces[1].Mode != ModeMember {
		t.Fatalf("members not marked: %+v", c.Interfaces)
	}
	if c.Interfaces[2].Mode != ModeDHCP {
		t.Fatalf("non-member changed: %+v", c.Interfaces[2])
	}

	bad := c
	bad.VLANs = []VLAN{{Parent: "eno1", ID: 20, Addressing: Addressing{Mode: ModeDHCP}}}
	invalid(t, bad, "is a bond member")

	bad = c
	bad.VLANs = []VLAN{{Parent: "bond0", ID: 5000, Addressing: Addressing{Mode: ModeDHCP}}}
	invalid(t, bad, "between 1 and 4094")

	bad = c
	bad.Bonds = append([]Bond{}, c.Bonds...)
	bad.Bonds = append(bad.Bonds, Bond{Name: "bond1", Members: []string{"eno1"}, Policy: "active-backup", Addressing: Addressing{Mode: ModeOff}})
	invalid(t, bad, "is in both bond0 and bond1")

	bad = c
	bad.Bonds = []Bond{{Name: "team0", Members: []string{"eno1"}, Policy: "active-backup", Addressing: Addressing{Mode: ModeDHCP}}}
	invalid(t, bad, "bond0 to bond99")

	bad = c
	bad.Bonds = []Bond{{Name: "bond0", Members: []string{"eno1"}, Policy: "round-robin", Addressing: Addressing{Mode: ModeDHCP}}}
	invalid(t, bad, "mode must be one of")

	// Leaving a bond turns a member back into a normal (off) port.
	c.Bonds = nil
	c.VLANs = nil
	c.Normalize()
	if c.Interfaces[0].Mode != ModeOff {
		t.Fatalf("former member = %q, want off", c.Interfaces[0].Mode)
	}
}

func TestRender(t *testing.T) {
	c := base()
	c.Interfaces[2].Addressing = Addressing{Mode: ModeStatic, Address: "192.168.1.20/24", Gateway: "192.168.1.1", MTU: 9000}
	c.Bonds = []Bond{{Name: "bond0", Members: []string{"eno1", "eno2"}, Policy: "active-backup", Addressing: Addressing{Mode: ModeOff}}}
	c.VLANs = []VLAN{{Parent: "bond0", ID: 30, Addressing: Addressing{Mode: ModeDHCP}}}
	c.DNS = []string{"192.168.1.1"}
	c.Search = []string{"home.arpa"}
	valid(t, c)
	c.Normalize()
	f := Render(c)
	ifs := *f[InterfacesPath]
	for _, want := range []string{
		"auto enp3s0\niface enp3s0 inet static\n\taddress 192.168.1.20/24\n\tgateway 192.168.1.1\n\tpre-up ip link set dev enp3s0 mtu 9000\n",
		"auto bond0\niface bond0 inet manual\n\tbond-slaves eno1 eno2\n\tbond-mode active-backup\n\tbond-miimon 100\n\tbond-primary eno1\n",
		"auto bond0.30\niface bond0.30 inet dhcp\n\tvlan-raw-device bond0\n",
	} {
		if !strings.Contains(ifs, want) {
			t.Errorf("interfaces missing:\n%s\n--- got:\n%s", want, ifs)
		}
	}
	if strings.Contains(ifs, "iface eno1") {
		t.Errorf("bond members must not get their own stanza:\n%s", ifs)
	}
	if got := *f[ResolvPath]; !strings.Contains(got, "nameserver 192.168.1.1\nsearch home.arpa\n") {
		t.Errorf("resolv.conf:\n%s", got)
	}
	if f[DNSHookPath] == nil {
		t.Error("custom DNS needs the dhclient hook")
	}
	if *f[HostnamePath] != "nas\n" {
		t.Errorf("hostname = %q", *f[HostnamePath])
	}

	// DHCP ports use allow-hotplug; DNS from DHCP leaves resolv.conf alone.
	d := base()
	f = Render(d)
	if !strings.Contains(*f[InterfacesPath], "allow-hotplug eno1\niface eno1 inet dhcp\n") {
		t.Errorf("dhcp port:\n%s", *f[InterfacesPath])
	}
	if _, ok := f[ResolvPath]; ok {
		t.Error("resolv.conf must be left to DHCP")
	}
	if v, ok := f[DNSHookPath]; !ok || v != nil {
		t.Error("the DNS hook must be removed when DNS comes from DHCP")
	}
}

func TestImportInstallerFile(t *testing.T) {
	// What the installer wrote for a static address on enp3s0.
	installer := `# Written by the HardyOS installer.

source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

allow-hotplug eno1
iface eno1 inet dhcp

auto enp3s0
iface enp3s0 inet static
	address 192.168.1.20/24
	gateway 192.168.1.1
`
	resolv := "# Written by the HardyOS installer\nnameserver 1.1.1.1\nnameserver 9.9.9.9\n"
	c := Import("nas", installer, resolv, ports)
	if err := c.Validate(ports); err != nil {
		t.Fatalf("imported settings invalid: %v", err)
	}
	want := map[string]string{"eno1": ModeDHCP, "eno2": ModeOff, "enp3s0": ModeStatic}
	for _, it := range c.Interfaces {
		if it.Mode != want[it.Name] {
			t.Errorf("%s = %s, want %s", it.Name, it.Mode, want[it.Name])
		}
	}
	if c.Interfaces[2].Address != "192.168.1.20/24" || c.Interfaces[2].Gateway != "192.168.1.1" {
		t.Errorf("static = %+v", c.Interfaces[2])
	}
	if strings.Join(c.DNS, ",") != "1.1.1.1,9.9.9.9" {
		t.Errorf("dns = %v", c.DNS)
	}

	// Round trip: what we render, we read back the same.
	c2 := base()
	c2.Bonds = []Bond{{Name: "bond0", Members: []string{"eno1", "eno2"}, Policy: "802.3ad", Addressing: Addressing{Mode: ModeStatic, Address: "10.0.0.5/24", Gateway: "10.0.0.1", MTU: 9000}}}
	c2.VLANs = []VLAN{{Parent: "enp3s0", ID: 7, Addressing: Addressing{Mode: ModeDHCP}}}
	c2.DNS = []string{"10.0.0.1"}
	c2.Normalize()
	f := Render(c2)
	back := Import("nas", *f[InterfacesPath], *f[ResolvPath], ports)
	back.Normalize()
	if a, b := mustJSON(t, c2), mustJSON(t, back); a != b {
		t.Fatalf("round trip differs:\nwant %s\ngot  %s", a, b)
	}
	// DHCP's own resolv.conf isn't treated as a choice.
	if c := Import("nas", installer, "domain lan\nnameserver 192.168.1.1\n", ports); len(c.DNS) != 0 {
		t.Errorf("dhcp dns imported as chosen: %v", c.DNS)
	}
}

func newManager(t *testing.T) (*Manager, *sysexec.Fake, string) {
	t.Helper()
	root := t.TempDir()
	fake := &sysexec.Fake{}
	fake.OnPrefix("ifdown ", sysexec.Result{})
	fake.OnPrefix("ifup ", sysexec.Result{})
	fake.OnPrefix("ifquery ", sysexec.Result{})
	fake.OnPrefix("hostname ", sysexec.Result{})
	fake.OnPrefix("ip -j", sysexec.Result{Stdout: []byte("[]")})
	m := &Manager{Runner: fake, Root: root, Ports: func() []string { return ports }}
	// What the installer left behind.
	mustWrite(t, filepath.Join(root, InterfacesPath), "auto lo\niface lo inet loopback\n\nallow-hotplug eno1\niface eno1 inet dhcp\n")
	mustWrite(t, filepath.Join(root, HostnamePath), "hardyos\n")
	mustWrite(t, filepath.Join(root, ResolvPath), "nameserver 192.168.1.1\n")
	return m, fake, root
}

func TestApplyConfirm(t *testing.T) {
	m, fake, root := newManager(t)
	ctx := context.Background()

	cur := m.Current()
	if cur.Hostname != "hardyos" || cur.Interfaces[0].Mode != ModeDHCP {
		t.Fatalf("imported = %+v", cur)
	}

	c := cur
	c.Hostname = "nas"
	c.Interfaces[0].Addressing = Addressing{Mode: ModeStatic, Address: "192.168.1.20/24", Gateway: "192.168.1.1"}
	c.DNS = []string{"192.168.1.1"}
	info, err := m.Apply(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Addresses) != 1 || info.Addresses[0] != "192.168.1.20" {
		t.Fatalf("addresses = %v", info.Addresses)
	}
	lines := strings.Join(fake.Lines(), "\n")
	// ifdown must run before the new file replaces the old definitions.
	if i, j := strings.Index(lines, "ifdown -a"), strings.Index(lines, "ifup -a --exclude=lo"); i < 0 || j < 0 || i > j {
		t.Fatalf("order of commands:\n%s", lines)
	}
	if got := read(t, root, InterfacesPath); !strings.Contains(got, "address 192.168.1.20/24") {
		t.Fatalf("interfaces not written:\n%s", got)
	}
	if read(t, root, HostnamePath) != "nas\n" {
		t.Fatal("hostname not written")
	}

	// A second change waits for the first.
	if _, err := m.Apply(ctx, c); !errors.Is(err, ErrPending) {
		t.Fatalf("second apply err = %v", err)
	}
	st, err := m.Status(ctx)
	if err != nil || st.Pending == nil || st.Config.Hostname != "nas" {
		t.Fatalf("status = %+v, %v", st, err)
	}

	if _, err := m.Confirm(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(); !errors.Is(err, ErrNothingPending) {
		t.Fatalf("second confirm err = %v", err)
	}
	// Saved settings win over the files from now on.
	if got := m.Current(); got.Interfaces[0].Mode != ModeStatic || got.Hostname != "nas" {
		t.Fatalf("saved = %+v", got)
	}
}

func TestApplyRevertsByItself(t *testing.T) {
	m, fake, root := newManager(t)
	m.RevertAfter = 50 * time.Millisecond
	orig := read(t, root, InterfacesPath)
	origResolv := read(t, root, ResolvPath)

	c := m.Current()
	c.Interfaces[0].Addressing = Addressing{Mode: ModeStatic, Address: "10.9.9.9/24"}
	c.DNS = []string{"10.9.9.1"}
	if _, err := m.Apply(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, DNSHookPath)); err != nil {
		t.Fatal("dns hook not written")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(m.stateDir(), "pending.json")); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not reverted in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if read(t, root, InterfacesPath) != orig || read(t, root, ResolvPath) != origResolv {
		t.Fatal("old files not restored")
	}
	if _, err := os.Stat(filepath.Join(root, DNSHookPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dns hook should be gone again")
	}
	if !strings.Contains(strings.Join(fake.Lines(), "\n"), "hostname hardyos") {
		t.Fatal("hostname not restored")
	}
	st, _ := m.Status(context.Background())
	if st.LastRevert == nil || !strings.Contains(st.LastRevert.Reason, "confirmed in time") {
		t.Fatalf("last revert = %+v", st.LastRevert)
	}
}

func TestApplyFailureRestores(t *testing.T) {
	m, fake, root := newManager(t)
	orig := read(t, root, InterfacesPath)
	fake.OnResult("ifup -a --exclude=lo", sysexec.Result{ExitCode: 1, Stderr: []byte("RTNETLINK answers: File exists")})
	c := m.Current()
	c.Interfaces[1].Mode = ModeDHCP
	if _, err := m.Apply(context.Background(), c); err == nil || !strings.Contains(err.Error(), "old ones are back") {
		t.Fatalf("err = %v", err)
	}
	if read(t, root, InterfacesPath) != orig {
		t.Fatal("old file not restored")
	}
	if st, _ := m.Status(context.Background()); st.Pending != nil {
		t.Fatal("nothing should be pending")
	}
}

func TestOnStartRevertsExpired(t *testing.T) {
	m, _, root := newManager(t)
	orig := read(t, root, InterfacesPath)
	now := time.Now()
	m.Now = func() time.Time { return now }
	c := m.Current()
	c.Interfaces[1].Mode = ModeDHCP
	if _, err := m.Apply(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	m.stopTimer()
	// The server restarted after the deadline.
	m2 := &Manager{Runner: m.Runner, Root: root, Ports: m.Ports, Now: func() time.Time { return now.Add(time.Hour) }}
	m2.OnStart(context.Background())
	if read(t, root, InterfacesPath) != orig {
		t.Fatal("expired change not undone at start")
	}
}

func TestTime(t *testing.T) {
	m, fake, root := newManager(t)
	fake.OnPrefix("systemctl ", sysexec.Result{})
	mustWrite(t, filepath.Join(root, "usr/share/zoneinfo/America/Denver"), "TZif")
	ctx := context.Background()
	if err := m.SetTime(ctx, TimeConfig{Timezone: "Mars/Olympus", NTP: true}); err == nil {
		t.Fatal("unknown zone accepted")
	}
	if err := m.SetTime(ctx, TimeConfig{Timezone: "../../etc/passwd", NTP: true}); err == nil {
		t.Fatal("path accepted as zone")
	}
	if err := m.SetTime(ctx, TimeConfig{Timezone: "America/Denver", NTP: true, NTPServers: []string{"time.cloudflare.com", "192.168.1.1"}}); err != nil {
		t.Fatal(err)
	}
	if target, _ := os.Readlink(filepath.Join(root, "etc/localtime")); target != "/usr/share/zoneinfo/America/Denver" {
		t.Fatalf("localtime -> %q", target)
	}
	conf := read(t, root, ChronyPath)
	if !strings.Contains(conf, "server time.cloudflare.com iburst\nserver 192.168.1.1 iburst\n") || strings.Contains(conf, "pool ") {
		t.Fatalf("chrony.conf:\n%s", conf)
	}
	if err := m.SetClock(ctx, time.Now()); err == nil {
		t.Fatal("manual clock allowed with NTP on")
	}
	if err := m.SetTime(ctx, TimeConfig{Timezone: "America/Denver", NTP: false}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(fake.Lines(), "\n"), "systemctl disable --now chrony.service") {
		t.Fatal("chrony not stopped")
	}
	if !strings.Contains(read(t, root, ChronyPath), "pool 2.debian.pool.ntp.org") {
		t.Fatal("empty server list should use the Debian pool")
	}
	if err := m.SetTime(ctx, TimeConfig{Timezone: "America/Denver", NTPServers: []string{"bad host!"}}); err == nil {
		t.Fatal("bad server accepted")
	}
}

func mustWrite(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, root, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestForgedPendingIsNotTrusted(t *testing.T) {
	m, _, root := newManager(t)
	ctx := context.Background()
	c := m.Current()
	c.Interfaces[1].Mode = ModeDHCP
	if _, err := m.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	m.stopTimer()
	// hardyd (which owns the directory) edits the undo record to make root
	// write somewhere else, and to run a command from the interfaces file.
	var p Pending
	b, _ := os.ReadFile(m.pendingFile())
	_ = json.Unmarshal(b, &p)
	evil := "root:x:0:0::/root:/bin/sh\n"
	cmd := "auto lo\niface lo inet loopback\n\tpre-up touch /tmp/pwned\n"
	p.Previous["etc/shadow"] = &evil
	p.Previous[InterfacesPath] = &cmd
	b, _ = json.Marshal(p)
	_ = os.WriteFile(m.pendingFile(), b, 0o644)

	// The whitelist alone keeps root to the network files.
	if err := m.Revert(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/shadow")); err == nil {
		t.Fatal("undo wrote a file outside the network files")
	}

	// With ownership checks on (as in hardyd-priv), a file root didn't
	// write isn't used at all.
	if os.Geteuid() != 0 {
		t.Skip("ownership checks need root")
	}
	if _, err := m.Apply(ctx, c); err != nil {
		t.Fatal(err)
	}
	m.stopTimer()
	b, _ = os.ReadFile(m.pendingFile())
	_ = json.Unmarshal(b, &p)
	p.Previous[InterfacesPath] = &cmd
	b, _ = json.Marshal(p)
	_ = os.WriteFile(m.pendingFile(), b, 0o644)
	_ = os.Chown(m.pendingFile(), 1000, 1000)
	rootfile.Enforce = true
	defer func() { rootfile.Enforce = false }()
	if err := m.Revert(ctx, "test"); err == nil {
		t.Fatal("a pending file owned by hardyd was trusted")
	}
	if got, _ := os.ReadFile(filepath.Join(root, InterfacesPath)); strings.Contains(string(got), "pwned") {
		t.Fatal("forged interfaces written")
	}
}
