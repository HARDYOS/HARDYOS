package domain

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestNormalizeDomain(t *testing.T) {
	good := map[string]string{
		"Home.HardyNetworks.net.": "home.hardynetworks.net",
		" ad.example.org ":        "ad.example.org",
		"corp.hardy-family.co.uk": "corp.hardy-family.co.uk",
	}
	for in, want := range good {
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "home", "hardy.local", "a..b", "-x.net", "x_y.net", "1.2.3.4", strings.Repeat("a", 61) + ".net"} {
		if _, err := NormalizeDomain(bad); err == nil {
			t.Errorf("NormalizeDomain(%q) accepted", bad)
		}
	}
}

func TestNetBIOS(t *testing.T) {
	if got := DefaultNetBIOS("home.hardynetworks.net"); got != "HOME" {
		t.Errorf("DefaultNetBIOS = %q", got)
	}
	if got := DefaultNetBIOS("averyveryverylongname.net"); got != "AVERYVERYVERYLO" {
		t.Errorf("DefaultNetBIOS long = %q", got)
	}
	if _, err := NormalizeNetBIOS("dc1"); err == nil {
		t.Error("NetBIOS name equal to the DC's name accepted")
	}
	if n, err := NormalizeNetBIOS("hardy"); err != nil || n != "HARDY" {
		t.Errorf("NormalizeNetBIOS(hardy) = %q, %v", n, err)
	}
	for _, bad := range []string{"", "HAS SPACE", "SIXTEENCHARSXXXX", "TRAILING-"} {
		if _, err := NormalizeNetBIOS(bad); err == nil {
			t.Errorf("NormalizeNetBIOS(%q) accepted", bad)
		}
	}
}

func TestCheckPassword(t *testing.T) {
	if err := CheckPassword("Sup3r-Secret", "alice"); err != nil {
		t.Errorf("good password refused: %v", err)
	}
	for _, bad := range []string{"short1A", "alllowercase", "ALLUPPER123", "Alice-2026!x"} {
		if err := CheckPassword(bad, "alice"); err == nil {
			t.Errorf("CheckPassword(%q) accepted", bad)
		}
	}
	var ve *ValidationError
	if !errors.As(CheckPassword("x", ""), &ve) {
		t.Error("password errors should be ValidationErrors")
	}
}

func TestNames(t *testing.T) {
	for _, ok := range []string{"alice", "Bob.Smith", "kid_2", "a"} {
		if CheckUsername(ok) != nil {
			t.Errorf("username %q refused", ok)
		}
	}
	for _, bad := range []string{"", "has space", "toolongusernamexxxxxx", "dot.", "-dash", "semi;colon"} {
		if CheckUsername(bad) == nil {
			t.Errorf("username %q accepted", bad)
		}
	}
	for _, ok := range []string{"Family", "Media Editors", "k", "kids_2"} {
		if CheckGroupName(ok) != nil {
			t.Errorf("group %q refused", ok)
		}
	}
	for _, bad := range []string{"", " lead", "trail ", "a/b", "x*"} {
		if CheckGroupName(bad) == nil {
			t.Errorf("group %q accepted", bad)
		}
	}
}

func TestCandidatesAndBroadcast(t *testing.T) {
	host := netip.MustParsePrefix("192.168.1.105/24")
	c := candidates(host, "192.168.1.1")
	if len(c) == 0 || c[0].String() != "192.168.1.20" {
		t.Fatalf("candidates = %v", c)
	}
	for _, a := range c {
		if a == host.Addr() || a.String() == "192.168.1.1" || !host.Masked().Contains(a) {
			t.Errorf("bad candidate %v", a)
		}
	}
	if !isBroadcast(netip.MustParsePrefix("192.168.1.255/24")) || isBroadcast(netip.MustParsePrefix("192.168.1.254/24")) {
		t.Error("isBroadcast /24 wrong")
	}
	if !isBroadcast(netip.MustParsePrefix("10.0.3.255/22")) || isBroadcast(netip.MustParsePrefix("10.0.2.255/22")) {
		t.Error("isBroadcast /22 wrong")
	}
	if mac := randomMAC(); mac[1] != '2' && mac[1] != '6' && mac[1] != 'a' && mac[1] != 'e' {
		t.Errorf("MAC %s isn't locally administered unicast", mac)
	}
}

const ipAddrJSON = `[{"ifname":"lo","flags":["LOOPBACK","UP"],"addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"}]},
{"ifname":"enp1s0","flags":["BROADCAST","UP","LOWER_UP"],"addr_info":[{"family":"inet","local":"192.168.1.105","prefixlen":24,"scope":"global"}]}]`

func testManager(t *testing.T, f *sysexec.Fake) *Manager {
	t.Helper()
	root := t.TempDir()
	for _, p := range []string{"usr/sbin/samba", "usr/lib/hardyos/hardyos-dc-admin", "etc/resolv.conf"} {
		_ = os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755)
		_ = os.WriteFile(filepath.Join(root, p), nil, 0o755)
	}
	_ = os.WriteFile(filepath.Join(root, "etc/resolv.conf"), []byte("nameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver 9.9.9.9\n"), 0o644)
	f.On("ip -j -4 addr show", ipAddrJSON)
	f.On("ip -j -4 route show default", `[{"dst":"default","gateway":"192.168.1.1","dev":"enp1s0"}]`)
	f.OnResult("findmnt -n -o FSTYPE,SOURCE --target /", sysexec.Result{Stdout: []byte("ext4 /dev/sda1\n")})
	return &Manager{Runner: f, Root: root}
}

func TestPlanFillsDefaults(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	f.OnPrefix("arping -D -q -c 2 -w 3 -I enp1s0 192.168.1.20", sysexec.Result{})
	c, err := m.plan(context.Background(), ProvisionArgs{Domain: "Home.HardyNetworks.net", AdminPassword: "Sup3r-Secret!", Address: "192.168.1.20"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Realm != "HOME.HARDYNETWORKS.NET" || c.NetBIOS != "HOME" || c.Address != "192.168.1.20/24" ||
		c.Gateway != "192.168.1.1" || c.Parent != "enp1s0" || c.DCName != "dc1.home.hardynetworks.net" {
		t.Errorf("plan = %+v", c)
	}
	if strings.Join(c.Forwarders, ",") != "192.168.1.1,9.9.9.9" {
		t.Errorf("forwarders = %v (loopback must be skipped)", c.Forwarders)
	}

	// An address someone else has.
	f.OnPrefix("arping -D -q -c 2 -w 3 -I enp1s0 192.168.1.21", sysexec.Result{ExitCode: 1})
	_, err = m.plan(context.Background(), ProvisionArgs{Domain: "home.hardynetworks.net", AdminPassword: "Sup3r-Secret!", Address: "192.168.1.21"})
	if err == nil || !strings.Contains(err.Error(), "already using") {
		t.Errorf("taken address: %v", err)
	}
	for _, addr := range []string{"192.168.1.105", "10.0.0.5", "192.168.1.255", "nonsense"} {
		if _, err := m.plan(context.Background(), ProvisionArgs{Domain: "home.hardynetworks.net", AdminPassword: "Sup3r-Secret!", Address: addr}); err == nil {
			t.Errorf("address %s accepted", addr)
		}
	}
}

func TestSmbConf(t *testing.T) {
	m := &Manager{Root: t.TempDir()}
	c := &Config{Domain: "home.example.net", Realm: "HOME.EXAMPLE.NET", NetBIOS: "HOME", Forwarders: []string{"192.168.1.1", "9.9.9.9"}}
	if err := m.writeSmbConf(c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(m.dataPath("etc", "smb.conf"))
	s := string(b)
	for _, want := range []string{
		"netbios name = DC1", "realm = HOME.EXAMPLE.NET", "workgroup = HOME",
		"dns forwarder = 192.168.1.1 9.9.9.9", "private dir = /var/lib/hardyos-dc/private",
		"pid directory = /var/lib/hardyos-dc/run", "path = /var/lib/hardyos-dc/state/sysvol/home.example.net/scripts",
		"disable spoolss = yes",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("smb.conf lacks %q", want)
		}
	}
	if strings.Contains(s, "[printers]") || strings.Contains(s, "passwd program") {
		t.Error("smb.conf keeps Debian defaults it shouldn't")
	}
}

func TestSetupNetworkCreatesEverything(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	lastParent.name = ""
	c := &Config{Address: "192.168.1.20/24", Gateway: "192.168.1.1", Parent: "enp1s0", MAC: "02:11:22:33:44:55"}
	// Namespace and links don't exist yet.
	f.OnPrefix("ip -j -n hardyos-dc addr show dev hdc0", sysexec.Result{ExitCode: 1, Stderr: []byte("does not exist")})
	f.OnPrefix("ip -j -d addr show dev hdc-shim", sysexec.Result{ExitCode: 1, Stderr: []byte("does not exist")})
	f.OnPrefix("ip ", sysexec.Result{})
	f.OnPrefix("sysctl ", sysexec.Result{})
	if err := m.SetupNetwork(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(f.Lines(), "\n")
	for _, want := range []string{
		"ip netns add hardyos-dc",
		"ip link add hdc-new link enp1s0 address 02:11:22:33:44:55 type macvlan mode bridge",
		"ip link set hdc-new netns hardyos-dc",
		"ip -n hardyos-dc link set hdc-new name hdc0",
		"ip -n hardyos-dc addr replace 192.168.1.20/24 dev hdc0",
		"ip -n hardyos-dc route replace default via 192.168.1.1 dev hdc0",
		"ip link add hdc-shim link enp1s0 type macvlan mode bridge",
		"sysctl -q -w net.ipv4.conf.hdc-shim.arp_ignore=8",
		"ip addr add 192.168.1.105/32 dev hdc-shim",
		"ip route replace 192.168.1.20/32 dev hdc-shim src 192.168.1.105",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestSetupNetworkLeavesWorkingSetupAlone(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	lastParent.name = "enp1s0"
	_ = os.MkdirAll(filepath.Join(m.Root, "run/netns"), 0o755)
	_ = os.WriteFile(filepath.Join(m.Root, "run/netns", Namespace), nil, 0o644)
	c := &Config{Address: "192.168.1.20/24", Gateway: "192.168.1.1", Parent: "enp1s0", MAC: "02:11:22:33:44:55"}
	f.On("ip -j -n hardyos-dc addr show dev hdc0", `[{"ifname":"hdc0","flags":["UP"],"addr_info":[{"family":"inet","local":"192.168.1.20","prefixlen":24,"scope":"global"}]}]`)
	f.On("ip -j -d addr show dev hdc-shim", `[{"ifname":"hdc-shim","link":"enp1s0","flags":["UP"],"addr_info":[{"family":"inet","local":"192.168.1.105","prefixlen":32,"scope":"global"}]}]`)
	f.OnPrefix("ip ", sysexec.Result{})
	f.OnPrefix("sysctl ", sysexec.Result{})
	if err := m.SetupNetwork(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	for _, l := range f.Lines() {
		if strings.Contains(l, "netns add") || strings.Contains(l, "link add") || strings.Contains(l, "addr flush") {
			t.Errorf("rebuilt a working setup: %s", l)
		}
	}
}

func TestAdminErrors(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	_ = os.MkdirAll(m.dataPath(), 0o700)
	if err := m.save(&Config{Domain: "home.example.net", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	tool := AdminTool + " " + m.SmbConf()
	f.OnResult(tool+" user.create", sysexec.Result{ExitCode: 1, Stderr: []byte("a user called bob already exists\n")})
	_, err := m.CreateUser(context.Background(), NewUser{Username: "bob", Password: "B0b-Passw0rd!"})
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Msg != "a user called bob already exists" {
		t.Errorf("CreateUser error = %v", err)
	}
	// Passwords travel on stdin, never on the command line.
	calls := f.Calls
	last := calls[len(calls)-1]
	if strings.Contains(last.Line, "B0b-Passw0rd!") || !strings.Contains(string(last.Stdin), "B0b-Passw0rd!") {
		t.Errorf("password handling: line %q stdin %q", last.Line, last.Stdin)
	}
	f.OnResult(tool+" users", sysexec.Result{ExitCode: 2, Stderr: []byte("Traceback\n  File x\nldb.LdbError: broken")})
	if _, err := m.Users(context.Background()); err == nil || errors.As(err, &ve) || !strings.Contains(err.Error(), "ldb.LdbError: broken") {
		t.Errorf("Users error = %v", err)
	}
	f.On(tool+" groups", `{"groups":[{"name":"Family","description":"","members":null,"builtin":false}]}`)
	g, err := m.Groups(context.Background())
	if err != nil || len(g) != 1 || g[0].Members == nil {
		t.Errorf("Groups = %+v, %v", g, err)
	}
}

func TestNotProvisioned(t *testing.T) {
	m := testManager(t, &sysexec.Fake{})
	if _, err := m.Users(context.Background()); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("Users without a domain: %v", err)
	}
	st, err := m.Status(context.Background())
	if err != nil || st.Provisioned || !st.Available {
		t.Errorf("Status = %+v, %v", st, err)
	}
	if err := m.Destroy(context.Background(), "x"); !errors.Is(err, ErrNotProvisioned) {
		t.Errorf("Destroy without a domain: %v", err)
	}
}

func TestDestroyNeedsTheName(t *testing.T) {
	f := &sysexec.Fake{}
	m := testManager(t, f)
	_ = os.MkdirAll(m.dataPath("private"), 0o700)
	_ = m.save(&Config{Domain: "home.example.net", Enabled: true})
	if err := m.Destroy(context.Background(), "home.example.org"); err == nil {
		t.Fatal("Destroy with the wrong name went ahead")
	}
	if _, err := os.Stat(m.dataPath("private")); err != nil {
		t.Fatal("data removed after a refused Destroy")
	}
	f.OnPrefix("systemctl stop", sysexec.Result{})
	f.OnPrefix("ip link del", sysexec.Result{})
	if err := m.Destroy(context.Background(), "HOME.example.net"); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(m.dataPath()); len(entries) != 0 {
		t.Errorf("left behind: %v", entries)
	}
}
