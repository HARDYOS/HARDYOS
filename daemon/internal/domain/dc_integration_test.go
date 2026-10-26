package domain

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// TestDCIntegration runs two real Samba AD domain controllers on this
// machine's LAN port, each in its own namespace like on two HardyOS
// servers: create, manage users, join a second DC, sign in through it alone,
// leave, back up and restore, and take over from a dead DC. It changes the
// machine (/var/lib/hardyos-dc*, namespaces, macvlans), so it only runs as
// root on a throwaway machine with samba-ad-dc, iputils-arping, dnsutils and
// smbclient installed and hardyos-dc-admin at /usr/lib/hardyos:
//
//	sudo HARDYOS_DC_INTEGRATION=1 go test ./internal/domain -run TestDCIntegration -v
//
// HARDYOS_DC_TEST_ADDRESS, HARDYOS_DC_TEST_ADDRESS2 and HARDYOS_DC_TEST_GATEWAY
// place the DCs (CI uses a dummy interface: cloud networks answer ARP for
// every address, so nothing looks free). Samba runs the way
// hardyos-dc.service runs it, without systemd.
func TestDCIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_DC_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_DC_INTEGRATION=1 on a throwaway machine")
	}
	ctx := context.Background()
	units := &unitless{units: map[string]*unit{}}
	t.Cleanup(units.stopAll)
	a := &Manager{Runner: units, Root: "/"}
	b := &Manager{Runner: units, Root: "/", DataDir: "/var/lib/hardyos-dc2", Namespace: "hardyos-dc2",
		Shim: "hdc-shim2", ShimAddr: "169.254.250.2", Service: "hardyos-dc2.service"}
	units.add(a)
	units.add(b)
	if !a.Available() {
		t.Fatal("samba or hardyos-dc-admin isn't installed")
	}
	for _, m := range []*Manager{a, b} {
		if c, _ := m.Load(); c != nil {
			t.Fatalf("a domain already exists in %s (%s)", m.Dir(), c.Domain)
		}
	}
	t.Cleanup(func() {
		for _, m := range []*Manager{a, b} {
			units.stop(m.service())
			m.TeardownNetwork(ctx)
			_ = m.removeData(ctx)
		}
	})

	addr1, addr2, gw := os.Getenv("HARDYOS_DC_TEST_ADDRESS"), os.Getenv("HARDYOS_DC_TEST_ADDRESS2"), os.Getenv("HARDYOS_DC_TEST_GATEWAY")
	if addr1 == "" {
		sug, err := a.Suggest(ctx)
		if err != nil || sug.Address == "" {
			t.Fatalf("no free address for the DC: %+v %v", sug, err)
		}
		addr1 = sug.Address
		p := netip.MustParsePrefix(addr1)
		addr2 = netip.PrefixFrom(p.Addr().Next(), p.Bits()).String()
	}
	const pw = "Ci-Admin-Passw0rd!"
	const dom = "home.hardyos-ci.net"

	// ---- the first DC -------------------------------------------------
	start := time.Now()
	c1, err := a.Provision(ctx, ProvisionArgs{Domain: dom, AdminPassword: pw, Address: addr1, Gateway: gw, Forwarders: []string{"9.9.9.9"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("dc1 at %s in %s", c1.Address, time.Since(start).Round(time.Second))
	waitResponding(t, a)
	// Still answering once its ARP entry for the NAS is gone.
	_ = exec.Command("ip", "-n", a.ns(), "neigh", "flush", "all").Run()
	_ = exec.Command("ip", "neigh", "flush", "dev", a.shim()).Run()
	if st, _ := a.Status(ctx); !st.Responding {
		t.Fatalf("dc1 stopped answering after its ARP cache was cleared: %+v", st)
	}
	smbOK(t, c1.IP(), "HOME", "Administrator", pw)
	if _, err := a.CreateUser(ctx, NewUser{Username: "alice", GivenName: "Alice", Surname: "Hardy", Password: "Al1ce-Passw0rd!"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateGroup(ctx, NewGroup{Name: "Family", Members: []string{"alice"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.SetUserEnabled(ctx, "alice", false); err != nil {
		t.Fatal(err)
	}
	if smbErr(c1.IP(), "HOME", "alice", "Al1ce-Passw0rd!") == nil {
		t.Error("a turned-off account could still sign in")
	}
	if _, err := a.SetUserEnabled(ctx, "alice", true); err != nil {
		t.Fatal(err)
	}
	signInIntegration(t, a, c1, pw)
	if _, err := a.SetForwarders(ctx, []string{"1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	waitResponding(t, a)

	// ---- a second DC joins ---------------------------------------------
	if _, err := b.Join(ctx, JoinArgs{Domain: dom, Existing: c1.IP(), AdminPassword: "wrong-Passw0rd", Address: addr2, Gateway: gw}); err == nil ||
		!strings.Contains(err.Error(), "password isn't right") {
		t.Fatalf("join with a wrong password: %v", err)
	}
	start = time.Now()
	c2, err := b.Join(ctx, JoinArgs{Domain: dom, Existing: c1.IP(), AdminPassword: pw, Address: addr2, Gateway: gw})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s joined at %s in %s (short name %s)", c2.DCName, c2.Address, time.Since(start).Round(time.Second), c2.NetBIOS)
	if c2.Host != "dc2" || c2.NetBIOS != "HOME" {
		t.Errorf("joined as %+v", c2)
	}
	waitResponding(t, b)
	// Accounts came along.
	if !hasUser(t, b, "alice") {
		t.Fatal("alice isn't on dc2")
	}
	// A new account on dc1 reaches dc2 by itself.
	if _, err := a.CreateUser(ctx, NewUser{Username: "bob", Password: "B0b-Passw0rd!x"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	for !hasUser(t, b, "bob") {
		if time.Now().After(deadline) {
			for _, m := range []*Manager{a, b} {
				c := mustLoad(t, m)
				out, _ := exec.Command("ip", "netns", "exec", m.ns(), "samba-tool", "drs", "showrepl", c.DCName,
					"-U", "Administrator%"+pw, "-s", m.SmbConf()).CombinedOutput()
				t.Logf("---- %s showrepl:\n%s", c.DCName, out)
				logs, _ := exec.Command("sh", "-c", "grep -h -i -E 'repl|notify|WERR|NT_STATUS' "+m.Dir()+"/log/log.* | tail -25").CombinedOutput()
				t.Logf("---- %s log:\n%s", c.DCName, logs)
				rc, _ := os.ReadFile(m.dataPath("resolv.conf"))
				t.Logf("---- %s resolv.conf:\n%s", c.DCName, rc)
			}
			t.Fatal("bob never replicated to dc2")
		}
		time.Sleep(5 * time.Second)
	}
	// Both DCs learn about each other, and DNS lists both.
	refresh(t, a, 1)
	refresh(t, b, 1)
	if got := strings.Join(mustLoad(t, a).DNSServers(), ","); got != c1.IP()+","+c2.IP() {
		t.Errorf("dc1's DNS servers = %s", got)
	}
	// With dc1 off, dc2 alone signs people in.
	if _, err := a.SetEnabled(ctx, false); err != nil {
		t.Fatal(err)
	}
	smbOK(t, c2.IP(), "HOME", "bob", "B0b-Passw0rd!x")
	if _, err := a.SetEnabled(ctx, true); err != nil {
		t.Fatal(err)
	}
	waitResponding(t, a)
	if err := a.Destroy(ctx, dom); err == nil {
		t.Error("dc1 deleted a domain dc2 still serves")
	}

	// ---- dc2 leaves ------------------------------------------------------
	if err := b.Leave(ctx, pw); err != nil {
		t.Fatal(err)
	}
	if st, _ := b.Status(ctx); st.Provisioned {
		t.Error("dc2 still has the domain after leaving")
	}
	refresh(t, a, 0)

	// ---- backup and restore ----------------------------------------------
	cfg, archive, err := a.BackupFiles(ctx) // while it runs
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("domain backup: %d bytes", len(archive))
	if err := a.Destroy(ctx, dom); err != nil {
		t.Fatal(err)
	}
	note, err := a.RestoreFiles(ctx, cfg, archive)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(note)
	if err := a.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	waitResponding(t, a)
	smbOK(t, c1.IP(), "HOME", "alice", "Al1ce-Passw0rd!")
	if !hasUser(t, a, "bob") {
		t.Error("bob is missing after the restore")
	}
	// The recorded HardyOS Admins group (signInIntegration) came back with
	// its SID, so desktop administrators stay administrators.
	if rc := mustLoad(t, a); rc.AdminsGroupSID == "" {
		t.Error("the HardyOS Admins SID wasn't restored")
	} else if groups, err := a.Groups(ctx); err != nil {
		t.Error(err)
	} else if rec, _ := FindAdminsGroup(rc, groups); rec == nil {
		t.Errorf("no group has the recorded SID %s after the restore", rc.AdminsGroupSID)
	}
	// Restoring over an existing domain keeps the existing one.
	if note, err := a.RestoreFiles(ctx, cfg, archive); err != nil || !strings.Contains(note, "was kept") {
		t.Errorf("restore over a domain: %q %v", note, err)
	}

	// ---- dc1 dies; dc2 takes over ------------------------------------------
	c2, err = b.Join(ctx, JoinArgs{Domain: dom, Existing: c1.IP(), AdminPassword: pw, Address: addr2, Gateway: gw})
	if err != nil {
		t.Fatal(err)
	}
	waitResponding(t, b)
	refresh(t, b, 1)
	units.stop(a.service())
	a.TeardownNetwork(ctx)
	if err := b.RemoveDead(ctx, c1.DCName, c1.DCName); err != nil {
		t.Fatal(err)
	}
	if others := mustLoad(t, b).Others; len(others) != 0 {
		t.Errorf("dc2 still lists %v", others)
	}
	// dc2 holds every role now: it can add accounts.
	if _, err := b.CreateUser(ctx, NewUser{Username: "carol", Password: "Car0l-Passw0rd!"}); err != nil {
		t.Fatal(err)
	}
	smbOK(t, c2.IP(), "HOME", "carol", "Car0l-Passw0rd!")
	_ = a.removeData(ctx)
	if err := b.Destroy(ctx, dom); err != nil {
		t.Fatal(err)
	}
}

func mustLoad(t *testing.T, m *Manager) *Config {
	t.Helper()
	c, err := m.Load()
	if err != nil || c == nil {
		t.Fatalf("load %s: %v", m.Dir(), err)
	}
	return c
}

// refresh updates a DC's list of partners now instead of within 5 minutes,
// waiting until it lists want of them (DNS records replicate between DCs
// within a few minutes).
func refresh(t *testing.T, m *Manager, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Minute)
	for {
		m.mu.Lock()
		c, _ := m.Load()
		m.refreshOthers(context.Background(), c)
		n := len(c.Others)
		m.mu.Unlock()
		if n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s lists %d other DCs, want %d: %+v", m.Dir(), n, want, c.Others)
		}
		time.Sleep(5 * time.Second)
	}
}

func hasUser(t *testing.T, m *Manager, name string) bool {
	t.Helper()
	users, err := m.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Username == name {
			return true
		}
	}
	return false
}

func waitResponding(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var st *Status
	for time.Now().Before(deadline) {
		st, _ = m.Status(context.Background())
		if st != nil && st.Running && st.Responding {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("%s never answered: %+v", m.Dir(), st)
}

func smbErr(ip, dom, user, pw string) error {
	out, err := exec.Command("smbclient", "-L", "//"+ip, "-U", dom+`\`+user+"%"+pw).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "sysvol") {
		return fmt.Errorf("smbclient as %s at %s: %v: %s", user, ip, err, out)
	}
	return nil
}

func smbOK(t *testing.T, ip, dom, user, pw string) {
	t.Helper()
	var err error
	for i := 0; i < 15; i++ {
		if err = smbErr(ip, dom, user, pw); err == nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal(err)
}

// unitless runs each DC the way hardyos-dc.service does (its namespace,
// /run/samba bound to its run folder) and answers systemctl for those units.
type unitless struct {
	units map[string]*unit
}

type unit struct {
	m    *Manager
	cmd  *exec.Cmd
	done chan struct{}
}

func (u *unitless) add(m *Manager) { u.units[m.service()] = &unit{m: m} }

func (n *unit) running() bool {
	if n.cmd == nil {
		return false
	}
	select {
	case <-n.done:
		return false
	default:
		return true
	}
}

func (u *unitless) stop(name string) {
	n := u.units[name]
	if n == nil || !n.running() {
		return
	}
	_ = n.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-n.done:
	case <-time.After(20 * time.Second):
		_ = n.cmd.Process.Kill()
		<-n.done
	}
	n.cmd = nil
	// systemd stops a unit's whole cgroup; Samba's helpers (winbindd's
	// children, samba-dcerpcd) can outlive their parent otherwise, and keep
	// the namespace (and the DC's MAC address) alive.
	var nsStat syscall.Stat_t
	if err := syscall.Stat(filepath.Join("/run/netns", n.m.ns()), &nsStat); err == nil {
		procs, _ := filepath.Glob("/proc/[0-9]*/ns/net")
		for _, p := range procs {
			var st syscall.Stat_t
			if syscall.Stat(p, &st) == nil && st.Ino == nsStat.Ino && st.Dev == nsStat.Dev {
				var pid int
				if _, err := fmt.Sscanf(strings.Split(p, "/")[2], "%d", &pid); err == nil && pid != os.Getpid() {
					_ = syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		}
	}
	conf := filepath.Join(n.m.Dir(), "etc", "smb.conf")
	procs, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, p := range procs {
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), conf) {
			var pid int
			if _, err := fmt.Sscanf(strings.Split(p, "/")[2], "%d", &pid); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}
	time.Sleep(time.Second)
}

func (u *unitless) stopAll() {
	for name := range u.units {
		u.stop(name)
	}
}

func (u *unitless) start(name string) error {
	n := u.units[name]
	if n.running() {
		return nil
	}
	dir := n.m.Dir()
	// A private /run/samba per DC, as BindPaths= gives the real unit.
	script := fmt.Sprintf("mkdir -p /run/samba && mount --bind %s /run/samba && mount --bind %s /etc/resolv.conf && touch /etc/krb5.conf && mount --bind %s /etc/krb5.conf && exec samba --foreground --no-process-group -s %s",
		filepath.Join(dir, "run"), filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "krb5.conf"), filepath.Join(dir, "etc", "smb.conf"))
	n.cmd = exec.Command("ip", "netns", "exec", n.m.ns(), "unshare", "-m", "--propagation", "private", "sh", "-c", script)
	_ = os.MkdirAll(filepath.Join(dir, "log"), 0o750)
	log, _ := os.Create(filepath.Join(dir, "log", "foreground.log"))
	n.cmd.Stdout, n.cmd.Stderr = log, log
	if err := n.cmd.Start(); err != nil {
		return err
	}
	n.done = make(chan struct{})
	go func(c *exec.Cmd, done chan struct{}) { _ = c.Wait(); close(done) }(n.cmd, n.done)
	time.Sleep(3 * time.Second)
	return nil
}

func (u *unitless) Run(ctx context.Context, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	if (name == "systemctl" || name == "journalctl") && len(args) > 0 {
		svc := args[len(args)-1]
		if name == "journalctl" {
			svc = args[1]
		}
		if n := u.units[svc]; n != nil {
			switch {
			case name == "journalctl":
				b, _ := os.ReadFile(filepath.Join(n.m.Dir(), "log", "foreground.log"))
				return sysexec.Result{Stdout: b}, nil
			case args[0] == "is-active":
				if n.running() {
					return sysexec.Result{}, nil
				}
				return sysexec.Result{ExitCode: 3}, nil
			case args[0] == "stop":
				u.stop(svc)
				return sysexec.Result{}, nil
			case args[0] == "start":
				if err := u.start(svc); err != nil {
					return sysexec.Result{ExitCode: 1, Stderr: []byte(err.Error())}, nil
				}
				return sysexec.Result{}, nil
			case args[0] == "restart":
				u.stop(svc)
				if err := u.start(svc); err != nil {
					return sysexec.Result{ExitCode: 1, Stderr: []byte(err.Error())}, nil
				}
				return sysexec.Result{}, nil
			}
		}
	}
	return sysexec.Exec{}.Run(ctx, stdin, name, args...)
}

// TestDCRestoreIntegration backs up a running DC, deletes the domain and
// restores it, the way a reinstall would.
func TestDCRestoreIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_DC_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_DC_INTEGRATION=1 on a throwaway machine")
	}
	ctx := context.Background()
	units := &unitless{units: map[string]*unit{}}
	t.Cleanup(units.stopAll)
	a := &Manager{Runner: units, Root: "/"}
	units.add(a)
	t.Cleanup(func() {
		units.stop(a.service())
		a.TeardownNetwork(ctx)
		_ = a.removeData(ctx)
	})
	addr, gw := os.Getenv("HARDYOS_DC_TEST_ADDRESS"), os.Getenv("HARDYOS_DC_TEST_GATEWAY")
	if addr == "" {
		sug, err := a.Suggest(ctx)
		if err != nil || sug.Address == "" {
			t.Fatalf("no free address: %v", err)
		}
		addr = sug.Address
	}
	const pw = "Ci-Admin-Passw0rd!"
	c, err := a.Provision(ctx, ProvisionArgs{Domain: "home.hardyos-ci.net", AdminPassword: pw, Address: addr, Gateway: gw, Forwarders: []string{"9.9.9.9"}})
	if err != nil {
		t.Fatal(err)
	}
	waitResponding(t, a)
	if _, err := a.CreateUser(ctx, NewUser{Username: "alice", Password: "Al1ce-Passw0rd!"}); err != nil {
		t.Fatal(err)
	}
	cfg, archive, err := a.BackupFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Destroy(ctx, c.Domain); err != nil {
		t.Fatal(err)
	}
	if out, _ := exec.Command("ip", "-br", "link").CombinedOutput(); strings.Contains(string(out), c.MAC) {
		t.Logf("links after destroy:\n%s", out)
	}
	note, err := a.RestoreFiles(ctx, cfg, archive)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(note)
	if err := a.Ensure(ctx); err != nil {
		out, _ := exec.Command("sh", "-c", "ip -d link; ls -la /run/netns; ip netns list").CombinedOutput()
		t.Fatalf("%v\n%s", err, out)
	}
	waitResponding(t, a)
	smbOK(t, c.IP(), "HOME", "alice", "Al1ce-Passw0rd!")
	smbOK(t, c.IP(), "HOME", "Administrator", pw)
}
