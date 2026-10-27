package domain

import (
	"context"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/smb"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// TestSMBMemberIntegration creates a domain on this machine (like
// TestDCIntegration), joins the host's own Samba to it as the file server,
// shares two folders (plain folders stand in for datasets) and checks with
// smbclient that domain accounts get what the folders' access rules say:
// read, write, none and guest, the recycle bin and Previous Versions. It
// runs the host's smbd and winbindd from a temporary folder (port 4455),
// each in a private mount namespace where /etc/resolv.conf and
// /etc/krb5.conf point at the test domain, and stops them afterwards. It
// needs root, samba, winbind, smbclient, and winbind in nsswitch.conf's
// passwd and group lines:
//
//	sudo HARDYOS_DC_INTEGRATION=1 go test ./internal/domain -run TestSMBMemberIntegration -v
func TestSMBMemberIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_DC_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_DC_INTEGRATION=1 on a throwaway machine")
	}
	if b, _ := os.ReadFile("/etc/nsswitch.conf"); !strings.Contains(string(b), "winbind") {
		t.Fatal("add winbind to the passwd and group lines of /etc/nsswitch.conf (libnss-winbind)")
	}
	ctx := context.Background()
	units := &unitless{units: map[string]*unit{}}
	t.Cleanup(units.stopAll)
	dc := &Manager{Runner: units, Root: "/"}
	units.add(dc)
	if !dc.Available() {
		t.Fatal("samba or hardyos-dc-admin isn't installed")
	}
	if c, _ := dc.Load(); c != nil {
		t.Fatalf("a domain already exists in %s (%s)", dc.Dir(), c.Domain)
	}
	t.Cleanup(func() {
		units.stop(dc.service())
		dc.TeardownNetwork(ctx)
		_ = dc.removeData(ctx)
	})
	addr, gw := os.Getenv("HARDYOS_DC_TEST_ADDRESS"), os.Getenv("HARDYOS_DC_TEST_GATEWAY")
	if addr == "" {
		sug, err := dc.Suggest(ctx)
		if err != nil || sug.Address == "" {
			t.Fatalf("no free address for the DC: %+v %v", sug, err)
		}
		addr = sug.Address
	}
	const pw = "Ci-Admin-Passw0rd!"
	const dom = "home.hardyos-ci.net"
	c, err := dc.Provision(ctx, ProvisionArgs{Domain: dom, AdminPassword: pw, Address: addr, Gateway: gw, Forwarders: []string{"9.9.9.9"}})
	if err != nil {
		t.Fatal(err)
	}
	waitResponding(t, dc)
	users := map[string]string{"alice": "Al1ce-Passw0rd!", "bob": "B0b-Passw0rd!x", "carol": "Car0l-Passw0rd!"}
	for u, p := range users {
		if _, err := dc.CreateUser(ctx, NewUser{Username: u, Password: p}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := dc.CreateGroup(ctx, NewGroup{Name: "Family", Members: []string{"bob"}}); err != nil {
		t.Fatal(err)
	}

	// ---- the member server's world ----------------------------------------
	tmp, err := os.MkdirTemp("", "hardyos-smb-it-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	_ = os.Chmod(tmp, 0o755) // domain users must reach the shared folders
	sub := func(p ...string) string { return filepath.Join(append([]string{tmp}, p...)...) }
	for _, d := range []string{"data", "run", "log", "avahi", "shares/docs", "shares/guest"} {
		if err := os.MkdirAll(sub(d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(sub("resolv.conf"), []byte(fmt.Sprintf("nameserver %s\nsearch %s\n", c.IP(), dom)), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(sub("krb5.conf"), nil, 0o644)
	// A snapshot as ZFS shows it, for Previous Versions.
	snap := sub("shares/docs/.zfs/snapshot/hardyos-auto-daily_2026-10-25-0000")
	_ = os.MkdirAll(snap, 0o755)
	_ = os.WriteFile(filepath.Join(snap, "readme.txt"), []byte("old\n"), 0o644)
	_ = os.WriteFile(sub("shares/docs/readme.txt"), []byte("new\n"), 0o644)
	_ = os.WriteFile(sub("shares/guest/hello.txt"), []byte("hi\n"), 0o644)

	sv := shares.DefaultServices()
	docs := shares.Share{ID: "docs", Name: "Family Docs", Dataset: "test/shares/docs", Path: sub("shares/docs"), Mounted: true, Recycle: true,
		Access: []shares.Rule{
			{Kind: shares.KindEveryone, Level: shares.LevelRead},
			{Kind: shares.KindUser, Name: `HOME\alice`, Level: shares.LevelWrite},
			{Kind: shares.KindUser, Name: `HOME\carol`, Level: shares.LevelNone},
		}, Services: sv}
	guest := shares.Share{ID: "guest", Name: "Guest Box", Dataset: "test/shares/guest", Path: sub("shares/guest"), Mounted: true, Guest: true,
		Access: []shares.Rule{{Kind: shares.KindGroup, Name: `HOME\Family`, Level: shares.LevelWrite}}, Services: sv}
	// Real shares are verified ZFS mounts (shares.OpenRoot checks the
	// device); these folders stand in for them on the test's file system.
	for _, sh := range []*shares.Share{&docs, &guest} {
		var st unix.Stat_t
		if err := unix.Stat(sh.Path, &st); err != nil {
			t.Fatal(err)
		}
		sh.RootDev = uint64(st.Dev)
	}
	src := &listShares{l: []shares.Share{docs, guest}}

	conf := sub("smb.conf")
	mr := &memberRunner{conf: conf, resolv: sub("resolv.conf"), krb5: sub("krb5.conf"), log: sub("log"), procs: map[string]*memberProc{}}
	t.Cleanup(mr.stopAll)
	m := &smb.Manager{
		Runner: mr, Shares: src, ServerName: "NASIT", Port: 4455, NoDataset: true,
		DataDir: sub("data"), ConfPath: conf, Krb5Conf: sub("krb5.conf"), NSSwitch: sub("nsswitch.conf"), AvahiService: sub("avahi", "hardyos-smb.service"),
		Dirs: &smb.Dirs{Private: sub("data/private"), State: sub("data/state"), Cache: sub("data/cache"), Lock: sub("data/lock"),
			PID: sub("run"), NCALRPC: sub("run/ncalrpc"), Log: sub("log"), Keytab: sub("data/krb5.keytab")},
		LocalDomain: func() *smb.Domain {
			c, _ := dc.Load()
			return &smb.Domain{Domain: c.Domain, Realm: c.Realm, NetBIOS: c.NetBIOS, DCs: c.DNSServers()}
		},
	}
	t.Cleanup(func() {
		m.Wait()
		if out, err := exec.Command("ls", "-la", sub("log")).CombinedOutput(); err == nil && t.Failed() {
			t.Logf("member logs:\n%s", out)
			b, _ := exec.Command("sh", "-c", "tail -40 "+sub("log")+"/log.*").CombinedOutput()
			t.Logf("%s", b)
		}
	})

	if _, err := m.Join(ctx, smb.JoinArgs{AdminPassword: "Wrong-Passw0rd"}); err == nil || !strings.Contains(err.Error(), "isn't right") {
		t.Fatalf("join with a wrong password: %v", err)
	}
	start := time.Now()
	st, err := m.Join(ctx, smb.JoinArgs{AdminPassword: pw})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("joined %s as %s in %s", st.Domain.Domain, st.ServerName, time.Since(start).Round(time.Second))
	m.Wait()
	if !st.Joined || !st.Running || !st.Winbind {
		t.Fatalf("status after joining: %+v", st)
	}
	if out, err := exec.Command("getent", "passwd", `HOME\alice`).CombinedOutput(); err != nil || !strings.Contains(string(out), ":10") {
		t.Fatalf("alice has no Linux ID: %v %s", err, out)
	}

	// ---- who may do what --------------------------------------------------
	type try struct {
		share, user, pass, cmd string
		ok                     bool
	}
	run := func(x try) (string, bool) {
		args := []string{"-p", "4455", "//127.0.0.1/" + x.share, "-c", x.cmd}
		if x.user == "" {
			args = append(args, "-N")
		} else {
			args = append(args, "-U", `HOME\`+x.user+"%"+x.pass)
		}
		out, err := exec.Command("smbclient", args...).CombinedOutput()
		return string(out), err == nil && !strings.Contains(string(out), "NT_STATUS_")
	}
	check := func(x try) {
		t.Helper()
		var out string
		var ok bool
		// winbind may need a moment for a fresh account.
		for i := 0; i < 5; i++ {
			if out, ok = run(x); ok == x.ok {
				return
			}
			time.Sleep(2 * time.Second)
		}
		t.Errorf("%s as %q: %q ok=%v, want %v:\n%s", x.share, x.user, x.cmd, ok, x.ok, out)
	}
	upload := sub("upload.txt")
	_ = os.WriteFile(upload, []byte("from smbclient\n"), 0o644)
	put := func(name string) string { return "put " + upload + " " + name }
	check(try{"Family Docs", "alice", users["alice"], put("alice.txt"), true})
	check(try{"Family Docs", "bob", users["bob"], "ls", true})
	check(try{"Family Docs", "bob", users["bob"], put("bob.txt"), false})
	check(try{"Family Docs", "carol", users["carol"], "ls", false})
	check(try{"Family Docs", "Administrator", pw, put("admin.txt"), true})
	check(try{"Family Docs", "", "", "ls", false})
	check(try{"Guest Box", "", "", "get hello.txt " + sub("hello.copy"), true})
	check(try{"Guest Box", "", "", put("guest.txt"), false})
	check(try{"Guest Box", "bob", users["bob"], put("bob.txt"), true})
	check(try{"Guest Box", "alice", users["alice"], put("alice.txt"), false}) // Everyone isn't on this one: alice reads as a guest at most
	if fi, err := os.Stat(sub("shares/docs/alice.txt")); err != nil {
		t.Error(err)
	} else if uid := fi.Sys().(*syscall.Stat_t).Uid; uid < 100000 {
		t.Errorf("alice's file belongs to %d", uid)
	}
	// Deleting goes to the recycle bin.
	check(try{"Family Docs", "alice", users["alice"], "del alice.txt", true})
	if _, err := os.Stat(sub("shares/docs/.recycle/home.alice/alice.txt")); err != nil {
		matches, _ := filepath.Glob(sub("shares/docs/.recycle/*/*"))
		t.Errorf("not in the recycle bin: %v (found %v)", err, matches)
	}
	// Previous Versions lists the snapshot.
	if out, _ := run(try{"Family Docs", "alice", users["alice"], "allinfo readme.txt", true}); !strings.Contains(out, "@GMT-2026.10.25-00.00.00") {
		t.Errorf("no previous version of readme.txt:\n%s", out)
	}

	t.Log("read, write, none, guest, recycle bin and Previous Versions checked")

	// ---- rules change -----------------------------------------------------
	src.set(1, func(s *shares.Share) {
		s.Access = []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelWrite}}
	})
	src.set(0, func(s *shares.Share) {
		s.Access = append(s.Access, shares.Rule{Kind: shares.KindGroup, Name: `HOME\Family`, Level: shares.LevelWrite})
	})
	if _, err := m.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	check(try{"Family Docs", "bob", users["bob"], put("bob2.txt"), true})
	check(try{"Guest Box", "alice", users["alice"], put("alice.txt"), true})

	t.Log("changed rules applied")

	// ---- leave ------------------------------------------------------------
	if st, err := m.Leave(ctx, smb.LeaveArgs{Confirm: true, AdminPassword: pw}); err != nil {
		t.Fatal(err)
	} else if st.Joined || st.Running {
		t.Errorf("after leaving: %+v", st)
	}
	if _, ok := run(try{"Family Docs", "alice", users["alice"], "ls", true}); ok {
		t.Error("still serving after leaving")
	}
}

type listShares struct {
	mu sync.Mutex
	l  []shares.Share
}

func (s *listShares) List(context.Context) ([]shares.Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]shares.Share(nil), s.l...), nil
}

func (s *listShares) set(i int, fn func(*shares.Share)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.l[i])
}

// memberRunner runs the member server's smbd and winbindd from the test's
// config and answers systemctl for their units; net runs where
// resolv.conf and krb5.conf point at the test domain. Everything else
// runs as is.
type memberRunner struct {
	conf, resolv, krb5, log string
	mu                      sync.Mutex
	procs                   map[string]*memberProc
}

type memberProc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (r *memberRunner) wrap(name string, args ...string) []string {
	script := fmt.Sprintf(`mount --bind %s /etc/resolv.conf && mount --bind %s /etc/krb5.conf && exec "$@"`, r.resolv, r.krb5)
	return append([]string{"unshare", "-m", "--propagation", "private", "sh", "-c", script, "sh", name}, args...)
}

func (r *memberRunner) running(unit string) bool {
	p := r.procs[unit]
	if p == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (r *memberRunner) start(unit string) error {
	if r.running(unit) {
		return nil
	}
	bin := map[string]string{smb.SmbdUnit: "smbd", smb.WinbindUnit: "winbindd"}[unit]
	argv := r.wrap(bin, "-F", "--no-process-group", "-s", r.conf)
	cmd := exec.Command(argv[0], argv[1:]...)
	logf, _ := os.Create(filepath.Join(r.log, bin+".out"))
	cmd.Stdout, cmd.Stderr = logf, logf
	// Its own process group: smbd signals its whole group when it stops
	// (systemd gives the real units their own).
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	p := &memberProc{cmd: cmd, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.done) }()
	r.procs[unit] = p
	time.Sleep(2 * time.Second)
	return nil
}

func (r *memberRunner) stop(unit string) {
	p := r.procs[unit]
	if p == nil {
		return
	}
	if r.running(unit) {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(15 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.done
		}
	}
	delete(r.procs, unit)
	// Their helpers (smbd's children, samba-dcerpcd) use the same config
	// file, which only this test has.
	bin := map[string]string{smb.SmbdUnit: "smbd", smb.WinbindUnit: "winbindd"}[unit]
	procs, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, pp := range procs {
		b, _ := os.ReadFile(pp)
		cmdline := string(b)
		if strings.Contains(cmdline, r.conf) && (strings.Contains(cmdline, bin) || (unit == smb.SmbdUnit && strings.Contains(cmdline, "samba-dcerpcd"))) {
			var pid int
			if _, err := fmt.Sscanf(strings.Split(pp, "/")[2], "%d", &pid); err == nil && pid != os.Getpid() {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}
}

func (r *memberRunner) stopAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range []string{smb.SmbdUnit, smb.WinbindUnit} {
		r.stop(u)
	}
}

func (r *memberRunner) systemctl(args []string) (sysexec.Result, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	verb := args[0]
	var units []string
	for _, a := range args[1:] {
		if a == smb.SmbdUnit || a == smb.WinbindUnit {
			units = append(units, a)
		}
	}
	if len(units) == 0 {
		return sysexec.Result{}, false
	}
	for _, u := range units {
		switch verb {
		case "is-active":
			if !r.running(u) {
				return sysexec.Result{ExitCode: 3}, true
			}
		case "start":
			if err := r.start(u); err != nil {
				return sysexec.Result{ExitCode: 1, Stderr: []byte(err.Error())}, true
			}
		case "restart":
			r.stop(u)
			if err := r.start(u); err != nil {
				return sysexec.Result{ExitCode: 1, Stderr: []byte(err.Error())}, true
			}
		case "reload":
			if p := r.procs[u]; p != nil && r.running(u) {
				_ = p.cmd.Process.Signal(syscall.SIGHUP)
			}
		case "stop", "disable":
			if verb == "stop" || contains(args, "--now") {
				r.stop(u)
			}
		}
	}
	return sysexec.Result{}, true
}

func (r *memberRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	return r.RunEnv(ctx, nil, stdin, name, args...)
}

func (r *memberRunner) RunEnv(ctx context.Context, env []string, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	if name == "systemctl" && len(args) > 0 {
		if res, ok := r.systemctl(args); ok {
			return res, nil
		}
	}
	if name == "net" {
		argv := r.wrap(name, args...)
		name, args = argv[0], argv[1:]
	}
	if name == "smbcontrol" {
		args = append(args, "-s", r.conf)
	}
	return sysexec.Exec{}.RunEnv(ctx, env, stdin, name, args...)
}
