package domain

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/sftp"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/smb"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// TestSFTPMemberIntegration creates a domain (like TestSMBMemberIntegration),
// joins the host's Samba to it, turns SFTP on for a shared folder and signs
// in over SFTP as domain users through a private sshd (port 2222, its own
// config including HardyOS's drop-in, in a mount namespace of its own where
// /etc/pam.d/sshd is HardyOS's edit of a copy of the system's). It checks: the views
// (a folder by its rules, read-only binds for read access), writing as the
// person, a wrong password and an account with nothing to see refused, no
// TTY, no port forwarding, a command forced into SFTP. It needs root, the
// packages of TestSMBMemberIntegration plus openssh-server, and it adds the
// hardyos-sftp group to the machine (removed afterwards if it made it):
//
//	sudo HARDYOS_DC_INTEGRATION=1 go test ./internal/domain -run TestSFTPMemberIntegration -v
func TestSFTPMemberIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_DC_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_DC_INTEGRATION=1 on a throwaway machine")
	}
	sshd := os.Getenv("HARDYOS_SSHD")
	if sshd == "" {
		sshd = "/usr/sbin/sshd"
	}
	if _, err := os.Stat(sshd); err != nil {
		t.Fatal("openssh-server isn't installed (or set HARDYOS_SSHD)")
	}
	ctx := context.Background()
	units := &unitless{units: map[string]*unit{}}
	t.Cleanup(units.stopAll)
	dc := &Manager{Runner: units, Root: "/"}
	units.add(dc)
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

	tmp, err := os.MkdirTemp("", "hardyos-sftp-it-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	_ = os.Chmod(tmp, 0o755)
	sub := func(p ...string) string { return filepath.Join(append([]string{tmp}, p...)...) }
	for _, d := range []string{"data", "run", "log", "avahi", "shares/docs", "sshd_config.d"} {
		if err := os.MkdirAll(sub(d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(sub("resolv.conf"), []byte(fmt.Sprintf("nameserver %s\nsearch %s\n", c.IP(), dom)), 0o644)
	_ = os.WriteFile(sub("krb5.conf"), nil, 0o644)
	_ = os.WriteFile(sub("shares/docs/readme.txt"), []byte("hello\n"), 0o644)
	// The views must sit under root-owned folders nobody else can write (sshd's chroot rule): not /tmp.
	views, err := os.MkdirTemp("/run", "hardyos-sftp-it-")
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(views, 0o755)
	t.Cleanup(func() {
		// The views' root is a mount of its own once SFTP was on; the binds
		// in it are gone by now (SFTP off), and it's private, so this
		// reaches nothing else.
		if l, err := (sftp.SysMounter{}).List(views); err != nil || len(l) > 0 {
			t.Logf("views still hold mounts, left alone: %+v %v", l, err)
			return
		}
		_ = unix.Unmount(views, unix.MNT_DETACH|unix.UMOUNT_NOFOLLOW)
		if ok, _ := (sftp.SysMounter{}).IsMount(views); !ok {
			_ = os.RemoveAll(views)
		}
	})
	// The test's sshd sees a copy of the system's /etc/pam.d over the real
	// one, in a mount namespace of its own; HardyOS edits the copy's sshd
	// file, and the session check reads the system's real common-session
	// (with its pam_systemd, if any). winbind is taken out of the copy's
	// common-* stacks, as on HardyOS's image (diverted pam-auth-update
	// profile), so domain passwords work only through HardyOS's block.
	pamDir := sub("pam.d")
	_ = os.Mkdir(pamDir, 0o755)
	pamPath := filepath.Join(pamDir, "sshd")
	ents, err := os.ReadDir("/etc/pam.d")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/etc/pam.d", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(e.Name(), "common-") {
			var kept []string
			for _, l := range strings.Split(string(b), "\n") {
				if strings.Contains(l, "pam_winbind") {
					// Keep the jumps right: pam_unix's success=N skipped it.
					l = strings.Replace(l, "pam_winbind.so", "pam_deny.so", 1)
				}
				kept = append(kept, l)
			}
			b = []byte(strings.Join(kept, "\n"))
		}
		_ = os.WriteFile(filepath.Join(pamDir, e.Name()), b, 0o644)
	}
	if _, err := os.Stat(pamPath); err != nil {
		t.Fatal("/etc/pam.d/sshd is missing (install openssh-server)")
	}
	key := sub("hostkey")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	mainConf := sub("sshd_config")
	_ = os.WriteFile(mainConf, []byte(fmt.Sprintf("Include %s/*.conf\nListenAddress 127.0.0.1\nPort 2222\nUsePAM yes\nPidFile none\nKbdInteractiveAuthentication no\nSubsystem sftp internal-sftp\n", sub("sshd_config.d"))), 0o644)
	hadGroup := exec.Command("getent", "group", sftp.Group).Run() == nil

	on := shares.DefaultServices()
	on.SFTP = true
	docs := shares.Share{ID: "docs", Name: "Family Docs", Dataset: "test/shares/docs", Path: sub("shares/docs"), Mounted: true,
		Access: []shares.Rule{
			{Kind: shares.KindEveryone, Level: shares.LevelRead},
			{Kind: shares.KindUser, Name: `HOME\alice`, Level: shares.LevelWrite},
			{Kind: shares.KindUser, Name: `HOME\carol`, Level: shares.LevelNone},
		}, Services: on}
	// Real shares are verified ZFS mounts (shares.OpenRoot checks the
	// device); this folder stands in for one on the test's file system.
	var dst unix.Stat_t
	if err := unix.Stat(docs.Path, &dst); err != nil {
		t.Fatal(err)
	}
	docs.RootDev = uint64(dst.Dev)
	src := &listShares{l: []shares.Share{docs}}
	conf := sub("smb.conf")
	mr := &memberRunner{conf: conf, resolv: sub("resolv.conf"), krb5: sub("krb5.conf"), log: sub("log"), procs: map[string]*memberProc{}}
	t.Cleanup(mr.stopAll)
	sr := &sshdRunner{inner: mr, sshd: sshd, conf: mainConf, key: key, pam: pamDir, log: sub("log", "sshd.out")}
	t.Cleanup(sr.stop)
	sm := &sftp.Manager{Runner: sr, Root: views, DropIn: sub("sshd_config.d", "hardyos-sftp.conf"), PAMPath: pamPath, CommonAuth: sub("common-auth")}
	m := &smb.Manager{
		Runner: mr, Shares: src, ServerName: "NASIT", Port: 4455, NoDataset: true,
		DataDir: sub("data"), ConfPath: conf, Krb5Conf: sub("krb5.conf"), NSSwitch: sub("nsswitch.conf"), AvahiService: sub("avahi", "hardyos-smb.service"),
		Dirs: &smb.Dirs{Private: sub("data/private"), State: sub("data/state"), Cache: sub("data/cache"), Lock: sub("data/lock"),
			PID: sub("run"), NCALRPC: sub("run/ncalrpc"), Log: sub("log"), Keytab: sub("data/krb5.keytab")},
		LocalDomain: func() *smb.Domain {
			c, _ := dc.Load()
			return &smb.Domain{Domain: c.Domain, Realm: c.Realm, NetBIOS: c.NetBIOS, DCs: c.DNSServers()}
		},
		SFTP:       sm,
		LookupUser: idLookup,
	}
	t.Cleanup(func() {
		_, _ = sm.Apply(ctx, false, nil, nil)
		m.Wait()
		// The failed-password tallies this test left (pam_faillock's default dir).
		for u := range users {
			_ = exec.Command("faillock", "--user", `HOME\`+u, "--reset").Run()
		}
		if !hadGroup {
			_ = exec.Command("groupdel", sftp.Group).Run()
		}
		if t.Failed() {
			b, _ := os.ReadFile(sub("log", "sshd.out"))
			t.Logf("sshd:\n%s", b)
		}
	})
	if _, err := m.Join(ctx, smb.JoinArgs{AdminPassword: pw}); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if err := sr.start(); err != nil {
		t.Fatal(err)
	}
	yes := true
	var st *smb.Status
	// winbind may need a moment for fresh accounts.
	for i := 0; i < 10; i++ {
		if st, err = m.SetSettings(ctx, smb.SettingsArgs{SFTPEnabled: &yes}); err == nil && st.SFTP != nil && st.SFTP.Users >= 2 {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if err != nil || st.SFTP == nil || st.SFTP.Problem != "" {
		t.Fatalf("turning SFTP on: %v %+v", err, st)
	}
	t.Logf("SFTP: %+v", *st.SFTP)

	dial := func(user, pass string) (*ssh.Client, error) {
		return ssh.Dial("tcp", "127.0.0.1:2222", &ssh.ClientConfig{User: `HOME\` + user, Auth: []ssh.AuthMethod{ssh.Password(pass)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 15 * time.Second})
	}
	alice, err := dial("alice", users["alice"])
	if err != nil {
		t.Fatalf("alice over SFTP: %v", err)
	}
	defer alice.Close()
	s, err := newSFTPClient(alice)
	if err != nil {
		t.Fatal(err)
	}
	if names, err := s.list("/"); err != nil || !has(names, "Family Docs") {
		t.Errorf("alice's view: %v %v", names, err)
	}
	if names, err := s.list("/Family Docs"); err != nil || !has(names, "readme.txt") {
		t.Errorf("Family Docs: %v %v", names, err)
	}
	if err := s.write("/Family Docs/from-sftp.txt", []byte("written over sftp\n")); err != nil {
		t.Errorf("alice writing: %v", err)
	}
	if fi, err := os.Stat(sub("shares/docs/from-sftp.txt")); err != nil {
		t.Error(err)
	} else if uid := fi.Sys().(*syscall.Stat_t).Uid; uid < sftp.DomainUIDLow {
		t.Errorf("alice's file belongs to %d", uid)
	}
	// No TTY, no tunnels, no commands.
	if sess, err := alice.NewSession(); err == nil {
		if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
			t.Error("alice got a TTY")
		}
		out, _ := sess.CombinedOutput("id")
		if strings.Contains(string(out), "uid=") {
			t.Errorf("alice ran a command: %s", out)
		}
	}
	if conn, err := alice.Dial("tcp", "127.0.0.1:2222"); err == nil {
		conn.Close()
		t.Error("alice forwarded a port")
	}

	bob, err := dial("bob", users["bob"])
	if err != nil {
		t.Fatalf("bob over SFTP: %v", err)
	}
	defer bob.Close()
	bs, err := newSFTPClient(bob)
	if err != nil {
		t.Fatal(err)
	}
	if err := bs.write("/Family Docs/bob.txt", []byte("x")); err == nil {
		t.Error("bob wrote to a folder he may only read")
	}
	if _, err := dial("alice", "Wrong-Passw0rd"); err == nil {
		t.Error("a wrong password got in")
	}
	if _, err := dial("carol", users["carol"]); err == nil {
		t.Error("carol, with nothing to see, got in")
	}
	// Domain Admins get no view unless File Services allows them (alice,
	// bob: the two with something to see).
	if st.SFTP.Users != 2 {
		t.Errorf("accounts with a view: %d", st.SFTP.Users)
	}
	if _, err := dial("administrator", pw); err == nil {
		t.Error("the domain administrator got in with administrators off")
	}

	// Too many wrong passwords lock the name for a while (pam_faillock),
	// even with the right one, without asking the DC.
	for i := 0; i < sftp.FaillockDeny; i++ {
		if c, err := dial("bob", fmt.Sprintf("Wrong-%d-Passw0rd", i)); err == nil {
			c.Close()
			t.Fatal("a wrong password got in")
		}
	}
	if out, _ := exec.Command("faillock", "--user", `HOME\bob`).CombinedOutput(); strings.Count(string(out), "RHOST") < sftp.FaillockDeny {
		pamNow, _ := exec.Command("nsenter", "-t", strconv.Itoa(sr.cmd.Process.Pid), "-m", "cat", "/etc/pam.d/sshd").CombinedOutput()
		t.Errorf("wrong passwords not counted; faillock:\n%s\nsshd's PAM file:\n%s", out, pamNow)
	}
	if c, err := dial("bob", users["bob"]); err == nil {
		c.Close()
		out, _ := exec.Command("faillock", "--user", `HOME\bob`).CombinedOutput()
		t.Errorf("bob got in after too many wrong passwords; faillock:\n%s", out)
	}
	_ = exec.Command("faillock", "--user", `HOME\bob`, "--reset").Run()
	if c, err := dial("bob", users["bob"]); err != nil {
		t.Errorf("bob after the lock was reset: %v", err)
	} else {
		c.Close()
	}

	// Something that overrides HardyOS's settings (an earlier drop-in):
	// the effective-config check fails, PAM stops taking domain passwords
	// and File Services says why; fixed, it works again.
	override := sub("sshd_config.d", "00-it-override.conf")
	_ = os.WriteFile(override, []byte("Match User *\\*\n\tForceCommand /bin/true\nMatch all\n"), 0o644)
	st, err = m.SetSettings(ctx, smb.SettingsArgs{SFTPEnabled: &yes})
	if err != nil || st.SFTP == nil || !strings.Contains(st.SFTP.Problem, "forcecommand") {
		t.Errorf("an override wasn't noticed: %v %+v", err, st.SFTP)
	}
	if b, _ := os.ReadFile(pamPath); strings.Contains(string(b), "pam_winbind") {
		t.Error("PAM still takes domain passwords with sshd's settings overridden")
	}
	sr.reload()
	if c, err := dial("alice", users["alice"]); err == nil {
		c.Close()
		t.Error("alice got in with sshd's settings overridden")
	}
	_ = os.Remove(override)
	if st, err = m.SetSettings(ctx, smb.SettingsArgs{SFTPEnabled: &yes}); err != nil || st.SFTP == nil || st.SFTP.Problem != "" {
		t.Errorf("after removing the override: %v %+v", err, st.SFTP)
	}
	sr.reload()
	if c, err := dial("alice", users["alice"]); err != nil {
		t.Errorf("alice after the fix: %v", err)
	} else {
		c.Close()
	}

	// Off: domain accounts are refused.
	no := false
	if _, err := m.SetSettings(ctx, smb.SettingsArgs{SFTPEnabled: &no}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if _, err := dial("alice", users["alice"]); err == nil {
		t.Error("alice got in with SFTP off")
	}
	if l, _ := (sftp.SysMounter{}).List(views); len(l) != 0 {
		t.Errorf("mounts left: %+v", l)
	}
}

func has(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// idLookup is the NSS helper's answer, from id(1).
func idLookup(ctx context.Context, name string) (*fileworker.Identity, error) {
	out, err := exec.CommandContext(ctx, "id", name).Output()
	if err != nil {
		return nil, err
	}
	num := func(flag string) []int {
		b, _ := exec.CommandContext(ctx, "id", flag, name).Output()
		var l []int
		for _, f := range strings.Fields(string(b)) {
			if n, err := strconv.Atoi(f); err == nil {
				l = append(l, n)
			}
		}
		return l
	}
	_ = out
	u, g := num("-u"), num("-g")
	if len(u) != 1 || len(g) != 1 {
		return nil, errors.New("no ids")
	}
	return &fileworker.Identity{UID: u[0], GID: g[0], Groups: num("-G")}, nil
}

// sshdRunner runs the test's own sshd for ssh.service and checks its
// config instead of the system's; everything else goes to inner.
type sshdRunner struct {
	inner                     sysexec.Runner
	sshd, conf, key, pam, log string
	cmd                       *exec.Cmd
	done                      chan struct{}
}

// start runs sshd in a mount namespace of its own (a private copy of this
// one, with a copy of /etc/pam.d holding HardyOS's sshd file). The views' binds are
// private, so they never propagate into it: the namespace is a snapshot,
// and reload starts sshd again in a fresh one.
func (r *sshdRunner) start() error {
	if _, err := os.Stat("/etc/pam.d/sshd"); err != nil {
		return errors.New("/etc/pam.d/sshd is missing (install openssh-server)")
	}
	script := `mount --bind "$1" /etc/pam.d && shift && exec "$@"`
	r.cmd = exec.Command("unshare", "-m", "--propagation", "private", "sh", "-c", script, "sh", r.pam, r.sshd, "-D", "-e", "-f", r.conf, "-h", r.key)
	f, _ := os.OpenFile(r.log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	r.cmd.Stdout, r.cmd.Stderr = f, f
	r.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := r.cmd.Start(); err != nil {
		return err
	}
	r.done = make(chan struct{})
	go func() { _ = r.cmd.Wait(); close(r.done) }()
	time.Sleep(time.Second)
	return nil
}

func (r *sshdRunner) running() bool {
	if r.cmd == nil {
		return false
	}
	select {
	case <-r.done:
		return false
	default:
		return true
	}
}

func (r *sshdRunner) stop() {
	if r.running() {
		_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-r.done:
		case <-time.After(10 * time.Second):
			_ = syscall.Kill(-r.cmd.Process.Pid, syscall.SIGKILL)
		}
	}
}

// reload starts the test's sshd again: it reads its files again and sees
// the views as they are now.
func (r *sshdRunner) reload() {
	if r.running() {
		r.stop()
		_ = r.start()
	}
}

func (r *sshdRunner) Run(ctx context.Context, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	switch line {
	case "sshd -t":
		return sysexec.Exec{}.Run(ctx, stdin, r.sshd, "-t", "-f", r.conf, "-h", r.key)
	case "systemctl is-active --quiet " + sftp.SSHUnit:
		if r.running() {
			return sysexec.Result{}, nil
		}
		return sysexec.Result{ExitCode: 3}, nil
	case "systemctl reload " + sftp.SSHUnit:
		r.reload()
		return sysexec.Result{}, nil
	}
	if name == "sshd" && len(args) > 0 && args[0] == "-T" {
		return sysexec.Exec{}.Run(ctx, stdin, r.sshd, append([]string{"-f", r.conf, "-h", r.key}, args...)...)
	}
	return r.inner.Run(ctx, stdin, name, args...)
}

// sftpClient speaks just enough SFTP (version 3) to list and write.
type sftpClient struct {
	w  io.WriteCloser
	r  io.Reader
	id uint32
}

const (
	fxpInit, fxpVersion, fxpOpen, fxpClose, fxpWrite = 1, 2, 3, 4, 6
	fxpOpendir, fxpReaddir                           = 11, 12
	fxpStatus, fxpHandle, fxpName                    = 101, 102, 104
)

func newSFTPClient(c *ssh.Client) (*sftpClient, error) {
	sess, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	w, _ := sess.StdinPipe()
	r, _ := sess.StdoutPipe()
	if err := sess.RequestSubsystem("sftp"); err != nil {
		return nil, err
	}
	s := &sftpClient{w: w, r: r}
	if err := s.send(fxpInit, u32(3)); err != nil {
		return nil, err
	}
	if t, _, err := s.recv(); err != nil || t != fxpVersion {
		return nil, fmt.Errorf("sftp version: %d %v", t, err)
	}
	return s, nil
}

func u32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func u64(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
func str(s []byte) []byte { return append(u32(uint32(len(s))), s...) }

func (s *sftpClient) send(t byte, payload ...[]byte) error {
	var b bytes.Buffer
	b.WriteByte(t)
	for _, p := range payload {
		b.Write(p)
	}
	_, err := s.w.Write(append(u32(uint32(b.Len())), b.Bytes()...))
	return err
}

func (s *sftpClient) recv() (byte, []byte, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(s.r, h); err != nil {
		return 0, nil, err
	}
	b := make([]byte, binary.BigEndian.Uint32(h))
	if _, err := io.ReadFull(s.r, b); err != nil {
		return 0, nil, err
	}
	return b[0], b[1:], nil
}

// call sends a request with a fresh id and returns the reply (id stripped).
func (s *sftpClient) call(t byte, payload ...[]byte) (byte, []byte, error) {
	s.id++
	if err := s.send(t, append([][]byte{u32(s.id)}, payload...)...); err != nil {
		return 0, nil, err
	}
	rt, b, err := s.recv()
	if err != nil || len(b) < 4 {
		return 0, nil, fmt.Errorf("sftp reply: %v", err)
	}
	return rt, b[4:], nil
}

func statusErr(t byte, b []byte) error {
	if t != fxpStatus || len(b) < 4 {
		return fmt.Errorf("unexpected reply %d", t)
	}
	if code := binary.BigEndian.Uint32(b); code != 0 {
		return fmt.Errorf("sftp status %d", code)
	}
	return nil
}

func readStr(b []byte) ([]byte, []byte) {
	n := binary.BigEndian.Uint32(b)
	return b[4 : 4+n], b[4+n:]
}

func skipAttrs(b []byte) []byte {
	flags := binary.BigEndian.Uint32(b)
	b = b[4:]
	if flags&1 != 0 {
		b = b[8:]
	}
	if flags&2 != 0 {
		b = b[8:]
	}
	if flags&4 != 0 {
		b = b[4:]
	}
	if flags&8 != 0 {
		b = b[8:]
	}
	if flags&0x80000000 != 0 {
		n := binary.BigEndian.Uint32(b)
		b = b[4:]
		for i := uint32(0); i < n; i++ {
			_, b = readStr(b)
			_, b = readStr(b)
		}
	}
	return b
}

func (s *sftpClient) list(dir string) ([]string, error) {
	t, b, err := s.call(fxpOpendir, str([]byte(dir)))
	if err != nil {
		return nil, err
	}
	if t != fxpHandle {
		return nil, statusErr(t, b)
	}
	h, _ := readStr(b)
	var names []string
	for {
		t, b, err := s.call(fxpReaddir, str(h))
		if err != nil {
			return nil, err
		}
		if t == fxpStatus {
			break
		}
		n := binary.BigEndian.Uint32(b)
		b = b[4:]
		for i := uint32(0); i < n; i++ {
			var name []byte
			name, b = readStr(b)
			_, b = readStr(b)
			b = skipAttrs(b)
			if s := string(name); s != "." && s != ".." {
				names = append(names, s)
			}
		}
	}
	_, _, _ = s.call(fxpClose, str(h))
	return names, nil
}

func (s *sftpClient) write(p string, data []byte) error {
	t, b, err := s.call(fxpOpen, str([]byte(p)), u32(0x02|0x08|0x10), u32(0))
	if err != nil {
		return err
	}
	if t != fxpHandle {
		return statusErr(t, b)
	}
	h, _ := readStr(b)
	t, b, err = s.call(fxpWrite, str(h), u64(0), str(data))
	if err != nil {
		return err
	}
	werr := statusErr(t, b)
	t, b, _ = s.call(fxpClose, str(h))
	if werr != nil {
		return werr
	}
	return statusErr(t, b)
}
