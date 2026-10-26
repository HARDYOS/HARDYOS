package sftp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestRenderSSHD(t *testing.T) {
	on := RenderSSHD("/srv/hardyos/sftp", true)
	for _, want := range []string{
		"Match Group *\\*\n", "Match User *\\*,*@*\n", "\tAllowGroups hardyos-sftp\n",
		"\tChrootDirectory /srv/hardyos/sftp/%U\n", "\tForceCommand internal-sftp -d /\n",
		"\tDisableForwarding yes\n", "\tAllowTcpForwarding no\n", "\tPermitTTY no\n", "\tX11Forwarding no\n",
		"\tPermitTunnel no\n", "\tPubkeyAuthentication no\n", "\tAuthorizedKeysFile none\n", "\tAuthenticationMethods password\n",
	} {
		if strings.Count(on, want) < 1 {
			t.Errorf("drop-in lacks %q:\n%s", want, on)
		}
	}
	if !strings.HasSuffix(on, "Match all\n") {
		t.Errorf("the drop-in must end its Match blocks:\n%s", on)
	}
	// Both blocks carry every setting.
	blocks := strings.Split(on, "Match ")
	if len(blocks) != 4 || strings.Count(blocks[1], "\t") != strings.Count(blocks[2], "\t") {
		t.Errorf("blocks differ: %q", blocks)
	}
	// No quotes or escapes: sshd versions parse those differently in Match.
	if strings.ContainsAny(on, "\"'") || strings.Contains(on, `\\`) {
		t.Errorf("quoting in the drop-in:\n%s", on)
	}
	off := RenderSSHD("/srv/hardyos/sftp", false)
	if !strings.Contains(off, "\tDenyGroups *\n") || strings.Contains(off, "AllowGroups") || !strings.Contains(off, "DisableForwarding yes") {
		t.Errorf("off drop-in should refuse domain accounts:\n%s", off)
	}
}

// TestRealSSHD checks the drop-in with a real sshd when HARDYOS_SSHD names
// one (it needs its privilege separation user and /run/sshd, so it's not
// run by default): the main config includes the drop-in first, the way
// Debian's does, and a local account keeps its settings.
func TestRealSSHD(t *testing.T) {
	sshd := os.Getenv("HARDYOS_SSHD")
	if sshd == "" {
		t.Skip("set HARDYOS_SSHD to an sshd binary to check the drop-in with it")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "hostkey")
	if out, err := exec.Command(os.Getenv("HARDYOS_SSH_KEYGEN"), "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen (HARDYOS_SSH_KEYGEN): %v %s", err, out)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	main := fmt.Sprintf("Include %s/d/*.conf\nKbdInteractiveAuthentication no\nUsePAM yes\nX11Forwarding yes\nSubsystem sftp /usr/lib/openssh/sftp-server\n", dir)
	if err := os.WriteFile(filepath.Join(dir, "sshd_config"), []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, on := range []bool{true, false} {
		if err := os.WriteFile(filepath.Join(dir, "d", "hardyos-sftp.conf"), []byte(RenderSSHD(ViewsRoot, on)), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(sshd, "-t", "-f", filepath.Join(dir, "sshd_config"), "-h", key).CombinedOutput()
		if err != nil {
			t.Fatalf("sshd -t (on=%v): %v %s", on, err, out)
		}
		out, err = exec.Command(sshd, "-T", "-f", filepath.Join(dir, "sshd_config"), "-h", key, "-C", "user=root,host=x,addr=192.0.2.1").CombinedOutput()
		if err != nil {
			t.Fatalf("sshd -T: %v %s", err, out)
		}
		if !strings.Contains(string(out), "x11forwarding yes") || !strings.Contains(string(out), "forcecommand none") {
			t.Errorf("root's settings changed (on=%v):\n%s", on, out)
		}
	}
	// A domain account (HARDYOS_SSHD_DOMAIN_USER, known to NSS) is locked in.
	if u := os.Getenv("HARDYOS_SSHD_DOMAIN_USER"); u != "" {
		_ = os.WriteFile(filepath.Join(dir, "d", "hardyos-sftp.conf"), []byte(RenderSSHD(ViewsRoot, true)), 0o644)
		out, err := exec.Command(sshd, "-T", "-f", filepath.Join(dir, "sshd_config"), "-h", key, "-C", "user="+u+",host=x,addr=192.0.2.1").CombinedOutput()
		if err != nil {
			t.Fatalf("sshd -T: %v %s", err, out)
		}
		for _, want := range []string{"forcecommand internal-sftp -d /", "chrootdirectory /srv/hardyos/sftp/%U", "disableforwarding yes", "permittty no", "allowgroups hardyos-sftp", "pubkeyauthentication no", "x11forwarding no", "allowtcpforwarding no"} {
			if !strings.Contains(string(out), want) {
				t.Errorf("%s: missing %q", u, want)
			}
		}
	}
}

// debianPAM is Debian's /etc/pam.d/sshd (trimmed comments).
const debianPAM = `# PAM configuration for the Secure Shell service

# Standard Un*x authentication.
@include common-auth

# Disallow non-root logins when /etc/nologin exists.
account    required     pam_nologin.so

# Standard Un*x authorization.
@include common-account

session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
@include common-session
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv # [1]
session    required     pam_limits.so
session    required     pam_env.so # [1]
session    required     pam_env.so envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open

# Standard Un*x password updating.
@include common-password
`

func TestEditPAM(t *testing.T) {
	on, err := EditPAM(debianPAM, true)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(on, "\n")
	idx := func(s string) int {
		for i, l := range lines {
			if strings.TrimSpace(l) == s {
				return i
			}
		}
		return -1
	}
	ia, iacc := idx("@include common-auth"), idx("@include common-account")
	wantAuth := "auth\t[success=done default=die]\tpam_winbind.so"
	wantAcct := "account\t[success=done default=die]\tpam_winbind.so"
	if a := idx(wantAuth); a < 0 || a != ia-2 || lines[ia-3] != "auth\t[success=ignore default=1]\tpam_succeed_if.so quiet uid >= 100000 uid <= 999999" {
		t.Errorf("auth block not right before common-auth:\n%s", on)
	}
	if a := idx(wantAcct); a < 0 || a != iacc-2 {
		t.Errorf("account block not right before common-account:\n%s", on)
	}
	if strings.Count(on, "pam_winbind") != 2 {
		t.Errorf("winbind used %d times", strings.Count(on, "pam_winbind"))
	}
	// Idempotent, and off restores the original exactly.
	again, _ := EditPAM(on, true)
	if again != on {
		t.Errorf("second edit changed it:\n%s", again)
	}
	off, _ := EditPAM(on, false)
	if off != debianPAM {
		t.Errorf("off didn't restore the file:\n%s", off)
	}
	if _, err := EditPAM("auth required pam_unix.so\n", true); err != ErrPAMLayout {
		t.Errorf("a hand-made file: %v", err)
	}
	if !WinbindEverywhere("auth [success=2 default=ignore] pam_winbind.so krb5_auth\n") || WinbindEverywhere("# pam_winbind.so\nauth required pam_unix.so\n") {
		t.Error("WinbindEverywhere")
	}
}

func TestPlan(t *testing.T) {
	gids := map[string]int{`HOME\Family`: 101104, `HOME\Kids`: 101106}
	groupID := func(n string) (int, bool) { g, ok := gids[n]; return g, ok }
	folders := []Folder{
		{ID: "media", Name: "Media", Path: "/mnt/tank/shares/media", Dataset: "tank/shares/media",
			Rules: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelRead}, {Kind: shares.KindGroup, Name: `HOME\Family`, Level: shares.LevelWrite}}},
		{ID: "private", Name: "Private", Path: "/mnt/tank/shares/private", Dataset: "tank/shares/private",
			Rules: []shares.Rule{{Kind: shares.KindUser, Name: `HOME\alice`, Level: shares.LevelWrite}, {Kind: shares.KindGroup, Name: `HOME\Kids`, Level: shares.LevelNone}}},
		{ID: "home2", Name: "home", Path: "/mnt/tank/shares/home2", Dataset: "tank/shares/home2",
			Rules: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelRead}}},
		{ID: "bad", Name: "..", Path: "/mnt/tank/shares/bad", Rules: []shares.Rule{{Kind: shares.KindEveryone, Level: shares.LevelRead}}},
	}
	users := []User{
		{Principal: `HOME\alice`, UID: 101103, GID: 100513, Groups: []int{101104}, Home: "/mnt/tank/homes/home.alice", HomeDataset: "tank/homes/home.alice"},
		{Principal: `HOME\bob`, UID: 101107, GID: 100513, Groups: []int{101106}},
		{Principal: `HOME\root`, UID: 0, GID: 0},
		{Principal: `HOME\admin`, UID: 100500, GID: 100513, Admin: true},
		{Principal: `HOME\carol`, UID: 101108, GID: 100513, Groups: []int{101106, 101104}},
	}
	got := map[string]string{}
	for _, b := range Plan(users, folders, groupID) {
		ro := "rw"
		if b.ReadOnly {
			ro = "ro"
		}
		got[b.Rel()] = b.Share + " " + ro
	}
	want := map[string]string{
		"101103/Home":                 fileworker.HomeShare + " rw",
		"101103/Media":                "media rw",
		"101103/Private":              "private rw",
		"101103/home (shared folder)": "home2 ro",
		"101107/Media":                "media ro",
		"101107/home":                 "home2 ro",
		"100500/Media":                "media rw",
		"100500/Private":              "private rw",
		"100500/home":                 "home2 rw",
		"101108/Media":                "media rw",
		"101108/home":                 "home2 ro",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("plan:\n got %v\nwant %v", got, want)
	}
}

func TestParseMountinfo(t *testing.T) {
	info := `22 1 0:21 / / rw,relatime shared:1 - zfs rpool/ROOT/a rw
90 22 0:50 / /srv/hardyos/sftp rw,relatime - zfs rpool/ROOT/a rw
91 90 0:51 / /srv/hardyos/sftp/101103/Media rw,nosuid,nodev,noexec - zfs tank/shares/media rw
92 90 0:52 / /srv/hardyos/sftp/101103/Kids\040Films ro,nosuid,nodev,noexec - zfs tank/shares/kids rw
93 22 0:53 / /srv/hardyos/sftpx rw - tmpfs tmpfs rw
`
	l, err := parseMountinfo(strings.NewReader(info), "/srv/hardyos/sftp")
	if err != nil {
		t.Fatal(err)
	}
	want := []MountPoint{
		{Target: "/srv/hardyos/sftp/101103/Media", Source: "tank/shares/media"},
		{Target: "/srv/hardyos/sftp/101103/Kids Films", Source: "tank/shares/kids", ReadOnly: true},
	}
	if !reflect.DeepEqual(l, want) {
		t.Errorf("got %+v", l)
	}
	if ok, _ := isMountIn(strings.NewReader(info), "/srv/hardyos/sftp"); !ok {
		t.Error("root not seen as a mount")
	}
}

// fakeMounter keeps mounts in a map.
type fakeMounter struct {
	mu      sync.Mutex
	m       map[string]MountPoint
	private map[string]bool
	busy    map[string]bool
	ds      map[string]string // source path -> dataset
}

func (f *fakeMounter) List(dir string) ([]MountPoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []MountPoint
	for t, m := range f.m {
		if strings.HasPrefix(t, dir+"/") {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out, nil
}
func (f *fakeMounter) IsMount(dir string) (bool, error) { return f.private[dir], nil }
func (f *fakeMounter) MakePrivate(dir string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.private == nil {
		f.private = map[string]bool{}
	}
	f.private[dir] = true
	return nil
}
func (f *fakeMounter) Bind(src, dst string, ro bool) error {
	for _, p := range []string{src, dst} {
		fi, err := os.Lstat(p)
		if err != nil || !fi.IsDir() {
			return fmt.Errorf("%s isn't a folder", p)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string]MountPoint{}
	}
	f.m[dst] = MountPoint{Target: dst, Source: f.ds[src], ReadOnly: ro}
	return nil
}
func (f *fakeMounter) Unmount(dst string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.busy[dst] {
		return fmt.Errorf("%s is busy", dst)
	}
	delete(f.m, dst)
	return nil
}

func newTestManager(t *testing.T) (*Manager, *fakeMounter, *sysexec.Fake, string) {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"etc/ssh/sshd_config.d", "etc/pam.d", "srv/hardyos", "shares/media", "shares/kids", "homes/home.alice"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "etc/pam.d/sshd"), []byte(debianPAM), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etc/pam.d/common-auth"), []byte("auth [success=1 default=ignore] pam_unix.so nullok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fm := &fakeMounter{ds: map[string]string{
		filepath.Join(dir, "shares/media"): "tank/shares/media", filepath.Join(dir, "shares/kids"): "tank/shares/kids",
		filepath.Join(dir, "homes/home.alice"): "tank/homes/home.alice",
	}}
	run := &sysexec.Fake{}
	run.OnResult("getent group hardyos-sftp", sysexec.Result{ExitCode: 2})
	run.On("groupadd --system hardyos-sftp", "")
	run.OnPrefix("gpasswd -M ", sysexec.Result{})
	run.On("sshd -t", "")
	run.On("systemctl is-active --quiet ssh.service", "")
	run.On("systemctl reload ssh.service", "")
	m := &Manager{Runner: run, Mounter: fm, Root: filepath.Join(dir, "srv/hardyos/sftp"),
		DropIn: filepath.Join(dir, "etc/ssh/sshd_config.d/hardyos-sftp.conf"), PAMPath: filepath.Join(dir, "etc/pam.d/sshd"),
		CommonAuth: filepath.Join(dir, "etc/pam.d/common-auth"), NoChown: os.Geteuid() != 0}
	return m, fm, run, dir
}

func TestApply(t *testing.T) {
	m, fm, run, dir := newTestManager(t)
	ctx := context.Background()
	media, kids, home := filepath.Join(dir, "shares/media"), filepath.Join(dir, "shares/kids"), filepath.Join(dir, "homes/home.alice")
	users := []User{{Principal: `HOME\alice`, Name: `HOME\alice`, UID: 101103}, {Principal: `HOME\bob`, Name: `HOME\bob`, UID: 101107}, {Principal: `HOME\eve`, Name: `HOME\eve`, UID: 101109}}
	binds := []Bind{
		{UID: 101103, Name: "Home", Share: "~home", Source: home, Dataset: "tank/homes/home.alice"},
		{UID: 101103, Name: "Media", Share: "media", Source: media, Dataset: "tank/shares/media"},
		{UID: 101103, Name: "Kids Films", Share: "kids", Source: kids, Dataset: "tank/shares/kids", ReadOnly: true},
		{UID: 101107, Name: "Media", Share: "media", Source: media, Dataset: "tank/shares/media", ReadOnly: true},
		{UID: 0, Name: "Media", Source: media}, // never a view for root
	}
	st, err := m.Apply(ctx, true, users, binds)
	if err != nil {
		t.Fatal(err)
	}
	if st.Users != 2 || st.Folders != 4 || st.Problem != "" || !st.Running {
		t.Errorf("status %+v", st)
	}
	root := m.root()
	mounts, _ := fm.List(root)
	if len(mounts) != 4 || !fm.private[root] {
		t.Errorf("mounts %+v private %v", mounts, fm.private)
	}
	if _, err := os.Stat(filepath.Join(root, "0")); err == nil {
		t.Error("a view for root")
	}
	if _, err := os.Stat(filepath.Join(root, "101109")); err == nil {
		t.Error("a view for someone with nothing to see")
	}
	fi, _ := os.Stat(filepath.Join(root, "101103"))
	if fi == nil || fi.Mode().Perm() != 0o755 {
		t.Errorf("view folder %v", fi)
	}
	want := `gpasswd -M HOME\alice,HOME\bob hardyos-sftp`
	if !contains(run.Lines(), want) {
		t.Errorf("group not set: %v", run.Lines())
	}
	b, _ := os.ReadFile(m.dropIn())
	if string(b) != RenderSSHD(root, true) {
		t.Errorf("drop-in:\n%s", b)
	}
	p, _ := os.ReadFile(m.pamPath())
	if strings.Count(string(p), "pam_winbind.so") != 2 {
		t.Errorf("pam:\n%s", p)
	}
	if !contains(run.Lines(), "sshd -t") || !contains(run.Lines(), "systemctl reload ssh.service") {
		t.Errorf("not validated and reloaded: %v", run.Lines())
	}

	// Bob loses Media, alice's Kids Films becomes writable; a busy mount stays.
	fm.busy = map[string]bool{filepath.Join(root, "101103/Home"): true}
	binds2 := []Bind{binds[1], {UID: 101103, Name: "Kids Films", Share: "kids", Source: kids, Dataset: "tank/shares/kids"}}
	n := len(run.Lines())
	st, err = m.Apply(ctx, true, users, binds2)
	if err == nil || !strings.Contains(err.Error(), "busy") {
		t.Errorf("busy unmount not reported: %v", err)
	}
	mounts, _ = fm.List(root)
	got := map[string]bool{}
	for _, mp := range mounts {
		got[strings.TrimPrefix(mp.Target, root+"/")] = mp.ReadOnly
	}
	if !reflect.DeepEqual(got, map[string]bool{"101103/Media": false, "101103/Kids Films": false, "101103/Home": false}) {
		t.Errorf("after change: %v", got)
	}
	if _, err := os.Stat(filepath.Join(root, "101107")); err == nil {
		t.Error("bob's empty view was kept")
	}
	if _, err := os.Stat(filepath.Join(root, "101103/Home")); err != nil {
		t.Error("a folder with a mount on it was removed")
	}
	if contains(run.Lines()[n:], "systemctl reload ssh.service") {
		t.Error("sshd reloaded though its settings didn't change")
	}

	// A shared folder going away: its binds go.
	fm.busy = nil
	if err := m.Release("tank/shares"); err != nil {
		t.Fatal(err)
	}
	mounts, _ = fm.List(root)
	if len(mounts) != 1 || mounts[0].Source != "tank/homes/home.alice" {
		t.Errorf("after release: %+v", mounts)
	}

	// Off: everything goes, domain accounts are refused.
	run.OnResult("getent group hardyos-sftp", sysexec.Result{Stdout: []byte("hardyos-sftp:x:998:HOME\\alice\n")})
	if _, err := m.Apply(ctx, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	mounts, _ = fm.List(root)
	if len(mounts) != 0 {
		t.Errorf("mounts left: %+v", mounts)
	}
	if ents, _ := os.ReadDir(root); len(ents) != 0 {
		t.Errorf("views left: %v", ents)
	}
	b, _ = os.ReadFile(m.dropIn())
	if string(b) != RenderSSHD(root, false) {
		t.Errorf("off drop-in:\n%s", b)
	}
	p, _ = os.ReadFile(m.pamPath())
	if string(p) != debianPAM {
		t.Errorf("pam not restored:\n%s", p)
	}
	if !contains(run.Lines(), "gpasswd -M  hardyos-sftp") {
		t.Errorf("group not emptied: %v", run.Lines())
	}
	// The shares themselves were never touched.
	for _, d := range []string{media, kids, home} {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("%s: %v", d, err)
		}
	}
}

func TestApplyRefusedConfigIsRolledBack(t *testing.T) {
	m, _, run, _ := newTestManager(t)
	if err := os.WriteFile(m.dropIn(), []byte("# old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run.OnResult("sshd -t", sysexec.Result{ExitCode: 255, Stderr: []byte("Bad configuration option")})
	_, err := m.Apply(context.Background(), true, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("err %v", err)
	}
	b, _ := os.ReadFile(m.dropIn())
	if string(b) != "# old\n" {
		t.Errorf("old drop-in not put back: %q", b)
	}
	if contains(run.Lines(), "systemctl reload ssh.service") {
		t.Error("reloaded with a refused config")
	}
}

func TestApplyWarnsAboutWinbindEverywhere(t *testing.T) {
	m, _, _, _ := newTestManager(t)
	_ = os.WriteFile(m.commonAuth(), []byte("auth [success=2 default=ignore] pam_winbind.so krb5_auth\n"), 0o644)
	st, _ := m.Apply(context.Background(), true, nil, nil)
	if !strings.Contains(st.Problem, "pam-auth-update") {
		t.Errorf("problem %q", st.Problem)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
