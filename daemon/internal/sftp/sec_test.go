package sftp

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// effectiveOK is what sshd -T prints for a domain account with the drop-in
// in effect (trimmed to the settings that matter, plus some others).
func effectiveOK(root string) string {
	return "port 22\nusepam yes\nforcecommand internal-sftp -d /\nchrootdirectory " + root + "/%U\n" +
		"disableforwarding yes\nallowgroups hardyos-sftp\nauthenticationmethods password\npubkeyauthentication no\n" +
		"permittty no\nallowtcpforwarding no\nallowagentforwarding no\nx11forwarding no\npermittunnel no\npasswordauthentication yes\n"
}

// checkJumps: every numeric jump in a block lands inside it or on the line
// right after it (the @include it stands in front of), and the condition's
// skip lands exactly there.
func checkJumps(t *testing.T, kind string, block []string) {
	t.Helper()
	body := block[1 : len(block)-1]
	re := regexp.MustCompile(`(success|default)=(\d+)`)
	for i, l := range body {
		for _, m := range re.FindAllStringSubmatch(l, -1) {
			n, _ := strconv.Atoi(m[2])
			if i+n+1 > len(body) {
				t.Errorf("%s line %d jumps %d, past the block", kind, i, n)
			}
			if i == 0 && m[1] == "default" && i+n+1 != len(body) {
				t.Errorf("%s: the condition skips %d lines, the block has %d after it", kind, n, len(body)-1)
			}
		}
	}
}

func TestCheckPAMSession(t *testing.T) {
	on, err := EditPAM(debianPAM, true)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"common-session": "session optional pam_systemd.so\nsession required pam_unix.so\n",
		"common-auth":    "auth [success=1 default=ignore] pam_unix.so nullok\n",
	}
	read := func(n string) ([]byte, error) {
		if s, ok := files[n]; ok {
			return []byte(s), nil
		}
		return nil, os.ErrNotExist
	}
	// common-session's pam_systemd comes after HardyOS's block: fine.
	if err := CheckPAMSession(on, read); err != nil {
		t.Errorf("Debian's file: %v", err)
	}
	// pam_systemd ahead of the block, directly or through an include.
	bad := strings.Replace(on, "session    required     pam_loginuid.so", "session    required     pam_loginuid.so\n-session optional /lib/security/pam_systemd.so", 1)
	if err := CheckPAMSession(bad, read); err == nil {
		t.Error("pam_systemd ahead of the block was accepted")
	}
	files["extra"] = "session [success=ok default=ignore] pam_systemd.so\n"
	bad = strings.Replace(on, "session    required     pam_loginuid.so", "@include extra", 1)
	if err := CheckPAMSession(bad, read); err == nil {
		t.Error("pam_systemd included ahead of the block was accepted")
	}
	if err := CheckPAMSession(debianPAM, read); err == nil {
		t.Error("a file without HardyOS's session block was accepted")
	}
	for l, want := range map[string]string{
		"session optional pam_systemd.so":                   "pam_systemd.so",
		"-session\t[default=ignore]\tpam_systemd.so x=1":    "pam_systemd.so",
		"session [success=ok ignore=ignore] pam_selinux.so": "pam_selinux.so",
		"# session optional pam_systemd.so":                 "",
	} {
		if _, got := pamModule(l); got != want {
			t.Errorf("pamModule(%q) = %q", l, got)
		}
	}
}

func TestCheckEffective(t *testing.T) {
	root := "/srv/hardyos/sftp"
	if err := CheckEffective(effectiveOK(root), root); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{
		"not included":       "port 22\nforcecommand none\nchrootdirectory none\nallowtcpforwarding yes\n",
		"forwarding back on": strings.Replace(effectiveOK(root), "allowtcpforwarding no", "allowtcpforwarding yes", 1),
		"keys allowed":       strings.Replace(effectiveOK(root), "pubkeyauthentication no", "pubkeyauthentication yes", 1),
		"other groups too":   effectiveOK(root) + "allowgroups users\n",
		"another chroot":     strings.Replace(effectiveOK(root), root+"/%U", "/", 1),
		"tty":                strings.Replace(effectiveOK(root), "permittty no", "permittty yes", 1),
		"any method":         strings.Replace(effectiveOK(root), "authenticationmethods password", "authenticationmethods any", 1),
		"no forcecommand":    strings.Replace(effectiveOK(root), "forcecommand internal-sftp -d /\n", "", 1),
		"no forwarding off":  strings.Replace(effectiveOK(root), "disableforwarding yes", "disableforwarding no", 1),
	} {
		if err := CheckEffective(out, root); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := CheckEffective("forcecommand none\n", root); err == nil || !strings.Contains(err.Error(), "Include") {
		t.Errorf("no hint about the Include: %v", err)
	}
	if got := strings.Join(EffectiveArgs(`HOME\alice`), " "); got != `-T -C user=HOME\alice,host=x,addr=127.0.0.1` {
		t.Errorf("args %q", got)
	}
}

// PAM lets domain accounts in only after sshd's effective settings were
// checked; if they're wrong, PAM's block comes out again (fail closed) and
// File Services says why. Every apply checks again.
func TestApplyVerifiesSSHDBeforePAM(t *testing.T) {
	m, _, run, dir := newTestManager(t)
	ctx := context.Background()
	media := filepath.Join(dir, "shares/media")
	probe := `sshd -T -C user=HOME\alice,host=x,addr=127.0.0.1`
	users := []User{{Principal: `HOME\alice`, Name: `HOME\alice`, UID: 101103}}
	binds := []Bind{{UID: 101103, Name: "Media", Share: "media", Source: media, Dataset: "tank/shares/media"}}
	if _, err := m.Apply(ctx, true, users, binds); err != nil {
		t.Fatal(err)
	}
	lines := run.Lines()
	iT, iV := index(lines, "sshd -t"), index(lines, probe)
	if iT < 0 || iV < iT {
		t.Errorf("sshd not checked before PAM: %v", lines)
	}
	if p, _ := os.ReadFile(m.pamPath()); !strings.Contains(string(p), "pam_winbind") {
		t.Fatal("PAM not on")
	}
	// Something overrides the drop-in now: PAM goes off on the next apply.
	run.On(probe, strings.Replace(effectiveOK(m.root()), "forcecommand internal-sftp -d /", "forcecommand none", 1))
	n := len(run.Lines())
	st, err := m.Apply(ctx, true, users, binds)
	if err == nil || !strings.Contains(st.Problem, "off until this is fixed") || !strings.Contains(st.Problem, "forcecommand") {
		t.Errorf("err %v, problem %q", err, st.Problem)
	}
	if index(run.Lines()[n:], probe) < 0 {
		t.Error("not checked again on an unchanged drop-in")
	}
	if p, _ := os.ReadFile(m.pamPath()); string(p) != debianPAM {
		t.Errorf("PAM still on:\n%s", p)
	}
	// sshd -T itself failing is no better.
	run.OnResult(probe, sysexec.Result{ExitCode: 255, Stderr: []byte("no hostkeys")})
	if _, err := m.Apply(ctx, true, users, binds); err == nil {
		t.Error("a failing sshd -T was accepted")
	}
	if p, _ := os.ReadFile(m.pamPath()); string(p) != debianPAM {
		t.Errorf("PAM on:\n%s", p)
	}
	// Nobody with a view: nothing to verify, PAM stays off.
	run.On(probe, effectiveOK(m.root()))
	if _, err := m.Apply(ctx, true, users, nil); err != nil {
		t.Fatal(err)
	}
	if p, _ := os.ReadFile(m.pamPath()); string(p) != debianPAM {
		t.Errorf("PAM on with nobody to let in:\n%s", p)
	}
}

func TestApplyRefusesPAMSystemd(t *testing.T) {
	m, _, _, dir := newTestManager(t)
	withSystemd := strings.Replace(debianPAM, "session    required     pam_loginuid.so", "session    required     pam_loginuid.so\nsession optional pam_systemd.so", 1)
	_ = os.WriteFile(m.pamPath(), []byte(withSystemd), 0o644)
	users := []User{{Principal: `HOME\alice`, Name: `HOME\alice`, UID: 101103}}
	binds := []Bind{{UID: 101103, Name: "Media", Share: "media", Source: filepath.Join(dir, "shares/media"), Dataset: "tank/shares/media"}}
	st, err := m.Apply(context.Background(), true, users, binds)
	if err == nil || !strings.Contains(st.Problem, "pam_systemd") {
		t.Errorf("err %v problem %q", err, st.Problem)
	}
	if p, _ := os.ReadFile(m.pamPath()); string(p) != withSystemd {
		t.Errorf("PAM changed:\n%s", p)
	}
}

// Views made by older versions were peers of the shared folders' mounts
// and picked up their child mounts. The sync makes everything private
// before it unmounts anything, never unmounts anything below a view's own
// mounts, and replaces such binds with private non-recursive ones.
func TestSyncViewsMigratesSharedBinds(t *testing.T) {
	m, fm, _, dir := newTestManager(t)
	root := m.root()
	media := filepath.Join(dir, "shares/media")
	for _, d := range []string{"101103/Media/Child", "101103/Kids", "101109", "x/y/z"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	shared := func(target, ds string, ro bool) MountPoint {
		return MountPoint{Target: filepath.Join(root, target), Source: ds, Root: "/", ReadOnly: ro, NoSuid: true, NoDev: true, NoExec: true, Shared: true}
	}
	fm.m = map[string]MountPoint{}
	for _, mp := range []MountPoint{
		shared("101103/Media", "tank/shares/media", false),
		// A child dataset mounted on the host later, propagated into the view.
		{Target: filepath.Join(root, "101103/Media/Child"), Source: "tank/shares/media/child", Root: "/", Shared: true},
		shared("101103/Kids", "tank/shares/kids", true),
		// Not the views' own: one level up, and somewhere deeper.
		{Target: filepath.Join(root, "101109"), Source: "tmpfs", Root: "/"},
		{Target: filepath.Join(root, "x/y/z"), Source: "tmpfs", Root: "/"},
	} {
		fm.m[mp.Target] = mp
	}
	binds := []Bind{{UID: 101103, Name: "Media", Share: "media", Source: media, Dataset: "tank/shares/media"}}
	n, err := m.syncViews(binds)
	if err != nil || n != 1 {
		t.Fatalf("sync = %d, %v", n, err)
	}
	if len(fm.ops) == 0 || fm.ops[0] != "private "+root {
		t.Errorf("not made private first: %v", fm.ops)
	}
	if len(fm.hostUnmounts) != 0 {
		t.Errorf("unmounts reached the host: %v", fm.hostUnmounts)
	}
	for _, op := range fm.ops {
		for _, other := range []string{"101103/Media/Child", "101109", "x/y/z"} {
			if op == "unmount "+filepath.Join(root, other) {
				t.Errorf("unmounted something not the views' own: %s", op)
			}
		}
	}
	got, _ := fm.List(root)
	want := map[string]bool{filepath.Join(root, "101103/Media"): true, filepath.Join(root, "101109"): true, filepath.Join(root, "x/y/z"): true}
	if len(got) != len(want) {
		t.Errorf("mounts %+v", got)
	}
	for _, c := range got {
		if !want[c.Target] {
			t.Errorf("left %s", c.Target)
		}
		if c.Target == filepath.Join(root, "101103/Media") && (!c.Restricted() || c.ReadOnly) {
			t.Errorf("Media rebound as %+v", c)
		}
	}
}

// A bind is only kept when it's exactly what the plan says: the dataset's
// own root, its device, restricted, nothing stacked or inside. An existing
// target folder is never chmodded or chowned.
func TestSyncViewsChecksEveryBind(t *testing.T) {
	m, fm, _, dir := newTestManager(t)
	root := m.root()
	media := filepath.Join(dir, "shares/media")
	fm.dev = map[string]uint64{media: 77}
	b := Bind{UID: 101103, Name: "Media", Share: "media", Source: media, Dataset: "tank/shares/media", Dev: 77}
	if n, err := m.syncViews([]Bind{b}); err != nil || n != 1 {
		t.Fatalf("sync = %d %v", n, err)
	}
	target := filepath.Join(root, "101103/Media")
	good := fm.m[target]
	for name, bad := range map[string]func(*MountPoint){
		"a subfolder":     func(c *MountPoint) { c.Root = "/sub" },
		"another device":  func(c *MountPoint) { c.Dev = 78 },
		"suid":            func(c *MountPoint) { c.NoSuid = false },
		"exec":            func(c *MountPoint) { c.NoExec = false },
		"another dataset": func(c *MountPoint) { c.Source = "tank/other" },
		"read-only":       func(c *MountPoint) { c.ReadOnly = true },
	} {
		c := good
		bad(&c)
		fm.m[target] = c
		fm.ops = nil
		if n, err := m.syncViews([]Bind{b}); err != nil || n != 1 {
			t.Fatalf("%s: sync = %d %v", name, n, err)
		}
		if !reflect.DeepEqual(fm.ops, []string{"private " + root, "unmount " + target, "bind " + target}) {
			t.Errorf("%s: %v", name, fm.ops)
		}
	}
	// Something mounted inside: replaced as a whole.
	fm.m[target+"/in"] = MountPoint{Target: target + "/in", Source: "x", Root: "/"}
	fm.ops = nil
	_, _ = m.syncViews([]Bind{b})
	if !reflect.DeepEqual(fm.ops, []string{"private " + root, "unmount " + target, "bind " + target}) {
		t.Errorf("inside: %v", fm.ops)
	}
	if _, ok := fm.m[target+"/in"]; ok {
		t.Error("the mount inside is still there")
	}
	// An existing target keeps its mode (it may be a shared folder's top).
	fm.m = nil
	if err := os.Chmod(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := m.syncViews([]Bind{b}); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o700 {
		t.Errorf("target chmodded to %v", fi.Mode().Perm())
	}
	// An unmount that fails: never mounted over.
	c := good
	c.Root = "/sub"
	fm.m = map[string]MountPoint{target: c}
	fm.busy = map[string]bool{target: true}
	fm.ops = nil
	if _, err := m.syncViews([]Bind{b}); err == nil {
		t.Error("busy not reported")
	}
	for _, op := range fm.ops {
		if op == "bind "+target {
			t.Error("bound over a mount that couldn't be taken away")
		}
	}
}

// A released dataset stays out of the views until the operation that
// released it is over.
func TestReleaseHoldsDataset(t *testing.T) {
	m, fm, _, dir := newTestManager(t)
	ctx := context.Background()
	media := filepath.Join(dir, "shares/media")
	users := []User{{Principal: `HOME\alice`, Name: `HOME\alice`, UID: 101103}}
	binds := []Bind{
		{UID: 101103, Name: "Media", Share: "media", Source: media, Dataset: "tank/shares/media"},
		{UID: 101103, Name: "Kids", Share: "kids", Source: filepath.Join(dir, "shares/kids"), Dataset: "tank/shares/kids"},
	}
	if _, err := m.Apply(ctx, true, users, binds); err != nil {
		t.Fatal(err)
	}
	if err := m.Release("tank/shares/media"); err != nil {
		t.Fatal(err)
	}
	st, _ := m.Apply(ctx, true, users, binds)
	if st.Folders != 1 {
		t.Errorf("folders while released: %d", st.Folders)
	}
	if _, ok := fm.m[filepath.Join(m.root(), "101103/Media")]; ok {
		t.Error("a released dataset was bound again")
	}
	m.Unhold("tank/shares/media")
	if st, _ := m.Apply(ctx, true, users, binds); st.Folders != 2 {
		t.Errorf("folders after: %d", st.Folders)
	}
	// A pool covers everything in it.
	_ = m.Release("tank")
	if st, _ := m.Apply(ctx, true, users, binds); st.Folders != 0 {
		t.Errorf("folders while the pool is released: %d", st.Folders)
	}
	m.Unhold("tank")
}

func index(l []string, s string) int {
	for i, x := range l {
		if x == s {
			return i
		}
	}
	return -1
}
