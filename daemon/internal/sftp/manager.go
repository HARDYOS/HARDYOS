package sftp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Status is how SFTP is doing (File Services shows it).
type Status struct {
	Enabled bool `json:"enabled"`
	// Running: the SSH server runs (HardyOS doesn't start or stop it).
	Running bool `json:"running"`
	// Users: domain accounts with a view; Folders: bind mounts in all views.
	Users   int    `json:"users"`
	Folders int    `json:"folders"`
	Port    int    `json:"port"`
	Problem string `json:"problem"`
}

// holdMax bounds how long a released dataset is kept out of the views if
// whoever released it never says it's done (a crash in between).
const holdMax = 30 * time.Minute

// Manager keeps sshd's settings, sshd's PAM stack, the views and the
// hardyos-sftp group in step with what Plan says. Safe for concurrent use.
type Manager struct {
	Runner sysexec.Runner
	Log    *slog.Logger
	// Paths; empty means the defaults (tests change them).
	Root, DropIn, PAMPath, CommonAuth string
	Unit                              string
	// Mounter; nil means SysMounter.
	Mounter Mounter
	// NoChown skips making the views root's (tests without root).
	NoChown bool

	mu   sync.Mutex
	last Status
	// held: datasets (and everything below them) a storage operation or a
	// shared folder delete is letting go of; no view binds them until
	// Unhold (or holdMax).
	held map[string]time.Time
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (m *Manager) root() string       { return filepath.Clean(or(m.Root, ViewsRoot)) }
func (m *Manager) dropIn() string     { return or(m.DropIn, DropIn) }
func (m *Manager) pamPath() string    { return or(m.PAMPath, PAMFile) }
func (m *Manager) commonAuth() string { return or(m.CommonAuth, CommonAuth) }
func (m *Manager) unit() string       { return or(m.Unit, SSHUnit) }
func (m *Manager) mounter() Mounter {
	if m.Mounter != nil {
		return m.Mounter
	}
	return SysMounter{}
}

// installed: OpenSSH's server is on this system.
func (m *Manager) installed() bool {
	_, err := os.Stat(filepath.Dir(m.dropIn()))
	return err == nil
}

// Apply makes SFTP match the plan: with on, the views get exactly binds
// (users with none get no view, so they can't sign in), the group lists
// those users, sshd's settings are written and checked as in effect, and
// only then PAM lets them in. With on false (or SFTP off), the views and
// the group are emptied and domain accounts are refused by sshd.
func (m *Manager) Apply(ctx context.Context, on bool, users []User, binds []Bind) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{Enabled: on, Port: 22}
	if !m.installed() {
		if on {
			st.Problem = "The SSH server (openssh-server) isn't installed."
		}
		m.last = st
		return st, nil
	}
	var err error
	if on {
		err = m.applyOn(ctx, users, binds, &st)
	} else {
		err = m.applyOff(ctx)
	}
	st.Running = m.active(ctx)
	if err != nil {
		st.Problem = err.Error()
	} else if on && !st.Running {
		st.Problem = "The SSH server isn't running, so SFTP can't be used. In the Terminal: systemctl enable --now ssh"
	}
	if b, rerr := os.ReadFile(m.commonAuth()); rerr == nil && WinbindEverywhere(string(b)) {
		st.Problem = strings.TrimSpace(st.Problem + " Domain accounts are in the system-wide PAM stack (" + m.commonAuth() +
			"): run pam-auth-update and untick Winbind, so they can only use SFTP.")
	}
	m.last = st
	return st, err
}

// Status is the last Apply's outcome, with the SSH server's state now.
func (m *Manager) Status(ctx context.Context) Status {
	m.mu.Lock()
	st := m.last
	m.mu.Unlock()
	if st.Port == 0 {
		st.Port = 22
	}
	st.Running = m.installed() && m.active(ctx)
	return st
}

func (m *Manager) active(ctx context.Context) bool {
	res, err := m.Runner.Run(ctx, nil, "systemctl", "is-active", "--quiet", m.unit())
	return err == nil && res.ExitCode == 0
}

// errSignInOff wraps anything that keeps domain sign-in off.
func signInOff(err error) error {
	return fmt.Errorf("SFTP sign-in for domain accounts is off until this is fixed: %w", err)
}

func (m *Manager) applyOn(ctx context.Context, users []User, binds []Bind, st *Status) error {
	// Views first, so nobody is let in before their view is ready.
	n, err := m.syncViews(binds)
	if err != nil {
		return err
	}
	st.Folders = n
	have := map[int]bool{}
	for _, b := range binds {
		have[b.UID] = true
	}
	var names []string
	for _, u := range users {
		if have[u.UID] && ValidNSSName(u.Name) {
			names = append(names, u.Name)
		}
	}
	sort.Strings(names)
	st.Users = len(names)
	if err := m.setGroup(ctx, names); err != nil {
		return err
	}
	// sshd's settings, checked as really in effect for a domain account,
	// before PAM accepts a single domain password. Any doubt: PAM stays (or
	// goes) off, so domain accounts can't sign in at all.
	if err := m.setSSHD(ctx, RenderSSHD(m.root(), true)); err != nil {
		m.pamOff()
		return signInOff(err)
	}
	if len(names) == 0 {
		// Nobody to let in.
		return m.setPAM(false)
	}
	if err := m.verifySSHD(ctx, names[0]); err != nil {
		m.pamOff()
		return signInOff(err)
	}
	if err := m.setPAM(true); err != nil {
		m.pamOff()
		return signInOff(err)
	}
	return nil
}

// pamOff takes HardyOS's PAM lines out (failing closed); a failure is logged.
func (m *Manager) pamOff() {
	if err := m.setPAM(false); err != nil {
		m.log().Error("sftp: taking domain sign-in out of sshd's PAM stack", "err", err)
	}
}

// verifySSHD asks sshd which settings a domain account (user, a name NSS
// knows) really gets, after every file and Match block.
func (m *Manager) verifySSHD(ctx context.Context, user string) error {
	res, err := m.Runner.Run(ctx, nil, "sshd", EffectiveArgs(user)...)
	if err == nil && res.ExitCode != 0 {
		err = fmt.Errorf("sshd -T failed: %s", strings.TrimSpace(string(res.Stderr)))
	}
	if err != nil {
		return fmt.Errorf("checking the SSH server's settings for %s: %w", user, err)
	}
	return CheckEffective(string(res.Stdout), m.root())
}

func (m *Manager) applyOff(ctx context.Context) error {
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	// sshd first: domain accounts are refused before anything else changes.
	if _, err := os.Stat(m.dropIn()); err == nil {
		keep(m.setSSHD(ctx, RenderSSHD(m.root(), false)))
	}
	keep(m.setPAM(false))
	if _, err := os.Stat(m.root()); err == nil {
		_, err := m.syncViews(nil)
		keep(err)
	}
	if m.groupExists(ctx) {
		keep(m.setGroup(ctx, nil))
	}
	return first
}

// ---- views -----------------------------------------------------------------

// errNotOurs: a folder in the views isn't what HardyOS made.
var errNotOurs = errors.New("isn't a plain root-owned folder")

func devOf(p string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Lstat(p, &st); err != nil {
		return 0, err
	}
	return uint64(st.Dev), nil
}

// ensureDir makes p, root's and 0755, if it isn't there. An existing p is
// never changed (chown or chmod on something mounted there would change a
// shared folder's own top): it must be a folder, not a link, and with
// sameDev on the same file system as its parent (nothing mounted on it).
// With owned (and NoChown off) it must also be root's and writable by
// root only, as sshd's ChrootDirectory insists.
func (m *Manager) ensureDir(p string, sameDev, owned bool) error {
	fi, err := os.Lstat(p)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.Mkdir(p, 0o755); err != nil {
			return err
		}
		if !m.NoChown {
			if err := os.Lchown(p, 0, 0); err != nil {
				return err
			}
		}
		return os.Chmod(p, 0o755)
	case err != nil:
		return err
	case fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir():
		return fmt.Errorf("%s isn't a folder; remove it so SFTP can use the name", p)
	}
	if sameDev {
		d, err := devOf(p)
		if err != nil {
			return err
		}
		pd, err := devOf(filepath.Dir(p))
		if err != nil {
			return err
		}
		if d != pd {
			return fmt.Errorf("something is already mounted on %s; it was left alone", p)
		}
	}
	if owned && !m.NoChown {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s %w (root's, not writable by others), so SFTP can't use it", p, errNotOurs)
		}
	}
	return nil
}

// managed reports whether target is exactly <root>/<uid>/<name>, the only
// mounts the views are made of. Anything deeper is never touched.
func managed(root, target string) bool {
	rel, ok := strings.CutPrefix(target, root+"/")
	if !ok {
		return false
	}
	uid, name, ok := strings.Cut(rel, "/")
	return ok && uid != "" && name != "" && !strings.Contains(name, "/")
}

// isHeld reports whether ds is (below) a dataset being let go of; m.mu.
func (m *Manager) isHeld(ds string) bool {
	if ds == "" {
		return false
	}
	for h, at := range m.held {
		if time.Since(at) > holdMax {
			m.log().Warn("sftp: a released dataset was never handed back; views use it again", "dataset", h)
			delete(m.held, h)
			continue
		}
		if ds == h || strings.HasPrefix(ds, h+"/") {
			return true
		}
	}
	return false
}

// syncViews makes the bind mounts at <root>/<uid>/<name> exactly binds and
// removes empty folders nobody needs. Folders are only ever removed with
// rmdir, so a bind that couldn't be unmounted (and the files behind it)
// stays. Before anything is unmounted every mount below the root is made
// private, so no unmount here reaches another mount namespace or the
// shared folders' own mounts. It returns how many binds are in place.
func (m *Manager) syncViews(binds []Bind) (int, error) {
	root := m.root()
	mt := m.mounter()
	if len(binds) > 0 {
		if err := m.ensureDir(filepath.Dir(root), false, true); err != nil {
			return 0, err
		}
		if err := m.ensureDir(root, false, true); err != nil {
			return 0, err
		}
	} else if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err := mt.MakePrivate(root); err != nil {
		return 0, err
	}
	want := map[string]Bind{}
	for _, b := range binds {
		if viewName(b.Name) == "" || b.UID < DomainUIDLow || b.UID > DomainUIDHigh || !filepath.IsAbs(b.Source) || m.isHeld(b.Dataset) {
			continue
		}
		want[filepath.Join(root, strconv.Itoa(b.UID), b.Name)] = b
	}
	cur, err := mt.List(root)
	if err != nil {
		return 0, err
	}
	// What is mounted inside each managed mount (a view made before binds
	// were private and non-recursive picked up the shared folders' child
	// mounts) and how many mounts are stacked on it.
	inside, stacked := map[string]int{}, map[string]int{}
	for _, c := range cur {
		if managed(root, c.Target) {
			stacked[c.Target]++
		}
		for d := filepath.Dir(c.Target); len(d) > len(root); d = filepath.Dir(d) {
			if managed(root, d) {
				inside[d]++
			}
		}
	}
	var first error
	keep := func(err error) {
		if err != nil {
			m.log().Warn("sftp views", "err", err)
			if first == nil {
				first = err
			}
		}
	}
	in := map[string]bool{}
	for _, c := range cur {
		if !managed(root, c.Target) {
			continue
		}
		b, ok := want[c.Target]
		if ok && !in[c.Target] && stacked[c.Target] == 1 && inside[c.Target] == 0 &&
			c.ReadOnly == b.ReadOnly && c.Restricted() && c.Root == "/" &&
			(b.Dataset == "" || c.Source == b.Dataset) && (b.Dev == 0 || c.Dev == b.Dev) {
			in[c.Target] = true
			continue
		}
		keep(mt.Unmount(c.Target))
	}
	// A wrong mount that couldn't be taken away is never mounted over.
	still := map[string]bool{}
	if now, err := mt.List(root); err == nil {
		for _, c := range now {
			still[c.Target] = true
		}
	} else {
		return 0, err
	}
	n := 0
	targets := make([]string, 0, len(want))
	for t := range want {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	for _, t := range targets {
		if in[t] {
			n++
			continue
		}
		b := want[t]
		if still[t] {
			keep(fmt.Errorf("%s still has an old mount on it; it'll be tried again", t))
			continue
		}
		if err := m.ensureDir(filepath.Dir(t), true, true); err != nil {
			keep(err)
			continue
		}
		if err := m.ensureDir(t, true, false); err != nil {
			keep(err)
			continue
		}
		if err := mt.Bind(b.Source, b.Dev, t, b.ReadOnly); err != nil {
			keep(err)
			continue
		}
		n++
	}
	// Folders nobody needs any more (never one something is mounted on).
	mounted := map[string]bool{}
	if left, err := mt.List(root); err == nil {
		for _, c := range left {
			for d := c.Target; len(d) > len(root); d = filepath.Dir(d) {
				mounted[d] = true
			}
		}
	} else {
		return n, err
	}
	users, _ := os.ReadDir(root)
	for _, ud := range users {
		up := filepath.Join(root, ud.Name())
		if !ud.IsDir() || ud.Type()&os.ModeSymlink != 0 {
			continue
		}
		names, _ := os.ReadDir(up)
		left := 0
		for _, nd := range names {
			np := filepath.Join(up, nd.Name())
			if _, ok := want[np]; ok || mounted[np] {
				left++
				continue
			}
			if err := syscall.Rmdir(np); err != nil {
				left++
				if !errors.Is(err, syscall.ENOENT) {
					m.log().Info("sftp views: a folder couldn't be removed", "path", np, "err", err)
				}
			}
		}
		if left == 0 && !mounted[up] {
			_ = syscall.Rmdir(up)
		}
	}
	return n, first
}

// Release unmounts every bind of datasets at or below ds (a pool, a shared
// folder's dataset), so it can be destroyed or exported, and keeps them
// out of the views until Unhold(ds): a sync in the meantime (the watch, a
// shared folder change) must not bind them again.
func (m *Manager) Release(ds string) error {
	if ds == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.held == nil {
		m.held = map[string]time.Time{}
	}
	m.held[ds] = time.Now()
	return m.release(func(c MountPoint) bool { return c.Source == ds || strings.HasPrefix(c.Source, ds+"/") })
}

// Unhold lets the views use ds again (the operation that released it is
// over; the next sync binds what still exists).
func (m *Manager) Unhold(ds string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.held, ds)
}

func (m *Manager) release(match func(MountPoint) bool) error {
	root := m.root()
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := m.mounter().MakePrivate(root); err != nil {
		return err
	}
	cur, err := m.mounter().List(root)
	if err != nil {
		return err
	}
	var first error
	for _, c := range cur {
		if !managed(root, c.Target) || !match(c) {
			continue
		}
		if err := m.mounter().Unmount(c.Target); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		_ = syscall.Rmdir(c.Target)
	}
	return first
}

// ---- group -----------------------------------------------------------------

func (m *Manager) groupExists(ctx context.Context) bool {
	res, err := m.Runner.Run(ctx, nil, "getent", "group", Group)
	return err == nil && res.ExitCode == 0
}

// setGroup makes the hardyos-sftp group list exactly names.
func (m *Manager) setGroup(ctx context.Context, names []string) error {
	sort.Strings(names)
	res, err := m.Runner.Run(ctx, nil, "getent", "group", Group)
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		if _, err := sysexec.Output(ctx, m.Runner, "groupadd", "--system", Group); err != nil {
			return fmt.Errorf("making the %s group: %w", Group, err)
		}
		res.Stdout = nil
	}
	var cur []string
	if f := strings.Split(strings.TrimSpace(string(res.Stdout)), ":"); len(f) == 4 && f[3] != "" {
		cur = strings.Split(f[3], ",")
		sort.Strings(cur)
	}
	if strings.Join(cur, ",") == strings.Join(names, ",") {
		return nil
	}
	if _, err := sysexec.Output(ctx, m.Runner, "gpasswd", "-M", strings.Join(names, ","), Group); err != nil {
		return fmt.Errorf("setting who may use SFTP: %w", err)
	}
	return nil
}

// ---- PAM and sshd ----------------------------------------------------------

// setPAM puts HardyOS's blocks in sshd's PAM file (on) or takes them out.
// With on, the result is checked before it's written: nothing in the
// session stack a domain account still reaches may start pam_systemd.
func (m *Manager) setPAM(on bool) error {
	b, err := os.ReadFile(m.pamPath())
	if errors.Is(err, os.ErrNotExist) {
		if on {
			return fmt.Errorf("%s is missing", m.pamPath())
		}
		return nil
	}
	if err != nil {
		return err
	}
	text, err := EditPAM(string(b), on)
	if err != nil {
		return err
	}
	if on {
		dir := filepath.Dir(m.pamPath())
		read := func(name string) ([]byte, error) {
			if name == "" || strings.ContainsAny(name, "/\x00") {
				return nil, os.ErrNotExist
			}
			return os.ReadFile(filepath.Join(dir, name))
		}
		if err := CheckPAMSession(text, read); err != nil {
			return err
		}
	}
	if text == string(b) {
		return nil
	}
	return writeAtomic(m.pamPath(), []byte(text), 0o644)
}

// setSSHD puts the drop-in in place, checks the whole configuration with
// sshd -t (putting the old one back if sshd refuses it) and reloads the
// SSH server when it runs. sshd reads its files only when (re)started, so
// a refused file is never used.
func (m *Manager) setSSHD(ctx context.Context, conf string) error {
	p := m.dropIn()
	old, oerr := os.ReadFile(p)
	if oerr == nil && string(old) == conf {
		return nil
	}
	if err := writeAtomic(p, []byte(conf), 0o644); err != nil {
		return err
	}
	res, err := m.Runner.Run(ctx, nil, "sshd", "-t")
	if err == nil && res.ExitCode != 0 {
		err = fmt.Errorf("the SSH server refused the SFTP settings: %s", strings.TrimSpace(string(res.Stderr)))
	}
	if err != nil {
		if oerr == nil {
			_ = writeAtomic(p, old, 0o644)
		} else {
			_ = os.Remove(p)
		}
		return err
	}
	if m.active(ctx) {
		if _, err := sysexec.Output(ctx, m.Runner, "systemctl", "reload", m.unit()); err != nil {
			return fmt.Errorf("reloading the SSH server: %w", err)
		}
	}
	return nil
}

func writeAtomic(p string, b []byte, mode os.FileMode) error {
	tmp := p + ".hardyos-tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, p)
}
