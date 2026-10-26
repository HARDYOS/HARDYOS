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
// those users, PAM and sshd let them in. With on false (or SFTP off), the
// views and the group are emptied and domain accounts are refused by sshd.
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
	st.Users = len(names)
	if err := m.setGroup(ctx, names); err != nil {
		return err
	}
	if err := m.setPAM(true); err != nil {
		return err
	}
	return m.setSSHD(ctx, RenderSSHD(m.root(), true))
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

// ensureDir makes a root-owned 0755 folder that isn't a link.
func (m *Manager) ensureDir(p string) error {
	fi, err := os.Lstat(p)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.Mkdir(p, 0o755); err != nil {
			return err
		}
	case err != nil:
		return err
	case fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir():
		return fmt.Errorf("%s isn't a folder; remove it so SFTP can use the name", p)
	}
	if !m.NoChown {
		if err := os.Lchown(p, 0, 0); err != nil {
			return err
		}
	}
	return os.Chmod(p, 0o755)
}

// syncViews makes the bind mounts below the root exactly binds and removes
// empty folders nobody needs. Folders are only ever removed with rmdir, so
// a bind that couldn't be unmounted (and the files behind it) stays.
// It returns how many binds are in place.
func (m *Manager) syncViews(binds []Bind) (int, error) {
	root := m.root()
	mt := m.mounter()
	if len(binds) > 0 {
		if err := m.ensureDir(filepath.Dir(root)); err != nil {
			return 0, err
		}
		if err := m.ensureDir(root); err != nil {
			return 0, err
		}
		if err := mt.MakePrivate(root); err != nil {
			return 0, err
		}
	}
	want := map[string]Bind{}
	for _, b := range binds {
		if viewName(b.Name) == "" || b.UID < DomainUIDLow || b.UID > DomainUIDHigh || !filepath.IsAbs(b.Source) {
			continue
		}
		want[filepath.Join(root, strconv.Itoa(b.UID), b.Name)] = b
	}
	cur, err := mt.List(root)
	if err != nil {
		return 0, err
	}
	// Deepest first, so nothing is unmounted from under another mount.
	sort.Slice(cur, func(i, j int) bool { return len(cur[i].Target) > len(cur[j].Target) })
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
		b, ok := want[c.Target]
		if ok && !in[c.Target] && c.ReadOnly == b.ReadOnly && (b.Dataset == "" || c.Source == b.Dataset) {
			in[c.Target] = true
			continue
		}
		keep(mt.Unmount(c.Target))
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
		if err := m.ensureDir(filepath.Dir(t)); err != nil {
			keep(err)
			continue
		}
		if err := m.ensureDir(t); err != nil {
			keep(err)
			continue
		}
		if err := mt.Bind(b.Source, t, b.ReadOnly); err != nil {
			keep(err)
			continue
		}
		n++
	}
	// Folders nobody needs any more (never one something is mounted on).
	mounted := map[string]bool{}
	if left, err := mt.List(root); err == nil {
		for _, c := range left {
			mounted[c.Target] = true
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
		if left == 0 {
			_ = syscall.Rmdir(up)
		}
	}
	return n, first
}

// Release unmounts every bind of datasets at or below ds (a pool, a shared
// folder's dataset), so it can be destroyed or exported.
func (m *Manager) Release(ds string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.release(func(c MountPoint) bool { return c.Source == ds || strings.HasPrefix(c.Source, ds+"/") })
}

func (m *Manager) release(match func(MountPoint) bool) error {
	cur, err := m.mounter().List(m.root())
	if err != nil {
		return err
	}
	var first error
	for _, c := range cur {
		if !match(c) {
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
