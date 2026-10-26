package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/boot"
	"github.com/hardyos/hardyos/daemon/internal/install"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// How an update proceeds:
//
//  1. Stage: verify the bundle, unpack it into a new boot environment, carry
//     this system's settings over, add it to the boot menu and choose it for
//     the next boot only. A marker records the pending update.
//  2. Restart: just before rebooting, the shared state dataset is
//     snapshotted, so a failed update can't leave a database the old version
//     can't read.
//  3. First boot of the new version: once hardyd is healthy it confirms the
//     update, which makes the new version the default and removes old ones
//     beyond KeepVersions. If it isn't confirmed within ConfirmTimeout, the
//     server restarts; the one-time boot choice is used up, so it comes back
//     on the previous version.
//  4. Back on the previous version with the marker still there: the update
//     failed. The state dataset is rolled back to the snapshot, the failed
//     boot environment is removed and the result is recorded.

// Defaults.
const (
	// ConfirmTimeout is how long a new version has to become healthy.
	ConfirmTimeout = 15 * time.Minute
	// KeepVersions is how many installed versions are kept (plus the running
	// and default ones).
	KeepVersions = 3
)

// Updater does the root-side work. Paths are host paths prefixed with Root.
type Updater struct {
	Runner sysexec.Runner
	Root   string
	// StateDir is the shared state dataset's mount point (/var/lib/hardyos).
	StateDir string
	// Keys returns the trusted signing keys.
	Keys func() []PublicKey
	// Arch overrides runtime.GOARCH (tests).
	Arch string
	Now  func() time.Time
	// Reboot restarts the server (systemctl reboot).
	Reboot func()
	// ConfirmTimeout overrides the default (tests).
	ConfirmTimeout time.Duration
}

// Pending is the marker for an update waiting for, or in, its first boot.
type Pending struct {
	BE          string    `json:"bootEnvironment"`
	Dataset     string    `json:"dataset"`
	Version     string    `json:"version"`
	FromBE      string    `json:"fromBootEnvironment"`
	FromVersion string    `json:"fromVersion"`
	StagedAt    time.Time `json:"stagedAt"`
	Snapshot    string    `json:"snapshot,omitempty"` // state snapshot taken before restarting
	Notes       string    `json:"notes,omitempty"`
}

// Result is the outcome of the last update or version switch.
type Result struct {
	OK      bool      `json:"ok"`
	Version string    `json:"version"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

// restoreMarker asks the next boot to roll the state dataset back.
type restoreMarker struct {
	Snapshot string `json:"snapshot"`
	Reason   string `json:"reason"`
	Version  string `json:"version"` // the version switched to
}

func (u *Updater) path(p string) string { return filepath.Join(u.Root, p) }

func (u *Updater) stateDir() string {
	if u.StateDir == "" {
		return "/var/lib/hardyos"
	}
	return u.StateDir
}

// UploadDir is where hardyd puts update files for staging.
func (u *Updater) UploadDir() string { return filepath.Join(u.stateDir(), "updates") }

func (u *Updater) pendingFile() string {
	return u.path(filepath.Join(u.stateDir(), "update-pending.json"))
}
func (u *Updater) resultFile() string {
	return u.path(filepath.Join(u.stateDir(), "update-result.json"))
}
func (u *Updater) restoreFile() string {
	return u.path(filepath.Join(u.stateDir(), "update-restore.json"))
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now().UTC()
}

func (u *Updater) arch() string {
	if u.Arch != "" {
		return u.Arch
	}
	return runtime.GOARCH
}

func (u *Updater) env() boot.Env { return boot.Env{Runner: u.Runner, Root: u.Root} }

func (u *Updater) bootConfig() (*boot.Config, error) {
	cfg, err := boot.LoadConfig(u.path(boot.ConfigPath))
	if errors.Is(err, boot.ErrNoConfig) {
		return nil, errors.New("updates need a system installed with the HardyOS installer")
	}
	return cfg, err
}

func (u *Updater) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := sysexec.Output(ctx, u.Runner, name, args...)
	var ce *sysexec.CommandError
	if errors.As(err, &ce) {
		return out, errors.New(ce.Error())
	}
	return out, err
}

// BootedDataset returns the ZFS dataset mounted at / (empty when / isn't ZFS).
func (u *Updater) BootedDataset() string {
	b, err := os.ReadFile(u.path("/proc/mounts"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == "/" && f[2] == "zfs" {
			return f[0]
		}
	}
	return ""
}

// readJSON reads one of the updater's state files. They live in hardyd's
// directory, so only files root wrote are trusted.
func readJSON(path string, v any) (bool, error) {
	b, err := rootfile.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, v)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// PendingUpdate returns the pending update, if any.
func (u *Updater) PendingUpdate() (*Pending, error) {
	var p Pending
	ok, err := readJSON(u.pendingFile(), &p)
	if !ok || err != nil {
		return nil, err
	}
	return &p, nil
}

func (u *Updater) setResult(ok bool, version, msg string) {
	_ = writeJSON(u.resultFile(), Result{OK: ok, Version: version, Message: msg, At: u.now()})
}

// Status ------------------------------------------------------------------

// Version is one installed version (boot environment).
type Version struct {
	boot.Environment
	Running bool `json:"running"`
	Trying  bool `json:"trying"` // staged, waiting for its first boot
}

// Status is what the Updates page shows.
type Status struct {
	Running  string    `json:"running"` // boot environment name
	Versions []Version `json:"versions"`
	Pending  *Pending  `json:"pending"`
	Last     *Result   `json:"last"`
	// RestoreOnBoot is set when the next boot restores settings from a snapshot.
	RestoreOnBoot bool `json:"restoreOnBoot"`
	// Managed is false on systems not installed with the HardyOS installer.
	Managed bool `json:"managed"`
}

// Status reports installed versions and update state.
func (u *Updater) Status(ctx context.Context) (*Status, error) {
	st := &Status{Versions: []Version{}}
	cfg, err := u.bootConfig()
	if err != nil {
		return st, nil
	}
	st.Managed = true
	booted := u.BootedDataset()
	st.Pending, _ = u.PendingUpdate()
	var last Result
	if ok, _ := readJSON(u.resultFile(), &last); ok {
		st.Last = &last
	}
	if _, err := os.Stat(u.restoreFile()); err == nil {
		st.RestoreOnBoot = true
	}
	bes, err := boot.List(ctx, u.env(), cfg.Pool)
	if err != nil {
		return nil, err
	}
	for _, be := range bes {
		v := Version{Environment: be, Running: be.Dataset == booted}
		if v.Running {
			st.Running = be.Name
		}
		if st.Pending != nil && st.Pending.Dataset == be.Dataset && !v.Running {
			v.Trying = true
		}
		st.Versions = append(st.Versions, v)
	}
	return st, nil
}

// Stage -------------------------------------------------------------------

// carryOver lists this system's settings copied into a new version.
var carryOver = []string{
	"etc/hostname", "etc/hosts", "etc/hostid", "etc/timezone", "etc/localtime", "etc/fstab",
	"etc/machine-id", "etc/network/interfaces", "etc/resolv.conf",
	"etc/chrony/chrony.conf", "etc/dhcp/dhclient-enter-hooks.d/hardyos-dns",
	"etc/zfs/zpool.cache", "etc/modprobe.d/hardyos-zfs.conf",
}

// carryOverGlobs are copied when present.
var carryOverGlobs = []string{"etc/ssh/ssh_host_*", "etc/network/interfaces.d/*", TrustedKeysDir[1:] + "/*.pub"}

// StageResult is returned by Stage.
type StageResult struct {
	Version string `json:"version"`
	BE      string `json:"bootEnvironment"`
	Notes   string `json:"notes,omitempty"`
}

// Stage installs the bundle at bundlePath (inside UploadDir) as a new
// version that starts on the next restart. The bundle is deleted afterwards.
func (u *Updater) Stage(ctx context.Context, bundlePath string) (*StageResult, error) {
	clean := filepath.Clean(bundlePath)
	if !strings.HasPrefix(clean, u.UploadDir()+"/") || strings.Contains(bundlePath, "..") {
		return nil, fmt.Errorf("update files must be in %s", u.UploadDir())
	}
	cfg, err := u.bootConfig()
	if err != nil {
		return nil, err
	}
	if p, _ := u.PendingUpdate(); p != nil {
		return nil, fmt.Errorf("HardyOS %s is already waiting for a restart", p.Version)
	}
	booted := u.BootedDataset()
	if booted == "" || !strings.HasPrefix(booted, cfg.Pool+"/ROOT/") {
		return nil, errors.New("can't tell which version is running")
	}
	keys := u.Keys()
	if len(keys) == 0 {
		return nil, errors.New("this server trusts no release key yet, so it can't verify updates")
	}
	staging := u.path(filepath.Join(u.UploadDir(), "staging.squashfs"))
	_ = os.Remove(staging)
	m, err := Extract(u.path(clean), keys, staging)
	if err != nil {
		return nil, err
	}
	defer os.Remove(staging)
	if m.Arch != u.arch() {
		return nil, fmt.Errorf("this update is for %s, but this server is %s", m.Arch, u.arch())
	}
	be := boot.BEName(m.Version)
	ds := cfg.Pool + "/ROOT/" + be
	if res, err := u.Runner.Run(ctx, nil, "zfs", "list", "-H", "-o", "name", ds); err == nil && res.ExitCode == 0 {
		return nil, fmt.Errorf("HardyOS %s is already installed", m.Version)
	}
	fromVersion := ""
	if out, err := u.run(ctx, "zfs", "get", "-H", "-o", "value", boot.VersionProp, booted); err == nil {
		fromVersion = strings.TrimSpace(string(out))
	}

	if _, err := u.run(ctx, "zfs", "create", "-o", "canmount=noauto", "-o", "mountpoint=/", "-o", boot.VersionProp+"="+m.Version, ds); err != nil {
		return nil, err
	}
	ok := false
	mnt := "/run/hardyos/update/root"
	defer func() {
		_, _ = u.Runner.Run(context.WithoutCancel(ctx), nil, "umount", mnt)
		if !ok {
			_, _ = u.Runner.Run(context.WithoutCancel(ctx), nil, "zfs", "destroy", "-r", ds)
		}
	}()
	if err := os.MkdirAll(u.path(mnt), 0o755); err != nil {
		return nil, err
	}
	if _, err := u.run(ctx, "mount", "-t", "zfs", "-o", "zfsutil", ds, mnt); err != nil {
		return nil, err
	}
	if _, err := u.run(ctx, "unsquashfs", "-f", "-no-progress", "-d", mnt, filepath.Join(u.UploadDir(), "staging.squashfs")); err != nil {
		return nil, fmt.Errorf("unpack the system image: %w", err)
	}
	if err := u.carrySettings(mnt); err != nil {
		return nil, fmt.Errorf("copy settings to the new version: %w", err)
	}
	if err := install.FinishRoot(ctx, u.Runner, u.Root, mnt); err != nil {
		return nil, err
	}
	if _, err := boot.Sync(ctx, u.env(), cfg, boot.SyncOptions{Mounted: map[string]string{ds: mnt}}); err != nil && !isPartial(err) {
		return nil, fmt.Errorf("add the new version to the boot menu: %w", err)
	}
	if err := boot.SetNextBoot(ctx, u.env(), cfg, be); err != nil && !isPartial(err) {
		return nil, fmt.Errorf("choose the new version for the next boot: %w", err)
	}
	p := Pending{BE: be, Dataset: ds, Version: m.Version, FromBE: filepath.Base(booted), FromVersion: fromVersion, StagedAt: u.now(), Notes: m.Notes}
	if err := writeJSON(u.pendingFile(), p); err != nil {
		return nil, err
	}
	ok = true
	_ = os.Remove(u.path(clean))
	return &StageResult{Version: m.Version, BE: be, Notes: m.Notes}, nil
}

func isPartial(err error) bool {
	var pe *boot.PartialError
	return errors.As(err, &pe)
}

// carrySettings copies this system's identity and settings into the new root.
func (u *Updater) carrySettings(mnt string) error {
	copyOne := func(rel string) error {
		src := u.path("/" + rel)
		dst := u.path(filepath.Join(mnt, rel))
		fi, err := os.Lstat(src)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		_ = os.Remove(dst)
		if fi.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(src)
			if err != nil {
				return err
			}
			// resolv.conf may point into /run; the new system makes its own then.
			if rel == "etc/resolv.conf" {
				return nil
			}
			return os.Symlink(target, dst)
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, fi.Mode().Perm())
	}
	for _, rel := range carryOver {
		if err := copyOne(rel); err != nil {
			return err
		}
	}
	for _, g := range carryOverGlobs {
		matches, _ := filepath.Glob(u.path("/" + g))
		for _, m := range matches {
			rel, err := filepath.Rel(u.path("/"), m)
			if err != nil {
				return err
			}
			if err := copyOne(rel); err != nil {
				return err
			}
		}
	}
	return nil
}

// BeforeReboot snapshots the shared state just before restarting into a
// pending update, so a failed update can be undone cleanly.
func (u *Updater) BeforeReboot(ctx context.Context) error {
	p, err := u.PendingUpdate()
	if err != nil || p == nil || p.Snapshot != "" {
		return err
	}
	cfg, err := u.bootConfig()
	if err != nil {
		return err
	}
	snap := fmt.Sprintf("%s/hardyos@pre-%s-%s", cfg.Pool, p.BE, u.now().Format("20060102-150405"))
	// Take the snapshot without the pending marker in it: restoring this
	// snapshot later (going back to this version by hand) must never bring
	// back a marker for an update that was long confirmed, whichever
	// version's code does the restoring.
	if err := os.Remove(u.pendingFile()); err != nil {
		return err
	}
	_, snapErr := u.run(ctx, "zfs", "snapshot", snap)
	if snapErr == nil {
		p.Snapshot = snap
	}
	if err := writeJSON(u.pendingFile(), p); err != nil {
		return err
	}
	return snapErr
}

// Confirm and boot-time checks ------------------------------------------------

// ConfirmResult says what Confirm did.
type ConfirmResult struct {
	Confirmed bool   `json:"confirmed"`
	Version   string `json:"version,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// Confirm makes a pending update permanent. hardyd calls it once it is
// healthy on the new version.
func (u *Updater) Confirm(ctx context.Context) (*ConfirmResult, error) {
	p, err := u.PendingUpdate()
	if err != nil {
		return nil, err
	}
	if p == nil {
		return &ConfirmResult{Reason: "no update is pending"}, nil
	}
	if u.BootedDataset() != p.Dataset {
		return &ConfirmResult{Reason: "the new version isn't running yet"}, nil
	}
	cfg, err := u.bootConfig()
	if err != nil {
		return nil, err
	}
	if _, err := u.run(ctx, "zpool", "set", "bootfs="+p.Dataset, cfg.Pool); err != nil {
		return nil, err
	}
	if _, err := boot.Sync(ctx, u.env(), cfg, boot.SyncOptions{}); err != nil && !isPartial(err) {
		return nil, err
	}
	_ = boot.ClearNextBoot(ctx, u.env(), cfg)
	if err := os.Remove(u.pendingFile()); err != nil {
		return nil, err
	}
	u.setResult(true, p.Version, fmt.Sprintf("Updated to HardyOS %s.", p.Version))
	u.Cleanup(ctx, KeepVersions)
	return &ConfirmResult{Confirmed: true, Version: p.Version}, nil
}

// OnBoot runs once when hardyd-priv starts, before hardyd uses the state
// dataset. It finishes a rollback, detects a failed update, or starts the
// confirmation watchdog for a new version.
func (u *Updater) OnBoot(ctx context.Context) {
	cfg, err := u.bootConfig()
	if err != nil {
		return
	}
	// A requested settings restore (switching back to an older version).
	var rm restoreMarker
	if ok, _ := readJSON(u.restoreFile(), &rm); ok {
		_ = os.Remove(u.restoreFile())
		if rm.Snapshot != "" && strings.HasPrefix(rm.Snapshot, cfg.Pool+"/hardyos@pre-") {
			if _, err := u.run(ctx, "zfs", "rollback", "-r", rm.Snapshot); err != nil {
				u.setResult(false, rm.Version, "Couldn't restore settings from before the update: "+err.Error())
			} else {
				// The snapshot was taken just before restarting into an update,
				// so it holds that update's pending marker. The update was
				// confirmed back then; the marker is stale and must not make
				// this boot look like a failed update.
				_ = os.Remove(u.pendingFile())
				_ = os.Remove(u.restoreFile())
				u.setResult(true, rm.Version, fmt.Sprintf("Switched to HardyOS %s and restored settings from before the update.", rm.Version))
			}
		}
		return
	}

	p, err := u.PendingUpdate()
	if err != nil || p == nil {
		return
	}
	booted := u.BootedDataset()
	if booted == p.Dataset {
		go u.watch(ctx, p.Dataset)
		return
	}
	if booted == "" {
		return
	}
	// Back on another version with the update unconfirmed: it failed. Only
	// ever touch the update's own boot environment and state snapshot.
	if !strings.HasPrefix(p.Dataset, cfg.Pool+"/ROOT/") || p.Dataset == booted ||
		(p.Snapshot != "" && !strings.HasPrefix(p.Snapshot, cfg.Pool+"/hardyos@pre-")) {
		_ = os.Remove(u.pendingFile())
		return
	}
	if p.Snapshot != "" {
		if _, err := u.run(ctx, "zfs", "rollback", "-r", p.Snapshot); err != nil {
			_ = err // keep going: the old version may still read the newer state
		}
		_, _ = u.run(ctx, "zfs", "destroy", p.Snapshot)
	}
	_ = os.Remove(u.pendingFile())
	_, _ = u.run(ctx, "zfs", "destroy", "-r", p.Dataset)
	_, _ = boot.Sync(ctx, u.env(), cfg, boot.SyncOptions{})
	_ = boot.ClearNextBoot(ctx, u.env(), cfg)
	from := p.FromVersion
	if from == "" {
		from = "the previous version"
	}
	u.setResult(false, p.Version, fmt.Sprintf("HardyOS %s didn't start correctly, so the server went back to %s. Nothing else changed.", p.Version, from))
}

func (u *Updater) confirmTimeout() time.Duration {
	if u.ConfirmTimeout > 0 {
		return u.ConfirmTimeout
	}
	return ConfirmTimeout
}

// watch restarts the server if the new version isn't confirmed in time. The
// one-time boot choice is already used up, so it comes back on the previous
// version and OnBoot records the failure.
func (u *Updater) watch(ctx context.Context, dataset string) {
	t := time.NewTimer(u.confirmTimeout())
	defer t.Stop()
	select {
	case <-ctx.Done():
		return
	case <-t.C:
	}
	if p, _ := u.PendingUpdate(); p != nil && p.Dataset == dataset && u.BootedDataset() == dataset && u.Reboot != nil {
		u.Reboot()
	}
}

// Switching and cleanup -------------------------------------------------------

// Activate makes another installed version the default; it starts on the
// next restart. With restoreSettings, settings are also restored from the
// snapshot taken before the running version was installed.
func (u *Updater) Activate(ctx context.Context, name string, restoreSettings bool) error {
	cfg, err := u.bootConfig()
	if err != nil {
		return err
	}
	if p, _ := u.PendingUpdate(); p != nil {
		return fmt.Errorf("finish or undo the pending update to %s first", p.Version)
	}
	ds, err := u.versionDataset(ctx, cfg, name)
	if err != nil {
		return err
	}
	booted := u.BootedDataset()
	if ds == booted {
		return errors.New("that version is already running")
	}
	snap := ""
	if restoreSettings {
		snap = u.latestSnapshot(ctx, cfg, filepath.Base(booted))
		if snap == "" {
			return errors.New("there is no saved copy of the settings from before this version was installed")
		}
	}
	if _, err := u.run(ctx, "zpool", "set", "bootfs="+ds, cfg.Pool); err != nil {
		return err
	}
	if _, err := boot.Sync(ctx, u.env(), cfg, boot.SyncOptions{}); err != nil && !isPartial(err) {
		return err
	}
	_ = boot.ClearNextBoot(ctx, u.env(), cfg)
	_ = os.Remove(u.restoreFile())
	if snap != "" {
		version := name
		if out, err := u.run(ctx, "zfs", "get", "-H", "-o", "value", boot.VersionProp, ds); err == nil {
			if v := strings.TrimSpace(string(out)); v != "" && v != "-" {
				version = v
			}
		}
		return writeJSON(u.restoreFile(), restoreMarker{Snapshot: snap, Reason: "switch to " + name, Version: version})
	}
	return nil
}

// Delete removes an installed version that is neither running nor the default.
func (u *Updater) Delete(ctx context.Context, name string) error {
	cfg, err := u.bootConfig()
	if err != nil {
		return err
	}
	ds, err := u.versionDataset(ctx, cfg, name)
	if err != nil {
		return err
	}
	if ds == u.BootedDataset() {
		return errors.New("the running version can't be removed")
	}
	if def, _ := u.run(ctx, "zpool", "get", "-H", "-o", "value", "bootfs", cfg.Pool); strings.TrimSpace(string(def)) == ds {
		return errors.New("the version that starts by default can't be removed")
	}
	if p, _ := u.PendingUpdate(); p != nil && p.Dataset == ds {
		_ = os.Remove(u.pendingFile())
		_ = boot.ClearNextBoot(ctx, u.env(), cfg)
	}
	if _, err := u.run(ctx, "zfs", "destroy", "-r", ds); err != nil {
		return err
	}
	u.destroySnapshots(ctx, cfg, name)
	if _, err := boot.Sync(ctx, u.env(), cfg, boot.SyncOptions{}); err != nil && !isPartial(err) {
		return err
	}
	return nil
}

// Cleanup removes the oldest versions beyond keep, never the running one,
// the default one or a pending one.
func (u *Updater) Cleanup(ctx context.Context, keep int) {
	cfg, err := u.bootConfig()
	if err != nil {
		return
	}
	bes, err := boot.List(ctx, u.env(), cfg.Pool)
	if err != nil {
		return
	}
	booted := u.BootedDataset()
	p, _ := u.PendingUpdate()
	sort.SliceStable(bes, func(i, j int) bool { return bes[i].Created > bes[j].Created })
	removed := false
	for i, be := range bes {
		if i < keep || be.Default || be.Dataset == booted || (p != nil && p.Dataset == be.Dataset) {
			continue
		}
		if _, err := u.run(ctx, "zfs", "destroy", "-r", be.Dataset); err == nil {
			u.destroySnapshots(ctx, cfg, be.Name)
			removed = true
		}
	}
	if removed {
		_, _ = boot.Sync(ctx, u.env(), cfg, boot.SyncOptions{})
	}
}

func (u *Updater) versionDataset(ctx context.Context, cfg *boot.Config, name string) (string, error) {
	bes, err := boot.List(ctx, u.env(), cfg.Pool)
	if err != nil {
		return "", err
	}
	for _, be := range bes {
		if be.Name == name {
			return be.Dataset, nil
		}
	}
	return "", fmt.Errorf("version %q is not installed", name)
}

// stateSnapshots lists <pool>/hardyos@pre-<be>-* snapshots, oldest first.
func (u *Updater) stateSnapshots(ctx context.Context, cfg *boot.Config, be string) []string {
	out, err := u.run(ctx, "zfs", "list", "-H", "-t", "snapshot", "-o", "name", "-s", "creation", cfg.Pool+"/hardyos")
	if err != nil {
		return nil
	}
	prefix := cfg.Pool + "/hardyos@pre-" + be + "-"
	var snaps []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(line, prefix) {
			snaps = append(snaps, line)
		}
	}
	return snaps
}

func (u *Updater) latestSnapshot(ctx context.Context, cfg *boot.Config, be string) string {
	s := u.stateSnapshots(ctx, cfg, be)
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}

func (u *Updater) destroySnapshots(ctx context.Context, cfg *boot.Config, be string) {
	for _, s := range u.stateSnapshots(ctx, cfg, be) {
		_, _ = u.run(ctx, "zfs", "destroy", s)
	}
}
