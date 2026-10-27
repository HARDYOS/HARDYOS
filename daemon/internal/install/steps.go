package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/boot"
	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Installer runs the install steps. Every file path is prefixed with Root
// ("/" for real, a temp dir in tests).
type Installer struct {
	Runner sysexec.Runner
	Root   string
	// Target is where the new system is assembled (default /target).
	Target string
	// Medium is the mounted live medium holding live/filesystem.squashfs
	// (default /run/live/medium).
	Medium string
	// Version is the HardyOS version being installed.
	Version string
	// ListDisks scans the disks (hw.ListDisks on a real system).
	ListDisks func(ctx context.Context) ([]hw.Disk, error)
	// SettleTimeout bounds the wait for new partition device nodes.
	SettleTimeout time.Duration
	// PoolName overrides the boot pool's name (tests; default rpool).
	PoolName string
}

func (in *Installer) pool() string {
	if in.PoolName == "" {
		return Pool
	}
	return in.PoolName
}

func (in *Installer) path(p string) string { return filepath.Join(in.Root, p) }

func (in *Installer) target() string {
	if in.Target == "" {
		return "/target"
	}
	return in.Target
}

// T returns a path inside the target system (without the Root prefix).
func (in *Installer) T(p string) string { return filepath.Join(in.target(), p) }

func (in *Installer) medium() string {
	if in.Medium == "" {
		return "/run/live/medium"
	}
	return in.Medium
}

// BEName is the boot environment this install creates.
func (in *Installer) BEName() string { return boot.BEName(in.Version) }

// BEDataset is the root dataset of the new boot environment.
func (in *Installer) BEDataset() string { return in.pool() + "/ROOT/" + in.BEName() }

func (in *Installer) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	out, err := sysexec.Output(ctx, in.Runner, name, args...)
	if err != nil {
		var ce *sysexec.CommandError
		if errors.As(err, &ce) {
			return out, errors.New(ce.Error())
		}
	}
	return out, err
}

// try runs a command whose failure doesn't matter (cleanup of things that
// may not exist).
func (in *Installer) try(ctx context.Context, name string, args ...string) {
	_, _ = in.Runner.Run(ctx, nil, name, args...)
}

// DiskCheck is the result of checking one chosen disk.
type DiskCheck struct {
	Disk     hw.Disk  `json:"disk"`
	Warnings []string `json:"warnings"`
}

// Check validates the plan against the hardware without changing anything.
func (in *Installer) Check(ctx context.Context, p Plan) ([]DiskCheck, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(in.path(filepath.Join("/usr/share/zoneinfo", p.Timezone))); err != nil {
		return nil, fmt.Errorf("unknown timezone %q", p.Timezone)
	}
	if _, err := in.squashfs(); err != nil {
		return nil, err
	}
	disks, err := in.ListDisks(ctx)
	if err != nil {
		return nil, fmt.Errorf("scan disks: %w", err)
	}
	byPath := map[string]hw.Disk{}
	for _, d := range disks {
		byPath[d.ByID] = d
	}
	var out []DiskCheck
	var smallest uint64
	for _, path := range p.Disks {
		d, ok := byPath[path]
		if !ok {
			return nil, fmt.Errorf("disk %s not found (was it removed?)", path)
		}
		if err := Eligible(d); err != nil {
			return nil, err
		}
		var warn []string
		switch d.Usage {
		case hw.UsageBoot, hw.UsagePool:
			warn = append(warn, fmt.Sprintf("member of pool %s: it will be destroyed", d.Pool))
		case hw.UsageHasData:
			warn = append(warn, "has existing data ("+d.UsageDetail+"): it will be erased")
		}
		if d.Removable {
			warn = append(warn, "is a removable (USB) disk; an internal disk is more reliable")
		}
		if d.Kind == hw.KindHDD {
			warn = append(warn, "is a hard drive; an SSD boots and updates much faster")
		}
		if smallest == 0 || d.SizeBytes < smallest {
			smallest = d.SizeBytes
		}
		out = append(out, DiskCheck{Disk: d, Warnings: append([]string{}, warn...)})
	}
	if len(out) > 1 {
		for i := range out {
			if out[i].Disk.SizeBytes > smallest+smallest/10 {
				out[i].Warnings = append(out[i].Warnings, "is larger than the other boot disk; the mirror only uses the smaller size")
			}
		}
	}
	return out, nil
}

// Eligible says whether a disk may become a boot disk. Old pool members
// (including a previous HardyOS install) are allowed; the disk running the
// live system and mounted disks are not.
func Eligible(d hw.Disk) error {
	switch {
	case d.Usage == hw.UsageMounted:
		return fmt.Errorf("disk %s is in use: %s", d.ByID, d.UsageDetail)
	case d.Usage == hw.UsageBoot && d.Pool == "":
		return fmt.Errorf("disk %s holds the running system", d.ByID)
	case d.SizeBytes < MinDiskBytes:
		return fmt.Errorf("disk %s is too small: boot disks need at least 16 GB", d.ByID)
	}
	return nil
}

func (in *Installer) squashfs() (string, error) {
	matches, _ := filepath.Glob(in.path(filepath.Join(in.medium(), "live", "*.squashfs")))
	sort.Strings(matches)
	host := func(m string) string { return filepath.Join(in.medium(), "live", filepath.Base(m)) }
	for _, m := range matches {
		if filepath.Base(m) == "filesystem.squashfs" {
			return host(m), nil
		}
	}
	if len(matches) > 0 {
		return host(matches[0]), nil
	}
	return "", errors.New("the HardyOS system image was not found on the install medium")
}

// Reset undoes a previous, interrupted attempt so a new one can start.
func (in *Installer) Reset(ctx context.Context) {
	_ = unbindSystemDirs(ctx, in.Runner, in.Root, in.target())
	if res, err := in.Runner.Run(ctx, nil, "zpool", "list", "-H", in.pool()); err == nil && res.ExitCode == 0 {
		in.try(ctx, "zpool", "export", "-f", in.pool())
	}
}

// Partition erases the chosen disks and creates the HardyOS partition layout.
func (in *Installer) Partition(ctx context.Context, p Plan, confirmWipe bool) error {
	if !confirmWipe {
		return errors.New("confirmWipe must be true: the boot disks will be erased")
	}
	checks, err := in.Check(ctx, p)
	if err != nil {
		return err
	}
	in.Reset(ctx)
	for _, c := range checks {
		d := c.Disk
		for _, part := range d.Partitions {
			in.try(ctx, "zpool", "labelclear", "-f", "/dev/"+part.Name)
			in.try(ctx, "wipefs", "-a", "/dev/"+part.Name)
		}
		in.try(ctx, "zpool", "labelclear", "-f", d.ByID)
		if _, err := in.run(ctx, "wipefs", "-a", d.ByID); err != nil {
			return err
		}
		if _, err := in.run(ctx, "sgdisk", "--zap-all", d.ByID); err != nil {
			return err
		}
		if _, err := in.run(ctx, "sgdisk",
			"-a1", "-n1:24K:+1000K", "-t1:EF02", "-c1:hardyos-bios",
			"-a2048", "-n2:1M:+1G", "-t2:EF00", "-c2:hardyos-esp",
			"-n3:0:0", "-t3:BF00", "-c3:hardyos-zfs",
			d.ByID); err != nil {
			return err
		}
		in.try(ctx, "partprobe", d.ByID)
	}
	in.try(ctx, "udevadm", "settle", "--timeout=30")
	for _, path := range p.Disks {
		for _, n := range []int{2, 3} {
			if err := in.waitFor(ctx, Partition(path, n)); err != nil {
				return err
			}
		}
		if _, err := in.run(ctx, "mkfs.vfat", "-F", "32", "-n", "HARDYOS-EFI", Partition(path, 2)); err != nil {
			return err
		}
	}
	return nil
}

func (in *Installer) waitFor(ctx context.Context, dev string) error {
	timeout := in.SettleTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(in.path(dev)); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("partition %s did not appear", dev)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// CreatePool creates rpool on partition 3 of every disk and mounts the new
// boot environment at the target.
func (in *Installer) CreatePool(ctx context.Context, p Plan) error {
	if err := p.Validate(); err != nil {
		return err
	}
	// The pool records this host ID; the installed system gets the same one.
	if _, err := os.Stat(in.path("/etc/hostid")); err != nil {
		if _, err := in.run(ctx, "zgenhostid"); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(in.path(in.target()), 0o755); err != nil {
		return err
	}
	args := []string{"create", "-f",
		"-o", "ashift=12", "-o", "autotrim=on",
		"-O", "acltype=posixacl", "-O", "xattr=sa", "-O", "dnodesize=auto",
		"-O", "compression=lz4", "-O", "normalization=formD", "-O", "relatime=on",
		"-O", "canmount=off", "-O", "mountpoint=none",
		"-R", in.target(), in.pool()}
	if len(p.Disks) > 1 {
		args = append(args, "mirror")
	}
	for _, d := range p.Disks {
		args = append(args, Partition(d, 3))
	}
	if _, err := in.run(ctx, "zpool", args...); err != nil {
		return err
	}
	steps := [][]string{
		{"zfs", "create", "-o", "canmount=off", "-o", "mountpoint=none", in.pool() + "/ROOT"},
		{"zfs", "create", "-o", "canmount=noauto", "-o", "mountpoint=/", "-o", boot.VersionProp + "=" + in.Version, in.BEDataset()},
		{"zfs", "mount", in.BEDataset()},
		// Shared state: settings, accounts and the boot configuration survive
		// switching between boot environments.
		{"zfs", "create", "-o", "mountpoint=/var/lib/hardyos", in.pool() + "/hardyos"},
		{"zpool", "set", "bootfs=" + in.BEDataset(), in.pool()},
	}
	for _, s := range steps {
		if _, err := in.run(ctx, s[0], s[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// CopySystem unpacks the live system image into the target.
func (in *Installer) CopySystem(ctx context.Context) error {
	sq, err := in.squashfs()
	if err != nil {
		return err
	}
	if _, err := in.run(ctx, "unsquashfs", "-f", "-no-progress", "-d", in.target(), sq); err != nil {
		return err
	}
	return in.ensureKernels()
}

// ensureKernels makes sure every kernel in the image has its vmlinuz in
// /boot (live-build may keep it only on the medium).
func (in *Installer) ensureKernels() error {
	mods, err := os.ReadDir(in.path(in.T("lib/modules")))
	if err != nil {
		return fmt.Errorf("the system image has no kernel modules: %w", err)
	}
	found := 0
	for _, m := range mods {
		ver := m.Name()
		dst := in.path(in.T("boot/vmlinuz-" + ver))
		if _, err := os.Stat(dst); err == nil {
			found++
			continue
		}
		for _, src := range []string{"live/vmlinuz-" + ver, "live/vmlinuz"} {
			b, err := os.ReadFile(in.path(filepath.Join(in.medium(), src)))
			if err != nil {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(dst, b, 0o644); err != nil {
				return err
			}
			found++
			break
		}
	}
	if found == 0 {
		return errors.New("no kernel found in the system image or on the install medium")
	}
	return nil
}

// Configure writes the chosen settings into the target, removes the
// live-system packages and builds the initramfs with ZFS support.
func (in *Installer) Configure(ctx context.Context, p Plan, seed Seed) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := seed.Validate(); err != nil {
		return err
	}
	files := map[string]string{
		"etc/hostname":           p.Hostname + "\n",
		"etc/hosts":              renderHosts(p.Hostname),
		"etc/timezone":           p.Timezone + "\n",
		"etc/fstab":              "# HardyOS: ZFS mounts its own datasets. The EFI partitions are mounted\n# only while \"hardyctl boot-sync\" updates them.\n",
		"etc/network/interfaces": RenderInterfaces(p.Network, in.nics()),
		// systemd creates a fresh machine ID on first boot.
		"etc/machine-id": "",
	}
	if p.Network.Mode == "static" && len(p.Network.DNS) > 0 {
		files["etc/resolv.conf"] = renderResolv(p.Network.DNS)
	}
	for rel, content := range files {
		dst := in.path(in.T(rel))
		_ = os.Remove(dst) // resolv.conf may be a symlink into /run
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(dst, []byte(content), 0o644); err != nil {
			return err
		}
	}
	if hostid, err := os.ReadFile(in.path("/etc/hostid")); err == nil {
		if err := os.WriteFile(in.path(in.T("etc/hostid")), hostid, 0o644); err != nil {
			return err
		}
	}
	localtime := in.path(in.T("etc/localtime"))
	_ = os.Remove(localtime)
	if err := os.Symlink(filepath.Join("/usr/share/zoneinfo", p.Timezone), localtime); err != nil {
		return err
	}
	if keys, _ := filepath.Glob(in.path(in.T("etc/ssh/ssh_host_*"))); len(keys) > 0 {
		for _, k := range keys {
			_ = os.Remove(k)
		}
	}
	if err := in.writeSeed(seed); err != nil {
		return err
	}

	return FinishRoot(ctx, in.Runner, in.Root, in.target())
}

func (in *Installer) nics() []string {
	entries, err := os.ReadDir(in.path("/sys/class/net"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if _, err := os.Stat(in.path(filepath.Join("/sys/class/net", e.Name(), "device"))); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func (in *Installer) writeSeed(seed Seed) error {
	uid, gid, err := lookupUser(in.path(in.T("etc/passwd")), "hardyd")
	if err != nil {
		return fmt.Errorf("the system image has no hardyd account: %w", err)
	}
	dir := in.path(in.T("var/lib/hardyos"))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.Chown(dir, uid, gid); err != nil && !errors.Is(err, os.ErrPermission) {
		return err
	}
	_ = os.Chmod(dir, 0o750)
	b, err := json.Marshal(seed)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, filepath.Base(SeedFile))
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil && !errors.Is(err, os.ErrPermission) {
		return err
	}
	return nil
}

// lookupUser reads uid and gid from a passwd file.
func lookupUser(passwd, name string) (int, int, error) {
	b, err := os.ReadFile(passwd)
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 4 && f[0] == name {
			uid, err1 := strconv.Atoi(f[2])
			gid, err2 := strconv.Atoi(f[3])
			if err1 != nil || err2 != nil {
				return 0, 0, fmt.Errorf("bad passwd entry for %s", name)
			}
			return uid, gid, nil
		}
	}
	return 0, 0, fmt.Errorf("user %s not found", name)
}

// InstallBootloader writes the boot configuration and installs GRUB and the
// kernel on every boot disk.
func (in *Installer) InstallBootloader(ctx context.Context, p Plan) error {
	if err := p.Validate(); err != nil {
		return err
	}
	cfg := &boot.Config{Pool: in.pool()}
	for _, d := range p.Disks {
		out, err := in.run(ctx, "blkid", "-s", "PARTUUID", "-o", "value", Partition(d, 2))
		if err != nil {
			return fmt.Errorf("read EFI partition ID: %w", err)
		}
		cfg.Disks = append(cfg.Disks, boot.Disk{ByID: d, ESPPartUUID: strings.TrimSpace(string(out))})
	}
	if err := cfg.Save(in.path(in.T(boot.ConfigPath))); err != nil {
		return err
	}
	env := boot.Env{Runner: in.Runner, Root: in.Root}
	if _, err := boot.Sync(ctx, env, cfg, boot.SyncOptions{
		InstallGRUB: true,
		Mounted:     map[string]string{in.BEDataset(): in.target()},
	}); err != nil {
		return err
	}
	boot.SetFirmwareEntries(ctx, env, p.Disks)
	return nil
}

// Finish unmounts the target and exports the pool so the new system imports
// it cleanly on first boot.
func (in *Installer) Finish(ctx context.Context) error {
	uerr := unbindSystemDirs(ctx, in.Runner, in.Root, in.target())
	if _, err := in.run(ctx, "zpool", "export", in.pool()); err != nil {
		// Say what keeps the pool busy: mounts left under the target and
		// the processes holding files there.
		var why []string
		if uerr != nil {
			why = append(why, uerr.Error())
		}
		if left := mountsUnder(in.Root, in.target(), false); len(left) > 0 {
			why = append(why, "still mounted: "+strings.Join(left, ", "))
		}
		if h := Holders(in.Root, in.target()); len(h) > 0 {
			why = append(why, "in use by "+strings.Join(h, ", "))
		}
		if len(why) > 0 {
			return fmt.Errorf("%w (%s)", err, strings.Join(why, "; "))
		}
		return err
	}
	return nil
}
