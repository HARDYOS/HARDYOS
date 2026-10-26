// Package boot manages how HardyOS boots: ZFS boot environments (one root
// dataset per installed version under <pool>/ROOT) and the GRUB setup on each
// boot disk's EFI system partition.
//
// GRUB never reads ZFS. Each boot environment's kernel and initramfs are
// copied to every ESP under /hardyos/<be>/, and grub.cfg lists one menu entry
// per boot environment with the pool's bootfs as the default. That keeps all
// ZFS pool features available and works the same for UEFI and BIOS boots.
package boot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// ConfigPath is where the boot configuration lives on an installed system.
// It sits on the shared state dataset so every boot environment sees it.
const ConfigPath = "/var/lib/hardyos/boot.json"

// VersionProp is the ZFS user property recording which HardyOS version a boot
// environment holds.
const VersionProp = "org.hardyos:version"

// MaxEntries bounds how many boot environments get kernels on the ESPs. Each
// takes roughly 100 MB; the default environment is always included.
const MaxEntries = 5

// Disk is one boot disk: its stable whole-disk path and its ESP.
type Disk struct {
	ByID        string `json:"byId"`
	ESPPartUUID string `json:"espPartUUID"`
}

// Config describes the boot disks. The installer writes it.
type Config struct {
	Pool  string `json:"pool"`
	Disks []Disk `json:"disks"`
}

// LoadConfig reads the boot configuration. A missing file returns ErrNoConfig.
func LoadConfig(path string) (*Config, error) {
	b, err := rootfile.ReadFile(path) // root acts on it: it must be root's
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoConfig
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Pool == "" || len(c.Disks) == 0 {
		return nil, fmt.Errorf("%s lists no boot disks", path)
	}
	return &c, nil
}

// Save writes the configuration atomically.
func (c *Config) Save(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(b, '\n'), 0o644)
}

// ErrNoConfig means the system wasn't installed by the HardyOS installer (for
// example the live ISO, or a package installed on plain Debian).
var ErrNoConfig = errors.New("no HardyOS boot configuration")

// Environment is one boot environment.
type Environment struct {
	Dataset string `json:"dataset"` // rpool/ROOT/hardyos-0.1.0
	Name    string `json:"name"`    // hardyos-0.1.0
	Version string `json:"version"` // 0.1.0, from VersionProp
	Created int64  `json:"created"` // unix seconds
	Default bool   `json:"default"` // the pool's bootfs
}

// Env is what boot operations need from the host. Root prefixes every file
// path ("/" on a real system, a temp dir in tests).
type Env struct {
	Runner sysexec.Runner
	Root   string
	// MountDir is where ESPs and inactive boot environments are mounted
	// temporarily (inside Root).
	MountDir string
}

func (e Env) path(p string) string { return filepath.Join(e.Root, p) }

func (e Env) mountDir() string {
	if e.MountDir == "" {
		return "/run/hardyos/boot"
	}
	return e.MountDir
}

// BEName turns a HardyOS version into a boot environment name:
// "0.1.0~dev.20261024.gabc" -> "hardyos-0.1.0-dev.20261024.gabc".
func BEName(version string) string {
	clean := regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(version, "-")
	clean = strings.Trim(clean, "-.")
	if clean == "" {
		clean = "unknown"
	}
	if len(clean) > 100 {
		clean = clean[:100]
	}
	return "hardyos-" + clean
}

// List returns the boot environments under <pool>/ROOT, newest first, with the
// default (bootfs) marked.
func List(ctx context.Context, env Env, pool string) ([]Environment, error) {
	out, err := sysexec.Output(ctx, env.Runner, "zfs", "list", "-H", "-p", "-o", "name,creation,"+VersionProp, "-d", "1", "-r", pool+"/ROOT")
	if err != nil {
		return nil, err
	}
	bootfs, err := sysexec.Output(ctx, env.Runner, "zpool", "get", "-H", "-o", "value", "bootfs", pool)
	if err != nil {
		return nil, err
	}
	def := strings.TrimSpace(string(bootfs))
	var bes []Environment
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 3 || f[0] == pool+"/ROOT" {
			continue
		}
		created, _ := strconv.ParseInt(f[1], 10, 64)
		ver := f[2]
		if ver == "-" {
			ver = ""
		}
		bes = append(bes, Environment{
			Dataset: f[0], Name: f[0][strings.LastIndex(f[0], "/")+1:],
			Version: ver, Created: created, Default: f[0] == def,
		})
	}
	sort.SliceStable(bes, func(i, j int) bool { return bes[i].Created > bes[j].Created })
	return bes, nil
}

// Kernel is a kernel and initramfs pair inside a boot environment.
type Kernel struct {
	Version string
	Vmlinuz string // full path on the host
	Initrd  string
}

// FindKernel returns the newest kernel with an initramfs in bootDir.
func FindKernel(bootDir string) (*Kernel, error) {
	entries, err := os.ReadDir(bootDir)
	if err != nil {
		return nil, err
	}
	var vers []string
	for _, e := range entries {
		if v, ok := strings.CutPrefix(e.Name(), "vmlinuz-"); ok {
			if _, err := os.Stat(filepath.Join(bootDir, "initrd.img-"+v)); err == nil {
				vers = append(vers, v)
			}
		}
	}
	if len(vers) == 0 {
		return nil, fmt.Errorf("no kernel with an initramfs in %s", bootDir)
	}
	sort.Slice(vers, func(i, j int) bool { return versionLess(vers[i], vers[j]) })
	v := vers[len(vers)-1]
	return &Kernel{Version: v, Vmlinuz: filepath.Join(bootDir, "vmlinuz-"+v), Initrd: filepath.Join(bootDir, "initrd.img-"+v)}, nil
}

// versionLess compares kernel versions numerically where they are numbers:
// 6.12.9 < 6.12.10.
func versionLess(a, b string) bool {
	split := regexp.MustCompile(`[0-9]+|[^0-9]+`)
	pa, pb := split.FindAllString(a, -1), split.FindAllString(b, -1)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		if ea == nil && eb == nil {
			if na != nb {
				return na < nb
			}
			continue
		}
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}

// MenuEntry is one GRUB menu entry.
type MenuEntry struct {
	ID      string // boot environment name
	Title   string
	Dataset string
	Created int64 // unix seconds; newer than the default means "trying"
}

// RenderGrub builds grub.cfg. entries[0] is the default.
func RenderGrub(entries []MenuEntry) string {
	var b strings.Builder
	b.WriteString("# Generated by HardyOS. Do not edit: changes are overwritten by \"hardyctl boot-sync\".\n")
	b.WriteString("insmod part_gpt\ninsmod fat\ninsmod all_video\n")
	b.WriteString("serial --unit=0 --speed=115200\nterminal_input console serial\nterminal_output console serial\n")
	b.WriteString("set timeout=5\n")
	if len(entries) > 0 {
		fmt.Fprintf(&b, "set default=%q\n", entries[0].ID)
	}
	// A one-time choice (an update being tried) overrides the default once:
	// it is cleared before booting, so if that system never comes up, the
	// next boot goes back to the default.
	b.WriteString(`if [ -s $prefix/grubenv ]; then
	load_env next_entry
fi
if [ "${next_entry}" ]; then
	set default="${next_entry}"
	set next_entry=
	save_env next_entry
fi
`)
	for i, e := range entries {
		title := e.Title
		switch {
		case i > 0 && e.Created > entries[0].Created:
			title += " (trying)"
		case i > 0:
			title += " (previous)"
		}
		fmt.Fprintf(&b, "\nmenuentry %q --id %q {\n", title, e.ID)
		fmt.Fprintf(&b, "\tlinux /hardyos/%s/vmlinuz root=ZFS=%s boot=zfs console=ttyS0,115200 console=tty0 quiet\n", e.ID, e.Dataset)
		fmt.Fprintf(&b, "\tinitrd /hardyos/%s/initrd.img\n}\n", e.ID)
	}
	b.WriteString("\nmenuentry \"Firmware settings\" --id firmware {\n\tfwsetup\n}\n")
	return b.String()
}

// SyncOptions controls Sync.
type SyncOptions struct {
	// InstallGRUB (re)installs the boot loader on every disk, not just the
	// kernels and menu. The installer and disk replacement set it.
	InstallGRUB bool
	// Mounted maps boot environment datasets to where they are already
	// mounted (the installer's target). Others are found in /proc/mounts or
	// mounted read-only for the copy.
	Mounted map[string]string
}

// Sync copies each boot environment's kernel to every ESP and rewrites the
// GRUB menu. It returns the menu entries written, default first.
func Sync(ctx context.Context, env Env, cfg *Config, opts SyncOptions) ([]MenuEntry, error) {
	bes, err := List(ctx, env, cfg.Pool)
	if err != nil {
		return nil, fmt.Errorf("list boot environments: %w", err)
	}
	if len(bes) == 0 {
		return nil, fmt.Errorf("no boot environments under %s/ROOT", cfg.Pool)
	}
	// Default first, then newest.
	sort.SliceStable(bes, func(i, j int) bool { return bes[i].Default && !bes[j].Default })

	mounts := readMounts(env.path("/proc/mounts"))
	for k, v := range opts.Mounted {
		mounts[k] = v
	}

	var chosen []staged
	var cleanups []func()
	defer func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}()
	for _, be := range bes {
		if len(chosen) == MaxEntries {
			break
		}
		root, ok := mounts[be.Dataset]
		if !ok {
			dir := filepath.Join(env.mountDir(), "be", be.Name)
			if err := os.MkdirAll(env.path(dir), 0o755); err != nil {
				return nil, err
			}
			if _, err := sysexec.Output(ctx, env.Runner, "mount", "-t", "zfs", "-o", "ro,zfsutil", be.Dataset, dir); err != nil {
				if be.Default {
					return nil, fmt.Errorf("mount %s: %w", be.Dataset, err)
				}
				continue
			}
			cleanups = append(cleanups, func() { _, _ = env.Runner.Run(context.Background(), nil, "umount", dir) })
			root = dir
		}
		k, err := FindKernel(env.path(filepath.Join(root, "boot")))
		if err != nil {
			if be.Default {
				return nil, fmt.Errorf("boot environment %s: %w", be.Name, err)
			}
			continue
		}
		title := "HardyOS"
		if be.Version != "" {
			title += " " + be.Version
		} else {
			title += " (" + be.Name + ")"
		}
		chosen = append(chosen, staged{MenuEntry{ID: be.Name, Title: title, Dataset: be.Dataset, Created: be.Created}, k})
	}
	// bes[0] is the default (or the newest when bootfs is unset); it must boot.
	if len(chosen) == 0 || chosen[0].entry.Dataset != bes[0].Dataset {
		return nil, errors.New("the default boot environment has no usable kernel")
	}
	entries := make([]MenuEntry, len(chosen))
	for i, c := range chosen {
		entries[i] = c.entry
	}
	grubCfg := RenderGrub(entries)

	var failed []string
	for i, d := range cfg.Disks {
		if err := syncDisk(ctx, env, i, d, chosen, grubCfg, opts.InstallGRUB); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", d.ByID, err))
		}
	}
	if len(failed) == len(cfg.Disks) {
		return nil, fmt.Errorf("no boot disk could be updated: %s", strings.Join(failed, "; "))
	}
	if len(failed) > 0 {
		return entries, &PartialError{Failed: failed}
	}
	return entries, nil
}

// staged is a boot environment chosen for the menu, with its kernel.
type staged struct {
	entry  MenuEntry
	kernel *Kernel
}

// PartialError means some boot disks were updated and others failed. The
// system still boots from the updated disks; the failed ones need attention.
type PartialError struct{ Failed []string }

func (e *PartialError) Error() string {
	return "some boot disks could not be updated: " + strings.Join(e.Failed, "; ")
}

var partUUIDRE = regexp.MustCompile(`^[0-9a-fA-F-]{8,64}$`)

func syncDisk(ctx context.Context, env Env, i int, d Disk, kernels []staged, grubCfg string, install bool) error {
	if !partUUIDRE.MatchString(d.ESPPartUUID) {
		return fmt.Errorf("invalid ESP partition UUID %q", d.ESPPartUUID)
	}
	dir := filepath.Join(env.mountDir(), fmt.Sprintf("esp%d", i))
	if err := os.MkdirAll(env.path(dir), 0o755); err != nil {
		return err
	}
	dev := espDevice(ctx, env, d.ESPPartUUID)
	if _, err := sysexec.Output(ctx, env.Runner, "mount", "-t", "vfat", "-o", "umask=0077", dev, dir); err != nil {
		return fmt.Errorf("mount ESP: %w", err)
	}
	defer func() { _, _ = env.Runner.Run(context.Background(), nil, "umount", dir) }()

	if install {
		if err := installGRUB(ctx, env, dir, d.ByID); err != nil {
			return err
		}
	}

	keep := map[string]bool{}
	for _, k := range kernels {
		keep[k.entry.ID] = true
		dst := env.path(filepath.Join(dir, "hardyos", k.entry.ID))
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return err
		}
		if err := copyIfChanged(k.kernel.Vmlinuz, filepath.Join(dst, "vmlinuz")); err != nil {
			return err
		}
		if err := copyIfChanged(k.kernel.Initrd, filepath.Join(dst, "initrd.img")); err != nil {
			return err
		}
	}
	// Remove kernels of boot environments that are gone or no longer listed.
	if entries, err := os.ReadDir(env.path(filepath.Join(dir, "hardyos"))); err == nil {
		for _, e := range entries {
			if !keep[e.Name()] {
				_ = os.RemoveAll(env.path(filepath.Join(dir, "hardyos", e.Name())))
			}
		}
	}
	if err := os.MkdirAll(env.path(filepath.Join(dir, "grub")), 0o755); err != nil {
		return err
	}
	return writeAtomic(env.path(filepath.Join(dir, "grub", "grub.cfg")), []byte(grubCfg), 0o644)
}

// espDevice finds an ESP by partition UUID: the udev link when it exists,
// otherwise whatever blkid finds (udev may not link every kind of device).
func espDevice(ctx context.Context, env Env, partUUID string) string {
	link := "/dev/disk/by-partuuid/" + strings.ToLower(partUUID)
	if _, err := os.Stat(env.path(link)); err == nil {
		return link
	}
	out, err := sysexec.Output(ctx, env.Runner, "blkid", "-l", "-o", "device", "-t", "PARTUUID="+strings.ToLower(partUUID))
	if dev := strings.TrimSpace(string(out)); err == nil && strings.HasPrefix(dev, "/dev/") {
		return dev
	}
	return link
}

// eachESP mounts every boot disk's ESP in turn and runs fn on its mount
// point. Like Sync, it succeeds when at least one disk worked.
func eachESP(ctx context.Context, env Env, cfg *Config, fn func(dir string) error) error {
	var failed []string
	for i, d := range cfg.Disks {
		dir := filepath.Join(env.mountDir(), fmt.Sprintf("esp%d", i))
		err := func() error {
			if !partUUIDRE.MatchString(d.ESPPartUUID) {
				return fmt.Errorf("invalid ESP partition UUID %q", d.ESPPartUUID)
			}
			if err := os.MkdirAll(env.path(dir), 0o755); err != nil {
				return err
			}
			if _, err := sysexec.Output(ctx, env.Runner, "mount", "-t", "vfat", "-o", "umask=0077", espDevice(ctx, env, d.ESPPartUUID), dir); err != nil {
				return fmt.Errorf("mount ESP: %w", err)
			}
			defer func() { _, _ = env.Runner.Run(context.Background(), nil, "umount", dir) }()
			return fn(dir)
		}()
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", d.ByID, err))
		}
	}
	if len(failed) == len(cfg.Disks) {
		return fmt.Errorf("no boot disk could be updated: %s", strings.Join(failed, "; "))
	}
	if len(failed) > 0 {
		return &PartialError{Failed: failed}
	}
	return nil
}

var beNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$`)

// SetNextBoot makes the next boot (only) start boot environment id. The
// boot menu must already list it (Sync).
func SetNextBoot(ctx context.Context, env Env, cfg *Config, id string) error {
	if !beNameRE.MatchString(id) {
		return fmt.Errorf("invalid boot environment name %q", id)
	}
	return eachESP(ctx, env, cfg, func(dir string) error {
		_, err := sysexec.Output(ctx, env.Runner, "grub-editenv", filepath.Join(dir, "grub", "grubenv"), "set", "next_entry="+id)
		return err
	})
}

// ClearNextBoot removes a pending one-time boot choice from every disk.
func ClearNextBoot(ctx context.Context, env Env, cfg *Config) error {
	return eachESP(ctx, env, cfg, func(dir string) error {
		_, err := sysexec.Output(ctx, env.Runner, "grub-editenv", filepath.Join(dir, "grub", "grubenv"), "unset", "next_entry")
		return err
	})
}

// EFITarget returns GRUB's EFI platform for this CPU architecture.
func EFITarget() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64-efi", nil
	case "arm64":
		return "arm64-efi", nil
	case "riscv64":
		return "riscv64-efi", nil
	}
	return "", fmt.Errorf("no EFI boot loader known for %s", runtime.GOARCH)
}

func installGRUB(ctx context.Context, env Env, espDir, disk string) error {
	target, err := EFITarget()
	if err != nil {
		return err
	}
	// --removable writes EFI/BOOT/BOOT<arch>.EFI, which every firmware boots
	// without an NVRAM entry, so any mirrored disk can boot on its own.
	if _, err := sysexec.Output(ctx, env.Runner, "grub-install", "--target="+target,
		"--efi-directory="+espDir, "--boot-directory="+espDir, "--removable", "--no-nvram"); err != nil {
		return fmt.Errorf("install EFI boot loader: %w", err)
	}
	// Legacy BIOS boot as well where GRUB supports it (x86 only), so the same
	// disks boot on old firmware or with CSM enabled.
	if _, err := os.Stat(env.path("/usr/lib/grub/i386-pc")); err == nil && runtime.GOARCH == "amd64" {
		if _, err := sysexec.Output(ctx, env.Runner, "grub-install", "--target=i386-pc",
			"--boot-directory="+espDir, disk); err != nil {
			return fmt.Errorf("install BIOS boot loader: %w", err)
		}
	}
	return nil
}

// readMounts maps mounted ZFS datasets to their mount points from /proc/mounts.
func readMounts(path string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[2] == "zfs" {
			if _, seen := out[f[0]]; !seen {
				out[f[0]] = unescapeMount(f[1])
			}
		}
	}
	return out
}

// unescapeMount decodes the octal escapes /proc/mounts uses for spaces etc.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	re := regexp.MustCompile(`\\([0-7]{3})`)
	return re.ReplaceAllStringFunc(s, func(m string) string {
		n, _ := strconv.ParseUint(m[1:], 8, 8)
		return string(rune(n))
	})
}

func copyIfChanged(src, dst string) error {
	si, err := os.Stat(src)
	if err != nil {
		return err
	}
	if di, err := os.Stat(dst); err == nil && di.Size() == si.Size() {
		a, err1 := os.ReadFile(src)
		b, err2 := os.ReadFile(dst)
		if err1 == nil && err2 == nil && string(a) == string(b) {
			return nil
		}
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeAtomic(dst, data, 0o644)
}

// writeAtomic writes via a temp file and rename, so a power cut never leaves
// a half-written grub.cfg or kernel.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
