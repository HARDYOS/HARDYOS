package devices

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/boot"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Host is the real Manager: it reads sysfs and procfs under Root and
// changes device bindings through Kernel. Every method is safe to call
// from several goroutines; changes run one at a time.
type Host struct {
	Runner sysexec.Runner
	// Root prefixes every path ("/" on a server, a temp dir in tests).
	Root string
	// Kernel writes sysfs control files; nil writes the real files under Root.
	Kernel Kernel
	// StateDir holds which devices are lent to which VM. It lives in /run:
	// device bindings and vGPU instances don't survive a restart either.
	StateDir string
	// RomDir holds GPU ROM files a VM may be given.
	RomDir string
	// Running lists running VMs (default: virsh).
	Running RunningFunc
	// Assignments lists every VM's configured devices (optional).
	Assignments AssignmentsFunc
	Log         *slog.Logger
	// Arch overrides runtime.GOARCH (tests).
	Arch string
	// SysfsTimeout bounds one sysfs control write (default 30 seconds).
	// An unbind can hang in a driver; the device is then reported stuck
	// and left alone while the write is still pending.
	SysfsTimeout time.Duration

	mu sync.Mutex

	pendMu  sync.Mutex
	pending map[string]string // device -> the sysfs write still hanging
}

var _ Manager = (*Host)(nil)
var _ Reconciler = (*Host)(nil)

// Defaults.
const (
	DefaultStateDir = "/run/hardyos/devices"
	// DefaultRomDir is the GPU ROM library: in root's own directory on the
	// shared state dataset (root's, 0755), so hardyd can't put a file there
	// or swap one.
	DefaultRomDir = rootfile.RootStateDir + "/vm-roms"
	// LegacyRomDir is where early builds looked (hardyd's directory).
	LegacyRomDir = "/var/lib/hardyos/vm-roms"
	// RomRunDir holds the copy of a ROM a running VM is given (root's,
	// 0755, readable by QEMU): checked once, then never changed under it.
	RomRunDir = "/run/hardyos-roms"
	// MaxROMBytes bounds a ROM file (real ones are well under 1 MiB).
	MaxROMBytes = 8 << 20
)

func (h *Host) path(p string) string { return filepath.Join(h.Root, p) }

func (h *Host) stateDir() string {
	if h.StateDir == "" {
		return DefaultStateDir
	}
	return h.StateDir
}

func (h *Host) romDir() string {
	if h.RomDir == "" {
		return DefaultRomDir
	}
	return h.RomDir
}

func (h *Host) log() *slog.Logger {
	if h.Log != nil {
		return h.Log
	}
	return slog.Default()
}

func (h *Host) kernel() Kernel {
	if h.Kernel != nil {
		return h.Kernel
	}
	return sysfsKernel{root: h.Root}
}

func (h *Host) bootEnv() boot.Env { return boot.Env{Runner: h.Runner, Root: h.Root} }

// running lists every active domain: running, paused, suspended (pmsuspended),
// shutting down, blocked. Any of them may still use its devices. An error
// means "can't tell", and callers then treat every VM as possibly running.
func (h *Host) running(ctx context.Context) ([]string, error) {
	if h.Running != nil {
		return h.Running(ctx)
	}
	// Without a state filter virsh lists all active domains (not shut off).
	out, err := sysexec.Output(ctx, h.Runner, "virsh", "-c", "qemu:///system", "list", "--name")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			names = append(names, l)
		}
	}
	return names, nil
}

// mightRun reports whether vm may be active. Only a successful list that
// doesn't name it says no; a failure is asked again a few times (libvirt
// restarting), then counts as "it may be running".
func (h *Host) mightRun(ctx context.Context, vm string, tries int) (bool, error) {
	var err error
	for i := 0; i < tries; i++ {
		var names []string
		if names, err = h.running(ctx); err == nil {
			return contains(names, vm), nil
		}
		if i+1 < tries {
			select {
			case <-ctx.Done():
				return true, err
			case <-time.After(time.Second):
			}
		}
	}
	return true, err
}

func (h *Host) sysfsTimeout() time.Duration {
	if h.SysfsTimeout > 0 {
		return h.SysfsTimeout
	}
	return 30 * time.Second
}

// ErrSysfsHung means a sysfs write didn't return in time (a driver hanging
// in unbind or reset). The device is left alone until the write returns.
var ErrSysfsHung = errors.New("the kernel didn't finish")

// write is Kernel.WriteSysfs with a deadline. dev names the device the
// write is about; while an earlier write for it still hangs, nothing else
// is written for it.
func (h *Host) write(dev, path, value string) error {
	h.pendMu.Lock()
	if p, busy := h.pending[dev]; busy {
		h.pendMu.Unlock()
		return fmt.Errorf("%s: an earlier change (%s) is still hanging in the kernel; restart the server to get it back", dev, p)
	}
	if h.pending == nil {
		h.pending = map[string]string{}
	}
	h.pending[dev] = path
	h.pendMu.Unlock()
	done := make(chan error, 1)
	k := h.kernel()
	go func() {
		err := k.WriteSysfs(path, value)
		h.pendMu.Lock()
		delete(h.pending, dev)
		h.pendMu.Unlock()
		done <- err
	}()
	t := time.NewTimer(h.sysfsTimeout())
	defer t.Stop()
	select {
	case err := <-done:
		return err
	case <-t.C:
		h.log().Error("sysfs write hangs", "device", dev, "path", path, "after", h.sysfsTimeout())
		return fmt.Errorf("%s: writing %s: %w within %s", dev, path, ErrSysfsHung, h.sysfsTimeout())
	}
}

// hanging reports whether a write for dev is still pending.
func (h *Host) hanging(dev string) bool {
	h.pendMu.Lock()
	defer h.pendMu.Unlock()
	_, ok := h.pending[dev]
	return ok
}

// Kernel writes sysfs control files (driver_override, unbind, bind,
// drivers_probe, mdev create/remove, sriov_numvfs, current_vgpu_type).
// path is the absolute path on the server ("/sys/bus/pci/...").
type Kernel interface {
	WriteSysfs(path, value string) error
}

type sysfsKernel struct{ root string }

// WriteSysfs writes value to an existing sysfs file (never creates one).
func (k sysfsKernel) WriteSysfs(path, value string) error {
	if !strings.HasPrefix(path, "/sys/") || strings.Contains(path, "..") {
		return fmt.Errorf("refusing to write %s", path)
	}
	f, err := os.OpenFile(filepath.Join(k.root, path), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, err = f.Write([]byte(value))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// Validation.
var (
	pciAddrRE  = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$`)
	usbIDRE    = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{4}$`)
	usbPortRE  = regexp.MustCompile(`^[0-9]{1,3}-[0-9]{1,3}(\.[0-9]{1,3}){0,6}$`)
	vmNameRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	romFileRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,100}\.(rom|bin)$`)
	vgpuTypeRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	driverRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	uuidRE     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// ValidPCIAddress reports whether s is a full PCI address (0000:01:00.0).
func ValidPCIAddress(s string) bool { return pciAddrRE.MatchString(s) }

// ValidVMName reports whether s is a VM name devices can be lent to.
func ValidVMName(s string) bool { return vmNameRE.MatchString(s) }

// readTrim reads a small sysfs/procfs file and trims it ("" when missing).
func (h *Host) readTrim(p string) string {
	b, err := os.ReadFile(h.path(p))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (h *Host) readInt(p string) (int, bool) {
	n, err := strconv.Atoi(h.readTrim(p))
	return n, err == nil
}

func (h *Host) exists(p string) bool {
	_, err := os.Lstat(h.path(p))
	return err == nil
}

// linkBase is the last element of a symlink's target ("" if it isn't one).
func (h *Host) linkBase(p string) string {
	t, err := os.Readlink(h.path(p))
	if err != nil {
		return ""
	}
	return filepath.Base(t)
}

// pciDev is a device's sysfs directory.
func pciDev(addr string) string { return "/sys/bus/pci/devices/" + addr }

// driverOf is the driver bound to a PCI device ("" for none).
func (h *Host) driverOf(addr string) string { return h.linkBase(pciDev(addr) + "/driver") }

// bootID identifies this boot; state from another boot is void.
func (h *Host) bootID() string { return h.readTrim("/proc/sys/kernel/random/boot_id") }

// slotOf is "0000:01:00" for "0000:01:00.1".
func slotOf(addr string) string {
	if i := strings.LastIndexByte(addr, '.'); i > 0 {
		return addr[:i]
	}
	return addr
}

func isNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }

func now() time.Time { return time.Now().UTC() }

// readROM reads a ROM file from the library: a regular file of root's
// (when enforced) in root's directory, never through a link, at most
// MaxROMBytes.
func (h *Host) readROM(name string) ([]byte, error) {
	if !romFileRE.MatchString(name) {
		return nil, fmt.Errorf("invalid ROM file name %q", name)
	}
	b, err := rootfile.ReadFileInRootDir(h.path(filepath.Join(h.romDir(), name)))
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || len(b) > MaxROMBytes {
		return nil, fmt.Errorf("the ROM file %s is empty or larger than %d MB", name, MaxROMBytes>>20)
	}
	return b, nil
}

// stageROM copies a checked ROM to RomRunDir and returns the path the VM
// gets.
func (h *Host) stageROM(name string) (string, error) {
	b, err := h.readROM(name)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	p := filepath.Join(RomRunDir, hex.EncodeToString(sum[:16])+filepath.Ext(name))
	if err := rootfile.WriteInRootDir(h.path(p), b, 0o644, 0o755); err != nil {
		return "", err
	}
	return p, nil
}

// MigrateRoms moves ROM files root owns from the old library in hardyd's
// directory into DefaultRomDir under root (a path prefix, "/" on a
// server). Files root didn't put there are left where they are, unused.
func MigrateRoms(root string) error {
	old := filepath.Join(root, LegacyRomDir)
	entries, err := os.ReadDir(old)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := rootfile.EnsureRootDir(filepath.Join(root, DefaultRomDir), 0o755); err != nil {
		return err
	}
	var skipped []string
	for _, e := range entries {
		if !romFileRE.MatchString(e.Name()) {
			continue
		}
		src := filepath.Join(old, e.Name())
		dst := filepath.Join(root, DefaultRomDir, e.Name())
		b, err := rootfile.ReadFile(src)
		if err != nil || len(b) > MaxROMBytes {
			skipped = append(skipped, e.Name())
			continue
		}
		if _, err := os.Lstat(dst); err == nil {
			continue
		}
		if err := rootfile.WriteInRootDir(dst, b, 0o644, 0o755); err != nil {
			return err
		}
		_ = os.Remove(src)
	}
	if len(skipped) > 0 {
		return fmt.Errorf("ROM files not moved (not root's, or too large): %s; copy them into %s as root", strings.Join(skipped, ", "), DefaultRomDir)
	}
	return nil
}
