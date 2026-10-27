package devices

import (
	"context"
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

	mu sync.Mutex
}

var _ Manager = (*Host)(nil)
var _ Reconciler = (*Host)(nil)

// Defaults.
const (
	DefaultStateDir = "/run/hardyos/devices"
	DefaultRomDir   = "/var/lib/hardyos/vm-roms"
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

func (h *Host) running(ctx context.Context) ([]string, error) {
	if h.Running != nil {
		return h.Running(ctx)
	}
	out, err := sysexec.Output(ctx, h.Runner, "virsh", "-c", "qemu:///system", "list", "--name", "--state-running")
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
