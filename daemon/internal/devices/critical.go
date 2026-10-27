package devices

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/boot"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Devices the server itself needs are never lent to a VM: the controllers
// of the boot disks, of disks in imported pools, of disks holding a mounted
// filesystem or swap, the network ports the server's own address goes
// through (with any bridge, bond or VLAN on top), and USB devices on those
// paths. The only graphics card is refused by gpuProblem.
//
// A disk the server uses isn't always a plain disk on its controller:
// device-mapper (LUKS, dm-multipath, LVM) and md RAID devices sit on
// other block devices (followed through slaves/, recursively), and an
// NVMe namespace with native multipathing is a head device under the
// NVMe subsystem whose paths (multipath/, or the subsystem's controllers)
// lead to the controllers. Every controller on every path is kept.

// critical returns reasons keyed by PCI address and by USB port.
func (h *Host) critical(ctx context.Context, pci []PCIDevice) (map[string]string, map[string]string) {
	pciCrit, usbCrit := map[string]string{}, map[string]string{}
	mark := func(sysPath, reason string) {
		real := h.resolve(sysPath)
		if real == "" {
			return
		}
		var lastPCI string
		for _, part := range strings.Split(real, "/") {
			switch {
			case pciAddrRE.MatchString(part):
				lastPCI = part
			case usbPortRE.MatchString(part):
				if _, ok := usbCrit[part]; !ok {
					usbCrit[part] = reason
				}
			}
		}
		if lastPCI != "" {
			if _, ok := pciCrit[lastPCI]; !ok {
				pciCrit[lastPCI] = reason
			}
		}
	}

	block := func(name, reason string) { h.markBlock(name, reason, mark, map[string]bool{}, 0) }

	// Boot disks.
	if cfg, err := boot.LoadConfig(h.path(boot.ConfigPath)); err == nil {
		for _, d := range cfg.Disks {
			if name := h.blockName(d.ByID); name != "" {
				block(name, fmt.Sprintf("Holds the boot disk (%s), which the server runs from.", name))
			}
		}
	}
	// Disks of imported pools (sorted, so the reason shown is stable).
	pools := h.poolDisks(ctx)
	devs := make([]string, 0, len(pools))
	for dev := range pools {
		devs = append(devs, dev)
	}
	sort.Strings(devs)
	for _, dev := range devs {
		if name := h.blockName(dev); name != "" {
			block(name, fmt.Sprintf("Holds disks of the storage pool %q.", pools[dev]))
		}
	}
	// Filesystems mounted from a disk (not a pool), and swap.
	for _, m := range h.blockMounts() {
		block(m.name, fmt.Sprintf("Holds a filesystem the server has mounted (%s).", m.where))
	}
	for _, sw := range h.swapDevices() {
		block(sw, fmt.Sprintf("Holds swap space the server uses (%s).", sw))
	}
	// The network ports the server's address goes through.
	for _, port := range h.lanPorts() {
		mark("/sys/class/net/"+port+"/device", fmt.Sprintf("Is the network port the server uses (%s).", port))
	}
	return pciCrit, usbCrit
}

// markBlock marks the controllers under block device name and under
// everything it's built on.
func (h *Host) markBlock(name, reason string, mark func(sysPath, reason string), seen map[string]bool, depth int) {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") || seen[name] || depth > 16 {
		return
	}
	seen[name] = true
	base := "/sys/class/block/" + name
	if !h.exists(base) {
		return
	}
	real := h.resolve(base)
	// A partition: the whole disk it's on.
	if h.exists(base+"/partition") && real != "" {
		h.markBlock(filepath.Base(filepath.Dir(real)), reason, mark, seen, depth+1)
	}
	// The device's own path (a plain disk's controller).
	mark(base, reason)
	// Device-mapper and md RAID: the devices it's made of.
	slaves, _ := os.ReadDir(h.path(base + "/slaves"))
	for _, sl := range slaves {
		h.markBlock(sl.Name(), reason, mark, seen, depth+1)
	}
	// NVMe native multipath head: each path's controller...
	paths, _ := os.ReadDir(h.path(base + "/multipath"))
	for _, p := range paths {
		mark(base+"/multipath/"+p.Name(), reason)
	}
	// ...and, whatever the kernel lists there, every controller of the
	// NVMe subsystem the head belongs to.
	if i := strings.Index(real, "/nvme-subsystem/"); i >= 0 {
		rest := real[i+len("/nvme-subsystem/"):]
		if subsys, _, ok := strings.Cut(rest, "/"); ok && nvmeSubsysRE.MatchString(subsys) {
			dir := real[:i] + "/nvme-subsystem/" + subsys
			entries, _ := os.ReadDir(h.path(dir))
			for _, e := range entries {
				if nvmeCtrlRE.MatchString(e.Name()) {
					mark(dir+"/"+e.Name(), reason)
					mark(dir+"/"+e.Name()+"/device", reason)
				}
			}
		}
	}
}

var (
	nvmeSubsysRE = regexp.MustCompile(`^nvme-subsys[0-9]+$`)
	nvmeCtrlRE   = regexp.MustCompile(`^nvme[0-9]+$`)
	majMinRE     = regexp.MustCompile(`^[0-9]+:[0-9]+$`)
)

type blockMount struct{ name, where string }

// blockMounts lists filesystems mounted from block devices (by the
// device number in mountinfo, so "/dev/root" and friends count too).
func (h *Host) blockMounts() []blockMount {
	var out []blockMount
	seen := map[string]bool{}
	for _, line := range strings.Split(h.readTrim("/proc/self/mountinfo"), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !majMinRE.MatchString(f[2]) || strings.HasPrefix(f[2], "0:") {
			continue
		}
		real := h.resolve("/sys/dev/block/" + f[2])
		if real == "" {
			continue
		}
		name := filepath.Base(real)
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, blockMount{name: name, where: unescapeOctal(f[4])})
	}
	return out
}

// swapDevices lists the block devices in use as swap (swap files live on
// a mounted filesystem, which blockMounts covers).
func (h *Host) swapDevices() []string {
	var out []string
	for _, line := range strings.Split(h.readTrim("/proc/swaps"), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 2 || f[1] != "partition" {
			continue
		}
		if name := h.blockName(unescapeOctal(f[0])); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// unescapeOctal decodes the \040-style escapes of /proc/self/mountinfo
// and /proc/swaps.
func unescapeOctal(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	return regexp.MustCompile(`\\([0-7]{3})`).ReplaceAllStringFunc(s, func(m string) string {
		n, _ := strconv.ParseUint(m[1:], 8, 8)
		return string(rune(n))
	})
}

// resolve follows symlinks under Root and returns the server path ("" if
// it doesn't exist).
func (h *Host) resolve(p string) string {
	real, err := filepath.EvalSymlinks(h.path(p))
	if err != nil {
		return ""
	}
	root, err := filepath.EvalSymlinks(h.Root)
	if err != nil {
		root = h.Root
	}
	rel, err := filepath.Rel(root, real)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}
	return "/" + rel
}

// blockName turns /dev/disk/by-id/... or /dev/sda1 into the kernel's name
// ("sda1").
func (h *Host) blockName(dev string) string {
	if !strings.HasPrefix(dev, "/dev/") {
		return ""
	}
	real := h.resolve(dev)
	if real == "" {
		return ""
	}
	name := filepath.Base(real)
	if !h.exists("/sys/class/block/" + name) {
		return ""
	}
	return name
}

// poolDisks maps each disk path of every imported pool to its pool.
func (h *Host) poolDisks(ctx context.Context) map[string]string {
	out := map[string]string{}
	if h.Runner == nil {
		return out
	}
	b, err := sysexec.Output(ctx, h.Runner, "zpool", "list", "-v", "-H", "-P", "-o", "name")
	if err != nil {
		return out
	}
	pool := ""
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		if line[0] != '\t' {
			pool = strings.Fields(line)[0]
			continue
		}
		f := strings.Fields(line)
		if len(f) > 0 && strings.HasPrefix(f[0], "/dev/") && pool != "" {
			out[f[0]] = pool
		}
	}
	return out
}

// lanPorts are the physical interfaces under the default routes, through
// any bridge, bond, VLAN or macvlan stacked on them.
func (h *Host) lanPorts() []string {
	top := map[string]bool{}
	for _, line := range strings.Split(h.readTrim("/proc/net/route"), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "00000000" {
			top[f[0]] = true
		}
	}
	for _, line := range strings.Split(h.readTrim("/proc/net/ipv6_route"), "\n") {
		f := strings.Fields(line)
		if len(f) == 10 && f[0] == strings.Repeat("0", 32) && f[1] == "00" && f[9] != "lo" {
			top[f[9]] = true
		}
	}
	seen := map[string]bool{}
	var out []string
	var walk func(ifc string, depth int)
	walk = func(ifc string, depth int) {
		if seen[ifc] || depth > 6 || ifc == "" || ifc == ".." || strings.Contains(ifc, "/") {
			return
		}
		seen[ifc] = true
		base := "/sys/class/net/" + ifc
		if h.exists(base + "/device") {
			out = append(out, ifc)
		}
		entries, _ := os.ReadDir(h.path(base))
		for _, e := range entries {
			if lower, ok := strings.CutPrefix(e.Name(), "lower_"); ok {
				walk(lower, depth+1)
			}
		}
		members, _ := os.ReadDir(h.path(base + "/brif"))
		for _, m := range members {
			walk(m.Name(), depth+1)
		}
	}
	names := make([]string, 0, len(top))
	for t := range top {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		walk(t, 0)
	}
	sort.Strings(out)
	return out
}
