package devices

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/boot"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Devices the server itself needs are never lent to a VM: the controllers
// of the boot disks and of disks in imported pools, the network ports the
// server's own address goes through (with any bridge, bond or VLAN on top),
// and USB devices on those paths. The only graphics card is refused by
// gpuProblem.

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

	// Boot disks.
	if cfg, err := boot.LoadConfig(h.path(boot.ConfigPath)); err == nil {
		for _, d := range cfg.Disks {
			if name := h.blockName(d.ByID); name != "" {
				mark("/sys/class/block/"+name, fmt.Sprintf("Holds the boot disk (%s), which the server runs from.", name))
			}
		}
	}
	// Disks of imported pools.
	for dev, pool := range h.poolDisks(ctx) {
		if name := h.blockName(dev); name != "" {
			mark("/sys/class/block/"+name, fmt.Sprintf("Holds disks of the storage pool %q.", pool))
		}
	}
	// The network ports the server's address goes through.
	for _, port := range h.lanPorts() {
		mark("/sys/class/net/"+port+"/device", fmt.Sprintf("Is the network port the server uses (%s).", port))
	}
	return pciCrit, usbCrit
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
