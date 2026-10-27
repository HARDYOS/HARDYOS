package devices

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// fakeSys lays out sysfs and procfs under a temp root, and its kernel
// answers writes to sysfs control files the way Linux does: unbind drops
// the driver link, drivers_probe binds driver_override (or the device's
// own driver), mdev create makes an instance.
type fakeSys struct {
	t    *testing.T
	root string
	// native is each device's own driver (what drivers_probe binds).
	native map[string]string
	// noRebind: these devices never go back to their driver (reset bug).
	noRebind map[string]bool
	// failUnbind: writing to unbind fails for these.
	failUnbind map[string]bool
	mu         sync.Mutex
	writes     []string
	run        *sysexec.Fake
}

func newFakeSys(t *testing.T) *fakeSys {
	t.Helper()
	f := &fakeSys{t: t, root: t.TempDir(), native: map[string]string{}, noRebind: map[string]bool{}, failUnbind: map[string]bool{}, run: &sysexec.Fake{}}
	f.file("/proc/sys/kernel/random/boot_id", "boot-1\n")
	f.file("/proc/cmdline", "BOOT_IMAGE=/hardyos/x/vmlinuz root=ZFS=rpool/ROOT/x boot=zfs quiet\n")
	f.file("/proc/cpuinfo", "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Core(TM) i7\n")
	f.file("/proc/net/route", "Iface\tDestination\tGateway\tFlags\n")
	f.mkdir("/sys/bus/pci/drivers")
	f.mkdir("/sys/bus/mdev/devices")
	f.mkdir("/sys/bus/usb/devices")
	f.mkdir("/sys/kernel/iommu_groups")
	f.run.OnPrefix("modprobe vfio-pci", sysexec.Result{})
	f.run.OnPrefix("zpool list", sysexec.Result{Stdout: []byte("")})
	f.run.OnPrefix("virsh ", sysexec.Result{})
	f.run.OnPrefix("nvidia-smi ", sysexec.Result{ExitCode: 127})
	return f
}

func (f *fakeSys) host() *Host {
	return &Host{Runner: f.run, Root: f.root, Kernel: f, Arch: "amd64"}
}

func (f *fakeSys) p(p string) string { return filepath.Join(f.root, p) }

func (f *fakeSys) file(p, data string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Dir(f.p(p)), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(f.p(p), []byte(data), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fakeSys) mkdir(p string) {
	f.t.Helper()
	if err := os.MkdirAll(f.p(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

// link makes p a symlink to target (relative to p's directory).
func (f *fakeSys) link(p, target string) {
	f.t.Helper()
	f.mkdir(filepath.Dir(p))
	_ = os.Remove(f.p(p))
	rel, err := filepath.Rel(filepath.Dir(p), target)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(rel, f.p(p)); err != nil {
		f.t.Fatal(err)
	}
}

type pciOpt struct {
	parent   string // bridge address it sits behind
	group    int    // -1: no IOMMU group
	bootVGA  bool
	reset    string // reset_method content ("" none)
	sub      map[string]string
	physfn   string
	noDriver bool
}

// pci adds a device at /sys/devices/pci0000:00/[parent/]addr with the
// /sys/bus/pci/devices link, its driver and its IOMMU group.
func (f *fakeSys) pci(addr, vendor, device, class, driver string, o pciOpt) string {
	f.t.Helper()
	real := "/sys/devices/pci0000:00/" + addr
	if o.parent != "" {
		real = filepath.Join(filepath.Dir(f.devPath(o.parent)), filepath.Base(f.devPath(o.parent)), addr)
	}
	f.mkdir(real)
	f.file(real+"/vendor", "0x"+vendor+"\n")
	f.file(real+"/device", "0x"+device+"\n")
	f.file(real+"/class", class+"\n")
	f.file(real+"/driver_override", "(null)\n")
	if o.bootVGA {
		f.file(real+"/boot_vga", "1\n")
	} else if strings.HasPrefix(class, "0x03") {
		f.file(real+"/boot_vga", "0\n")
	}
	if o.reset != "" {
		f.file(real+"/reset_method", o.reset+"\n")
	}
	for k, v := range o.sub {
		f.file(real+"/"+k, v)
	}
	f.link("/sys/bus/pci/devices/"+addr, real)
	if driver != "" {
		f.native[addr] = driver
		f.bindLink(addr, driver)
	}
	if o.group >= 0 {
		g := "/sys/kernel/iommu_groups/" + strconv.Itoa(o.group)
		f.mkdir(g + "/devices")
		f.link(g+"/devices/"+addr, real)
		f.link(real+"/iommu_group", g)
	}
	if o.physfn != "" {
		f.link(real+"/physfn", f.devPath(o.physfn))
		n := 0
		for {
			if _, err := os.Lstat(f.p(f.devPath(o.physfn) + "/virtfn" + strconv.Itoa(n))); err != nil {
				break
			}
			n++
		}
		f.link(f.devPath(o.physfn)+"/virtfn"+strconv.Itoa(n), real)
	}
	return real
}

func (f *fakeSys) devPath(addr string) string {
	t, err := filepath.EvalSymlinks(f.p("/sys/bus/pci/devices/" + addr))
	if err != nil {
		f.t.Fatalf("no device %s", addr)
	}
	rel, _ := filepath.Rel(f.root, t)
	return "/" + rel
}

func (f *fakeSys) bindLink(addr, driver string) {
	f.mkdir("/sys/bus/pci/drivers/" + driver)
	f.link(f.devPath(addr)+"/driver", "/sys/bus/pci/drivers/"+driver)
}

func (f *fakeSys) driver(addr string) string {
	t, err := os.Readlink(f.p(f.devPath(addr) + "/driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(t)
}

// WriteSysfs implements Kernel.
func (f *fakeSys) WriteSysfs(path, value string) error {
	f.mu.Lock()
	f.writes = append(f.writes, path+" < "+strings.TrimSpace(value))
	f.mu.Unlock()
	if !strings.HasPrefix(path, "/sys/") {
		return fmt.Errorf("not sysfs: %s", path)
	}
	switch {
	case strings.HasSuffix(path, "/driver_override"):
		v := strings.TrimSpace(value)
		if v == "" {
			v = "(null)"
		}
		return os.WriteFile(f.p(path), []byte(v+"\n"), 0o644)
	case strings.HasPrefix(path, "/sys/bus/pci/drivers/") && strings.HasSuffix(path, "/unbind"):
		drv := filepath.Base(filepath.Dir(path))
		if f.failUnbind[value] {
			return fmt.Errorf("write %s: device or resource busy", path)
		}
		if f.driver(value) != drv {
			return fmt.Errorf("write %s: no such device", path)
		}
		return os.Remove(f.p(f.devPath(value) + "/driver"))
	case path == "/sys/bus/pci/drivers_probe":
		if f.driver(value) != "" {
			return nil
		}
		ov, _ := os.ReadFile(f.p(f.devPath(value) + "/driver_override"))
		if o := strings.TrimSpace(string(ov)); o != "(null)" && o != "" {
			f.bindLink(value, o)
			return nil
		}
		if f.noRebind[value] {
			return nil
		}
		if d := f.native[value]; d != "" {
			f.bindLink(value, d)
		}
		return nil
	case strings.HasPrefix(path, "/sys/bus/pci/drivers/") && strings.HasSuffix(path, "/bind"):
		if f.noRebind[value] {
			return fmt.Errorf("write %s: no such device", path)
		}
		f.bindLink(value, filepath.Base(filepath.Dir(path)))
		return nil
	case strings.HasSuffix(path, "/create") && strings.Contains(path, "/mdev_supported_types/"):
		typeDir := filepath.Dir(path)
		avail, _ := os.ReadFile(f.p(typeDir + "/available_instances"))
		n, _ := strconv.Atoi(strings.TrimSpace(string(avail)))
		if n < 1 {
			return fmt.Errorf("write %s: no space left on device", path)
		}
		parentLink := filepath.Dir(filepath.Dir(typeDir)) // /sys/bus/pci/devices/<addr>
		parent := f.devPath(filepath.Base(parentLink))
		inst := parent + "/" + value
		f.mkdir(inst)
		f.link(inst+"/mdev_type", parent+"/mdev_supported_types/"+filepath.Base(typeDir))
		f.file(inst+"/remove", "")
		f.link("/sys/bus/mdev/devices/"+value, inst)
		return os.WriteFile(f.p(typeDir+"/available_instances"), []byte(strconv.Itoa(n-1)+"\n"), 0o644)
	case strings.HasPrefix(path, "/sys/bus/mdev/devices/") && strings.HasSuffix(path, "/remove"):
		uuid := filepath.Base(filepath.Dir(path))
		real, err := filepath.EvalSymlinks(f.p("/sys/bus/mdev/devices/" + uuid))
		if err != nil {
			return err
		}
		typeDir, _ := filepath.EvalSymlinks(filepath.Join(real, "mdev_type"))
		avail, _ := os.ReadFile(filepath.Join(typeDir, "available_instances"))
		n, _ := strconv.Atoi(strings.TrimSpace(string(avail)))
		_ = os.WriteFile(filepath.Join(typeDir, "available_instances"), []byte(strconv.Itoa(n+1)+"\n"), 0o644)
		_ = os.Remove(f.p("/sys/bus/mdev/devices/" + uuid))
		return os.RemoveAll(real)
	case strings.HasSuffix(path, "/nvidia/current_vgpu_type"), strings.HasSuffix(path, "/sriov_numvfs"):
		if strings.HasSuffix(path, "/sriov_numvfs") {
			f.setVFs(filepath.Base(filepath.Dir(path)), strings.TrimSpace(value))
		}
		return os.WriteFile(f.p(path), []byte(strings.TrimSpace(value)+"\n"), 0o644)
	}
	return fmt.Errorf("fake kernel: unexpected write %s", path)
}

// setVFs creates (or drops) the virtual functions of an Intel GPU.
func (f *fakeSys) setVFs(pf, count string) {
	n, _ := strconv.Atoi(count)
	if n == 0 {
		return
	}
	for i := 0; i < n; i++ {
		addr := fmt.Sprintf("0000:00:02.%d", i+1)
		if _, err := os.Lstat(f.p("/sys/bus/pci/devices/" + addr)); err == nil {
			continue
		}
		f.pci(addr, "8086", "a7a0", "0x030000", "i915", pciOpt{group: 30 + i, physfn: pf, reset: "flr"})
	}
}

func (f *fakeSys) wrote() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.writes...)
}

// procOpener adds a process with a device file open.
func (f *fakeSys) procOpener(pid int, comm, cgroup, dev string) {
	d := "/proc/" + strconv.Itoa(pid)
	f.file(d+"/comm", comm+"\n")
	f.file(d+"/cgroup", cgroup+"\n")
	f.mkdir(d + "/fd")
	_ = os.Symlink(dev, f.p(d+"/fd/7"))
	_ = os.Symlink("/dev/null", f.p(d+"/fd/0"))
}

// server builds Cade's kind of server: an Intel iGPU (console), a Quadro
// RTX 4000 (four functions, own group), an AMD RX 580 sharing a group with
// a USB controller, a SATA controller with the boot disk, an Ethernet port
// under br0 carrying the default route, a second unused port, and USB
// devices.
func server(t *testing.T) *fakeSys {
	f := newFakeSys(t)
	f.pci("0000:00:00.0", "8086", "3e30", "0x060000", "", pciOpt{group: 0})
	f.pci("0000:00:01.0", "8086", "1901", "0x060400", "pcieport", pciOpt{group: 1, reset: "pm"})
	f.pci("0000:00:01.1", "8086", "1905", "0x060400", "pcieport", pciOpt{group: 1, reset: "pm"})
	f.pci("0000:00:02.0", "8086", "3e92", "0x030000", "i915", pciOpt{group: 2, bootVGA: true, reset: "flr"})
	f.pci("0000:00:14.0", "8086", "a36d", "0x0c0330", "xhci_hcd", pciOpt{group: 3, reset: "flr"})
	f.pci("0000:00:17.0", "8086", "a352", "0x010601", "ahci", pciOpt{group: 4, reset: "pm"})
	f.pci("0000:00:1f.6", "8086", "15bc", "0x020000", "e1000e", pciOpt{group: 5, reset: "flr"})
	// Quadro RTX 4000 behind 00:01.0.
	q := pciOpt{parent: "0000:00:01.0", group: 12, reset: "flr bus"}
	f.pci("0000:01:00.0", "10de", "1eb1", "0x030000", "nvidia", q)
	f.pci("0000:01:00.1", "10de", "10f8", "0x040300", "snd_hda_intel", q)
	f.pci("0000:01:00.2", "10de", "1ad8", "0x0c0330", "xhci_hcd", q)
	f.pci("0000:01:00.3", "10de", "1ad9", "0x0c8000", "nvidia-gpu", q)
	// RX 580 behind 00:01.1, in a group with a second network port.
	a := pciOpt{parent: "0000:00:01.1", group: 13, reset: "bus"}
	f.pci("0000:02:00.0", "1002", "67df", "0x030000", "amdgpu", a)
	f.pci("0000:02:00.1", "1002", "aaf0", "0x040300", "snd_hda_intel", a)
	f.pci("0000:03:00.0", "8086", "1533", "0x020000", "igb", pciOpt{parent: "0000:00:01.1", group: 13, reset: "flr"})
	f.file(f.devPath("0000:02:00.0")+"/mem_info_vram_total", "8589934592\n")
	// DRM nodes and NVIDIA's minor.
	f.mkdir(f.devPath("0000:00:02.0") + "/drm/card0")
	f.mkdir(f.devPath("0000:00:02.0") + "/drm/renderD128")
	f.mkdir(f.devPath("0000:01:00.0") + "/drm/card1")
	f.mkdir(f.devPath("0000:01:00.0") + "/drm/renderD129")
	f.mkdir(f.devPath("0000:02:00.0") + "/drm/card2")
	f.mkdir(f.devPath("0000:02:00.0") + "/drm/renderD130")
	f.file("/proc/driver/nvidia/gpus/0000:01:00.0/information", "Model: \t\t Quadro RTX 4000\nDevice Minor: \t 0\n")

	// Boot disk sda on the SATA controller.
	f.mkdir(f.devPath("0000:00:17.0") + "/ata1/host0/target0:0:0/0:0:0:0/block/sda/sda1")
	f.link("/sys/class/block/sda", f.devPath("0000:00:17.0")+"/ata1/host0/target0:0:0/0:0:0:0/block/sda")
	f.link("/sys/class/block/sda1", f.devPath("0000:00:17.0")+"/ata1/host0/target0:0:0/0:0:0:0/block/sda/sda1")
	f.file("/dev/sda", "")
	f.link("/dev/disk/by-id/ata-BOOT", "/dev/sda")
	f.file("/var/lib/hardyos/boot.json", `{"pool":"rpool","disks":[{"byId":"/dev/disk/by-id/ata-BOOT","espPartUUID":"11111111-aaaa-bbbb-cccc-000000000001"}]}`)

	// Networking: br0 (default route) over eno1; enp3s0 unused.
	f.file("/proc/net/route", "Iface\tDestination\tGateway\tFlags\nbr0\t00000000\t0102A8C0\t0003\nbr0\t0002A8C0\t00000000\t0001\n")
	f.mkdir("/sys/class/net/br0/brif/eno1")
	f.link("/sys/class/net/eno1/device", f.devPath("0000:00:1f.6"))
	f.link("/sys/class/net/enp3s0/device", f.devPath("0000:03:00.0"))

	// USB: a root hub, a keyboard receiver, a Zigbee stick on a hub.
	usb := func(port, vid, pid, product, class string) {
		real := f.devPath("0000:00:14.0") + "/usb1/" + port
		if strings.Contains(port, ".") {
			real = f.devPath("0000:00:14.0") + "/usb1/1-3/" + port
		}
		f.file(real+"/idVendor", vid+"\n")
		f.file(real+"/idProduct", pid+"\n")
		f.file(real+"/product", product+"\n")
		f.file(real+"/busnum", "1\n")
		f.file(real+"/devnum", strconv.Itoa(len(port)+2)+"\n")
		f.file(real+"/speed", "12\n")
		f.file(real+"/bDeviceClass", class+"\n")
		f.link("/sys/bus/usb/devices/"+port, real)
	}
	f.mkdir(f.devPath("0000:00:14.0") + "/usb1")
	f.link("/sys/bus/usb/devices/usb1", f.devPath("0000:00:14.0")+"/usb1")
	usb("1-2", "046d", "c52b", "USB Receiver", "00")
	usb("1-3", "05e3", "0610", "USB2.0 Hub", "09")
	usb("1-3.1", "10c4", "ea60", "Sonoff Zigbee 3.0 USB Dongle Plus", "00")
	f.mkdir(f.devPath("0000:00:14.0") + "/usb1/1-2/1-2:1.0") // an interface, not listed

	f.file("/usr/share/misc/pci.ids", `# pci.ids
8086  Intel Corporation
	1533  I210 Gigabit Network Connection
	3e92  CoffeeLake-S GT2 [UHD Graphics 630]
	a352  Cannon Lake PCH SATA AHCI Controller
10de  NVIDIA Corporation
	1eb1  TU104GL [Quadro RTX 4000]
		10de 12a0  Quadro RTX 4000
	10f8  TU104 HD Audio Controller
1002  Advanced Micro Devices, Inc. [AMD/ATI]
	67df  Ellesmere [Radeon RX 470/480/570/570X/580/580X/590]
C 03  Display controller
	00  VGA compatible controller
`)
	f.file("/usr/share/misc/usb.ids", "046d  Logitech, Inc.\n\tc52b  Unifying Receiver\n10c4  Silicon Labs\n")
	return f
}
