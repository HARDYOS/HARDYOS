package devices

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// --- Prepare / Release / Reconcile and libvirt's view ---------------------

func TestReleaseKeepsDevicesWhenVirshFails(t *testing.T) {
	f := server(t)
	h := f.host()
	ctx := context.Background()
	if _, err := h.Prepare(ctx, "gaming", []Device{{Kind: KindGPU, ID: "0000:01:00.0"}}); err != nil {
		t.Fatal(err)
	}
	h.Running = func(context.Context) ([]string, error) { return nil, errors.New("libvirt is restarting") }
	if err := h.Release(ctx, "gaming"); err == nil || !strings.Contains(err.Error(), "can't tell whether the VM gaming has stopped") {
		t.Fatalf("release: %v", err)
	}
	if f.driver("0000:01:00.0") != "vfio-pci" {
		t.Fatal("devices released while libvirt couldn't say")
	}
	// A second start can't pull them either.
	if _, err := h.Prepare(ctx, "gaming", []Device{{Kind: KindGPU, ID: "0000:01:00.0"}}); err == nil || !strings.Contains(err.Error(), "can't tell") {
		t.Fatalf("prepare again: %v", err)
	}
	if err := h.Reconcile(ctx); err == nil || f.driver("0000:01:00.0") != "vfio-pci" {
		t.Fatalf("reconcile: %v", err)
	}
	h.Running = func(context.Context) ([]string, error) { return nil, nil }
	if err := h.Release(ctx, "gaming"); err != nil || f.driver("0000:01:00.0") != "nvidia" {
		t.Fatalf("release once known: %v", err)
	}
}

// virsh lists every active domain (paused, pmsuspended, in shutdown) when
// asked without a state filter; a paused VM keeps its devices.
func TestPausedVMKeepsDevices(t *testing.T) {
	f := server(t)
	h := f.host()
	ctx := context.Background()
	if _, err := h.Prepare(ctx, "gaming", []Device{{Kind: KindGPU, ID: "0000:01:00.0"}}); err != nil {
		t.Fatal(err)
	}
	f.run.OnResult("virsh -c qemu:///system list --name", sysexec.Result{Stdout: []byte("gaming\n\n")})
	if err := h.Release(ctx, "gaming"); err == nil || !strings.Contains(err.Error(), "still running") {
		t.Fatalf("release of a paused VM: %v", err)
	}
	for _, l := range f.run.Lines() {
		if strings.Contains(l, "--state-") {
			t.Fatalf("filtered list: %s", l)
		}
	}
	f.run.OnResult("virsh -c qemu:///system list --name", sysexec.Result{Stdout: []byte("\n")})
	if err := h.Release(ctx, "gaming"); err != nil {
		t.Fatal(err)
	}
}

// blockingKernel hangs on one sysfs write until released.
type blockingKernel struct {
	*fakeSys
	path    string
	release chan struct{}
}

func (k *blockingKernel) WriteSysfs(path, value string) error {
	if path == k.path {
		<-k.release
	}
	return k.fakeSys.WriteSysfs(path, value)
}

func TestHangingUnbindDoesNotHoldTheLock(t *testing.T) {
	f := server(t)
	k := &blockingKernel{fakeSys: f, path: "/sys/bus/pci/drivers/snd_hda_intel/unbind", release: make(chan struct{})}
	h := f.host()
	h.Kernel = k
	// Let the hanging write finish before the fake root goes away.
	t.Cleanup(func() {
		close(k.release)
		for i := 0; i < 500 && h.hanging("0000:01:00.1"); i++ {
			time.Sleep(10 * time.Millisecond)
		}
	})
	h.SysfsTimeout = 100 * time.Millisecond
	ctx := context.Background()
	start := time.Now()
	_, err := h.Prepare(ctx, "gaming", []Device{{Kind: KindGPU, ID: "0000:01:00.0"}})
	if !errors.Is(err, ErrSysfsHung) {
		t.Fatalf("prepare: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("waited for the hanging write")
	}
	// The lock is free, and the hanging device is reported stuck.
	done := make(chan *Inventory, 1)
	go func() { inv, _ := h.Inventory(ctx); done <- inv }()
	select {
	case inv := <-done:
		found := false
		for _, s := range inv.Stuck {
			if s.Address == "0000:01:00.1" {
				found = true
			}
		}
		if !found {
			t.Fatalf("stuck = %+v", inv.Stuck)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the devices lock is still held")
	}
	// Nothing else is written for it while the write hangs.
	if err := h.write("0000:01:00.1", "/sys/bus/pci/drivers_probe", "0000:01:00.1"); err == nil || !strings.Contains(err.Error(), "still hanging") {
		t.Fatalf("second write: %v", err)
	}
}

// --- SR-IOV ---------------------------------------------------------------

func TestSetVFsRules(t *testing.T) {
	f := server(t)
	h := f.host()
	ctx := context.Background()
	// Not a graphics card.
	f.file(f.devPath("0000:03:00.0")+"/sriov_totalvfs", "7\n")
	if err := h.SetVFs(ctx, "0000:03:00.0", 2); err == nil || !strings.Contains(err.Error(), "isn't a graphics card") {
		t.Fatalf("network card: %v", err)
	}
	// An AMD card with SR-IOV: the kernel's interface, never NVIDIA's tool.
	f.file("/usr/lib/nvidia/sriov-manage", "#!/bin/sh\n")
	f.file(f.devPath("0000:02:00.0")+"/sriov_totalvfs", "4\n")
	f.file(f.devPath("0000:02:00.0")+"/sriov_numvfs", "0\n")
	if err := h.SetVFs(ctx, "0000:02:00.0", 0); err != nil {
		t.Fatal(err)
	}
	if len(f.wrote()) != 0 {
		t.Fatalf("wrote for no change: %v", f.wrote())
	}
	if err := h.SetVFs(ctx, "0000:02:00.0", 2); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(f.run.Lines(), "\n"), "sriov-manage") {
		t.Fatal("sriov-manage run for an AMD card")
	}
	if !strings.Contains(strings.Join(f.wrote(), "\n"), "0000:02:00.0/sriov_numvfs < 2") {
		t.Fatalf("writes: %v", f.wrote())
	}
	// The new virtual functions went to a host driver (this card has no
	// autoprobe switch): changing them now is refused.
	vfs := h.virtfns("0000:02:00.0")
	if len(vfs) != 2 || f.driver(vfs[0]) == "" {
		t.Fatalf("vfs = %v", vfs)
	}
	if err := h.SetVFs(ctx, "0000:02:00.0", 0); err == nil || !strings.Contains(err.Error(), "in use by the server's driver") {
		t.Fatalf("VF with a host driver: %v", err)
	}
	// Not on a virtual function itself.
	if err := h.SetVFs(ctx, vfs[0], 0); err == nil || !strings.Contains(err.Error(), "virtual function itself") {
		t.Fatalf("on a VF: %v", err)
	}
}

func TestSetVFsRefusesCriticalCard(t *testing.T) {
	f := server(t)
	// A card whose USB-C controller function holds the boot disk (a USB
	// stick): the card is in the boot disk's path.
	f.file(f.devPath("0000:01:00.0")+"/sriov_totalvfs", "4\n")
	f.mkdir(f.devPath("0000:01:00.0") + "/usb3/3-1/3-1:1.0/host9/target9:0:0/9:0:0:0/block/sdz")
	f.link("/sys/class/block/sdz", f.devPath("0000:01:00.0")+"/usb3/3-1/3-1:1.0/host9/target9:0:0/9:0:0:0/block/sdz")
	f.file("/dev/sdz", "")
	f.link("/dev/disk/by-id/usb-BOOT", "/dev/sdz")
	f.file("/var/lib/hardyos/boot.json", `{"pool":"rpool","disks":[{"byId":"/dev/disk/by-id/usb-BOOT","espPartUUID":"11111111-aaaa-bbbb-cccc-000000000001"}]}`)
	err := f.host().SetVFs(context.Background(), "0000:01:00.0", 2)
	if err == nil || !strings.Contains(err.Error(), "boot disk") {
		t.Fatalf("critical card: %v", err)
	}
}

// --- vGPU slices made outside HardyOS ---------------------------------------

func TestRemoveSliceChecksUsers(t *testing.T) {
	f := server(t)
	f.pci("0000:05:00.0", "10de", "1e30", "0x030000", "nvidia", pciOpt{group: 20, reset: "flr"})
	dir := f.devPath("0000:05:00.0") + "/mdev_supported_types/nvidia-259"
	f.file(dir+"/name", "GRID RTX6000-4Q\n")
	f.file(dir+"/available_instances", "6\n")
	const id = "11111111-2222-5333-8444-555555555555"
	if err := f.WriteSysfs("/sys/bus/pci/devices/0000:05:00.0/mdev_supported_types/nvidia-259/create", id); err != nil {
		t.Fatal(err)
	}
	inst := f.devPath("0000:05:00.0") + "/" + id
	f.mkdir("/sys/kernel/iommu_groups/77/devices")
	f.link(inst+"/iommu_group", "/sys/kernel/iommu_groups/77")
	h := f.host()
	ctx := context.Background()

	// QEMU has its IOMMU group open.
	f.procOpener(4242, "qemu-system-x86", "0::/machine.slice/machine-qemu\\x2d1\\x2dlab.scope", "/dev/vfio/77")
	if err := h.RemoveSlice(ctx, id); err == nil || !strings.Contains(err.Error(), "open by qemu-system-x86") {
		t.Fatalf("open slice: %v", err)
	}
	_ = os.RemoveAll(filepath.Join(f.root, "proc/4242"))

	// An active VM's definition names it.
	f.run.OnResult("virsh -c qemu:///system list --name", sysexec.Result{Stdout: []byte("lab\n")})
	f.run.OnResult("virsh -c qemu:///system dumpxml -- lab", sysexec.Result{Stdout: []byte("<hostdev><source><address uuid='" + strings.ToUpper(id) + "'/></source></hostdev>")})
	if err := h.RemoveSlice(ctx, id); err == nil || !strings.Contains(err.Error(), "VM lab is using") {
		t.Fatalf("defined slice: %v", err)
	}
	// libvirt can't be asked: kept.
	h.Running = func(context.Context) ([]string, error) { return nil, errors.New("down") }
	if err := h.RemoveSlice(ctx, id); err == nil || !strings.Contains(err.Error(), "can't tell") {
		t.Fatalf("libvirt down: %v", err)
	}
	h.Running = func(context.Context) ([]string, error) { return []string{}, nil }
	if err := h.RemoveSlice(ctx, id); err != nil {
		t.Fatal(err)
	}
}

// --- USB by vendor:product ------------------------------------------------

func (f *fakeSys) usbDev(port, vid, pid string) {
	real := f.devPath("0000:00:14.0") + "/usb1/" + port
	f.file(real+"/idVendor", vid+"\n")
	f.file(real+"/idProduct", pid+"\n")
	f.file(real+"/busnum", "1\n")
	f.file(real+"/devnum", strconv.Itoa(10+len(port))+"\n")
	f.file(real+"/bDeviceClass", "00\n")
	f.link("/sys/bus/usb/devices/"+port, real)
}

func TestUSBByIDChecksEveryMatch(t *testing.T) {
	f := server(t)
	h := f.host()
	ctx := context.Background()
	// Two identical sticks: ambiguous by ID.
	f.usbDev("1-5", "0781", "5583")
	f.usbDev("1-6", "0781", "5583")
	p := problems(t, h.Check(ctx, "vm", []Device{{Kind: KindUSB, ID: "0781:5583"}}))
	if !hasProblem(p, "2 USB devices have the ID 0781:5583 (ports 1-5, 1-6)") {
		t.Fatalf("problems = %v", p)
	}
	// By port, each is fine.
	if err := h.Check(ctx, "vm", []Device{{Kind: KindUSB, ID: "1-6"}}); err != nil {
		t.Fatal(err)
	}
	// Same ID as the boot stick: refused even though another match is free.
	f.usbDev("1-7", "0951", "1666")
	f.usbDev("1-8", "0951", "1666")
	stick := f.devPath("0000:00:14.0") + "/usb1/1-8/1-8:1.0/host7/target7:0:0/7:0:0:0/block/sdy"
	f.mkdir(stick)
	f.link("/sys/class/block/sdy", stick)
	f.file("/dev/sdy", "")
	f.link("/dev/disk/by-id/usb-Kingston-BOOT", "/dev/sdy")
	f.file("/var/lib/hardyos/boot.json", `{"pool":"rpool","disks":[{"byId":"/dev/disk/by-id/usb-Kingston-BOOT","espPartUUID":"11111111-aaaa-bbbb-cccc-000000000001"}]}`)
	p = problems(t, h.Check(ctx, "vm", []Device{{Kind: KindUSB, ID: "0951:1666"}}))
	if !hasProblem(p, "(in port 1-8) can't go to a VM") {
		t.Fatalf("problems = %v", p)
	}
}

// --- ROM files --------------------------------------------------------------

func TestROMLibraryChecks(t *testing.T) {
	f := server(t)
	h := f.host()
	ctx := context.Background()
	dir := "/var/lib/hardyos/root/vm-roms"
	f.mkdir(dir)
	// A symlink in the library isn't followed.
	_ = os.Symlink("/etc/shadow", filepath.Join(f.root, dir, "evil.rom"))
	p := problems(t, h.Check(ctx, "vm", []Device{{Kind: KindGPU, ID: "0000:02:00.0", ROMFile: "evil.rom"}}))
	if !hasProblem(p, "can't be used") {
		t.Fatalf("symlink ROM: %v", p)
	}
	// Too large.
	big := make([]byte, MaxROMBytes+1)
	_ = os.WriteFile(filepath.Join(f.root, dir, "big.rom"), big, 0o644)
	p = problems(t, h.Check(ctx, "vm", []Device{{Kind: KindGPU, ID: "0000:02:00.0", ROMFile: "big.rom"}}))
	if !hasProblem(p, "larger than") {
		t.Fatalf("big ROM: %v", p)
	}
	// A good one is copied for the VM; the library file can change later
	// without touching the copy.
	f.file(dir+"/rx580.rom", "ROM1")
	prep, err := h.Prepare(ctx, "win", []Device{{Kind: KindGPU, ID: "0000:02:00.0", ROMFile: "rx580.rom"}})
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(prep[0].XML, "<rom file='")
	rom := prep[0].XML[i+len("<rom file='"):]
	rom = rom[:strings.Index(rom, "'")]
	if !strings.HasPrefix(rom, RomRunDir+"/") {
		t.Fatalf("rom path %s", rom)
	}
	f.file(dir+"/rx580.rom", "ROM2")
	if b, _ := os.ReadFile(filepath.Join(f.root, rom)); string(b) != "ROM1" {
		t.Fatalf("copy = %q", b)
	}
	_ = h.Release(ctx, "win")
}

func TestMigrateRoms(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, LegacyRomDir)
	_ = os.MkdirAll(old, 0o755)
	_ = os.WriteFile(filepath.Join(old, "a.rom"), []byte("A"), 0o644)
	_ = os.WriteFile(filepath.Join(old, "notes.txt"), []byte("x"), 0o644)
	if err := MigrateRoms(root); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(root, DefaultRomDir, "a.rom")); err != nil || string(b) != "A" {
		t.Fatalf("moved: %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(old, "a.rom")); err == nil {
		t.Fatal("old copy kept")
	}
}
