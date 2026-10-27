package devices

import (
	"context"
	"strings"
	"testing"
)

// Fake sysfs layouts for disks the server uses that aren't a plain disk on
// its controller (the security review: such controllers were missed and
// could be handed to a VM from under the server).

// storageHost has six storage controllers, nothing on any of them yet.
func storageHost(t *testing.T) *fakeSys {
	f := newFakeSys(t)
	for i, addr := range []string{"0000:05:00.0", "0000:06:00.0", "0000:07:00.0", "0000:08:00.0", "0000:09:00.0", "0000:0a:00.0", "0000:0b:00.0", "0000:0c:00.0"} {
		class := "0x010601" // SATA
		if i == 0 || i == 7 {
			class = "0x010802" // NVMe
		}
		f.pci(addr, "1b4b", "9230", class, "ahci", pciOpt{group: 40 + i})
	}
	return f
}

// disk adds a SCSI/SATA disk (with partitions) on a controller.
func (f *fakeSys) disk(ctrl, name string, majmin string, parts ...string) {
	real := f.devPath(ctrl) + "/ata1/host0/target0:0:0/0:0:0:0/block/" + name
	f.mkdir(real)
	f.link("/sys/class/block/"+name, real)
	f.file("/dev/"+name, "")
	if majmin != "" {
		f.link("/sys/dev/block/"+majmin, real)
	}
	for _, p := range parts {
		f.mkdir(real + "/" + p)
		f.file(real+"/"+p+"/partition", "1\n")
		f.link("/sys/class/block/"+p, real+"/"+p)
		f.file("/dev/"+p, "")
	}
}

// virtual adds a device-mapper or md device made of slaves.
func (f *fakeSys) virtual(name, majmin string, slaves ...string) {
	real := "/sys/devices/virtual/block/" + name
	f.mkdir(real + "/slaves")
	for _, s := range slaves {
		target := f.devPath2("/sys/class/block/" + s)
		f.link(real+"/slaves/"+s, target)
	}
	f.link("/sys/class/block/"+name, real)
	f.file("/dev/"+name, "")
	if majmin != "" {
		f.link("/sys/dev/block/"+majmin, real)
	}
}

// devPath2 resolves any link under the fake root to its real path.
func (f *fakeSys) devPath2(p string) string {
	f.t.Helper()
	return resolveFake(f, p)
}

func resolveFake(f *fakeSys, p string) string {
	h := f.host()
	r := h.resolve(p)
	if r == "" {
		f.t.Fatalf("can't resolve %s", p)
	}
	return r
}

func critOf(t *testing.T, f *fakeSys) map[string]string {
	t.Helper()
	pci := f.host().readPCI()
	crit, _ := f.host().critical(context.Background(), pci)
	return crit
}

func wantCritical(t *testing.T, crit map[string]string, addr, reason string) {
	t.Helper()
	if !strings.Contains(crit[addr], reason) {
		t.Errorf("%s: critical = %q, want %q", addr, crit[addr], reason)
	}
}

func TestCriticalNVMeMultipathHead(t *testing.T) {
	for _, layout := range []string{"multipath", "subsystem"} {
		t.Run(layout, func(t *testing.T) {
			f := storageHost(t)
			// Two controllers (dual-port NVMe) in one subsystem; the namespace
			// head nvme0n1 is a virtual device under the subsystem.
			sub := "/sys/devices/virtual/nvme-subsystem/nvme-subsys0"
			for i, ctrl := range []string{"0000:05:00.0", "0000:0c:00.0"} {
				c := "nvme" + string(rune('0'+i))
				cdir := f.devPath(ctrl) + "/nvme/" + c
				f.mkdir(cdir + "/" + c + "c" + string(rune('0'+i)) + "n1")
				f.link(cdir+"/device", f.devPath(ctrl))
				f.link(sub+"/"+c, cdir)
				if layout == "multipath" {
					f.link(sub+"/nvme0n1/multipath/"+c+"c"+string(rune('0'+i))+"n1", cdir+"/"+c+"c"+string(rune('0'+i))+"n1")
				}
			}
			f.mkdir(sub + "/nvme0n1/nvme0n1p1")
			f.file(sub+"/nvme0n1/nvme0n1p1/partition", "1\n")
			f.link("/sys/class/block/nvme0n1", sub+"/nvme0n1")
			f.link("/sys/class/block/nvme0n1p1", sub+"/nvme0n1/nvme0n1p1")
			f.file("/dev/nvme0n1p1", "")
			f.run.On("zpool list -v -H -P -o name", "tank\n\tmirror-0\n\t\t/dev/nvme0n1p1\n")
			crit := critOf(t, f)
			wantCritical(t, crit, "0000:05:00.0", `storage pool "tank"`)
			wantCritical(t, crit, "0000:0c:00.0", `storage pool "tank"`)
			if crit["0000:06:00.0"] != "" {
				t.Errorf("unrelated controller marked: %v", crit)
			}
		})
	}
}

func TestCriticalStackedDisks(t *testing.T) {
	f := storageHost(t)
	// LUKS (dm-crypt) on sdb2, under the pool "secure".
	f.disk("0000:06:00.0", "sdb", "", "sdb2")
	f.virtual("dm-0", "", "sdb2")
	f.link("/dev/mapper/luks-secure", "/dev/dm-0")
	// md RAID1 on sdc1 + sdd1 (two controllers), mounted at /srv (9:0).
	f.disk("0000:07:00.0", "sdc", "", "sdc1")
	f.disk("0000:08:00.0", "sdd", "", "sdd1")
	f.virtual("md0", "9:0", "sdc1", "sdd1")
	// dm-multipath over sde and sdf (two HBAs), with LVM on top (dm-2 on
	// dm-1), under the pool "san".
	f.disk("0000:09:00.0", "sde", "")
	f.disk("0000:0a:00.0", "sdf", "")
	f.virtual("dm-1", "", "sde", "sdf")
	f.virtual("dm-2", "", "dm-1")
	f.link("/dev/mapper/san-lv", "/dev/dm-2")
	// Swap on sdg2.
	f.disk("0000:0b:00.0", "sdg", "8:96", "sdg2")
	f.file("/proc/swaps", "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/dev/sdg2                               partition\t8388604\t\t0\t\t-2\n")
	f.file("/proc/self/mountinfo", strings.Join([]string{
		"22 1 0:21 / / rw,relatime shared:1 - zfs rpool/ROOT/hardyos-0.5.0 rw,xattr,posixacl",
		"25 22 0:5 / /dev rw,nosuid shared:2 - devtmpfs udev rw",
		"90 22 9:0 / /srv\\040data rw,relatime shared:40 - ext4 /dev/md0 rw",
	}, "\n")+"\n")
	f.run.On("zpool list -v -H -P -o name", "secure\n\t/dev/mapper/luks-secure\nsan\n\t/dev/mapper/san-lv\n")

	crit := critOf(t, f)
	wantCritical(t, crit, "0000:06:00.0", `storage pool "secure"`)
	wantCritical(t, crit, "0000:07:00.0", "mounted (/srv data)")
	wantCritical(t, crit, "0000:08:00.0", "mounted (/srv data)")
	wantCritical(t, crit, "0000:09:00.0", `storage pool "san"`)
	wantCritical(t, crit, "0000:0a:00.0", `storage pool "san"`)
	wantCritical(t, crit, "0000:0b:00.0", "swap space")
	if crit["0000:05:00.0"] != "" || crit["0000:0c:00.0"] != "" {
		t.Errorf("unused controllers marked: %v", crit)
	}
	// And the plan refuses them.
	f.file("/proc/cmdline", "intel_iommu=on\n")
	_, probs := f.host().plan(context.Background(), "vm1", []Device{{Kind: KindPCI, ID: "0000:0a:00.0"}}, f.host().loadState(), f.host().inventory(context.Background(), f.host().loadState()))
	if !hasProblem(probs, "can't go to a VM") {
		t.Fatalf("problems = %v", probs)
	}
}

// A slaves loop (never real, but sysfs is input) ends.
func TestCriticalSlavesLoop(t *testing.T) {
	f := storageHost(t)
	f.mkdir("/sys/devices/virtual/block/dm-5/slaves")
	f.mkdir("/sys/devices/virtual/block/dm-6/slaves")
	f.link("/sys/class/block/dm-5", "/sys/devices/virtual/block/dm-5")
	f.link("/sys/class/block/dm-6", "/sys/devices/virtual/block/dm-6")
	f.link("/sys/devices/virtual/block/dm-5/slaves/dm-6", "/sys/devices/virtual/block/dm-6")
	f.link("/sys/devices/virtual/block/dm-6/slaves/dm-5", "/sys/devices/virtual/block/dm-5")
	f.file("/dev/dm-5", "")
	f.run.On("zpool list -v -H -P -o name", "loop\n\t/dev/dm-5\n")
	_ = critOf(t, f) // returns
}
