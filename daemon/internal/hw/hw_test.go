package hw

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

const lsblkFixture = `{
 "blockdevices": [
  {"name":"sdb","path":"/dev/sdb","size":12000138625024,"type":"disk","rota":true,"model":"WDC WD120EFBX-68B0EN0","serial":"5QG0AAAA","wwn":"0x5000cca2aaaaaaaa","tran":"sata","fstype":null,"label":null,"mountpoints":[null],"hotplug":false,"phy-sec":4096,
   "children":[{"name":"sdb1","path":"/dev/sdb1","size":11999000000000,"type":"part","rota":true,"model":null,"serial":null,"wwn":null,"tran":null,"fstype":"zfs_member","label":"tank","mountpoints":[null],"hotplug":false,"phy-sec":4096}]},
  {"name":"sda","path":"/dev/sda","size":12000138625024,"type":"disk","rota":"1","model":"WDC WD120EFBX-68B0EN0","serial":"5QG0BBBB","wwn":"0x5000cca2bbbbbbbb","tran":"sata","fstype":null,"label":null,"mountpoints":[null],"hotplug":false,"phy-sec":4096},
  {"name":"nvme0n1","path":"/dev/nvme0n1","size":256060514304,"type":"disk","rota":false,"model":"Samsung SSD 980 250GB","serial":"S64BNX0T1","wwn":"eui.002538","tran":"nvme","fstype":null,"label":null,"mountpoints":[null],"hotplug":false,"phy-sec":512,
   "children":[
    {"name":"nvme0n1p1","path":"/dev/nvme0n1p1","size":536870912,"type":"part","rota":false,"model":null,"serial":null,"wwn":null,"tran":"nvme","fstype":"vfat","label":null,"mountpoints":["/boot/efi"],"hotplug":false,"phy-sec":512},
    {"name":"nvme0n1p2","path":"/dev/nvme0n1p2","size":255000000000,"type":"part","rota":false,"model":null,"serial":null,"wwn":null,"tran":"nvme","fstype":"zfs_member","label":"rpool","mountpoints":[null],"hotplug":false,"phy-sec":512}]},
  {"name":"nvme1n1","path":"/dev/nvme1n1","size":1000204886016,"type":"disk","rota":false,"model":"WD Red SN700 1000GB","serial":"22AAA","wwn":null,"tran":"nvme","fstype":null,"label":null,"mountpoints":[null],"hotplug":false,"phy-sec":512},
  {"name":"nvme2n1","path":"/dev/nvme2n1","size":1000204886016,"type":"disk","rota":false,"model":"WD Red SN700 1000GB","serial":"22BBB","wwn":null,"tran":"nvme","fstype":null,"label":null,"mountpoints":[null],"hotplug":false,"phy-sec":512},
  {"name":"sdc","path":"/dev/sdc","size":480103981056,"type":"disk","rota":false,"model":"INTEL SSDSC2KB480G8","serial":"PHYF1","wwn":null,"tran":"sata","fstype":null,"label":null,"mountpoints":[null],"hotplug":false,"phy-sec":4096,
   "children":[{"name":"sdc1","path":"/dev/sdc1","size":480000000000,"type":"part","rota":false,"model":null,"serial":null,"wwn":null,"tran":null,"fstype":"ext4","label":"old","mountpoints":[null],"hotplug":false,"phy-sec":4096}]},
  {"name":"sdd","path":"/dev/sdd","size":31037849600,"type":"disk","rota":false,"model":"SanDisk Ultra","serial":"USB1","wwn":null,"tran":"usb","fstype":"iso9660","label":"HARDYOS","mountpoints":["/run/live/medium"],"hotplug":true,"phy-sec":512},
  {"name":"loop0","path":"/dev/loop0","size":1000000,"type":"loop","rota":false,"model":null,"serial":null,"wwn":null,"tran":null,"fstype":"squashfs","label":null,"mountpoints":["/run/live/rootfs/filesystem.squashfs"],"hotplug":false,"phy-sec":512},
  {"name":"sr0","path":"/dev/sr0","size":1073741312,"type":"rom","rota":true,"model":"VMware SATA CD01","serial":"01","wwn":null,"tran":"sata","fstype":null,"label":null,"mountpoints":[null],"hotplug":true,"phy-sec":2048}
 ]
}`

func link(target string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(target), Mode: fs.ModeSymlink | 0o777}
}

func fakeRoot() fstest.MapFS {
	return fstest.MapFS{
		"dev/disk/by-id/wwn-0x5000cca2aaaaaaaa":                   link("../../sdb"),
		"dev/disk/by-id/ata-WDC_WD120EFBX-68B0EN0_5QG0AAAA":       link("../../sdb"),
		"dev/disk/by-id/ata-WDC_WD120EFBX-68B0EN0_5QG0AAAA-part1": link("../../sdb1"),
		"dev/disk/by-id/ata-WDC_WD120EFBX-68B0EN0_5QG0BBBB":       link("../../sda"),
		"dev/disk/by-id/nvme-eui.002538":                          link("../../nvme0n1"),
		"dev/disk/by-id/nvme-Samsung_SSD_980_250GB_S64BNX0T1":     link("../../nvme0n1"),
		"dev/disk/by-id/nvme-WD_Red_SN700_1000GB_22AAA":           link("../../nvme1n1"),
		"dev/disk/by-id/nvme-WD_Red_SN700_1000GB_22BBB":           link("../../nvme2n1"),

		"proc/cpuinfo": {Data: []byte("processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) E-2388G\nflags\t\t: fpu vmx sse\n\nprocessor\t: 1\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) E-2388G\nflags\t\t: fpu vmx sse\n")},
		"proc/meminfo": {Data: []byte("MemTotal:       131072000 kB\nMemFree:        1000 kB\n")},

		"sys/devices/system/edac/mc/mc0/size_mb": {Data: []byte("131072\n")},
		"sys/kernel/iommu_groups/0/type":         {Data: []byte("DMA\n")},
		"sys/kernel/iommu_groups/1/type":         {Data: []byte("DMA\n")},

		"sys/bus/pci/devices/0000:00:02.0/class":       {Data: []byte("0x030000\n")},
		"sys/bus/pci/devices/0000:00:02.0/vendor":      {Data: []byte("0x8086\n")},
		"sys/bus/pci/devices/0000:00:02.0/device":      {Data: []byte("0x4c8a\n")},
		"sys/bus/pci/devices/0000:00:02.0/driver":      link("../../../bus/pci/drivers/i915"),
		"sys/bus/pci/devices/0000:00:02.0/iommu_group": link("../../../kernel/iommu_groups/1"),
		"sys/bus/pci/devices/0000:00:1f.6/class":       {Data: []byte("0x020000\n")},

		"sys/class/net/lo/address":         {Data: []byte("00:00:00:00:00:00\n")},
		"sys/class/net/eno1/address":       {Data: []byte("3c:ec:ef:00:00:01\n")},
		"sys/class/net/eno1/operstate":     {Data: []byte("up\n")},
		"sys/class/net/eno1/speed":         {Data: []byte("10000\n")},
		"sys/class/net/eno1/device/vendor": {Data: []byte("0x8086\n")},
		"sys/class/net/eno1/device/driver": link("../../../../bus/pci/drivers/ixgbe"),
		"sys/class/net/docker0/address":    {Data: []byte("02:42:00:00:00:00\n")},
	}
}

func TestListDisks(t *testing.T) {
	f := (&sysexec.Fake{}).On("lsblk -J -b -o "+lsblkColumns, lsblkFixture)
	disks, err := ListDisks(context.Background(), f, fakeRoot())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Disk{}
	var order []string
	for _, d := range disks {
		byName[d.Name] = d
		order = append(order, d.Name)
	}
	if got := len(disks); got != 7 {
		t.Fatalf("got %d disks %v, want 7 (loop and rom skipped)", got, order)
	}
	if order[0] != "nvme0n1" || order[3] != "sda" || order[4] != "sdb" {
		t.Errorf("order = %v", order)
	}

	cases := []struct {
		name   string
		usage  UsageState
		kind   DiskKind
		byID   string
		pool   string
		usable bool
	}{
		{"sda", UsageFree, KindHDD, "/dev/disk/by-id/ata-WDC_WD120EFBX-68B0EN0_5QG0BBBB", "", true},
		{"sdb", UsagePool, KindHDD, "/dev/disk/by-id/wwn-0x5000cca2aaaaaaaa", "tank", false},
		{"nvme0n1", UsageBoot, KindNVMe, "/dev/disk/by-id/nvme-Samsung_SSD_980_250GB_S64BNX0T1", "", false},
		{"nvme1n1", UsageFree, KindNVMe, "/dev/disk/by-id/nvme-WD_Red_SN700_1000GB_22AAA", "", true},
		{"sdc", UsageHasData, KindSSD, "/dev/sdc", "", true},
		{"sdd", UsageMounted, KindSSD, "/dev/sdd", "", false},
	}
	for _, c := range cases {
		d, ok := byName[c.name]
		if !ok {
			t.Errorf("%s missing", c.name)
			continue
		}
		if d.Usage != c.usage || d.Kind != c.kind || d.ByID != c.byID || d.Pool != c.pool || d.Usage.Usable() != c.usable {
			t.Errorf("%s = usage %s kind %s byID %s pool %q; want %s %s %s %q",
				c.name, d.Usage, d.Kind, d.ByID, d.Pool, c.usage, c.kind, c.byID, c.pool)
		}
	}
	if byName["sdb"].SizeBytes != 12000138625024 || byName["sdb"].PhysSector != 4096 {
		t.Errorf("sizes not parsed: %+v", byName["sdb"])
	}
	if !byName["sdd"].Removable {
		t.Error("USB stick should be removable")
	}
}

func TestReadSystemAndProfile(t *testing.T) {
	root := fakeRoot()
	sys := ReadSystem(root)
	if sys.CPU.Threads != 2 || sys.CPU.Virtualization != "vt-x" || sys.CPU.Model != "Intel(R) Xeon(R) E-2388G" {
		t.Errorf("cpu = %+v", sys.CPU)
	}
	if sys.Memory.TotalBytes != 131072000*1024 || sys.Memory.ECC == nil || !*sys.Memory.ECC {
		t.Errorf("memory = %+v", sys.Memory)
	}
	if !sys.IOMMUEnabled || sys.IOMMUGroups != 2 {
		t.Errorf("iommu = %v/%d", sys.IOMMUEnabled, sys.IOMMUGroups)
	}
	if len(sys.GPUs) != 1 || sys.GPUs[0].Vendor != "intel" || sys.GPUs[0].Driver != "i915" || *sys.GPUs[0].IOMMUGroup != 1 {
		t.Errorf("gpus = %+v", sys.GPUs)
	}
	if len(sys.NICs) != 1 || sys.NICs[0].Name != "eno1" || sys.NICs[0].SpeedMbps != 10000 || !sys.NICs[0].Up || sys.NICs[0].Driver != "ixgbe" {
		t.Errorf("nics = %+v", sys.NICs)
	}

	f := (&sysexec.Fake{}).On("lsblk -J -b -o "+lsblkColumns, lsblkFixture)
	disks, _ := ListDisks(context.Background(), f, root)
	caps := Profile(sys, disks)
	if !caps.Virtualization || !caps.PCIePassthrough || !caps.HardwareTranscode {
		t.Errorf("caps = %+v", caps)
	}
	// Free flash: nvme1n1, nvme2n1, sdc (has-data but usable) = 3.
	if !caps.SpecialVdev || !caps.SLOG || !caps.L2ARC {
		t.Errorf("cache caps = %+v", caps)
	}
	if caps.ARCMaxBytes == 0 || caps.ARCMaxBytes >= sys.Memory.TotalBytes {
		t.Errorf("arc = %d", caps.ARCMaxBytes)
	}
	foundPLP := false
	for _, a := range caps.Advisories {
		if len(a) > 0 && a[:4] == "The " {
			foundPLP = true
		}
	}
	if !foundPLP {
		t.Errorf("expected power-loss-protection advisory, got %v", caps.Advisories)
	}
}

func TestProfileWithoutIOMMU(t *testing.T) {
	sys := System{CPU: CPU{Virtualization: "amd-v"}, Memory: Memory{TotalBytes: 4 * GiB}}
	caps := Profile(sys, nil)
	if caps.PCIePassthrough || caps.SpecialVdev || caps.L2ARC {
		t.Errorf("caps = %+v", caps)
	}
	if len(caps.Advisories) < 2 {
		t.Errorf("want IOMMU and low-RAM advisories, got %v", caps.Advisories)
	}
}

func TestNaturalLess(t *testing.T) {
	cases := [][2]string{{"sda", "sdb"}, {"sdz", "sdaa"}, {"nvme2n1", "nvme10n1"}, {"nvme0n1", "sda"}}
	for _, c := range cases {
		if !naturalLess(c[0], c[1]) || naturalLess(c[1], c[0]) {
			t.Errorf("want %s < %s", c[0], c[1])
		}
	}
}
