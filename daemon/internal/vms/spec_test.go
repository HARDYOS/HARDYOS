package vms

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/devices"
)

func TestEveryTemplateMakesAValidVM(t *testing.T) {
	for _, tp := range Templates {
		s := fromTemplate(t, "vm-"+tp.ID, tp.ID)
		if len(tp.Presets) != 3 || tp.DefaultPreset == "" {
			t.Errorf("%s: presets", tp.ID)
		}
		for _, p := range tp.Presets {
			if p.MemoryMB < tp.MinMemoryMB || p.DiskGB < tp.MinDiskGB {
				t.Errorf("%s/%s is below the template's minimum", tp.ID, p.ID)
			}
		}
		if err := s.Validate(testHost()); err != nil {
			t.Errorf("%s: %v", tp.ID, err)
		}
		if _, err := DomainXML(s, x86, testPaths(), nil); err != nil {
			t.Errorf("%s: %v", tp.ID, err)
		}
	}
}

func TestValidateListsEveryProblem(t *testing.T) {
	s := fromTemplate(t, "win11", "windows11")
	s.ID = "Bad Name"
	s.CPU = CPU{Cores: 0, Threads: 3}
	s.Memory.MB = 64
	s.Disks = append(s.Disks, Disk{Name: "disk0", SizeGB: 0, Bus: "ide"})
	s.Media = append(s.Media, Media{Kind: MediaISO, ISO: "../../etc/shadow"}, Media{Kind: MediaVirtio})
	s.NICs = append(s.NICs, NIC{Mode: NICVLAN, VLAN: 5000, Model: "rtl8139", MAC: "01:00:5e:00:00:01"})
	s.Boot = []string{"disk", "disk", "floppy"}
	s.Devices = []devices.Device{{Kind: "gpu", ID: "01:00.0"}, {Kind: "usb", ID: "abc"}, {Kind: "pci", ID: "0000:02:00.0", Primary: true}, {Kind: "vgpu", ID: "0000:01:00.0"}}
	s.Firmware = Firmware{Type: FirmwareBIOS, SecureBoot: true}
	err := s.Validate(testHost())
	p, ok := err.(Problems)
	if !ok {
		t.Fatalf("err = %v", err)
	}
	all := strings.Join(p, "\n")
	for _, want := range []string{
		"isn't a valid VM name", "1 to 256 CPU cores", "threads per core", "memory must be",
		"two disks called disk0", "disk0: size must be", "virtio-scsi, virtio-blk or sata",
		"isn't a file name", "attached once", "VLAN must be 1 to 4094", "virtio or e1000e", "usable MAC",
		"boot order", "PCI address", "USB device", "only a whole GPU", "vGPU", "Secure Boot needs UEFI",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("no problem about %q in:\n%s", want, all)
		}
	}
}

func TestValidateHostLimits(t *testing.T) {
	s := fromTemplate(t, "win11", "windows11")
	h := testHost()
	h.TPM, h.SecureBoot = false, false
	h.Pools = []string{"other"}
	err := s.Validate(h)
	for _, want := range []string{"no Secure Boot firmware", "no virtual TPM", `no pool called "tank"`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	// ARM servers have no SATA and no BIOS.
	a := fromTemplate(t, "router", "opnsense")
	a.Disks[0].Bus = BusSATA
	a.Firmware = Firmware{Type: FirmwareBIOS}
	h = testHost()
	h.Arch = arm
	err = a.Validate(h)
	if err == nil || !strings.Contains(err.Error(), "no SATA") || !strings.Contains(err.Error(), "only have UEFI") {
		t.Errorf("arm64: %v", err)
	}
}

func TestCloudInitCantBeInjected(t *testing.T) {
	s := fromTemplate(t, "web", "linux")
	s.CloudInit.SSHKeys = []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHardyOS key\nruncmd: [rm -rf /]"}
	if err := s.Validate(testHost()); err == nil || !strings.Contains(err.Error(), "SSH key") {
		t.Fatalf("a multi-line key: %v", err)
	}
	s = fromTemplate(t, "web", "linux")
	s.CloudInit.SSHKeys = []string{`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHardyOSTestKey0000 "quotes" & stuff`}
	ud, err := UserData(s)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(ud), "#cloud-config\n") {
		t.Fatalf("user-data: %s", ud)
	}
	var cfg map[string]any
	if err := json.Unmarshal(ud[len("#cloud-config\n"):], &cfg); err != nil {
		t.Fatalf("user-data isn't JSON: %v\n%s", err, ud)
	}
	users := cfg["users"].([]any)
	if u := users[0].(map[string]any); u["name"] != "cade" || u["lock_passwd"] != true {
		t.Fatalf("user = %v", u)
	}
	if cfg["packages"].([]any)[0] != "qemu-guest-agent" {
		t.Fatalf("agent: %v", cfg["packages"])
	}
	md := string(MetaData(s))
	if !strings.Contains(md, `"instance-id":"6f1c2a9e-3b4d-4c5e-8f90-a1b2c3d4e5f6"`) {
		t.Fatalf("meta-data: %s", md)
	}
}

func TestFileNames(t *testing.T) {
	for _, ok := range []string{"Win11_24H2_English_x64.iso", "haos_ova-16.2.qcow2.xz", "ubuntu 24.04 (server).iso"} {
		if ValidFile(ok) != nil {
			t.Errorf("refused %q", ok)
		}
	}
	for _, bad := range []string{"", ".hidden.iso", "a/b.iso", "../x.iso", "x..iso", " lead.iso", "new\nline.iso", strings.Repeat("a", 201)} {
		if ValidFile(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if !IsISO("A.ISO") || IsISO("a.img") || !IsDiskImage("a.qcow2.xz") || IsDiskImage("a.iso") {
		t.Error("extensions")
	}
	if formatFor("x.qcow2.xz") != "qcow2" || formatFor("cloud.img") != "" || formatFor("disk.vmdk") != "vmdk" {
		t.Error("formats")
	}
}

func TestMACsAndUUIDs(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		m := NewMAC()
		if !macRE.MatchString(m) || !validMAC(m) || !strings.HasPrefix(m, "52:54:00:") {
			t.Fatalf("mac %s", m)
		}
		u := NewUUID()
		if !uuidRE.MatchString(u) || seen[u] {
			t.Fatalf("uuid %s", u)
		}
		seen[u] = true
	}
	if tapName("6f1c2a9e-3b4d", 2) != "hv6f1c2a2" || len(tapName(NewUUID(), 7)) > 15 {
		t.Fatal("tap names")
	}
}
