package vms

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/devices"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/")

var x86, _ = ArchFor("amd64")
var arm, _ = ArchFor("arm64")

func testHost() Host {
	return Host{CPUs: 16, MemoryMB: 65536, Pools: []string{"tank", "fast"}, Arch: x86, TPM: true, SecureBoot: true}
}

func testPaths() Paths {
	return Paths{
		StateDir:   "/mnt/tank/vms/win11",
		ISOs:       map[string]string{"Win11_24H2_English_x64.iso": "/mnt/tank/shares/isos/Win11_24H2_English_x64.iso", "OPNsense-25.7-dvd-amd64.iso": "/mnt/tank/shares/isos/OPNsense-25.7-dvd-amd64.iso"},
		Virtio:     "/mnt/tank/shares/isos/virtio-win-0.1.302.iso",
		CloudInit:  "/mnt/tank/vms/web/cloud-init.iso",
		Bridge:     "br0",
		NATNetwork: "default",
	}
}

// fromTemplate builds a spec the way the wizard does.
func fromTemplate(t *testing.T, id, tmpl string) *Spec {
	t.Helper()
	tp, ok := TemplateByID(tmpl)
	if !ok {
		t.Fatalf("no template %s", tmpl)
	}
	var pre Preset
	for _, p := range tp.Presets {
		if p.ID == tp.DefaultPreset {
			pre = p
		}
	}
	s := &Spec{
		ID: id, Name: tp.Name, Template: tp.ID, OS: tp.OS, Pool: "tank",
		UUID:     "6f1c2a9e-3b4d-4c5e-8f90-a1b2c3d4e5f6",
		CPU:      CPU{Cores: pre.Cores, Threads: pre.Threads},
		Memory:   Memory{MB: pre.MemoryMB, Balloon: tp.Balloon},
		Firmware: tp.Firmware,
		Disks:    []Disk{{Name: "disk0", SizeGB: pre.DiskGB, Bus: tp.DiskBus}},
		Video:    tp.Video, GuestAgent: true,
	}
	for i := 0; i < tp.NICs; i++ {
		s.NICs = append(s.NICs, NIC{Mode: NICBridge, Model: tp.NICModel, MAC: []string{"52:54:00:12:34:56", "52:54:00:12:34:57"}[i]})
	}
	if tp.Virtio {
		s.Media = append(s.Media, Media{Kind: MediaVirtio})
	}
	if tp.CloudInit {
		s.Media = append(s.Media, Media{Kind: MediaCloudInit})
		s.CloudInit = &CloudInit{User: "cade", SSHKeys: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHardyOSTestKeyOnlyNotARealOne0000000000 cade@laptop"}, InstallAgent: true}
	}
	s.Normalize()
	return s
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/vms -run XML -update)", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s differs from the golden file (run with -update to accept):\n%s", name, got)
	}
}

func TestDomainXMLGolden(t *testing.T) {
	cases := []struct {
		golden string
		spec   func() *Spec
		arch   ArchInfo
		devs   []devices.Prepared
	}{
		{"windows11.xml", func() *Spec {
			s := fromTemplate(t, "win11", "windows11")
			s.Media = append([]Media{{Kind: MediaISO, ISO: "Win11_24H2_English_x64.iso"}}, s.Media...)
			s.Normalize()
			return s
		}, x86, nil},
		{"linux-cloudinit.xml", func() *Spec {
			s := fromTemplate(t, "web", "linux")
			s.Disks[0].Import = &Import{File: "noble-server-cloudimg-amd64.img"}
			s.Boot = []string{"disk"}
			s.NICs[0].Mode = NICVLAN
			s.NICs[0].VLAN = 20
			s.Autostart = Autostart{Enabled: true, Order: 1, DelaySec: 30}
			return s
		}, x86, nil},
		{"appliance-haos.xml", func() *Spec {
			s := fromTemplate(t, "homeassistant", "haos")
			s.Disks[0].Import = &Import{File: "haos_ova-16.2.qcow2.xz"}
			s.GuestAgent = true
			return s
		}, x86, nil},
		{"appliance-opnsense.xml", func() *Spec {
			s := fromTemplate(t, "router", "opnsense")
			s.Firmware = Firmware{Type: FirmwareBIOS}
			s.Disks[0].Bus = BusSATA
			s.NICs[1].Mode = NICNAT
			s.Media = []Media{{Kind: MediaISO, ISO: "OPNsense-25.7-dvd-amd64.iso"}}
			s.GuestAgent = false
			return s
		}, x86, nil},
		{"gaming-gpu.xml", func() *Spec {
			s := fromTemplate(t, "gaming", "gaming")
			s.Devices = []devices.Device{{Kind: devices.KindGPU, ID: "0000:01:00.0", Primary: true}}
			s.Video = "none"
			return s
		}, x86, []devices.Prepared{{
			Device: devices.Device{Kind: devices.KindGPU, ID: "0000:01:00.0"},
			XML:    `<hostdev mode="subsystem" type="pci" managed="no"><source><address domain="0x0000" bus="0x01" slot="0x00" function="0x0"/></source></hostdev>`,
		}}},
		{"linux-arm64.xml", func() *Spec {
			s := fromTemplate(t, "web", "linux")
			return s
		}, arm, nil},
	}
	for _, c := range cases {
		t.Run(c.golden, func(t *testing.T) {
			s := c.spec()
			h := testHost()
			h.Arch = c.arch
			if err := s.Validate(h); err != nil {
				t.Fatalf("spec isn't valid: %v", err)
			}
			p := testPaths()
			p.StateDir = "/mnt/tank/vms/" + s.ID
			out, err := DomainXML(s, c.arch, p, c.devs)
			if err != nil {
				t.Fatal(err)
			}
			golden(t, c.golden, out)
		})
	}
}

func TestDomainXMLWindows11Essentials(t *testing.T) {
	s := fromTemplate(t, "win11", "windows11")
	out, err := DomainXML(s, x86, testPaths(), nil)
	if err != nil {
		t.Fatal(err)
	}
	x := string(out)
	for _, want := range []string{
		`<os firmware="efi">`, `<feature enabled="yes" name="secure-boot">`, `<loader secure="yes">`,
		`<smm state="on">`, `<tpm model="tpm-crb">`, `<backend type="emulator" version="2.0">`,
		`<hyperv mode="custom">`, `<clock offset="localtime">`, `<nvram>/mnt/tank/vms/win11/nvram.fd</nvram>`,
		`machine="q35"`, `<source dev="/dev/zvol/tank/vms/win11/disk0">`, `<target dev="hv6f1c2a0">`,
		`<seclabel model="dac" relabel="no">`, `<listen type="socket">`,
	} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestDomainXMLEscapes(t *testing.T) {
	s := fromTemplate(t, "web", "linux")
	s.Name = `Dad's <"server"> & more`
	s.Description = "]]><devices><emulator>/bin/sh</emulator></devices>"
	out, err := DomainXML(s, x86, testPaths(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "<emulator>") {
		t.Fatalf("description wasn't escaped:\n%s", out)
	}
}

func TestDeviceFragments(t *testing.T) {
	s := fromTemplate(t, "gaming", "gaming")
	bad := []string{
		`<emulator>/bin/sh</emulator>`,
		`<hostdev/><hostdev/>`,
		`<hostdev></hostdev><disk/>`,
		`<hostdev>`,
		`</devices><devices>`,
		`<qemu:commandline xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0"/>`,
		`<hostdev xmlns:q="x" q:a="1"/>`,
		`<!DOCTYPE x><hostdev/>`,
		`text<hostdev/>`,
		`<?xml-stylesheet x?><hostdev/>`,
	}
	for _, frag := range bad {
		if _, err := DomainXML(s, x86, testPaths(), []devices.Prepared{{XML: frag}}); err == nil {
			t.Errorf("fragment %q was accepted", frag)
		}
	}
	ok := `<hostdev mode="subsystem" type="usb" managed="yes"><source><vendor id="0x1a86"/><product id="0x7523"/></source></hostdev>`
	if _, err := DomainXML(s, x86, testPaths(), []devices.Prepared{{XML: ok}}); err != nil {
		t.Errorf("a USB hostdev was refused: %v", err)
	}
}

func TestDomainXMLNeedsPaths(t *testing.T) {
	s := fromTemplate(t, "win11", "windows11")
	p := testPaths()
	p.Virtio = ""
	if _, err := DomainXML(s, x86, p, nil); err == nil || !strings.Contains(err.Error(), "VirtIO") {
		t.Errorf("no drivers disc: %v", err)
	}
	p = testPaths()
	p.Bridge = ""
	if _, err := DomainXML(s, x86, p, nil); err == nil || !strings.Contains(err.Error(), "bridge") {
		t.Errorf("no bridge: %v", err)
	}
	s.Media = []Media{{Kind: MediaISO, ISO: "missing.iso"}}
	if _, err := DomainXML(s, x86, testPaths(), nil); err == nil {
		t.Error("a disc missing from the library was accepted")
	}
}
