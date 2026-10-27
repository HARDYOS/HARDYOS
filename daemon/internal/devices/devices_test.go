package devices

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		_ = os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("golden %s: %v (run with -update)", name, err)
	}
	if string(want) != got {
		t.Errorf("%s differs:\n--- got\n%s--- want\n%s", name, got, want)
	}
}

func gpuOf(inv *Inventory, addr string) *GPU {
	for i := range inv.GPUs {
		if inv.GPUs[i].Address == addr {
			return &inv.GPUs[i]
		}
	}
	return nil
}

func problems(t *testing.T, err error) Problems {
	t.Helper()
	var p Problems
	if !errors.As(err, &p) {
		t.Fatalf("want Problems, got %v", err)
	}
	return p
}

func hasProblem(p Problems, sub string) bool {
	for _, x := range p {
		if strings.Contains(x.Message, sub) {
			return true
		}
	}
	return false
}

func TestInventory(t *testing.T) {
	f := server(t)
	inv, err := f.host().Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !inv.IOMMU.Enabled || inv.IOMMU.CPUVendor != "intel" || !inv.IOMMU.CanTurnOn || inv.IOMMU.Configured {
		t.Fatalf("iommu = %+v", inv.IOMMU)
	}
	if len(inv.GPUs) != 3 {
		t.Fatalf("gpus = %+v", inv.GPUs)
	}
	q := gpuOf(inv, "0000:01:00.0")
	if q.Vendor != "nvidia" || q.Model != "TU104GL [Quadro RTX 4000]" || len(q.Functions) != 4 || q.Owner.Kind != OwnerApps || q.Problem != "" {
		t.Fatalf("quadro = %+v", q)
	}
	if q.Functions[1].Kind != "Audio (HDMI/DisplayPort)" || q.Functions[2].Kind != "USB controller" {
		t.Errorf("functions = %+v", q.Functions)
	}
	amd := gpuOf(inv, "0000:02:00.0")
	if amd.VRAMBytes != 8<<30 || len(amd.Hints) == 0 || !strings.Contains(amd.Hints[0], "vendor-reset") {
		t.Errorf("amd = %+v", amd)
	}
	intel := gpuOf(inv, "0000:00:02.0")
	if !intel.BootVGA || !intel.SharedMemory || intel.Problem != "" {
		t.Errorf("intel = %+v", intel)
	}
	crit := map[string]string{}
	for _, p := range inv.PCI {
		crit[p.Address] = p.Critical
	}
	if !strings.Contains(crit["0000:00:17.0"], "boot disk (sda)") {
		t.Errorf("SATA controller: %q", crit["0000:00:17.0"])
	}
	if !strings.Contains(crit["0000:00:1f.6"], "network port the server uses (eno1)") {
		t.Errorf("LAN port: %q", crit["0000:00:1f.6"])
	}
	if crit["0000:03:00.0"] != "" || crit["0000:01:00.0"] != "" {
		t.Errorf("unexpected critical: %v", crit)
	}
	var g13 *Group
	for i := range inv.Groups {
		if inv.Groups[i].ID == 13 {
			g13 = &inv.Groups[i]
		}
	}
	if g13 == nil || len(g13.Devices) != 3 || !strings.Contains(g13.Explanation, "can't keep them apart") {
		t.Errorf("group 13 = %+v", g13)
	}
	for _, g := range inv.Groups {
		if g.ID == 12 && !strings.Contains(g.Explanation, "one card with 4 parts") {
			t.Errorf("group 12 = %q", g.Explanation)
		}
	}
	if len(inv.USB) != 3 || inv.USB[0].Product != "USB Receiver" || inv.USB[0].Manufacturer != "Logitech, Inc." || !inv.USB[1].Hub {
		t.Errorf("usb = %+v", inv.USB)
	}
}

func TestOnlyGPUStaysWithServer(t *testing.T) {
	f := newFakeSys(t)
	f.pci("0000:00:02.0", "8086", "3e92", "0x030000", "i915", pciOpt{group: 2, bootVGA: true, reset: "flr"})
	h := f.host()
	inv, _ := h.Inventory(context.Background())
	if inv.GPUs[0].Problem == "" {
		t.Fatal("the only GPU may be lent")
	}
	err := h.Check(context.Background(), "win11", []Device{{Kind: KindGPU, ID: "0000:00:02.0"}})
	if p := problems(t, err); !hasProblem(p, "only graphics card") {
		t.Fatalf("problems = %v", p)
	}
}

func TestCheckRefusals(t *testing.T) {
	f := server(t)
	// Jellyfin (an app) has the Quadro open.
	f.procOpener(4242, "jellyfin", "0::/hardyos.slice/hardyos-app-jellyfin.slice/docker-abc.scope", "/dev/nvidia0")
	// nvidia-persistenced doesn't count: HardyOS stops it itself.
	f.procOpener(99, "nvidia-persistenced", "0::/system.slice/nvidia-persistenced.service", "/dev/nvidia0")
	h := f.host()
	ctx := context.Background()
	cases := []struct {
		ds   []Device
		want string
	}{
		{[]Device{{Kind: KindGPU, ID: "0000:01:00.0"}}, "in use by the app jellyfin right now"},
		{[]Device{{Kind: KindPCI, ID: "0000:00:17.0"}}, "boot disk"},
		{[]Device{{Kind: KindPCI, ID: "0000:00:1f.6"}}, "network port the server uses"},
		{[]Device{{Kind: KindPCI, ID: "0000:00:01.0"}}, "PCI bridge"},
		{[]Device{{Kind: KindPCI, ID: "0000:09:00.0"}}, "no PCI device at"},
		{[]Device{{Kind: KindPCI, ID: "1:0.0"}}, "isn't a PCI address"},
		{[]Device{{Kind: KindGPU, ID: "0000:00:14.0"}}, "isn't a graphics card"},
		{[]Device{{Kind: KindUSB, ID: "1-3"}}, "USB hub"},
		{[]Device{{Kind: KindUSB, ID: "1-9"}}, "Nothing is plugged into USB port 1-9"},
		{[]Device{{Kind: KindUSB, ID: "not-usb"}}, "isn't a USB device ID"},
		{[]Device{{Kind: KindVGPU, ID: "0000:02:00.0", VGPUType: "x"}}, "doesn't offer vGPU slices"},
		{[]Device{{Kind: KindGPU, ID: "0000:02:00.0", ROMFile: "../evil.rom"}}, "ROM file names"},
		{[]Device{{Kind: KindGPU, ID: "0000:02:00.0", ROMFile: "rx580.rom"}}, "isn't in the ROM library"},
		{[]Device{{Kind: KindGPU, ID: "0000:02:00.0"}, {Kind: KindGPU, ID: "0000:02:00.0"}}, "listed twice"},
		{[]Device{{Kind: KindGPU, ID: "0000:02:00.0"}, {Kind: KindPCI, ID: "0000:02:00.1"}}, "listed twice"},
		{[]Device{{Kind: "floppy", ID: "a"}}, "Unknown device kind"},
	}
	for _, c := range cases {
		err := h.Check(ctx, "win11", c.ds)
		if p := problems(t, err); !hasProblem(p, c.want) {
			t.Errorf("%+v: want %q, got %v", c.ds, c.want, p)
		}
	}
	if err := h.Check(ctx, "bad name!", nil); err == nil {
		t.Error("bad VM name accepted")
	}
	// Absent USB by ID is fine (the VM starts without it); present ones too.
	if err := h.Check(ctx, "win11", []Device{{Kind: KindUSB, ID: "1234:abcd"}, {Kind: KindUSB, ID: "10c4:ea60"}, {Kind: KindUSB, ID: "1-2"}}); err != nil {
		t.Fatalf("usb: %v", err)
	}
	// Check changes nothing.
	if w := f.wrote(); len(w) != 0 {
		t.Fatalf("check wrote %v", w)
	}
}

func TestIOMMUOffRefusesPCI(t *testing.T) {
	f := server(t)
	_ = os.RemoveAll(filepath.Join(f.root, "sys/kernel/iommu_groups"))
	_ = os.MkdirAll(filepath.Join(f.root, "sys/kernel/iommu_groups"), 0o755)
	h := f.host()
	err := h.Check(context.Background(), "win11", []Device{{Kind: KindPCI, ID: "0000:03:00.0"}})
	if p := problems(t, err); !hasProblem(p, "IOMMU is off") || !hasProblem(p, "Turn on IOMMU") {
		t.Fatalf("problems = %v", p)
	}
	// USB needs no IOMMU.
	if err := h.Check(context.Background(), "win11", []Device{{Kind: KindUSB, ID: "1-2"}}); err != nil {
		t.Fatal(err)
	}
}

// The ownership state machine: Docker apps -> VM -> Docker apps.
func TestGPUOwnershipRoundTrip(t *testing.T) {
	f := server(t)
	f.file("/lib/systemd/system/nvidia-persistenced.service", "")
	f.run.OnResult("systemctl is-active --quiet nvidia-persistenced.service", sysexec.Result{})
	f.run.OnPrefix("systemctl stop ", sysexec.Result{})
	f.run.OnPrefix("systemctl start ", sysexec.Result{})
	h := f.host()
	ctx := context.Background()

	prep, err := h.Prepare(ctx, "gaming", []Device{{Kind: KindGPU, ID: "0000:01:00.0", Primary: true}, {Kind: KindUSB, ID: "046d:c52b"}, {Kind: KindUSB, ID: "1-3.1"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"0000:01:00.0", "0000:01:00.1", "0000:01:00.2", "0000:01:00.3"} {
		if d := f.driver(a); d != "vfio-pci" {
			t.Errorf("%s on %q", a, d)
		}
	}
	if len(prep) != 3 || len(prep[0].Addresses) != 4 {
		t.Fatalf("prepared = %+v", prep)
	}
	golden(t, "gpu_quadro.xml", prep[0].XML)
	golden(t, "usb_by_id.xml", prep[1].XML)
	golden(t, "usb_by_port.xml", prep[2].XML)
	lines := strings.Join(f.run.Lines(), "\n")
	if !strings.Contains(lines, "systemctl stop nvidia-persistenced.service") || !strings.Contains(lines, "modprobe vfio-pci") {
		t.Errorf("commands:\n%s", lines)
	}

	inv, _ := h.Inventory(ctx)
	if g := gpuOf(inv, "0000:01:00.0"); g.Owner.Kind != OwnerVM || g.Owner.VM != "gaming" {
		t.Fatalf("owner = %+v", g.Owner)
	}
	// Another VM can't have it.
	if p := problems(t, h.Check(ctx, "other", []Device{{Kind: KindGPU, ID: "0000:01:00.0"}})); !hasProblem(p, "in use by the VM gaming") {
		t.Fatalf("problems = %v", p)
	}
	if p := problems(t, h.Check(ctx, "other", []Device{{Kind: KindUSB, ID: "046d:c52b"}})); !hasProblem(p, "VM gaming") {
		t.Fatalf("usb problems = %v", p)
	}
	// Released while running: refused.
	f.run.OnResult("virsh -c qemu:///system list --name --state-running", sysexec.Result{Stdout: []byte("gaming\n")})
	if err := h.Release(ctx, "gaming"); err == nil || !strings.Contains(err.Error(), "still running") {
		t.Fatalf("release while running: %v", err)
	}
	f.run.OnResult("virsh -c qemu:///system list --name --state-running", sysexec.Result{Stdout: []byte("\n")})
	if err := h.Release(ctx, "gaming"); err != nil {
		t.Fatal(err)
	}
	for a, want := range map[string]string{"0000:01:00.0": "nvidia", "0000:01:00.1": "snd_hda_intel", "0000:01:00.2": "xhci_hcd", "0000:01:00.3": "nvidia-gpu"} {
		if d := f.driver(a); d != want {
			t.Errorf("%s back on %q, want %s", a, d, want)
		}
		ov, _ := os.ReadFile(filepath.Join(f.root, f.devPath(a), "driver_override"))
		if strings.TrimSpace(string(ov)) != "(null)" {
			t.Errorf("%s override left: %q", a, ov)
		}
	}
	if !strings.Contains(strings.Join(f.run.Lines(), "\n"), "systemctl start nvidia-persistenced.service") {
		t.Error("persistence daemon not started again")
	}
	inv, _ = h.Inventory(ctx)
	if g := gpuOf(inv, "0000:01:00.0"); g.Owner.Kind != OwnerApps {
		t.Fatalf("owner after release = %+v", g.Owner)
	}
	// Releasing again is a no-op.
	if err := h.Release(ctx, "gaming"); err != nil {
		t.Fatal(err)
	}
}

func TestGroupCompanionsAreHeldAndReturned(t *testing.T) {
	f := server(t)
	h := f.host()
	ctx := context.Background()
	prep, err := h.Prepare(ctx, "win11", []Device{{Kind: KindGPU, ID: "0000:02:00.0"}})
	if err != nil {
		t.Fatal(err)
	}
	// The second network port shares group 13: off the server, not in the VM.
	if d := f.driver("0000:03:00.0"); d != "vfio-pci" {
		t.Fatalf("companion on %q", d)
	}
	if strings.Contains(prep[0].XML, "bus='0x03'") {
		t.Fatalf("companion given to the VM:\n%s", prep[0].XML)
	}
	if err := h.Release(ctx, "win11"); err != nil {
		t.Fatal(err)
	}
	if d := f.driver("0000:03:00.0"); d != "igb" {
		t.Fatalf("companion back on %q", d)
	}

	// If that port were the server's LAN port, the card couldn't go.
	f.file("/proc/net/route", "Iface\tDestination\tGateway\tFlags\nenp3s0\t00000000\t0102A8C0\t0003\n")
	err = h.Check(ctx, "win11", []Device{{Kind: KindGPU, ID: "0000:02:00.0"}})
	if p := problems(t, err); !hasProblem(p, "shares IOMMU group 13 with 0000:03:00.0") {
		t.Fatalf("problems = %v", p)
	}
}

func TestPrepareFailureUndoes(t *testing.T) {
	f := server(t)
	f.failUnbind["0000:01:00.2"] = true
	h := f.host()
	if _, err := h.Prepare(context.Background(), "gaming", []Device{{Kind: KindGPU, ID: "0000:01:00.0"}}); err == nil {
		t.Fatal("prepare succeeded")
	}
	for a, want := range map[string]string{"0000:01:00.0": "nvidia", "0000:01:00.1": "snd_hda_intel", "0000:01:00.2": "xhci_hcd"} {
		if d := f.driver(a); d != want {
			t.Errorf("%s left on %q", a, d)
		}
	}
	if len(h.Owners()) != 0 {
		t.Fatalf("owners = %v", h.Owners())
	}
}

func TestStuckAfterResetBugAndReconcile(t *testing.T) {
	f := server(t)
	h := f.host()
	ctx := context.Background()
	if _, err := h.Prepare(ctx, "win11", []Device{{Kind: KindGPU, ID: "0000:02:00.0"}}); err != nil {
		t.Fatal(err)
	}
	f.noRebind["0000:02:00.0"] = true
	err := h.Release(ctx, "win11")
	if err == nil || !strings.Contains(err.Error(), "0000:02:00.0 didn't go back to its driver amdgpu") {
		t.Fatalf("release: %v", err)
	}
	inv, _ := h.Inventory(ctx)
	g := gpuOf(inv, "0000:02:00.0")
	if g.Owner.Kind != OwnerStuck || len(inv.Stuck) != 1 || !strings.Contains(inv.Stuck[0].Message, "vendor-reset") {
		t.Fatalf("owner = %+v stuck = %+v", g.Owner, inv.Stuck)
	}
	// The audio function and the companion port did come back.
	if f.driver("0000:02:00.1") != "snd_hda_intel" || f.driver("0000:03:00.0") != "igb" {
		t.Fatal("other functions not returned")
	}
	// Reconcile tries again (the card reset meanwhile).
	delete(f.noRebind, "0000:02:00.0")
	if err := h.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if f.driver("0000:02:00.0") != "amdgpu" {
		t.Fatal("not returned by reconcile")
	}
	inv, _ = h.Inventory(ctx)
	if len(inv.Stuck) != 0 {
		t.Fatalf("stuck = %+v", inv.Stuck)
	}
}

func TestReconcileAfterCrash(t *testing.T) {
	f := server(t)
	h := f.host()
	ctx := context.Background()
	if _, err := h.Prepare(ctx, "gaming", []Device{{Kind: KindGPU, ID: "0000:01:00.0"}}); err != nil {
		t.Fatal(err)
	}
	// hardyd-priv restarts (a new Host, same state file); the VM stopped meanwhile.
	h2 := f.host()
	h2.Running = func(context.Context) ([]string, error) { return nil, errors.New("libvirt is down") }
	if err := h2.Reconcile(ctx); err == nil {
		t.Fatal("released without knowing what runs")
	}
	if f.driver("0000:01:00.0") != "vfio-pci" {
		t.Fatal("released while unsure")
	}
	h2.Running = func(context.Context) ([]string, error) { return []string{}, nil }
	// Within the start-up grace period the VM may still be starting.
	if err := h2.Reconcile(ctx); err != nil || f.driver("0000:01:00.0") != "vfio-pci" {
		t.Fatalf("released during start-up: %v", err)
	}
	st := h2.loadState()
	st.VMs["gaming"].ReadyAt = st.VMs["gaming"].ReadyAt.Add(-readyGrace - 1)
	if err := h2.saveState(st); err != nil {
		t.Fatal(err)
	}
	h2.Running = func(context.Context) ([]string, error) { return []string{"other"}, nil }
	if err := h2.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if f.driver("0000:01:00.0") != "nvidia" || len(h2.Owners()) != 0 {
		t.Fatalf("not released: %s %v", f.driver("0000:01:00.0"), h2.Owners())
	}

	// A running VM keeps its devices.
	if _, err := h2.Prepare(ctx, "gaming", []Device{{Kind: KindGPU, ID: "0000:01:00.0"}}); err != nil {
		t.Fatal(err)
	}
	h2.Running = func(context.Context) ([]string, error) { return []string{"gaming"}, nil }
	if err := h2.Reconcile(ctx); err != nil || f.driver("0000:01:00.0") != "vfio-pci" {
		t.Fatalf("running VM lost its GPU: %v", err)
	}

	// After a restart (new boot ID) the old state is void.
	f.file("/proc/sys/kernel/random/boot_id", "boot-2\n")
	if len(f.host().Owners()) != 0 {
		t.Fatal("state survived a reboot")
	}
}

func TestPrepareAgainReleasesLeftovers(t *testing.T) {
	f := server(t)
	h := f.host()
	ctx := context.Background()
	if _, err := h.Prepare(ctx, "gaming", []Device{{Kind: KindGPU, ID: "0000:01:00.0"}}); err != nil {
		t.Fatal(err)
	}
	// No Release (the VM crashed); the next start works.
	if _, err := h.Prepare(ctx, "gaming", []Device{{Kind: KindGPU, ID: "0000:01:00.0"}}); err != nil {
		t.Fatal(err)
	}
	if f.driver("0000:01:00.0") != "vfio-pci" {
		t.Fatal("not bound")
	}
	if err := h.Release(ctx, "gaming"); err != nil || f.driver("0000:01:00.0") != "nvidia" {
		t.Fatalf("release: %v", err)
	}
}

func TestPCIWithROM(t *testing.T) {
	f := server(t)
	f.file("/var/lib/hardyos/vm-roms/rx580.rom", "ROM")
	h := f.host()
	prep, err := h.Prepare(context.Background(), "win11", []Device{{Kind: KindGPU, ID: "0000:02:00.0", ROMFile: "rx580.rom"}, {Kind: KindPCI, ID: "0000:00:14.0"}})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "gpu_amd_rom.xml", prep[0].XML)
	golden(t, "pci_usb_controller.xml", prep[1].XML)
	_ = h.Release(context.Background(), "win11")
}

func TestXMLRefusesBadValues(t *testing.T) {
	if _, err := HostdevPCI("0000:01:00.0'/>", ""); err == nil {
		t.Error("bad address")
	}
	if _, err := HostdevPCI("0000:01:00.0", "rom.rom"); err == nil {
		t.Error("relative rom")
	}
	if _, err := HostdevMdev("not-a-uuid"); err == nil {
		t.Error("bad uuid")
	}
	if _, err := HostdevUSBByID("zzzz", "1"); err == nil {
		t.Error("bad usb id")
	}
	if _, err := HostdevUSBByAddress(0, 1); err == nil {
		t.Error("bad usb address")
	}
	defer func() {
		if recover() == nil {
			t.Error("unsafe attribute accepted")
		}
	}()
	_, _ = HostdevPCI("0000:01:00.0", "/a'b.rom")
}

func TestStableUUID(t *testing.T) {
	a := stableUUID("vm", "0000:01:00.0", "nvidia-256", 0)
	if a != stableUUID("vm", "0000:01:00.0", "nvidia-256", 0) || a == stableUUID("vm", "0000:01:00.0", "nvidia-256", 1) || !uuidRE.MatchString(a) {
		t.Fatalf("uuid %s", a)
	}
}
