package devices

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/boot"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// An officially supported card (Quadro RTX 6000) on NVIDIA's vGPU host
// driver, which lists mdev types on the card.
func mdevServer(t *testing.T) *fakeSys {
	f := server(t)
	f.pci("0000:05:00.0", "10de", "1e30", "0x030000", "nvidia", pciOpt{group: 20, reset: "flr"})
	f.mkdir("/sys/module/nvidia_vgpu_vfio")
	for id, d := range map[string][3]string{
		"nvidia-256": {"GRID RTX6000-4Q", "num_heads=4, frl_config=60, framebuffer=4096M, max_resolution=7680x4320, max_instance=6", "6"},
		"nvidia-259": {"GRID RTX6000-12Q", "num_heads=4, frl_config=60, framebuffer=12288M, max_resolution=7680x4320, max_instance=2", "2"},
	} {
		dir := f.devPath("0000:05:00.0") + "/mdev_supported_types/" + id
		f.file(dir+"/name", d[0]+"\n")
		f.file(dir+"/description", d[1]+"\n")
		f.file(dir+"/available_instances", d[2]+"\n")
		f.file(dir+"/device_api", "vfio-pci\n")
		f.file(dir+"/create", "")
	}
	return f
}

func TestMdevSlices(t *testing.T) {
	f := mdevServer(t)
	h := f.host()
	ctx := context.Background()
	inv, _ := h.Inventory(ctx)
	g := gpuOf(inv, "0000:05:00.0")
	if g.VGPU == nil || g.VGPU.Mode != ModeMdev || !g.VGPU.HostDriver || len(g.VGPU.Types) != 2 {
		t.Fatalf("vgpu = %+v", g.VGPU)
	}
	if vt := g.VGPU.Types[0]; vt.ID != "nvidia-256" || vt.FramebufferMB != 4096 || vt.MaxInstances != 6 || vt.Available != 6 {
		t.Fatalf("type = %+v", vt)
	}
	// Too many of one type.
	three := []Device{{Kind: KindVGPU, ID: "0000:05:00.0", VGPUType: "nvidia-259"}, {Kind: KindVGPU, ID: "0000:05:00.0", VGPUType: "nvidia-259"}, {Kind: KindVGPU, ID: "0000:05:00.0", VGPUType: "nvidia-259"}}
	if p := problems(t, h.Check(ctx, "a", three)); !hasProblem(p, "room for 2 more") {
		t.Fatalf("problems = %v", p)
	}
	if p := problems(t, h.Check(ctx, "a", []Device{{Kind: KindVGPU, ID: "0000:05:00.0", VGPUType: "nvidia-999"}})); !hasProblem(p, "no vGPU type") {
		t.Fatalf("problems = %v", p)
	}

	prep, err := h.Prepare(ctx, "office", []Device{{Kind: KindVGPU, ID: "0000:05:00.0", VGPUType: "nvidia-256"}, {Kind: KindVGPU, ID: "0000:05:00.0", VGPUType: "nvidia-256"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(prep) != 2 || prep[0].MdevUUID == prep[1].MdevUUID || prep[0].MdevUUID != stableUUID("office", "0000:05:00.0", "nvidia-256", 0) {
		t.Fatalf("prepared = %+v", prep)
	}
	got := strings.ReplaceAll(prep[0].XML, prep[0].MdevUUID, "UUID")
	golden(t, "vgpu_mdev.xml", got)
	// The card itself stays with the vGPU driver.
	if f.driver("0000:05:00.0") != "nvidia" {
		t.Fatal("card rebound")
	}
	inv, _ = h.Inventory(ctx)
	g = gpuOf(inv, "0000:05:00.0")
	if len(g.VGPU.Instances) != 2 || g.VGPU.Instances[0].VM != "office" || g.VGPU.Types[0].Available != 4 || g.Owner.Kind != OwnerVGPU || g.Owner.Label != "vGPU slices (2 in use)" {
		t.Fatalf("after prepare: %+v %+v", g.VGPU, g.Owner)
	}
	// Whole-card passthrough is refused while it has slices.
	if p := problems(t, h.Check(ctx, "b", []Device{{Kind: KindGPU, ID: "0000:05:00.0"}})); !hasProblem(p, "split into vGPU slices") {
		t.Fatalf("problems = %v", p)
	}
	if err := h.RemoveSlice(ctx, prep[0].MdevUUID); err == nil {
		t.Fatal("removed a slice in use")
	}
	if err := h.Release(ctx, "office"); err != nil {
		t.Fatal(err)
	}
	inv, _ = h.Inventory(ctx)
	if g = gpuOf(inv, "0000:05:00.0"); len(g.VGPU.Instances) != 0 || g.VGPU.Types[0].Available != 6 {
		t.Fatalf("after release: %+v", g.VGPU)
	}

	// A leftover instance (made by hand) can be removed.
	if err := f.WriteSysfs("/sys/bus/pci/devices/0000:05:00.0/mdev_supported_types/nvidia-259/create", "11111111-2222-5333-8444-555555555555"); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveSlice(ctx, "11111111-2222-5333-8444-555555555555"); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveSlice(ctx, "../../x"); err == nil {
		t.Fatal("bad id accepted")
	}
}

func TestNvidiaVFSlices(t *testing.T) {
	f := server(t)
	// An A16-style card on NVIDIA's newer vGPU driver: types per virtual function.
	f.pci("0000:06:00.0", "10de", "25b6", "0x030200", "nvidia", pciOpt{group: 21, reset: "flr", sub: map[string]string{"sriov_totalvfs": "4\n"}})
	f.file("/usr/lib/nvidia/sriov-manage", "#!/bin/sh\n")
	for i, a := range []string{"0000:06:00.4", "0000:06:00.5"} {
		f.pci(a, "10de", "25b6", "0x030200", "nvidia", pciOpt{group: 22 + i, physfn: "0000:06:00.0", reset: "flr"})
		f.file(f.devPath(a)+"/nvidia/creatable_vgpu_types", "ID    : vGPU Name\n732   : NVIDIA A16-4Q\n733   : NVIDIA A16-8Q\n")
		f.file(f.devPath(a)+"/nvidia/current_vgpu_type", "0\n")
	}
	h := f.host()
	ctx := context.Background()
	inv, _ := h.Inventory(ctx)
	g := gpuOf(inv, "0000:06:00.0")
	if g.VGPU == nil || g.VGPU.Mode != ModeNvidiaVF || len(g.VGPU.Types) != 2 || g.VGPU.Types[0].Available != 2 || g.VGPU.VFs != 2 {
		t.Fatalf("vgpu = %+v", g.VGPU)
	}
	prep, err := h.Prepare(ctx, "vdi", []Device{{Kind: KindVGPU, ID: "0000:06:00.0", VGPUType: "732"}})
	if err != nil {
		t.Fatal(err)
	}
	if prep[0].Addresses[0] != "0000:06:00.4" || !strings.Contains(prep[0].XML, "function='0x4'") {
		t.Fatalf("prepared = %+v", prep[0])
	}
	b, _ := os.ReadFile(filepath.Join(f.root, f.devPath("0000:06:00.4"), "nvidia/current_vgpu_type"))
	if strings.TrimSpace(string(b)) != "732" {
		t.Fatalf("type = %q", b)
	}
	if err := h.SetVFs(ctx, "0000:06:00.0", 0); err == nil {
		t.Fatal("turned slices off while used")
	}
	if err := h.Release(ctx, "vdi"); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(f.root, f.devPath("0000:06:00.4"), "nvidia/current_vgpu_type"))
	if strings.TrimSpace(string(b)) != "0" {
		t.Fatalf("type after release = %q", b)
	}
	f.run.OnPrefix("/usr/lib/nvidia/sriov-manage ", sysexec.Result{})
	// Already on: nothing to do.
	if err := h.SetVFs(ctx, "0000:06:00.0", 4); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(f.run.Lines(), "\n"), "sriov-manage") {
		t.Fatal("sriov-manage run for no change")
	}
	if err := h.SetVFs(ctx, "0000:06:00.0", 0); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.run.Lines(), "\n"), "/usr/lib/nvidia/sriov-manage -d 0000:06:00.0") {
		t.Fatal("sriov-manage not run")
	}
}

func TestIntelSRIOVSlices(t *testing.T) {
	f := newFakeSys(t)
	f.pci("0000:00:02.0", "8086", "a7a0", "0x030000", "i915", pciOpt{group: 2, bootVGA: true, reset: "flr", sub: map[string]string{"sriov_totalvfs": "7\n", "sriov_numvfs": "0\n", "sriov_drivers_autoprobe": "1\n"}})
	f.pci("0000:01:00.0", "1002", "73bf", "0x030000", "amdgpu", pciOpt{group: 3, reset: "flr"})
	h := f.host()
	ctx := context.Background()
	inv, _ := h.Inventory(ctx)
	g := gpuOf(inv, "0000:00:02.0")
	if g.VGPU == nil || g.VGPU.Mode != ModeSRIOVVF || g.VGPU.MaxVFs != 7 || g.VGPU.Note == "" {
		t.Fatalf("vgpu = %+v", g.VGPU)
	}
	if err := h.SetVFs(ctx, "0000:00:02.0", 9); err == nil {
		t.Fatal("too many VFs accepted")
	}
	if err := h.SetVFs(ctx, "0000:00:02.0", 2); err != nil {
		t.Fatal(err)
	}
	inv, _ = h.Inventory(ctx)
	g = gpuOf(inv, "0000:00:02.0")
	if g.VGPU.VFs != 2 || g.VGPU.Types[0].Available != 2 {
		t.Fatalf("vgpu = %+v", g.VGPU)
	}
	// The VFs aren't GPUs of their own in the list.
	if len(inv.GPUs) != 2 {
		t.Fatalf("gpus = %d", len(inv.GPUs))
	}
	prep, err := h.Prepare(ctx, "media", []Device{{Kind: KindVGPU, ID: "0000:00:02.0", VGPUType: SRIOVType}})
	if err != nil {
		t.Fatal(err)
	}
	vf := prep[0].Addresses[0]
	if vf != "0000:00:02.1" || f.driver(vf) != "vfio-pci" || f.driver("0000:00:02.0") != "i915" {
		t.Fatalf("vf %s on %s", vf, f.driver(vf))
	}
	// The new virtual functions came up without a host driver (autoprobe
	// off) and go back to none.
	if err := h.Release(ctx, "media"); err != nil || f.driver(vf) != "" {
		t.Fatalf("release: %v %s", err, f.driver(vf))
	}
	if !strings.Contains(strings.Join(f.wrote(), "\n"), "/sriov_drivers_autoprobe < 0") {
		t.Fatal("autoprobe not turned off")
	}
}

func bootFake(f *fakeSys) {
	f.mkdir("/target/boot")
	f.file("/run/hardyos/boot/be/hardyos-0.1.0/boot/vmlinuz-6.12.9-amd64", "k")
	f.file("/run/hardyos/boot/be/hardyos-0.1.0/boot/initrd.img-6.12.9-amd64", "i")
	f.file("/dev/disk/by-partuuid/11111111-aaaa-bbbb-cccc-000000000001", "")
	f.run.On("zfs list -H -p -o name,creation,org.hardyos:version -d 1 -r rpool/ROOT", "rpool/ROOT\t100\t-\nrpool/ROOT/hardyos-0.1.0\t200\t0.1.0\n")
	f.run.On("zpool get -H -o value bootfs rpool", "rpool/ROOT/hardyos-0.1.0\n")
	f.run.OnPrefix("mount ", sysexec.Result{})
	f.run.OnPrefix("umount ", sysexec.Result{})
}

func TestEnableIOMMU(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		cpu  string
		want string
	}{{"GenuineIntel", "intel_iommu=on iommu=pt"}, {"AuthenticAMD", "amd_iommu=on iommu=pt"}} {
		f := server(t)
		bootFake(f)
		f.file("/proc/cpuinfo", "vendor_id\t: "+c.cpu+"\n")
		h := f.host()
		// An old conflicting flag is replaced.
		if err := boot.SaveKernelArgs(h.bootEnv(), []string{"iommu=off", "nomodeset"}); err != nil {
			t.Fatal(err)
		}
		res, err := h.EnableIOMMU(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !res.RestartNeeded || len(res.Added) != 2 {
			t.Fatalf("%s: %+v", c.cpu, res)
		}
		cfg, _ := os.ReadFile(filepath.Join(f.root, "run/hardyos/boot/esp0/grub/grub.cfg"))
		if !strings.Contains(string(cfg), "quiet nomodeset "+c.want+"\n") {
			t.Fatalf("%s grub.cfg:\n%s", c.cpu, cfg)
		}
		inv, _ := h.Inventory(ctx)
		if !inv.IOMMU.Configured || !inv.IOMMU.RestartNeeded || inv.IOMMU.CanTurnOn {
			t.Fatalf("%s state = %+v", c.cpu, inv.IOMMU)
		}
		// Running with the flags: no restart needed.
		f.file("/proc/cmdline", "root=ZFS=x quiet nomodeset "+c.want+"\n")
		if inv, _ = h.Inventory(ctx); inv.IOMMU.RestartNeeded || !inv.IOMMU.Active {
			t.Fatalf("%s active state = %+v", c.cpu, inv.IOMMU)
		}
	}

	// Another architecture needs no flags.
	f := server(t)
	h := f.host()
	h.Arch = "arm64"
	res, err := h.EnableIOMMU(ctx)
	if err != nil || len(res.Added) != 0 || res.RestartNeeded {
		t.Fatalf("arm64: %+v %v", res, err)
	}
	// No boot configuration (not installed by HardyOS).
	f2 := server(t)
	_ = os.Remove(filepath.Join(f2.root, "var/lib/hardyos/boot.json"))
	if _, err := f2.host().EnableIOMMU(ctx); err == nil {
		t.Fatal("changed boot settings without a boot configuration")
	}
}

func TestIOMMUOffMessages(t *testing.T) {
	f := newFakeSys(t)
	f.pci("0000:00:02.0", "8086", "3e92", "0x030000", "i915", pciOpt{group: -1})
	h := f.host()
	s := h.iommuState(true)
	if s.Enabled || !s.CanTurnOn || !strings.Contains(s.Message, "Turn on IOMMU") {
		t.Fatalf("off = %+v", s)
	}
	f.file("/proc/cmdline", "quiet intel_iommu=on iommu=pt\n")
	_ = boot.SaveKernelArgs(h.bootEnv(), []string{"intel_iommu=on", "iommu=pt"})
	if s = h.iommuState(true); !strings.Contains(s.Message, "BIOS") || s.RestartNeeded {
		t.Fatalf("bios = %+v", s)
	}
}
