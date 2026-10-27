package boot

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRenderGrubWithArgs(t *testing.T) {
	entries := []MenuEntry{
		{ID: "hardyos-0.2.0", Title: "HardyOS 0.2.0", Dataset: "rpool/ROOT/hardyos-0.2.0"},
		{ID: "hardyos-0.1.0", Title: "HardyOS 0.1.0", Dataset: "rpool/ROOT/hardyos-0.1.0"},
	}
	cfg := RenderGrubWithArgs(entries, []string{"intel_iommu=on", "iommu=pt"})
	for _, id := range []string{"hardyos-0.2.0", "hardyos-0.1.0"} {
		want := "linux /hardyos/" + id + "/vmlinuz root=ZFS=rpool/ROOT/" + id + " boot=zfs console=ttyS0,115200 console=tty0 quiet intel_iommu=on iommu=pt\n"
		if !strings.Contains(cfg, want) {
			t.Errorf("missing %q in:\n%s", want, cfg)
		}
	}
	// Without extras the line is exactly what it always was.
	if plain := RenderGrub(entries); !strings.Contains(plain, "console=tty0 quiet\n") || strings.Contains(plain, "iommu") {
		t.Fatalf("plain menu:\n%s", plain)
	}
}

func TestKernelArgValidation(t *testing.T) {
	for _, ok := range []string{"intel_iommu=on", "amd_iommu=on", "iommu=pt", "video=efifb:off", "pcie_acs_override=downstream,multifunction", "nomodeset"} {
		if err := ValidateKernelArg(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "x=$(reboot)", "init=/bin/sh", "root=ZFS=tank/evil", "console=ttyS1", `x="y"`, "x;y", "x=" + strings.Repeat("a", 200), "Upper=1", "x={y}"} {
		if err := ValidateKernelArg(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMergeAndRemoveKernelArgs(t *testing.T) {
	got := MergeKernelArgs([]string{"iommu=soft", "nomodeset"}, []string{"intel_iommu=on", "iommu=pt"})
	if want := []string{"iommu=pt", "nomodeset", "intel_iommu=on"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("merge = %v", got)
	}
	if got := RemoveKernelArgs(got, "iommu", "intel_iommu=whatever"); !reflect.DeepEqual(got, []string{"nomodeset"}) {
		t.Fatalf("remove = %v", got)
	}
}

func TestKernelArgsFileAndSync(t *testing.T) {
	env, _, cfg := fakeHost(t)
	if args, err := LoadKernelArgs(env); err != nil || args != nil {
		t.Fatalf("missing file = %v, %v", args, err)
	}
	if err := SaveKernelArgs(env, []string{"iommu=pt", "iommu=soft"}); err == nil {
		t.Fatal("duplicate keys accepted")
	}
	if err := SaveKernelArgs(env, []string{"init=/bin/sh"}); err == nil {
		t.Fatal("reserved key accepted")
	}
	if err := SaveKernelArgs(env, []string{"intel_iommu=on", "iommu=pt"}); err != nil {
		t.Fatal(err)
	}
	if args, err := LoadKernelArgs(env); err != nil || !reflect.DeepEqual(args, []string{"intel_iommu=on", "iommu=pt"}) {
		t.Fatalf("load = %v, %v", args, err)
	}
	if _, err := Sync(context.Background(), env, cfg, SyncOptions{Mounted: map[string]string{"rpool/ROOT/hardyos-0.2.0": "/target"}}); err != nil {
		t.Fatal(err)
	}
	// Every boot disk, every entry.
	for _, esp := range []string{"esp0", "esp1"} {
		b, _ := os.ReadFile(filepath.Join(env.Root, "run/hardyos/boot", esp, "grub/grub.cfg"))
		if n := strings.Count(string(b), "quiet intel_iommu=on iommu=pt\n"); n != 2 {
			t.Errorf("%s: %d entries with the flags:\n%s", esp, n, b)
		}
	}

	// A broken file never stops the server from booting: Sync leaves the extras out.
	_ = os.WriteFile(filepath.Join(env.Root, KernelArgsPath), []byte(`{"args":["init=/bin/sh"]}`), 0o644)
	if _, err := LoadKernelArgs(env); err == nil {
		t.Fatal("bad file loaded")
	}
	if _, err := Sync(context.Background(), env, cfg, SyncOptions{Mounted: map[string]string{"rpool/ROOT/hardyos-0.2.0": "/target"}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(env.Root, "run/hardyos/boot/esp0/grub/grub.cfg"))
	if strings.Contains(string(b), "init=") || !strings.Contains(string(b), "console=tty0 quiet\n") {
		t.Fatalf("bad args reached the menu:\n%s", b)
	}
}
