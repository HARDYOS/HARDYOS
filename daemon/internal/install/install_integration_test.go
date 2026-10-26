package install

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/boot"
	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// TestInstallIntegration runs the real install steps (sgdisk, mkfs.vfat,
// zpool, unsquashfs, grub-install) on two loop devices with a tiny system
// image. Configure is left out: it needs a full Debian image to chroot into
// and is covered by TestFullInstall. Needs root, ZFS, gdisk, dosfstools,
// squashfs-tools and the GRUB EFI/BIOS binaries; runs only when
// HARDYOS_ZFS_INTEGRATION=1 (the "ZFS integration" CI job).
func TestInstallIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_ZFS_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_ZFS_INTEGRATION=1 to run against real disks tools (needs root)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out)
	}

	dir := t.TempDir()
	const pool = "hardyosinstalltest"
	const kver = "6.0.0-hardyostest"
	_ = exec.Command("zpool", "destroy", "-f", pool).Run()

	// Two sparse 20 GiB "disks".
	var loops []string
	for i := 0; i < 2; i++ {
		img := filepath.Join(dir, "disk"+string(rune('a'+i))+".img")
		f, err := os.Create(img)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(20 << 30); err != nil {
			t.Fatal(err)
		}
		f.Close()
		loop := strings.TrimSpace(run("losetup", "-f", "-P", "--show", img))
		loops = append(loops, loop)
		t.Cleanup(func() { _ = exec.Command("losetup", "-d", loop).Run() })
	}

	// A tiny system image standing in for the live squashfs.
	tree := filepath.Join(dir, "image")
	for p, data := range map[string]string{
		"lib/modules/" + kver + "/modules.dep": "",
		"boot/vmlinuz-" + kver:                 "kernel-bytes",
		"etc/passwd":                           "root:x:0:0:root:/root:/bin/sh\nhardyd:x:998:997::/var/lib/hardyos:/usr/sbin/nologin\n",
		"etc/hardyos/live-installer":           "",
		"var/lib/hardyos/.keep":                "",
	} {
		full := filepath.Join(tree, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	medium := filepath.Join(dir, "medium")
	if err := os.MkdirAll(filepath.Join(medium, "live"), 0o755); err != nil {
		t.Fatal(err)
	}
	run("mksquashfs", tree, filepath.Join(medium, "live", "filesystem.squashfs"), "-noappend", "-quiet")

	target := filepath.Join(dir, "target")
	in := &Installer{
		Runner: sysexec.Exec{}, Root: "/", Target: target, Medium: medium,
		Version: "0.0.0-test", PoolName: pool, SettleTimeout: 30 * time.Second,
		ListDisks: func(context.Context) ([]hw.Disk, error) {
			var out []hw.Disk
			for _, l := range loops {
				out = append(out, hw.Disk{Name: filepath.Base(l), Path: l, ByID: l, Kind: hw.KindSSD, SizeBytes: 20 << 30, Usage: hw.UsageFree, Partitions: []hw.Partition{}})
			}
			return out, nil
		},
	}
	t.Cleanup(func() {
		in.Reset(context.Background())
		_ = exec.Command("zpool", "destroy", "-f", pool).Run()
	})
	plan := Plan{Disks: loops, Hostname: "itest", Timezone: "UTC", Network: Network{Mode: "dhcp"}}

	step := func(name string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		t.Logf("%s: ok", name)
	}
	step("partition", in.Partition(ctx, plan, true))
	for _, l := range loops {
		parts := run("sgdisk", "-p", l)
		for _, want := range []string{"EF02", "EF00", "BF00", "hardyos-esp"} {
			if !strings.Contains(parts, want) {
				t.Errorf("%s partition table missing %s:\n%s", l, want, parts)
			}
		}
	}
	step("pool", in.CreatePool(ctx, plan))
	step("copy system", in.CopySystem(ctx))
	if _, err := os.Stat(filepath.Join(target, "etc/hardyos/live-installer")); err != nil {
		t.Fatalf("image not unpacked into the target: %v", err)
	}
	// What Configure's update-initramfs would have produced.
	if err := os.WriteFile(filepath.Join(target, "boot", "initrd.img-"+kver), []byte("initrd-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	step("boot loader", in.InstallBootloader(ctx, plan))

	be := pool + "/ROOT/hardyos-0.0.0-test"
	if got := strings.TrimSpace(run("zpool", "get", "-H", "-o", "value", "bootfs", pool)); got != be {
		t.Errorf("bootfs = %q", got)
	}
	if got := strings.TrimSpace(run("zfs", "get", "-H", "-o", "value", boot.VersionProp, be)); got != "0.0.0-test" {
		t.Errorf("version property = %q", got)
	}
	// While imported with an altroot (-R target), ZFS shows mountpoints under it.
	if got := strings.TrimSpace(run("zfs", "get", "-H", "-o", "value", "mountpoint", pool+"/hardyos")); got != filepath.Join(target, "var/lib/hardyos") {
		t.Errorf("state dataset mountpoint = %q", got)
	}
	if st := run("zpool", "status", pool); !strings.Contains(st, "mirror-0") {
		t.Errorf("pool is not a mirror:\n%s", st)
	}
	var cfg boot.Config
	b, err := os.ReadFile(filepath.Join(target, "var/lib/hardyos/boot.json"))
	if err != nil || json.Unmarshal(b, &cfg) != nil || len(cfg.Disks) != 2 || cfg.Pool != pool {
		t.Fatalf("boot.json = %s, %v", b, err)
	}

	step("finish", in.Finish(ctx))
	if err := exec.Command("zpool", "list", pool).Run(); err == nil {
		t.Error("pool is still imported after finish")
	}

	// Every boot disk carries the boot loader, the kernel and the menu.
	for i, l := range loops {
		mnt := filepath.Join(dir, "esp-check", filepath.Base(l))
		if err := os.MkdirAll(mnt, 0o755); err != nil {
			t.Fatal(err)
		}
		run("mount", "-o", "ro", Partition(l, 2), mnt)
		func() {
			defer func() { _ = exec.Command("umount", mnt).Run() }()
			for _, p := range []string{"EFI/BOOT/BOOTX64.EFI", "grub/grub.cfg", "grub/x86_64-efi", "grub/i386-pc", "hardyos/hardyos-0.0.0-test/vmlinuz", "hardyos/hardyos-0.0.0-test/initrd.img"} {
				if _, err := os.Stat(filepath.Join(mnt, p)); err != nil {
					t.Errorf("disk %d: missing %s", i, p)
				}
			}
			grubCfg, _ := os.ReadFile(filepath.Join(mnt, "grub/grub.cfg"))
			if !strings.Contains(string(grubCfg), "root=ZFS="+be+" boot=zfs") {
				t.Errorf("disk %d grub.cfg:\n%s", i, grubCfg)
			}
			if k, _ := os.ReadFile(filepath.Join(mnt, "hardyos/hardyos-0.0.0-test/vmlinuz")); string(k) != "kernel-bytes" {
				t.Errorf("disk %d kernel = %q", i, k)
			}
		}()
	}
}
