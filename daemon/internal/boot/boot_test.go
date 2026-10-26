package boot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

func TestBEName(t *testing.T) {
	cases := map[string]string{
		"0.1.0":                   "hardyos-0.1.0",
		"0.1.0~dev.20261024.gabc": "hardyos-0.1.0-dev.20261024.gabc",
		"1.2.3+build 7":           "hardyos-1.2.3-build-7",
		"~~":                      "hardyos-unknown",
	}
	for in, want := range cases {
		if got := BEName(in); got != want {
			t.Errorf("BEName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFindKernelPicksNewestWithInitrd(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"vmlinuz-6.12.9-amd64", "initrd.img-6.12.9-amd64", "vmlinuz-6.12.10-amd64", "initrd.img-6.12.10-amd64", "vmlinuz-6.13.0-amd64"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(f), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	k, err := FindKernel(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 6.13.0 has no initramfs, and 6.12.10 sorts above 6.12.9 numerically.
	if k.Version != "6.12.10-amd64" {
		t.Fatalf("picked %s", k.Version)
	}
	if _, err := FindKernel(t.TempDir()); err == nil {
		t.Fatal("expected an error for an empty /boot")
	}
}

func TestRenderGrub(t *testing.T) {
	cfg := RenderGrub([]MenuEntry{
		{ID: "hardyos-0.2.0", Title: "HardyOS 0.2.0", Dataset: "rpool/ROOT/hardyos-0.2.0"},
		{ID: "hardyos-0.1.0", Title: "HardyOS 0.1.0", Dataset: "rpool/ROOT/hardyos-0.1.0"},
	})
	for _, want := range []string{
		`set default="hardyos-0.2.0"`,
		`menuentry "HardyOS 0.2.0" --id "hardyos-0.2.0"`,
		`menuentry "HardyOS 0.1.0 (previous)" --id "hardyos-0.1.0"`,
		"linux /hardyos/hardyos-0.2.0/vmlinuz root=ZFS=rpool/ROOT/hardyos-0.2.0 ",
		"initrd /hardyos/hardyos-0.1.0/initrd.img",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("grub.cfg missing %q:\n%s", want, cfg)
		}
	}
}

func TestReadMounts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mounts")
	_ = os.WriteFile(p, []byte("rpool/ROOT/a / zfs rw 0 0\nrpool/hardyos /var/lib/hardyos zfs rw 0 0\ntank/my\\040files /mnt/my\\040files zfs rw 0 0\nproc /proc proc rw 0 0\n"), 0o644)
	m := readMounts(p)
	if m["rpool/ROOT/a"] != "/" || m["tank/my\\040files"] != "/mnt/my files" || len(m) != 3 {
		t.Fatalf("mounts = %v", m)
	}
}

// fakeHost lays out a host filesystem with an installed boot environment
// mounted at /target and an older one that Sync has to mount itself.
func fakeHost(t *testing.T) (Env, *sysexec.Fake, *Config) {
	t.Helper()
	root := t.TempDir()
	write := func(p, data string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("/target/boot/vmlinuz-6.12.10-amd64", "kernel-new")
	write("/target/boot/initrd.img-6.12.10-amd64", "initrd-new")
	// The old BE gets "mounted" by the fake: its files already sit at the mount point.
	write("/run/hardyos/boot/be/hardyos-0.1.0/boot/vmlinuz-6.12.9-amd64", "kernel-old")
	write("/run/hardyos/boot/be/hardyos-0.1.0/boot/initrd.img-6.12.9-amd64", "initrd-old")
	// udev links for the first ESP only; the second is found through blkid.
	write("/dev/disk/by-partuuid/11111111-aaaa-bbbb-cccc-000000000001", "")
	// A stale kernel dir from a deleted BE.
	write("/run/hardyos/boot/esp0/hardyos/hardyos-0.0.1/vmlinuz", "stale")

	f := &sysexec.Fake{}
	f.On("zfs list -H -p -o name,creation,org.hardyos:version -d 1 -r rpool/ROOT",
		"rpool/ROOT\t100\t-\nrpool/ROOT/hardyos-0.1.0\t200\t0.1.0\nrpool/ROOT/hardyos-0.2.0\t300\t0.2.0\n")
	f.On("zpool get -H -o value bootfs rpool", "rpool/ROOT/hardyos-0.2.0\n")
	f.On("blkid -l -o device -t PARTUUID=11111111-aaaa-bbbb-cccc-000000000002", "/dev/sdb2\n")
	f.OnPrefix("mount ", sysexec.Result{})
	f.OnPrefix("umount ", sysexec.Result{})
	f.OnPrefix("grub-install ", sysexec.Result{})
	cfg := &Config{Pool: "rpool", Disks: []Disk{
		{ByID: "/dev/disk/by-id/ata-A", ESPPartUUID: "11111111-aaaa-bbbb-cccc-000000000001"},
		{ByID: "/dev/disk/by-id/ata-B", ESPPartUUID: "11111111-aaaa-bbbb-cccc-000000000002"},
	}}
	return Env{Runner: f, Root: root}, f, cfg
}

func TestSync(t *testing.T) {
	env, f, cfg := fakeHost(t)
	entries, err := Sync(context.Background(), env, cfg, SyncOptions{
		InstallGRUB: true,
		Mounted:     map[string]string{"rpool/ROOT/hardyos-0.2.0": "/target"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].ID != "hardyos-0.2.0" || entries[1].ID != "hardyos-0.1.0" {
		t.Fatalf("entries = %+v", entries)
	}
	for _, esp := range []string{"esp0", "esp1"} {
		base := filepath.Join(env.Root, "run/hardyos/boot", esp)
		for p, want := range map[string]string{
			"hardyos/hardyos-0.2.0/vmlinuz":    "kernel-new",
			"hardyos/hardyos-0.2.0/initrd.img": "initrd-new",
			"hardyos/hardyos-0.1.0/vmlinuz":    "kernel-old",
		} {
			b, err := os.ReadFile(filepath.Join(base, p))
			if err != nil || string(b) != want {
				t.Errorf("%s/%s = %q, %v", esp, p, b, err)
			}
		}
		cfgText, err := os.ReadFile(filepath.Join(base, "grub/grub.cfg"))
		if err != nil || !strings.Contains(string(cfgText), `set default="hardyos-0.2.0"`) {
			t.Errorf("%s grub.cfg: %v\n%s", esp, err, cfgText)
		}
	}
	if _, err := os.Stat(filepath.Join(env.Root, "run/hardyos/boot/esp0/hardyos/hardyos-0.0.1")); !errors.Is(err, os.ErrNotExist) {
		t.Error("stale boot environment kernels were not removed")
	}

	lines := strings.Join(f.Lines(), "\n")
	for _, want := range []string{
		"mount -t zfs -o ro,zfsutil rpool/ROOT/hardyos-0.1.0 /run/hardyos/boot/be/hardyos-0.1.0",
		"mount -t vfat -o umask=0077 /dev/disk/by-partuuid/11111111-aaaa-bbbb-cccc-000000000001 /run/hardyos/boot/esp0",
		"mount -t vfat -o umask=0077 /dev/sdb2 /run/hardyos/boot/esp1",
		"grub-install --target=",
		"--efi-directory=/run/hardyos/boot/esp0 --boot-directory=/run/hardyos/boot/esp0 --removable --no-nvram",
		"umount /run/hardyos/boot/esp0",
		"umount /run/hardyos/boot/be/hardyos-0.1.0",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing command %q in:\n%s", want, lines)
		}
	}
	if strings.Contains(lines, "rpool/ROOT/hardyos-0.2.0 /run") {
		t.Error("mounted the boot environment that was already mounted")
	}
}

func TestSyncPartialAndTotalFailure(t *testing.T) {
	env, f, cfg := fakeHost(t)
	f.OnResult("mount -t vfat -o umask=0077 /dev/sdb2 /run/hardyos/boot/esp1",
		sysexec.Result{ExitCode: 32, Stderr: []byte("special device does not exist")})
	opts := SyncOptions{Mounted: map[string]string{"rpool/ROOT/hardyos-0.2.0": "/target"}}
	_, err := Sync(context.Background(), env, cfg, opts)
	var pe *PartialError
	if !errors.As(err, &pe) || len(pe.Failed) != 1 {
		t.Fatalf("want a partial failure, got %v", err)
	}

	f.OnResult("mount -t vfat -o umask=0077 /dev/disk/by-partuuid/11111111-aaaa-bbbb-cccc-000000000001 /run/hardyos/boot/esp0",
		sysexec.Result{ExitCode: 32, Stderr: []byte("special device does not exist")})
	if _, err := Sync(context.Background(), env, cfg, opts); err == nil || errors.As(err, &pe) {
		t.Fatalf("want a total failure, got %v", err)
	}
}

func TestSyncFailsWhenDefaultHasNoKernel(t *testing.T) {
	env, _, cfg := fakeHost(t)
	_ = os.RemoveAll(filepath.Join(env.Root, "target/boot"))
	_, err := Sync(context.Background(), env, cfg, SyncOptions{Mounted: map[string]string{"rpool/ROOT/hardyos-0.2.0": "/target"}})
	if err == nil || !strings.Contains(err.Error(), "hardyos-0.2.0") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "boot.json")
	if _, err := LoadConfig(p); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("missing file: %v", err)
	}
	c := &Config{Pool: "rpool", Disks: []Disk{{ByID: "/dev/disk/by-id/x", ESPPartUUID: "abcd-1234"}}}
	if err := c.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(p)
	if err != nil || got.Disks[0].ESPPartUUID != "abcd-1234" {
		t.Fatalf("got %+v, %v", got, err)
	}
}
