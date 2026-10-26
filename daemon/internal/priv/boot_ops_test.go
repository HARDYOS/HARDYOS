package priv

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/boot"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// The second boot NVMe died (gone from lsblk); sda is a new, bigger disk and
// sdb a too-small one.
const bootLsblk = `{"blockdevices":[
 {"name":"nvme0n1","path":"/dev/nvme0n1","size":256000000000,"type":"disk","rota":false,"tran":"nvme","mountpoints":[null],"hotplug":false,
  "children":[{"name":"nvme0n1p1","size":1000000,"type":"part","mountpoints":[null]},
              {"name":"nvme0n1p2","size":1000000000,"type":"part","fstype":"vfat","label":"HARDYOS-EFI","mountpoints":[null]},
              {"name":"nvme0n1p3","size":254000000000,"type":"part","fstype":"zfs_member","label":"rpool","mountpoints":[null]}]},
 {"name":"sda","path":"/dev/sda","size":512000000000,"type":"disk","rota":false,"tran":"sata","mountpoints":[null],"hotplug":false},
 {"name":"sdb","path":"/dev/sdb","size":120000000000,"type":"disk","rota":false,"tran":"sata","mountpoints":[null],"hotplug":false}
]}`

const degradedStatus = `  pool: rpool
 state: DEGRADED
status: One or more devices could not be used.
config:

	NAME                                    STATE     READ WRITE CKSUM
	rpool                                   DEGRADED     0     0     0
	  mirror-0                              DEGRADED     0     0     0
	    /dev/disk/by-id/nvme-BOOT1-part3    ONLINE       0     0     0
	    1234567890123456789                 UNAVAIL      0     0     0  was /dev/disk/by-id/nvme-BOOT2-part3

errors: No known data errors
`

func bootEnv(t *testing.T) (*bootOps, *sysexec.Fake, string) {
	t.Helper()
	root := t.TempDir()
	fsys := fstest.MapFS{
		"dev/disk/by-id/nvme-BOOT1":   symlink("../../nvme0n1"),
		"dev/disk/by-id/ata-NEW_sda":  symlink("../../sda"),
		"dev/disk/by-id/ata-TINY_sdb": symlink("../../sdb"),
	}
	f := (&sysexec.Fake{}).On(lsblkCmd, bootLsblk)
	f.On("zpool status -P -p rpool", degradedStatus)
	for _, p := range []string{"wipefs ", "zpool labelclear", "sgdisk ", "partprobe ", "udevadm ", "mkfs.vfat ", "zpool replace ", "zpool attach ", "zpool detach "} {
		f.OnPrefix(p, sysexec.Result{})
	}
	f.OnPrefix("blkid -s PARTUUID", sysexec.Result{Stdout: []byte("aaaa-bbbb-cccc\n")})
	// The new disk's partitions appear once sgdisk has run.
	for _, n := range []string{"2", "3"} {
		p := filepath.Join(root, "dev/disk/by-id/ata-NEW_sda-part"+n)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, nil, 0o644)
	}
	cfgPath := filepath.Join(root, "boot.json")
	cfg := &boot.Config{Pool: "rpool", Disks: []boot.Disk{
		{ByID: "/dev/disk/by-id/nvme-BOOT1", ESPPartUUID: "1111-1111"},
		{ByID: "/dev/disk/by-id/nvme-BOOT2", ESPPartUUID: "2222-2222"},
	}}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatal(err)
	}
	b := &bootOps{
		st: &storageOps{env: StorageEnv{Runner: f, Root: fsys}}, root: root, configPath: cfgPath, settle: time.Second,
		sync: func(ctx context.Context, env boot.Env, c *boot.Config, o boot.SyncOptions) ([]boot.MenuEntry, error) {
			if !o.InstallGRUB {
				t.Error("the new disk needs the boot loader installed")
			}
			return nil, nil
		},
	}
	return b, f, cfgPath
}

func TestBootDisks(t *testing.T) {
	b, _, _ := bootEnv(t)
	res, err := b.disks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := res.(BootDisksResult)
	if r.Pool != "rpool" || len(r.Disks) != 2 || r.Status.State != "DEGRADED" {
		t.Fatalf("result = %+v", r)
	}
	// Only sda is free and big enough (sdb is too small; nvme0n1 is the boot disk).
	if len(r.Candidates) != 1 || r.Candidates[0].ByID != "/dev/disk/by-id/ata-NEW_sda" {
		t.Fatalf("candidates = %+v", r.Candidates)
	}
}

func TestBootReplace(t *testing.T) {
	b, f, cfgPath := bootEnv(t)
	ctx := context.Background()
	newDisk := "/dev/disk/by-id/ata-NEW_sda"
	if _, err := b.replace(ctx, BootReplaceArgs{Old: "1234567890123456789", Disk: newDisk}); err == nil {
		t.Fatal("replaced without confirmWipe")
	}
	if _, err := b.replace(ctx, BootReplaceArgs{Old: "/dev/disk/by-id/nope-part3", Disk: newDisk, ConfirmWipe: true}); err == nil {
		t.Fatal("replaced a device that isn't in the pool")
	}
	if _, err := b.replace(ctx, BootReplaceArgs{Old: "1234567890123456789", Disk: "/dev/disk/by-id/ata-TINY_sdb", ConfirmWipe: true}); err == nil || !strings.Contains(err.Error(), "smaller") {
		t.Fatalf("too-small disk: %v", err)
	}
	if _, err := b.replace(ctx, BootReplaceArgs{Old: "1234567890123456789", Disk: newDisk, ConfirmWipe: true}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Join(f.Lines(), "\n")
	for _, want := range []string{
		"wipefs -a " + newDisk,
		"sgdisk --replicate=" + newDisk + " /dev/disk/by-id/nvme-BOOT1",
		"sgdisk --randomize-guids " + newDisk,
		"mkfs.vfat -F 32 -n HARDYOS-EFI " + newDisk + "-part2",
		"zpool replace -f rpool 1234567890123456789 " + newDisk + "-part3",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %q in:\n%s", want, lines)
		}
	}
	// The replicate must come after the wipe and before mkfs.
	if strings.Index(lines, "sgdisk --replicate") > strings.Index(lines, "mkfs.vfat") || strings.Index(lines, "wipefs -a "+newDisk) > strings.Index(lines, "sgdisk --replicate") {
		t.Errorf("wrong order:\n%s", lines)
	}
	cfg, err := boot.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Disks) != 2 || cfg.Disks[0].ByID != "/dev/disk/by-id/nvme-BOOT1" || cfg.Disks[1].ByID != newDisk || cfg.Disks[1].ESPPartUUID != "aaaa-bbbb-cccc" {
		t.Fatalf("boot config = %+v", cfg.Disks)
	}
}

func TestBootAttachAndDetach(t *testing.T) {
	b, f, cfgPath := bootEnv(t)
	ctx := context.Background()
	if _, err := b.attach(ctx, BootAttachArgs{Disk: "/dev/disk/by-id/ata-NEW_sda", ConfirmWipe: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(f.Lines(), "\n"), "zpool attach -f rpool /dev/disk/by-id/nvme-BOOT1-part3 /dev/disk/by-id/ata-NEW_sda-part3") {
		t.Fatalf("attach:\n%s", strings.Join(f.Lines(), "\n"))
	}
	cfg, _ := boot.LoadConfig(cfgPath)
	if len(cfg.Disks) != 3 {
		t.Fatalf("after attach = %+v", cfg.Disks)
	}
	// The only working disk can't be removed.
	if _, err := b.detach(ctx, BootDetachArgs{Device: "/dev/disk/by-id/nvme-BOOT1-part3"}); err == nil || !strings.Contains(err.Error(), "only working boot disk") {
		t.Fatalf("detach the last disk: %v", err)
	}
	// The dead one can.
	if _, err := b.detach(ctx, BootDetachArgs{Device: "1234567890123456789"}); err != nil {
		t.Fatal(err)
	}
	cfg, _ = boot.LoadConfig(cfgPath)
	for _, d := range cfg.Disks {
		if d.ByID == "/dev/disk/by-id/nvme-BOOT2" {
			t.Fatalf("dead disk still in the boot config: %+v", cfg.Disks)
		}
	}
	if _, err := b.detach(ctx, BootDetachArgs{Device: "rm -rf /"}); err == nil {
		t.Fatal("bad device accepted")
	}
	_ = zfs.ClassData
}
