package priv

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

const lsblkCmd = "lsblk -J -b -o NAME,PATH,SIZE,TYPE,ROTA,MODEL,SERIAL,WWN,TRAN,FSTYPE,LABEL,MOUNTPOINTS,HOTPLUG,PHY-SEC"

// Four free HDDs (one with an old ext4 partition), one in pool "old", and the boot NVMe.
const lsblkOut = `{"blockdevices":[
 {"name":"sda","path":"/dev/sda","size":4000000000000,"type":"disk","rota":true,"tran":"sata","mountpoints":[null],"hotplug":false},
 {"name":"sdb","path":"/dev/sdb","size":4000000000000,"type":"disk","rota":true,"tran":"sata","mountpoints":[null],"hotplug":false},
 {"name":"sdc","path":"/dev/sdc","size":4000000000000,"type":"disk","rota":true,"tran":"sata","mountpoints":[null],"hotplug":false},
 {"name":"sdd","path":"/dev/sdd","size":4000000000000,"type":"disk","rota":true,"tran":"sata","mountpoints":[null],"hotplug":false,
  "children":[{"name":"sdd1","size":4000000000000,"type":"part","fstype":"ext4","mountpoints":[null]}]},
 {"name":"sde","path":"/dev/sde","size":4000000000000,"type":"disk","rota":true,"tran":"sata","mountpoints":[null],"hotplug":false,
  "children":[{"name":"sde1","size":4000000000000,"type":"part","fstype":"zfs_member","label":"old","mountpoints":[null]}]},
 {"name":"nvme0n1","path":"/dev/nvme0n1","size":256000000000,"type":"disk","rota":false,"tran":"nvme","mountpoints":[null],"hotplug":false,
  "children":[{"name":"nvme0n1p1","size":256000000000,"type":"part","fstype":"ext4","mountpoints":["/"]}]}
]}`

func symlink(target string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(target), Mode: fs.ModeSymlink | 0o777}
}

func storageEnv(t *testing.T) (*storageOps, *sysexec.Fake) {
	t.Helper()
	root := fstest.MapFS{}
	for _, n := range []string{"sda", "sdb", "sdc", "sdd", "sde", "nvme0n1"} {
		root["dev/disk/by-id/ata-DISK_"+n] = symlink("../../" + n)
	}
	f := (&sysexec.Fake{}).On(lsblkCmd, lsblkOut)
	dir := t.TempDir()
	env := StorageEnv{Runner: f, Root: root, KeyDir: filepath.Join(dir, "keys"),
		ARCConf: filepath.Join(dir, "zfs.conf"), ARCParam: filepath.Join(dir, "zfs_arc_max")}
	return &storageOps{env: env}, f
}

const okStatus = "  pool: tank\n state: ONLINE\nconfig:\n\n\tNAME STATE READ WRITE CKSUM\n\ttank ONLINE 0 0 0\n\nerrors: No known data errors\n"

func id(n string) string { return "/dev/disk/by-id/ata-DISK_" + n }

func TestCreatePoolWipesAndCreates(t *testing.T) {
	st, f := storageEnv(t)
	f.OnPrefix("zpool labelclear", sysexec.Result{ExitCode: 1}) // no label: ignored
	f.OnPrefix("wipefs -a", sysexec.Result{})
	f.OnPrefix("zpool create", sysexec.Result{})
	f.On("zpool status -P -p tank", okStatus)

	spec := zfs.PoolSpec{Name: "tank", Data: []zfs.VdevSpec{{Type: zfs.RAIDZ1, Disks: []string{id("sda"), id("sdb"), id("sdd")}}}, Encrypt: true}
	res, err := st.createPool(context.Background(), PoolCreateArgs{Spec: spec, ConfirmWipe: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.(*zfs.Status).Name != "tank" {
		t.Fatalf("result = %+v", res)
	}
	lines := strings.Join(f.Lines(), "\n")
	for _, want := range []string{
		"wipefs -a /dev/sdd1",
		"wipefs -a " + id("sdd"),
		"zpool create -f -o ashift=12",
		"keylocation=file://" + filepath.Join(st.env.KeyDir, "tank.key"),
		"tank raidz1 " + id("sda") + " " + id("sdb") + " " + id("sdd"),
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %q in:\n%s", want, lines)
		}
	}
	info, err := os.Stat(filepath.Join(st.env.KeyDir, "tank.key"))
	if err != nil || info.Mode().Perm() != 0o400 || info.Size() != 32 {
		t.Fatalf("key file: %v %v", info, err)
	}
}

func TestCreatePoolRefusesUnsafeDisks(t *testing.T) {
	st, f := storageEnv(t)
	cases := []struct {
		name  string
		disks []string
		conf  bool
		code  string
	}{
		{"no confirmation", []string{id("sda"), id("sdb")}, false, CodeBadArgs},
		{"disk in another pool", []string{id("sda"), id("sde")}, true, CodeForbidden},
		{"boot disk", []string{id("sda"), id("nvme0n1")}, true, CodeForbidden},
		{"unknown disk", []string{id("sda"), id("sdz")}, true, CodeBadArgs},
	}
	for _, c := range cases {
		spec := zfs.PoolSpec{Name: "tank", Data: []zfs.VdevSpec{{Type: zfs.Mirror, Disks: c.disks}}}
		_, err := st.createPool(context.Background(), PoolCreateArgs{Spec: spec, ConfirmWipe: c.conf})
		var pe *Error
		if !errors.As(err, &pe) || pe.Code != c.code {
			t.Errorf("%s: err = %v, want %s", c.name, err, c.code)
		}
	}
	for _, l := range f.Lines() {
		if strings.HasPrefix(l, "wipefs") || strings.HasPrefix(l, "zpool create") {
			t.Fatalf("ran %q for a refused request", l)
		}
	}
}

func TestCreatePoolRemovesKeyOnFailure(t *testing.T) {
	st, f := storageEnv(t)
	f.OnPrefix("zpool labelclear", sysexec.Result{})
	f.OnPrefix("wipefs -a", sysexec.Result{})
	f.OnPrefix("zpool create", sysexec.Result{ExitCode: 1, Stderr: []byte("cannot create 'tank': pool already exists")})

	spec := zfs.PoolSpec{Name: "tank", Data: []zfs.VdevSpec{{Type: zfs.Mirror, Disks: []string{id("sda"), id("sdb")}}}, Encrypt: true}
	_, err := st.createPool(context.Background(), PoolCreateArgs{Spec: spec, ConfirmWipe: true})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(st.env.KeyDir, "tank.key")); !os.IsNotExist(err) {
		t.Fatal("key file left behind after a failed create")
	}
}

func TestBootPoolIsProtected(t *testing.T) {
	st, _ := storageEnv(t)
	ctx := context.Background()
	checks := []error{
		func() error {
			_, e := st.destroyPool(ctx, PoolDestroyArgs{Pool: "rpool", ConfirmName: "rpool"})
			return e
		}(),
		func() error { _, e := st.scrub(ctx, PoolScrubArgs{Pool: "rpool", Action: "start"}); return e }(),
		func() error {
			_, e := st.setDataset(ctx, DatasetSetArgs{Name: "rpool/ROOT", Props: map[string]string{"atime": "on"}})
			return e
		}(),
		func() error {
			_, e := st.destroySnapshot(ctx, SnapshotArgs{Name: "rpool/ROOT@x"})
			return e
		}(),
	}
	for i, err := range checks {
		var pe *Error
		if !errors.As(err, &pe) || pe.Code != CodeForbidden {
			t.Errorf("check %d: err = %v, want forbidden", i, err)
		}
	}
}

func TestDestructiveOpsNeedConfirmation(t *testing.T) {
	st, f := storageEnv(t)
	ctx := context.Background()
	if _, err := st.destroyPool(ctx, PoolDestroyArgs{Pool: "tank", ConfirmName: "Tank"}); err == nil {
		t.Error("pool destroy without exact name accepted")
	}
	if _, err := st.destroyDataset(ctx, DatasetDestroyArgs{Name: "tank/family", ConfirmName: "tank"}); err == nil {
		t.Error("dataset destroy without exact name accepted")
	}
	if _, err := st.destroyDataset(ctx, DatasetDestroyArgs{Name: "tank", ConfirmName: "tank"}); err == nil {
		t.Error("destroying the pool's root dataset accepted")
	}
	if _, err := st.rollback(ctx, SnapshotRollbackArgs{Name: "tank/family@x"}); err == nil {
		t.Error("rollback without confirm accepted")
	}
	if len(f.Calls) != 0 {
		t.Fatalf("commands ran: %v", f.Lines())
	}
}

func TestDatasetCommands(t *testing.T) {
	st, f := storageEnv(t)
	f.OnPrefix("zfs create", sysexec.Result{})
	f.OnPrefix("zfs set", sysexec.Result{})
	f.OnPrefix("zfs list", sysexec.Result{Stdout: []byte("tank/family\tfilesystem\t1\t2\t1\t/mnt/tank/family\tlz4\t1.00x\toff\t-\t0\t131072\t-\tyes\n")})
	ctx := context.Background()

	if _, err := st.createDataset(ctx, DatasetCreateArgs{Name: "tank/family", Props: map[string]string{"quota": "2T", "compression": "zstd"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.createDataset(ctx, DatasetCreateArgs{Name: "tank/vms/win11", VolSize: "128G"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.setDataset(ctx, DatasetSetArgs{Name: "tank/family", Props: map[string]string{"canmount": "off"}}); err == nil {
		t.Error("disallowed property accepted")
	}
	lines := strings.Join(f.Lines(), "\n")
	for _, want := range []string{
		"zfs create -o compression=zstd -o quota=2T tank/family",
		"zfs create -s -V 128G tank/vms/win11",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("missing %q in:\n%s", want, lines)
		}
	}
}

func TestScrubAndARC(t *testing.T) {
	st, f := storageEnv(t)
	f.OnPrefix("zpool scrub", sysexec.Result{})
	f.On("zpool status -P -p tank", okStatus)
	ctx := context.Background()
	for action, want := range map[string]string{"start": "zpool scrub tank", "pause": "zpool scrub -p tank", "stop": "zpool scrub -s tank"} {
		if _, err := st.scrub(ctx, PoolScrubArgs{Pool: "tank", Action: action}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(f.Lines(), "\n"), want) {
			t.Errorf("%s: missing %q", action, want)
		}
	}
	if _, err := st.scrub(ctx, PoolScrubArgs{Pool: "tank", Action: "explode"}); err == nil {
		t.Error("bad scrub action accepted")
	}

	if _, err := st.setARC(ctx, ARCSetArgs{MaxBytes: 64 << 30}); err != nil {
		t.Fatal(err)
	}
	live, _ := os.ReadFile(st.env.ARCParam)
	conf, _ := os.ReadFile(st.env.ARCConf)
	if string(live) != "68719476736" || !strings.Contains(string(conf), "zfs_arc_max=68719476736") {
		t.Fatalf("arc live=%q conf=%q", live, conf)
	}
	if _, err := st.setARC(ctx, ARCSetArgs{MaxBytes: 1024}); err == nil {
		t.Error("tiny ARC accepted")
	}
}

func TestTypedRejectsUnknownFields(t *testing.T) {
	h := typed(func(ctx context.Context, a PoolArgs) (any, error) { return a.Pool, nil })
	if _, err := h(context.Background(), []byte(`{"pool":"tank","force":true}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if v, err := h(context.Background(), []byte(`{"pool":"tank"}`)); err != nil || v != "tank" {
		t.Fatalf("got %v %v", v, err)
	}
}
