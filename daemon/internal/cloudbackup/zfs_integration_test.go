package cloudbackup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// zfsShares lists one real dataset as a shared folder, verified like
// shares.Manager does.
type zfsShares struct {
	id, dataset, path string
}

func (z *zfsShares) List(context.Context) ([]shares.Share, error) {
	t, err := shares.ReadMountTable()
	if err != nil {
		return nil, err
	}
	dev, err := t.VerifyMount(z.path, z.dataset)
	if err != nil {
		return nil, err
	}
	pool, _, _ := strings.Cut(z.dataset, "/")
	return []shares.Share{{ID: z.id, Name: "Family", Pool: pool, Dataset: z.dataset, Path: z.path, Mounted: true, RootDev: dev}}, nil
}

func (z *zfsShares) Create(context.Context, shares.NewShare) (*shares.Share, error) { return nil, nil }

func zfsRun(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// TestZFSIntegrationCloudBackup backs a dataset and a zvol up from real
// snapshots (mounted read-only at a stable folder; the zvol through a
// clone) into a local restic repository, and restores through a private
// staging dataset. Root on a throwaway machine only (CI's ZFS job).
func TestZFSIntegrationCloudBackup(t *testing.T) {
	if os.Getenv("HARDYOS_ZFS_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_ZFS_INTEGRATION=1 to run against real ZFS (needs root)")
	}
	bin := needRestic(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	dir := t.TempDir()
	vdev := filepath.Join(dir, "vdev")
	f, err := os.Create(vdev)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Truncate(512 << 20)
	f.Close()
	const pool = "hardyoscloud"
	_ = exec.Command("zpool", "destroy", "-f", pool).Run()
	zfsRun(t, "zpool", "create", "-m", filepath.Join(dir, "mnt"), "-O", "acltype=posixacl", "-O", "xattr=sa", pool, vdev)
	t.Cleanup(func() {
		_ = exec.Command("umount", "-R", filepath.Join(dir, "run")).Run()
		_ = exec.Command("zpool", "destroy", "-f", pool).Run()
	})
	zfsRun(t, "zfs", "create", "-p", pool+"/shares/family")
	share := filepath.Join(dir, "mnt", "shares", "family")
	write(t, filepath.Join(share, "docs", "letter.txt"), "dear family v1")
	if err := os.Chown(filepath.Join(share, "docs", "letter.txt"), 3001, 3001); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/shadow", filepath.Join(share, "evil")); err != nil {
		t.Fatal(err)
	}
	disk := make([]byte, 8<<20)
	_, _ = rand.Read(disk[:1<<20])
	zfsRun(t, "zfs", "create", "-p", "-V", "16M", pool+"/vms/web/disk0")
	devPath := "/dev/zvol/" + pool + "/vms/web/disk0"
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(devPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := os.WriteFile(devPath, disk, 0); err != nil {
		t.Fatalf("writing the zvol: %v", err)
	}

	runDir := filepath.Join(dir, "run")
	key := bytes.Repeat([]byte{7}, 32)
	r := &Root{
		Restic:     &Restic{Binary: bin, CacheDir: filepath.Join(dir, "cache"), Sandbox: testSandbox(t)},
		Vol:        &ZFS{Runner: sysexec.Exec{}, RunDir: runDir},
		Shares:     &zfsShares{id: "family", dataset: pool + "/shares/family", path: share},
		Dir:        filepath.Join(dir, "state"),
		Key:        func() ([]byte, error) { return key, nil },
		AllowLocal: true,
	}
	if _, err := r.Save(ctx, SaveArgs{Target: Target{ID: "local", Name: "Local", Kind: KindLocal, Path: filepath.Join(dir, "repo")}}); err != nil {
		t.Fatal(err)
	}
	wait := func(task *Task, err error) *Task {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		for ctx.Err() == nil {
			x, _ := r.TaskStatus(task.ID)
			if x.Done {
				return x
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("timed out")
		return nil
	}
	x := wait(r.StartBackup(BackupArgs{Target: "local", Task: "t", Run: "z1", Items: []Item{{Kind: ItemShare, ID: "family"}}, Retention: DefaultRetention}))
	if x.Error != "" {
		t.Fatalf("backup: %s", x.Error)
	}
	// Nothing is left mounted, and the snapshot is gone.
	if out := zfsRun(t, "zfs", "list", "-H", "-t", "snapshot", "-o", "name", "-r", pool); strings.Contains(out, "hardyos-cloud-") {
		t.Fatalf("snapshots left: %s", out)
	}
	if mi, _ := os.ReadFile("/proc/self/mountinfo"); strings.Contains(string(mi), runDir) {
		t.Fatal("a snapshot is still mounted")
	}
	// Backing up was from the snapshot: the stable path is in the version.
	snapshotCache.drop("local")
	v, err := r.Versions(ctx, "local")
	if err != nil || len(v) != 1 {
		t.Fatalf("versions: %+v %v", v, err)
	}
	snap := v[0].Items[0].Snapshot

	// The zvol, through a clone of its snapshot.
	zv := &ZFS{Runner: sysexec.Exec{}, RunDir: runDir}
	if err := zv.Snapshot(ctx, pool+"/vms/web/disk0", "hardyos-cloud-z2"); err != nil {
		t.Fatal(err)
	}
	rd, err := zv.OpenZvolSnapshot(ctx, pool+"/vms/web/disk0", "hardyos-cloud-z2")
	if err != nil {
		t.Fatal(err)
	}
	repo, _ := r.repo("local")
	sum, err := r.Restic.Backup(ctx, repo, ResticBackup{Stdin: rd, StdinName: "vm-web-disk0.raw", Tags: []string{"task=t", "run=z2", "item=vm:web", "part=disk:disk0"}}, nil)
	rd.Close()
	if err != nil {
		t.Fatal(err)
	}
	if sum.TotalBytes != 16<<20 {
		t.Fatalf("the disk image is %d bytes", sum.TotalBytes)
	}
	var got bytes.Buffer
	if err := r.Restic.Dump(ctx, repo, sum.SnapshotID, "/vm-web-disk0.raw", &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes()[:len(disk)], disk) {
		t.Fatal("the disk image differs")
	}
	if out := zfsRun(t, "zfs", "list", "-H", "-o", "name", "-r", pool); strings.Contains(out, CloneParent+"/") {
		t.Fatalf("the clone is left: %s", out)
	}

	// Change the folder, plant a link where a restored folder goes, and
	// put a file back in place: the link is replaced, never followed.
	write(t, filepath.Join(share, "docs", "letter.txt"), "changed")
	victim := filepath.Join(dir, "victim")
	_ = os.MkdirAll(victim, 0o755)
	if err := os.RemoveAll(filepath.Join(share, "docs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(share, "docs")); err != nil {
		t.Fatal(err)
	}
	_ = wait(r.StartRestore(ctx, RestoreArgs{Target: "local", Snapshot: snap, Paths: []string{"docs/letter.txt"}, Mode: ModeInPlace}))
	entries, _ := os.ReadDir(victim)
	if len(entries) != 0 {
		t.Fatalf("the restore wrote through a link: %v", entries)
	}
	// Roll the whole folder back: exactly version 1, owners kept.
	x = wait(r.StartRestore(ctx, RestoreArgs{Target: "local", Snapshot: snap, Mode: ModeRollback, Confirm: "Family"}))
	if x.Error != "" {
		t.Fatalf("rollback: %s", x.Error)
	}
	var rr RestoreResult
	_ = json.Unmarshal(x.Result, &rr)
	if got := read(t, filepath.Join(share, "docs", "letter.txt")); got != "dear family v1" {
		t.Fatalf("letter: %q", got)
	}
	if out := zfsRun(t, "stat", "-c", "%u", filepath.Join(share, "docs", "letter.txt")); strings.TrimSpace(out) != "3001" {
		t.Fatalf("owner after restore: %s", out)
	}
	if l, err := os.Readlink(filepath.Join(share, "evil")); err != nil || l != "/etc/shadow" {
		t.Fatalf("link: %q %v", l, err)
	}
	if !strings.Contains(zfsRun(t, "zfs", "list", "-H", "-t", "snapshot", "-o", "name", pool+"/shares/family"), rr.Safety) {
		t.Fatalf("no safety snapshot %s", rr.Safety)
	}
	// The staging datasets are gone.
	if out := zfsRun(t, "zfs", "list", "-H", "-o", "name", "-r", pool); strings.Contains(out, StagingParent+"/") {
		t.Fatalf("staging left: %s", out)
	}
}
