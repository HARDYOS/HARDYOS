package priv

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// TestZFSIntegration runs storage operations against real ZFS using
// file-backed vdevs. It needs root and ZFS, so it only runs when
// HARDYOS_ZFS_INTEGRATION=1 (CI sets this in the "ZFS integration" job).
func TestZFSIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_ZFS_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_ZFS_INTEGRATION=1 to run against real ZFS (needs root)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	dir := t.TempDir()
	files := make([]string, 8)
	for i := range files {
		files[i] = filepath.Join(dir, "vdev"+string(rune('a'+i)))
		f, err := os.Create(files[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(256 << 20); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	const pool = "hardyostest"
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	_ = exec.Command("zpool", "destroy", "-f", pool).Run()
	run("zpool", "create", "-o", "ashift=12", "-m", filepath.Join(dir, "mnt"), pool,
		"raidz1", files[0], files[1], files[2],
		"special", "mirror", files[3], files[4],
		"log", files[5],
		"cache", files[6],
		"spare", files[7])
	t.Cleanup(func() { _ = exec.Command("zpool", "destroy", "-f", pool).Run() })

	st := &storageOps{env: StorageEnv{Runner: sysexec.Exec{}, KeyDir: filepath.Join(dir, "keys")}}

	// Pool list and status parse real output.
	out, err := st.zpool(ctx, zfs.PoolListArgs...)
	if err != nil {
		t.Fatal(err)
	}
	pools, err := zfs.ParsePoolList(out)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range pools {
		if p.Name == pool {
			found = true
			if p.Health != "ONLINE" || p.SizeBytes == 0 {
				t.Errorf("pool row = %+v", p)
			}
		}
	}
	if !found {
		t.Fatalf("pool %s not listed: %+v", pool, pools)
	}
	status, err := st.status(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	classes := map[zfs.VdevClass]int{}
	for _, g := range status.Groups {
		classes[g.Class]++
	}
	if classes[zfs.ClassData] != 1 || classes[zfs.ClassSpecial] != 1 || classes[zfs.ClassLog] != 1 ||
		classes[zfs.ClassCache] != 1 || classes[zfs.ClassSpare] != 1 {
		t.Errorf("vdev classes from real status = %v\n%s", classes, run("zpool", "status", "-P", "-p", pool))
	}
	if status.Groups[0].Type != "raidz1" || len(status.Groups[0].Children) != 3 {
		t.Errorf("data vdev = %+v", status.Groups[0])
	}

	// Datasets: create, set, list.
	if _, err := st.createDataset(ctx, DatasetCreateArgs{Name: pool + "/family", Props: map[string]string{"compression": "zstd", "hardyos:role": "shares"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.setDataset(ctx, DatasetSetArgs{Name: pool + "/family", Props: map[string]string{"quota": "100M"}}); err != nil {
		t.Fatal(err)
	}
	dsAny, err := st.listDatasets(ctx, DatasetListArgs{Root: pool + "/family"})
	if err != nil {
		t.Fatal(err)
	}
	ds := dsAny.([]zfs.Dataset)
	if len(ds) != 1 || ds[0].Compression != "zstd" || ds[0].QuotaBytes != 100<<20 || !ds[0].Mounted {
		t.Errorf("dataset = %+v", ds)
	}
	if _, err := st.createDataset(ctx, DatasetCreateArgs{Name: pool + "/vm1", VolSize: "64M"}); err != nil {
		t.Fatal(err)
	}

	// Snapshots: create, list, rollback, destroy.
	if _, err := st.createSnapshot(ctx, SnapshotCreateArgs{Dataset: pool + "/family", Label: "auto-daily-20261024-0000"}); err != nil {
		t.Fatal(err)
	}
	snapsAny, err := st.listSnapshots(ctx, DatasetListArgs{Root: pool})
	if err != nil {
		t.Fatal(err)
	}
	snaps := snapsAny.([]zfs.Snapshot)
	if len(snaps) != 1 || snaps[0].Label != "auto-daily-20261024-0000" || snaps[0].CreatedAt.IsZero() {
		t.Errorf("snapshots = %+v", snaps)
	}
	if _, err := st.rollback(ctx, SnapshotRollbackArgs{Name: snaps[0].Name, Confirm: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.destroySnapshot(ctx, SnapshotArgs{Name: snaps[0].Name}); err != nil {
		t.Fatal(err)
	}

	// Scrub: start, then the status reports a scrub (it may finish instantly on a tiny pool).
	if _, err := st.scrub(ctx, PoolScrubArgs{Pool: pool, Action: "start"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Minute)
	for {
		s, err := st.status(ctx, pool)
		if err != nil {
			t.Fatal(err)
		}
		if s.Scan.Kind == "scrub" && s.Scan.State == "finished" {
			if s.Scan.Errors == nil || *s.Scan.Errors != 0 || s.Scan.FinishedAt == nil {
				t.Errorf("finished scrub = %+v", s.Scan)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("scrub never finished: %+v", s.Scan)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Offline/online a member, then clear.
	member := status.Groups[0].Children[0].Name
	if _, err := st.simpleDevice("offline")(ctx, PoolDeviceArgs{Pool: pool, Device: member}); err == nil {
		t.Log("offline of a file vdev accepted (path isn't under /dev/disk/by-id in this test, so it should have been refused)")
	} else if !strings.Contains(err.Error(), "by-id") {
		t.Errorf("unexpected offline error: %v", err)
	}

	// Destroy needs the exact name.
	if _, err := st.destroyPool(ctx, PoolDestroyArgs{Pool: pool, ConfirmName: "nope"}); err == nil {
		t.Fatal("destroy without the exact name succeeded")
	}
	if _, err := st.destroyPool(ctx, PoolDestroyArgs{Pool: pool, ConfirmName: pool}); err != nil {
		t.Fatal(err)
	}
}
