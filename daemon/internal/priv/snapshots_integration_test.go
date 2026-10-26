package priv

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/snapshots"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// TestZFSIntegrationSnapshots runs the automatic snapshot scheduler and the
// manual snapshot operations against real ZFS on a file-backed pool, with a
// test clock: snapshots are taken per slot, pruned per kind, other
// snapshots are left alone, unmounted and deleted folders are skipped.
// Needs root and ZFS; runs in CI's "ZFS integration" job
// (HARDYOS_ZFS_INTEGRATION=1, -test.run TestZFSIntegration).
func TestZFSIntegrationSnapshots(t *testing.T) {
	if os.Getenv("HARDYOS_ZFS_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_ZFS_INTEGRATION=1 to run against real ZFS (needs root)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	dir := t.TempDir()
	vdev := filepath.Join(dir, "vdev")
	f, err := os.Create(vdev)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(256 << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	const pool = "hardyossnaps"
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	_ = exec.Command("zpool", "destroy", "-f", pool).Run()
	run("zpool", "create", "-o", "ashift=12", "-m", filepath.Join(dir, "mnt", pool),
		"-O", "xattr=sa", "-O", "acltype=posixacl", pool, vdev)
	t.Cleanup(func() { _ = exec.Command("zpool", "destroy", "-f", pool).Run() })

	shm := &shares.Manager{Runner: sysexec.Exec{}, Root: "/"}
	t.Cleanup(shm.Wait)
	keep := shares.DefaultServices()
	keep.Snapshots = shares.Snapshots{Hourly: 2, Daily: 1}
	photos, err := shm.Create(ctx, shares.NewShare{Pool: pool, Name: "Photos", Services: &keep})
	if err != nil {
		t.Fatal(err)
	}
	ds := photos.Dataset
	// Snapshots the scheduler must never touch.
	for _, n := range []string{"zrepl_keep", "hardyos-auto-hourly_2026-01-01-0030", "hardyos-update-20261101-120000"} {
		run("zfs", "snapshot", ds+"@"+n)
	}

	now := time.Date(2026, 11, 2, 0, 0, 30, 0, time.UTC) // Monday 2 November
	m := &snapshots.Manager{Runner: sysexec.Exec{}, Shares: shm, Now: func() time.Time { return now }}
	names := func() []string {
		t.Helper()
		var out []string
		for _, l := range strings.Split(strings.TrimSpace(run("zfs", "list", "-H", "-o", "name", "-t", "snapshot", "-d", "1", ds)), "\n") {
			if _, label, ok := strings.Cut(l, "@"); ok {
				out = append(out, label)
			}
		}
		slices.Sort(out)
		return out
	}
	expect := func(want ...string) {
		t.Helper()
		want = append(want, "hardyos-auto-hourly_2026-01-01-0030", "hardyos-update-20261101-120000", "zrepl_keep")
		slices.Sort(want)
		if got := names(); !slices.Equal(got, want) {
			t.Fatalf("snapshots at %s:\n  %s\nwant\n  %s", now.Format(time.RFC3339), strings.Join(got, "\n  "), strings.Join(want, "\n  "))
		}
	}
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(photos.Path, "note.txt"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("v1")
	m.Tick(ctx)
	expect("hardyos-auto-hourly_2026-11-02-0000", "hardyos-auto-daily_2026-11-02-0000")
	m.Tick(ctx) // idempotent
	expect("hardyos-auto-hourly_2026-11-02-0000", "hardyos-auto-daily_2026-11-02-0000")

	write("v2")
	now = time.Date(2026, 11, 2, 1, 0, 5, 0, time.UTC)
	m.Tick(ctx)
	now = time.Date(2026, 11, 2, 2, 0, 5, 0, time.UTC)
	m.Tick(ctx)
	expect("hardyos-auto-hourly_2026-11-02-0100", "hardyos-auto-hourly_2026-11-02-0200", "hardyos-auto-daily_2026-11-02-0000")
	// What Previous Versions and the File Manager read.
	if b, err := os.ReadFile(filepath.Join(photos.Path, ".zfs/snapshot/hardyos-auto-daily_2026-11-02-0000/note.txt")); err != nil || string(b) != "v1" {
		t.Errorf("daily snapshot content = %q %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(photos.Path, ".zfs/snapshot/hardyos-auto-hourly_2026-11-02-0100/note.txt")); err != nil || string(b) != "v2" {
		t.Errorf("hourly snapshot content = %q %v", b, err)
	}

	// Server off from Monday 02:00 to Wednesday 15:20: one of each, newest slot.
	now = time.Date(2026, 11, 4, 15, 20, 0, 0, time.UTC)
	m.Tick(ctx)
	expect("hardyos-auto-hourly_2026-11-02-0200", "hardyos-auto-hourly_2026-11-04-1500", "hardyos-auto-daily_2026-11-04-0000")

	// Manual snapshots: listed, never pruned, deleted only with confirmation.
	sn, err := m.Create(ctx, photos.ID, "before-cleanup")
	if err != nil || sn.Kind != "manual" {
		t.Fatalf("create = %+v %v", sn, err)
	}
	if _, err := m.Create(ctx, photos.ID, "before-cleanup"); err == nil {
		t.Error("the same name twice")
	}
	l, err := m.List(ctx, photos.ID)
	if err != nil || len(l) != 7 || l[0].CreatedAt.Before(l[6].CreatedAt) {
		t.Fatalf("list = %+v %v", l, err)
	}
	kinds := map[string]string{}
	for _, s := range l {
		kinds[s.Name] = s.Kind
	}
	if kinds["before-cleanup"] != "manual" || kinds["zrepl_keep"] != "other" || kinds["hardyos-auto-daily_2026-11-04-0000"] != "daily" || kinds["hardyos-auto-hourly_2026-01-01-0030"] != "other" {
		t.Errorf("kinds = %v", kinds)
	}
	if err := m.Delete(ctx, photos.ID, "zrepl_keep", "zrepl"); err == nil {
		t.Error("deleted without the name")
	}

	// Lower counts prune at once; 0 turns a kind off.
	keep.Snapshots = shares.Snapshots{Hourly: 1}
	if _, err := shm.Update(ctx, shares.ShareUpdate{ID: photos.ID, Services: &keep}); err != nil {
		t.Fatal(err)
	}
	m.Tick(ctx)
	expect("hardyos-auto-hourly_2026-11-04-1500", "before-cleanup")
	if err := m.Delete(ctx, photos.ID, "before-cleanup", "before-cleanup"); err != nil {
		t.Fatal(err)
	}
	expect("hardyos-auto-hourly_2026-11-04-1500")

	// Unmounted: skipped, not an error; back again: caught up.
	run("zfs", "unmount", ds)
	now = time.Date(2026, 11, 4, 16, 0, 10, 0, time.UTC)
	m.Tick(ctx)
	expect("hardyos-auto-hourly_2026-11-04-1500")
	run("zfs", "mount", ds)
	m.Tick(ctx)
	expect("hardyos-auto-hourly_2026-11-04-1600")

	// Deleting the folder destroys its snapshots; the scheduler carries on.
	if err := shm.Delete(ctx, photos.ID, "Photos"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	m.Tick(ctx)
	if _, err := m.List(ctx, photos.ID); err == nil {
		t.Error("listed a deleted folder")
	}
}
