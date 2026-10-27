package vms

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// Restoring a VM from a backup checks the version's spec before anything
// changes and never destroys a disk the version doesn't have (decision 175).
func TestRestoreFromBackupChecksFirstAndKeepsDisks(t *testing.T) {
	zvolReady = func(os.FileInfo) bool { return true }
	t.Cleanup(func() { zvolReady = func(fi os.FileInfo) bool { return fi.Mode()&os.ModeDevice != 0 } })
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	e.m.Now = func() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) }
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	cur, err := e.m.Get(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	version := cur.Spec // the backup: disk0 only
	s := cur.Spec
	s.Disks = append(s.Disks, Disk{Name: "disk1", SizeGB: 10, Bus: BusVirtioSCSI})
	if _, err := e.m.Update(ctx, UpdateArgs{Spec: s}); err != nil {
		t.Fatal(err)
	}
	var written []string
	fill := func(spec Spec) RestoreFill {
		return RestoreFill{Spec: spec, DiskBytes: map[string]int64{"disk0": 20 << 30},
			Disk: func(_ context.Context, name, _ string) error { written = append(written, name); return nil }}
	}

	// A version whose spec isn't valid here changes nothing.
	bad := version
	bad.NICs = append([]NIC(nil), bad.NICs...)
	bad.NICs[0].MAC = ""
	before := len(e.sim.Lines())
	if _, err := e.m.RestoreFromBackup(ctx, "web", "web", fill(bad)); err == nil || !strings.Contains(err.Error(), "isn't valid here") {
		t.Fatalf("invalid spec: %v", err)
	}
	other := version
	other.UUID = "00000000-0000-4000-8000-000000000001"
	if _, err := e.m.RestoreFromBackup(ctx, "web", "web", fill(other)); err == nil || !strings.Contains(err.Error(), "another VM") {
		t.Fatalf("another VM's backup: %v", err)
	}
	for _, l := range e.sim.Lines()[before:] {
		if strings.HasPrefix(l, "zfs snapshot") || strings.HasPrefix(l, "zfs set") || strings.HasPrefix(l, "zfs destroy") {
			t.Fatalf("a refused restore changed something: %s", l)
		}
	}

	var notes []string
	f := fill(version)
	f.Note = func(m string) { notes = append(notes, m) }
	v, err := e.m.RestoreFromBackup(ctx, "web", "web", f)
	if err != nil {
		t.Fatal(err)
	}
	if e.sim.has("zfs destroy -r tank/vms/web/disk1") {
		t.Fatal("a disk the version doesn't have was destroyed")
	}
	if len(v.Spec.Disks) != 2 || v.Spec.Disks[0].Name != "disk0" || v.Spec.Disks[1].Name != "disk1" {
		t.Fatalf("disks after the restore: %+v", v.Spec.Disks)
	}
	if strings.Join(written, ",") != "disk0" {
		t.Fatalf("disks written: %v", written)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "kept disk1") || !strings.Contains(strings.Join(notes, "\n"), "vm-20261026-120000") {
		t.Fatalf("notes: %v", notes)
	}
	// The safety snapshot covers both disks, so going back to it works.
	snaps, _ := e.m.Snapshots(ctx, "web")
	if len(snaps) != 1 {
		t.Fatalf("snapshots: %+v", snaps)
	}
	if _, err := e.m.Rollback(ctx, RollbackArgs{ID: "web", Snapshot: snaps[0].Name, Confirm: "web"}); err != nil {
		t.Fatal(err)
	}
	if !e.sim.has("zfs rollback -r tank/vms/web/disk1@" + snaps[0].Name) {
		t.Fatal("disk1 didn't go back with the safety snapshot")
	}
}
