package cloudbackup

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

func (e *env) backup(target, task, run string, items ...Item) (*Task, *RunResult) {
	e.t.Helper()
	db := filepath.Join(e.work, "cloud-0123456789abcdef.db")
	write(e.t, db, "SQLite format 3\x00 fake database")
	x := e.wait(e.root.StartBackup(BackupArgs{Target: target, Task: task, Run: run, Items: items, Retention: DefaultRetention,
		SystemDB: db, System: SystemMeta{Version: "1.2.3", Hostname: "nas", Schema: 10, Users: 2}}))
	var res RunResult
	if len(x.Result) > 0 {
		if err := json.Unmarshal(x.Result, &res); err != nil {
			e.t.Fatal(err)
		}
	}
	snapshotCache.drop(target)
	return x, &res
}

func TestBackupBrowseRestoreShare(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tg := e.target("offsite")
	share := filepath.Join(e.base, "media")
	write(t, filepath.Join(share, "Photos", "a.jpg"), "photo A v1")
	write(t, filepath.Join(share, "notes.txt"), "notes v1")
	write(t, filepath.Join(share, ".recycle", "old.txt"), "recycled")
	if err := os.Symlink("/etc/passwd", filepath.Join(share, "link")); err != nil {
		t.Fatal(err)
	}
	e.shares.add("media", "Media", share)

	x, res := e.backup(tg.ID, "nightly", "r1", Item{Kind: ItemShare, ID: "media"}, Item{Kind: ItemSystem})
	if x.Error != "" {
		t.Fatalf("backup failed: %s (%+v)", x.Error, res)
	}
	if len(res.Items) != 2 || res.Items[0].Error != "" || res.Items[1].Error != "" || res.Manifest == "" {
		t.Fatalf("result: %+v", res)
	}
	// The snapshot was taken, mounted, unmounted and destroyed.
	joined := strings.Join(e.vol.calls, "\n")
	for _, want := range []string{"snapshot tank/shares/media@hardyos-cloud-r1", "mount tank/shares/media@hardyos-cloud-r1", "umount", "destroy tank/shares/media@hardyos-cloud-r1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}

	// A second version with changes.
	write(t, filepath.Join(share, "notes.txt"), "notes v2")
	write(t, filepath.Join(share, "new.txt"), "new")
	if x, _ := e.backup(tg.ID, "nightly", "r2", Item{Kind: ItemShare, ID: "media"}); x.Error != "" {
		t.Fatal(x.Error)
	}

	versions, err := e.root.Versions(ctx, tg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || versions[0].Run != "r2" || versions[1].Run != "r1" {
		t.Fatalf("versions: %+v", versions)
	}
	var v1 VersionItem
	for _, it := range versions[1].Items {
		if it.Item == "share:media" {
			v1 = it
		}
	}
	if v1.Snapshot == "" || versions[1].Manifest == "" {
		t.Fatalf("version 1: %+v", versions[1])
	}

	// Browsing hides the recycle bin; the link is listed as a link.
	entries, err := e.root.Browse(ctx, BrowseArgs{Target: tg.ID, Snapshot: v1.Snapshot})
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, en := range entries {
		names = append(names, en.Name+":"+en.Type)
	}
	if got := strings.Join(names, ","); got != "Photos:dir,link:symlink,notes.txt:file" {
		t.Fatalf("browse: %s", got)
	}
	if _, err := e.root.Browse(ctx, BrowseArgs{Target: tg.ID, Snapshot: v1.Snapshot, Path: "../x"}); err == nil {
		t.Fatal("browse with .. worked")
	}

	// Restore notes.txt in place: the old content comes back; new.txt stays.
	x = e.wait(e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: v1.Snapshot, Paths: []string{"notes.txt"}, Mode: ModeInPlace}))
	if x.Error != "" {
		t.Fatal(x.Error)
	}
	if got := read(t, filepath.Join(share, "notes.txt")); got != "notes v1" {
		t.Fatalf("in place: %q", got)
	}
	if _, err := os.Stat(filepath.Join(share, "new.txt")); err != nil {
		t.Fatal("in-place restore removed a newer file")
	}

	// Restore to a new folder.
	x = e.wait(e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: v1.Snapshot, Paths: []string{"Photos"}, Mode: ModeCopy, Folder: "Restored"}))
	if x.Error != "" {
		t.Fatal(x.Error)
	}
	if got := read(t, filepath.Join(share, "Restored", "Photos", "a.jpg")); got != "photo A v1" {
		t.Fatalf("copy: %q", got)
	}
	// The same folder name again is refused.
	x = e.wait(e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: v1.Snapshot, Paths: []string{"Photos"}, Mode: ModeCopy, Folder: "Restored"}))
	if x.Error == "" {
		t.Fatal("restoring over an existing folder name worked")
	}

	// Rollback needs the name; then the folder is exactly version 1.
	if _, err := e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: v1.Snapshot, Mode: ModeRollback}); err == nil {
		t.Fatal("rollback without confirmation")
	}
	x = e.wait(e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: v1.Snapshot, Mode: ModeRollback, Confirm: "wrong"}))
	if x.Error == "" {
		t.Fatal("rollback with the wrong name worked")
	}
	x = e.wait(e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: v1.Snapshot, Mode: ModeRollback, Confirm: "Media"}))
	if x.Error != "" {
		t.Fatal(x.Error)
	}
	var rr RestoreResult
	_ = json.Unmarshal(x.Result, &rr)
	if !strings.HasPrefix(rr.Safety, "hardyos-manual-") {
		t.Fatalf("no safety snapshot: %+v", rr)
	}
	for _, gone := range []string{"new.txt", "Restored"} {
		if _, err := os.Lstat(filepath.Join(share, gone)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still there after the rollback", gone)
		}
	}
	if l, err := os.Readlink(filepath.Join(share, "link")); err != nil || l != "/etc/passwd" {
		t.Errorf("the link came back as %q, %v", l, err)
	}
	if got := read(t, filepath.Join(share, ".recycle", "old.txt")); got != "recycled" {
		t.Error("the recycle bin was touched by a rollback")
	}

	// Settings: the archive opens with the repository key and is staged.
	var sys VersionItem
	for _, it := range versions[1].Items {
		if it.Item == ItemSystem {
			sys = it
		}
	}
	x = e.wait(e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: sys.Snapshot, Mode: ModeRollback, Confirm: "settings", MaxSchema: 10}))
	if x.Error != "" {
		t.Fatal(x.Error)
	}
	if e.system.staged == nil || string(e.system.staged.DB) != "SQLite format 3\x00 fake database" || e.system.staged.Manifest.Hostname != "nas" {
		t.Fatalf("settings staged: %+v", e.system.staged)
	}
	x = e.wait(e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: sys.Snapshot, Mode: ModeRollback, Confirm: "settings", MaxSchema: 9}))
	if !strings.Contains(x.Error, "newer HardyOS") {
		t.Fatalf("a newer database was staged: %q", x.Error)
	}
}

func TestPersonRestore(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tg := e.target("t1")
	share := filepath.Join(e.base, "family")
	write(t, filepath.Join(share, "mine.txt"), "mine v1")
	write(t, filepath.Join(share, "private.txt"), "secret")
	if err := os.Chmod(filepath.Join(share, "private.txt"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.shares.add("family", "Family", share)
	if x, _ := e.backup(tg.ID, "daily", "p1", Item{Kind: ItemShare, ID: "family"}); x.Error != "" {
		t.Fatal(x.Error)
	}
	versions, _ := e.root.Versions(ctx, tg.ID)
	snap := versions[0].Items[0].Snapshot
	who := &fileworker.Who{Principal: `HOME\alice`}

	// No rule access: nothing.
	e.files.level = "none"
	if _, err := e.root.Browse(ctx, BrowseArgs{Target: tg.ID, Snapshot: snap, Who: who}); err == nil {
		t.Fatal("browsed a folder without access")
	}
	if _, err := e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: snap, Mode: ModeCopy, Folder: "x", Who: who}); err == nil {
		t.Fatal("restore without access started")
	}
	// Read only: no restore.
	e.files.level = "read"
	x := e.wait(e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: snap, Mode: ModeCopy, Folder: "x", Who: who}))
	if x.Error == "" {
		t.Fatal("restored into a read-only folder")
	}
	// People can't roll back.
	e.files.level = "write"
	if _, err := e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: snap, Mode: ModeRollback, Confirm: "Family", Who: who}); err == nil {
		t.Fatal("a person rolled a folder back")
	}
	// A copy goes through the person's file operations; the file they
	// couldn't read in the backup is skipped.
	x = e.wait(e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: snap, Mode: ModeCopy, Folder: "Back", Who: who}))
	if x.Error != "" {
		t.Fatal(x.Error)
	}
	var rr RestoreResult
	_ = json.Unmarshal(x.Result, &rr)
	if got := read(t, filepath.Join(share, "Back", "mine.txt")); got != "mine v1" {
		t.Fatalf("restored %q", got)
	}
	if _, err := os.Stat(filepath.Join(share, "Back", "private.txt")); err == nil || rr.Skipped != 1 {
		t.Fatalf("a file the person couldn't read was restored (%+v)", rr)
	}
	ops := strings.Join(e.files.ops, ",")
	if !strings.Contains(ops, "in:open mine.txt") || !strings.Contains(ops, "create Back/mine.txt") {
		t.Fatalf("not through the person's file operations: %s", ops)
	}
}

func TestBackupVMAndApp(t *testing.T) {
	requireBlockDevice = false
	t.Cleanup(func() { requireBlockDevice = true })
	e := newEnv(t)
	ctx := context.Background()
	tg := e.target("vmt")
	vmDir := filepath.Join(e.base, "vm-web")
	write(t, filepath.Join(vmDir, "nvram.fd"), "nvram v1")
	spec := vms.Spec{ID: "web", Name: "Web", Disks: []vms.Disk{{Name: "disk0", SizeGB: 1}}}
	sb, _ := json.Marshal(spec)
	write(t, filepath.Join(vmDir, "vm.json"), string(sb))
	disk := filepath.Join(e.base, "zvol-web-disk0")
	write(t, disk, strings.Repeat("D", 70000))
	e.vol.ds["tank/vms/web"] = vmDir
	e.vol.ds["tank/vms/web/disk0"] = disk
	e.vms.specs["web"] = spec
	e.vms.dirs["web"] = vmDir
	e.vms.disks["web/disk0"] = filepath.Join(e.base, "restored-disk0")

	appDir := filepath.Join(e.base, "app-kincast")
	write(t, filepath.Join(appDir, "data", "db.sqlite"), "app data v1")
	write(t, filepath.Join(appDir, ".hardyos", "app.env"), "SECRET=1")
	// Links root would follow when it reads an app's or VM's own files
	// (decision 173): only links under an app's data/ come back.
	for _, l := range [][2]string{
		{"/etc/shadow", filepath.Join(appDir, ".hardyos", "icon.png")},
		{"/etc/hostname", filepath.Join(appDir, "data", "host")},
		{"/etc/shadow", filepath.Join(vmDir, "evil.fd")},
	} {
		if err := os.Symlink(l[0], l[1]); err != nil {
			t.Fatal(err)
		}
	}
	e.vol.ds["tank/apps/kincast"] = appDir
	e.apps.srcs["kincast"] = appSource("kincast", "KinCast")
	e.apps.dirs["kincast"] = appDir

	x, res := e.backup(tg.ID, "all", "v1", Item{Kind: ItemVM, ID: "web"}, Item{Kind: ItemApp, ID: "kincast"})
	if x.Error != "" {
		t.Fatalf("%s %+v", x.Error, res)
	}
	versions, _ := e.root.Versions(ctx, tg.ID)
	var vmItem, appItem VersionItem
	for _, it := range versions[0].Items {
		switch it.Item {
		case "vm:web":
			vmItem = it
		case "app:kincast":
			appItem = it
		}
	}
	if vmItem.Snapshot == "" || vmItem.Disks["disk0"] == "" || appItem.Snapshot == "" {
		t.Fatalf("items: %+v", versions[0].Items)
	}

	// Change both, then restore.
	for _, p := range []string{filepath.Join(appDir, ".hardyos", "icon.png"), filepath.Join(appDir, "data", "host"), filepath.Join(vmDir, "evil.fd")} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(vmDir, "nvram.fd"), "nvram v2")
	write(t, filepath.Join(appDir, "data", "db.sqlite"), "app data v2")
	write(t, filepath.Join(appDir, "data", "extra"), "x")

	x = e.wait(e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: vmItem.Snapshot, Mode: ModeRollback, Confirm: "Web"}))
	if x.Error != "" {
		t.Fatal(x.Error)
	}
	if got := read(t, filepath.Join(vmDir, "nvram.fd")); got != "nvram v1" {
		t.Fatalf("nvram %q", got)
	}
	if got := read(t, e.vms.disks["web/disk0"]); got != strings.Repeat("D", 70000) {
		t.Fatalf("disk restored wrong (%d bytes)", len(got))
	}
	if e.vms.got[0].Spec.ID != "web" || e.vms.got[0].DiskBytes["disk0"] != 70000 {
		t.Fatalf("fill: %+v", e.vms.got[0])
	}
	// Disk snapshots can't be restored on their own.
	if _, err := e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: vmItem.Disks["disk0"], Mode: ModeRollback, Confirm: "Web"}); err == nil {
		t.Fatal("restored a disk part on its own")
	}

	x = e.wait(e.root.StartRestore(ctx, RestoreArgs{Target: tg.ID, Snapshot: appItem.Snapshot, Mode: ModeRollback, Confirm: "KinCast"}))
	if x.Error != "" {
		t.Fatal(x.Error)
	}
	if got := read(t, filepath.Join(appDir, "data", "db.sqlite")); got != "app data v1" {
		t.Fatalf("app data %q", got)
	}
	if _, err := os.Stat(filepath.Join(appDir, "data", "extra")); err == nil {
		t.Fatal("app rollback kept a file the version doesn't have")
	}
	if got := read(t, filepath.Join(appDir, ".hardyos", "app.env")); got != "SECRET=1" {
		t.Fatal("app settings not restored")
	}
	if _, err := os.Lstat(filepath.Join(appDir, ".hardyos", "icon.png")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a link in the app's own files was restored")
	}
	if l, err := os.Readlink(filepath.Join(appDir, "data", "host")); err != nil || l != "/etc/hostname" {
		t.Errorf("a link in the app's data didn't come back: %q %v", l, err)
	}
	if _, err := os.Lstat(filepath.Join(vmDir, "evil.fd")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a link in the VM's folder was restored")
	}
}

func TestRetentionAndCancel(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tg := e.target("ret")
	share := filepath.Join(e.base, "s")
	write(t, filepath.Join(share, "f"), "x")
	e.shares.add("s", "S", share)
	for _, run := range []string{"a1", "a2", "a3"} {
		db := filepath.Join(e.work, "cloud-0123456789abcdef.db")
		write(t, db, "db")
		x := e.wait(e.root.StartBackup(BackupArgs{Target: tg.ID, Task: "t", Run: run, Items: []Item{{Kind: ItemShare, ID: "s"}}, Retention: Retention{Daily: 1}}))
		if x.Error != "" {
			t.Fatal(x.Error)
		}
	}
	snapshotCache.drop(tg.ID)
	v, err := e.root.Versions(ctx, tg.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Daily 1 keeps the newest of today (per item path, manifests too).
	if len(v) != 1 || v[0].Run != "a3" {
		t.Fatalf("after retention: %+v", v)
	}
	// One task per destination at a time; cancelling stops it.
	big := filepath.Join(e.base, "big")
	write(t, filepath.Join(big, "f"), strings.Repeat("y", 1<<20))
	e.shares.add("big", "Big", big)
	task, err := e.root.StartBackup(BackupArgs{Target: tg.ID, Task: "t", Run: "c1", Items: []Item{{Kind: ItemShare, ID: "big"}}, Retention: DefaultRetention})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.root.StartPrune(tg.ID); err == nil {
		t.Fatal("two tasks ran on one destination")
	}
	e.root.CancelTask(task.ID)
	x := e.wait(task, nil)
	if x.Error != "cancelled" && x.Error != "" {
		t.Fatalf("cancel: %q", x.Error)
	}
	x = e.wait(e.root.StartCheck(tg.ID, 10))
	if x.Error != "" {
		t.Fatalf("check: %s", x.Error)
	}
	x = e.wait(e.root.StartPrune(tg.ID))
	if x.Error != "" {
		t.Fatalf("prune: %s", x.Error)
	}
}

func TestTargetsAndKit(t *testing.T) {
	e := newEnv(t)
	tg := e.target("home")
	// The repository exists now: saving another destination there without
	// its key is refused, with its key it connects.
	other := Target{ID: "again", Name: "Again", Kind: KindLocal, Path: tg.Path}
	if _, err := e.root.Save(context.Background(), SaveArgs{Target: other}); !errors.Is(err, ErrRepoExists) {
		t.Fatalf("saved over an existing repository: %v", err)
	}
	kit, err := e.root.Kit(tg.ID)
	if err != nil || len(kit.Key) < 40 {
		t.Fatalf("kit: %+v %v", kit, err)
	}
	if _, err := e.root.Save(context.Background(), SaveArgs{Target: other, RepoPassword: "wrong-wrong-wrong-wrong"}); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("a wrong key connected: %v", err)
	}
	if _, err := e.root.Save(context.Background(), SaveArgs{Target: other, RepoPassword: kit.Key}); err != nil {
		t.Fatal(err)
	}
	// The targets file holds no key in the clear.
	b, err := os.ReadFile(filepath.Join(e.root.Dir, StoreFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), kit.Key) {
		t.Fatal("the repository key is stored in the clear")
	}
	// Sealed values are bound to their target.
	var f storeFile
	_ = json.Unmarshal(b, &f)
	f.Targets[0].Sealed, f.Targets[1].Sealed = f.Targets[1].Sealed, f.Targets[0].Sealed
	nb, _ := json.Marshal(f)
	_ = os.WriteFile(filepath.Join(e.root.Dir, StoreFile), nb, 0o600)
	if _, err := e.root.Kit("home"); err == nil {
		t.Fatal("a sealed value moved to another target opened")
	}
	_ = os.WriteFile(filepath.Join(e.root.Dir, StoreFile), b, 0o600)
	// Kit text round trip.
	txt := EncodeKit(KitData{Target: tg, Repository: tg.Repository(), Key: kit.Key})
	k, err := ParseKit("Instructions...\n" + txt + "\nmore")
	if err != nil || k.Key != kit.Key || k.Target.ID != "home" {
		t.Fatalf("kit parse: %+v %v", k, err)
	}
	if err := e.root.Remove("again", "nope"); err == nil {
		t.Fatal("removed without the name")
	}
	if err := e.root.Remove("again", "Again"); err != nil {
		t.Fatal(err)
	}
}
