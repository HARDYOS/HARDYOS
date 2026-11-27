package hacopy

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// TestHAShareIntegration moves a shared folder with its app (decisions
// 500-503) between two file-backed pools against the real kernel: the
// folder is held as shares.HAHold holds it, its final snapshot is sent as
// single-dataset streams into the storage pool's incoming copy and adopted
// there as a shared folder with its settings, held (read-only, unmounted);
// the POSIX ACL entries of its people and its app travel with the files;
// a write after the final snapshot keeps this server's copy from being
// parked; once parked, it is put back as it was (Undo); and the storage
// server's copy is parked only with its conversion's mark.
//
// Needs root and ZFS (acl's getfacl/setfacl): CI's Cluster (namespaces)
// job, HARDYOS_CLUSTER_INTEGRATION=1.
func TestHAShareIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_CLUSTER_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_CLUSTER_INTEGRATION=1 to run against real ZFS (needs root)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}
	for _, tool := range []string{"zpool", "zfs", "setfacl", "getfacl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s isn't installed", tool)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sh := func(name string, args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		return string(out), err
	}
	must := func(name string, args ...string) string {
		t.Helper()
		out, err := sh(name, args...)
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return out
	}
	dir := t.TempDir()
	mkPool := func(name string) {
		vdev := filepath.Join(dir, name+".vdev")
		f, _ := os.Create(vdev)
		_ = f.Truncate(512 << 20)
		f.Close()
		_, _ = sh("zpool", "destroy", "-f", name)
		must("zpool", "create", "-o", "ashift=12", "-m", "/mnt/"+name, "-O", "xattr=sa", name, vdev)
		t.Cleanup(func() { _, _ = exec.Command("zpool", "destroy", "-f", name).CombinedOutput() })
	}
	const localPool, storePool = "hcshlocal", "hcshstore"
	mkPool(localPool)
	mkPool(storePool)

	// A shared folder as shares.Manager makes it, with a file the app's
	// user (30001) may write and a domain group (2000100) may read.
	must("zfs", "create", "-o", "org.hardyos:role=shares", localPool+"/shares")
	must("zfs", "create", "-o", "acltype=posixacl", "-o", "xattr=sa", "-o", "aclinherit=passthrough", "-o", "devices=off", "-o", "setuid=off",
		"-o", shares.PropShare+"=1", "-o", shares.PropName+"=Media", localPool+"/shares/media")
	file := "/mnt/" + localPool + "/shares/media/movie.mkv"
	if err := os.WriteFile(file, []byte("a family movie"), 0o640); err != nil {
		t.Fatal(err)
	}
	must("setfacl", "-m", "u:30001:rw-,g:2000100:r--", file)

	run := sysexec.Exec{}
	var released, changed int
	compute := &Root{Runner: run, ShareRelease: func(context.Context, string) func() { released++; return nil }, ShareChanged: func(context.Context) { changed++ }}
	busy := false
	storage := &Root{Runner: run, ShareTaken: func(context.Context, string, string) error { return nil }, ShareChanged: func(context.Context) {},
		ShareBusy: func(context.Context, string, string) (bool, error) { return busy, nil }}
	const conv = "hashareconv1s0"
	local := Ref{Kind: KindShare, ID: "media", Pool: localPool, Side: SideLocal}
	clRef := Ref{Kind: KindShare, ID: "media", Pool: storePool, Side: SideCluster}

	// Held as shares.HAHold holds it, then its final snapshot.
	must("zfs", "set", "canmount=noauto", "readonly=on", propHAHold+"="+conv, localPool+"/shares/media")
	must("zfs", "unmount", localPool+"/shares/media")
	final := SnapPrefix + conv + "-final1"
	if err := compute.Snapshot(ctx, SnapArgs{Ref: local, Name: final}); err != nil {
		t.Fatal(err)
	}
	ss, rf, err := compute.Send(ctx, SendArgs{Ref: local, To: final})
	if err != nil {
		t.Fatal(err)
	}
	rs, wf, err := storage.Recv(ctx, RecvArgs{Ref: clRef, Conv: conv, Label: final})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(wf, rf)
	wf.Close()
	rf.Close()
	wait := func(r *Root, id string) StreamState {
		for i := 0; i < 600; i++ {
			st, err := r.Stream(id)
			if err != nil {
				t.Fatal(err)
			}
			if st.Done {
				return *st
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("a stream never finished")
		return StreamState{}
	}
	if st := wait(compute, ss.Stream); !st.OK {
		t.Fatalf("send: %s", st.Error)
	}
	if st := wait(storage, rs.Stream); !st.OK {
		t.Fatalf("receive: %s", st.Error)
	}
	set := &shares.Settings{Name: "Media", Access: []shares.Rule{{Kind: shares.KindGroup, Name: `HOME\Family`, Level: shares.LevelRead}},
		Apps: []shares.AppGrant{{App: "jellyfin", UID: 30001, Level: shares.LevelWrite}}, Services: shares.DefaultServices()}
	res, err := storage.Adopt(ctx, AdoptArgs{Ref: clRef, Conv: conv, Share: set})
	if err != nil {
		t.Fatal(err)
	}
	ds := storePool + "/shares/media"
	got := strings.Fields(must("zfs", "get", "-H", "-o", "value", "readonly,canmount,mounted,"+propHAHold+","+shares.PropShare+","+shares.PropName, ds))
	if res.Dataset != ds || strings.Join(got, " ") != "on noauto no "+conv+" 1 Media" {
		t.Fatalf("adopted %+v: %v", res, got)
	}
	// posixacl (older ZFS) or posix (newer) are the same.
	if a := strings.TrimSpace(must("zfs", "get", "-H", "-o", "value", "acltype", ds)); !strings.HasPrefix(a, "posix") {
		t.Fatalf("acltype %q", a)
	}
	// What arrived carries the files' ACLs (mounted here only to look).
	must("zfs", "mount", ds)
	acl := must("getfacl", "-n", "/mnt/"+ds+"/movie.mkv")
	if !strings.Contains(acl, "user:30001:rw-") || !strings.Contains(acl, "group:2000100:r--") {
		t.Fatalf("the ACL didn't travel:\n%s", acl)
	}
	if err := os.WriteFile("/mnt/"+ds+"/new.txt", []byte("x"), 0o600); err == nil {
		t.Fatal("the held copy on the storage pool was writable")
	}
	must("zfs", "unmount", ds)

	// Written after the final snapshot: this server's copy isn't parked.
	must("zfs", "set", "readonly=off", localPool+"/shares/media")
	must("zfs", "mount", localPool+"/shares/media")
	if err := os.WriteFile("/mnt/"+localPool+"/shares/media/late.txt", []byte("written after the final snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	must("zfs", "unmount", localPool+"/shares/media")
	must("zfs", "set", "readonly=on", localPool+"/shares/media")
	if _, err := compute.Park(ctx, ParkArgs{Ref: local, Confirm: "media", Conv: conv, Since: final, RefuseChanged: true}); !errors.Is(err, ErrChanged) {
		t.Fatalf("parked a copy written after its final snapshot: %v", err)
	}
	must("zfs", "rollback", localPool+"/shares/media@"+final)
	pr, err := compute.Park(ctx, ParkArgs{Ref: local, Confirm: "media", Conv: conv, Since: final, RefuseChanged: true})
	if err != nil {
		t.Fatal(err)
	}
	if released == 0 || changed == 0 {
		t.Fatal("file sharing wasn't told")
	}
	if _, err := sh("zfs", "list", localPool+"/shares/media"); err == nil {
		t.Fatal("still a shared folder after parking")
	}
	// Undo: put back as it was, its hold over, ACLs as they were.
	if _, err := compute.UnparkState(ctx, UnparkArgs{Ref: local, Name: pr.Name}); err != nil {
		t.Fatal(err)
	}
	got = strings.Fields(must("zfs", "get", "-H", "-o", "value", "readonly,mounted,"+propHAHold, localPool+"/shares/media"))
	if strings.Join(got, " ") != "off yes -" {
		t.Fatalf("put back %v", got)
	}
	if acl := must("getfacl", "-n", file); !strings.Contains(acl, "user:30001:rw-") {
		t.Fatalf("the ACL after putting back:\n%s", acl)
	}
	// The storage server's copy: only with its conversion's mark, and
	// never while compute servers mount it.
	if _, err := storage.Park(ctx, ParkArgs{Ref: clRef, Confirm: "media", Conv: conv + "x1"}); err == nil {
		t.Fatal("parked the storage server's shared folder without a mark")
	}
	busy = true
	if _, err := storage.Park(ctx, ParkArgs{Ref: clRef, Confirm: "media", Conv: conv + "x1", Expect: conv}); !errors.Is(err, ErrBusy) {
		t.Fatalf("parked while exported: %v", err)
	}
	busy = false
	if _, err := storage.Park(ctx, ParkArgs{Ref: clRef, Confirm: "media", Conv: conv + "x1", Expect: conv}); err != nil {
		t.Fatal(err)
	}
	if l, err := storage.ParkedList(ctx); err != nil || len(l) != 1 || l[0].Kind != KindShare || l[0].ID != "media" || l[0].Side != SideCluster {
		t.Fatalf("parked on the storage pool: %+v %v", l, err)
	}
}
