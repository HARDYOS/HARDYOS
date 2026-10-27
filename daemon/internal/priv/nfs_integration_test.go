package priv

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/nfs"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// TestNFSIntegration shares folders on a file-backed ZFS pool with the real
// NFS server and mounts them over loopback: clients are squashed to the
// folder's own NFS identity, which the ACLs let in; read-only clients
// can't write, and the most specific rule wins. It writes
// /etc/exports.d/hardyos.exports and starts nfs-server, so it only runs on
// a throwaway machine: HARDYOS_ZFS_INTEGRATION=1 and HARDYOS_NFS_INTEGRATION=1
// (CI's "NFS (loopback)" job), as root.
func TestNFSIntegration(t *testing.T) {
	if os.Getenv("HARDYOS_ZFS_INTEGRATION") != "1" || os.Getenv("HARDYOS_NFS_INTEGRATION") != "1" {
		t.Skip("set HARDYOS_ZFS_INTEGRATION=1 and HARDYOS_NFS_INTEGRATION=1 to run against real ZFS and NFS (needs root, changes the NFS server)")
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
	const pool = "hardyosnfs"
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	_ = exec.Command("zpool", "destroy", "-f", pool).Run()
	// A short mountpoint without the temp dir's odd characters.
	mnt := "/mnt/" + pool
	run("zpool", "create", "-o", "ashift=12", "-m", mnt, "-O", "xattr=sa", "-O", "acltype=posixacl", pool, vdev)

	shm := &shares.Manager{Runner: sysexec.Exec{}, Root: "/"}
	nm := &nfs.Manager{Runner: sysexec.Exec{}, Shares: shm, Root: "/"}
	var mounts []string
	t.Cleanup(func() {
		for _, m := range mounts {
			_ = exec.Command("umount", "-f", m).Run()
		}
		_ = os.Remove(nfs.ExportsFile)
		_ = exec.Command("exportfs", "-ra").Run()
		_ = exec.Command("systemctl", "disable", "--now", nfs.Unit).Run()
		shm.Wait()
		_ = exec.Command("zpool", "destroy", "-f", pool).Run()
	})

	svc := func(clients ...shares.NFSRule) *shares.Services {
		s := shares.DefaultServices()
		s.NFS = shares.NFS{Enabled: true, Clients: clients}
		return &s
	}
	rw, err := shm.Create(ctx, shares.NewShare{Pool: pool, Name: "Projects", Services: svc(shares.NFSRule{Client: "127.0.0.0/8", Access: "write"})})
	if err != nil {
		t.Fatal(err)
	}
	// 127.0.0.1 is in the write network, but its own rule says read.
	ro, err := shm.Create(ctx, shares.NewShare{Pool: pool, Name: "Library", Services: svc(
		shares.NFSRule{Client: "127.0.0.0/8", Access: "write"}, shares.NFSRule{Client: "127.0.0.1", Access: "read"})})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ro.Path, "book.txt"), []byte("chapter one"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := nm.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	shm.Wait()
	st := nm.Status(ctx)
	uidRW, uidRO := st.UIDs[rw.ID], st.UIDs[ro.ID]
	if uidRW < shares.FirstNFSUID || uidRO < shares.FirstNFSUID || uidRW == uidRO {
		t.Fatalf("identities = %v", st.UIDs)
	}
	if got := strings.TrimSpace(run("zfs", "get", "-H", "-o", "value", shares.PropNFSUID, rw.Dataset)); got != strconv.Itoa(uidRW) {
		t.Errorf("%s = %q", shares.PropNFSUID, got)
	}
	b, _ := os.ReadFile(nfs.ExportsFile)
	t.Logf("exports:\n%s", b)

	// Wait for the server (started without blocking).
	deadline := time.Now().Add(90 * time.Second)
	for exec.Command("systemctl", "is-active", "--quiet", nfs.Unit).Run() != nil {
		if time.Now().After(deadline) {
			t.Fatalf("nfs-server didn't start:\n%s", run("systemctl", "status", "--no-pager", nfs.Unit))
		}
		time.Sleep(time.Second)
	}
	_ = exec.Command("exportfs", "-ra").Run()
	t.Logf("exportfs -v:\n%s", run("exportfs", "-v"))

	mount := func(path, vers string) string {
		t.Helper()
		target := filepath.Join(dir, "client-"+filepath.Base(path)+"-"+vers)
		if err := os.MkdirAll(target, 0o755); err != nil {
			t.Fatal(err)
		}
		run("mount", "-t", "nfs", "-o", "nfsvers="+vers+",proto=tcp", "127.0.0.1:"+path, target)
		mounts = append(mounts, target)
		return target
	}
	for _, vers := range []string{"3", "4"} {
		c := mount(rw.Path, vers)
		// Root on the client is squashed to the folder's identity, which the
		// ACL lets write.
		p := filepath.Join(c, "made-over-nfs-v"+vers)
		if err := os.WriteFile(p, []byte("hi"), 0o644); err != nil {
			t.Fatalf("v%s write: %v", vers, err)
		}
		var sst syscall.Stat_t
		if err := syscall.Stat(filepath.Join(rw.Path, "made-over-nfs-v"+vers), &sst); err != nil {
			t.Fatal(err)
		}
		if int(sst.Uid) != uidRW || int(sst.Gid) != uidRW {
			t.Errorf("v%s: a file written as root is owned by %d:%d, want %d", vers, sst.Uid, sst.Gid, uidRW)
		}

		c = mount(ro.Path, vers)
		if b, err := os.ReadFile(filepath.Join(c, "book.txt")); err != nil || string(b) != "chapter one" {
			t.Errorf("v%s read = %q %v", vers, b, err)
		}
		err := os.WriteFile(filepath.Join(c, "graffiti"), []byte("x"), 0o644)
		if err == nil {
			t.Errorf("v%s: wrote to a folder 127.0.0.1 may only read", vers)
		} else if !errors.Is(err, syscall.EROFS) && !errors.Is(err, syscall.EACCES) {
			t.Logf("v%s: write refused with %v", vers, err)
		}
	}

	// Turning NFS off removes the export and the identity's access.
	off := shares.DefaultServices()
	if _, err := shm.Update(ctx, shares.ShareUpdate{ID: rw.ID, Services: &off}); err != nil {
		t.Fatal(err)
	}
	if err := nm.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	shm.Wait()
	if b, _ := os.ReadFile(nfs.ExportsFile); strings.Contains(string(b), rw.Path) {
		t.Errorf("still exported:\n%s", b)
	}
	if a := run("getfacl", "-n", "-p", "--omit-header", rw.Path); strings.Contains(a, strconv.Itoa(uidRW)) {
		t.Errorf("the identity keeps access:\n%s", a)
	}
}
