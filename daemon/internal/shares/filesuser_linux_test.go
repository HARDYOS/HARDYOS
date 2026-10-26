//go:build linux

package shares

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"golang.org/x/sys/unix"
)

func TestEnsureFilesUser(t *testing.T) {
	m, f, root, calls := newManager(t)
	media := filepath.Join(root, "mnt/tank/shares/media")
	done := filepath.Join(root, "mnt/tank/shares/done")
	mkdir(t, media)
	mkdir(t, done)
	f.On(listAll, rows(
		row{ds: "tank/shares/media", name: "Media", mounted: true},
		row{ds: "tank/shares/done", name: "Done", mounted: true},
		row{ds: "tank/shares/offline", name: "Offline", mounted: false},
	))
	f.OnPrefix("setfacl ", sysexec.Result{})

	// "done" already gives hardyos-files rwx (if this file system keeps ACLs).
	full := aclFromMode(0o755).withUser(FilesUID, permR|permW|permX)
	acls := unix.Setxattr(done, xattrAccess, full.encode(), 0) == nil &&
		unix.Setxattr(done, xattrDefault, full.encode(), 0) == nil

	if err := m.EnsureFilesUser(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	lines := f.Lines()
	if !slices.Contains(lines, "setfacl -m u:29999:rwX,d:u:29999:rwX -- "+media) {
		t.Fatalf("media not granted: %v", lines)
	}
	if got := slices.Contains(lines, "setfacl -m u:29999:rwX,d:u:29999:rwX -- "+done); got == acls {
		t.Errorf("done granted again = %v (ACLs on this file system: %v)", got, acls)
	}
	found := false
	for _, c := range *calls {
		if c.root == media && c.uid == FilesUID && c.write && !c.revoke {
			found = true
		}
		if c.root != media && c.root != done {
			t.Errorf("walked %s", c.root)
		}
	}
	if !found {
		t.Errorf("no background walk for media: %v", *calls)
	}
}
