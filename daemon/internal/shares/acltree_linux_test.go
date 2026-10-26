//go:build linux

package shares

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func pathACL(t *testing.T, p, attr string) acl {
	t.Helper()
	buf := make([]byte, 1024)
	n, err := unix.Lgetxattr(p, attr, buf)
	if errors.Is(err, unix.ENODATA) {
		return nil
	}
	if err != nil {
		t.Fatalf("%s %s: %v", p, attr, err)
	}
	a, err := decodeACL(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func userPerm(a acl, uid uint32) (uint16, bool) {
	for _, e := range a {
		if e.Tag == tagUser && e.ID == uid {
			return e.Perm, true
		}
	}
	return 0, false
}

// TestApplyTree runs the walker on the test machine's own file system
// (skipped where it has no POSIX ACLs).
func TestApplyTree(t *testing.T) {
	root := t.TempDir()
	probe := filepath.Join(root, "probe")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(probe, xattrAccess, aclFromMode(0o644).withUser(30001, 4).encode(), 0); err != nil {
		t.Skipf("no POSIX ACLs here: %v", err)
	}
	os.Remove(probe)

	share := filepath.Join(root, "share")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{share + "/Movies/Kids", outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]os.FileMode{share + "/Movies/film.mkv": 0o644, share + "/Movies/Kids/run.sh": 0o755, outside + "/secret": 0o600}
	for p, mode := range files {
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, share+"/Movies/link"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside+"/secret", share+"/secret-link"); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(share+"/pipe", 0o644); err != nil {
		t.Fatal(err)
	}

	st, err := applyTree(context.Background(), share, 30001, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Failed != 0 || st.Seen != 4 || st.Changed != 4 || st.Skipped != 3 {
		t.Errorf("stats = %+v", st)
	}
	for p, want := range map[string]uint16{share + "/Movies": 7, share + "/Movies/Kids": 7, share + "/Movies/film.mkv": 6, share + "/Movies/Kids/run.sh": 7} {
		if got, ok := userPerm(pathACL(t, p, xattrAccess), 30001); !ok || got != want {
			t.Errorf("%s: access perm %o %v, want %o", p, got, ok, want)
		}
	}
	for _, d := range []string{share + "/Movies", share + "/Movies/Kids"} {
		if got, ok := userPerm(pathACL(t, d, xattrDefault), 30001); !ok || got != 7 {
			t.Errorf("%s: default perm %o %v", d, got, ok)
		}
	}
	if pathACL(t, share+"/Movies/film.mkv", xattrDefault) != nil {
		t.Error("a file got a default ACL")
	}
	// Nothing behind a link changed, and the root is the caller's job.
	for _, p := range []string{outside, outside + "/secret", share} {
		if a := pathACL(t, p, xattrAccess); a != nil {
			t.Errorf("%s was changed: %+v", p, a)
		}
	}
	// The file mode's group bits now show the mask.
	if fi, _ := os.Stat(share + "/Movies/film.mkv"); fi.Mode().Perm() != 0o664 {
		t.Errorf("film mode = %v", fi.Mode().Perm())
	}

	// Running again changes nothing; read-only lowers it.
	if st, _ := applyTree(context.Background(), share, 30001, true, false); st.Changed != 0 {
		t.Errorf("second run changed %d", st.Changed)
	}
	if _, err := applyTree(context.Background(), share, 30001, false, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := userPerm(pathACL(t, share+"/Movies/film.mkv", xattrAccess), 30001); got != 4 {
		t.Errorf("read-only perm = %o", got)
	}

	// Revoking puts everything back as it was.
	if _, err := applyTree(context.Background(), share, 30001, false, true); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{share + "/Movies", share + "/Movies/Kids", share + "/Movies/film.mkv"} {
		if a := pathACL(t, p, xattrAccess); a != nil {
			t.Errorf("%s still has an ACL: %+v", p, a)
		}
		if a := pathACL(t, p, xattrDefault); a != nil {
			t.Errorf("%s still has a default ACL: %+v", p, a)
		}
	}
	if fi, _ := os.Stat(share + "/Movies/film.mkv"); fi.Mode().Perm() != 0o644 {
		t.Errorf("film mode after revoke = %v", fi.Mode().Perm())
	}

	// A cancelled walk stops.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := applyTree(ctx, share, 30001, true, false); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled walk: %v", err)
	}
}
