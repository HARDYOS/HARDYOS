//go:build linux

package shares

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func aclsWork(t *testing.T, dir string) bool {
	t.Helper()
	probe := filepath.Join(dir, ".probe")
	if err := os.WriteFile(probe, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(probe)
	return unix.Setxattr(probe, xattrAccess, aclFromMode(0o644).withUser(30001, 4).encode(), 0) == nil
}

func openPath(t *testing.T, p string) int {
	t.Helper()
	fd, err := unix.Open(p, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

func TestOpenRoot(t *testing.T) {
	d := t.TempDir()
	share := filepath.Join(d, "share")
	mkdir(t, share)
	os.Symlink(share, filepath.Join(d, "link"))
	dev := devOf(share)
	fd, err := OpenRoot(share, dev, unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
	for _, c := range []struct {
		p   string
		dev uint64
	}{{share, 0}, {share, dev + 1}, {filepath.Join(d, "link"), dev}, {share + "/", dev}, {"relative", dev}, {filepath.Join(d, "link", "."), dev}} {
		if fd, err := OpenRoot(c.p, c.dev, unix.O_RDONLY); err == nil {
			unix.Close(fd)
			t.Errorf("OpenRoot(%s, %d) opened", c.p, c.dev)
		}
	}
	if _, err := OpenRoot(share, 0, 0); !errors.Is(err, ErrUnverified) {
		t.Errorf("unverified = %v", err)
	}
}

func TestEnsureRecycle(t *testing.T) {
	share := t.TempDir()
	acls := aclsWork(t, share)
	if acls {
		// The share's default ACL would give its people every bin.
		def := aclFromMode(0o755).withUser(100513, 7)
		if err := unix.Setxattr(share, xattrDefault, def.encode(), 0); err != nil {
			t.Fatal(err)
		}
	}
	root := openPath(t, share)
	fixed, err := EnsureRecycle(root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(fixed, "made") || !slices.Contains(fixed, "mode") || acls != slices.Contains(fixed, "acl") {
		t.Errorf("fixed = %v", fixed)
	}
	rec := filepath.Join(share, RecycleDir)
	check := func() {
		t.Helper()
		var st unix.Stat_t
		if err := unix.Lstat(rec, &st); err != nil {
			t.Fatal(err)
		}
		if st.Mode&0o7777 != 0o1777 || st.Uid != uint32(os.Geteuid()) {
			t.Errorf(".recycle mode %o owner %d", st.Mode&0o7777, st.Uid)
		}
		if a := pathACL(t, rec, xattrAccess); a.hasNamed() {
			t.Errorf(".recycle access ACL %v", a)
		}
		if a := pathACL(t, rec, xattrDefault); a != nil {
			t.Errorf(".recycle default ACL %v", a)
		}
	}
	check()
	if fixed, err := EnsureRecycle(root); err != nil || len(fixed) != 0 {
		t.Errorf("second time = %v %v", fixed, err)
	}
	// Someone made it theirs and opened it up: fixed.
	os.Chmod(rec, 0o777)
	if acls {
		unix.Setxattr(rec, xattrDefault, aclFromMode(0o777).withUser(100900, 7).encode(), 0)
	}
	if os.Geteuid() == 0 {
		os.Chown(rec, 100900, 100513)
	}
	if fixed, err := EnsureRecycle(root); err != nil || !slices.Contains(fixed, "mode") || (os.Geteuid() == 0) != slices.Contains(fixed, "owner") {
		t.Errorf("repair = %v %v", fixed, err)
	}
	check()

	// A link or a file there is refused, never followed.
	outside := t.TempDir()
	os.Chmod(outside, 0o755)
	for _, plant := range []func(string) error{
		func(p string) error { return os.Symlink(outside, p) },
		func(p string) error { return os.WriteFile(p, nil, 0o644) },
	} {
		os.RemoveAll(rec)
		if err := plant(rec); err != nil {
			t.Fatal(err)
		}
		var be *BinError
		if _, err := EnsureRecycle(root); !errors.As(err, &be) {
			t.Errorf("planted .recycle = %v", err)
		}
	}
	if fi, _ := os.Stat(outside); fi.Mode().Perm() != 0o755 || fi.Mode()&os.ModeSticky != 0 {
		t.Errorf("the link's target was changed: %v", fi.Mode())
	}
}

func TestCheckBin(t *testing.T) {
	d := t.TempDir()
	acls := aclsWork(t, d)
	bin := filepath.Join(d, "home.alice")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	me := uint32(os.Geteuid())
	open := func() int {
		fd, err := unix.Open(bin, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		return fd
	}
	if owner, err := CheckBin(open(), me); err != nil || !owner {
		t.Fatalf("own 0700 bin = %v %v", owner, err)
	}
	if _, err := CheckBin(open(), me+1); err == nil {
		t.Error("someone else's bin accepted")
	}
	os.Chmod(bin, 0o770)
	if owner, err := CheckBin(open(), me); err == nil || !owner {
		t.Errorf("group-writable bin = %v %v", owner, err)
	}
	if acls {
		os.Chmod(bin, 0o700)
		unix.Setxattr(bin, xattrAccess, aclFromMode(0o700).withUser(100900, 7).encode(), 0)
		if _, err := CheckBin(open(), me); err == nil {
			t.Error("bin with an ACL entry for someone else accepted")
		}
	}
	if err := TightenBin(open()); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckBin(open(), me); err != nil {
		t.Errorf("after TightenBin = %v", err)
	}
}

// The walkers never enter .recycle or .zfs at the top: bins stay their
// owner's alone.
func TestWalkersSkipTheRecycleBin(t *testing.T) {
	share := t.TempDir()
	if !aclsWork(t, share) {
		t.Skip("no POSIX ACLs here")
	}
	for _, p := range []string{".recycle/home.alice/Photos", ".zfs/snapshot/x", "Photos/.recycle"} {
		mkdir(t, filepath.Join(share, p))
	}
	os.WriteFile(filepath.Join(share, ".recycle/home.alice/Photos/a.jpg"), []byte("x"), 0o600)
	os.Chmod(filepath.Join(share, ".recycle/home.alice"), 0o700)
	dev := devOf(share)
	if _, err := applyTree(context.Background(), share, dev, 30001, true, false); err != nil {
		t.Fatal(err)
	}
	p := PeopleACL{Entries: []PersonEntry{{Group: true, ID: 100513, Level: LevelWrite}}, Managed: func(bool, uint32) bool { return true }}
	if _, err := ApplyPeopleTree(context.Background(), share, dev, p); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{".recycle", ".recycle/home.alice", ".recycle/home.alice/Photos/a.jpg", ".zfs", ".zfs/snapshot/x"} {
		if a := pathACL(t, filepath.Join(share, rel), xattrAccess); a.hasNamed() {
			t.Errorf("%s was given ACL entries: %v", rel, a)
		}
	}
	// A .recycle further down is an ordinary folder.
	if a := pathACL(t, filepath.Join(share, "Photos/.recycle"), xattrAccess); !a.hasNamed() {
		t.Errorf("Photos/.recycle wasn't walked: %v", a)
	}
}
