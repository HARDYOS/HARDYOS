package shares

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestGrantReadFD(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "disc.iso")
	if err := os.WriteFile(p, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := GrantReadFD(int(f.Fd()), 64055); err != nil {
		if errors.Is(err, unix.EOPNOTSUPP) {
			t.Skip("no POSIX ACLs on this file system")
		}
		t.Fatal(err)
	}
	a, err := getACL(int(f.Fd()), xattrAccess)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range a {
		if e.Tag == tagUser && e.ID == 64055 && e.Perm == permR {
			found = true
		}
	}
	if !found {
		t.Fatalf("acl = %+v", a)
	}
	// Twice is the same.
	if err := GrantReadFD(int(f.Fd()), 64055); err != nil {
		t.Fatal(err)
	}
	d, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := GrantReadFD(int(d.Fd()), 64055); err != nil {
		t.Fatal(err)
	}
	a, _ = getACL(int(d.Fd()), xattrAccess)
	for _, e := range a {
		if e.Tag == tagUser && e.ID == 64055 && e.Perm != permR|permX {
			t.Fatalf("folder entry = %+v", e)
		}
	}
	// Not for devices, sockets and the like.
	null, err := os.Open("/dev/null")
	if err == nil {
		defer null.Close()
		if GrantReadFD(int(null.Fd()), 64055) == nil {
			t.Fatal("granted a device")
		}
	}
}
