package rootfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	_ = os.WriteFile(p, []byte("{}"), 0o644)
	Enforce = true
	defer func() { Enforce = false }()
	if os.Geteuid() != 0 {
		if err := Check(p); !errors.Is(err, ErrNotTrusted) {
			t.Fatalf("file owned by a normal user trusted: %v", err)
		}
		return
	}
	if err := Check(p); err != nil {
		t.Fatalf("root-owned 0644: %v", err)
	}
	_ = os.Chmod(p, 0o666)
	if err := Check(p); !errors.Is(err, ErrNotTrusted) {
		t.Fatalf("world-writable trusted: %v", err)
	}
	_ = os.Chmod(p, 0o644)
	_ = os.Chown(p, 1000, 1000)
	if err := Check(p); !errors.Is(err, ErrNotTrusted) {
		t.Fatalf("other owner trusted: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	_ = os.Symlink("/etc/hostname", link)
	if err := Check(link); !errors.Is(err, ErrNotTrusted) {
		t.Fatalf("symlink trusted: %v", err)
	}
	if _, err := ReadFile(filepath.Join(dir, "missing")); !IsNotExist(err) {
		t.Fatalf("missing: %v", err)
	}
}
