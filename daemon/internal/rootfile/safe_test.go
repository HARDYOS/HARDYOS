package rootfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A planted "<path>.tmp" symlink (what the old writer used) and a symlink
// at the path itself must never be followed: the files they point to stay
// as they were.
func TestWriteAtomicNeverFollowsPlantedLinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("precious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(state, "kernel-args.json")
	_ = os.Symlink(victim, p+".tmp")
	if err := WriteAtomic(p, []byte(`{"args":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious\n" {
		t.Fatalf("victim rewritten through the .tmp link: %q", b)
	}
	// Now a symlink at the target itself: replaced, not followed.
	_ = os.Remove(p)
	_ = os.Symlink(victim, p)
	if err := WriteAtomic(p, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious\n" {
		t.Fatalf("victim rewritten through the target link: %q", b)
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
		t.Fatalf("target = %v %v", fi, err)
	}
	// No temporary files are left behind.
	entries, _ := os.ReadDir(state)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("left %s", e.Name())
		}
	}
}

// A directory in the path that someone else could have replaced with a
// symlink (here: in a world-writable directory) isn't followed.
func TestWriteAtomicRefusesSymlinkedParent(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	_ = os.Symlink(elsewhere, filepath.Join(dir, "apps"))
	err := WriteAtomic(filepath.Join(dir, "apps", "engine.json"), []byte("{}"), 0o600)
	if !errors.Is(err, ErrNotTrusted) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(elsewhere, "engine.json")); err == nil {
		t.Fatal("wrote through the symlinked directory")
	}
}

func TestReadFileRefusesLinksAndForeignFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "boot.json")
	if err := WriteAtomic(p, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	Enforce = true
	defer func() { Enforce = false }()
	link := filepath.Join(dir, "link.json")
	_ = os.Symlink(p, link)
	if _, err := ReadFile(link); !errors.Is(err, ErrNotTrusted) {
		t.Fatalf("symlink read: %v", err)
	}
	if _, err := ReadFile(filepath.Join(dir, "missing")); !IsNotExist(err) {
		t.Fatalf("missing: %v", err)
	}
	if os.Geteuid() != 0 {
		if _, err := ReadFile(p); !errors.Is(err, ErrNotTrusted) {
			t.Fatalf("a normal user's file trusted: %v", err)
		}
		return
	}
	if b, err := ReadFile(p); err != nil || string(b) != "{}" {
		t.Fatalf("root's file: %q %v", b, err)
	}
	// A second name (a hard link someone made) makes it untrusted.
	hard := filepath.Join(dir, "hard.json")
	if err := os.Link(p, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(hard); !errors.Is(err, ErrNotTrusted) {
		t.Fatalf("hard link trusted: %v", err)
	}
}

func TestRootDir(t *testing.T) {
	base := t.TempDir()
	d := filepath.Join(base, "root")
	if err := WriteInRootDir(filepath.Join(d, "kernel-args.json"), []byte(`{}`), 0o644, 0o755); err != nil {
		t.Fatal(err)
	}
	if b, err := ReadFileInRootDir(filepath.Join(d, "kernel-args.json")); err != nil || string(b) != "{}" {
		t.Fatalf("read: %q %v", b, err)
	}
	if err := CreateExclusive(filepath.Join(d, "kernel-args.json"), []byte("x"), 0o600, 0o755); err == nil {
		t.Fatal("CreateExclusive replaced an existing file")
	}
	if os.Geteuid() != 0 {
		return
	}
	// As root: a directory that isn't root's is moved aside and replaced,
	// and files in one aren't trusted.
	Enforce = true
	defer func() { Enforce = false }()
	if err := os.Chown(d, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileInRootDir(filepath.Join(d, "kernel-args.json")); !errors.Is(err, ErrNotTrusted) {
		t.Fatalf("file in a foreign directory trusted: %v", err)
	}
	if err := EnsureRootDir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(d)
	if fi == nil || !fi.IsDir() {
		t.Fatal("no fresh directory")
	}
	if _, err := os.Stat(filepath.Join(d, "kernel-args.json")); err == nil {
		t.Fatal("the foreign directory's content is still in place")
	}
	matches, _ := filepath.Glob(d + ".untrusted-*")
	if len(matches) != 1 {
		t.Fatalf("moved aside: %v", matches)
	}
	// A symlink in place of the directory is moved aside too.
	_ = os.RemoveAll(d)
	_ = os.Symlink(t.TempDir(), d)
	if err := EnsureRootDir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(d); fi == nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("symlink kept")
	}
}
