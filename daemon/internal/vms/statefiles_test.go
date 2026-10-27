package vms

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A VM's folder can come back from a backup: a link as its NVRAM or seed
// must never be handed to libvirt (decision 173).
func TestCheckStateFilesRefusesLinks(t *testing.T) {
	root := t.TempDir()
	m := &Manager{Root: root}
	st := &stored{dir: "/vm"}
	dir := filepath.Join(root, "vm")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := m.checkStateFiles(st); err != nil {
		t.Fatalf("empty folder: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "nvram.fd"), []byte("nv"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.checkStateFiles(st); err != nil {
		t.Fatalf("regular nvram: %v", err)
	}
	key := filepath.Join(root, "master.key")
	if err := os.WriteFile(key, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nvram.fd", seedFile} {
		p := filepath.Join(dir, name)
		_ = os.Remove(p)
		if err := os.Symlink(key, p); err != nil {
			t.Fatal(err)
		}
		if err := m.checkStateFiles(st); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Errorf("%s as a link: %v", name, err)
		}
		_ = os.Remove(p)
	}
	if err := os.Symlink(root, filepath.Join(dir, "tpm")); err != nil {
		t.Fatal(err)
	}
	if err := m.checkStateFiles(st); err == nil {
		t.Error("tpm as a link to a folder was accepted")
	}
}
