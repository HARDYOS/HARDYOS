package apps

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// State files come from datasets HardyOS may not have written (a restore
// from another server): no links anywhere, no FIFOs, a size cap.
func TestReadStateFile(t *testing.T) {
	dir := t.TempDir()
	meta := filepath.Join(dir, "app", ".hardyos")
	if err := os.MkdirAll(meta, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "state.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := readStateFile(filepath.Join(meta, "state.json")); err != nil || string(b) != "{}" {
		t.Fatal(string(b), err)
	}
	if _, err := readStateFile(filepath.Join(meta, "missing.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	// A link as the folder or as the file.
	secret := filepath.Join(dir, "secret")
	_ = os.MkdirAll(secret, 0o700)
	_ = os.WriteFile(filepath.Join(secret, "state.json"), []byte("secret"), 0o600)
	evil := filepath.Join(dir, "evil")
	_ = os.MkdirAll(evil, 0o700)
	_ = os.Symlink(secret, filepath.Join(evil, ".hardyos"))
	if _, err := readStateFile(filepath.Join(evil, ".hardyos", "state.json")); err == nil {
		t.Fatal("followed a linked folder")
	}
	_ = os.Symlink(filepath.Join(secret, "state.json"), filepath.Join(meta, "manifest.json"))
	if _, err := readStateFile(filepath.Join(meta, "manifest.json")); err == nil {
		t.Fatal("followed a linked file")
	}
	// A FIFO doesn't hang the reader.
	fifo := filepath.Join(meta, "app.env")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readStateFile(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read a FIFO")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a FIFO hung the reader")
	}
	big := filepath.Join(meta, "compose.json")
	if err := os.WriteFile(big, []byte(strings.Repeat("x", MaxStateFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStateFile(big); err == nil {
		t.Fatal("read a file over the cap")
	}
}
