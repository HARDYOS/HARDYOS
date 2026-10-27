package boot

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// hardyd owns /var/lib/hardyos: a link it plants where root used to put
// its temporary file must never be followed (the security review's
// kernel-args.json.tmp -> /etc/shadow).
func TestRootStateWritesIgnorePlantedLinks(t *testing.T) {
	root := t.TempDir()
	env := Env{Root: root}
	victim := filepath.Join(root, "etc/shadow")
	_ = os.MkdirAll(filepath.Dir(victim), 0o755)
	_ = os.WriteFile(victim, []byte("root:x:\n"), 0o600)
	_ = os.MkdirAll(filepath.Join(root, "var/lib/hardyos/root"), 0o755)
	for _, p := range []string{KernelArgsPath, LegacyKernelArgsPath, ConfigPath} {
		_ = os.Symlink(victim, filepath.Join(root, p)+".tmp")
	}
	if err := SaveKernelArgs(env, []string{"iommu=pt"}); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{Pool: "rpool", Disks: []Disk{{ByID: "/dev/disk/by-id/a", ESPPartUUID: "11111111-aaaa-bbbb-cccc-000000000001"}}}
	if err := cfg.Save(filepath.Join(root, ConfigPath)); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "root:x:\n" {
		t.Fatalf("victim changed: %q", b)
	}
	if args, err := LoadKernelArgs(env); err != nil || len(args) != 1 {
		t.Fatalf("load = %v %v", args, err)
	}
}

func TestMigrateRootState(t *testing.T) {
	root := t.TempDir()
	env := Env{Root: root}
	legacy := filepath.Join(root, LegacyKernelArgsPath)
	_ = os.MkdirAll(filepath.Dir(legacy), 0o755)
	_ = os.WriteFile(legacy, []byte(`{"args":["intel_iommu=on","iommu=pt"]}`), 0o644)
	// Read from the old place until migrated.
	if args, err := LoadKernelArgs(env); err != nil || len(args) != 2 {
		t.Fatalf("legacy load = %v %v", args, err)
	}
	if err := MigrateRootState(env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("legacy file kept")
	}
	if args, err := LoadKernelArgs(env); err != nil || !reflect.DeepEqual(args, []string{"intel_iommu=on", "iommu=pt"}) {
		t.Fatalf("load = %v %v", args, err)
	}
	if err := MigrateRootState(env); err != nil { // nothing left to do
		t.Fatal(err)
	}
}
