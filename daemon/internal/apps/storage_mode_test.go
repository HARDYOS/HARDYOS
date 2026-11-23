package apps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultStorageModeOfTheCatalog(t *testing.T) {
	want := map[string]string{
		"immich": StorageModeBlock, "paperless-ngx": StorageModeBlock, "apex-rmm": StorageModeBlock, // database servers
		"vaultwarden": StorageModeBlock, "jellyfin": StorageModeBlock, "home-assistant": StorageModeBlock, // SQLite, declared
		"qbittorrent": StorageModeNFS, "onlyoffice": StorageModeNFS,
	}
	dir := "../../../apps/catalog"
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Skip("catalog not found:", err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(dir, e.Name(), ManifestFile))
		if err != nil {
			continue
		}
		var m Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if err := m.Validate(); err != nil {
			t.Errorf("%s: %v", e.Name(), err)
		}
		compose, _ := os.ReadFile(filepath.Join(dir, e.Name(), ComposeFile))
		mode, reason := DefaultStorageMode(m, compose)
		if w, ok := want[e.Name()]; ok && mode != w {
			t.Errorf("%s: %s (%s), want %s", e.Name(), mode, reason, w)
		}
	}
}

func TestStorageHints(t *testing.T) {
	m := Manifest{Storage: &StorageHints{Mode: "nfs", Database: "sqlite"}}
	if mode, _ := DefaultStorageMode(m, nil); mode != StorageModeNFS {
		t.Fatal("an explicit mode wins")
	}
	if imgs := DatabaseImages([]byte("services:\n  db:\n    image: docker.io/library/postgres:18\n  app:\n    image: \"ghcr.io/x/app:1\"\n  r:\n    image: mariadb@sha256:abc\n")); len(imgs) != 2 {
		t.Fatalf("%v", imgs)
	}
	if imgs := DatabaseImages([]byte("image: ghcr.io/x/postgres-exporter:1\nimage: lscr.io/linuxserver/radarr\n")); len(imgs) != 0 {
		t.Fatalf("false positives %v", imgs)
	}
	var p Problems
	(&StorageHints{Mode: "iscsi", Database: "oracle", BlockSizeGB: -1}).validate(&p)
	if len(p) != 3 {
		t.Fatalf("%v", p)
	}
}
