package appstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/apps"
)

func TestCatalogAndUploads(t *testing.T) {
	catalog := t.TempDir()
	b, err := apps.Pack(filepath.Join("..", "..", "..", "apps", "catalog", "kincast"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(catalog, "kincast.hardyapp"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	// A broken file doesn't hide the rest.
	_ = os.WriteFile(filepath.Join(catalog, "broken.hardyapp"), []byte("nope"), 0o644)
	s := &Store{CatalogDir: catalog, UploadDir: filepath.Join(t.TempDir(), "up")}

	c, err := s.Catalog()
	if err != nil || len(c) != 1 {
		t.Fatalf("catalog: %v %+v", err, c)
	}
	e := c[0]
	want := map[string]bool{"postgres:16-alpine": true, "ghcr.io/hardynetworks/kintube:latest": true, "ghcr.io/hardynetworks/kintube-rtmp:latest": true}
	if len(e.Images) != 3 {
		t.Fatalf("images: %v", e.Images)
	}
	for _, img := range e.Images {
		if !want[img] {
			t.Errorf("image %q", img)
		}
	}
	// Generated secrets aren't asked for.
	for _, st := range e.Settings {
		if st.Env == "SESSION_SECRET" {
			t.Error("generated secret listed as a setting")
		}
	}
	if s.CatalogVersion("kincast") != "1.0.0" || s.CatalogVersion("nope") != "" {
		t.Error("catalog version")
	}

	up, err := s.Save(b)
	if err != nil || up.Source != SourceUpload || len(up.Ref) != 64 {
		t.Fatalf("save: %v %+v", err, up)
	}
	if p, err := s.Load(SourceUpload, up.Ref); err != nil || p.Manifest.ID != "kincast" {
		t.Fatalf("load upload: %v", err)
	}
	for _, bad := range [][2]string{{SourceUpload, "../../etc/passwd"}, {SourceCatalog, "../x"}, {"web", "kincast"}, {SourceUpload, up.Ref[:63] + "0"}} {
		if _, err := s.Load(bad[0], bad[1]); !errors.Is(err, ErrNotFound) {
			t.Errorf("Load(%q, %q) = %v", bad[0], bad[1], err)
		}
	}
	if _, err := s.Save([]byte("junk")); err == nil {
		t.Error("saved junk")
	}
}
