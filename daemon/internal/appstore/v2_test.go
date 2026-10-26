package appstore

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func TestPrincipals(t *testing.T) {
	list, err := NormalizePrincipals([]Principal{
		{Kind: "group", Name: `HOME\Family`}, {Kind: "user", Name: " Alice "}, {Kind: "user", Name: `HOME\bob`}, {Kind: "user", Name: "alice"},
	})
	if err != nil || len(list) != 3 || list[0].Name != "alice" || list[1].Name != `HOME\bob` || list[2].Kind != "group" {
		t.Fatalf("normalize: %v %+v", err, list)
	}
	if l, _ := NormalizePrincipals([]Principal{{Kind: "user", Name: "alice"}, {Kind: "everyone", Name: "x"}}); len(l) != 1 || l[0] != (Principal{Kind: "everyone"}) {
		t.Fatalf("everyone: %+v", l)
	}
	for _, bad := range []Principal{{Kind: "group", Name: "Family"}, {Kind: "user", Name: "x"}, {Kind: "user", Name: `HOME\a/b`}, {Kind: "role", Name: "a"}, {Kind: "user", Name: `TOOLONGDOMAINNAME1\a`}} {
		if _, err := NormalizePrincipals([]Principal{bad}); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	rules := []Principal{{Kind: "user", Name: "alice"}, {Kind: "group", Name: `HOME\Family`}}
	for who, want := range map[*Who]bool{
		{Username: "alice"}: true,
		{Username: "bob"}:   false,
		{Username: `HOME\bob`, Groups: []string{`home\family`}}:   true,
		{Username: `HOME\carol`, Groups: []string{`HOME\Guests`}}: false,
		{Username: "carol", Admin: true}:                          true,
	} {
		if MayUse(rules, *who) != want {
			t.Errorf("MayUse(%+v) != %v", who, want)
		}
	}
	if !MayUse(nil, Who{Username: "anyone"}) {
		t.Error("no rules should mean everyone")
	}
}

func TestParseIndex(t *testing.T) {
	base, _ := url.Parse("https://apps.example.net/hardy/index.json")
	sha := strings.Repeat("ab", 32)
	idx, skipped, err := ParseIndex([]byte(`{"name":" Example ","apps":[
	  {"id":"good","name":"Good","version":"1.2.3","summary":"ok","url":"good.hardyapp","sha256":"`+strings.ToUpper(sha)+`","icon":"data:image/png;base64,iVBORw0K"},
	  {"id":"good","name":"Again","version":"1","summary":"","url":"x","sha256":"`+sha+`"},
	  {"id":"Bad_ID","name":"x","version":"1","url":"x","sha256":"`+sha+`"},
	  {"id":"plain","name":"Plain","version":"1","url":"http://evil.example/p","sha256":"`+sha+`"},
	  {"id":"short","name":"Short","version":"1","url":"s","sha256":"abc"}]}`), base)
	if err != nil || idx.Name != "Example" || len(idx.Apps) != 1 || len(skipped) != 4 {
		t.Fatalf("index: %v %+v %v", err, idx, skipped)
	}
	if a := idx.Apps[0]; a.URL != "https://apps.example.net/hardy/good.hardyapp" || a.SHA256 != sha || a.Icon == "" {
		t.Fatalf("app: %+v", a)
	}
	for _, bad := range []string{`nope`, `{"name":"","apps":[]}`, `{"name":"HardyOS","apps":[]}`} {
		if _, _, err := ParseIndex([]byte(bad), base); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := CheckCatalogURL("https://user:pw@example.com/i.json"); err == nil {
		t.Error("accepted a URL with a password")
	}
}

func TestRecordsTravelInBackups(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Store{DB: db}
	if err := s.SetAccess(ctx, "jellyfin", []Principal{{Kind: "user", Name: "kid"}, {Kind: "group", Name: `HOME\Family`}}); err != nil {
		t.Fatal(err)
	}
	p1, err := s.AllocateProxyPort(ctx, "jellyfin", 44300, nil)
	if err != nil || p1 != 44300 {
		t.Fatalf("port: %v %d", err, p1)
	}
	if p, _ := s.AllocateProxyPort(ctx, "immich", 44300, map[int]bool{44301: true}); p != 44302 {
		t.Fatalf("second port %d", p)
	}
	if p, _ := s.AllocateProxyPort(ctx, "jellyfin", 44300, map[int]bool{44300: true}); p != 44301 {
		t.Fatalf("moved port %d", p)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO app_catalogs (url, name, added_at, index_json) VALUES ('https://x/i.json', 'X', ?, '{"name":"X","apps":[{"id":"a","name":"A","version":"1","sha256":"`+strings.Repeat("c", 64)+`"}]}')`, store.Now()); err != nil {
		t.Fatal(err)
	}

	// A settings backup is a snapshot of hardyd's database.
	snap := filepath.Join(t.TempDir(), "backup.db")
	if err := db.Snapshot(ctx, snap); err != nil {
		t.Fatal(err)
	}
	restored, err := store.Open(ctx, snap)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	r := &Store{DB: restored}
	if l, _ := r.Access(ctx, "jellyfin"); len(l) != 2 {
		t.Errorf("access after restore: %+v", l)
	}
	if p, _ := r.ProxyPorts(ctx); p["jellyfin"] != 44301 || p["immich"] != 44302 {
		t.Errorf("ports after restore: %v", p)
	}
	if c, _ := r.Catalogs(ctx); len(c) != 1 || len(c[0].Apps) != 1 {
		t.Errorf("catalogs after restore: %+v", c)
	}
	v, sha, cid := r.ImportedLatest(ctx, "X", "a")
	if v != "1" || sha == "" || cid == 0 {
		t.Errorf("imported latest: %q %q %d", v, sha, cid)
	}
	if v2, sha2 := r.ImportedLatestIn(ctx, cid, "a"); v2 != v || sha2 != sha {
		t.Errorf("imported latest by id: %q %q", v2, sha2)
	}
	if v2, _ := r.ImportedLatestIn(ctx, cid+1, "a"); v2 != "" {
		t.Error("another catalog id lists it")
	}
	if err := r.SetOrigin(ctx, Origin{AppID: "jellyfin", Source: SourceImported, CatalogID: cid, CatalogName: "X", Ref: sha}); err != nil {
		t.Fatal(err)
	}
	if o := r.OriginOf(ctx, "jellyfin"); o == nil || o.CatalogID != cid || o.CatalogName != "X" {
		t.Errorf("origin: %+v", o)
	}
	if err := r.ForgetApp(ctx, "jellyfin"); err != nil {
		t.Fatal(err)
	}
	if l, _ := r.Access(ctx, "jellyfin"); len(l) != 0 {
		t.Error("forget kept access")
	}
	if r.OriginOf(ctx, "jellyfin") != nil {
		t.Error("forget kept the origin")
	}
}

// customRaw reads a built custom package's bytes.
func customRaw(t *testing.T, s *Store, ref string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.customDir(), ref+".hardyapp"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBuildCustom(t *testing.T) {
	s := &Store{UploadDir: t.TempDir()}
	e, err := s.BuildCustom(CustomApp{ID: "whoami", Name: "who am I", Compose: "services:\n  web:\n    image: traefik/whoami\n    ports: [\"${HARDY_PORT_WEB}:80\"]\n",
		Ports: []apps.Port{{Name: "WEB", Label: "Website", Default: 8400}}, WebPort: "WEB"})
	if err != nil || e.Source != SourceCustom || e.Version != "1.0.0" || !e.Ports[0].Web {
		t.Fatalf("custom: %v %+v", err, e)
	}
	p, err := s.Load(SourceCustom, e.Ref)
	if err != nil || p.Manifest.Publisher == "" || !strings.Contains(string(p.Icon), ">W<") {
		t.Fatalf("load: %v %+v", err, p)
	}
	// The same input builds the same package.
	if e2, _ := s.BuildCustom(CustomApp{ID: "whoami", Name: "who am I", Compose: "services:\n  web:\n    image: traefik/whoami\n    ports: [\"${HARDY_PORT_WEB}:80\"]\n",
		Ports: []apps.Port{{Name: "WEB", Label: "Website", Default: 8400}}, WebPort: "WEB"}); e2 == nil || e2.Ref != e.Ref {
		t.Error("not reproducible")
	}
	// A custom package isn't an upload, and an upload isn't custom: each is
	// only found under the source it was saved as.
	if _, err := s.Load(SourceUpload, e.Ref); err == nil {
		t.Error("the custom package loads as an upload")
	}
	up, err := s.Save(customRaw(t, s, e.Ref))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(SourceCustom, up.Ref); err != nil {
		t.Errorf("same bytes saved as custom: %v", err) // built as custom, so it's there
	}
	if err := os.Remove(filepath.Join(s.customDir(), e.Ref+".hardyapp")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(SourceCustom, up.Ref); err == nil {
		t.Error("an uploaded package loads as custom")
	}
	if _, err := s.Load(SourceUpload, up.Ref); err != nil {
		t.Errorf("upload: %v", err)
	}
	_, err = s.BuildCustom(CustomApp{ID: "Bad", Name: "", Compose: "image: x", WebPort: "WEB"})
	if p, ok := err.(apps.Problems); !ok || len(p) < 3 {
		t.Fatalf("bad custom: %v", err)
	}
}
