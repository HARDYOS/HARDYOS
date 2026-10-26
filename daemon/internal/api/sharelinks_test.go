package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sharelinks"
	"github.com/hardyos/hardyos/daemon/internal/sharelinks/linktest"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

type linkEnv struct {
	srv  *httptest.Server
	db   *store.DB
	fake *linktest.Fake
}

func newLinkEnv(t *testing.T, withFiles bool) *linkEnv {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	fake := linktest.New(t.TempDir(), "media", "backups")
	cfg := Config{DB: db, Insecure: true}
	if withFiles {
		cfg.Files = fake
	}
	srv := httptest.NewServer(New(cfg))
	t.Cleanup(func() {
		srv.Close()
		db.Close()
	})
	return &linkEnv{srv: srv, db: db, fake: fake}
}

func (e *linkEnv) signIn(t *testing.T, admin *client, name string) *client {
	t.Helper()
	if code := admin.do("POST", "/api/v1/users", map[string]string{"username": name, "password": name + "password1"}, nil); code != 201 {
		t.Fatalf("create %s = %d", name, code)
	}
	c := &client{t: t, base: e.srv.URL, http: (&testEnv{srv: e.srv}).client(t).http}
	if code := c.do("POST", "/api/v1/auth/login", map[string]string{"username": name, "password": name + "password1"}, nil); code != 200 {
		t.Fatalf("login %s = %d", name, code)
	}
	return c
}

func TestShareLinksAPI(t *testing.T) {
	e := newLinkEnv(t, true)
	admin := (&testEnv{srv: e.srv}).client(t)
	if code := admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil); code != 201 {
		t.Fatalf("setup = %d", code)
	}
	kid := e.signIn(t, admin, "kid")
	mom := e.signIn(t, admin, "mom")
	e.fake.Grant("media", "kid", "read")
	e.fake.Grant("media", "mom", "write")
	e.fake.Write("media", "Photos/beach.jpg", "JPEG")

	// Signed out: no API.
	anon := (&testEnv{srv: e.srv}).client(t)
	if code := anon.do("GET", "/api/v1/sharelinks", nil, nil); code != 401 {
		t.Fatalf("anonymous list = %d", code)
	}

	// Read access isn't enough to share; no access looks like no access.
	var er ErrorResponse
	if code := kid.do("POST", "/api/v1/sharelinks", map[string]any{"share": "media", "path": "Photos"}, &er); code != 403 || !strings.Contains(er.Message, "can change") {
		t.Fatalf("read-only share = %d %v", code, er)
	}
	if code := kid.do("POST", "/api/v1/sharelinks", map[string]any{"share": "backups", "path": ""}, nil); code != 403 {
		t.Fatalf("no access = %d", code)
	}
	if code := mom.do("POST", "/api/v1/sharelinks", map[string]any{"share": "media", "path": "nope"}, nil); code != 404 {
		t.Fatalf("missing path = %d", code)
	}
	if code := mom.do("POST", "/api/v1/sharelinks", map[string]any{"share": "media", "path": "Photos", "expiresInDays": 91, "password": "abc"}, &er); code != 400 || len(er.Details) != 2 {
		t.Fatalf("invalid = %d %v", code, er)
	}
	if code := mom.do("POST", "/api/v1/sharelinks", map[string]any{"share": "media", "path": "Photos/beach.jpg", "allowUpload": true}, &er); code != 400 {
		t.Fatalf("upload to a file = %d", code)
	}
	if code := mom.do("POST", "/api/v1/sharelinks", map[string]any{"share": "media", "path": ".recycle"}, nil); code != 400 {
		t.Fatalf("hidden path = %d", code)
	}

	// Write access: a link, read as mom.
	var made ShareLinkCreated
	if code := mom.do("POST", "/api/v1/sharelinks", map[string]any{"share": "media", "path": "/Photos/", "allowUpload": true, "maxDownloads": 5}, &made); code != 201 {
		t.Fatalf("create = %d", code)
	}
	if made.URL != "/s/"+made.Token || made.Link.Path != "Photos" || !made.Link.Dir || made.Link.CreatedBy != "mom" || made.Link.Status != "active" {
		t.Fatalf("created = %+v", made)
	}
	if d := made.Link.ExpiresAt.Sub(made.Link.CreatedAt).Hours(); d != 7*24 {
		t.Fatalf("default expiry = %v hours", d)
	}
	// An admin may share anything.
	var adminLink ShareLinkCreated
	if code := admin.do("POST", "/api/v1/sharelinks", map[string]any{"share": "backups", "path": "", "expiresInDays": 90}, &adminLink); code != 201 {
		t.Fatalf("admin create = %d", code)
	}

	res, err := http.Get(e.srv.URL + made.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(body), "beach.jpg") || !strings.Contains(string(body), "Shared by mom") {
		t.Fatalf("public page = %d %s", res.StatusCode, body)
	}
	if !strings.Contains(strings.Join(e.fake.Calls, "\n"), "list mom media/Photos") {
		t.Fatalf("not read as mom: %v", e.fake.Calls)
	}
	// The desktop's CSP doesn't apply to link pages.
	if csp := res.Header.Get("Content-Security-Policy"); !strings.HasPrefix(csp, "default-src 'none'") {
		t.Fatalf("csp = %q", csp)
	}

	// Lists: mine, and all for admins only.
	var lst struct{ Links []sharelinks.Link }
	if code := mom.do("GET", "/api/v1/sharelinks", nil, &lst); code != 200 || len(lst.Links) != 1 {
		t.Fatalf("mom's links = %d %v", code, lst)
	}
	if code := mom.do("GET", "/api/v1/sharelinks?scope=all", nil, nil); code != 403 {
		t.Fatalf("non-admin all = %d", code)
	}
	if code := admin.do("GET", "/api/v1/sharelinks?scope=all", nil, &lst); code != 200 || len(lst.Links) != 2 {
		t.Fatalf("all links = %d %v", code, lst)
	}
	raw := ""
	{
		r, _ := mom.http.Get(e.srv.URL + "/api/v1/sharelinks")
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		raw = string(b)
	}
	if strings.Contains(raw, made.Token) || strings.Contains(raw, "password") && !strings.Contains(raw, "hasPassword") {
		t.Fatalf("list leaks secrets: %s", raw)
	}

	// Revoke: only the creator or an admin.
	id := itoa(int(made.Link.ID))
	if code := kid.do("POST", "/api/v1/sharelinks/"+id+"/revoke", nil, nil); code != 404 {
		t.Fatalf("kid revokes mom's link = %d", code)
	}
	var revoked sharelinks.Link
	if code := admin.do("POST", "/api/v1/sharelinks/"+id+"/revoke", nil, &revoked); code != 200 || !revoked.Revoked || revoked.Status != "revoked" {
		t.Fatalf("admin revoke = %d %+v", code, revoked)
	}
	res, _ = http.Get(e.srv.URL + made.URL)
	res.Body.Close()
	if res.StatusCode != 410 {
		t.Fatalf("revoked link = %d", res.StatusCode)
	}

	// Disabling the creator stops their links.
	var made2 ShareLinkCreated
	mom.do("POST", "/api/v1/sharelinks", map[string]any{"share": "media", "path": "Photos/beach.jpg"}, &made2)
	var users []map[string]any
	admin.do("GET", "/api/v1/users", nil, &users)
	var momID string
	for _, u := range users {
		if u["username"] == "mom" {
			momID = itoa(int(u["id"].(float64)))
		}
	}
	if code := admin.do("PATCH", "/api/v1/users/"+momID, map[string]any{"disabled": true}, nil); code != 200 {
		t.Fatalf("disable mom = %d", code)
	}
	res, _ = http.Get(e.srv.URL + made2.URL + "/download")
	res.Body.Close()
	if res.StatusCode != 410 {
		t.Fatalf("link of a disabled account = %d", res.StatusCode)
	}

	// Audited: created, used, revoked.
	var entries []map[string]any
	admin.do("GET", "/api/v1/audit?action=sharelink.", nil, &entries)
	seen := map[string]bool{}
	for _, en := range entries {
		seen[en["action"].(string)+" "+en["outcome"].(string)] = true
	}
	for _, want := range []string{"sharelink.create success", "sharelink.create denied", "sharelink.revoke success"} {
		if !seen[want] {
			t.Errorf("audit missing %q: %v", want, seen)
		}
	}
}

func TestShareLinksWithoutFileAccess(t *testing.T) {
	e := newLinkEnv(t, false)
	admin := (&testEnv{srv: e.srv}).client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	if code := admin.do("POST", "/api/v1/sharelinks", map[string]any{"share": "media", "path": ""}, nil); code != 503 {
		t.Fatalf("create without file access = %d", code)
	}
	if code := admin.do("GET", "/api/v1/sharelinks", nil, nil); code != 200 {
		t.Fatalf("list = %d", code)
	}
	// A link stored earlier doesn't open.
	l, tok, err := (&sharelinks.Store{DB: e.db}).Create(context.Background(), sharelinks.Request{Share: "media", ExpiresInDays: 1}, true, sharelinks.Owner{ID: 1, Principal: "cade"})
	if err != nil || l == nil {
		t.Fatal(err)
	}
	res, _ := http.Get(e.srv.URL + "/s/" + tok)
	res.Body.Close()
	if res.StatusCode != 410 {
		t.Fatalf("link without file access = %d", res.StatusCode)
	}
}
