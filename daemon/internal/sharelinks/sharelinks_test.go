package sharelinks_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/sharelinks"
	"github.com/hardyos/hardyos/daemon/internal/sharelinks/linktest"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

type env struct {
	t      *testing.T
	links  *sharelinks.Store
	fake   *linktest.Fake
	srv    *httptest.Server
	pub    *sharelinks.Public
	owner  int64
	gone   map[int64]bool
	mu     sync.Mutex
	audits []string
	now    time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "links.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	users := &auth.Users{DB: db}
	u, err := users.Create(ctx, auth.NewUser{Username: "alice", Password: "alicepassword", Role: auth.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, fake: linktest.New(t.TempDir(), "media", "backups"), owner: u.ID, gone: map[int64]bool{}, now: time.Now()}
	e.links = &sharelinks.Store{DB: db, Now: func() time.Time { return e.now }}
	e.fake.Grant("media", "HOME\\alice", "write")
	e.pub = &sharelinks.Public{
		Links: e.links,
		Files: e.fake,
		Owner: func(_ context.Context, id int64) (files.Who, error) {
			e.mu.Lock()
			defer e.mu.Unlock()
			if e.gone[id] {
				return files.Who{}, sharelinks.ErrOwnerGone
			}
			return files.Who{Principal: "HOME\\alice"}, nil
		},
		Audit: func(_ *http.Request, l *sharelinks.Link, action, target string, outcome audit.Outcome, detail string) {
			e.mu.Lock()
			e.audits = append(e.audits, action+" "+string(outcome)+" "+target)
			e.mu.Unlock()
		},
		Insecure: true,
		Now:      func() time.Time { return e.now },
	}
	mux := http.NewServeMux()
	e.pub.Register(mux)
	e.srv = httptest.NewServer(mux)
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) link(q sharelinks.Request, dir bool) (*sharelinks.Link, string) {
	e.t.Helper()
	if probs := q.Validate(); len(probs) > 0 {
		e.t.Fatalf("validate: %v", probs)
	}
	l, tok, err := e.links.Create(context.Background(), q, dir, sharelinks.Owner{ID: e.owner, Principal: "HOME\\alice"})
	if err != nil {
		e.t.Fatal(err)
	}
	return l, tok
}

func (e *env) client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func get(t *testing.T, c *http.Client, u string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("GET", u, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), res.Header
}

func TestValidate(t *testing.T) {
	q := sharelinks.Request{Share: "media", Path: "/Photos/2024/"}
	if p := q.Validate(); len(p) != 0 || q.Path != "Photos/2024" || q.ExpiresInDays != 7 {
		t.Fatalf("defaults: %v %+v", p, q)
	}
	bad := sharelinks.Request{Share: "", Path: "a/../b", ExpiresInDays: 91, Password: "abc", MaxDownloads: -1}
	if p := bad.Validate(); len(p) != 5 {
		t.Fatalf("problems = %v", p)
	}
	for _, p := range []string{".recycle/x", "a/.zfs/snapshot", ".hardyos-meta", "a//b", "./a", "a\x00b"} {
		if _, err := sharelinks.CleanPath(p); err == nil {
			t.Errorf("CleanPath(%q) allowed", p)
		}
	}
}

func TestTokensAreHashed(t *testing.T) {
	e := newEnv(t)
	_, tok := e.link(sharelinks.Request{Share: "media", Path: "a.txt"}, false)
	if !sharelinks.ValidToken(tok) || len(tok) != 43 {
		t.Fatalf("token %q", tok)
	}
	var n int
	if err := e.links.DB.QueryRow(`SELECT COUNT(*) FROM share_links WHERE token_hash = ? OR token_hash = ?`, tok, sharelinks.HashToken(tok)).Scan(&n); err != nil || n != 1 {
		t.Fatalf("stored rows matching hash = %d %v", n, err)
	}
	var raw int
	_ = e.links.DB.QueryRow(`SELECT COUNT(*) FROM share_links WHERE token_hash = ?`, tok).Scan(&raw)
	if raw != 0 {
		t.Fatal("the raw token is stored")
	}
	other := []byte(tok)
	if other[0] = 'A'; tok[0] == 'A' {
		other[0] = 'B' // still base64, a different token
	}
	if _, err := e.links.ByToken(context.Background(), string(other)); !errors.Is(err, sharelinks.ErrNotFound) {
		t.Fatalf("a different token found a link: %v", err)
	}
	if l, err := e.links.ByToken(context.Background(), tok); err != nil || l.Path != "a.txt" {
		t.Fatalf("token lookup: %v", err)
	}
}

func TestFolderLinkBrowseDownloadAndHidden(t *testing.T) {
	e := newEnv(t)
	e.fake.Write("media", "Photos/beach.jpg", "JPEGDATA")
	e.fake.Write("media", "Photos/2024/snow.jpg", "SNOW")
	e.fake.Write("media", "Photos/.recycle/old.jpg", "OLD")
	e.fake.Write("media", "Photos/.zfs/snapshot/x", "SNAP")
	e.fake.Write("media", "Photos/.hardyos-index", "IDX")
	e.fake.Write("media", "secret.txt", "TOP SECRET")
	_, tok := e.link(sharelinks.Request{Share: "media", Path: "Photos"}, true)
	c := e.client()
	base := e.srv.URL + "/s/" + tok

	code, body, h := get(t, c, base)
	if code != 200 || !strings.Contains(body, "beach.jpg") || !strings.Contains(body, "2024/") {
		t.Fatalf("page = %d %s", code, body)
	}
	for _, hidden := range []string{".recycle", ".zfs", ".hardyos", "secret.txt"} {
		if strings.Contains(body, hidden) {
			t.Errorf("page shows %s", hidden)
		}
	}
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") || h.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers: csp=%q referrer=%q", csp, h.Get("Referrer-Policy"))
	}
	if strings.Contains(body, "<script") || strings.Contains(body, "style=") || strings.Contains(body, " on") && strings.Contains(body, "onclick") {
		t.Error("page has inline script or style")
	}

	// Sub folder, and no way out of the linked folder.
	if code, body, _ := get(t, c, base+"?path=2024"); code != 200 || !strings.Contains(body, "snow.jpg") {
		t.Fatalf("sub folder = %d %s", code, body)
	}
	for _, p := range []string{"..", "../secret.txt", ".recycle", ".zfs/snapshot", "2024/../../secret.txt"} {
		if code, _, _ := get(t, c, base+"/download?path="+url.QueryEscape(p)); code != 400 {
			t.Errorf("download %q = %d, want 400", p, code)
		}
	}

	// File download with Range, read as the creator.
	code, body, h = get(t, c, base+"/download?path=beach.jpg")
	if code != 200 || body != "JPEGDATA" || !strings.Contains(h.Get("Content-Disposition"), "attachment") || !strings.Contains(h.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("download = %d %q %v", code, body, h)
	}
	if code, body, _ := get(t, c, base+"/download?path=beach.jpg", "Range", "bytes=4-"); code != 206 || body != "DATA" {
		t.Fatalf("range = %d %q", code, body)
	}

	// Whole folder as a zip, without hidden folders.
	code, body, h = get(t, c, base+"/download")
	if code != 200 || h.Get("Content-Type") != "application/zip" {
		t.Fatalf("zip = %d %v", code, h)
	}
	zr, err := zip.NewReader(bytes.NewReader([]byte(body)), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "2024/,2024/snow.jpg,beach.jpg" {
		t.Fatalf("zip has %v", names)
	}
	for _, c := range e.fake.Calls {
		if !strings.Contains(c, "HOME\\alice") || strings.HasPrefix(c, "versions") || strings.HasPrefix(c, "openversion") {
			t.Fatalf("unexpected file call %q", c)
		}
	}
	l, _ := e.links.ByToken(context.Background(), tok)
	if l.DownloadCount != 2 || l.LastUsedAt == nil {
		t.Fatalf("download count = %d (the range request isn't counted)", l.DownloadCount)
	}
	if len(e.audits) != 2 || !strings.HasPrefix(e.audits[0], "sharelink.download success Photos/beach.jpg") {
		t.Fatalf("audits = %v", e.audits)
	}
}

func TestFileLink(t *testing.T) {
	e := newEnv(t)
	e.fake.Write("media", "Docs/report.pdf", "PDF")
	_, tok := e.link(sharelinks.Request{Share: "media", Path: "Docs/report.pdf", MaxDownloads: 1}, false)
	c := e.client()
	base := e.srv.URL + "/s/" + tok
	if code, body, _ := get(t, c, base); code != 200 || !strings.Contains(body, "report.pdf") || !strings.Contains(body, "Download") {
		t.Fatalf("page = %d %s", code, body)
	}
	if code, _, _ := get(t, c, base+"/download?path=other"); code != 400 {
		t.Fatalf("file link with a path = %d", code)
	}
	if code, body, _ := get(t, c, base+"/download"); code != 200 || body != "PDF" {
		t.Fatalf("download = %d %q", code, body)
	}
	// The limit of one download is used up.
	if code, body, _ := get(t, c, base); code != 410 || !strings.Contains(body, "as many times") {
		t.Fatalf("after limit = %d %s", code, body)
	}
	if code, _, _ := get(t, c, base+"/download"); code != 410 {
		t.Fatalf("download after limit = %d", code)
	}
}

func TestLinkStops(t *testing.T) {
	e := newEnv(t)
	e.fake.Write("media", "a.txt", "A")
	c := e.client()

	// Unknown and malformed tokens.
	for _, tok := range []string{"nope", strings.Repeat("A", 43)} {
		if code, body, _ := get(t, c, e.srv.URL+"/s/"+tok); code != 404 || !strings.Contains(body, "Link not found") {
			t.Fatalf("unknown token = %d", code)
		}
	}

	l, tok := e.link(sharelinks.Request{Share: "media", Path: "a.txt"}, false)
	u := e.srv.URL + "/s/" + tok + "/download"
	if code, _, _ := get(t, c, u); code != 200 {
		t.Fatalf("download = %d", code)
	}
	// Creator loses access to the folder.
	e.fake.Grant("media", "HOME\\alice", "")
	if code, _, _ := get(t, c, u); code != 410 {
		t.Fatalf("after access removed = %d", code)
	}
	e.fake.Grant("media", "HOME\\alice", "read")
	if code, _, _ := get(t, c, u); code != 200 {
		t.Fatalf("read access is enough to download = %d", code)
	}
	// Creator's account disabled or deleted.
	e.gone[e.owner] = true
	if code, body, _ := get(t, c, u); code != 410 || !strings.Contains(body, "no longer works") {
		t.Fatalf("owner gone = %d %s", code, body)
	}
	e.gone[e.owner] = false
	// Expired.
	e.now = e.now.Add(8 * 24 * time.Hour)
	if code, body, _ := get(t, c, u); code != 410 || !strings.Contains(body, "expired") {
		t.Fatalf("expired = %d %s", code, body)
	}
	e.now = time.Now()
	// Revoked.
	if _, err := e.links.Revoke(context.Background(), l.ID); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := get(t, c, u); code != 410 || !strings.Contains(body, "turned off") {
		t.Fatalf("revoked = %d %s", code, body)
	}
	// The file is moved away.
	_, tok2 := e.link(sharelinks.Request{Share: "media", Path: "gone.txt"}, false)
	if code, _, _ := get(t, c, e.srv.URL+"/s/"+tok2); code != 410 {
		t.Fatalf("missing target = %d", code)
	}
}

func TestPassword(t *testing.T) {
	e := newEnv(t)
	e.fake.Write("media", "a.txt", "A")
	_, tok := e.link(sharelinks.Request{Share: "media", Path: "a.txt", Password: "open sesame"}, false)
	c := e.client()
	base := e.srv.URL + "/s/" + tok
	code, body, _ := get(t, c, base)
	if code != 200 || !strings.Contains(body, `type="password"`) || strings.Contains(body, "a.txt") {
		t.Fatalf("password form = %d %s", code, body)
	}
	if code, _, _ := get(t, c, base+"/download"); code != 403 {
		t.Fatalf("download before password = %d", code)
	}
	post := func(pw string, origin string) (int, string) {
		req, _ := http.NewRequest("POST", base+"/unlock", strings.NewReader(url.Values{"password": {pw}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		res, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, _ := post("open sesame", "https://evil.example"); code != 403 {
		t.Fatalf("cross-site unlock = %d", code)
	}
	if code, body := post("wrong", ""); code != 401 || !strings.Contains(body, "password isn&#39;t right") {
		t.Fatalf("wrong password = %d", code)
	}
	if code, _ := post("open sesame", e.srv.URL); code != 303 {
		t.Fatalf("right password = %d", code)
	}
	if code, body, _ := get(t, c, base+"/download"); code != 200 || body != "A" {
		t.Fatalf("download after password = %d %q", code, body)
	}
	// Another browser still needs the password.
	if code, body, _ := get(t, e.client(), base); code != 200 || !strings.Contains(body, `type="password"`) {
		t.Fatalf("other browser = %d", code)
	}
	// Wrong passwords lock out after five tries.
	for i := 0; i < 5; i++ {
		post("wrong", "")
	}
	if code, body := post("open sesame", ""); code != 429 || !strings.Contains(body, "Too many") {
		t.Fatalf("after many wrong passwords = %d", code)
	}
	if !strings.Contains(strings.Join(e.audits, "\n"), "sharelink.password denied") {
		t.Fatalf("audits = %v", e.audits)
	}
}

func upload(t *testing.T, c *http.Client, u string, names ...string) (int, string, http.Header) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, n := range names {
		w, _ := mw.CreateFormFile("file", n)
		_, _ = w.Write([]byte("content of " + n))
	}
	mw.Close()
	req, _ := http.NewRequest("POST", u, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), res.Header
}

func TestUpload(t *testing.T) {
	e := newEnv(t)
	e.fake.Write("media", "Drop/existing.txt", "OLD")
	_, ro := e.link(sharelinks.Request{Share: "media", Path: "Drop"}, true)
	_, tok := e.link(sharelinks.Request{Share: "media", Path: "Drop", AllowUpload: true}, true)
	c := e.client()

	if code, _, _ := upload(t, c, e.srv.URL+"/s/"+ro+"/upload", "x.txt"); code != 403 {
		t.Fatalf("upload to a read-only link = %d", code)
	}
	if code, body, _ := get(t, c, e.srv.URL+"/s/"+tok); !strings.Contains(body, `enctype="multipart/form-data"`) || code != 200 {
		t.Fatal("upload form missing")
	}
	code, _, h := upload(t, c, e.srv.URL+"/s/"+tok+"/upload", "existing.txt", `..\..\evil.txt`, ".recycle", "new.txt")
	if code != 303 || !strings.Contains(h.Get("Location"), "uploaded=3") {
		t.Fatalf("upload = %d %v", code, h)
	}
	if e.fake.Read("media", "Drop/existing.txt") != "OLD" || e.fake.Read("media", "Drop/existing (2).txt") != "content of existing.txt" {
		t.Fatal("an upload replaced an existing file")
	}
	if e.fake.Read("media", "Drop/evil.txt") == "" || e.fake.Read("media", "evil.txt") != "" || e.fake.Read("media", "Drop/.recycle") != "" {
		t.Fatal("upload names weren't made safe")
	}
	if !strings.Contains(strings.Join(e.audits, "\n"), "sharelink.upload success media/Drop") {
		t.Fatalf("audits = %v", e.audits)
	}
	// The creator can only read now: uploads stop.
	e.fake.Grant("media", "HOME\\alice", "read")
	if code, body, _ := upload(t, c, e.srv.URL+"/s/"+tok+"/upload", "late.txt"); code != 400 || !strings.Contains(body, "take uploads any more") {
		t.Fatalf("upload without write access = %d %s", code, body)
	}
	// Cross-site posts are refused.
	req, _ := http.NewRequest("POST", e.srv.URL+"/s/"+tok+"/upload", strings.NewReader(""))
	req.Header.Set("Origin", "https://evil.example")
	res, _ := c.Do(req)
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("cross-site upload = %d", res.StatusCode)
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	e.pub.PerIP = sharelinks.NewRateLimiter(3, time.Minute)
	e.fake.Write("media", "a.txt", "A")
	_, tok := e.link(sharelinks.Request{Share: "media", Path: "a.txt"}, false)
	c := e.client()
	for i := 0; i < 3; i++ {
		if code, _, _ := get(t, c, e.srv.URL+"/s/"+tok); code != 200 {
			t.Fatalf("request %d = %d", i, code)
		}
	}
	if code, _, h := get(t, c, e.srv.URL+"/s/"+tok); code != 429 || h.Get("Retry-After") == "" {
		t.Fatalf("over the limit = %d", code)
	}
	l := sharelinks.NewRateLimiter(1, time.Minute)
	now := time.Now()
	l.Now = func() time.Time { return now }
	if !l.Allow("k") || l.Allow("k") {
		t.Fatal("limiter")
	}
	now = now.Add(time.Minute)
	if !l.Allow("k") {
		t.Fatal("limiter didn't reset")
	}
}

func TestStaticAndListing(t *testing.T) {
	e := newEnv(t)
	c := e.client()
	if code, body, h := get(t, c, e.srv.URL+"/s/-/static/style.css"); code != 200 || !strings.Contains(h.Get("Content-Type"), "text/css") || !strings.Contains(body, "#22d3ee") {
		t.Fatalf("css = %d", code)
	}
	if code, _, _ := get(t, c, e.srv.URL+"/s/-/static/page.html"); code != 404 {
		t.Fatalf("template served = %d", code)
	}
	l1, _ := e.link(sharelinks.Request{Share: "media", Path: "a"}, true)
	l2, _ := e.link(sharelinks.Request{Share: "media", Path: "b.txt", Password: "secret123"}, false)
	mine, _ := e.links.List(context.Background(), e.owner)
	if len(mine) != 2 || mine[0].ID != l2.ID || !mine[0].HasPassword || mine[1].ID != l1.ID || mine[1].Status != "active" {
		t.Fatalf("list = %+v", mine)
	}
	if other, _ := e.links.List(context.Background(), e.owner+1); len(other) != 0 {
		t.Fatal("someone else's list has links")
	}
	if _, _, err := e.links.Create(context.Background(), sharelinks.Request{Share: "media", Path: "x", ExpiresInDays: 1, AllowUpload: true}, false, sharelinks.Owner{ID: e.owner}); err == nil {
		t.Fatal("upload link to a file")
	}
	// Old expired links are pruned.
	e.now = e.now.Add(40 * 24 * time.Hour)
	if n, err := e.links.Prune(context.Background()); err != nil || n != 2 {
		t.Fatalf("prune = %d %v", n, err)
	}
}
