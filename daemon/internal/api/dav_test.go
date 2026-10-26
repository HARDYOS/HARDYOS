package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/smb"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// davFiles is what files.status says about WebDAV in these tests.
type davFiles struct {
	mu      sync.Mutex
	enabled bool
	on      map[string]bool
}

func (d *davFiles) register(ps *priv.Server) {
	ps.Handle(priv.OpFilesStatus, func(context.Context, json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		st := smb.Status{Available: true, Joined: true, Settings: smb.Settings{SMBEnabled: true, WebDAVEnabled: d.enabled}}
		for _, id := range []string{"media", "private", "home2"} {
			st.Shares = append(st.Shares, smb.ShareStatus{ID: id, Name: id, WebDAV: d.on[id]})
		}
		return st, nil
	})
}

type davEnv struct {
	*testEnv
	server *Server
	fk     *fakeFiles
	dc     *signinDC
	df     *davFiles
}

func newDAVEnv(t *testing.T) *davEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	dc := &signinDC{provisioned: true, reachable: true, accounts: map[string]*domain.UserGroups{}, passwords: map[string]string{}, adminsSID: signinAdminsSID}
	df := &davFiles{enabled: true, on: map[string]bool{"media": true, "home2": true}}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	priv.RegisterBuiltins(ps)
	dc.register(ps)
	df.register(ps)
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	fk := &fakeFiles{
		dirs:    map[string]string{"media": t.TempDir(), "private": t.TempDir(), files.HomeShare: t.TempDir(), "home2": t.TempDir()},
		recycle: map[string]bool{"media": true},
	}
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	s := New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Files: fk, Insecure: true, Kerberos: dc, DomainInfoTTL: time.Millisecond})
	srv := httptest.NewServer(s)
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	env := &davEnv{testEnv: &testEnv{srv: srv, db: db, broker: broker}, server: s, fk: fk, dc: dc, df: df}
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	dc.add("alice", "Al1ce-Passw0rd!", "Family")
	return env
}

// req sends one WebDAV request.
func (e *davEnv) req(t *testing.T, method, p, user, pw string, body io.Reader, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	r, _ := http.NewRequest(method, e.srv.URL+p, body)
	if user != "" {
		r.SetBasicAuth(user, pw)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

const alicePW = "Al1ce-Passw0rd!"

func TestDAVBrowseAndHidden(t *testing.T) {
	e := newDAVEnv(t)
	media := e.fk.dirs["media"]
	put(t, media, "Films/a.txt", "film")
	put(t, media, ".recycle/alice/old.txt", "old")
	put(t, media, ".zfs/snapshot/s/x.txt", "snap")
	put(t, media, ".hardyos-upload-0123456789abcdef01234567", "partial")
	put(t, e.fk.dirs["private"], "secret.txt", "s")
	put(t, e.fk.dirs[files.HomeShare], "mine.txt", "m")

	res, _ := e.req(t, "PROPFIND", "/dav/", "", "", nil, map[string]string{"Depth": "1"})
	if res.StatusCode != 401 || !strings.HasPrefix(res.Header.Get("WWW-Authenticate"), "Basic realm=") {
		t.Fatalf("no credentials: %d %v", res.StatusCode, res.Header)
	}
	res, body := e.req(t, "PROPFIND", "/dav/", `HOME\alice`, alicePW, nil, map[string]string{"Depth": "1"})
	if res.StatusCode != 207 {
		t.Fatalf("PROPFIND / = %d %s", res.StatusCode, body)
	}
	for _, want := range []string{"/dav/Home/", "/dav/Media/", "/dav/Home2/"} {
		if !strings.Contains(body, want) {
			t.Errorf("top lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Private") {
		t.Errorf("a folder without WebDAV is listed:\n%s", body)
	}
	res, body = e.req(t, "PROPFIND", "/dav/Media/", "alice", alicePW, nil, map[string]string{"Depth": "1"})
	if res.StatusCode != 207 || !strings.Contains(body, "/dav/Media/Films/") {
		t.Fatalf("PROPFIND /Media = %d %s", res.StatusCode, body)
	}
	for _, hidden := range []string{".recycle", ".zfs", ".hardyos"} {
		if strings.Contains(body, hidden) {
			t.Errorf("%s listed:\n%s", hidden, body)
		}
	}
	for _, p := range []string{"/dav/Media/.recycle/alice/old.txt", "/dav/Media/.zfs/snapshot/s/x.txt", "/dav/Media/.hardyos-upload-0123456789abcdef01234567", "/dav/Private/secret.txt", "/dav/Media/../Private/secret.txt"} {
		if res, _ := e.req(t, "GET", p, "alice", alicePW, nil, nil); res.StatusCode != 404 {
			t.Errorf("GET %s = %d", p, res.StatusCode)
		}
	}
	// Nothing can be written under a hidden name, not even an upload's.
	for _, p := range []string{"/dav/Media/.hardyos-upload-aaaaaaaaaaaaaaaaaaaaaaaa", "/dav/Media/.recycle/x.txt", "/dav/Media/.zfs/x"} {
		if res, _ := e.req(t, "PUT", p, "alice", alicePW, strings.NewReader("x"), nil); res.StatusCode < 400 {
			t.Errorf("PUT %s = %d", p, res.StatusCode)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(media, ".hardyos-upload-0123456789abcdef01234567")); string(b) != "partial" {
		t.Error("a hidden file was changed")
	}
	// Nothing can be made or removed at the top.
	if res, _ := e.req(t, "MKCOL", "/dav/New/", "alice", alicePW, nil, nil); res.StatusCode < 400 {
		t.Errorf("MKCOL at the top = %d", res.StatusCode)
	}
	if res, _ := e.req(t, "DELETE", "/dav/Media/", "alice", alicePW, nil, nil); res.StatusCode < 400 {
		t.Errorf("DELETE a shared folder = %d", res.StatusCode)
	}
}

func TestDAVReadWrite(t *testing.T) {
	e := newDAVEnv(t)
	media := e.fk.dirs["media"]
	put(t, media, "page.html", "<script>alert(1)</script>")

	res, body := e.req(t, "GET", "/dav/Media/page.html", "alice", alicePW, nil, nil)
	if res.StatusCode != 200 || body != "<script>alert(1)</script>" {
		t.Fatalf("GET = %d %q", res.StatusCode, body)
	}
	if res.Header.Get("Content-Disposition") != "attachment" || !strings.Contains(res.Header.Get("Content-Security-Policy"), "sandbox") ||
		res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("active content could run: %v", res.Header)
	}
	res, _ = e.req(t, "GET", "/dav/Media/page.html", "alice", alicePW, nil, map[string]string{"Range": "bytes=0-7"})
	if res.StatusCode != 206 {
		t.Errorf("Range = %d", res.StatusCode)
	}

	// PUT streams into place, replacing a file only when complete.
	if res, _ := e.req(t, "PUT", "/dav/Media/new.txt", "alice", alicePW, strings.NewReader("hello"), nil); res.StatusCode != 201 {
		t.Fatalf("PUT = %d", res.StatusCode)
	}
	if b, _ := os.ReadFile(filepath.Join(media, "new.txt")); string(b) != "hello" {
		t.Errorf("uploaded %q", b)
	}
	if res, _ := e.req(t, "PUT", "/dav/Media/new.txt", "alice", alicePW, strings.NewReader("hello again"), nil); res.StatusCode != 201 {
		t.Fatalf("PUT over = %d", res.StatusCode)
	}
	if b, _ := os.ReadFile(filepath.Join(media, "new.txt")); string(b) != "hello again" {
		t.Errorf("replaced with %q", b)
	}
	// A body that breaks off leaves the old file and no temporary one.
	u, _ := url.Parse(e.srv.URL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "PUT /dav/Media/new.txt HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\nContent-Length: 100000\r\n\r\npartial data", u.Host, basic("alice", alicePW))
	time.Sleep(200 * time.Millisecond)
	conn.Close()
	time.Sleep(300 * time.Millisecond)
	if b, _ := os.ReadFile(filepath.Join(media, "new.txt")); string(b) != "hello again" {
		t.Errorf("a broken upload replaced the file: %q", b)
	}
	if ents, _ := filepath.Glob(filepath.Join(media, ".hardyos-upload-*")); len(ents) != 0 {
		t.Errorf("temporary files left: %v", ents)
	}

	// MKCOL, MOVE (within and between folders), COPY, DELETE to the recycle bin.
	if res, _ := e.req(t, "MKCOL", "/dav/Media/Docs/", "alice", alicePW, nil, nil); res.StatusCode != 201 {
		t.Errorf("MKCOL = %d", res.StatusCode)
	}
	if res, _ := e.req(t, "MOVE", "/dav/Media/new.txt", "alice", alicePW, nil, map[string]string{"Destination": e.srv.URL + "/dav/Media/Docs/moved.txt"}); res.StatusCode != 201 {
		t.Errorf("MOVE = %d", res.StatusCode)
	}
	if b, _ := os.ReadFile(filepath.Join(media, "Docs/moved.txt")); string(b) != "hello again" {
		t.Errorf("moved: %q", b)
	}
	if res, _ := e.req(t, "COPY", "/dav/Media/Docs/moved.txt", "alice", alicePW, nil, map[string]string{"Destination": e.srv.URL + "/dav/Home/copy.txt"}); res.StatusCode != 201 {
		t.Errorf("COPY = %d", res.StatusCode)
	}
	if b, _ := os.ReadFile(filepath.Join(e.fk.dirs[files.HomeShare], "copy.txt")); string(b) != "hello again" {
		t.Errorf("copied: %q", b)
	}
	if res, _ := e.req(t, "DELETE", "/dav/Media/Docs/moved.txt", "alice", alicePW, nil, nil); res.StatusCode != 204 {
		t.Errorf("DELETE = %d", res.StatusCode)
	}
	found := false
	for _, c := range e.fk.calls {
		if c == "delete media:Docs/moved.txt permanent=false" {
			found = true
		}
	}
	if !found {
		t.Errorf("delete didn't go to the recycle bin: %v", e.fk.calls)
	}

	// PROPPATCH: dead properties aren't kept; Windows' modified time is.
	patch := `<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:"><D:set><D:prop>` +
		`<Z:Win32LastModifiedTime>Tue, 01 Jan 2030 10:00:00 GMT</Z:Win32LastModifiedTime><Z:Other>evil</Z:Other></D:prop></D:set></D:propertyupdate>`
	res, body = e.req(t, "PROPPATCH", "/dav/Home/copy.txt", "alice", alicePW, strings.NewReader(patch), map[string]string{"Content-Type": "application/xml"})
	if res.StatusCode != 207 || !strings.Contains(body, "200 OK") {
		t.Errorf("PROPPATCH = %d %s", res.StatusCode, body)
	}
	if fi, _ := os.Stat(filepath.Join(e.fk.dirs[files.HomeShare], "copy.txt")); fi == nil || fi.ModTime().Year() != 2030 {
		t.Errorf("modified time not set: %v", fi)
	}
	res, body = e.req(t, "PROPFIND", "/dav/Home/copy.txt", "alice", alicePW,
		strings.NewReader(`<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><Other xmlns="urn:schemas-microsoft-com:"/></D:prop></D:propfind>`), map[string]string{"Depth": "0"})
	if strings.Contains(body, "evil") {
		t.Errorf("a dead property was kept: %s", body)
	}

	// The audit log has the upload, the move and the delete.
	var n int
	_ = e.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action IN ('files.upload','files.move','files.delete') AND detail LIKE 'webdav%'`).Scan(&n)
	if n < 4 {
		t.Errorf("audit entries: %d", n)
	}

	// LOCK / UNLOCK (Finder and Office need them).
	lock := `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype></D:lockinfo>`
	res, _ = e.req(t, "LOCK", "/dav/Home/copy.txt", "alice", alicePW, strings.NewReader(lock), map[string]string{"Timeout": "Second-60"})
	if res.StatusCode != 200 || res.Header.Get("Lock-Token") == "" {
		t.Fatalf("LOCK = %d", res.StatusCode)
	}
	if res, _ := e.req(t, "PUT", "/dav/Home/copy.txt", "alice", alicePW, strings.NewReader("x"), nil); res.StatusCode != 423 {
		t.Errorf("PUT without the lock token = %d", res.StatusCode)
	}
	if res, _ := e.req(t, "UNLOCK", "/dav/Home/copy.txt", "alice", alicePW, nil, map[string]string{"Lock-Token": res.Header.Get("Lock-Token")}); res.StatusCode != 204 {
		t.Errorf("UNLOCK = %d", res.StatusCode)
	}
}

func basic(u, p string) string {
	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth(u, p)
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Basic ")
}

func TestDAVSignIn(t *testing.T) {
	e := newDAVEnv(t)
	propfind := func(user, pw string) int {
		res, _ := e.req(t, "PROPFIND", "/dav/", user, pw, nil, map[string]string{"Depth": "0"})
		return res.StatusCode
	}

	// Each spelling works; a checked password is trusted for a while.
	for _, n := range []string{"alice", `HOME\alice`, "alice@home.example.net"} {
		if c := propfind(n, alicePW); c != 207 {
			t.Errorf("%s = %d", n, c)
		}
	}
	// The DC going away doesn't stop someone already checked...
	e.dc.mu.Lock()
	e.dc.reachable = false
	e.dc.mu.Unlock()
	if c := propfind("alice", alicePW); c != 207 {
		t.Errorf("cached sign-in with the DC down = %d", c)
	}
	// ...but a new check fails closed with 503, not counted as a guess.
	for i := 0; i < 6; i++ {
		if c := propfind("alice", "Other-Passw0rd"); c != 503 {
			t.Errorf("DC down = %d", c)
		}
	}
	e.dc.mu.Lock()
	e.dc.reachable = true
	e.dc.mu.Unlock()

	// Turned off here: out at once, even with a checked password.
	if _, err := e.db.Exec(`UPDATE users SET disabled = 1 WHERE username = ?`, `HOME\alice`); err != nil {
		t.Fatal(err)
	}
	if c := propfind("alice", alicePW); c != 401 {
		t.Errorf("disabled account = %d", c)
	}
	_, _ = e.db.Exec(`UPDATE users SET disabled = 0 WHERE username = ?`, `HOME\alice`)

	// Five wrong guesses lock the account for WebDAV and the desktop alike.
	for i := 0; i < 5; i++ {
		if c := propfind(`HOME\alice`, fmt.Sprintf("guess-%d", i)); c != 401 {
			t.Errorf("guess %d = %d", i, c)
		}
	}
	if c := propfind("alice@home.example.net", "guess-5"); c != 429 {
		t.Errorf("after five guesses = %d", c)
	}
	var er ErrorResponse
	if code := e.client(t).do("POST", "/api/v1/auth/login", map[string]string{"username": "alice", "password": alicePW}, &er); code != 429 {
		t.Errorf("desktop sign-in during the lockout = %d %+v", code, er)
	}
	var n int
	_ = e.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'dav.login' AND outcome = 'failure'`).Scan(&n)
	if n < 5 {
		t.Errorf("failed sign-ins audited: %d", n)
	}
	// The password is never kept: only an HMAC with a per-process key.
	e.server.dav.mu.Lock()
	for k := range e.server.dav.checked {
		if strings.Contains(string(k[:]), alicePW) {
			t.Error("password in the cache")
		}
	}
	e.server.dav.mu.Unlock()
}

func TestDAVSwitches(t *testing.T) {
	e := newDAVEnv(t)
	e.df.mu.Lock()
	e.df.enabled = false
	e.df.mu.Unlock()
	if res, _ := e.req(t, "PROPFIND", "/dav/", "alice", alicePW, nil, nil); res.StatusCode != 404 {
		t.Errorf("WebDAV off = %d", res.StatusCode)
	}
	e.df.mu.Lock()
	e.df.enabled = true
	e.df.mu.Unlock()
	e.server.dav.cfgMu.Lock()
	e.server.dav.cfg = nil
	e.server.dav.cfgMu.Unlock()
	res, _ := e.req(t, "OPTIONS", "/", "", "", nil, nil)
	if res.Header.Get("DAV") != "1, 2" {
		t.Errorf("OPTIONS / for Windows: %v", res.Header)
	}
	if res, _ := e.req(t, "PROPFIND", "/dav", "alice", alicePW, nil, map[string]string{"Depth": "0"}); res.StatusCode != 207 {
		t.Errorf("/dav without a slash = %d", res.StatusCode)
	}
	// Plain HTTP is refused unless the server is in development mode.
	s := New(Config{DB: e.db, Files: e.fk})
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("PROPFIND", "/dav/", nil))
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "HTTPS") {
		t.Errorf("plain HTTP = %d %s", rec.Code, rec.Body)
	}
}
