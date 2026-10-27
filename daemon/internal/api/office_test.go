package api

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/office"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

type officeEnv struct {
	*testEnv
	s      *Server
	fk     *fakeFiles
	admin  *client
	origin string // the office origin
	ds     *httptest.Server
	dsMu   sync.Mutex
	dsSeen []string // paths and commands the Document Server got
}

func (e *officeEnv) seen() []string {
	e.dsMu.Lock()
	defer e.dsMu.Unlock()
	return append([]string(nil), e.dsSeen...)
}

func newOfficeEnv(t *testing.T) *officeEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	fk := &fakeFiles{dirs: map[string]string{"docs": t.TempDir()}, readOnly: map[string]bool{}, recycle: map[string]bool{}}
	env := &officeEnv{}
	ds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			http.Error(w, "cookies reached the Document Server", http.StatusTeapot)
			return
		}
		seen := r.URL.EscapedPath()
		if r.URL.Path == office.CommandPath {
			b, _ := io.ReadAll(r.Body)
			seen += " " + string(b)
			_, _ = io.WriteString(w, `{"error":0}`)
		} else {
			_, _ = io.WriteString(w, "ds:"+r.URL.Path)
		}
		env.dsMu.Lock()
		env.dsSeen = append(env.dsSeen, seen)
		env.dsMu.Unlock()
	}))
	dsURL, _ := url.Parse(ds.URL)
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	s := New(Config{DB: db, Jobs: m, Events: broker, Files: fk, Insecure: true,
		OfficeInternal:     func() (*url.URL, error) { return dsURL, nil },
		OfficeCallbackBase: "http://127.0.0.1:9"})
	srv := httptest.NewServer(s)
	// A free port for the office origin.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	t.Cleanup(func() {
		srv.Close()
		ds.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	env.testEnv, env.s, env.fk, env.ds = &testEnv{srv: srv, db: db, broker: broker}, s, fk, ds
	env.origin = "http://127.0.0.1:" + strconv.Itoa(port)
	env.admin = env.client(t)
	env.admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	// Turned on directly (the enable job needs Docker).
	if _, _, err := s.office.settings.EnsureSecret(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.office.settings.Save(ctx, office.Settings{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	go s.RunOffice(ctx, OfficeOptions{Port: port, ListenHost: "127.0.0.1", InternalListen: "127.0.0.1:0", Interval: 50 * time.Millisecond})
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.office.mu.Lock()
		up := s.office.srv != nil
		s.office.mu.Unlock()
		if up {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("office origin didn't start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return env
}

// noRedirect is a client that shares c's cookies but doesn't follow redirects.
func noRedirect(c *client) *http.Client {
	return &http.Client{Jar: c.http.Jar, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func oget(t *testing.T, hc *http.Client, u string) (*http.Response, string) {
	t.Helper()
	res, err := hc.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

var configRE = regexp.MustCompile(`data-config="([^"]+)"`)

func editorConfig(t *testing.T, page string) map[string]any {
	t.Helper()
	m := configRE.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no editor config in %s", page)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(m[1], "&#43;", "+"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestOfficeOpenFromDesktop(t *testing.T) {
	env := newOfficeEnv(t)
	put(t, env.fk.dirs["docs"], "plan.docx", "doc")
	put(t, env.fk.dirs["docs"], "photo.jpg", "jpg")

	var st OfficeStatus
	if code := env.admin.do("GET", "/api/v1/office", nil, &st); code != 200 || !st.Enabled || !st.Ready || st.EditorLimit != 20 || st.Settings == nil {
		t.Fatalf("status %d %+v", code, st)
	}
	var e ErrorResponse
	if code := env.admin.do("POST", "/api/v1/office/open", map[string]string{"share": "docs", "path": "photo.jpg"}, &e); code != 400 {
		t.Fatalf("photo = %d %+v", code, e)
	}
	var op OfficeOpened
	if code := env.admin.do("POST", "/api/v1/office/open", map[string]string{"share": "docs", "path": "plan.docx"}, &op); code != 200 || op.Mode != "edit" {
		t.Fatalf("open = %d %+v", code, op)
	}
	if !strings.HasPrefix(op.URL, env.origin+"/s/-/office/editor?t=") {
		t.Fatalf("url %s", op.URL)
	}
	// Another browser (no desktop session) can't use the ticket.
	stranger := env.client(t)
	if res, _ := oget(t, stranger.http, op.URL); res.StatusCode != http.StatusForbidden {
		t.Fatalf("stranger = %d", res.StatusCode)
	}
	// The ticket was used up by that attempt; open again.
	env.admin.do("POST", "/api/v1/office/open", map[string]string{"share": "docs", "path": "plan.docx"}, &op)
	res, page := oget(t, env.admin.http, op.URL)
	if res.StatusCode != 200 {
		t.Fatalf("editor = %d %s", res.StatusCode, page)
	}
	csp := res.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors "+env.srv.URL) || !strings.Contains(csp, "script-src 'self'") {
		t.Fatalf("csp %q", csp)
	}
	cfg := editorConfig(t, page)
	ec := cfg["editorConfig"].(map[string]any)
	if ec["mode"] != "edit" || ec["user"].(map[string]any)["name"] != "cade" || cfg["token"] == "" {
		t.Fatalf("config %v", cfg)
	}
	if res, _ := oget(t, env.admin.http, op.URL); res.StatusCode != http.StatusGone {
		t.Fatalf("ticket reused = %d", res.StatusCode)
	}
	// The gate cookie lets this browser use the Document Server proxy, and
	// HardyOS cookies never reach it.
	res, body := oget(t, env.admin.http, env.origin+"/s/-/ds/web-apps/apps/api/documents/api.js")
	if res.StatusCode != 200 || body != "ds:/web-apps/apps/api/documents/api.js" {
		t.Fatalf("proxy = %d %s", res.StatusCode, body)
	}
	if res, _ := oget(t, stranger.http, env.origin+"/s/-/ds/web-apps/apps/api/documents/api.js"); res.StatusCode != http.StatusForbidden {
		t.Fatalf("proxy without the gate = %d", res.StatusCode)
	}
	// Never on the desktop's own origin.
	if res, _ := oget(t, env.admin.http, env.srv.URL+"/s/-/ds/web-apps/apps/api/documents/api.js"); res.StatusCode != http.StatusNotFound {
		t.Fatalf("proxy on the desktop origin = %d", res.StatusCode)
	}
	// View mode on request.
	env.admin.do("POST", "/api/v1/office/open", map[string]string{"share": "docs", "path": "plan.docx", "mode": "view"}, &op)
	if op.Mode != "view" {
		t.Fatalf("view mode = %+v", op)
	}

	// Local accounts that aren't administrators get no files.
	env.admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	if code := kid.do("POST", "/api/v1/office/open", map[string]string{"share": "docs", "path": "plan.docx"}, &e); code != 403 {
		t.Fatalf("kid open = %d %+v", code, e)
	}
	if code := kid.do("POST", "/api/v1/office/enable", map[string]string{}, &e); code != 403 {
		t.Fatalf("kid enable = %d", code)
	}

	// Off: nothing opens.
	if err := env.s.office.settings.Save(context.Background(), office.Settings{Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if code := env.admin.do("POST", "/api/v1/office/open", map[string]string{"share": "docs", "path": "plan.docx"}, &e); code != 409 || e.Code != "office_off" {
		t.Fatalf("off = %d %+v", code, e)
	}
}

func TestOfficeNewDocument(t *testing.T) {
	env := newOfficeEnv(t)
	var e ErrorResponse
	for _, bad := range []map[string]string{
		{"share": "docs", "kind": "macro", "name": "x"},
		{"share": "docs", "kind": "document", "name": "../x"},
		{"share": "docs", "kind": "document", "name": ".hardyos-x"},
	} {
		if code := env.admin.do("POST", "/api/v1/office/new", bad, &e); code != 400 {
			t.Errorf("%v = %d", bad, code)
		}
	}
	for kind, ext := range office.NewKinds {
		var got map[string]any
		if code := env.admin.do("POST", "/api/v1/office/new", map[string]string{"share": "docs", "kind": kind, "name": "Report " + kind}, &got); code != 201 {
			t.Fatalf("%s = %d %v", kind, code, got)
		}
		p := filepath.Join(env.fk.dirs["docs"], "Report "+kind+"."+ext)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := zip.NewReader(strings.NewReader(string(b)), int64(len(b))); err != nil {
			t.Fatalf("%s isn't an Office file: %v", kind, err)
		}
	}
	// Never over an existing file.
	if code := env.admin.do("POST", "/api/v1/office/new", map[string]string{"share": "docs", "kind": "document", "name": "Report document.docx"}, &e); code != 409 {
		t.Fatalf("existing = %d", code)
	}
}

func TestOfficeShareLinks(t *testing.T) {
	env := newOfficeEnv(t)
	put(t, env.fk.dirs["docs"], "plan.docx", "doc")
	put(t, env.fk.dirs["docs"], "old.doc", "doc")
	put(t, env.fk.dirs["docs"], "photo.jpg", "jpg")

	var e ErrorResponse
	for _, p := range []string{"photo.jpg", "old.doc"} {
		if code := env.admin.do("POST", "/api/v1/sharelinks", map[string]any{"share": "docs", "path": p, "access": "edit"}, &e); code != 400 {
			t.Errorf("edit link to %s = %d", p, code)
		}
	}
	if code := env.admin.do("POST", "/api/v1/sharelinks", map[string]any{"share": "docs", "path": "plan.docx", "access": "admin"}, &e); code != 400 {
		t.Errorf("bad access = %d", code)
	}
	var edit, view ShareLinkCreated
	if code := env.admin.do("POST", "/api/v1/sharelinks", map[string]any{"share": "docs", "path": "plan.docx", "access": "edit"}, &edit); code != 201 || edit.Link.Access != "edit" {
		t.Fatalf("edit link = %d %+v", code, edit.Link)
	}
	if code := env.admin.do("POST", "/api/v1/sharelinks", map[string]any{"share": "docs", "path": "plan.docx"}, &view); code != 201 || view.Link.Access != "view" {
		t.Fatalf("view link = %d %+v", code, view.Link)
	}
	visitor := &client{t: t, base: env.srv.URL}
	jar, _ := cookiejar.New(nil)
	visitor.http = &http.Client{Jar: jar, Timeout: 10 * time.Second}
	nr := noRedirect(visitor)

	// The link page offers the editor.
	if _, page := oget(t, nr, env.srv.URL+edit.URL); !strings.Contains(page, "Edit in the browser") {
		t.Fatalf("link page: %s", page)
	}
	// Asked for a name first.
	if _, page := oget(t, nr, env.srv.URL+edit.URL+"/office"); !strings.Contains(page, "Your name") {
		t.Fatalf("name form: %s", page)
	}
	// On the desktop's address the editor moves to the office origin.
	res, _ := oget(t, nr, env.srv.URL+edit.URL+"/office?name=Sam")
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != env.origin+edit.URL+"/office?name=Sam" {
		t.Fatalf("redirect = %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	res, page := oget(t, nr, env.origin+edit.URL+"/office?name=Sam")
	if res.StatusCode != 200 {
		t.Fatalf("editor = %d %s", res.StatusCode, page)
	}
	cfg := editorConfig(t, page)
	ec := cfg["editorConfig"].(map[string]any)
	if ec["mode"] != "edit" || ec["user"].(map[string]any)["name"] != "Sam (guest)" {
		t.Fatalf("edit link config %v", ec)
	}
	_, page = oget(t, nr, env.origin+view.URL+"/office?name=Sam")
	if ec := editorConfig(t, page)["editorConfig"].(map[string]any); ec["mode"] != "view" {
		t.Fatalf("view link opened %v", ec["mode"])
	}

	// A participant from an edit link writes as the creator while the link
	// is usable and still allows editing.
	ctx := context.Background()
	sessions, _ := env.s.office.svc.OpenSessions(ctx)
	if len(sessions) == 0 {
		t.Fatal("no session")
	}
	sess := sessions[0]
	p := office.Participant{Kind: office.KindLink, LinkID: edit.Link.ID, Name: "Sam (guest)"}
	if who, err := env.s.officeIdentity(ctx, p, sess, true); err != nil || who.Principal != "cade" {
		t.Fatalf("identity = %+v %v", who, err)
	}
	if _, err := env.s.officeIdentity(ctx, office.Participant{Kind: office.KindLink, LinkID: view.Link.ID}, sess, true); err == nil {
		t.Fatal("a view link may write")
	}
	if _, err := env.s.officeIdentity(ctx, p, &office.Session{Share: "docs", Path: "other.docx"}, true); err == nil {
		t.Fatal("an edit link may write another file")
	}
	env.admin.do("POST", "/api/v1/sharelinks/"+strconv.FormatInt(edit.Link.ID, 10)+"/revoke", nil, nil)
	if _, err := env.s.officeIdentity(ctx, p, sess, true); err == nil {
		t.Fatal("a revoked link may write")
	}
	if res, _ := oget(t, nr, env.origin+edit.URL+"/office?name=Sam"); res.StatusCode != http.StatusGone {
		t.Fatalf("revoked link editor = %d", res.StatusCode)
	}
}

// Security review M1: the proxy can't be talked into other Document Server
// paths with encoded slashes or dots, at the ServeMux level.
func TestOfficeProxyEncodedPaths(t *testing.T) {
	env := newOfficeEnv(t)
	put(t, env.fk.dirs["docs"], "plan.docx", "doc")
	var op OfficeOpened
	env.admin.do("POST", "/api/v1/office/open", map[string]string{"share": "docs", "path": "plan.docx"}, &op)
	if res, _ := oget(t, env.admin.http, op.URL); res.StatusCode != 200 {
		t.Fatalf("editor = %d", res.StatusCode)
	}
	nr := noRedirect(env.admin)
	for _, p := range []string{
		"/s/-/ds/%2Fcoauthoring/CommandService.ashx",
		"/s/-/ds/%2fcoauthoring/CommandService.ashx",
		"/s/-/ds//coauthoring/CommandService.ashx",
		"/s/-/ds/web-apps/%2E%2E/coauthoring/CommandService.ashx",
		"/s/-/ds/web-apps/%2e%2e/%2e%2e/converter",
		"/s/-/ds/web-apps/../coauthoring/CommandService.ashx",
		"/s/-/ds/9.4.0-129/%2Fcoauthoring/x",
		"/s/-/ds/coauthoring/CommandService.ashx",
		"/s/-/ds/info/info.json",
		"/s/-/ds/web-apps%5C..%5Ccoauthoring",
	} {
		u, err := url.Parse(env.origin + p)
		if err != nil {
			t.Fatal(err)
		}
		res, err := nr.Do(&http.Request{Method: "GET", URL: u, Header: http.Header{}})
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode == 200 {
			t.Errorf("%s = 200", p)
		}
	}
	for _, s := range env.seen() {
		low := strings.ToLower(s)
		if strings.Contains(low, "coauthoring") || strings.Contains(low, "converter") || strings.Contains(low, "info") {
			t.Fatalf("the Document Server got %q", s)
		}
	}
	// What's allowed is forwarded exactly as checked.
	res, body := oget(t, env.admin.http, env.origin+"/s/-/ds/9.4.0-129/web-apps/apps/a%20b.js")
	if res.StatusCode != 200 || body != "ds:/9.4.0-129/web-apps/apps/a b.js" {
		t.Fatalf("allowed path = %d %q", res.StatusCode, body)
	}
}

// Security review M2: turning a link off puts its visitors out of the
// document through the Document Server's command service.
func TestOfficeRevokeDropsVisitors(t *testing.T) {
	env := newOfficeEnv(t)
	put(t, env.fk.dirs["docs"], "plan.docx", "doc")
	var edit ShareLinkCreated
	env.admin.do("POST", "/api/v1/sharelinks", map[string]any{"share": "docs", "path": "plan.docx", "access": "edit"}, &edit)
	visitor := env.client(t)
	res, page := oget(t, noRedirect(visitor), env.origin+edit.URL+"/office?name=Sam")
	if res.StatusCode != 200 {
		t.Fatalf("editor = %d", res.StatusCode)
	}
	cfg := editorConfig(t, page)
	key := cfg["document"].(map[string]any)["key"].(string)
	pid := cfg["editorConfig"].(map[string]any)["user"].(map[string]any)["id"].(string)
	// The Document Server says Sam is in the document.
	secret, err := env.s.office.settings.Secret(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cb := map[string]any{"key": key, "status": 1, "users": []string{pid}}
	tok, _ := office.SignJWT(secret, map[string]any{"payload": cb, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix()})
	body, _ := json.Marshal(cb)
	env.s.office.mu.Lock()
	iaddr := env.s.office.iaddr
	env.s.office.mu.Unlock()
	req, _ := http.NewRequest("POST", "http://"+iaddr+"/office/callback/"+key, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	env.admin.do("POST", "/api/v1/sharelinks/"+strconv.FormatInt(edit.Link.ID, 10)+"/revoke", nil, nil)
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, s := range env.seen() {
			if strings.HasPrefix(s, office.CommandPath) && strings.Contains(s, `"drop"`) && strings.Contains(s, pid) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no drop command: %v", env.seen())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestOfficePlaceLabel(t *testing.T) {
	if got := placeLabel(`~home:home\alice`); got != "Home of alice" {
		t.Fatalf("%q", got)
	}
	if got := placeLabel("media"); got != "media" {
		t.Fatalf("%q", got)
	}
}
