package office

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/files"
)

// Security review of PR #31 (decisions 263-276).

// HIGH-1: every person's "~home" is a different folder; sessions are kept
// apart by the folder they really are.
func TestHomeFoldersAreSeparate(t *testing.T) {
	e := newEnv(t)
	alice, bob := t.TempDir(), t.TempDir()
	e.fs.homes = map[string]string{"alice": alice, "bob": bob}
	os.WriteFile(filepath.Join(alice, "plan.docx"), []byte("alice v1"), 0o644)
	os.WriteFile(filepath.Join(bob, "plan.docx"), []byte("bob v1"), 0o644)
	open := func(who string) *Editor {
		ed, err := e.svc.Open(context.Background(), OpenRequest{Who: files.Who{Principal: who}, Share: files.HomeShare, Path: "plan.docx",
			Kind: KindUser, Name: who, WantEdit: true, MayEdit: true})
		if err != nil {
			t.Fatal(err)
		}
		return ed
	}
	a, b := open("alice"), open("bob")
	if cfgKey(a) == cfgKey(b) {
		t.Fatal("two people's home folders share an editing session")
	}
	if a.Session.Location != "~home:alice" || b.Session.Location != "~home:bob" {
		t.Fatalf("locations %q %q", a.Session.Location, b.Session.Location)
	}
	// Bob's document came from Bob's home.
	h := e.svc.InternalHandler(func(netip.Addr) bool { return true })
	if w := fetchDoc(t, h, "127.0.0.1:1", b.Config["document"].(map[string]any)["url"].(string)); w.Body.String() != "bob v1" {
		t.Fatalf("bob got %q", w.Body.String())
	}
	e.join(cfgKey(a), a.Participant.ID)
	e.join(cfgKey(b), b.Participant.ID)
	// Alice's participant can't save into Bob's session.
	if _, err := e.callback(cfgKey(b), map[string]any{"key": cfgKey(b), "status": 6, "url": e.cacheURL("x"), "users": []string{a.Participant.ID}}); err == nil {
		t.Fatal("a participant of another home's session saved")
	}
	// A participant whose identity is now someone else can't write the home.
	e.as["bob"] = "alice"
	if _, err := e.callback(cfgKey(b), map[string]any{"key": cfgKey(b), "status": 6, "url": e.cacheURL("x"), "users": []string{b.Participant.ID}}); err == nil {
		t.Fatal("saved into a home folder as another person")
	}
	delete(e.as, "bob")
	if _, err := e.callback(cfgKey(b), map[string]any{"key": cfgKey(b), "status": 2, "url": e.cacheURL("bob v2"), "users": []string{b.Participant.ID}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(bob, "plan.docx")); string(got) != "bob v2" {
		t.Fatalf("bob's file %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(alice, "plan.docx")); string(got) != "alice v1" {
		t.Fatalf("alice's file changed: %q", got)
	}
}

// M1: the proxy allows only the editor's paths, checked as written.
func TestDSPathEncodedBypasses(t *testing.T) {
	bad := []string{
		"/%2Fcoauthoring/CommandService.ashx", "/%2fcoauthoring/CommandService.ashx", "//coauthoring/CommandService.ashx",
		"/web-apps/%2E%2E/coauthoring/CommandService.ashx", "/web-apps/%2e%2e/%2e%2e/info/info.json", "/web-apps/../converter",
		"/web-apps/%5C..%5Ccoauthoring", "/web-apps/./x", "/9.4.0-129/%2Fcoauthoring/", "/9.4.0-129//coauthoring/",
		"/coauthoring/CommandService.ashx", "/ConvertService.ashx", "/example/", "/info/info.json", "/sdkjs-plugins/x.js",
		"/admin", "/healthcheck", "/web-apps%2F../x", "/web-apps/a%00b", "/", "",
	}
	for _, p := range bad {
		if dsPathAllowed(p) {
			t.Errorf("allowed %q", p)
		}
	}
	good := []string{"/web-apps/apps/api/documents/api.js", "/9.4.0-129/web-apps/apps/documenteditor/main/index.html",
		"/doc/abcd/c/", "/cache/files/data/x/output.docx/output.docx", "/fonts/000", "/upload/k/u/1", "/dictionaries/en_US/en_US.dic",
		"/9.4.0-129/sdkjs/word/sdk-all.js", "/downloadas/k", "/printfile/k/x.pdf", "/web-apps/apps/a%20b.png"}
	for _, p := range good {
		if !dsPathAllowed(p) {
			t.Errorf("refused %q", p)
		}
	}
}

// M2: people who may no longer be in a document are put out of it.
func TestDropsInvalidParticipants(t *testing.T) {
	e := newEnv(t)
	e.write("plan.docx", "v1")
	a := e.open("plan.docx", "alice", true)
	s := e.open("plan.docx", "sam", true)
	key := cfgKey(a)
	e.join(key, a.Participant.ID, s.Participant.ID)
	if n := len(e.cmds()); n != 0 {
		t.Fatalf("commands before anything changed: %d", n)
	}
	// Sam's link is turned off: the next status-1 drops Sam.
	e.gone["sam"] = true
	e.join(key, a.Participant.ID, s.Participant.ID)
	waitFor(t, func() bool { return len(e.cmds()) == 1 })
	c := e.cmds()[0]
	if c["c"] != "drop" || c["key"] != key || len(c["users"].([]any)) != 1 || c["users"].([]any)[0] != s.Participant.ID {
		t.Fatalf("command %v", c)
	}
	// The sweep does the same without waiting for the Document Server.
	e.svc.Sweep(context.Background())
	if n := len(e.cmds()); n != 2 {
		t.Fatalf("sweep sent %d commands", n)
	}
	// DropLink puts a link's visitors out at once.
	e.svc.DropLink(context.Background(), 0, "turned off")
	if n := len(e.cmds()); n != 2 {
		t.Fatalf("drop for a link with no visitors: %d", n)
	}
	dropped := 0
	for _, a := range e.audits {
		if a.Action == "office.drop" {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("drops weren't audited")
	}
}

func (e *env) cmds() []map[string]any {
	e.cmdMu.Lock()
	defer e.cmdMu.Unlock()
	return append([]map[string]any(nil), e.commands...)
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out")
}

// M3: saves only from live sessions, by someone recently in the document.
func TestSavesNeedRecentActivity(t *testing.T) {
	e := newEnv(t)
	e.write("plan.docx", "v1")
	now := time.Now()
	e.svc.Now = func() time.Time { return now }
	a := e.open("plan.docx", "alice", true)
	b := e.open("plan.docx", "bob", true)
	key := cfgKey(a)
	save := func(id string) error {
		_, err := e.callback(key, map[string]any{"key": key, "status": 6, "url": e.cacheURL("x"), "users": []string{id}})
		return err
	}
	// Never reported in the document.
	if err := save(a.Participant.ID); !errors.Is(err, ErrCallbackUser) {
		t.Fatalf("never active: %v", err)
	}
	e.join(key, a.Participant.ID, b.Participant.ID)
	e.join(key, a.Participant.ID) // bob leaves
	if err := save(b.Participant.ID); err != nil {
		t.Fatalf("just left: %v", err)
	}
	now = now.Add(LeftGrace + time.Minute)
	if err := save(b.Participant.ID); !errors.Is(err, ErrCallbackUser) {
		t.Fatalf("left long ago: %v", err)
	}
	if err := save(a.Participant.ID); err != nil {
		t.Fatalf("still in it: %v", err)
	}
	// A Document Server that went quiet for a day takes no more saves.
	now = now.Add(MaxSessionQuiet + time.Minute)
	if err := save(a.Participant.ID); err == nil || !strings.Contains(err.Error(), "quiet") {
		t.Fatalf("quiet session: %v", err)
	}
	// And the sweep closes it, dropping its people.
	e.svc.Sweep(context.Background())
	sess, _ := e.svc.db().session(context.Background(), key)
	if sess.State != StateClosed {
		t.Fatalf("state %s", sess.State)
	}
	// An empty session is closed after half an hour.
	e.write("other.docx", "x")
	c := e.open("other.docx", "carol", true)
	now = now.Add(EmptySessionQuiet + time.Minute)
	e.svc.Sweep(context.Background())
	if sess, _ := e.svc.db().session(context.Background(), cfgKey(c)); sess.State != StateClosed {
		t.Fatalf("empty session %s", sess.State)
	}
}

// L1: only the formats the editor writes for the document type.
func TestSaveFormats(t *testing.T) {
	for orig, ft := range map[string]string{"docx": "docx", "odt": "docx", "xlsx": "csv", "pptx": "odp", "csv": "xlsx"} {
		if !SaveFormat(orig, ft) {
			t.Errorf("%s -> %s refused", orig, ft)
		}
	}
	for orig, ft := range map[string]string{"docx": "html", "xlsx": "docx", "pptx": "../x", "rtf": "DOCX", "odt": "averyverylongext", "x": "docx"} {
		if SaveFormat(orig, ft) {
			t.Errorf("%s -> %s allowed", orig, ft)
		}
	}
	e := newEnv(t)
	e.write("plan.docx", "v1")
	a := e.open("plan.docx", "alice", true)
	key := cfgKey(a)
	e.join(key, a.Participant.ID)
	if _, err := e.callback(key, map[string]any{"key": key, "status": 6, "url": e.cacheURL("<script>"), "filetype": "html", "users": []string{a.Participant.ID}}); err == nil {
		t.Fatal("saved as html")
	}
	entries, _ := os.ReadDir(e.dir)
	if len(entries) != 1 {
		t.Fatalf("files: %v", entries)
	}
}

// L4, L5, L6: caps on link editors, per address and pending downloads;
// coalesced audits; guest names; no download for view links.
func TestLinkLimits(t *testing.T) {
	e := newEnv(t)
	e.write("plan.docx", "v1")
	link := func(name, ip string) (*Editor, error) {
		return e.svc.Open(context.Background(), OpenRequest{Who: files.Who{Principal: "cade"}, Share: "docs", Path: "plan.docx",
			Kind: KindLink, LinkID: 9, Name: name, WantEdit: true, MayEdit: true, IP: ip, NoDownload: true})
	}
	for i := 0; i < LinkEditors; i++ {
		ed, err := link("v", "203.0.113.9")
		if err != nil || ed.Mode != ModeEdit {
			t.Fatalf("editor %d: %v %v", i, ed, err)
		}
		perms := ed.Config["document"].(map[string]any)["permissions"].(map[string]any)
		if perms["download"] != false || perms["print"] != false {
			t.Fatalf("download allowed: %v", perms)
		}
	}
	if ed, _ := link("v", "203.0.113.9"); ed.Mode != ModeView {
		t.Fatalf("6th editor through one link: %s", ed.Mode)
	}
	opens := 0
	for _, a := range e.audits {
		if a.Action == "office.open" {
			opens++
		}
	}
	if opens != 1 {
		t.Fatalf("audited %d openings from one visitor", opens)
	}
	for i := 0; i < IPOpens; i++ {
		if _, err := link("v", "198.51.100.1"); err != nil {
			if !errors.Is(err, ErrTooMany) {
				t.Fatal(err)
			}
			if i < IPOpens-LinkEditors-1 {
				t.Fatalf("refused after %d", i)
			}
			break
		}
	}
	if _, err := link("v", "198.51.100.1"); !errors.Is(err, ErrTooMany) {
		t.Fatalf("no per-address cap: %v", err)
	}
	if got := CleanGuestName(`Sam) (admin [x] "y" \z`); strings.ContainsAny(got, `()[]"\`) || got != "Sam admin x y z" {
		t.Fatalf("guest name %q", got)
	}
	// The pending downloads are bounded.
	e.svc.downloads = map[string]*download{}
	for i := 0; i < maxDownloads; i++ {
		e.svc.downloads[newID("")] = &download{expires: time.Now().Add(time.Hour)}
	}
	if _, err := e.svc.Open(context.Background(), OpenRequest{Who: files.Who{Principal: "alice"}, Share: "docs", Path: "plan.docx", Kind: KindUser, Name: "a"}); !errors.Is(err, ErrTooMany) {
		t.Fatalf("downloads cap: %v", err)
	}
}

// L3: files from the cache and uploads never run as a page.
func TestProxyFileResponses(t *testing.T) {
	ds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".pdf") {
			w.Header().Set("Content-Type", "application/pdf")
		} else {
			w.Header().Set("Content-Type", "text/html")
		}
		_, _ = w.Write([]byte("<script>x</script>"))
	}))
	defer ds.Close()
	in, _ := url.Parse(ds.URL)
	gate := &Gate{}
	p := &Proxy{Service: &Service{Internal: func() (*url.URL, error) { return in, nil }}, Gate: gate}
	get := func(path, dest string) http.Header {
		req := httptest.NewRequest(http.MethodGet, "https://nas:44250"+path, nil)
		set := httptest.NewRecorder()
		gate.Set(set, req)
		req.AddCookie(set.Result().Cookies()[0])
		if dest != "" {
			req.Header.Set("Sec-Fetch-Dest", dest)
		}
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		return w.Header()
	}
	h := get(DSPrefix+"/cache/files/data/k/media/a.html", "document")
	if !strings.HasPrefix(h.Get("Content-Disposition"), "attachment") || !strings.Contains(h.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("navigation to a cached file: %v", h)
	}
	h = get(DSPrefix+"/upload/k/u/1", "")
	if !strings.HasPrefix(h.Get("Content-Disposition"), "attachment") {
		t.Fatalf("upload without Sec-Fetch-Dest: %v", h)
	}
	h = get(DSPrefix+"/cache/files/data/k/media/a.html", "iframe")
	if !strings.Contains(h.Get("Content-Security-Policy"), "sandbox") || h.Get("Content-Disposition") != "" {
		t.Fatalf("framed: %v", h)
	}
	h = get(DSPrefix+"/cache/files/data/k/out.pdf", "iframe")
	if strings.Contains(h.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("framed pdf sandboxed: %v", h)
	}
	h = get(DSPrefix+"/cache/files/data/k/media/image1.png", "image")
	if h.Get("Content-Disposition") != "" || strings.Contains(h.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("editor fetch changed: %v", h)
	}
	h = get(DSPrefix+"/web-apps/apps/api/documents/api.js", "document")
	if h.Get("Content-Disposition") != "" {
		t.Fatalf("editor code: %v", h)
	}
}
