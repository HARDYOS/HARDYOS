package office

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// ---- JWT -------------------------------------------------------------------------

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func TestJWTRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tok, err := SignJWT(testSecret, map[string]any{"key": "abc", "exp": now.Add(time.Minute).Unix(), "iat": now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyJWT(testSecret, tok, VerifyOptions{Now: now, RequireExp: true})
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	_ = json.Unmarshal(claims, &c)
	if c["key"] != "abc" {
		t.Fatalf("claims = %s", claims)
	}
}

func TestJWTRefusals(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	good, _ := SignJWT(testSecret, map[string]any{"exp": now.Add(time.Minute).Unix()})
	parts := strings.Split(good, ".")
	enc := func(s string) string { return b64.EncodeToString([]byte(s)) }
	resign := func(head, body string) string {
		sig := b64.EncodeToString(mac(testSecret, head+"."+body))
		return head + "." + body + "." + sig
	}
	noExp, _ := SignJWT(testSecret, map[string]any{"a": 1})
	expired, _ := SignJWT(testSecret, map[string]any{"exp": now.Add(-5 * time.Minute).Unix()})
	future, _ := SignJWT(testSecret, map[string]any{"exp": now.Add(time.Hour).Unix(), "nbf": now.Add(10 * time.Minute).Unix()})
	old, _ := SignJWT(testSecret, map[string]any{"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-3 * time.Hour).Unix()})
	cases := []struct {
		name string
		tok  string
		want error
		opt  VerifyOptions
	}{
		{"other secret", func() string {
			t, _ := SignJWT([]byte("another secret, long enough!!"), map[string]any{"exp": now.Unix() + 60})
			return t
		}(), ErrTokenSignature, VerifyOptions{}},
		{"alg none", enc(`{"alg":"none"}`) + "." + parts[1] + ".", ErrTokenMalformed, VerifyOptions{}},
		{"alg none signed", resign(enc(`{"alg":"none","typ":"JWT"}`), parts[1]), ErrTokenAlg, VerifyOptions{}},
		{"alg RS256", resign(enc(`{"alg":"RS256","typ":"JWT"}`), parts[1]), ErrTokenAlg, VerifyOptions{}},
		{"kid header", resign(enc(`{"alg":"HS256","kid":"x"}`), parts[1]), ErrTokenAlg, VerifyOptions{}},
		{"crit header", resign(enc(`{"alg":"HS256","crit":["b64"]}`), parts[1]), ErrTokenAlg, VerifyOptions{}},
		{"tampered body", parts[0] + "." + enc(`{"exp":9999999999,"admin":true}`) + "." + parts[2], ErrTokenSignature, VerifyOptions{}},
		{"two parts", parts[0] + "." + parts[1], ErrTokenMalformed, VerifyOptions{}},
		{"huge", strings.Repeat("a", MaxTokenBytes+1), ErrTokenMalformed, VerifyOptions{}},
		{"body not object", resign(parts[0], enc(`[1,2]`)), ErrTokenMalformed, VerifyOptions{}},
		{"no exp", noExp, ErrTokenNoExpiry, VerifyOptions{RequireExp: true}},
		{"expired", expired, ErrTokenExpired, VerifyOptions{}},
		{"not yet", future, ErrTokenNotYet, VerifyOptions{}},
		{"too old", old, ErrTokenExpired, VerifyOptions{MaxAge: time.Hour}},
	}
	for _, c := range cases {
		c.opt.Now = now
		if _, err := VerifyJWT(testSecret, c.tok, c.opt); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := VerifyJWT(nil, good, VerifyOptions{Now: now}); err == nil {
		t.Error("an empty secret verified a token")
	}
	if _, err := SignJWT([]byte("short"), map[string]any{}); err == nil {
		t.Error("signed with a short secret")
	}
}

// ---- keys and formats ------------------------------------------------------------------

func TestDeriveKey(t *testing.T) {
	mod := time.Unix(1_800_000_000, 123)
	k := DeriveKey(testSecret, "docs", "a/b.docx", 10, mod, "n1")
	if !ValidKey(k) || len(k) != 40 || len(k) > MaxKeyLength {
		t.Fatalf("key %q isn't a valid document key", k)
	}
	if k != DeriveKey(testSecret, "docs", "a/b.docx", 10, mod, "n1") {
		t.Fatal("same input, different key")
	}
	others := []string{
		DeriveKey([]byte("another secret entirely......"), "docs", "a/b.docx", 10, mod, "n1"),
		DeriveKey(testSecret, "docs2", "a/b.docx", 10, mod, "n1"),
		DeriveKey(testSecret, "docs", "a/c.docx", 10, mod, "n1"),
		DeriveKey(testSecret, "docs", "a/b.docx", 11, mod, "n1"),
		DeriveKey(testSecret, "docs", "a/b.docx", 10, mod.Add(time.Nanosecond), "n1"),
		DeriveKey(testSecret, "docs", "a/b.docx", 10, mod, "n2"),
		// The separator stops share/path shifting into each other.
		DeriveKey(testSecret, "docsa", "/b.docx", 10, mod, "n1"),
	}
	for i, o := range others {
		if o == k {
			t.Errorf("variant %d gave the same key", i)
		}
	}
	for _, bad := range []string{"", "short", strings.Repeat("a", 39) + "/", strings.Repeat("a", 41)} {
		if ValidKey(bad) {
			t.Errorf("ValidKey(%q)", bad)
		}
	}
}

func TestFormats(t *testing.T) {
	for name, want := range map[string]string{"A.DOCX": "word", "b.xlsx": "cell", "c.pptx": "slide", "d.csv": "cell", "e.txt": "word", "f.odp": "slide"} {
		f, ok := FormatOf(name)
		if !ok || f.DocumentType != want || !f.Editable {
			t.Errorf("%s: %+v %v", name, f, ok)
		}
	}
	if f, ok := FormatOf("old.doc"); !ok || f.Editable {
		t.Errorf("doc should open read only: %+v", f)
	}
	for _, n := range []string{"x.pdf", "x.exe", "docx", "x.docx.zip"} {
		if _, ok := FormatOf(n); ok {
			t.Errorf("%s opens", n)
		}
	}
}

func TestBlankDocuments(t *testing.T) {
	for kind, ext := range NewKinds {
		b, err := Blank(kind)
		if err != nil {
			t.Fatal(err)
		}
		z, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		names := map[string]bool{}
		for _, f := range z.File {
			names[f.Name] = true
		}
		main := map[string]string{"docx": "word/document.xml", "xlsx": "xl/workbook.xml", "pptx": "ppt/presentation.xml"}[ext]
		if !names["[Content_Types].xml"] || !names["_rels/.rels"] || !names[main] {
			t.Errorf("%s: parts %v", kind, names)
		}
		again, _ := Blank(kind)
		if !bytes.Equal(b, again) {
			t.Errorf("%s isn't the same every time", kind)
		}
	}
	if _, err := Blank("macro"); err == nil {
		t.Error("unknown kind accepted")
	}
}

func TestCleanName(t *testing.T) {
	cases := map[string]string{
		"  Alice  ":              "Alice",
		"":                       "Guest",
		"a‮evil​\tname":          "aevil name",
		"line\nbreak":            "line break",
		strings.Repeat("x", 100): strings.Repeat("x", 64),
	}
	for in, want := range cases {
		if got := CleanName(in, "Guest"); got != want {
			t.Errorf("CleanName(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- a service over folders ----------------------------------------------------------------

// fakeFiles is office.Files over plain folders, one per share. Principals
// in readOnly can read but not change anything.
type fakeFiles struct {
	mu       sync.Mutex
	dirs     map[string]string
	readOnly map[string]bool
	reads    []string // principals that opened files
	writes   []string // principal + path written
}

func (f *fakeFiles) path(share, p string) (string, error) {
	d, ok := f.dirs[share]
	if !ok {
		return "", &files.Error{Kind: files.ErrNotFound, Msg: "no share"}
	}
	if strings.Contains(p, "..") {
		return "", &files.Error{Kind: files.ErrNotAllowed, Msg: "no"}
	}
	return filepath.Join(d, filepath.FromSlash(p)), nil
}

func mapErr(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return &files.Error{Kind: files.ErrNotFound, Msg: "not found"}
	}
	return err
}

func (f *fakeFiles) entry(full, p string, who files.Who) (*files.Entry, error) {
	fi, err := os.Stat(full)
	if err != nil {
		return nil, mapErr(err)
	}
	f.mu.Lock()
	ro := f.readOnly[who.Principal]
	f.mu.Unlock()
	return &files.Entry{Name: filepath.Base(p), Path: p, Dir: fi.IsDir(), Size: fi.Size(), Modified: fi.ModTime(), Writable: !ro}, nil
}

func (f *fakeFiles) Stat(_ context.Context, who files.Who, share, p string) (*files.Entry, error) {
	full, err := f.path(share, p)
	if err != nil {
		return nil, err
	}
	return f.entry(full, p, who)
}

func (f *fakeFiles) Open(_ context.Context, who files.Who, share, p string) (*os.File, *files.Entry, error) {
	full, err := f.path(share, p)
	if err != nil {
		return nil, nil, err
	}
	e, err := f.entry(full, p, who)
	if err != nil {
		return nil, nil, err
	}
	fh, err := os.Open(full)
	f.mu.Lock()
	f.reads = append(f.reads, who.Principal)
	f.mu.Unlock()
	return fh, e, err
}

func (f *fakeFiles) writable(who files.Who) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readOnly[who.Principal] {
		return &files.Error{Kind: files.ErrNoAccess, Msg: "read only"}
	}
	return nil
}

func (f *fakeFiles) Create(_ context.Context, who files.Who, share, p string, overwrite bool) (*os.File, error) {
	if err := f.writable(who); err != nil {
		return nil, err
	}
	full, err := f.path(share, p)
	if err != nil {
		return nil, err
	}
	flag := os.O_CREATE | os.O_WRONLY | os.O_EXCL
	if overwrite {
		flag = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}
	return os.OpenFile(full, flag, 0o644)
}

func (f *fakeFiles) OpenWrite(_ context.Context, who files.Who, share, p string) (*os.File, *files.Entry, error) {
	if err := f.writable(who); err != nil {
		return nil, nil, err
	}
	full, err := f.path(share, p)
	if err != nil {
		return nil, nil, err
	}
	fh, err := os.OpenFile(full, os.O_WRONLY, 0)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	e, _ := f.entry(full, p, who)
	return fh, e, nil
}

func (f *fakeFiles) Replace(_ context.Context, who files.Who, share, from, to string) error {
	if err := f.writable(who); err != nil {
		return err
	}
	a, _ := f.path(share, from)
	b, _ := f.path(share, to)
	f.mu.Lock()
	f.writes = append(f.writes, who.Principal+" "+to)
	f.mu.Unlock()
	return os.Rename(a, b)
}

func (f *fakeFiles) Rename(_ context.Context, who files.Who, share, from, toShare, to string) error {
	if err := f.writable(who); err != nil {
		return err
	}
	a, _ := f.path(share, from)
	b, _ := f.path(toShare, to)
	if _, err := os.Stat(b); err == nil {
		return &files.Error{Kind: files.ErrExists, Msg: "exists"}
	}
	f.mu.Lock()
	f.writes = append(f.writes, who.Principal+" "+to)
	f.mu.Unlock()
	return os.Rename(a, b)
}

func (f *fakeFiles) DeleteItem(_ context.Context, _ files.Who, share, p string, _ bool) (bool, error) {
	full, _ := f.path(share, p)
	return false, os.Remove(full)
}

type env struct {
	t      *testing.T
	svc    *Service
	fs     *fakeFiles
	dir    string
	ds     *httptest.Server
	dsMu   sync.Mutex
	dsFile map[string][]byte // path under /cache/files/ -> content
	// noWrite: principals Identity refuses to write as.
	noWrite map[string]bool
	audits  []AuditEvent
	amu     sync.Mutex
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	dir := t.TempDir()
	e := &env{t: t, dir: dir, dsFile: map[string][]byte{}, noWrite: map[string]bool{},
		fs: &fakeFiles{dirs: map[string]string{"docs": dir}, readOnly: map[string]bool{}}}
	e.ds = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.dsMu.Lock()
		b, ok := e.dsFile[r.URL.Path]
		e.dsMu.Unlock()
		if !ok || r.URL.Query().Get("md5") != "sig" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(e.ds.Close)
	in, _ := url.Parse(e.ds.URL)
	e.svc = &Service{
		DB: db, Files: e.fs,
		Secret:       func(context.Context) ([]byte, error) { return testSecret, nil },
		Internal:     func() (*url.URL, error) { return in, nil },
		CallbackBase: func() string { return "http://host.docker.internal:44251" },
		Identity: func(_ context.Context, p Participant, _ *Session, write bool) (files.Who, error) {
			who := files.Who{Principal: p.Name}
			if write && e.noWrite[p.Name] {
				return files.Who{}, errors.New("no longer allowed")
			}
			return who, nil
		},
		Audit: func(_ context.Context, a AuditEvent) {
			e.amu.Lock()
			e.audits = append(e.audits, a)
			e.amu.Unlock()
		},
	}
	return e
}

func (e *env) write(name, content string) {
	if err := os.WriteFile(filepath.Join(e.dir, name), []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) read(name string) string {
	b, _ := os.ReadFile(filepath.Join(e.dir, name))
	return string(b)
}

func (e *env) open(name, who string, edit bool) *Editor {
	e.t.Helper()
	ed, err := e.svc.Open(context.Background(), OpenRequest{Who: files.Who{Principal: who}, Share: "docs", Path: name,
		Kind: KindUser, UserID: 7, Name: who, WantEdit: edit, MayEdit: true})
	if err != nil {
		e.t.Fatal(err)
	}
	return ed
}

// cacheURL puts content in the fake Document Server's cache.
func (e *env) cacheURL(content string) string {
	p := "/cache/files/data/" + newID("") + "/output.docx/output.docx"
	e.dsMu.Lock()
	e.dsFile[p] = []byte(content)
	e.dsMu.Unlock()
	return e.ds.URL + p + "?md5=sig&expires=99"
}

// signed is a callback as the Document Server sends it (token in the header).
func signed(t *testing.T, secret []byte, cb map[string]any) (string, []byte) {
	t.Helper()
	tok, err := SignJWT(secret, map[string]any{"payload": cb, "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(cb)
	return "Bearer " + tok, body
}

func (e *env) callback(key string, cb map[string]any) (*CallbackResult, error) {
	e.t.Helper()
	h, body := signed(e.t, testSecret, cb)
	parsed, err := ParseCallback(testSecret, h, body, time.Now())
	if err != nil {
		return nil, err
	}
	return e.svc.HandleCallback(context.Background(), key, parsed)
}

func cfgKey(ed *Editor) string { return ed.Config["document"].(map[string]any)["key"].(string) }

// ---- opening -----------------------------------------------------------------------------

func TestOpenConfigSignedAndShared(t *testing.T) {
	e := newEnv(t)
	e.write("plan.docx", "v1")
	a := e.open("plan.docx", "alice", true)
	if a.Mode != ModeEdit {
		t.Fatalf("mode %s (%s)", a.Mode, a.ViewReason)
	}
	b := e.open("plan.docx", "bob", true)
	if cfgKey(a) != cfgKey(b) {
		t.Fatal("two people opening the same file got different document keys (no co-editing)")
	}
	tok, _ := a.Config["token"].(string)
	claims, err := VerifyJWT(testSecret, tok, VerifyOptions{RequireExp: true})
	if err != nil {
		t.Fatalf("config token: %v", err)
	}
	var c struct {
		Document struct {
			Key, URL string
		}
		EditorConfig struct {
			CallbackURL string `json:"callbackUrl"`
			User        struct{ ID, Name string }
			Mode        string
		}
		Exp int64 `json:"exp"`
	}
	_ = json.Unmarshal(claims, &c)
	if c.Document.Key != cfgKey(a) || !strings.HasPrefix(c.Document.URL, "http://host.docker.internal:44251/office/file/") ||
		c.EditorConfig.CallbackURL != "http://host.docker.internal:44251/office/callback/"+cfgKey(a) ||
		c.EditorConfig.User.ID != a.Participant.ID || c.EditorConfig.User.Name != "alice" || c.EditorConfig.Mode != "edit" {
		t.Fatalf("signed config: %s", claims)
	}
	if time.Until(time.Unix(c.Exp, 0)) > ConfigLifetime+time.Second {
		t.Fatalf("config token lives too long: %v", time.Until(time.Unix(c.Exp, 0)))
	}
	cust := a.Config["editorConfig"].(map[string]any)["customization"].(map[string]any)
	if cust["plugins"] != false || cust["macros"] != false {
		t.Fatalf("plugins/macros not off: %v", cust)
	}
}

func TestOpenReadOnlyReasons(t *testing.T) {
	e := newEnv(t)
	e.write("a.docx", "x")
	e.write("old.doc", "x")
	e.write("big.docx", "0123456789")
	e.fs.readOnly["carol"] = true
	if ed := e.open("a.docx", "carol", true); ed.Mode != ModeView || ed.ViewReason == "" {
		t.Errorf("read-only person: %s %q", ed.Mode, ed.ViewReason)
	}
	if ed := e.open("old.doc", "alice", true); ed.Mode != ModeView || !strings.Contains(ed.ViewReason, ".docx") {
		t.Errorf("binary format: %s %q", ed.Mode, ed.ViewReason)
	}
	ed, _ := e.svc.Open(context.Background(), OpenRequest{Who: files.Who{Principal: "x"}, Share: "docs", Path: "a.docx", Kind: KindLink, LinkID: 3, Name: "Sam", WantEdit: true, MayEdit: false})
	if ed.Mode != ModeView {
		t.Error("a view link opened for editing")
	}
	if ed := e.open("a.docx", "alice", false); ed.Mode != ModeView || ed.ViewReason != "" {
		t.Errorf("asked to view: %s %q", ed.Mode, ed.ViewReason)
	}
	for _, p := range []string{"a.exe", "nothere.docx"} {
		if _, err := e.svc.Open(context.Background(), OpenRequest{Who: files.Who{Principal: "a"}, Share: "docs", Path: p, WantEdit: true, MayEdit: true}); err == nil {
			t.Errorf("%s opened", p)
		}
	}
	e.svc.MaxFileBytes = func() int64 { return 1 }
	if _, err := e.svc.Open(context.Background(), OpenRequest{Who: files.Who{Principal: "a"}, Share: "docs", Path: "big.docx", Kind: KindUser}); !errors.Is(err, ErrTooBig) {
		t.Errorf("too big: %v", err)
	}
}

func TestEditorLimit(t *testing.T) {
	e := newEnv(t)
	e.write("a.docx", "x")
	e.write("b.docx", "x")
	ed := e.open("a.docx", "p0", true)
	var ids []string
	for i := 0; i < EditorLimit; i++ {
		x := e.open("a.docx", "p"+string(rune('a'+i)), true)
		ids = append(ids, x.Participant.ID)
	}
	if _, err := e.callback(cfgKey(ed), map[string]any{"key": cfgKey(ed), "status": 1, "users": ids}); err != nil {
		t.Fatal(err)
	}
	if got := e.open("b.docx", "late", true); got.Mode != ModeView || !strings.Contains(got.ViewReason, "20") {
		t.Fatalf("21st editor: %s %q", got.Mode, got.ViewReason)
	}
	// Unknown ids from the Document Server don't count.
	if _, err := e.callback(cfgKey(ed), map[string]any{"key": cfgKey(ed), "status": 1, "users": []string{"pforged", ids[0]}}); err != nil {
		t.Fatal(err)
	}
	if got := e.open("b.docx", "late2", true); got.Mode != ModeEdit {
		t.Fatalf("after people left: %s", got.Mode)
	}
}

// ---- downloads -----------------------------------------------------------------------------

func fetchDoc(t *testing.T, h http.Handler, peer, rawURL string) *httptest.ResponseRecorder {
	t.Helper()
	u, _ := url.Parse(rawURL)
	req := httptest.NewRequest(http.MethodGet, u.Path, nil)
	req.RemoteAddr = peer
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestDownloadOneTimeAndScoped(t *testing.T) {
	e := newEnv(t)
	e.write("a.docx", "contents of a")
	e.write("b.docx", "contents of b")
	ed := e.open("a.docx", "alice", true)
	docURL := ed.Config["document"].(map[string]any)["url"].(string)
	allow := func(a netip.Addr) bool { return a.IsLoopback() || netip.MustParsePrefix("172.17.0.0/16").Contains(a) }
	h := e.svc.InternalHandler(allow)

	if w := fetchDoc(t, h, "192.168.1.50:1234", docURL); w.Code != http.StatusForbidden {
		t.Fatalf("LAN peer: %d", w.Code)
	}
	w := fetchDoc(t, h, "172.17.0.2:5555", docURL)
	if w.Code != http.StatusOK || w.Body.String() != "contents of a" {
		t.Fatalf("download: %d %q", w.Code, w.Body.String())
	}
	if got := e.fs.reads; len(got) != 1 || got[0] != "alice" {
		t.Fatalf("read as %v, want alice", got)
	}
	if w := fetchDoc(t, h, "172.17.0.2:5555", docURL); w.Code != http.StatusNotFound {
		t.Fatalf("second use: %d", w.Code)
	}
	// The token names one file: changing the path's other parts gets nothing else.
	for _, p := range []string{"/office/file/" + strings.Repeat("0", 64), "/office/file/../callback/x", "/office/file/b.docx", "/office/file/"} {
		if w := fetchDoc(t, h, "127.0.0.1:1", "http://x"+p); w.Code == http.StatusOK {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	// Expired.
	ed2 := e.open("b.docx", "alice", true)
	u2 := ed2.Config["document"].(map[string]any)["url"].(string)
	e.svc.Now = func() time.Time { return time.Now().Add(DownloadLifetime + time.Minute) }
	if w := fetchDoc(t, h, "127.0.0.1:1", u2); w.Code != http.StatusNotFound {
		t.Fatalf("expired: %d", w.Code)
	}
}

// ---- callbacks -----------------------------------------------------------------------------

func TestCallbackSavesAsLastEditor(t *testing.T) {
	e := newEnv(t)
	e.write("plan.docx", "v1")
	a := e.open("plan.docx", "alice", true)
	b := e.open("plan.docx", "bob", true)
	key := cfgKey(a)
	if _, err := e.callback(key, map[string]any{"key": key, "status": 1, "users": []string{a.Participant.ID, b.Participant.ID}}); err != nil {
		t.Fatal(err)
	}
	// Force save while open, by bob.
	res, err := e.callback(key, map[string]any{"key": key, "status": 6, "url": e.cacheURL("v2"), "users": []string{b.Participant.ID}})
	if err != nil || res.Saved != "plan.docx" || res.Conflict {
		t.Fatalf("force save: %+v %v", res, err)
	}
	if e.read("plan.docx") != "v2" {
		t.Fatalf("content %q", e.read("plan.docx"))
	}
	// Everyone closes; alice made the last change.
	res, err = e.callback(key, map[string]any{"key": key, "status": 2, "url": e.cacheURL("v3"), "users": []string{a.Participant.ID}})
	if err != nil || res.Conflict {
		t.Fatalf("final save: %+v %v", res, err)
	}
	if e.read("plan.docx") != "v3" {
		t.Fatalf("content %q", e.read("plan.docx"))
	}
	if got := e.fs.writes; len(got) != 2 || got[0] != "bob plan.docx" || got[1] != "alice plan.docx" {
		t.Fatalf("writes %v", got)
	}
	var wrote int
	for _, a := range e.audits {
		if a.Action == "files.write" {
			wrote++
		}
	}
	if wrote != 2 {
		t.Fatalf("audited %d writes", wrote)
	}
	// The session is over: opening again starts a new one.
	if c := e.open("plan.docx", "alice", true); cfgKey(c) == key {
		t.Fatal("a closed session was reused")
	}
}

func TestCallbackReplayAndForgery(t *testing.T) {
	e := newEnv(t)
	e.write("plan.docx", "v1")
	a := e.open("plan.docx", "alice", true)
	key := cfgKey(a)
	cb := map[string]any{"key": key, "status": 2, "url": e.cacheURL("v2"), "users": []string{a.Participant.ID}}
	if _, err := e.callback(key, cb); err != nil {
		t.Fatal(err)
	}
	e.write("plan.docx", "changed later by someone else")
	// The same callback again: acknowledged, never written twice.
	res, err := e.callback(key, cb)
	if err != nil || !res.Duplicate {
		t.Fatalf("replay: %+v %v", res, err)
	}
	if e.read("plan.docx") != "changed later by someone else" {
		t.Fatal("a replayed callback wrote the file again")
	}
	// A new callback for the closed session: refused.
	if _, err := e.callback(key, map[string]any{"key": key, "status": 2, "url": e.cacheURL("evil"), "users": []string{a.Participant.ID}}); !errors.Is(err, ErrCallbackSession) {
		t.Fatalf("after close: %v", err)
	}

	// Forged: another secret, through the HTTP handler.
	b := e.open("plan.docx", "alice", true)
	h := e.svc.InternalHandler(func(netip.Addr) bool { return true })
	post := func(key, auth string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/office/callback/"+key, bytes.NewReader(body))
		req.RemoteAddr = "172.17.0.2:1"
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	evil := map[string]any{"key": cfgKey(b), "status": 2, "url": e.cacheURL("forged"), "users": []string{b.Participant.ID}}
	hdr, body := signed(t, []byte("not the office secret, but long"), evil)
	if w := post(cfgKey(b), hdr, body); w.Code != http.StatusForbidden {
		t.Fatalf("forged signature: %d %s", w.Code, w.Body.String())
	}
	// Unsigned body.
	if w := post(cfgKey(b), "", body); w.Code != http.StatusForbidden {
		t.Fatalf("unsigned: %d", w.Code)
	}
	// Signed, but the body's own fields say something else: the signed payload counts.
	hdr, _ = signed(t, testSecret, map[string]any{"key": cfgKey(b), "status": 1, "users": []string{}})
	if w := post(cfgKey(b), hdr, body); w.Code != http.StatusOK {
		t.Fatalf("status 1: %d", w.Code)
	}
	if e.read("plan.docx") != "changed later by someone else" {
		t.Fatal("unsigned body fields were acted on")
	}
	// A good signed save works through the handler.
	hdr, body = signed(t, testSecret, map[string]any{"key": cfgKey(b), "status": 2, "url": e.cacheURL("v3"), "users": []string{b.Participant.ID}})
	if w := post(cfgKey(b), hdr, body); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"error":0`) {
		t.Fatalf("good: %d %s", w.Code, w.Body.String())
	}
}

func TestCallbackWrongFile(t *testing.T) {
	e := newEnv(t)
	e.write("a.docx", "A")
	e.write("b.docx", "B")
	a := e.open("a.docx", "alice", true)
	b := e.open("b.docx", "alice", true)
	// A callback signed for a's key, posted to b's callback URL.
	if _, err := e.callback(cfgKey(b), map[string]any{"key": cfgKey(a), "status": 2, "url": e.cacheURL("X"), "users": []string{a.Participant.ID}}); !errors.Is(err, ErrCallbackKey) {
		t.Fatalf("mismatched key: %v", err)
	}
	// b's key, naming a participant of a.
	if _, err := e.callback(cfgKey(b), map[string]any{"key": cfgKey(b), "status": 2, "url": e.cacheURL("X"), "users": []string{a.Participant.ID}}); !errors.Is(err, ErrCallbackUser) {
		t.Fatalf("participant of another session: %v", err)
	}
	// An unknown key.
	fake := DeriveKey(testSecret, "docs", "c.docx", 1, time.Now(), "z")
	if _, err := e.callback(fake, map[string]any{"key": fake, "status": 2, "url": e.cacheURL("X"), "users": []string{"p1"}}); !errors.Is(err, ErrCallbackSession) {
		t.Fatalf("unknown key: %v", err)
	}
	if e.read("a.docx") != "A" || e.read("b.docx") != "B" {
		t.Fatal("a refused callback wrote a file")
	}
}

func TestCallbackLostWriteAccess(t *testing.T) {
	e := newEnv(t)
	e.write("plan.docx", "v1")
	a := e.open("plan.docx", "alice", true)
	v := e.open("plan.docx", "victor", false)
	key := cfgKey(a)
	// A viewer named as the last editor: refused.
	if _, err := e.callback(key, map[string]any{"key": key, "status": 6, "url": e.cacheURL("v"), "users": []string{v.Participant.ID}}); !errors.Is(err, ErrCallbackUser) {
		t.Fatalf("viewer: %v", err)
	}
	// Alice's account loses write access (Identity refuses).
	e.noWrite["alice"] = true
	if _, err := e.callback(key, map[string]any{"key": key, "status": 6, "url": e.cacheURL("v2"), "users": []string{a.Participant.ID}}); err == nil {
		t.Fatal("saved for someone who lost access")
	}
	delete(e.noWrite, "alice")
	// The folder's permissions changed: the file system says no.
	e.fs.readOnly["alice"] = true
	if _, err := e.callback(key, map[string]any{"key": key, "status": 2, "url": e.cacheURL("v3"), "users": []string{a.Participant.ID}}); err == nil {
		t.Fatal("saved over a file alice can't change")
	}
	if e.read("plan.docx") != "v1" {
		t.Fatalf("file changed: %q", e.read("plan.docx"))
	}
	sess, _ := e.svc.db().session(context.Background(), key)
	if sess.State != StateError || sess.Error == "" {
		t.Fatalf("session %s %q", sess.State, sess.Error)
	}
	denied := 0
	for _, a := range e.audits {
		if a.Action == "office.save" && a.Outcome == "denied" {
			denied++
		}
	}
	if denied < 3 {
		t.Fatalf("audited %d refusals", denied)
	}
}

func TestCallbackConflictCopy(t *testing.T) {
	e := newEnv(t)
	e.write("plan.docx", "v1")
	a := e.open("plan.docx", "alice", true)
	key := cfgKey(a)
	// Someone changes the file outside the editor (SMB, another app).
	time.Sleep(10 * time.Millisecond)
	e.write("plan.docx", "changed over SMB")
	res, err := e.callback(key, map[string]any{"key": key, "status": 2, "url": e.cacheURL("edited"), "users": []string{a.Participant.ID}})
	if err != nil || !res.Conflict || !strings.HasPrefix(res.Saved, "plan (edited by alice ") || !strings.HasSuffix(res.Saved, ").docx") {
		t.Fatalf("conflict: %+v %v", res, err)
	}
	if e.read("plan.docx") != "changed over SMB" || e.read(res.Saved) != "edited" {
		t.Fatal("the other change was overwritten")
	}
}

func TestCallbackURLMustBeDocumentServerCache(t *testing.T) {
	e := newEnv(t)
	e.write("plan.docx", "v1")
	a := e.open("plan.docx", "alice", true)
	key := cfgKey(a)
	e.svc.NoteBase("https://nas.lan:44250/s/-/ds")
	good := e.cacheURL("via proxy")
	gu, _ := url.Parse(good)
	viaProxy := "https://nas.lan:44250/s/-/ds" + gu.RequestURI()
	bad := []string{
		"http://169.254.169.254/cache/files/x",
		"http://192.168.1.1/cache/files/x",
		"https://evil.example/s/-/ds/cache/files/x",
		e.ds.URL + "/info/info.json",
		e.ds.URL + "/cache/files/../../etc/passwd",
		e.ds.URL + "/cache/files/%2e%2e/%2e%2e/x",
		e.ds.URL + "/cache/files/a%2fb",
		"https://nas.lan:44250/s/-/dsX/cache/files/x",
		"https://nas.lan:44250/other/cache/files/x",
		"file:///etc/passwd",
		"http://user:pw@" + strings.TrimPrefix(e.ds.URL, "http://") + "/cache/files/x",
	}
	for _, u := range bad {
		if _, err := e.svc.InternalURL(u); err == nil {
			t.Errorf("accepted %s", u)
		}
	}
	in, err := e.svc.InternalURL(viaProxy)
	if err != nil || !strings.HasPrefix(in.String(), e.ds.URL+"/cache/files/") || in.Query().Get("md5") != "sig" {
		t.Fatalf("proxy URL: %v %v", in, err)
	}
	res, err := e.callback(key, map[string]any{"key": key, "status": 2, "url": viaProxy, "users": []string{a.Participant.ID}})
	if err != nil || e.read("plan.docx") != "via proxy" {
		t.Fatalf("save via proxy URL: %+v %v", res, err)
	}
	// After a restart (no bases noted), the public origins are still known.
	e.svc.bases = nil
	if _, err := e.svc.InternalURL(viaProxy); err == nil {
		t.Fatal("accepted a base nobody vouched for")
	}
	e.svc.PublicBase = func(scheme, host string) bool { return host == "nas.lan:44250" }
	if _, err := e.svc.InternalURL(viaProxy); err != nil {
		t.Fatalf("public base: %v", err)
	}
	if _, err := e.svc.InternalURL("https://nas.lan:44250/elsewhere/cache/files/x"); err == nil {
		t.Fatal("accepted a path outside the proxy prefix")
	}
}

func TestCallbackSizeLimit(t *testing.T) {
	e := newEnv(t)
	e.write("plan.docx", "v1")
	a := e.open("plan.docx", "alice", true)
	key := cfgKey(a)
	e.svc.MaxFileBytes = func() int64 { return 4 }
	if _, err := e.callback(key, map[string]any{"key": key, "status": 6, "url": e.cacheURL("way too big"), "users": []string{a.Participant.ID}}); err == nil {
		t.Fatal("saved more than the limit")
	}
	if e.read("plan.docx") != "v1" {
		t.Fatal("file changed")
	}
	entries, _ := os.ReadDir(e.dir)
	for _, d := range entries {
		if strings.HasPrefix(d.Name(), ".hardyos-upload-") {
			t.Fatalf("temporary file left: %s", d.Name())
		}
	}
}

func TestParseCallbackBodyToken(t *testing.T) {
	cb := map[string]any{"key": DeriveKey(testSecret, "a", "b", 1, time.Now(), ""), "status": 4}
	cb["iat"] = time.Now().Unix()
	cb["exp"] = time.Now().Add(time.Minute).Unix()
	tok, _ := SignJWT(testSecret, cb)
	body, _ := json.Marshal(map[string]any{"key": "ignored", "status": 2, "token": tok})
	got, err := ParseCallback(testSecret, "", body, time.Now())
	if err != nil || got.Status != 4 {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := ParseCallback(testSecret, "Basic abc", body, time.Now()); err == nil {
		t.Fatal("accepted a Basic header")
	}
}

// ---- proxy --------------------------------------------------------------------------------

func TestDSPathAllowed(t *testing.T) {
	ok := []string{"/web-apps/apps/api/documents/api.js", "/9.4.0-129/web-apps/apps/documenteditor/main/index.html",
		"/doc/abc/c/", "/cache/files/data/x/output.docx/output.docx", "/sdkjs/word/sdk-all.js", "/fonts/000"}
	bad := []string{"/coauthoring/CommandService.ashx", "/ConvertService.ashx", "/converter", "/command", "/docbuilder",
		"/info/info.json", "/example/", "/admin", "/9.4.0-129/sdkjs-plugins/x.js", "/internal/cluster/inactive", "/healthcheck",
		"/web-apps/../coauthoring/", "relative", "/a\\b", "/9.4.0-129/coauthoring/CommandService.ashx"}
	for _, p := range ok {
		if !dsPathAllowed(p) {
			t.Errorf("refused %s", p)
		}
	}
	for _, p := range bad {
		if dsPathAllowed(p) {
			t.Errorf("allowed %s", p)
		}
	}
}

func TestProxyGateAndHeaders(t *testing.T) {
	var got *http.Request
	ds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Set-Cookie", "ds=1")
		_, _ = io.WriteString(w, "ok")
	}))
	defer ds.Close()
	in, _ := url.Parse(ds.URL)
	svc := &Service{Internal: func() (*url.URL, error) { return in, nil }}
	gate := &Gate{}
	p := &Proxy{Service: svc, Gate: gate}

	req := httptest.NewRequest(http.MethodGet, "https://nas.lan:44250/s/-/ds/web-apps/apps/api/documents/api.js", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("without the gate cookie: %d", w.Code)
	}
	// Get a cookie for this host.
	set := httptest.NewRecorder()
	gate.Set(set, req)
	cookie := set.Result().Cookies()[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.Name != GateCookie {
		t.Fatalf("gate cookie %+v", cookie)
	}
	req = httptest.NewRequest(http.MethodGet, "https://nas.lan:44250/s/-/ds/web-apps/apps/api/documents/api.js", nil)
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: "__Host-hardyos_session", Value: "desktop-secret"})
	w = httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("with the cookie: %d", w.Code)
	}
	if got.URL.Path != "/web-apps/apps/api/documents/api.js" || got.Header.Get("X-Forwarded-Host") != "nas.lan:44250/s/-/ds" ||
		got.Header.Get("X-Forwarded-Proto") != "https" || got.Header.Get("Cookie") != "" {
		t.Fatalf("upstream request: %s %v", got.URL.Path, got.Header)
	}
	if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-Frame-Options") != "" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'self'") {
		t.Fatalf("response headers %v", w.Header())
	}
	// The cookie is for its own host only.
	req = httptest.NewRequest(http.MethodGet, "https://files.example.com/s/-/ds/web-apps/x.js", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cookie on another host: %d", w.Code)
	}
	// Blocked paths never reach the Document Server.
	got = nil
	req = httptest.NewRequest(http.MethodPost, "https://nas.lan:44250/s/-/ds/coauthoring/CommandService.ashx", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound || got != nil {
		t.Fatalf("command service: %d", w.Code)
	}
	// Expired cookie.
	gate.Now = func() time.Time { return time.Now().Add(GateLifetime + time.Minute) }
	req = httptest.NewRequest(http.MethodGet, "https://nas.lan:44250/s/-/ds/web-apps/x.js", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	p.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expired cookie: %d", w.Code)
	}
}

func TestEditorPage(t *testing.T) {
	e := newEnv(t)
	e.write("a.docx", "x")
	ed := e.open("a.docx", "alice", true)
	w := httptest.NewRecorder()
	ServeEditor(w, ed, `a "<b>".docx`, "", "https://nas.lan")
	body := w.Body.String()
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors https://nas.lan") || strings.Contains(csp, "unsafe-eval") {
		t.Fatalf("csp %q", csp)
	}
	if strings.Contains(body, "<b>") || !strings.Contains(body, "/s/-/ds/web-apps/apps/api/documents/api.js") {
		t.Fatalf("page %s", body)
	}
}
