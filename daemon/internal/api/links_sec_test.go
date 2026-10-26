package api

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sharelinks"
	"github.com/hardyos/hardyos/daemon/internal/sharelinks/linktest"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestLogPath(t *testing.T) {
	for in, want := range map[string]string{
		"/s/" + strings.Repeat("A", 43):               "/s/…",
		"/s/" + strings.Repeat("A", 43) + "/download": "/s/…/download",
		"/s/anything/unlock":                          "/s/…/unlock",
		"/s/-/static/style.css":                       "/s/-/static/style.css",
		"/api/v1/files/list":                          "/api/v1/files/list",
		"/":                                           "/",
		"/s":                                          "/s",
	} {
		if got := logPath(in); got != want {
			t.Errorf("logPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// Share link tokens never reach the log; the client address comes from a
// trusted proxy's X-Forwarded-For only; new link settings are saved.
func TestShareLinkLogsSettingsAndProxy(t *testing.T) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	logs := &lockedBuffer{}
	fake := linktest.New(t.TempDir(), "media")
	fake.Write("media", "Drop/a.txt", "A")
	srv := httptest.NewServer(New(Config{
		DB: db, Insecure: true, Files: fake,
		Logger:         slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")},
	}))
	t.Cleanup(func() {
		srv.Close()
		db.Close()
	})
	admin := (&testEnv{srv: srv}).client(t)
	if code := admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil); code != 201 {
		t.Fatalf("setup = %d", code)
	}
	var er ErrorResponse
	if code := admin.do("POST", "/api/v1/sharelinks", map[string]any{"share": "media", "path": "Drop", "allowUpload": true, "maxUploadBytes": 5}, &er); code != 400 || !strings.Contains(er.Message, "upload limit") {
		t.Fatalf("tiny upload budget = %d %v", code, er)
	}
	var made ShareLinkCreated
	if code := admin.do("POST", "/api/v1/sharelinks", map[string]any{"share": "media", "path": "Drop", "allowUpload": true,
		"maxUploadBytes": 2_000_000_000, "maxZipBytes": 3_000_000_000}, &made); code != 201 {
		t.Fatalf("create = %d", code)
	}
	if made.Link.MaxUploadBytes != 2_000_000_000 || made.Link.MaxZipBytes != 3_000_000_000 || made.Link.UploadedBytes != 0 {
		t.Fatalf("settings = %+v", made.Link)
	}
	var def ShareLinkCreated
	admin.do("POST", "/api/v1/sharelinks", map[string]any{"share": "media", "path": "Drop"}, &def)
	if def.Link.MaxUploadBytes != 0 || def.Link.MaxZipBytes != sharelinks.DefaultZipBytes {
		t.Fatalf("defaults = %+v", def.Link)
	}

	req, _ := http.NewRequest("GET", srv.URL+made.URL+"/download?path=a.txt", nil)
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(b) != "A" {
		t.Fatalf("download = %d %q", res.StatusCode, b)
	}
	var entries []map[string]any
	admin.do("GET", "/api/v1/audit", nil, &entries)
	found := false
	for _, a := range entries {
		if a["action"] == "sharelink.download" {
			found = true
			if a["ip"] != "203.0.113.9" {
				t.Errorf("download audited from %v", a["ip"])
			}
		}
	}
	if !found {
		t.Fatalf("no download audit: %v", entries)
	}

	out := logs.String()
	for _, tok := range []string{made.Token, def.Token} {
		if strings.Contains(out, tok) {
			t.Fatalf("a share link token was logged:\n%s", out)
		}
	}
	if !strings.Contains(out, "/s/…/download") {
		t.Fatalf("link requests not logged redacted:\n%s", out)
	}
}

func TestFilesZipNamesAndPermanentCancel(t *testing.T) {
	_, fk, admin, _ := newFilesEnv(t)
	media := fk.dirs["media"]
	put(t, media, `Odd/a\b.txt`, "1")
	put(t, media, "Odd/c:d.txt", "2")
	put(t, media, "Odd/bell\x07.txt", "3")
	put(t, media, `Odd/x\y/z.txt`, "4")
	res, body := admin.send("GET", "/api/v1/files/download?share=media&path=Odd", nil, nil)
	if res.StatusCode != 200 {
		t.Fatalf("zip = %d", res.StatusCode)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	if strings.Join(names, "|") != "a_b.txt|bell_.txt|c_d.txt|x_y/|x_y/z.txt" {
		t.Errorf("zip names = %q", names)
	}
	// Several items: the top names too.
	res, body = admin.send("GET", "/api/v1/files/download?share=media&path=Odd/c:d.txt&path=Odd/x%5Cy", nil, nil)
	zr, err = zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("items zip = %d %v", res.StatusCode, err)
	}
	names = nil
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	if strings.Join(names, "|") != "c_d.txt|x_y/|x_y/z.txt" {
		t.Errorf("items zip names = %q", names)
	}

	// A cancelled upload's temporary file is deleted for good, never recycled
	// (media has a recycle bin).
	var up FilesUpload
	if code := admin.do("POST", "/api/v1/files/upload", FilesUploadRequest{Share: "media", Path: "Odd/big.bin", Size: 10}, &up); code != 201 {
		t.Fatalf("start = %d", code)
	}
	if res, _ := admin.send("DELETE", "/api/v1/files/upload/"+up.ID, nil, nil); res.StatusCode != 204 {
		t.Fatalf("cancel = %d", res.StatusCode)
	}
	fk.mu.Lock()
	calls := strings.Join(fk.calls, "\n")
	fk.mu.Unlock()
	if !strings.Contains(calls, "delete media:Odd/.hardyos-upload-"+up.ID+" permanent=true") || strings.Contains(calls, "permanent=false") {
		t.Errorf("cancel deleted with %s", calls)
	}
}
