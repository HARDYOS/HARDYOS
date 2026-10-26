package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func newFilesEnv(t *testing.T) (*testEnv, *fakeFiles, *client, *client) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	fk := &fakeFiles{
		dirs:     map[string]string{"media": t.TempDir(), "docs": t.TempDir()},
		readOnly: map[string]bool{"docs": true},
		recycle:  map[string]bool{"media": true},
	}
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	RegisterFileJobs(m, fk)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Files: fk, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	env := &testEnv{srv: srv, db: db, broker: broker}
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	return env, fk, admin, kid
}

func put(t *testing.T, root, p, s string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// send sends a request with a raw body and headers and returns the response
// (body read).
func (c *client) send(method, p string, body []byte, hdr map[string]string) (*http.Response, []byte) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.base+p, bytes.NewReader(body))
	req.Header.Set("X-HardyOS-Request", "1")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, b
}

func q(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v.Encode()
}

func TestFilesAPIReading(t *testing.T) {
	_, fk, admin, kid := newFilesEnv(t)
	media := fk.dirs["media"]
	put(t, media, "Movies/film.mp4", "0123456789")
	put(t, media, "Movies/extras/trailer.mp4", "trailer")
	put(t, media, "notes.txt", "hello notes")
	put(t, media, "page.html", "<script>alert(1)</script>")
	put(t, media, ".zfs/snapshot/hardyos-auto-daily_2026-10-24-0000/notes.txt", "old notes")

	// Local accounts that aren't administrators don't get files.
	var e ErrorResponse
	if code := kid.do("GET", "/api/v1/files/shares", nil, &e); code != 403 || e.Code != "no_access" {
		t.Fatalf("kid = %d %+v", code, e)
	}
	var sh FilesSharesResponse
	if code := admin.do("GET", "/api/v1/files/shares", nil, &sh); code != 200 || len(sh.Shares) != 2 || sh.Shares[1].ID != "media" || !sh.Shares[1].Recycle {
		t.Fatalf("shares = %d %+v", code, sh)
	}
	var l files.Listing
	if code := admin.do("GET", "/api/v1/files/list?"+q("share", "media", "path", "Movies"), nil, &l); code != 200 || len(l.Entries) != 2 || !l.Folder.Writable {
		t.Fatalf("list = %d %+v", code, l)
	}
	for p, want := range map[string]int{"nothing": 404, "../etc": 409, ".zfs/snapshot": 409} {
		if code := admin.do("GET", "/api/v1/files/list?"+q("share", "media", "path", p), nil, &e); code != want {
			t.Errorf("list %q = %d %+v", p, code, e)
		}
	}
	if code := admin.do("GET", "/api/v1/files/list?"+q("share", "ghost"), nil, nil); code != 404 {
		t.Errorf("missing share = %d", code)
	}
	var en files.Entry
	if code := admin.do("GET", "/api/v1/files/stat?"+q("share", "media", "path", "notes.txt"), nil, &en); code != 200 || en.Size != 11 || en.Name != "notes.txt" {
		t.Errorf("stat = %d %+v", code, en)
	}

	// Downloads: whole, ranges, inline previews only for safe types.
	res, body := admin.send("GET", "/api/v1/files/download?"+q("share", "media", "path", "Movies/film.mp4"), nil, nil)
	if res.StatusCode != 200 || string(body) != "0123456789" || !strings.HasPrefix(res.Header.Get("Content-Disposition"), `attachment; filename="film.mp4"`) ||
		res.Header.Get("Accept-Ranges") != "bytes" || !strings.Contains(res.Header.Get("Content-Security-Policy"), "sandbox") {
		t.Fatalf("download = %d %q %v", res.StatusCode, body, res.Header)
	}
	etag := res.Header.Get("ETag")
	res, body = admin.send("GET", "/api/v1/files/download?"+q("share", "media", "path", "Movies/film.mp4"), nil, map[string]string{"Range": "bytes=2-5"})
	if res.StatusCode != 206 || string(body) != "2345" || res.Header.Get("Content-Range") != "bytes 2-5/10" {
		t.Fatalf("range = %d %q %v", res.StatusCode, body, res.Header)
	}
	res, body = admin.send("GET", "/api/v1/files/download?"+q("share", "media", "path", "Movies/film.mp4"), nil, map[string]string{"Range": "bytes=8-", "If-Range": etag})
	if res.StatusCode != 206 || string(body) != "89" {
		t.Fatalf("if-range = %d %q", res.StatusCode, body)
	}
	res, _ = admin.send("GET", "/api/v1/files/download?"+q("share", "media", "path", "Movies/film.mp4", "inline", "1"), nil, nil)
	if res.Header.Get("Content-Type") != "video/mp4" || !strings.HasPrefix(res.Header.Get("Content-Disposition"), "inline") {
		t.Errorf("inline video = %v", res.Header)
	}
	res, _ = admin.send("GET", "/api/v1/files/download?"+q("share", "media", "path", "page.html", "inline", "1"), nil, nil)
	if ct := res.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("an HTML page is shown as %q", ct)
	}
	res, _ = admin.send("GET", "/api/v1/files/download?"+q("share", "media", "path", "page.html"), nil, nil)
	if ct := res.Header.Get("Content-Type"); ct != "application/octet-stream" || !strings.HasPrefix(res.Header.Get("Content-Disposition"), "attachment") {
		t.Errorf("an HTML download is %q", ct)
	}
	res, body = admin.send("GET", "/api/v1/files/download?"+q("share", "media", "path", "notes.txt", "snapshot", "hardyos-auto-daily_2026-10-24-0000"), nil, nil)
	if res.StatusCode != 200 || string(body) != "old notes" {
		t.Errorf("old version = %d %q", res.StatusCode, body)
	}
	if res, _ := admin.send("GET", "/api/v1/files/download?"+q("share", "media", "path", "ghost.txt"), nil, nil); res.StatusCode != 404 {
		t.Errorf("missing download = %d", res.StatusCode)
	}

	// A folder is a zip of its contents; several items a zip of each.
	readZip := func(b []byte) map[string]string {
		t.Helper()
		zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			t.Fatalf("zip: %v", err)
		}
		out := map[string]string{}
		for _, f := range zr.File {
			rc, _ := f.Open()
			c, _ := io.ReadAll(rc)
			rc.Close()
			out[f.Name] = string(c)
		}
		return out
	}
	res, body = admin.send("GET", "/api/v1/files/download?"+q("share", "media", "path", "Movies"), nil, nil)
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/zip" || !strings.Contains(res.Header.Get("Content-Disposition"), `filename="Movies.zip"`) {
		t.Fatalf("folder download = %d %v", res.StatusCode, res.Header)
	}
	got := readZip(body)
	if got["film.mp4"] != "0123456789" || got["extras/trailer.mp4"] != "trailer" || len(got) != 3 {
		t.Fatalf("folder zip = %v", got)
	}
	res, body = admin.send("GET", "/api/v1/files/download?"+q("share", "media", "path", "Movies", "path", "notes.txt"), nil, nil)
	got = readZip(body)
	var names []string
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	if res.StatusCode != 200 || strings.Join(names, ",") != "Movies/,Movies/extras/,Movies/extras/trailer.mp4,Movies/film.mp4,notes.txt" {
		t.Fatalf("items zip = %d %v", res.StatusCode, names)
	}
	if res, _ := admin.send("GET", "/api/v1/files/download?"+q("share", "media", "path", "Movies", "path", "ghost"), nil, nil); res.StatusCode != 404 {
		t.Errorf("zip with a missing item = %d", res.StatusCode)
	}

	var vs FilesVersionsResponse
	if code := admin.do("GET", "/api/v1/files/snapshots?"+q("share", "media", "path", "notes.txt"), nil, &vs); code != 200 || len(vs.Versions) != 1 || vs.Versions[0].Size != 9 {
		t.Errorf("versions = %d %+v", code, vs)
	}
}

func TestFilesAPIUploads(t *testing.T) {
	env, fk, admin, _ := newFilesEnv(t)
	media := fk.dirs["media"]
	put(t, media, "Photos/keep.jpg", "keep")
	read := func(p string) string {
		b, err := os.ReadFile(filepath.Join(media, p))
		if err != nil {
			return "<missing>"
		}
		return string(b)
	}
	temps := func() []string {
		m, _ := filepath.Glob(filepath.Join(media, "Photos", ".hardyos-upload-*"))
		return m
	}
	start := func(c *client, req FilesUploadRequest) (int, FilesUpload) {
		var up FilesUpload
		code := c.do("POST", "/api/v1/files/upload", req, &up)
		return code, up
	}
	chunk := func(c *client, id string, offset int, data string) (int, FilesUpload, []byte) {
		res, body := c.send("PUT", fmt.Sprintf("/api/v1/files/upload/%s?offset=%d", id, offset), []byte(data),
			map[string]string{"Content-Type": "application/octet-stream"})
		var up FilesUpload
		json.Unmarshal(body, &up)
		return res.StatusCode, up, body
	}

	// In chunks, resumed after a wrong offset.
	mod := time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)
	code, up := start(admin, FilesUploadRequest{Share: "media", Path: "Photos/big.bin", Size: 12, Modified: mod.UnixMilli()})
	if code != 201 || up.ID == "" || up.Size != 12 || up.Received != 0 || len(temps()) != 1 {
		t.Fatalf("start = %d %+v", code, up)
	}
	id := up.ID
	if code, up, body := chunk(admin, id, 0, "01234"); code != 200 || up.Received != 5 || up.Entry != nil {
		t.Fatalf("first chunk = %d %s", code, body)
	}
	if read("Photos/big.bin") != "<missing>" {
		t.Fatal("the file appeared before the upload finished")
	}
	if code, _, body := chunk(admin, id, 9, "zzz"); code != 409 || !strings.Contains(string(body), `"received":5`) {
		t.Errorf("wrong offset = %d %s", code, body)
	}
	var cur FilesUpload
	if code := admin.do("GET", "/api/v1/files/upload/"+id, nil, &cur); code != 200 || cur.Received != 5 || cur.Path != "Photos/big.bin" {
		t.Errorf("status = %d %+v", code, cur)
	}
	if code, _, _ := chunk(admin, id, 5, "56789abcdef"); code != 400 {
		t.Errorf("too long = %d", code)
	}
	if code := admin.do("GET", "/api/v1/files/upload/"+id, nil, &cur); cur.Received != 5 {
		t.Errorf("after a too-long chunk = %d %+v", code, cur)
	}
	if code, up, _ := chunk(admin, id, 5, "56789"); code != 200 || up.Received != 10 {
		t.Fatalf("second chunk = %d %+v", code, up)
	}
	code, up, body := chunk(admin, id, 10, "ab")
	if code != 200 || up.Entry == nil || up.Entry.Size != 12 || up.Received != 12 {
		t.Fatalf("last chunk = %d %s", code, body)
	}
	if read("Photos/big.bin") != "0123456789ab" || len(temps()) != 0 {
		t.Fatalf("assembled %q, temps %v", read("Photos/big.bin"), temps())
	}
	if fi, _ := os.Stat(filepath.Join(media, "Photos/big.bin")); !fi.ModTime().Equal(mod) {
		t.Errorf("modified = %v", fi.ModTime())
	}
	if code := admin.do("GET", "/api/v1/files/upload/"+id, nil, nil); code != 404 {
		t.Errorf("finished upload still known: %d", code)
	}

	// An empty file is one empty chunk.
	code, up = start(admin, FilesUploadRequest{Share: "media", Path: "Photos/empty.txt", Size: 0})
	if code != 201 {
		t.Fatal(code)
	}
	if code, up, body := chunk(admin, up.ID, 0, ""); code != 200 || up.Entry == nil || read("Photos/empty.txt") != "" {
		t.Fatalf("empty = %d %s", code, body)
	}

	// Names taken, overwriting, bad names and read-only folders.
	var e ErrorResponse
	if code := admin.do("POST", "/api/v1/files/upload", FilesUploadRequest{Share: "media", Path: "Photos/keep.jpg", Size: 1}, &e); code != 409 {
		t.Errorf("upload over a file = %d", code)
	}
	if code := admin.do("POST", "/api/v1/files/upload", FilesUploadRequest{Share: "media", Path: "Photos", Size: 1, Overwrite: true}, &e); code != 409 {
		t.Errorf("upload over a folder = %d", code)
	}
	code, up = start(admin, FilesUploadRequest{Share: "media", Path: "Photos/keep.jpg", Size: 1, Overwrite: true})
	if code != 201 {
		t.Fatal(code)
	}
	if code, _, _ := chunk(admin, up.ID, 0, "K"); code != 200 || read("Photos/keep.jpg") != "K" {
		t.Errorf("overwrite = %d %q", code, read("Photos/keep.jpg"))
	}
	if code := admin.do("POST", "/api/v1/files/upload", FilesUploadRequest{Share: "docs", Path: "x.txt", Size: 1}, &e); code != 403 {
		t.Errorf("upload to a read-only folder = %d", code)
	}
	for bad, want := range map[string]int{"": 400, "Photos/.hardyos-x": 400, ".recycle/x": 409, "../x": 409} {
		if code := admin.do("POST", "/api/v1/files/upload", FilesUploadRequest{Share: "media", Path: bad, Size: 1}, &e); code != want {
			t.Errorf("upload to %q = %d, want %d", bad, code, want)
		}
	}

	// Cancelling removes the temporary file; someone else can't touch it.
	code, up = start(admin, FilesUploadRequest{Share: "media", Path: "Photos/c.bin", Size: 10})
	if code != 201 {
		t.Fatal(code)
	}
	admin.do("POST", "/api/v1/users", map[string]string{"username": "ann", "password": "annpassword1", "role": "admin"}, nil)
	other := env.client(t)
	other.do("POST", "/api/v1/auth/login", map[string]string{"username": "ann", "password": "annpassword1"}, nil)
	if code := other.do("GET", "/api/v1/files/upload/"+up.ID, nil, nil); code != 404 {
		t.Errorf("another person saw the upload: %d", code)
	}
	if code, _, _ := chunk(other, up.ID, 0, "x"); code != 404 {
		t.Errorf("another person wrote to the upload: %d", code)
	}
	if res, _ := other.send("DELETE", "/api/v1/files/upload/"+up.ID, nil, nil); res.StatusCode != 404 {
		t.Errorf("another person cancelled the upload: %d", res.StatusCode)
	}
	if res, _ := admin.send("DELETE", "/api/v1/files/upload/"+up.ID, nil, nil); res.StatusCode != 204 || len(temps()) != 0 {
		t.Errorf("cancel = %d %v", res.StatusCode, temps())
	}

	// Uploads are audited.
	var audit []map[string]any
	admin.do("GET", "/api/v1/audit", nil, &audit)
	n := 0
	for _, a := range audit {
		if a["action"] == "files.upload" {
			n++
		}
	}
	if n != 3 {
		t.Errorf("%d upload audit entries: %v", n, audit)
	}
}

func TestFilesAPIChanges(t *testing.T) {
	_, fk, admin, _ := newFilesEnv(t)
	media := fk.dirs["media"]
	for i := 0; i < 7; i++ {
		put(t, media, fmt.Sprintf("Inbox/f%d.txt", i), "x")
	}
	put(t, media, "notes.txt", "now")
	put(t, media, ".zfs/snapshot/hardyos-auto-daily_2026-10-24-0000/notes.txt", "then")
	exists := func(p string) bool { _, err := os.Stat(filepath.Join(media, p)); return err == nil }
	var e ErrorResponse

	var en files.Entry
	var br FilesBulkResult
	if code := admin.do("POST", "/api/v1/files/mkdir", FilesPathRequest{Share: "media", Path: "Archive"}, &en); code != 201 || !en.Dir || en.Name != "Archive" {
		t.Fatalf("mkdir = %d %+v", code, en)
	}
	if code := admin.do("POST", "/api/v1/files/mkdir", FilesPathRequest{Share: "media", Path: "Archive"}, &e); code != 409 || e.Code != "exists" {
		t.Errorf("mkdir again = %d %+v", code, e)
	}
	if code := admin.do("POST", "/api/v1/files/mkdir", FilesPathRequest{Share: "docs", Path: "x"}, &e); code != 403 {
		t.Errorf("mkdir read-only = %d", code)
	}
	var pr FilesPathResponse
	if code := admin.do("POST", "/api/v1/files/rename", FilesRenameRequest{Share: "media", Path: "Inbox/f0.txt", Name: "zero.txt"}, &en); code != 200 || en.Path != "Inbox/zero.txt" || !exists("Inbox/zero.txt") {
		t.Fatalf("rename = %d %+v", code, en)
	}
	if code := admin.do("POST", "/api/v1/files/rename", FilesRenameRequest{Share: "media", Path: "Inbox/f1.txt", Name: "zero.txt"}, &e); code != 409 {
		t.Errorf("rename onto a file = %d", code)
	}
	if code := admin.do("POST", "/api/v1/files/rename", FilesRenameRequest{Share: "media", Path: "Inbox/f1.txt", Name: "a/b"}, &e); code != 400 {
		t.Errorf("rename with a slash = %d", code)
	}
	if code := admin.do("POST", "/api/v1/files/move", FilesCopyRequest{Share: "media", Paths: []string{"Inbox/zero.txt"}, ToDir: "Archive"}, &br); code != 200 || !exists("Archive/zero.txt") {
		t.Fatalf("move = %d %+v", code, br)
	}

	// A few files: done at once.
	if code := admin.do("POST", "/api/v1/files/copy", FilesCopyRequest{Share: "media", Paths: []string{"Inbox/f1.txt", "Inbox/f2.txt"}, ToDir: "Archive"}, &br); code != 200 || !br.Done || len(br.Results) != 2 || !br.Results[0].OK || br.Results[0].To != "Archive/f1.txt" {
		t.Fatalf("copy = %d %+v", code, br)
	}
	// Again: the names are taken, so copies get " (copy)".
	if code := admin.do("POST", "/api/v1/files/copy", FilesCopyRequest{Share: "media", Paths: []string{"Inbox/f1.txt"}, ToDir: "Archive"}, &br); code != 200 || br.Results[0].To != "Archive/f1 (copy).txt" {
		t.Errorf("copy again = %d %+v", code, br)
	}
	if code := admin.do("POST", "/api/v1/files/copy", FilesCopyRequest{Share: "media", Paths: []string{"Inbox/f1.txt"}, ToDir: "Archive", Conflict: "fail"}, &e); code != 409 {
		t.Errorf("copy with fail = %d", code)
	}
	if code := admin.do("POST", "/api/v1/files/copy", FilesCopyRequest{Share: "media", Paths: []string{"Inbox/f1.txt"}, ToDir: "Archive", Conflict: "bogus"}, &e); code != 400 {
		t.Errorf("bad conflict = %d", code)
	}
	if code := admin.do("POST", "/api/v1/files/copy", FilesCopyRequest{Share: "media", Paths: []string{""}, ToDir: "Archive"}, &e); code != 409 {
		t.Errorf("copy the top = %d", code)
	}
	if code := admin.do("POST", "/api/v1/files/copy", FilesCopyRequest{Share: "media", Paths: []string{"Inbox/f3.txt"}, ToShare: "docs", ToDir: ""}, &e); code != 403 {
		t.Errorf("copy into read-only = %d %+v", code, e)
	}
	// A move within the share is a rename, even for many items.
	if code := admin.do("POST", "/api/v1/files/move", FilesCopyRequest{Share: "media", Paths: []string{"Inbox/f3.txt"}, ToDir: "Archive"}, &br); code != 200 || exists("Inbox/f3.txt") || !exists("Archive/f3.txt") {
		t.Errorf("move = %d %+v", code, br)
	}

	// A folder copy runs as a job.
	var acc struct {
		Job struct {
			ID string `json:"id"`
		} `json:"job"`
	}
	if code := admin.do("POST", "/api/v1/files/copy", FilesCopyRequest{Share: "media", Paths: []string{"Inbox"}, ToDir: "Archive"}, &acc); code != 202 {
		t.Fatalf("folder copy = %d", code)
	}
	j := waitJobDone(t, admin, acc.Job.ID)
	if j["state"] != "succeeded" || j["kind"] != JobKindFilesCopy || !exists("Archive/Inbox/f4.txt") {
		t.Fatalf("copy job = %v", j)
	}

	// Deletes: a few at once, many as a job; all audited.
	if code := admin.do("POST", "/api/v1/files/delete", FilesDeleteRequest{Share: "media", Paths: []string{"Inbox/f4.txt"}}, &br); code != 200 || !br.Recycled || !br.Results[0].Recycled || exists("Inbox/f4.txt") {
		t.Fatalf("delete = %d %+v", code, br)
	}
	if code := admin.do("POST", "/api/v1/files/delete", FilesDeleteRequest{Share: "media", Paths: []string{"Inbox/ghost"}}, &e); code != 404 {
		t.Errorf("delete missing = %d", code)
	}
	paths := []string{"Archive/Inbox/f1.txt", "Archive/Inbox/f2.txt", "Archive/Inbox/f4.txt", "Archive/Inbox/f5.txt", "Archive/Inbox/f6.txt", "Archive/zero.txt"}
	if code := admin.do("POST", "/api/v1/files/delete", FilesDeleteRequest{Share: "media", Paths: paths, Permanent: true}, &acc); code != 202 {
		t.Fatalf("bulk delete = %d", code)
	}
	j = waitJobDone(t, admin, acc.Job.ID)
	if j["state"] != "succeeded" || exists("Archive/zero.txt") {
		t.Fatalf("delete job = %v", j)
	}
	if !strings.Contains(strings.Join(fk.calls, "\n"), "delete media:Archive/zero.txt permanent=true") {
		t.Errorf("calls = %v", fk.calls)
	}

	// Restore: a file at once, next to the current one.
	if code := admin.do("POST", "/api/v1/files/restore", FilesRestoreRequest{Share: "media", Path: "notes.txt", Snapshot: "hardyos-auto-daily_2026-10-24-0000"}, &pr); code != 200 || pr.Path != "notes (restored 2026-10-24).txt" {
		t.Fatalf("restore = %d %+v", code, pr)
	}
	if code := admin.do("POST", "/api/v1/files/restore", FilesRestoreRequest{Share: "media", Path: "notes.txt", Snapshot: "bogus"}, &e); code != 404 {
		t.Errorf("restore bogus = %d", code)
	}

	var audit []map[string]any
	admin.do("GET", "/api/v1/audit", nil, &audit)
	seen := map[string]int{}
	for _, a := range audit {
		seen[fmt.Sprint(a["action"])]++
	}
	if seen["files.delete"] != 2 || seen["files.restore"] != 1 || seen["files.rename"] != 1 || seen["files.copy"] != 1 || seen["files.move"] != 2 {
		t.Errorf("audit = %v", seen)
	}
}
