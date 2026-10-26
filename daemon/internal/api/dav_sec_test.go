package api

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/webdav"

	"github.com/hardyos/hardyos/daemon/internal/files"
)

// A local account's name over WebDAV is answered like a wrong password
// and counted like an unknown name (the address, and a key of its own),
// never under the account's own key, so the administrator keeps the
// desktop. Rate-limited requests don't each get an audit row.
func TestDAVLocalAccountNames(t *testing.T) {
	e := newDAVEnv(t)
	res, body := e.req(t, "PROPFIND", "/dav/", "cade", "supersecret1", nil, map[string]string{"Depth": "0"})
	if res.StatusCode != 401 || res.Header.Get("WWW-Authenticate") == "" || strings.Contains(body, "domain accounts") || !strings.Contains(body, "incorrect username or password") {
		t.Errorf("local account = %d %q", res.StatusCode, body)
	}
	for i := 0; i < 4; i++ {
		if res, _ := e.req(t, "PROPFIND", "/dav/", "cade", "wrong", nil, map[string]string{"Depth": "0"}); res.StatusCode != 401 {
			t.Errorf("guess %d = %d", i, res.StatusCode)
		}
	}
	for i := 0; i < 6; i++ {
		if res, _ := e.req(t, "PROPFIND", "/dav/", "cade", "wrong", nil, map[string]string{"Depth": "0"}); res.StatusCode != 429 {
			t.Errorf("after five = %d", res.StatusCode)
		}
	}
	if ok, _ := e.server.cfg.Limiter.Allowed("user:cade"); !ok {
		t.Error("the administrator's own sign-in key was locked by WebDAV guesses")
	}
	var n int
	_ = e.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'dav.login' AND detail LIKE 'rate limited%'`).Scan(&n)
	if n != 1 {
		t.Errorf("rate-limited audit rows: %d", n)
	}
	_ = e.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'dav.login' AND outcome = 'failure'`).Scan(&n)
	if n != 5 {
		t.Errorf("failed sign-ins audited: %d", n)
	}
}

// PUT over an existing file needs write access to that file (not just its
// folder), and the old version goes to the recycle bin when there is one.
func TestDAVPutOverExisting(t *testing.T) {
	e := newDAVEnv(t)
	media, home := e.fk.dirs["media"], e.fk.dirs[files.HomeShare]
	put(t, media, "ro.txt", "keep me")
	if err := os.Chmod(filepath.Join(media, "ro.txt"), 0o444); err != nil {
		t.Fatal(err)
	}
	res, _ := e.req(t, "PUT", "/dav/Media/ro.txt", "alice", alicePW, strings.NewReader("overwritten"), nil)
	if res.StatusCode != 403 {
		t.Errorf("PUT over a read-only file = %d", res.StatusCode)
	}
	if b, _ := os.ReadFile(filepath.Join(media, "ro.txt")); string(b) != "keep me" {
		t.Errorf("read-only file now %q", b)
	}
	// COPY or MOVE over it: the same rule.
	put(t, media, "other.txt", "other")
	for _, m := range []string{"COPY", "MOVE"} {
		if res, _ := e.req(t, m, "/dav/Media/other.txt", "alice", alicePW, nil, map[string]string{"Destination": "/dav/Media/ro.txt", "Overwrite": "T"}); res.StatusCode != 403 {
			t.Errorf("%s over a read-only file = %d", m, res.StatusCode)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(media, "ro.txt")); string(b) != "keep me" {
		t.Errorf("read-only file now %q", b)
	}
	// A file the person may write: replaced, the old version in the bin.
	put(t, media, "rw.txt", "old version")
	if res, _ := e.req(t, "PUT", "/dav/Media/rw.txt", "alice", alicePW, strings.NewReader("new version"), nil); res.StatusCode != 201 && res.StatusCode != 204 {
		t.Fatalf("PUT = %d", res.StatusCode)
	}
	if b, _ := os.ReadFile(filepath.Join(media, "rw.txt")); string(b) != "new version" {
		t.Errorf("replaced with %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(media, ".recycle/bin/rw.txt")); string(b) != "old version" {
		t.Errorf("old version in the bin: %q", b)
	}
	// No bin (Home): replaced in one step, nothing deleted first.
	put(t, home, "h.txt", "old")
	n := len(e.fk.calls)
	if res, _ := e.req(t, "PUT", "/dav/Home/h.txt", "alice", alicePW, strings.NewReader("new"), nil); res.StatusCode >= 300 {
		t.Fatalf("PUT = %d", res.StatusCode)
	}
	if b, _ := os.ReadFile(filepath.Join(home, "h.txt")); string(b) != "new" {
		t.Errorf("Home file %q", b)
	}
	for _, c := range e.fk.calls[n:] {
		if strings.HasPrefix(c, "delete "+files.HomeShare+":h.txt") {
			t.Errorf("deleted before replacing without a bin: %s", c)
		}
	}
}

func TestDAVRequestLimits(t *testing.T) {
	e := newDAVEnv(t)
	media := e.fk.dirs["media"]
	put(t, media, "Films/a.txt", "a")
	// PROPFIND of a whole tree is refused, as RFC 4918 allows.
	for _, depth := range []string{"infinity", ""} {
		hdr := map[string]string{}
		if depth != "" {
			hdr["Depth"] = depth
		}
		res, body := e.req(t, "PROPFIND", "/dav/Media/", "alice", alicePW, nil, hdr)
		if res.StatusCode != 403 || !strings.Contains(body, "propfind-finite-depth") {
			t.Errorf("Depth %q = %d %s", depth, res.StatusCode, body)
		}
	}
	if res, _ := e.req(t, "PROPFIND", "/dav/Media/", "alice", alicePW, nil, map[string]string{"Depth": "1"}); res.StatusCode != 207 {
		t.Errorf("Depth 1 = %d", res.StatusCode)
	}
	// POST isn't WebDAV.
	if res, _ := e.req(t, "POST", "/dav/Media/Films/a.txt", "alice", alicePW, strings.NewReader("x"), nil); res.StatusCode != 405 {
		t.Errorf("POST = %d", res.StatusCode)
	}
	// XML bodies are bounded.
	big := `<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:"><D:set><D:prop><X xmlns="urn:x">` + strings.Repeat("a", 2<<20) + `</X></D:prop></D:set></D:propertyupdate>`
	if res, _ := e.req(t, "PROPPATCH", "/dav/Media/Films/a.txt", "alice", alicePW, strings.NewReader(big), nil); res.StatusCode < 400 || res.StatusCode >= 500 {
		t.Errorf("a 2 MiB PROPPATCH = %d", res.StatusCode)
	}
}

func TestDAVLockLimits(t *testing.T) {
	e := newDAVEnv(t)
	home := e.fk.dirs[files.HomeShare]
	lock := func(p, timeout, owner string) (int, string) {
		body := `<?xml version="1.0"?><D:lockinfo xmlns:D="DAV:"><D:lockscope><D:exclusive/></D:lockscope><D:locktype><D:write/></D:locktype>` +
			`<D:owner>` + owner + `</D:owner></D:lockinfo>`
		res, b := e.req(t, "LOCK", p, "alice", alicePW, strings.NewReader(body), map[string]string{"Timeout": timeout, "Depth": "0"})
		return res.StatusCode, b
	}
	put(t, home, "a.txt", "a")
	for _, to := range []string{"Infinite", "Second-99999999"} {
		code, body := lock("/dav/Home/a.txt", to, "me")
		if code != 200 || !strings.Contains(body, "Second-3600") {
			t.Errorf("Timeout %s = %d %s", to, code, body)
		}
		ls := e.server.dav.lockSystem(`HOME\alice`)
		ls.mu.Lock()
		var toks []string
		for tok := range ls.held {
			toks = append(toks, tok)
		}
		ls.mu.Unlock()
		for _, tok := range toks {
			_ = ls.Unlock(time.Now(), tok)
		}
	}
	if code, _ := lock("/dav/Home/a.txt", "Second-60", "me"); code != 200 {
		t.Errorf("LOCK = %d", code)
	}
	// At most davMaxLocksPerUser locks per person.
	for i := 0; i < davMaxLocksPerUser; i++ {
		put(t, home, fmt.Sprintf("l/%d.txt", i), "x")
	}
	refused := -1
	for i := 0; i < davMaxLocksPerUser; i++ {
		if code, _ := lock(fmt.Sprintf("/dav/Home/l/%d.txt", i), "Second-600", ""); code != 200 {
			refused = i
			break
		}
	}
	// One lock (the owner test's) is already held.
	if refused != davMaxLocksPerUser-1 {
		t.Errorf("locks refused from %d", refused)
	}
	if n := e.server.dav.lockCount.Load(); n != davMaxLocksPerUser {
		t.Errorf("locks counted: %d", n)
	}
}

// recLS records what cappedLS hands on.
type recLS struct {
	webdav.LockSystem
	got []webdav.LockDetails
	ref []time.Duration
}

func (r *recLS) Create(now time.Time, d webdav.LockDetails) (string, error) {
	r.got = append(r.got, d)
	return r.LockSystem.Create(now, d)
}

func (r *recLS) Refresh(now time.Time, tok string, d time.Duration) (webdav.LockDetails, error) {
	r.ref = append(r.ref, d)
	return r.LockSystem.Refresh(now, tok, d)
}

func TestCappedLockSystem(t *testing.T) {
	var total atomic.Int64
	rec := &recLS{LockSystem: webdav.NewMemLS()}
	ls := &cappedLS{LockSystem: rec, total: &total, held: map[string]time.Time{}}
	now := time.Now()
	tok, err := ls.Create(now, webdav.LockDetails{Root: "/a", Duration: -1, OwnerXML: strings.Repeat("o", davMaxLockOwner+1), ZeroDepth: true})
	if err != nil {
		t.Fatal(err)
	}
	if rec.got[0].Duration != davMaxLockTime || rec.got[0].OwnerXML != "" {
		t.Errorf("handed on %+v", rec.got[0])
	}
	if _, err := ls.Refresh(now, tok, 48*time.Hour); err != nil || rec.ref[0] != davMaxLockTime {
		t.Errorf("refresh %v %v", rec.ref, err)
	}
	if total.Load() != 1 {
		t.Errorf("total %d", total.Load())
	}
	// Locks that ran out stop counting.
	if _, err := ls.Create(now.Add(2*time.Hour), webdav.LockDetails{Root: "/b", Duration: time.Minute, ZeroDepth: true}); err != nil {
		t.Fatal(err)
	}
	if total.Load() != 1 || ls.count() != 1 {
		t.Errorf("after expiry: total %d, held %d", total.Load(), ls.count())
	}
	for in, want := range map[string]string{
		"": "Second-3600", "Infinite": "Second-3600", "Infinite, Second-4100000000": "Second-3600",
		"Second-60": "Second-60", "Second-3601": "Second-3600", "Second-x": "Second-3600",
	} {
		if got := davLockTimeout(in); got != want {
			t.Errorf("davLockTimeout(%q) = %q", in, got)
		}
	}
}

// MOVE or COPY onto itself (spelled differently) is refused before
// x/net/webdav would delete the destination, i.e. the source.
func TestDAVDestination(t *testing.T) {
	e := newDAVEnv(t)
	media := e.fk.dirs["media"]
	put(t, media, "a.txt", "a")
	put(t, media, "Dir/x.txt", "x")
	for _, dst := range []string{"/dav/Media//a.txt", "/dav/Media/./a.txt", "/dav/Media/Dir/../a.txt", e.srv.URL + "/dav/Media/a.txt/"} {
		for _, m := range []string{"MOVE", "COPY"} {
			if res, _ := e.req(t, m, "/dav/Media/a.txt", "alice", alicePW, nil, map[string]string{"Destination": dst, "Overwrite": "T"}); res.StatusCode != 403 {
				t.Errorf("%s to %s = %d", m, dst, res.StatusCode)
			}
		}
	}
	if b, _ := os.ReadFile(filepath.Join(media, "a.txt")); string(b) != "a" {
		t.Fatalf("the source is gone: %q", b)
	}
	if res, _ := e.req(t, "COPY", "/dav/Media/Dir/", "alice", alicePW, nil, map[string]string{"Destination": "/dav/Media/Dir/Sub/"}); res.StatusCode != 403 {
		t.Errorf("a folder into itself = %d", res.StatusCode)
	}
	if res, _ := e.req(t, "MOVE", "/dav/Media/a.txt", "alice", alicePW, nil, map[string]string{"Destination": "/elsewhere/a.txt"}); res.StatusCode != 403 {
		t.Errorf("outside /dav = %d", res.StatusCode)
	}
	// A cleaned name with characters URLs treat specially still arrives.
	if res, _ := e.req(t, "MOVE", "/dav/Media/a.txt", "alice", alicePW, nil, map[string]string{"Destination": "/dav/Media/Dir/../b%23c%25d.txt"}); res.StatusCode != 201 {
		t.Errorf("MOVE to b#c%%d.txt = %d", res.StatusCode)
	}
	if b, _ := os.ReadFile(filepath.Join(media, "b#c%d.txt")); string(b) != "a" {
		t.Errorf("moved: %q", b)
	}
}

// MKCOL, PROPPATCH time changes, MOVE (with both ends) and COPY (as a
// copy) are all in the audit log.
func TestDAVAudit(t *testing.T) {
	e := newDAVEnv(t)
	media := e.fk.dirs["media"]
	put(t, media, "a.txt", "a")
	e.req(t, "MKCOL", "/dav/Media/New/", "alice", alicePW, nil, nil)
	e.req(t, "MOVE", "/dav/Media/a.txt", "alice", alicePW, nil, map[string]string{"Destination": "/dav/Media/New/b.txt"})
	e.req(t, "COPY", "/dav/Media/New/b.txt", "alice", alicePW, nil, map[string]string{"Destination": "/dav/Home/c.txt"})
	patch := `<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:"><D:set><D:prop>` +
		`<Z:Win32LastModifiedTime>Tue, 01 Jan 2030 10:00:00 GMT</Z:Win32LastModifiedTime></D:prop></D:set></D:propertyupdate>`
	e.req(t, "PROPPATCH", "/dav/Home/c.txt", "alice", alicePW, strings.NewReader(patch), nil)
	want := map[string]string{
		"files.mkdir":   "media:/New|webdav",
		"files.move":    "media:/a.txt|webdav, to media:/New/b.txt",
		"files.copy":    "home:/c.txt|webdav, from media:/New/b.txt, 1 bytes",
		"files.settime": "home:/c.txt|webdav, modified 2030-01-01T10:00:00Z",
	}
	for action, w := range want {
		target, detail, _ := strings.Cut(w, "|")
		target = strings.Replace(target, "home:", files.HomeShare+":", 1)
		detail = strings.Replace(detail, "home:", files.HomeShare+":", 1)
		var n int
		_ = e.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ? AND target = ? AND detail = ?`, action, target, detail).Scan(&n)
		if n != 1 {
			var got []string
			rows, _ := e.db.Query(`SELECT action || ' ' || target || ' ' || detail FROM audit_log WHERE action LIKE 'files.%'`)
			for rows.Next() {
				var s string
				_ = rows.Scan(&s)
				got = append(got, s)
			}
			rows.Close()
			t.Errorf("%s %s %q: %d rows (have %v)", action, target, detail, n, got)
		}
	}
}
