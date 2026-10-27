package sharelinks_test

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/sharelinks"
	"github.com/hardyos/hardyos/daemon/internal/sharelinks/linktest"
)

// Security review fixes (decisions 103-104): download counting with
// Range, zip limits, upload budgets, names, password lockout.

func (e *env) count(tok string) int {
	e.t.Helper()
	l, err := e.links.ByToken(context.Background(), tok)
	if err != nil {
		e.t.Fatal(err)
	}
	return l.DownloadCount
}

func (e *env) auditCount(prefix string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, a := range e.audits {
		if strings.HasPrefix(a, prefix) {
			n++
		}
	}
	return n
}

func do(t *testing.T, c *http.Client, method, u string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, u, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] != "" {
			req.Header.Add(hdr[i], hdr[i+1])
		}
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res, string(b)
}

// Range requests can't be used to download a file without counting it.
func TestDownloadCountingAndRanges(t *testing.T) {
	e := newEnv(t)
	const content = "0123456789ABCDEFGHIJ"
	e.fake.Write("media", "Films/film.mp4", content)
	e.fake.Write("media", "Films/other.mp4", "OTHER FILE")
	_, tok := e.link(sharelinks.Request{Share: "media", Path: "Films"}, true)
	u := e.srv.URL + "/s/" + tok + "/download?path=film.mp4"
	c := e.client()
	want := 0
	check := func(what string, wantStatus int, wantBody string, counted bool, res *http.Response, body string) {
		t.Helper()
		if counted {
			want++
		}
		if res.StatusCode != wantStatus || (wantBody != "" && body != wantBody) {
			t.Errorf("%s = %d %q, want %d %q", what, res.StatusCode, body, wantStatus, wantBody)
		}
		if got := e.count(tok); got != want {
			t.Errorf("%s: download count = %d, want %d", what, got, want)
		}
		if got := e.auditCount("sharelink.download"); got != want {
			t.Errorf("%s: %d download audits, want %d", what, got, want)
		}
	}

	// HEAD tells the size, and isn't counted, audited or given a ticket.
	res, body := do(t, c, "HEAD", u)
	check("HEAD", 200, "", false, res, body)
	if res.Header.Get("Content-Length") != "20" || len(res.Cookies()) != 0 {
		t.Errorf("HEAD headers %v", res.Header)
	}
	res, body = do(t, c, "HEAD", u, "Range", "bytes=0-")
	check("HEAD with a range", 206, "", false, res, body)

	// A partial request without a ticket is a new download.
	res, body = do(t, c, "GET", u, "Range", "bytes=10-")
	check("range without a ticket", 206, "ABCDEFGHIJ", true, res, body)
	ticket := ""
	for _, ck := range res.Cookies() {
		if strings.HasPrefix(ck.Name, "hardyos_dl_") {
			ticket = ck.Name
			if !ck.HttpOnly || ck.Path != "/s/"+tok || ck.MaxAge != 6*3600 {
				t.Errorf("ticket cookie %+v", ck)
			}
		}
	}
	if ticket == "" {
		t.Fatal("no download ticket set")
	}

	// With the ticket, resuming isn't counted...
	res, body = do(t, c, "GET", u, "Range", "bytes=15-")
	check("resume", 206, "FGHIJ", false, res, body)
	res, body = do(t, c, "GET", u, "Range", "bytes=-3")
	check("suffix resume", 206, "HIJ", false, res, body)
	res, body = do(t, c, "GET", u, "Range", "bytes= 5-9")
	check("resume with a space", 206, "56789", false, res, body)
	// ...but anything that includes the start, or more than one range, is.
	for _, rg := range []string{"bytes=0-", "bytes= 0-", "bytes=0-4", "bytes=1-,0-", "bytes=1-, 0-", "bytes=-20", "bytes=-99", "bytes=2-3,5-6", "bytes=5-,5-"} {
		res, body = do(t, c, "GET", u, "Range", rg)
		check(rg, res.StatusCode, "", true, res, body)
		if res.StatusCode != 200 && res.StatusCode != 206 {
			t.Errorf("%s = %d", rg, res.StatusCode)
		}
	}
	res, body = do(t, c, "GET", u)
	check("no range", 200, content, true, res, body)
	// Two Range headers.
	res, body = do(t, c, "GET", u, "Range", "bytes=10-", "Range", "bytes=0-")
	check("two Range headers", res.StatusCode, "", true, res, body)
	// If-Range that doesn't match sends the whole file: counted.
	res, body = do(t, c, "GET", u, "Range", "bytes=10-", "If-Range", `"x"`)
	check("If-Range etag", 200, content, true, res, body)
	res, body = do(t, c, "GET", u, "Range", "bytes=10-", "If-Range", "Mon, 01 Jan 2001 00:00:00 GMT")
	check("old If-Range date", 200, content, true, res, body)
	// Ranges ServeContent wouldn't serve: refused, nothing sent, not counted.
	for _, rg := range []string{"bytes=x-", "Bytes=0-", "bytes=+0-", "bytes=5-1"} {
		res, body = do(t, c, "GET", u, "Range", rg)
		check(rg, 416, "", false, res, body)
		if strings.Contains(body, "0123") {
			t.Errorf("%s sent the file", rg)
		}
	}

	// The ticket is only good for its own file, link and time.
	ou := e.srv.URL + "/s/" + tok + "/download?path=other.mp4"
	res, body = do(t, c, "GET", ou, "Range", "bytes=6-")
	check("another file", 206, "FILE", true, res, body)
	forged := &http.Client{}
	res, body = do(t, forged, "GET", u, "Range", "bytes=10-", "Cookie", ticket+"=9999999999.AAAA")
	check("forged ticket", 206, "", true, res, body)
	e.now = e.now.Add(6*time.Hour + time.Minute)
	res, body = do(t, c, "GET", u, "Range", "bytes=15-")
	check("expired ticket", 206, "FGHIJ", true, res, body)

	// A folder zip always counts, whatever Range says; HEAD never does
	// (and reads no file).
	zu := e.srv.URL + "/s/" + tok + "/download"
	opens := func() int {
		n := 0
		for _, call := range e.fake.Calls {
			if strings.HasPrefix(call, "open ") {
				n++
			}
		}
		return n
	}
	before := opens()
	res, body = do(t, c, "HEAD", zu)
	check("HEAD zip", 200, "", false, res, body)
	if opens() != before {
		t.Error("HEAD of a folder read its files")
	}
	for _, rg := range []string{"bytes=1-,0-", "bytes=100-", ""} {
		res, body = do(t, c, "GET", zu, "Range", rg)
		check("zip "+rg, 200, "", true, res, body)
		if res.Header.Get("Content-Type") != "application/zip" {
			t.Errorf("zip %q: %v", rg, res.Header)
		}
	}
}

// With a download limit, the last download may still be resumed, but no
// new one starts.
func TestDownloadLimitWithResume(t *testing.T) {
	e := newEnv(t)
	e.fake.Write("media", "a.bin", "0123456789")
	_, tok := e.link(sharelinks.Request{Share: "media", Path: "a.bin", MaxDownloads: 1}, false)
	u := e.srv.URL + "/s/" + tok + "/download"
	c := e.client()
	if res, body := do(t, c, "GET", u, "Range", "bytes=0-4"); res.StatusCode != 206 || body != "01234" {
		t.Fatalf("first part = %d %q", res.StatusCode, body)
	}
	if res, body := do(t, c, "GET", u, "Range", "bytes=5-"); res.StatusCode != 206 || body != "56789" {
		t.Fatalf("resume after the limit = %d %q", res.StatusCode, body)
	}
	for _, rg := range []string{"", "bytes=0-", "bytes=1-,0-", "bytes=-10"} {
		if res, _ := do(t, c, "GET", u, "Range", rg); res.StatusCode != 410 {
			t.Errorf("new download %q after the limit = %d", rg, res.StatusCode)
		}
	}
	if res, _ := do(t, e.client(), "GET", u, "Range", "bytes=5-"); res.StatusCode != 410 {
		t.Errorf("a range without the ticket after the limit = %d", res.StatusCode)
	}
	if res, _ := do(t, e.client(), "HEAD", u); res.StatusCode != 410 {
		t.Errorf("HEAD after the limit = %d", res.StatusCode)
	}
	if res, _ := do(t, c, "GET", e.srv.URL+"/s/"+tok); res.StatusCode != 410 {
		t.Errorf("page after the limit = %d", res.StatusCode)
	}
	if n := e.count(tok); n != 1 {
		t.Errorf("count = %d", n)
	}
}

// blockingFiles holds every Open of a file called big.bin until release
// is closed, so a test can keep zips running.
type blockingFiles struct {
	*linktest.Fake
	opened  chan string
	release chan struct{}
}

func (b *blockingFiles) Open(ctx context.Context, who files.Who, share, p string) (*os.File, *files.Entry, error) {
	if strings.HasSuffix(p, "big.bin") {
		b.opened <- p
		<-b.release
	}
	return b.Fake.Open(ctx, who, share, p)
}

func TestZipConcurrencyLimits(t *testing.T) {
	e := newEnv(t)
	bf := &blockingFiles{Fake: e.fake, opened: make(chan string, 10), release: make(chan struct{})}
	e.pub.Files = bf
	for _, d := range []string{"A", "B", "C"} {
		e.fake.Write("media", d+"/big.bin", "BIG")
	}
	e.fake.Write("media", "C/small.txt", "small")
	_, ta := e.link(sharelinks.Request{Share: "media", Path: "A"}, true)
	_, tb := e.link(sharelinks.Request{Share: "media", Path: "B"}, true)
	_, tc := e.link(sharelinks.Request{Share: "media", Path: "C"}, true)
	zipURL := func(tok string) string { return e.srv.URL + "/s/" + tok + "/download" }
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for _, tok := range []string{ta, tb} {
		wg.Add(1)
		go func(tok string) {
			defer wg.Done()
			res, err := http.Get(zipURL(tok))
			if err != nil {
				results <- 0
				return
			}
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
			results <- res.StatusCode
		}(tok)
	}
	<-bf.opened
	<-bf.opened
	c := e.client()
	// Link A is busy: one zip per link at a time.
	if res, body := do(t, c, "GET", zipURL(ta)); res.StatusCode != 429 || res.Header.Get("Retry-After") == "" || !strings.Contains(body, "already being downloaded") {
		t.Errorf("second zip of a link = %d", res.StatusCode)
	}
	// This address has two going: two per address.
	if res, _ := do(t, c, "GET", zipURL(tc)); res.StatusCode != 429 {
		t.Errorf("third zip from one address = %d", res.StatusCode)
	}
	// Single files still download meanwhile.
	if res, body := do(t, c, "GET", zipURL(tc)+"?path=small.txt"); res.StatusCode != 200 || body != "small" {
		t.Errorf("file during zips = %d %q", res.StatusCode, body)
	}
	if n := e.count(ta); n != 1 {
		t.Errorf("a refused zip was counted: %d", n)
	}
	close(bf.release)
	wg.Wait()
	close(results)
	for code := range results {
		if code != 200 {
			t.Errorf("running zip = %d", code)
		}
	}
	if res, _ := do(t, c, "GET", zipURL(ta)); res.StatusCode != 200 {
		t.Errorf("zip after the others finished = %d", res.StatusCode)
	}
}

func readZip(t *testing.T, body string) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(strings.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = string(b)
	}
	return out
}

func TestZipSizeCapAndNames(t *testing.T) {
	e := newEnv(t)
	big := strings.Repeat("x", 600_000)
	e.fake.Write("media", "Big/a.bin", big)
	e.fake.Write("media", "Big/b.bin", big)
	e.fake.Write("media", `Names/a\b.txt`, "1")
	e.fake.Write("media", "Names/c:d.txt", "2")
	e.fake.Write("media", "Names/tab\tname.txt", "3")
	e.fake.Write("media", `Names/sub\dir/x.txt`, "4")
	_, tb := e.link(sharelinks.Request{Share: "media", Path: "Big", MaxZipBytes: 1_000_000}, true)
	l, tn := e.link(sharelinks.Request{Share: "media", Path: "Names"}, true)
	if l.MaxZipBytes != sharelinks.DefaultZipBytes {
		t.Errorf("default zip cap = %d", l.MaxZipBytes)
	}
	for _, bad := range []int64{-1, 999_999, sharelinks.MaxZipBytes + 1} {
		q := sharelinks.Request{Share: "media", Path: "Big", MaxZipBytes: bad}
		if len(q.Validate()) == 0 {
			t.Errorf("zip cap %d allowed", bad)
		}
	}
	c := e.client()
	res, body := do(t, c, "GET", e.srv.URL+"/s/"+tb+"/download")
	got := readZip(t, body)
	if res.StatusCode != 200 || got["a.bin"] != big || got["b.bin"] != "" || !strings.Contains(got["Not included.txt"], "at most 1 MB") {
		t.Errorf("capped zip = %d %d entries, note %q", res.StatusCode, len(got), got["Not included.txt"])
	}
	_, body = do(t, c, "GET", e.srv.URL+"/s/"+tn+"/download")
	var names []string
	for n := range readZip(t, body) {
		names = append(names, n)
	}
	sort.Strings(names)
	if strings.Join(names, "|") != "a_b.txt|c_d.txt|sub_dir/|sub_dir/x.txt|tab_name.txt" {
		t.Errorf("zip names = %q", names)
	}
}

func uploadSized(t *testing.T, c *http.Client, u string, sizes map[string]int) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	var names []string
	for n := range sizes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, _ := mw.CreateFormFile("file", n)
		_, _ = w.Write(bytes.Repeat([]byte("u"), sizes[n]))
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
	return res.StatusCode, string(b)
}

func TestUploadBudget(t *testing.T) {
	e := newEnv(t)
	e.pub.MaxFileBytes = 300_000
	e.fake.Write("media", "Drop/keep.txt", "KEEP")
	l, tok := e.link(sharelinks.Request{Share: "media", Path: "Drop", AllowUpload: true, MaxUploadBytes: 1_000_000}, true)
	if l.MaxUploadBytes != 1_000_000 || l.UploadedBytes != 0 {
		t.Fatalf("link %+v", l)
	}
	if def, _ := e.link(sharelinks.Request{Share: "media", Path: "Drop", AllowUpload: true}, true); def.MaxUploadBytes != sharelinks.DefaultUploadBudget {
		t.Fatalf("default upload budget = %d", def.MaxUploadBytes)
	}
	if ro, _ := e.link(sharelinks.Request{Share: "media", Path: "Drop"}, true); ro.MaxUploadBytes != 0 {
		t.Fatalf("a link without uploads has a budget: %d", ro.MaxUploadBytes)
	}
	for _, bad := range []int64{-1, 999_999, sharelinks.MaxUploadBudget + 1} {
		q := sharelinks.Request{Share: "media", Path: "Drop", AllowUpload: true, MaxUploadBytes: bad}
		if len(q.Validate()) == 0 {
			t.Errorf("upload budget %d allowed", bad)
		}
	}
	u := e.srv.URL + "/s/" + tok + "/upload"
	c := e.client()
	used := func() int64 {
		l, _ := e.links.ByToken(context.Background(), tok)
		return l.UploadedBytes
	}
	noRecycle := func(what string) {
		t.Helper()
		for _, call := range e.fake.Calls {
			if strings.HasPrefix(call, "delete ") {
				t.Errorf("%s: a partial upload went to the recycle bin: %s", what, call)
			}
		}
	}
	if code, body, _ := get(t, c, e.srv.URL+"/s/"+tok); code != 200 || !strings.Contains(body, "Up to 300 KB per file; 1 MB more in all.") {
		t.Errorf("upload note missing: %d", code)
	}

	// Too big for one file: refused, deleted for good, nothing used.
	if code, body := uploadSized(t, c, u, map[string]int{"huge.bin": 400_000}); code != 413 || !strings.Contains(body, "too big") {
		t.Errorf("file over the cap = %d %s", code, body)
	}
	if e.fake.Read("media", "Drop/huge.bin") != "" || used() != 0 || !strings.Contains(strings.Join(e.fake.Calls, "\n"), `purge HOME\alice media/Drop/huge.bin`) {
		t.Errorf("partial upload left: used %d, calls %v", used(), e.fake.Calls)
	}
	noRecycle("over the file cap")

	// Three files fit.
	if code, _ := uploadSized(t, c, u, map[string]int{"a.bin": 250_000, "b.bin": 250_000, "c.bin": 250_000}); code != 303 {
		t.Fatalf("upload = %d", code)
	}
	if used() != 750_000 {
		t.Fatalf("used = %d", used())
	}
	// The fourth fits exactly, the fifth doesn't: deleted, not counted.
	code, body := uploadSized(t, c, u, map[string]int{"d.bin": 250_000, "e.bin": 250_000})
	if code != 413 || !strings.Contains(body, "e.bin didn") || !strings.Contains(body, "1 file uploaded before") {
		t.Errorf("over the budget = %d %s", code, body)
	}
	if len(e.fake.Read("media", "Drop/d.bin")) != 250_000 || e.fake.Read("media", "Drop/e.bin") != "" || used() != 1_000_000 {
		t.Errorf("after the budget: d=%d e=%q used=%d", len(e.fake.Read("media", "Drop/d.bin")), e.fake.Read("media", "Drop/e.bin"), used())
	}
	noRecycle("over the budget")
	// Used up: refused at once.
	if code, body := uploadSized(t, c, u, map[string]int{"f.bin": 1}); code != 413 || !strings.Contains(body, "as much as it allows") {
		t.Errorf("upload to a full link = %d %s", code, body)
	}

	// Parallel reservations never go over the budget.
	l2, _ := e.link(sharelinks.Request{Share: "media", Path: "Drop", AllowUpload: true, MaxUploadBytes: 1_000_000}, true)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.links.ReserveUpload(context.Background(), l2.ID, 100_000) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 10 {
		t.Errorf("%d reservations of 100 KB fit in 1 MB", ok)
	}
}

func TestUploadRefusesDotAndControlNames(t *testing.T) {
	e := newEnv(t)
	_, tok := e.link(sharelinks.Request{Share: "media", Path: "Drop", AllowUpload: true}, true)
	e.fake.Write("media", "Drop/keep.txt", "KEEP")
	c := e.client()
	code, body, _ := upload(t, c, e.srv.URL+"/s/"+tok+"/upload", ".env", ".htaccess", `..\.ssh`)
	if code != 400 || !strings.Contains(body, "start with a dot") {
		t.Errorf("dot names = %d %s", code, body)
	}
	// Control characters (Go's multipart reader already stops at most of
	// them in a header; uploadName refuses the rest, see the unit test).
	if code, _, _ := upload(t, c, e.srv.URL+"/s/"+tok+"/upload", "bad\x01name.txt"); code != 400 {
		t.Errorf("control character name = %d", code)
	}
	for _, n := range []string{".env", ".htaccess", ".ssh", "bad\x01name.txt"} {
		if e.fake.Read("media", "Drop/"+n) != "" {
			t.Errorf("%q was written", n)
		}
	}
	if code, _, h := upload(t, c, e.srv.URL+"/s/"+tok+"/upload", ".env", "fine.txt"); code != 303 || !strings.Contains(h.Get("Location"), "uploaded=1") {
		t.Errorf("mixed upload = %d", code)
	}
}

func TestPasswordLockoutPerAddress(t *testing.T) {
	e := newEnv(t)
	e.pub.ClientIP = func(r *http.Request) string { return r.Header.Get("X-Test-IP") }
	e.pub.LinkPasswords = &auth.LoginLimiter{MaxFailures: 12, Window: time.Hour, Lockout: time.Hour}
	e.fake.Write("media", "a.txt", "A")
	_, tok := e.link(sharelinks.Request{Share: "media", Path: "a.txt", Password: "open sesame"}, false)
	post := func(ip, pw string) int {
		req, _ := http.NewRequest("POST", e.srv.URL+"/s/"+tok+"/unlock", strings.NewReader(url.Values{"password": {pw}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Test-IP", ip)
		res, err := e.client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	for i := 0; i < 5; i++ {
		post("198.51.100.1", "wrong")
	}
	if code := post("198.51.100.1", "open sesame"); code != 429 {
		t.Errorf("locked address = %d", code)
	}
	// Someone else with the link still gets in.
	if code := post("198.51.100.2", "open sesame"); code != 303 {
		t.Errorf("other address = %d", code)
	}
	// Past the link's own, much higher, ceiling it's locked for everyone.
	for i := 0; i < 7; i++ {
		post("198.51.100."+strconv.Itoa(10+i), "wrong")
	}
	if code := post("198.51.100.3", "open sesame"); code != 429 {
		t.Errorf("after the link's ceiling = %d", code)
	}
}
