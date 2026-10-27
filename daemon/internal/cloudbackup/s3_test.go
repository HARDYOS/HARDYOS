package cloudbackup

import (
	"bufio"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeS3 is just enough S3 for restic (path-style, one bucket), checking
// the access key in every request's signature.
type fakeS3 struct {
	mu      sync.Mutex
	bucket  string
	key     string
	objects map[string][]byte
	denied  int
	seen    []string // request lines, to check no secret is in a URL
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, r.Method+" "+r.URL.String())
	if !strings.Contains(r.Header.Get("Authorization"), "Credential="+f.key+"/") {
		f.denied++
		w.WriteHeader(http.StatusForbidden)
		code := "AccessDenied"
		if strings.Contains(r.Header.Get("Authorization"), "Credential=AKIDUNKNOWN") {
			// What AWS answers for a key it doesn't know; restic retries it.
			code = "InvalidAccessKeyId"
		}
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>Access Denied</Message></Error>`, code)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(p, "/")
	if bucket != f.bucket {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<Error><Code>NoSuchBucket</Code><Message>no bucket</Message></Error>`)
		return
	}
	q := r.URL.Query()
	switch {
	case key == "" && q.Has("location"):
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">us-east-1</LocationConstraint>`)
	case key == "" && r.Method == http.MethodHead:
		w.WriteHeader(http.StatusOK)
	case key == "" && r.Method == http.MethodGet:
		f.list(w, q.Get("prefix"), q.Get("delimiter"))
	case r.Method == http.MethodPut:
		var body io.Reader = r.Body
		if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
			body = dechunk(r.Body)
		}
		b, err := io.ReadAll(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.objects[key] = b
		w.Header().Set("ETag", `"`+strconv.Itoa(len(b))+`"`)
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		b, ok := f.objects[key]
		if !ok {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			if r.Method == http.MethodGet {
				fmt.Fprint(w, `<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
			}
			return
		}
		w.Header().Set("ETag", `"`+strconv.Itoa(len(b))+`"`)
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		http.ServeContent(w, r, key, time.Now(), strings.NewReader(string(b)))
	case r.Method == http.MethodDelete:
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
}

func (f *fakeS3) list(w http.ResponseWriter, prefix, delim string) {
	var keys []string
	prefixes := map[string]bool{}
	for k := range f.objects {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if delim != "" {
			if i := strings.Index(k[len(prefix):], delim); i >= 0 {
				prefixes[k[:len(prefix)+i+1]] = true
				continue
			}
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>%s</Name><Prefix>%s</Prefix><KeyCount>%d</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>`, f.bucket, prefix, len(keys))
	for _, k := range keys {
		fmt.Fprintf(&b, `<Contents><Key>%s</Key><LastModified>%s</LastModified><ETag>"%d"</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass></Contents>`,
			k, time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), len(f.objects[k]), len(f.objects[k]))
	}
	for p := range prefixes {
		fmt.Fprintf(&b, `<CommonPrefixes><Prefix>%s</Prefix></CommonPrefixes>`, p)
	}
	b.WriteString(`</ListBucketResult>`)
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprint(w, b.String())
}

// dechunk reads aws-chunked bodies (signatures not checked).
func dechunk(r io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		br := bufio.NewReader(r)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			sz, _, _ := strings.Cut(strings.TrimSpace(line), ";")
			n, err := strconv.ParseInt(sz, 16, 64)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			if n == 0 {
				pw.Close()
				return
			}
			if _, err := io.CopyN(pw, br, n); err != nil {
				pw.CloseWithError(err)
				return
			}
			_, _ = br.ReadString('\n')
		}
	}()
	return pr
}

type staticResolver map[string][]netip.Addr

func (s staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := s[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func TestS3CredentialsAndEgress(t *testing.T) {
	e := newEnv(t)
	fake := &fakeS3{bucket: "hardy-test", key: "AKIDTESTKEY1234", objects: map[string][]byte{}}
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	ca := filepath.Join(e.base, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	port := strings.TrimPrefix(srv.URL, "https://127.0.0.1:")
	e.root.Restic.CACert = ca
	tgt := Target{ID: "s3", Name: "Fake S3", Kind: KindS3, Endpoint: "https://127.0.0.1:" + port, Bucket: "hardy-test", Prefix: "nas"}
	ctx := context.Background()

	// Loopback is never a destination...
	if _, err := e.root.Save(ctx, SaveArgs{Target: tgt, AccessKey: fake.key, SecretKey: "secret-secret"}); err == nil || !strings.Contains(err.Error(), "not an address") {
		t.Fatalf("a loopback endpoint was accepted: %v", err)
	}
	// ...not even with "allow LAN".
	tgt.AllowLAN = true
	if _, err := e.root.Save(ctx, SaveArgs{Target: tgt, AccessKey: fake.key, SecretKey: "secret-secret"}); err == nil {
		t.Fatal("a loopback endpoint was accepted with allow LAN")
	}
	tgt.AllowLAN = false
	// The test lets loopback through on both checks (save and proxy).
	allow := func(a netip.Addr) bool { return a.IsLoopback() }
	e.root.TestAllow, e.root.Restic.TestAllow = allow, allow

	// A wrong access key: the save fails, nothing is kept.
	if _, err := e.root.Save(ctx, SaveArgs{Target: tgt, AccessKey: "AKIDWRONG0000", SecretKey: "secret-secret"}); err == nil {
		t.Fatal("saved with a wrong access key")
	}
	// An unknown key restic keeps retrying: the access test gives up.
	e.root.AccessTimeout = 3 * time.Second
	if _, err := e.root.Save(ctx, SaveArgs{Target: tgt, AccessKey: "AKIDUNKNOWN00", SecretKey: "secret-secret"}); err == nil || !strings.Contains(err.Error(), "in time") {
		t.Fatalf("an unknown key: %v", err)
	}
	e.root.AccessTimeout = 0
	if l, _ := e.root.Targets(); len(l) != 0 {
		t.Fatal("a failed destination was kept")
	}
	if fake.denied == 0 {
		t.Fatal("the fake S3 never saw the wrong key")
	}
	res, err := e.root.Save(ctx, SaveArgs{Target: tgt, AccessKey: fake.key, SecretKey: "secret-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.Target.AccessKeyHint != "…1234" {
		t.Fatalf("save: %+v", res)
	}
	if _, ok := fake.objects["nas/config"]; !ok {
		t.Fatalf("no repository was made: %v", keysOf(fake.objects))
	}
	// A backup through the egress proxy.
	share := filepath.Join(e.base, "docs")
	write(t, filepath.Join(share, "a.txt"), "hello")
	e.shares.add("docs", "Docs", share)
	if x, _ := e.backup("s3", "t", "s1", Item{Kind: ItemShare, ID: "docs"}); x.Error != "" {
		t.Fatal(x.Error)
	}
	for _, l := range fake.seen {
		if strings.Contains(l, "secret-secret") || strings.Contains(l, fake.key+"&") {
			t.Fatalf("a credential is in a request URL: %s", l)
		}
	}
	// Changing the endpoint to another host means another repository.
	moved := res.Target
	moved.Endpoint = "https://localhost:" + port
	if _, err := e.root.Save(ctx, SaveArgs{Target: moved, Update: true}); err == nil {
		t.Fatal("moved a destination without its key")
	}
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestEgressProxyRefuses(t *testing.T) {
	// Something listening on loopback that the proxy must not reach.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "inside") }))
	defer srv.Close()
	host, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")
	p, _ := strconv.Atoi(port)
	cases := []struct {
		name    string
		rules   []hostRule
		res     staticResolver
		connect string
	}{
		{"other host", []hostRule{{host: "s3.example.com", port: 443}}, staticResolver{}, host + ":" + port},
		{"rebinding to loopback", []hostRule{{host: "s3.example.com", port: p}}, staticResolver{"s3.example.com": {netip.MustParseAddr(host)}}, "s3.example.com:" + port},
		{"metadata address", []hostRule{{host: "169.254.169.254", port: 80}}, staticResolver{}, "169.254.169.254:80"},
		{"b2 lookalike", []hostRule{{suffix: ".backblazeb2.com", port: 443}}, staticResolver{}, "evil-backblazeb2.com:443"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eg, err := startEgress(c.rules, c.res, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer eg.Close()
			conn, err := net.Dial("tcp", eg.ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", c.connect, c.connect)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("CONNECT %s answered %d", c.connect, resp.StatusCode)
			}
		})
	}
}

func TestAddrAllowed(t *testing.T) {
	for _, c := range []struct {
		a   string
		lan bool
		ok  bool
	}{
		{"8.8.8.8", false, true},
		{"2606:4700::1111", false, true},
		{"127.0.0.1", true, false},
		{"::1", true, false},
		{"169.254.169.254", true, false},
		{"fe80::1", true, false},
		{"10.0.0.5", false, false},
		{"10.0.0.5", true, true},
		{"192.168.1.20", true, true},
		{"fd00::5", true, true},
		{"100.64.1.1", false, false},
		{"0.0.0.0", true, false},
		{"::ffff:127.0.0.1", true, false},
		{"64:ff9b::7f00:1", true, false},
		{"224.0.0.1", true, false},
	} {
		err := AddrAllowed(netip.MustParseAddr(c.a), c.lan)
		if (err == nil) != c.ok {
			t.Errorf("%s lan=%v: %v", c.a, c.lan, err)
		}
	}
}

func TestTargetValidation(t *testing.T) {
	good := Target{ID: "aws", Name: "AWS", Kind: KindS3, Endpoint: "https://s3.us-east-1.amazonaws.com", Bucket: "my-bucket", Prefix: "nas/one"}
	if err := good.Normalize(false); err != nil {
		t.Fatal(err)
	}
	if r := good.Repository(); r != "s3:https://s3.us-east-1.amazonaws.com/my-bucket/nas/one" {
		t.Fatal(r)
	}
	b2 := Target{ID: "b2", Name: "B2", Kind: KindB2, Bucket: "My-Bucket-1"}
	if err := b2.Normalize(false); err != nil || b2.Repository() != "b2:My-Bucket-1:hardyos" {
		t.Fatalf("%v %s", err, b2.Repository())
	}
	for _, bad := range []Target{
		{ID: "x", Name: "x", Kind: KindS3, Endpoint: "http://s3.example.com", Bucket: "abc"},
		{ID: "x", Name: "x", Kind: KindS3, Endpoint: "https://s3.example.com/path", Bucket: "abc"},
		{ID: "x", Name: "x", Kind: KindS3, Endpoint: "https://user:pw@s3.example.com", Bucket: "abc"},
		{ID: "x", Name: "x", Kind: KindS3, Endpoint: "https://s3.example.com?x=1", Bucket: "abc"},
		{ID: "x", Name: "x", Kind: KindS3, Endpoint: "https://s3.example.com", Bucket: "AB"},
		{ID: "x", Name: "x", Kind: KindS3, Endpoint: "https://s3.example.com", Bucket: "abc", Prefix: "a/../b"},
		{ID: "x", Name: "x", Kind: KindS3, Endpoint: "https://s3.example.com", Bucket: "abc", Prefix: "a b"},
		{ID: "x", Name: "x", Kind: KindS3, Endpoint: "https://-bad.example.com", Bucket: "abc"},
		{ID: "x", Name: "x", Kind: KindLocal, Path: "/tmp/x"},
		{ID: "X!", Name: "x", Kind: KindB2, Bucket: "bucket1"},
		{ID: "x", Name: "x", Kind: "ftp", Bucket: "bucket1"},
		{ID: "x", Name: "x", Kind: KindB2, Bucket: "bucket1", LimitUploadKiB: -1},
	} {
		if err := bad.Normalize(false); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	if CheckCredentials(KindS3, Credentials{AccessKey: "AK ID", SecretKey: "x"}) == nil {
		t.Error("a key with a space was accepted")
	}
}
