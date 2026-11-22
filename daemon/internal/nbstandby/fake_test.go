package nbstandby

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const testHost = "vpn.example.net"

const testGeneration = "0123456789abcdef0123456789abcdef"

var testConfig = `server:
  listenAddress: ":80"
  exposedAddress: "https://vpn.example.net:443"
  stunPorts:
    - 3478
  authSecret: "relaysecret"
  dataDir: "/var/lib/netbird"
  auth:
    issuer: "https://vpn.example.net/oauth2"
    sessionCookieEncryptionKey: "cookiekey"
  store:
    engine: "sqlite"
    encryptionKey: "c3RvcmVrZXlzdG9yZWtleXN0b3Jla2V5c3RvcmVrZXk="
`

func sqliteFile(body string) []byte {
	return append(append([]byte{}, sqliteMagic...), []byte(body)...)
}

func testACME(t *testing.T, host string, notAfter time.Time) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	store := map[string]any{"letsencrypt": map[string]any{"Account": map[string]any{"Email": "a@example.net"},
		"Certificates": []any{map[string]any{"domain": map[string]any{"main": host}, "certificate": base64.StdEncoding.EncodeToString(pemCert),
			"key": base64.StdEncoding.EncodeToString([]byte("KEY"))}}}}
	b, _ := json.Marshal(store)
	return b
}

// snapFiles are a snapshot's entries (without the manifest).
type snapFiles map[string][]byte

func defaultFiles(t *testing.T) snapFiles {
	return snapFiles{
		EntryConfig:    []byte(testConfig),
		EntryDashboard: []byte("AUTH_CLIENT_ID=netbird-dashboard\n"),
		EntryStore:     sqliteFile("store"),
		EntryIDP:       sqliteFile("idp"),
		EntryACME:      testACME(t, testHost, time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)),
	}
}

type tarEntry struct {
	name string
	body []byte
	typ  byte
	link string
}

// makeSnapshot builds a tar like the VPS script's; edit tweaks the manifest.
func makeSnapshot(t *testing.T, files snapFiles, edit func(*Manifest)) []byte {
	t.Helper()
	m := Manifest{Format: 1, Created: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC), Hostname: testHost,
		Image: "netbirdio/netbird-server:0.83.1", Digest: "sha256:f6acc1a6", Version: "0.83.1", Engine: "sqlite", Peers: 7, SetupKeys: 2,
		Generation: testGeneration, Files: map[string]string{}}
	var names []string
	for n, b := range files {
		s := sha256.Sum256(b)
		m.Files[n] = hex.EncodeToString(s[:])
		names = append(names, n)
	}
	sort.Strings(names)
	if edit != nil {
		edit(&m)
	}
	mb, _ := json.Marshal(m)
	entries := []tarEntry{{name: EntryManifest, body: mb}}
	for _, n := range names {
		entries = append(entries, tarEntry{name: n, body: files[n]})
	}
	return buildTar(t, entries)
}

func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.body)), Typeflag: typ, Linkname: e.link}
		if typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write(e.body)
		}
	}
	tw.Close()
	return buf.Bytes()
}

// fakeVPS is the VPS's forced command, in process.
type fakeVPS struct {
	mu       sync.Mutex
	snapshot []byte
	status   string
	fail     map[string]string // verb -> stderr message
	restored []byte
	verbs    []string
	hang     bool
}

func (f *fakeVPS) Run(ctx context.Context, verb string, stdin io.Reader, stdout io.Writer) error {
	f.mu.Lock()
	f.verbs = append(f.verbs, verb)
	msg, failing := f.fail[verb]
	snap, status, hang := f.snapshot, f.status, f.hang
	f.mu.Unlock()
	if failing {
		return &VPSError{Msg: msg}
	}
	switch verb {
	case VerbStatus:
		_, err := io.WriteString(stdout, status)
		return err
	case VerbSnapshot:
		if hang {
			<-ctx.Done()
			return ctx.Err()
		}
		_, err := stdout.Write(snap)
		return err
	case VerbFence, VerbUnfence:
		_, err := io.WriteString(stdout, verb+"d")
		return err
	case VerbRestore:
		b, err := io.ReadAll(stdin)
		if err != nil {
			return err
		}
		f.mu.Lock()
		f.restored = b
		f.mu.Unlock()
		_, err = io.WriteString(stdout, "restored; the VPS's previous databases are in /var/lib/hardyos-standby/root/before-handback-x\n")
		return err
	}
	return errors.New("refused")
}

func (f *fakeVPS) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.verbs...)
}

// fakeApps is the installed app.
type fakeApps struct {
	dir       string
	running   bool
	catalog   bool
	installed bool
}

func (a *fakeApps) StandbyApp(context.Context) (string, bool, bool, error) {
	if !a.installed {
		return "", false, false, fmt.Errorf("%w", ErrNoApp)
	}
	return a.dir, a.running, a.catalog, nil
}

type fakeNet struct {
	mu    sync.Mutex
	calls []string
}

func (n *fakeNet) Apply(_ context.Context, open bool, host string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, fmt.Sprintf("apply open=%v %s", open, host))
	return nil
}

func (n *fakeNet) Remove(context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls = append(n.calls, "remove")
	return nil
}

func (n *fakeNet) last() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.calls) == 0 {
		return ""
	}
	return n.calls[len(n.calls)-1]
}

func readTar(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		out[h.Name] = body
	}
}

func hasLine(s, want string) bool {
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) == want {
			return true
		}
	}
	return false
}
