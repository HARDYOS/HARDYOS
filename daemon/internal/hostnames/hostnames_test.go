package hostnames_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/hostnames"
	"github.com/hardyos/hardyos/daemon/internal/hostnames/hosttest"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/tlscert"
)

func newManager(t *testing.T) (*hostnames.Manager, *hosttest.Env, *tlscert.Store) {
	t.Helper()
	env := hosttest.New(t, "example.net", nil)
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	self, key, _ := tlscert.Generate([]string{"nas"}, nil, time.Now())
	fb, _ := tls.X509KeyPair(self, key)
	certs := tlscert.NewStore(fb)
	m := &hostnames.Manager{Store: &hostnames.Store{DB: db, Keys: secretbox.NewStaticSource()}, DNS: hostnames.PrivDNS{Priv: env.Priv},
		Certs: certs, Dir: t.TempDir(), Directory: env.ACME.Directory()}
	return m, env, certs
}

func TestIssueWildcardThroughRootsDNS(t *testing.T) {
	m, env, certs := newManager(t)
	ctx := context.Background()
	if _, err := m.Issue(ctx, nil); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("issued without a token: %v", err)
	}
	env.SetToken(t, "home.example.net")
	if !m.Due("home.example.net") {
		t.Fatal("nothing installed but not due")
	}
	var steps []string
	rec, err := m.Issue(ctx, func(_ float64, s string) { steps = append(steps, s) })
	if err != nil {
		t.Fatal(err)
	}
	if rec.Names != "*.home.example.net" || rec.NotAfter.IsZero() {
		t.Fatalf("%+v", rec)
	}
	// The challenge went through the fake Cloudflare (via root) and was
	// removed again.
	if len(env.ACME.Checked) != 1 || env.ACME.Checked[0] != "_acme-challenge.home.example.net" {
		t.Fatalf("%v", env.ACME.Checked)
	}
	if n := len(env.CF.TXT("_acme-challenge.home.example.net")); n != 0 {
		t.Fatalf("%d challenge records left", n)
	}
	// Never served while the hostnames aren't active.
	if c, _ := certs.GetCertificate(&tls.ClientHelloInfo{ServerName: "photos.home.example.net"}); c.Leaf != nil && c.Leaf.Issuer.CommonName == "Fake ACME CA" {
		t.Fatal("wildcard served while inactive")
	}
	certs.SetActive(true)
	// Served for names one label under the base, not for others.
	for name, want := range map[string]bool{"photos.home.example.net": true, "NAS.home.example.net.": true,
		"a.b.home.example.net": false, "home.example.net": false, "192.168.1.5": false, "nas": false} {
		c, _ := certs.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
		leaf, _ := x509.ParseCertificate(c.Certificate[0])
		got := leaf.Issuer.CommonName == "Fake ACME CA"
		if got != want {
			t.Errorf("%s: wildcard=%v", name, got)
		}
	}
	if m.Due("home.example.net") {
		t.Fatal("fresh certificate due")
	}
	if !m.Due("other.example.net") {
		t.Fatal("certificate for another base not due")
	}
	// It's kept on disk and comes back at start.
	certs2 := tlscert.NewStore(tls.Certificate{})
	m2 := &hostnames.Manager{Store: m.Store, DNS: m.DNS, Certs: certs2, Dir: m.Dir}
	if err := m2.LoadInstalled(ctx); err != nil {
		t.Fatal(err)
	}
	if b, leaf := certs2.Wildcard(); b != "home.example.net" || leaf == nil {
		t.Fatal("not loaded")
	}
	ok, failed, err := m.Store.Last(ctx)
	if err != nil || ok == nil || failed != nil {
		t.Fatalf("%+v %+v %v", ok, failed, err)
	}
	// The same ACME account is used again.
	if _, err := m.Issue(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if env.ACME.Issued != 2 {
		t.Fatalf("issued %d", env.ACME.Issued)
	}
}

func TestRenewalWindowAndFailure(t *testing.T) {
	m, env, _ := newManager(t)
	ctx := context.Background()
	env.SetToken(t, "home.example.net")
	env.ACME.Validity = 20 * 24 * time.Hour // inside the renewal window
	if _, err := m.Issue(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if !m.Due("home.example.net") {
		t.Fatal("a certificate expiring in 20 days isn't due")
	}
	// A challenge Let's Encrypt can't see fails cleanly and is recorded.
	env.ACME.Lookup = func(string) []string { return nil }
	if _, err := m.Issue(ctx, nil); err == nil {
		t.Fatal("issued without a visible challenge")
	}
	_, failed, _ := m.Store.Last(ctx)
	if failed == nil || failed.Error == "" {
		t.Fatalf("%+v", failed)
	}
	if n := len(env.CF.TXT("_acme-challenge.home.example.net")); n != 0 {
		t.Fatalf("%d challenge records left after a failure", n)
	}
}

func TestSettingsValidate(t *testing.T) {
	for _, bad := range []string{"x", "a@b@c", "Alice <a@example.net>"} {
		if (hostnames.Settings{Email: bad}).Validate() == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if (hostnames.Settings{Email: "cade@example.net"}).Validate() != nil {
		t.Fatal("refused a plain address")
	}
}
