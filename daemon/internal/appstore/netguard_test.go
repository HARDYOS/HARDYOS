package appstore

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func TestClassifyAddr(t *testing.T) {
	for addr, want := range map[string]string{
		"8.8.8.8": "public", "2606:4700::1111": "public", "100.63.255.255": "public", "172.32.0.1": "public",
		"127.0.0.1": "local", "::1": "local", "10.1.2.3": "local", "172.16.5.5": "local", "192.168.1.1": "local",
		"169.254.169.254": "local", "fe80::1": "local", "100.64.0.1": "local", "100.127.255.254": "local",
		"fd00::1": "local", "fc12::1": "local", "::ffff:192.168.0.1": "local", "64:ff9b::a00:1": "local",
		"0.0.0.0": "never", "::": "never", "0.1.2.3": "never", "224.0.0.1": "never", "ff02::1": "never",
		"255.255.255.255": "never",
	} {
		local, never := classifyAddr(netip.MustParseAddr(addr))
		got := "public"
		if never {
			got = "never"
		} else if local {
			got = "local"
		}
		if got != want {
			t.Errorf("%s: %s, want %s", addr, got, want)
		}
	}
	if err := checkDialAddr("10.0.0.1:443", false); err == nil {
		t.Error("private address allowed without the flag")
	}
	if err := checkDialAddr("10.0.0.1:443", true); err != nil {
		t.Errorf("private address with the flag: %v", err)
	}
	var le *LocalAddressError
	if err := checkDialAddr("[::]:443", true); !errors.As(err, &le) || !le.Never {
		t.Errorf("unspecified with the flag: %v", err)
	}
}

// A catalog on this server is refused unless the admin ticked "On my
// network"; the guard sits in the dialer, so the same holds for every
// redirect and for packages.
func TestCatalogFetchGuard(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var hits int
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/old.json" {
			http.Redirect(w, r, "/index.json", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, `{"name":"Local","apps":[]}`)
	}))
	defer srv.Close()
	s := &Store{DB: db, Client: srv.Client()}
	_, err = s.AddCatalog(ctx, srv.URL+"/index.json", "cade", false)
	if p, ok := err.(apps.Problems); !ok || !strings.Contains(p[0], "On my network") {
		t.Fatalf("local catalog without the flag: %v", err)
	}
	if hits != 0 {
		t.Fatalf("the server was reached %d times", hits)
	}
	c, err := s.AddCatalog(ctx, srv.URL+"/old.json", "cade", true)
	if err != nil || !c.LocalNetwork || hits != 2 {
		t.Fatalf("with the flag: %v %+v (%d hits)", err, c, hits)
	}
	// Refreshing follows the stored flag.
	if err := s.SetCatalogLocal(ctx, c.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RefreshCatalog(ctx, c.ID); err == nil || !strings.Contains(err.Error(), "On my network") {
		t.Fatalf("refresh after turning it off: %v", err)
	}
	if err := s.SetCatalogLocal(ctx, 999, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing catalog: %v", err)
	}
}
