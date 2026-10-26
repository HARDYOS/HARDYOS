package network

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDomainDNSWithDHCP(t *testing.T) {
	m, _, root := newManager(t)
	ctx := context.Background()
	var dcs []string
	domain := "home.example.net"
	m.DomainDNS = func() ([]string, string) { return dcs, domain }
	read := func(rel string) string { b, _ := os.ReadFile(filepath.Join(root, rel)); return string(b) }

	// No domain, never had one: dhclient's file is left alone.
	dcs = nil
	if err := m.SyncDomainDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if read(ResolvPath) != "nameserver 192.168.1.1\n" {
		t.Fatalf("resolv.conf touched without a domain: %q", read(ResolvPath))
	}

	dcs = []string{"192.168.1.30", "192.168.1.31"}
	if err := m.SyncDomainDNS(ctx); err != nil {
		t.Fatal(err)
	}
	got := read(ResolvPath)
	if !strings.Contains(got, "nameserver 192.168.1.30\nnameserver 192.168.1.31\nnameserver 192.168.1.1\n") || !strings.Contains(got, "search home.example.net") {
		t.Fatalf("resolv.conf =\n%s", got)
	}
	if hook := read(DomainHookPath); !strings.Contains(hook, `new_domain_name_servers="192.168.1.30 192.168.1.31 ${new_domain_name_servers}"`) {
		t.Fatalf("dhclient hook =\n%s", hook)
	}
	// Idempotent.
	before := got
	_ = m.SyncDomainDNS(ctx)
	if read(ResolvPath) != before {
		t.Fatal("a second sync changed resolv.conf")
	}

	// The domain goes away: our servers and the hook go with it.
	dcs = nil
	if err := m.SyncDomainDNS(ctx); err != nil {
		t.Fatal(err)
	}
	got = read(ResolvPath)
	if strings.Contains(got, "192.168.1.30") || strings.Contains(got, "home.example.net") || !strings.Contains(got, "nameserver 192.168.1.1") {
		t.Fatalf("after the domain left:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(root, DomainHookPath)); err == nil {
		t.Fatal("the dhclient hook stayed")
	}
}

func TestDomainDNSWithStaticDNS(t *testing.T) {
	m, _, root := newManager(t)
	ctx := context.Background()
	c := m.Current()
	c.Interfaces[0].Addressing = Addressing{Mode: ModeStatic, Address: "192.168.1.20/24", Gateway: "192.168.1.1"}
	c.DNS = []string{"192.168.1.1", "9.9.9.9"}
	m.DomainDNS = func() ([]string, string) { return []string{"192.168.1.30", "192.168.1.31"}, "home.example.net" }
	if err := m.WriteNow(c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(root, ResolvPath))
	got := string(b)
	// Three servers at most: both DCs, then the first of the person's own.
	if !strings.Contains(got, "nameserver 192.168.1.30\nnameserver 192.168.1.31\nnameserver 192.168.1.1\n") || strings.Contains(got, "9.9.9.9") {
		t.Fatalf("resolv.conf =\n%s", got)
	}
	if err := m.SyncDomainDNS(ctx); err != nil {
		t.Fatal(err)
	}
	if b2, _ := os.ReadFile(filepath.Join(root, ResolvPath)); string(b2) != got {
		t.Fatalf("sync disagreed with WriteNow:\n%s\nvs\n%s", b2, got)
	}
}

func TestRenderResolvDomainKeepsAnOutsideServer(t *testing.T) {
	got := RenderResolvDomain([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, "x.net", []string{"1.1.1.1"}, nil)
	if !strings.Contains(got, "nameserver 10.0.0.1\nnameserver 10.0.0.2\nnameserver 1.1.1.1\n") {
		t.Fatalf("got\n%s", got)
	}
}
