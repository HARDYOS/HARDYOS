// Package hosttest wires a fake Cloudflare, hardyd-priv's real DNS
// operations (on a test socket) and a fake ACME server together, for tests
// of the hostnames feature. Nothing reaches the network.
package hosttest

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cfdns/cftest"
	"github.com/hardyos/hardyos/daemon/internal/hostnames/acmetest"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// Token is the fake Cloudflare's token.
const Token = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"

// Env is the wired fakes.
type Env struct {
	CF     *cftest.Server
	ACME   *acmetest.Server
	Server *priv.Server
	Priv   *priv.Client
	KeyDir string
	Socket string
}

// New starts the fakes with zone (e.g. "example.net"). register adds more
// operations to the test hardyd-priv before it starts (may be nil).
func New(t testing.TB, zone string, register func(*priv.Server)) *Env {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cf := cftest.New(Token, zone)
	t.Cleanup(cf.Close)
	ac := acmetest.New()
	ac.Lookup = cf.TXT
	t.Cleanup(ac.Close)
	dir, err := os.MkdirTemp("", "hosttest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	priv.RegisterBuiltins(ps)
	keys := filepath.Join(dir, "keys")
	priv.RegisterDNS(ps, priv.DNSEnv{KeyDir: keys, Client: cf.Client})
	if register != nil {
		register(ps)
	}
	go func() { _ = ps.Serve(ctx, ln) }()
	return &Env{CF: cf, ACME: ac, Server: ps, Priv: priv.NewClient(sock), KeyDir: keys, Socket: sock}
}

// SetToken gives root the token for base.
func (e *Env) SetToken(t testing.TB, base string) {
	t.Helper()
	if err := e.Priv.Call(context.Background(), priv.OpDNSTokenSet, priv.DNSTokenSetArgs{Token: Token, Base: base}, nil); err != nil {
		t.Fatal(err)
	}
}
