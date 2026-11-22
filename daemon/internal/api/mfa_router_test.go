package api

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	testRouter    = "192.168.1.1"
	testRouterMAC = "aa:bb:cc:00:11:22"
)

// davFrom is a WebDAV PROPFIND with a password from an address.
func davFrom(t *testing.T, e *mfaEnv, ip, user, pw string) (int, string) {
	t.Helper()
	r, _ := http.NewRequest("PROPFIND", e.srv.URL+"/dav/", nil)
	r.SetBasicAuth(user, pw)
	r.Header.Set("Depth", "0")
	if ip != "" {
		r.Header.Set("X-Forwarded-For", ip)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// The router's own address is outside unless an administrator at home
// trusted it; trusting it is bound to that router, and even then its codes
// and own passwords aren't home's (re-review HIGH 1).
func TestRouterAddress(t *testing.T) {
	e := newMFAEnv(t)
	var ch LoginChallenge
	if code := doFrom(e.client(t), testRouter, "POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &ch); code != 202 {
		t.Fatalf("login from the router = %d (outside wants a code)", code)
	}
	var pol TwoFactorPolicy
	e.admin.do("GET", "/api/v1/auth/2fa/policy", nil, &pol)
	if pol.RouterSeenAt == nil || pol.TrustRouter.On || !pol.CanChangeTrustRouter {
		t.Fatalf("policy = %+v", pol)
	}
	// Seen is kept across restarts.
	if v, err := e.db.GetSetting(t.Context(), settingRouterSeen); err != nil || v == "" {
		t.Fatalf("router seen not saved: %q %v", v, err)
	}

	// Not from the router's address itself (nor from outside).
	var er ErrorResponse
	on := true
	admin := e.client(t)
	e.login(t, admin, "", "cade", "supersecret1")
	if code := doFrom(admin, testRouter, "PUT", "/api/v1/auth/2fa/policy", map[string]any{"adminGraceDays": 7, "trustRouter": on}, &er); code == 200 {
		t.Fatal("the router's address trusted from the router")
	}
	// From home: on.
	if code := admin.do("PUT", "/api/v1/auth/2fa/policy", map[string]any{"adminGraceDays": 7, "trustRouter": on}, &pol); code != 200 || !pol.TrustRouter.On || pol.TrustRouter.IP != testRouter {
		t.Fatalf("trust router = %d %+v", code, pol)
	}
	if got := auditActions(e.admin, "auth.2fa.trust_router"); len(got) != 1 {
		t.Fatalf("trust router audit = %+v", got)
	}
	var u map[string]any
	if code := doFrom(e.client(t), testRouter, "POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &u); code != 200 {
		t.Fatalf("login from the trusted router = %d", code)
	}
	// Its sessions can't change the setting.
	if code := doFrom(admin, testRouter, "PUT", "/api/v1/auth/2fa/policy", map[string]any{"adminGraceDays": 7, "trustRouter": false}, &er); code != 403 || er.Code != "not_from_home" {
		t.Fatalf("turned off from the router = %d %+v", code, er)
	}
	// Own passwords stay refused for WebDAV from it.
	if code, body := davFrom(t, e, testRouter, "alice", alicePW); code != 401 {
		t.Fatalf("WebDAV with the own password from the router = %d %s", code, body)
	}
	if code, _ := davFrom(t, e, "192.168.1.20", "alice", alicePW); code != 207 {
		t.Fatalf("WebDAV at home = %d", code)
	}
	// The router's codes have their own bucket and count in the outside
	// budget (Origin.Outside with its own address).
	if o := e.server.origin(httptestReq(testRouter)); !o.Outside || o.IP != testRouter {
		t.Fatalf("router origin = %+v", o)
	}

	// Another router (a new MAC at the same address): lapsed.
	e.server.inside.routerFor = func() (netip.Addr, string) { return netip.MustParseAddr(testRouter), "aa:bb:cc:99:99:99" }
	e.server.inside.at = e.server.inside.at.AddDate(-1, 0, 0)
	if code := doFrom(e.client(t), testRouter, "POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &ch); code != 202 {
		t.Fatalf("login from a new router = %d", code)
	}
	e.admin.do("GET", "/api/v1/auth/2fa/policy", nil, &pol)
	if pol.TrustRouter.On || !pol.TrustRouter.Lapsed {
		t.Fatalf("lapsed = %+v", pol.TrustRouter)
	}
	off := false
	if code := admin.do("PUT", "/api/v1/auth/2fa/policy", map[string]any{"adminGraceDays": 7, "trustRouter": off}, &pol); code != 200 || pol.TrustRouter.Lapsed {
		t.Fatalf("off = %d %+v", code, pol)
	}
}

func httptestReq(ip string) *http.Request {
	r, _ := http.NewRequest("GET", "http://x/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", ip)
	return r
}

// Loopback is home only when its other end is root's or hardyd's; a
// forwarded claim of loopback isn't (re-review M4).
func TestLoopbackPeer(t *testing.T) {
	e := newMFAEnv(t)
	var ch LoginChallenge
	if code := doFrom(e.client(t), "", "POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &ch); code != 200 {
		t.Fatalf("loopback from hardyd's own user = %d", code)
	}
	// A proxy saying the client was one of this server's own addresses:
	// whose connection that was can't be told.
	e.server.inside.ownFor = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.168.1.5")} }
	e.server.inside.at = e.server.inside.at.AddDate(-1, 0, 0)
	if code := doFrom(e.client(t), "192.168.1.5", "POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &ch); code != 202 {
		t.Fatalf("a forwarded own address = %d", code)
	}
	e.server.inside.peerIsSelf = func(*http.Request) bool { return false }
	if code := doFrom(e.client(t), "", "POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &ch); code != 202 {
		t.Fatalf("loopback from another process (a host-network container) = %d", code)
	}
}

// The real lookup finds this process's own connection, and not another
// process's, even one of the same user.
func TestPeerIsSelfProc(t *testing.T) {
	if _, err := os.Stat("/proc/net/tcp"); err != nil {
		t.Skip("no /proc/net/tcp")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type seen struct {
		self bool
		uid  int
	}
	got := make(chan seen, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := peerProc(r)
		got <- seen{self: peerIsSelfProc(r), uid: p.uid}
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	res, err := http.Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if g := <-got; !g.self || g.uid != os.Getuid() {
		t.Fatalf("this process: %+v", g)
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3 for another process")
	}
	if out, err := exec.Command(py, "-I", "-c", "import sys, urllib.request; urllib.request.urlopen(sys.argv[1]).read()", "http://"+ln.Addr().String()+"/").CombinedOutput(); err != nil {
		t.Fatalf("python3: %v %s", err, out)
	}
	if g := <-got; g.self || g.uid != os.Getuid() {
		t.Fatalf("another process of the same user: %+v", g)
	}
}

func procHex(b []byte) string {
	var s string
	for i := 0; i < len(b); i += 4 {
		s += fmt.Sprintf("%08X", binary.NativeEndian.Uint32(b[i:]))
	}
	return s
}

func TestParseProcAddr(t *testing.T) {
	a, ok := parseProcAddr(procHex([]byte{127, 0, 0, 1}) + ":1F90")
	if !ok || a.String() != "127.0.0.1:8080" {
		t.Fatalf("v4 = %v %v", a, ok)
	}
	a, ok = parseProcAddr(procHex(netip.MustParseAddr("::1").AsSlice()) + ":0016")
	if !ok || a.String() != "[::1]:22" {
		t.Fatalf("v6 = %v %v", a, ok)
	}
	if _, ok := parseProcAddr("0100007:0016"); ok {
		t.Fatal("short address accepted")
	}
}

// A public IPv4 network or an IPv6 global prefix on the default-route
// interface isn't home (re-review M2).
func TestHomePrefix(t *testing.T) {
	for _, c := range []struct {
		ip    string
		bits  int
		def6  bool
		want  string
		label string
	}{
		{"192.168.1.20", 24, false, "192.168.1.0/24", "private IPv4"},
		{"10.1.2.3", 8, false, "10.0.0.0/8", "private IPv4 /8"},
		{"10.1.2.3", 7, false, "", "wider than the private range"},
		{"203.0.113.7", 24, false, "", "public IPv4 (a VPS)"},
		{"100.70.0.2", 10, false, "", "CGNAT"},
		{"fd12:3456::7", 64, true, "fd12:3456::/64", "ULA"},
		{"2001:db8:1::7", 64, false, "2001:db8:1::/64", "global, not the default route"},
		{"2001:db8:1::7", 64, true, "", "global on the default route"},
		{"fe80::1", 64, false, "", "link-local"},
	} {
		p, ok := homePrefix(netip.MustParseAddr(c.ip), c.bits, c.def6)
		if got := map[bool]string{true: p.String(), false: ""}[ok]; got != c.want {
			t.Errorf("%s: %q, want %q", c.label, got, c.want)
		}
	}
}

// NetBird's peers are home only while it's connected, and its reverse
// proxy peer never (re-review M3).
func TestNetBirdHome(t *testing.T) {
	e := newMFAEnv(t)
	s := e.server
	peer := netip.MustParseAddr("100.83.0.7")
	if s.insideAddr(peer) {
		t.Fatal("a NetBird address with NetBird not connected")
	}
	s.remote.mu.Lock()
	s.remote.connected, s.remote.peers = true, netip.MustParsePrefix("100.83.0.0/16")
	s.remote.mu.Unlock()
	if !s.insideAddr(peer) {
		t.Fatal("a NetBird peer while connected")
	}
	s.notePeerProxy(peer)
	if s.insideAddr(peer) {
		t.Fatal("NetBird's reverse proxy peer")
	}
	if !strings.HasPrefix(s.remote.netbirdNetwork().String(), "100.83.") {
		t.Fatal(s.remote.netbirdNetwork())
	}
}
