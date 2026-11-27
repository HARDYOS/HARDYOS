package api

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/cluster/member"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/tlscert"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

// stubPriv serves a stubApps root helper on a socket.
func stubPriv(t *testing.T, stub *stubApps) *priv.Client {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	stub.register(ps)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = ps.Serve(ctx, ln) }()
	return priv.NewClient(sock)
}

// windowBackend is an app on the member that runs it: pages that say what
// they got, a redirect to its own address, and a WebSocket echo.
func windowBackend(t *testing.T) (int, chan *http.Request) {
	t.Helper()
	seen := make(chan *http.Request, 100)
	var port int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Clone(context.Background()):
		default:
		}
		switch r.URL.Path {
		case "/ws":
			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
			if err != nil {
				return
			}
			defer c.CloseNow()
			for {
				typ, b, err := c.Read(context.Background())
				if err != nil {
					return
				}
				if err := c.Write(context.Background(), typ, append([]byte("echo:"), b...)); err != nil {
					return
				}
			}
		case "/away":
			http.Redirect(w, r, "http://127.0.0.1:"+strconv.Itoa(port)+"/here", http.StatusFound)
		default:
			w.Header().Add("Set-Cookie", "sid=1; Path=/")
			_, _ = io.WriteString(w, "board:"+r.URL.Path+" host="+r.Host+" proto="+r.Header.Get("X-Forwarded-Proto"))
		}
	}))
	t.Cleanup(srv.Close)
	port = srv.Listener.Addr().(*net.TCPAddr).Port
	return port, seen
}

// windowCluster is nas (storage) and c1 (compute) where c1 runs the app
// "board" and nas's window proxy runs.
func windowCluster(t *testing.T) (nas, c1 *clusterNode, admin *client, seen chan *http.Request) {
	t.Helper()
	port, seen := windowBackend(t)
	nasStub := &stubApps{apps: map[string]apps.App{}, pool: "tank"}
	c1Stub := &stubApps{apps: map[string]apps.App{
		"board": {ID: "board", Name: "Board", State: "running", Web: &apps.AppWeb{Port: port, Path: "/start", Scheme: "http"}},
	}, pool: "tank"}
	// The fake network, or (the Cluster (namespaces) CI job, in a network
	// namespace of its own) the kernel's TCP, both addresses on one veth.
	nasAddr, c1Addr := "192.168.1.105", "192.168.1.21"
	tcp := os.Getenv("HARDYOS_WINDOWS_TCP") == "1"
	if tcp {
		nasAddr, c1Addr = "10.99.0.10", "10.99.0.21"
	}
	mod := func(svc *member.Service) {
		svc.Live().Register(state.Placements{})
		if tcp {
			svc.Net = cluster.TCP{}
		}
	}
	fakeNet := clustertest.NewNet()
	nas = newClusterNodeWith(t, fakeNet, "nas", cluster.Addresses{LAN: netip.MustParseAddr(nasAddr)},
		func(c *Config) {
			c.Priv = stubPriv(t, nasStub)
			c.Updates = &updates.Service{Jobs: c.Jobs, DB: c.DB, Dir: t.TempDir()}
		}, mod)
	c1 = newClusterNodeWith(t, fakeNet, "c1", cluster.Addresses{LAN: netip.MustParseAddr(c1Addr)},
		func(c *Config) {
			c.Priv = stubPriv(t, c1Stub)
			c.Updates = &updates.Service{Jobs: c.Jobs, DB: c.DB, Dir: t.TempDir()}
		}, mod)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := nas.svc.Create(ctx, member.CreateParams{Name: "home", Role: cluster.RoleStorage, Actor: cluster.Actor{Kind: "local", Name: "cade"}}); err != nil {
		t.Fatal(err)
	}
	off, err := nas.svc.Core().OpenJoinCode(ctx, cluster.RoleCompute, "cade")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c1.svc.Join(ctx, nasAddr, off.Code, cluster.RoleCompute); err != nil {
		t.Fatal(err)
	}
	for ctx.Err() == nil && clusterReady(ctx, nas, c1) != nil {
		time.Sleep(50 * time.Millisecond)
	}
	admin = nas.env.client(t)
	if code := admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil); code != 201 {
		t.Fatalf("setup nas = %d", code)
	}
	if code := c1.env.client(t).do("POST", "/api/v1/setup/admin", map[string]string{"username": "dora", "password": "supersecret1"}, nil); code != 201 {
		t.Fatalf("setup c1 = %d", code)
	}
	// nas's window proxy.
	certPEM, keyPEM, err := tlscert.Generate([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	base := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	pctx, pcancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		nas.s.RunAppProxy(pctx, AppProxyOptions{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, BasePort: base,
			ListenHost: "127.0.0.1", DesktopPort: 443, Interval: time.Hour})
	}()
	t.Cleanup(func() { pcancel(); <-done })
	for deadline := time.Now().Add(5 * time.Second); !nas.s.proxy.isRunning() && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	return nas, c1, admin, seen
}

// signInWindow follows an AppOpen's link in the person's browser and
// returns the window's base URL and the page it landed on.
func signInWindow(t *testing.T, c *client, open AppOpen) (string, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", open.URL, nil)
	req.Header.Set("Sec-Fetch-Dest", "iframe")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	res, err := browserOf(c).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("signing in to the window = %d %s", res.StatusCode, body)
	}
	u, _ := url.Parse(open.URL)
	return "https://" + u.Host, string(body)
}

// An app window on member nas for an app that runs on member c1: HTTP
// and WebSocket through nas's window proxy and the cluster relay, the
// app's own redirects kept on the window, and a cluster app opening on
// its owner whatever server the desktop named (decision 493).
func TestAppWindowAcrossMembers(t *testing.T) {
	oldCheck := sessionCheck
	sessionCheck = 100 * time.Millisecond
	t.Cleanup(func() { sessionCheck = oldCheck })
	nas, c1, admin, seen := windowCluster(t)

	// The desktop lists c1's app for nas's administrator.
	var list []ClusterWindow
	if code := admin.do("GET", "/api/v1/cluster/windows", nil, &list); code != 200 || len(list) != 1 || list[0].Node != "c1" || list[0].ID != "board" || list[0].Cluster {
		t.Fatalf("windows = %d %+v", code, list)
	}

	// Opened for c1 (the switcher): a window on nas relayed to c1.
	var open AppOpen
	if code := admin.do("POST", "/api/v1/nodes/c1/apps/board/open", nil, &open); code != 200 || !open.Proxied {
		t.Fatalf("open = %d %+v", code, open)
	}
	win, page := signInWindow(t, admin, open)
	if !strings.HasPrefix(page, "board:/start ") || !strings.Contains(page, "proto=https") {
		t.Fatalf("landed on %q (the app's web path, how the browser came)", page)
	}
	b := browserOf(admin)
	if code, body := get(t, b, win+"/hello", nil); code != 200 || !strings.HasPrefix(body, "board:/hello host=127.0.0.1:") {
		t.Fatalf("GET = %d %q", code, body)
	}
	// Only the app's own cookies reach it, never HardyOS's.
	for len(seen) > 1 {
		<-seen
	}
	if code, _ := get(t, b, win+"/again", nil); code != 200 {
		t.Fatal(code)
	}
	r := <-seen
	if c := r.Header.Get("Cookie"); strings.Contains(c, "hardyos") || !strings.Contains(c, "sid=1") {
		t.Fatalf("cookies at the app: %q", c)
	}
	// The app's redirect to its own address stays on the window.
	nr := &http.Client{Jar: b.Jar, Transport: b.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := nr.Get(win + "/away")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if loc := res.Header.Get("Location"); res.StatusCode != http.StatusFound || loc != win+"/here" {
		t.Fatalf("redirect = %d %q, want %s/here", res.StatusCode, loc, win)
	}

	// A WebSocket through the window and the relay.
	wsURL := "wss" + strings.TrimPrefix(win, "https") + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: b})
	if err != nil {
		t.Fatalf("websocket: %v", err)
	}
	defer ws.CloseNow()
	if err := ws.Write(ctx, websocket.MessageText, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	if _, msg, err := ws.Read(ctx); err != nil || string(msg) != "echo:hi" {
		t.Fatalf("echo = %q %v", msg, err)
	}

	// c1 stops accepting nas's administrators: the open WebSocket closes
	// (the owner rechecks), new requests are refused.
	other := c1.env.client(t)
	other.do("POST", "/api/v1/auth/login", map[string]string{"username": "dora", "password": "supersecret1"}, nil)
	var trust ClusterAdminTrust
	other.do("GET", "/api/v1/cluster/admin-trust", nil, &trust)
	trust.Members[0].Accept = false
	if code := other.do("PUT", "/api/v1/cluster/admin-trust", trust, &trust); code != 200 {
		t.Fatalf("trust = %d", code)
	}
	rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rcancel()
	if _, _, err := ws.Read(rctx); err == nil || rctx.Err() != nil {
		t.Fatalf("the WebSocket stayed open after access ended: %v", err)
	}
	if code, _ := get(t, b, win+"/hello", nil); code != http.StatusForbidden {
		t.Fatalf("after access ended = %d", code)
	}
	var e ErrorResponse
	if code := admin.do("POST", "/api/v1/nodes/c1/apps/board/open", nil, &e); code != 403 {
		t.Fatalf("open after access ended = %d %+v", code, e)
	}
	trust.Members[0].Accept = true
	other.do("PUT", "/api/v1/cluster/admin-trust", trust, nil)

	// A cluster app placed on c1 opens there from nas's own App Store
	// (POST /apps/board/open) and when the desktop named nas.
	pctx, pcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pcancel()
	if _, err := c1.svc.Live().Propose(pctx, cluster.CmdWorkloadAdd, state.WorkloadAdd{Workload: cluster.WorkloadRef{Kind: cluster.KindApp, ID: "board"},
		Name: "Board", Owner: "c1", Requested: cluster.RequestRunning, SpecHash: "sha256:" + strings.Repeat("a", 64),
		Storage: cluster.WorkloadStorage{Pool: "tank"}}, cluster.Actor{Kind: "local", Name: "dora"}); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if _, ok := nas.s.cluster.placed("board"); ok {
			break
		}
	}
	if _, ok := nas.s.cluster.placed("board"); !ok {
		t.Fatalf("nas doesn't see the placement: %+v", nas.svc.Core().State().Snapshot().Placements)
	}
	for _, path := range []string{"/api/v1/apps/board/open", "/api/v1/nodes/nas/apps/board/open"} {
		var o AppOpen
		var raw map[string]any
		if code := admin.do("POST", path, nil, &raw); code != 200 || raw["proxied"] != true {
			t.Fatalf("%s = %d %+v", path, code, raw)
		}
		o.URL, o.Proxied = raw["url"].(string), true
		if _, page := signInWindow(t, admin, o); !strings.HasPrefix(page, "board:/start ") {
			t.Fatalf("%s landed on %q", path, page)
		}
	}
	if code := admin.do("GET", "/api/v1/cluster/windows", nil, &list); code != 200 || len(list) != 1 || !list[0].Cluster {
		t.Fatalf("windows = %d %+v", code, list)
	}
	// Hostnames route the same way: c1 runs it.
	if node, many := nas.s.windows.route(context.Background(), "board"); node != "c1" || many != nil {
		t.Fatalf("route = %q %v", node, many)
	}
	if node, _ := c1.s.windows.route(context.Background(), "board"); node != "" {
		t.Fatalf("on its owner the app is its own: %q", node)
	}
}

// Without a cluster app, the hostname of an app goes to the one other
// member that has it (the peer API's directory).
func TestAppWindowDirectory(t *testing.T) {
	nas, c1, _, _ := windowCluster(t)
	if node, many := nas.s.windows.route(context.Background(), "board"); node != "c1" || many != nil {
		t.Fatalf("route = %q %v", node, many)
	}
	if node, _ := nas.s.windows.route(context.Background(), "nothing"); node != "" {
		t.Fatalf("an unknown app routed to %q", node)
	}
	if node, _ := c1.s.windows.route(context.Background(), "board"); node != "" {
		t.Fatalf("c1's own app routed to %q", node)
	}
}
