package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/netbird"
	"github.com/hardyos/hardyos/daemon/internal/netbird/nbtest"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/publish"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/tlscert"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

// stubNetBird is hardyd-priv's NetBird client in these tests.
type stubNetBird struct {
	mu     sync.Mutex
	joined *netbird.JoinArgs
	left   []netbird.LeaveArgs
	raw    []string // every op's raw arguments
}

func (n *stubNetBird) register(ps *priv.Server) {
	ps.Handle(priv.OpNetBirdStatus, func(context.Context, json.RawMessage) (any, error) {
		n.mu.Lock()
		defer n.mu.Unlock()
		st := netbird.ClientStatus{Installed: true, State: "off", Interface: "wt0"}
		if n.joined != nil {
			st = netbird.ClientStatus{Installed: true, Joined: true, Running: true, State: "connected", Connected: true,
				IP: "100.83.40.2", Network: "100.83.0.0/16", FQDN: "nas.netbird.selfhosted", ManagementURL: n.joined.ManagementURL,
				ManagementConnected: true, Hostname: n.joined.Hostname, PeersTotal: 3, PeersConnected: 2, Interface: "wt0"}
		}
		return st, nil
	})
	ps.Handle(priv.OpNetBirdSettings, func(context.Context, json.RawMessage) (any, error) {
		n.mu.Lock()
		defer n.mu.Unlock()
		s := netbird.Settings{Installed: true}
		if n.joined != nil {
			s.ManagementURL, s.Hostname = n.joined.ManagementURL, n.joined.Hostname
		}
		return s, nil
	})
	ps.Handle(priv.OpNetBirdJoin, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a netbird.JoinArgs
		_ = json.Unmarshal(raw, &a)
		n.mu.Lock()
		defer n.mu.Unlock()
		n.raw = append(n.raw, string(raw))
		n.joined = &a
		return netbird.ClientStatus{Joined: true, Connected: true, IP: "100.83.40.2"}, nil
	})
	ps.Handle(priv.OpNetBirdLeave, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a netbird.LeaveArgs
		_ = json.Unmarshal(raw, &a)
		n.mu.Lock()
		defer n.mu.Unlock()
		n.left = append(n.left, a)
		n.joined = nil
		return netbird.LeaveResult{Left: "https://vpn.hardynetworks.net"}, nil
	})
}

type remoteEnv struct {
	*appsEnv
	nb     *stubNetBird
	api    *nbtest.Server
	pub    *publish.Publisher
	gwPort int
	cert   tls.Certificate
}

const testToken = "nbp_TestToken0123456789"

func newRemoteEnv(t *testing.T) *remoteEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stub := &stubApps{apps: map[string]apps.App{}}
	nb := &stubNetBird{}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	stub.register(ps)
	nb.register(ps)
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	RegisterJobKinds(m, pc)
	catalog := t.TempDir()
	writeTestApp(t, catalog, "1.0.0")
	writeBoardApp(t, catalog)
	st := &appstore.Store{CatalogDir: catalog, UploadDir: filepath.Join(t.TempDir(), "uploads"),
		ImportDir: filepath.Join(t.TempDir(), "imports"), DB: db}
	RegisterAppJobs(m, pc, st)
	fake := nbtest.New(testToken)
	pub := &publish.Publisher{Store: &publish.Store{DB: db, Sealer: &publish.Sealer{KeyFile: filepath.Join(t.TempDir(), "k", "hardyd.key")}}}
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	gwPort := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	pub.GatewayPort = gwPort
	RegisterRemoteJobs(m, pc, pub)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	upd := &updates.Service{Priv: pc, Jobs: m, DB: db, Dir: t.TempDir(), Notify: &notify.Center{DB: db, Events: broker}}
	server := New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Updates: upd, Apps: st, Insecure: true, Remote: pub})
	srv := httptest.NewServer(server)
	t.Cleanup(func() {
		srv.Close()
		fake.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	ae := &appsEnv{testEnv: &testEnv{srv: srv, db: db, broker: broker}, ctx: ctx, server: server, stub: stub, store: st, catalog: catalog}
	ae.admin = ae.client(t)
	ae.admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	ae.admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	ae.kid = ae.client(t)
	ae.kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	certPEM, keyPEM, err := tlscert.Generate([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &remoteEnv{appsEnv: ae, nb: nb, api: fake, pub: pub, gwPort: gwPort, cert: cert}
}

// jobText is a job as the API shows it, for "does a secret show up" checks.
func jobText(t *testing.T, c *client, id string) string {
	var raw json.RawMessage
	c.do("GET", "/api/v1/jobs/"+id, nil, &raw)
	return string(raw)
}

func (e *remoteEnv) submit(t *testing.T, method, path string, body any) (map[string]any, string) {
	t.Helper()
	var acc jobRef
	var er ErrorResponse
	code := e.admin.do(method, path, body, &acc)
	if code != 202 {
		e.admin.do(method, path, body, &er)
		t.Fatalf("%s %s = %d %+v", method, path, code, er)
	}
	return waitJobDone(t, e.admin, acc.Job.ID), acc.Job.ID
}

func TestRemoteJoinLeaveKeepsTheSetupKeySecret(t *testing.T) {
	e := newRemoteEnv(t)
	key := "A1B2C3D4-0000-1111-2222-333344445555"
	for _, bad := range []RemoteJoinRequest{
		{ManagementURL: "http://vpn.hardynetworks.net", SetupKey: key},
		{ManagementURL: "https://vpn.hardynetworks.net", SetupKey: "x"},
		{ManagementURL: "https://vpn.hardynetworks.net", SetupKey: key, Hostname: "my nas"},
	} {
		if code := e.admin.do("POST", "/api/v1/remote/join", bad, nil); code != 400 {
			t.Errorf("%+v = %d", bad, code)
		}
	}
	if code := e.kid.do("POST", "/api/v1/remote/join", RemoteJoinRequest{ManagementURL: "https://vpn.hardynetworks.net", SetupKey: key}, nil); code != 403 {
		t.Fatalf("kid joined: %d", code)
	}
	j, id := e.submit(t, "POST", "/api/v1/remote/join", RemoteJoinRequest{ManagementURL: "https://vpn.hardynetworks.net/", SetupKey: key})
	if j["state"] != "succeeded" {
		t.Fatalf("join = %v", j)
	}
	e.nb.mu.Lock()
	if e.nb.joined == nil || e.nb.joined.SetupKey != key || e.nb.joined.Hostname != "nas" || e.nb.joined.ManagementURL != "https://vpn.hardynetworks.net" {
		t.Fatalf("root got %+v", e.nb.joined)
	}
	e.nb.mu.Unlock()
	var st RemoteStatus
	if code := e.admin.do("GET", "/api/v1/remote", nil, &st); code != 200 || !st.Client.Connected || st.Client.IP != "100.83.40.2" || !st.Available {
		t.Fatalf("status = %d %+v", code, st.Client)
	}
	var everything strings.Builder
	everything.WriteString(jobText(t, e.admin, id))
	var raw json.RawMessage
	e.admin.do("GET", "/api/v1/remote", nil, &raw)
	everything.Write(raw)
	e.admin.do("GET", "/api/v1/audit", nil, &raw)
	everything.Write(raw)
	e.admin.do("GET", "/api/v1/jobs", nil, &raw)
	everything.Write(raw)
	if strings.Contains(everything.String(), key) {
		t.Fatal("the setup key shows up in a job, the status or the audit log")
	}
	if !strings.Contains(strings.Join(auditActions(e.admin, "remote."), ","), "remote.join https://vpn.hardynetworks.net as nas") {
		t.Fatalf("audit = %v", auditActions(e.admin, "remote."))
	}

	// Leaving needs the server's name.
	if code := e.admin.do("POST", "/api/v1/remote/leave", RemoteLeaveRequest{Confirm: "yes"}, nil); code != 400 {
		t.Fatalf("leave without confirmation = %d", code)
	}
	if j, _ := e.submit(t, "POST", "/api/v1/remote/leave", RemoteLeaveRequest{Confirm: "vpn.hardynetworks.net"}); j["state"] != "succeeded" {
		t.Fatalf("leave = %v", j)
	}
	if len(e.nb.left) != 1 || e.nb.left[0].Confirm != "vpn.hardynetworks.net" {
		t.Fatalf("left = %+v", e.nb.left)
	}
}

func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

func TestRemotePublishingKeepsTheTokenSecret(t *testing.T) {
	e := newRemoteEnv(t)
	tok := testToken
	// Publishing needs a token.
	if code := e.admin.do("PUT", "/api/v1/remote/publishing", RemotePublishingRequest{Enabled: true, BaseDomain: "home.example.net"}, nil); code != 400 {
		t.Fatalf("no token = %d", code)
	}
	if code := e.admin.do("PUT", "/api/v1/remote/publishing", RemotePublishingRequest{BaseDomain: "home example"}, nil); code != 400 {
		t.Fatalf("bad domain = %d", code)
	}
	j, id := e.submit(t, "PUT", "/api/v1/remote/publishing", RemotePublishingRequest{Enabled: false, BaseDomain: "home.example.net",
		APIURL: e.api.URL, Token: &tok})
	if j["state"] != "succeeded" {
		t.Fatalf("save = %v", j)
	}
	var st RemoteStatus
	e.admin.do("GET", "/api/v1/remote", nil, &st)
	if st.Settings == nil || !st.Settings.HasToken || st.Settings.TokenUnreadable || st.Settings.BaseDomain != "home.example.net" || st.Settings.DesktopName != "nas" {
		t.Fatalf("settings = %+v", st.Settings)
	}
	var raw json.RawMessage
	var all strings.Builder
	e.admin.do("GET", "/api/v1/remote", nil, &raw)
	all.Write(raw)
	all.WriteString(jobText(t, e.admin, id))
	e.admin.do("GET", "/api/v1/audit", nil, &raw)
	all.Write(raw)
	v, _ := e.db.GetSetting(e.ctx, "remote.token")
	all.WriteString(v)
	if strings.Contains(all.String(), tok) {
		t.Fatal("the access token shows up in the API, a job, the audit log or the database")
	}
	// Absent keeps it, "" forgets it.
	e.submit(t, "PUT", "/api/v1/remote/publishing", RemotePublishingRequest{BaseDomain: "home.example.net", APIURL: e.api.URL})
	if got, _ := e.pub.Store.Token(e.ctx); got != tok {
		t.Fatal("token lost when not sent")
	}
	empty := ""
	e.submit(t, "PUT", "/api/v1/remote/publishing", RemotePublishingRequest{BaseDomain: "home.example.net", APIURL: e.api.URL, Token: &empty})
	if e.pub.Store.HasToken(e.ctx) {
		t.Fatal("token kept")
	}
}

// gwBrowser is a browser on the internet reaching published names through
// NetBird's proxy: every name resolves to the gateway, and the "proxy"
// adds the shared header and X-Forwarded-For, as NetBird's does.
type gwBrowser struct {
	jar    http.CookieJar
	client *http.Client
	secret string
	ip     string
}

type proxyHop struct {
	next   http.RoundTripper
	secret string
	ip     string
}

func (p *proxyHop) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if p.secret != "" {
		r.Header.Set(publish.GatewayHeader, p.secret)
	}
	r.Header.Set("X-Forwarded-For", "198.51.100.1, "+p.ip) // the client's own entry first, then the proxy's
	return p.next.RoundTrip(r)
}

func (e *remoteEnv) browser(t *testing.T, secret string) *gwBrowser {
	jar, _ := cookiejar.New(nil)
	port := itoa(e.gwPort)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, "127.0.0.1:"+port)
		},
	}
	b := &gwBrowser{jar: jar, secret: secret, ip: "203.0.113.9"}
	b.client = &http.Client{Jar: jar, Transport: &proxyHop{next: tr, secret: secret, ip: b.ip}, Timeout: 10 * time.Second}
	return b
}

func (b *gwBrowser) nav(t *testing.T, method, u string, hdr map[string]string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(method, u, nil)
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Site", "none")
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body), res.Header
}

// signIn signs the browser in to the desktop at its published name.
func (b *gwBrowser) signIn(t *testing.T, user, pw string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": user, "password": pw})
	req, _ := http.NewRequest("POST", "https://nas.home.example.net/api/v1/auth/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HardyOS-Request", "1")
	req.Header.Set("Origin", "https://nas.home.example.net")
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("sign in through the gateway = %d", res.StatusCode)
	}
}

func (b *gwBrowser) cookies(u string) map[string]string {
	out := map[string]string{}
	for _, c := range b.jar.Cookies(mustURL(u)) {
		out[c.Name] = c.Value
	}
	return out
}

// gwBackend is every app's page: /set sets cookies (one with a Domain),
// / echoes the Host and cookies it got, /ws echoes WebSocket messages.
func gwBackend(t *testing.T) int {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/set":
			app := strings.SplitN(r.Host, ".", 2)[0]
			for _, c := range []string{"sid=" + app + "; Path=/; HttpOnly", "hardyos_session=evil; Path=/",
				"wide=" + app + "; Domain=home.example.net; Path=/"} {
				w.Header().Add("Set-Cookie", c)
			}
			_, _ = io.WriteString(w, "set")
		case "/ws":
			c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
			if err != nil {
				return
			}
			defer c.CloseNow()
			for {
				typ, b, err := c.Read(r.Context())
				if err != nil {
					return
				}
				if err := c.Write(r.Context(), typ, b); err != nil {
					return
				}
			}
		case "/go":
			http.Redirect(w, r, "http://"+r.Host+"/there", http.StatusFound)
		default:
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
			_, _ = io.WriteString(w, "host="+r.Host+" xff="+r.Header.Get("X-Forwarded-For")+" proto="+r.Header.Get("X-Forwarded-Proto")+
				" nb="+r.Header.Get(publish.GatewayHeader)+" cookies="+r.Header.Get("Cookie"))
		}
	}))
	t.Cleanup(backend.Close)
	return backend.Listener.Addr().(*net.TCPAddr).Port
}

// setUp installs notes (cade only) and board (everyone), publishes them
// and the desktop, and runs the gateway on 127.0.0.1.
func (e *remoteEnv) setUp(t *testing.T) (secret string) {
	t.Helper()
	e.stub.webPortFrom = gwBackend(t)
	e.installNotes(t, []appstore.Principal{{Kind: "user", Name: "cade"}})
	if j := e.runJob(t, "POST", "/api/v1/apps/install", AppInstallRequest{AppPackageRef: AppPackageRef{Source: "catalog", Ref: "board"}}); j["state"] != "succeeded" {
		t.Fatalf("install board: %v", j)
	}
	e.submit(t, "POST", "/api/v1/remote/join", RemoteJoinRequest{ManagementURL: "https://vpn.hardynetworks.net", SetupKey: "A1B2C3D4-0000-1111-2222-333344445555"})
	// A private proxy cluster: the desktop is NetBird-only by default.
	e.api.Lock()
	for i := range e.api.Domains {
		e.api.Domains[i].SupportsPrivate = true
	}
	e.api.Unlock()
	// The test accounts are HardyOS's own: let them use HardyOS sign-in.
	if err := e.server.OIDC().SetLocalAccounts(e.ctx, true); err != nil {
		t.Fatal(err)
	}
	// The fake NetBird knows this server by the stub's address.
	tok := testToken
	j, _ := e.submit(t, "PUT", "/api/v1/remote/publishing", RemotePublishingRequest{Enabled: true, BaseDomain: "home.example.net",
		APIURL: e.api.URL, DefaultMode: publish.ModePublic, Token: &tok})
	if j["state"] != "succeeded" {
		t.Fatalf("publish = %v", j)
	}
	res := j["result"].(map[string]any)
	if res["created"] != float64(4) || res["problem"] != nil {
		t.Fatalf("sync = %v", res)
	}
	ctx, cancel := context.WithCancel(e.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.server.RunRemote(ctx, RemoteOptions{TLS: &tls.Config{Certificates: []tls.Certificate{e.cert}}, Port: e.gwPort,
			ListenHost: "127.0.0.1", Network: "127.0.0.0/8", SyncEvery: time.Hour, StatusEvery: time.Hour})
	}()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, g := e.server.remote.info(); g.Listening {
			break
		}
		if time.Now().After(deadline) {
			_, g := e.server.remote.info()
			t.Fatalf("gateway not listening: %+v", g)
		}
		time.Sleep(10 * time.Millisecond)
	}
	secret, _ = e.pub.Store.GatewaySecret(e.ctx)
	return secret
}

func TestGatewayOnlyTakesNetBirdsProxy(t *testing.T) {
	e := newRemoteEnv(t)
	secret := e.setUp(t)
	for _, b := range []*gwBrowser{e.browser(t, ""), e.browser(t, "wrong")} {
		if code, _, _ := b.nav(t, "GET", "https://board.home.example.net/", nil); code != 403 {
			t.Fatalf("without the proxy's secret = %d", code)
		}
	}
	b := e.browser(t, secret)
	// sso.<base> is HardyOS's sign-in provider.
	if code, _, _ := b.nav(t, "GET", "https://sso.home.example.net/.well-known/openid-configuration", nil); code != 200 {
		t.Fatalf("sso host = %d", code)
	}
	if code, _, _ := b.nav(t, "GET", "https://unknown.home.example.net/", nil); code != 404 {
		t.Fatalf("unpublished host = %d", code)
	}
	// From outside the NetBird network, even with the secret.
	rt := e.server.remote
	req := httptest.NewRequest("GET", "https://board.home.example.net/", nil)
	req.RemoteAddr = "192.168.1.50:5000"
	req.Header.Set(publish.GatewayHeader, secret)
	if rt.fromProxy(req, mustPrefix("100.64.0.0/10"), secret) {
		t.Fatal("accepted a LAN address")
	}
	req.RemoteAddr = "100.83.12.7:5000"
	if !rt.fromProxy(req, mustPrefix("100.64.0.0/10"), secret) {
		t.Fatal("refused NetBird's proxy")
	}
}
