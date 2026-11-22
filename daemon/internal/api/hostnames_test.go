package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/hostnames"
	"github.com/hardyos/hardyos/daemon/internal/hostnames/hosttest"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/photos"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/tlscert"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

type hostsEnv struct {
	t      *testing.T
	srv    *httptest.Server
	server *Server
	hosts  *hosttest.Env
	stub   *stubApps
	store  *appstore.Store
	db     *store.DB
	// seen are the requests the apps' backend got.
	seen chan *http.Request
}

// hostsClient is a browser for names under home.example.net, all dialled
// at the test server.
type hostsClient struct {
	e  *hostsEnv
	hc *http.Client
}

func (e *hostsEnv) browser(follow bool) *hostsClient {
	jar, _ := cookiejar.New(nil)
	addr := e.srv.Listener.Addr().String()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // checked separately against the fake CA
	}
	hc := &http.Client{Jar: jar, Transport: tr, Timeout: 20 * time.Second}
	if !follow {
		hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return &hostsClient{e: e, hc: hc}
}

func (c *hostsClient) req(method, rawURL string, body any) (*http.Response, string) {
	c.e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(method, rawURL, rd)
	r.Header.Set("Accept", "text/html")
	if method != http.MethodGet {
		r.Header.Set("X-HardyOS-Request", "1")
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(r)
	if err != nil {
		c.e.t.Fatalf("%s %s: %v", method, rawURL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

const desk = "https://nas.home.example.net"

func newHostsEnv(t *testing.T) *hostsEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan *http.Request, 100)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Clone(context.Background()):
		default:
		}
		w.Header().Add("Set-Cookie", "sid=1; Path=/; Domain=home.example.net")
		w.Header().Add("Set-Cookie", "hardyos_session=evil; Path=/")
		_, _ = io.WriteString(w, "app:"+r.Host+r.URL.Path)
	}))
	t.Cleanup(backend.Close)
	port := backend.Listener.Addr().(*net.TCPAddr).Port
	stub := &stubApps{apps: map[string]apps.App{
		photos.AppID: {ID: photos.AppID, Name: "Photos", Web: &apps.AppWeb{Port: port, Path: "/"}},
		"board":      {ID: "board", Name: "Board", Web: &apps.AppWeb{Port: port, Path: "/"}},
		"sso":        {ID: "sso", Name: "Pretend SSO", Web: &apps.AppWeb{Port: port}},
	}, pool: "tank"}
	he := hosttest.New(t, "example.net", stub.register)
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	RegisterJobKinds(m, he.Priv)
	st := &appstore.Store{CatalogDir: t.TempDir(), UploadDir: filepath.Join(t.TempDir(), "u"), ImportDir: filepath.Join(t.TempDir(), "i"), DB: db}
	RegisterAppJobs(m, he.Priv, st)
	self, key, _ := tlscert.Generate([]string{"nas"}, nil, time.Now())
	fb, _ := tls.X509KeyPair(self, key)
	certs := tlscert.NewStore(fb)
	mgr := &hostnames.Manager{Store: &hostnames.Store{DB: db, Keys: secretbox.NewStaticSource()}, DNS: hostnames.PrivDNS{Priv: he.Priv},
		Certs: certs, Dir: t.TempDir(), Directory: he.ACME.Directory()}
	upd := &updates.Service{Priv: he.Priv, Jobs: m, DB: db, Dir: t.TempDir(), Notify: &notify.Center{DB: db, Events: broker}}
	server := New(Config{DB: db, Jobs: m, Events: broker, Priv: he.Priv, Updates: upd, Apps: st, Hostnames: mgr})
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(server)
	srv.TLS = certs.TLSConfig()
	srv.StartTLS()
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &hostsEnv{t: t, srv: srv, server: server, hosts: he, stub: stub, store: st, db: db, seen: seen}
}

func (e *hostsEnv) waitJob(c *hostsClient, body string) map[string]any {
	e.t.Helper()
	var acc struct {
		Job struct {
			ID string `json:"id"`
		} `json:"job"`
	}
	if err := json.Unmarshal([]byte(body), &acc); err != nil || acc.Job.ID == "" {
		e.t.Fatalf("not a job: %s", body)
	}
	for i := 0; i < 200; i++ {
		_, b := c.req("GET", desk+"/api/v1/jobs/"+acc.Job.ID, nil)
		var j map[string]any
		_ = json.Unmarshal([]byte(b), &j)
		if s, _ := j["state"].(string); s == "succeeded" || s == "failed" || s == "cancelled" {
			return j
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatal("job didn't finish")
	return nil
}

// activate signs the administrator in at the desktop's hostname, saves the
// token and turns hostnames on (which gets the certificate).
func (e *hostsEnv) activate() *hostsClient {
	e.t.Helper()
	admin := e.browser(true)
	if r, b := admin.req("POST", desk+"/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}); r.StatusCode >= 300 {
		e.t.Fatalf("%d %s", r.StatusCode, b)
	}
	r, b := admin.req("PUT", desk+"/api/v1/hostnames/token", map[string]string{"token": hosttest.Token, "base": "home.example.net"})
	if r.StatusCode != http.StatusAccepted {
		e.t.Fatalf("%d %s", r.StatusCode, b)
	}
	if j := e.waitJob(admin, b); j["state"] != "succeeded" {
		e.t.Fatalf("%v", j)
	}
	r, b = admin.req("PUT", desk+"/api/v1/hostnames/settings", map[string]any{"enabled": true})
	if r.StatusCode != http.StatusAccepted {
		e.t.Fatalf("%d %s", r.StatusCode, b)
	}
	if j := e.waitJob(admin, b); j["state"] != "succeeded" {
		e.t.Fatalf("%v", j)
	}
	e.server.hosts.refresh(context.Background())
	if active, _, _ := e.server.hosts.snapshot(); !active {
		e.t.Fatal("hostnames not active")
	}
	return admin
}

func TestHostnamesOffChangesNothing(t *testing.T) {
	e := newHostsEnv(t)
	c := e.browser(false)
	// Without a token every name is the desktop, as before.
	r, b := c.req("GET", "https://photos.home.example.net/api/v1/health", nil)
	if r.StatusCode != 200 || !strings.Contains(b, "ok") {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	if u := e.server.hosts.hostURL(photos.AppID); u != "" {
		t.Fatal(u)
	}
}

func TestHostnamesTokenAndCertificate(t *testing.T) {
	e := newHostsEnv(t)
	admin := e.activate()
	_, b := admin.req("GET", desk+"/api/v1/hostnames", nil)
	if strings.Contains(b, hosttest.Token) {
		t.Fatal("the token came back")
	}
	var st HostnamesStatus
	if err := json.Unmarshal([]byte(b), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Active || !st.Token.Set || st.Token.Base != "home.example.net" || st.Token.VerifiedAt == nil || st.Certificate == nil ||
		st.Certificate.Names[0] != "*.home.example.net" || st.DesktopURL != desk {
		t.Fatalf("%+v", st)
	}
	labels := map[string]bool{}
	for _, n := range st.Names {
		labels[n.Label] = true
	}
	if !labels["nas"] || !labels["sso"] || !labels["photos"] || !labels["board"] || labels["immich"] || labels["office"] {
		t.Fatalf("%+v", st.Names)
	}
	// The served chain is the fake CA's, for every name under the base.
	pool := x509.NewCertPool()
	pool.AddCert(e.hosts.ACME.CA())
	for _, name := range []string{"photos.home.example.net", "nas.home.example.net"} {
		conn, err := tls.Dial("tcp", e.srv.Listener.Addr().String(), &tls.Config{ServerName: name, RootCAs: pool})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		conn.Close()
	}
	// A non-administrator can't see or change any of it.
	admin.req("POST", desk+"/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"})
	kid := e.browser(true)
	kid.req("POST", desk+"/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"})
	for _, x := range []struct{ m, p string }{{"GET", "/api/v1/hostnames"}, {"PUT", "/api/v1/hostnames/token"}, {"PUT", "/api/v1/hostnames/settings"},
		{"POST", "/api/v1/hostnames/certificate"}, {"POST", "/api/v1/hostnames/lan"}, {"DELETE", "/api/v1/hostnames/token"}} {
		if r, _ := kid.req(x.m, desk+x.p, map[string]any{}); r.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s: %d", x.m, x.p, r.StatusCode)
		}
	}
	if r, b := kid.req("GET", desk+"/api/v1/hostnames/desktop", nil); r.StatusCode != 200 || !strings.Contains(b, desk) {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	// Clearing needs the base typed; then everything is as before.
	if r, _ := admin.req("DELETE", desk+"/api/v1/hostnames/token", map[string]string{"confirm": "nope"}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("%d", r.StatusCode)
	}
	r, b := admin.req("DELETE", desk+"/api/v1/hostnames/token", map[string]string{"confirm": "home.example.net"})
	if j := e.waitJob(admin, b); r.StatusCode != http.StatusAccepted || j["state"] != "succeeded" {
		t.Fatalf("%d %v", r.StatusCode, j)
	}
	if active, _, _ := e.server.hosts.snapshot(); active {
		t.Fatal("still active after clearing")
	}
}

func TestHostnamesRouting(t *testing.T) {
	e := newHostsEnv(t)
	admin := e.activate()
	for _, x := range []struct {
		url    string
		status int
		want   string
	}{
		{desk + "/api/v1/health", 200, "ok"},
		{"https://sso.home.example.net/", 404, "sign-in"},              // no provider here: never the desktop
		{"https://sso.home.example.net/api/v1/health", 404, "sign-in"}, // nor its API
		{"https://files.home.example.net/api/v1/health", 404, "share links"},
		{"https://files.home.example.net/s/-/ds/web-apps/x", 404, "share links"},
		{"https://office.home.example.net/", 404, "office suite is off"},
		{"https://nothing.home.example.net/api/v1/health", 404, "No HardyOS app"},
		{"https://immich.home.example.net/x", 200, "app:photos.home.example.net/x"}, // by app id too (NetBird's name): one origin
	} {
		r, b := admin.req("GET", x.url, nil)
		if r.StatusCode != x.status || !strings.Contains(b, x.want) {
			t.Errorf("%s: %d %s", x.url, r.StatusCode, b)
		}
	}
	// Apps open at their hostname from the desktop's.
	r, b := admin.req("POST", desk+"/api/v1/apps/immich/open", map[string]any{})
	var open AppOpen
	_ = json.Unmarshal([]byte(b), &open)
	if r.StatusCode != 200 || open.URL != "https://photos.home.example.net/" || !open.Hostname {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	// Signed in to the desktop, the bounce gives the app its own session;
	// HardyOS's cookies never reach it and its cookies stay on its host.
	r, b = admin.req("GET", "https://photos.home.example.net/library", nil)
	if r.StatusCode != 200 || b != "app:photos.home.example.net/library" {
		t.Fatalf("%d %s", r.StatusCode, b)
	}
	var got *http.Request
	for len(e.seen) > 0 {
		got = <-e.seen
	}
	if c := got.Header.Get("Cookie"); strings.Contains(c, "hardyos") {
		t.Fatalf("HardyOS cookie reached the app: %s", c)
	}
	if got.Header.Get("X-Forwarded-Proto") != "https" || got.Header.Get("X-Forwarded-For") == "" {
		t.Fatalf("%v", got.Header)
	}
	for _, c := range r.Header.Values("Set-Cookie") {
		if strings.Contains(strings.ToLower(c), "domain=") || strings.Contains(c, "hardyos_session") {
			t.Fatalf("app cookie not kept on its host: %s", c)
		}
	}
	// The desktop's CSP lets it frame the hostnames.
	r, _ = admin.req("GET", desk+"/api/v1/health", nil)
	if !strings.Contains(r.Header.Get("Content-Security-Policy"), "https://*.home.example.net") {
		t.Fatal(r.Header.Get("Content-Security-Policy"))
	}
	// Another page's fetch is refused.
	req, _ := http.NewRequest("POST", "https://photos.home.example.net/api/x", strings.NewReader("{}"))
	req.Header.Set("Origin", "https://board.home.example.net")
	resp, err := admin.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-app post: %d", resp.StatusCode)
	}
	// Signing out of the desktop ends the app session.
	admin.req("POST", desk+"/api/v1/auth/logout", map[string]any{})
	e.server.proxy.sweep(context.Background())
	nf := admin.browserNoFollow()
	r, _ = nf.req("GET", "https://photos.home.example.net/library", nil)
	if r.StatusCode != http.StatusSeeOther || !strings.HasPrefix(r.Header.Get("Location"), desk+hostBindPath) {
		t.Fatalf("after sign-out: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
}

// browserNoFollow is the same cookie jar without following redirects.
func (c *hostsClient) browserNoFollow() *hostsClient {
	hc := *c.hc
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &hostsClient{e: c.e, hc: &hc}
}

func TestHostnamesBind(t *testing.T) {
	e := newHostsEnv(t)
	e.activate()
	admin := e.browser(false)
	admin.req("POST", desk+"/api/v1/auth/login", map[string]string{"username": "cade", "password": "supersecret1"})
	// Step 1: the app host sends the browser to the desktop host.
	r, _ := admin.req("GET", "https://photos.home.example.net/x?y=1", nil)
	loc, _ := url.Parse(r.Header.Get("Location"))
	if r.StatusCode != http.StatusSeeOther || loc.Host != "nas.home.example.net" || loc.Path != hostBindPath || loc.Query().Get("app") != photos.AppID ||
		loc.Query().Get("next") != "/x?y=1" {
		t.Fatalf("%d %s", r.StatusCode, loc)
	}
	// Not for fetches, images or scripts.
	req, _ := http.NewRequest("GET", "https://photos.home.example.net/api/x", nil)
	if resp, err := admin.hc.Do(req); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("fetch started a sign-in: %v %v", resp.StatusCode, err)
	}
	// Step 2: the desktop host hands out a code for that app's host only.
	r2, _ := admin.req("GET", loc.String(), nil)
	cb, _ := url.Parse(r2.Header.Get("Location"))
	if r2.StatusCode != http.StatusSeeOther || cb.Host != "photos.home.example.net" || cb.Path != hostCallback {
		t.Fatalf("%d %s", r2.StatusCode, cb)
	}
	code := cb.Query().Get("code")
	// Another browser (no state cookie) can't use the code...
	other := e.browser(false)
	if r, _ := other.req("GET", cb.String(), nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("code used without the state cookie: %d", r.StatusCode)
	}
	// ...and it's single use, even after a failed try.
	if r, _ := admin.req("GET", cb.String(), nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("code reused: %d", r.StatusCode)
	}
	// A fresh round: a code for one app is no good on another's host.
	r, _ = admin.req("GET", "https://photos.home.example.net/", nil)
	loc, _ = url.Parse(r.Header.Get("Location"))
	q := loc.Query()
	q.Set("app", "board")
	loc.RawQuery = q.Encode()
	r2, _ = admin.req("GET", loc.String(), nil)
	cb, _ = url.Parse(r2.Header.Get("Location"))
	if cb.Host != "board.home.example.net" {
		t.Fatalf("code sent to %s", cb.Host)
	}
	cb.Host = "photos.home.example.net"
	if r, _ := admin.req("GET", cb.String(), nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("board's code accepted by photos: %d", r.StatusCode)
	}
	_ = code
	// The bind refuses: no desktop session, bad state, reserved or unknown
	// apps, a cross-site start, and someone not given the app.
	anon := e.browser(false)
	good := "?app=immich&s=" + strings.Repeat("a", 64)
	for _, x := range []struct {
		c      *hostsClient
		q      string
		hdr    string
		status int
	}{
		{anon, good, "", http.StatusOK},                        // one click to bring a Strict cookie along...
		{anon, good + "&again=1", "", http.StatusUnauthorized}, // ...and then no session is no session
		{admin, "?app=immich&s=short", "", http.StatusBadRequest},
		{admin, "?app=sso&s=" + strings.Repeat("a", 64), "", http.StatusNotFound},
		{admin, "?app=nope&s=" + strings.Repeat("a", 64), "", http.StatusNotFound},
		{admin, good, "cross-site", http.StatusOK}, // the continue page: one same-origin click
	} {
		req, _ := http.NewRequest("GET", desk+hostBindPath+x.q, nil)
		if x.hdr != "" {
			req.Header.Set("Sec-Fetch-Site", x.hdr)
		}
		resp, err := x.c.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != x.status {
			t.Errorf("bind%s %s: %d, want %d", x.q, x.hdr, resp.StatusCode, x.status)
		}
	}
	// The bind only happens on the desktop's own host.
	if r, _ := admin.req("GET", "https://board.home.example.net"+hostBindPath+good, nil); r.StatusCode == http.StatusSeeOther &&
		strings.Contains(r.Header.Get("Location"), "code=") {
		t.Fatal("bind served on an app host")
	}
	// Someone not given an app can't bind to it.
	if err := e.store.SetAccess(context.Background(), "board", []appstore.Principal{{Kind: appstore.KindUser, Name: "cade"}}); err != nil {
		t.Fatal(err)
	}
	adminF := admin.browserFollow()
	adminF.req("POST", desk+"/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"})
	kid := e.browser(true)
	kid.req("POST", desk+"/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"})
	if r, b := kid.req("GET", "https://board.home.example.net/", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("kid got board: %d %s", r.StatusCode, b)
	}
	if r, b := kid.req("GET", "https://photos.home.example.net/", nil); r.StatusCode != 200 {
		t.Fatalf("kid can't get photos: %d %s", r.StatusCode, b)
	}
}

func (c *hostsClient) browserFollow() *hostsClient {
	hc := *c.hc
	hc.CheckRedirect = nil
	return &hostsClient{e: c.e, hc: &hc}
}

func TestHostnamesRedirectOldAddresses(t *testing.T) {
	e := newHostsEnv(t)
	e.activate()
	h := e.server.hosts
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://nas.home.example.net:44301/files?x=1", nil)
	if !h.redirectOld(w, r, "board") || w.Code != http.StatusPermanentRedirect || w.Header().Get("Location") != "https://board.home.example.net/files?x=1" {
		t.Fatalf("%v %d %s", w.Code, w.Code, w.Header().Get("Location"))
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "https://nas.home.example.net:44301"+proxyAuthPath+"?token=abc", nil)
	if !h.redirectOld(w, r, photos.AppID) || w.Header().Get("Location") != "https://photos.home.example.net/" {
		t.Fatalf("%s", w.Header().Get("Location"))
	}
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "https://nas.home.example.net:44250/s/-/office/editor?t=abc", nil)
	if !h.redirectOld(w, r, hostOfficeID) || w.Header().Get("Location") != "https://office.home.example.net/s/-/office/editor?t=abc" {
		t.Fatalf("%s", w.Header().Get("Location"))
	}
	// By address the old origins keep working.
	w = httptest.NewRecorder()
	r = httptest.NewRequest("GET", "https://192.168.1.5:44301/", nil)
	if h.redirectOld(w, r, "board") {
		t.Fatal("redirected a request by address")
	}
}

// probe dials name at the test server and says whether the fake CA's
// wildcard came back, and what /api/v1/health answers there.
func (e *hostsEnv) probe(c *hostsClient, name string) (bool, int, string) {
	e.t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(e.hosts.ACME.CA())
	conn, err := tls.Dial("tcp", e.srv.Listener.Addr().String(), &tls.Config{ServerName: name, RootCAs: pool})
	wild := err == nil
	if conn != nil {
		conn.Close()
	}
	r, b := c.req("GET", "https://"+name+"/api/v1/health", nil)
	return wild, r.StatusCode, b
}

func TestHostnamesOffRefusesAppNames(t *testing.T) {
	e := newHostsEnv(t)
	admin := e.activate()
	if wild, code, body := e.probe(admin, "photos.home.example.net"); !wild || code != 200 || !strings.HasPrefix(body, "app:") {
		t.Fatalf("on: wildcard=%v health=%d %s", wild, code, body)
	}
	r, b := admin.req("PUT", desk+"/api/v1/hostnames/settings", map[string]any{"enabled": false})
	if j := e.waitJob(admin, b); r.StatusCode != http.StatusAccepted || j["state"] != "succeeded" {
		t.Fatalf("%d %v", r.StatusCode, j)
	}
	// Off: no wildcard for any name, the certificate is gone, and app
	// names never get the desktop or its API.
	for _, n := range []string{"photos.home.example.net", "board.home.example.net", "files.home.example.net", "sso.home.example.net"} {
		wild, code, body := e.probe(admin, n)
		if wild || code != http.StatusNotFound || !strings.Contains(body, "Hostnames are off") {
			t.Errorf("%s off: wildcard=%v %d %s", n, wild, code, body)
		}
	}
	resp, _ := admin.req("GET", "https://photos.home.example.net/", nil)
	if resp.Header.Get("Clear-Site-Data") == "" {
		t.Fatal("no Clear-Site-Data")
	}
	if _, leaf := e.server.cfg.Hostnames.Certs.Wildcard(); leaf != nil {
		t.Fatal("certificate kept while off")
	}
	// The desktop's own name still works.
	if _, code, _ := e.probe(admin, "nas.home.example.net"); code != 200 {
		t.Fatalf("desktop: %d", code)
	}
	// And after the token is forgotten too.
	r, b = admin.req("DELETE", desk+"/api/v1/hostnames/token", map[string]string{"confirm": "home.example.net"})
	e.waitJob(admin, b)
	e.server.hosts.refresh(context.Background())
	if _, code, body := e.probe(admin, "photos.home.example.net"); code != http.StatusNotFound || !strings.Contains(body, "Hostnames are off") {
		t.Fatalf("after forgetting: %d %s", code, body)
	}
}

func TestHostnamesUnknownAndDeepNames(t *testing.T) {
	e := newHostsEnv(t)
	admin := e.activate()
	for _, n := range []string{"https://x.photos.home.example.net/api/v1/health", "https://a.b.home.example.net/", "https://nothing.home.example.net/"} {
		if r, b := admin.req("GET", n, nil); r.StatusCode != http.StatusNotFound || strings.Contains(b, `"status"`) {
			t.Errorf("%s: %d %s", n, r.StatusCode, b)
		}
	}
}

func TestHostnamesCookieTossing(t *testing.T) {
	e := newHostsEnv(t)
	admin := e.activate()
	// Both apps' own responses set "sid" (Photos' is in the jar); Board's
	// also sets board_token.
	e.server.hosts.learnCookies(http.Header{"Set-Cookie": {"board_token=x; Path=/"}}, "board")
	admin.req("GET", "https://board.home.example.net/", nil)
	admin.req("GET", "https://photos.home.example.net/", nil)
	for len(e.seen) > 0 {
		<-e.seen
	}
	// A script on board.<base> wrote cookies for the whole base: one with
	// Board's name, and a second immich_access_token on /api (the
	// "Immich path" trick: sent before Immich's own).
	req, _ := http.NewRequest("GET", "https://photos.home.example.net/api/x", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.AddCookie(&http.Cookie{Name: "board_token", Value: "evil"})
	req.AddCookie(&http.Cookie{Name: "immich_access_token", Value: "attacker"})
	req.AddCookie(&http.Cookie{Name: "immich_access_token", Value: "real"})
	resp, err := admin.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var got *http.Request
	for len(e.seen) > 0 {
		got = <-e.seen
	}
	if got == nil {
		t.Fatalf("no request reached the app (%d)", resp.StatusCode)
	}
	c := got.Header.Get("Cookie")
	if strings.Contains(c, "board_token") || strings.Contains(c, "immich_access_token") || !strings.Contains(c, "sid=1") {
		t.Fatalf("cookies reaching Photos: %q", c)
	}
}

func TestHostnamesBindCaps(t *testing.T) {
	e := newHostsEnv(t)
	e.activate()
	admin := e.browser(false)
	admin.req("POST", desk+"/api/v1/auth/login", map[string]string{"username": "cade", "password": "supersecret1"})
	u := desk + hostBindPath + "?app=immich&s=" + strings.Repeat("a", 64)
	for i := 0; i < maxCodesEach; i++ {
		if r, _ := admin.req("GET", u, nil); r.StatusCode != http.StatusSeeOther {
			t.Fatalf("%d: %d", i, r.StatusCode)
		}
	}
	if r, _ := admin.req("GET", u, nil); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over the cap: %d", r.StatusCode)
	}
}
