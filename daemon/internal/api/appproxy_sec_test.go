package api

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/tlscert"
)

// secBackend is every app's web page in these tests: it sets cookies on
// /set, echoes the cookies it got on /, and holds WebSockets on /ws.
func secBackend(t *testing.T) int {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/set":
			_, port, _ := net.SplitHostPort(r.Host)
			for _, c := range []string{"sid=" + port + "; Path=/; HttpOnly", "hardyos_session=evil; Path=/", "HardyOS_App_board=evil; Path=/",
				"dom=1; Domain=127.0.0.1; Path=/"} {
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
		default:
			_, _ = io.WriteString(w, "cookies="+r.Header.Get("Cookie"))
		}
	}))
	t.Cleanup(backend.Close)
	return backend.Listener.Addr().(*net.TCPAddr).Port
}

// writeBoardApp adds a second catalog app with a web page.
func writeBoardApp(t *testing.T, dir string) {
	t.Helper()
	b := packApp(t, `{"format":1,"id":"board","name":"Board","version":"1.0.0","summary":"A board.","icon":"icon.svg",
	  "web":{"port":"WEB"},"ports":[{"name":"WEB","label":"Website","default":8500}]}`,
		"services:\n  app:\n    image: ghcr.io/x/board:1\n    ports: [\"${HARDY_PORT_WEB}:80\"]\n")
	if err := os.WriteFile(filepath.Join(dir, "board.hardyapp"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// startProxy runs the window proxy with a test certificate on free ports.
func startProxy(t *testing.T, e *appsEnv, interval time.Duration) func() {
	t.Helper()
	certPEM, keyPEM, err := tlscert.Generate([]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	probe, _ := net.Listen("tcp", "127.0.0.1:0")
	base := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	ctx, cancel := context.WithCancel(e.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.server.RunAppProxy(ctx, AppProxyOptions{TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, BasePort: base,
			ListenHost: "127.0.0.1", DesktopPort: 443, Interval: interval})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !e.server.proxy.isRunning() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	stop := func() { cancel(); <-done }
	t.Cleanup(stop)
	return stop
}

var insecureTLS = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

// browserOf is c's browser: its cookie jar (with the desktop session) for
// every port on the host.
func browserOf(c *client) *http.Client {
	return &http.Client{Jar: c.http.Jar, Transport: insecureTLS, Timeout: 10 * time.Second}
}

// openApp asks the desktop for an app's link and follows it in c's browser,
// returning the proxy's base URL.
func openApp(t *testing.T, c *client, id string) string {
	t.Helper()
	var open AppOpen
	if code := c.do("POST", "/api/v1/apps/"+id+"/open", nil, &open); code != 200 || !open.Proxied {
		t.Fatalf("open %s = %d %+v", id, code, open)
	}
	req, _ := http.NewRequest("GET", open.URL, nil)
	req.Header.Set("Sec-Fetch-Dest", "iframe")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	res, err := browserOf(c).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("signing in to %s's window = %d", id, res.StatusCode)
	}
	u, _ := url.Parse(open.URL)
	return "https://" + u.Host
}

func get(t *testing.T, b *http.Client, u string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", u, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(body)
}

func withProxyTimes(t *testing.T, recheck, sweep time.Duration) {
	oldR, oldS := proxyRecheck, proxySweep
	proxyRecheck, proxySweep = recheck, sweep
	t.Cleanup(func() { proxyRecheck, proxySweep = oldR, oldS })
}

// Two apps on two ports share the browser's cookie jar (cookies aren't
// isolated by port): each app only ever sees its own cookies, under its own
// names, and never HardyOS's.
func TestAppProxyCookieIsolation(t *testing.T) {
	withProxyTimes(t, 0, time.Hour)
	bport := secBackend(t)
	e := newAppsEnv(t)
	writeBoardApp(t, e.catalog)
	e.stub.webPortFrom = bport
	e.installNotes(t, nil)
	if j := e.runJob(t, "POST", "/api/v1/apps/install", AppInstallRequest{AppPackageRef: AppPackageRef{Source: "catalog", Ref: "board"}}); j["state"] != "succeeded" {
		t.Fatalf("install board: %v", j)
	}
	startProxy(t, e, time.Hour)
	notes, board := openApp(t, e.admin, "notes"), openApp(t, e.admin, "board")
	if notes == board {
		t.Fatal("one port for two apps")
	}
	b := browserOf(e.admin)
	var desktopBefore string
	for _, c := range e.admin.http.Jar.Cookies(mustURL(notes)) {
		if c.Name == SessionCookie {
			desktopBefore = c.Value
		}
	}
	if desktopBefore == "" {
		t.Fatal("the desktop cookie doesn't reach the proxy's port (test setup)")
	}

	if code, _ := get(t, b, notes+"/set", nil); code != 200 {
		t.Fatalf("notes /set = %d", code)
	}
	names := map[string]string{}
	for _, c := range e.admin.http.Jar.Cookies(mustURL(notes)) {
		names[c.Name] = c.Value
	}
	_, nport, _ := net.SplitHostPort(mustURL(notes).Host)
	if names["a_notes_sid"] != nport || names["a_notes_dom"] != "1" || names["sid"] != "" || names["a_notes_hardyos_session"] != "" {
		t.Fatalf("cookies after notes set them: %v", names)
	}
	if names[SessionCookie] != desktopBefore || names["hardyos_app_board"] == "evil" {
		t.Fatalf("an app overwrote a HardyOS cookie: %v", names)
	}

	// Board sees none of notes' cookies, and no HardyOS cookie.
	if code, body := get(t, b, board+"/", nil); code != 200 || body != "cookies=" {
		t.Fatalf("board sees %d %q", code, body)
	}
	get(t, b, board+"/set", nil)
	_, bp, _ := net.SplitHostPort(mustURL(board).Host)
	if _, body := get(t, b, notes+"/", nil); body != "cookies=sid="+nport+"; dom=1" {
		t.Fatalf("notes sees %q", body)
	}
	if _, body := get(t, b, board+"/", nil); body != "cookies=sid="+bp+"; dom=1" {
		t.Fatalf("board sees %q", body)
	}
	// A cookie a page sets from JavaScript has no app prefix: no app gets
	// it (the residual risk is that every page on the host can read it).
	e.admin.http.Jar.SetCookies(mustURL(notes), []*http.Cookie{{Name: "js", Value: "1", Path: "/"}})
	if _, body := get(t, b, notes+"/", nil); strings.Contains(body, "js=") {
		t.Fatalf("a script cookie reached the app: %q", body)
	}
}

// Another app's page (same site, another port) can't post to, embed or
// open WebSockets to an app, nor sign someone in with its own token.
func TestAppProxyCrossAppRequests(t *testing.T) {
	withProxyTimes(t, 0, time.Hour)
	bport := secBackend(t)
	e := newAppsEnv(t)
	e.stub.webPortFrom = bport
	e.installNotes(t, nil)
	startProxy(t, e, time.Hour)
	notes := openApp(t, e.admin, "notes")
	b := browserOf(e.admin)
	other := "https://127.0.0.1:1" // another app's proxy origin

	post := func(origin string, hdr map[string]string) int {
		req, _ := http.NewRequest("POST", notes+"/form", strings.NewReader("x=1"))
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		res, err := b.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if code := post(other, map[string]string{"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate"}); code != 403 {
		t.Errorf("form post from another app = %d", code)
	}
	if code := post("null", nil); code != 403 {
		t.Errorf("post from an opaque origin = %d", code)
	}
	if code := post(notes, map[string]string{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"}); code != 200 {
		t.Errorf("the app's own post = %d", code)
	}
	if code := post("", nil); code != 200 {
		t.Errorf("post without Origin (old browser) = %d", code)
	}
	for _, h := range []map[string]string{
		{"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"},
		{"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors"},
	} {
		if code, _ := get(t, b, notes+"/", h); code != 403 {
			t.Errorf("GET %v = %d", h, code)
		}
	}
	for _, h := range []map[string]string{
		{"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}, // a link into the app
		{"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"},
		{"Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate"},
	} {
		if code, _ := get(t, b, notes+"/", h); code != 200 {
			t.Errorf("GET %v = %d", h, code)
		}
	}

	ws := "wss" + strings.TrimPrefix(notes, "https") + "/ws"
	if _, _, err := websocket.Dial(e.ctx, ws, &websocket.DialOptions{HTTPClient: b, HTTPHeader: http.Header{"Origin": {other}}}); err == nil {
		t.Error("a WebSocket from another app's page connected")
	}
	c, _, err := websocket.Dial(e.ctx, ws, &websocket.DialOptions{HTTPClient: b, HTTPHeader: http.Header{"Origin": {notes}}})
	if err != nil {
		t.Fatalf("the app's own WebSocket: %v", err)
	}
	c.CloseNow()

	// Sign-in links: only for frames and pages, never fetched as an image,
	// never from another site, and only in the browser with the desktop
	// session the link was made for.
	var open AppOpen
	e.admin.do("POST", "/api/v1/apps/notes/open", nil, &open)
	noFollow := &http.Client{Jar: e.admin.http.Jar, Transport: insecureTLS, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	try := func(cl *http.Client, hdr map[string]string) *http.Response {
		req, _ := http.NewRequest("GET", open.URL, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		res, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	if res := try(noFollow, map[string]string{"Sec-Fetch-Dest": "image", "Sec-Fetch-Site": "same-site"}); res.StatusCode != 403 {
		t.Errorf("sign-in as an image = %d", res.StatusCode)
	}
	if res := try(noFollow, map[string]string{"Sec-Fetch-Dest": "iframe", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}); res.StatusCode != 403 {
		t.Errorf("sign-in from another site = %d", res.StatusCode)
	}
	// Login CSRF: the admin's link opened in the kid's browser.
	kidNoFollow := &http.Client{Jar: e.kid.http.Jar, Transport: insecureTLS, CheckRedirect: noFollow.CheckRedirect}
	if res := try(kidNoFollow, map[string]string{"Sec-Fetch-Dest": "iframe", "Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "navigate"}); res.StatusCode != 403 {
		t.Errorf("someone else's sign-in link = %d", res.StatusCode)
	}
	// (that used the link up)
	e.admin.do("POST", "/api/v1/apps/notes/open", nil, &open)
	res := try(noFollow, map[string]string{"Sec-Fetch-Dest": "document", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate"})
	if res.StatusCode != 303 {
		t.Fatalf("Open in new tab = %d", res.StatusCode)
	}
	var pc *http.Cookie
	for _, ck := range res.Cookies() {
		if ck.Name == "hardyos_app_notes" {
			pc = ck
		}
	}
	if pc == nil || pc.SameSite != http.SameSiteStrictMode || !pc.HttpOnly || !pc.Secure {
		t.Fatalf("proxy cookie: %+v", pc)
	}

	// A proxy cookie planted in another browser (scripts can set cookies
	// for every port) is useless without the desktop session it belongs to.
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(mustURL(notes), []*http.Cookie{{Name: pc.Name, Value: pc.Value, Path: "/"}})
	kidJar := e.kid.http.Jar
	for _, ck := range kidJar.Cookies(mustURL(e.srv.URL)) {
		jar.SetCookies(mustURL(notes), []*http.Cookie{{Name: ck.Name, Value: ck.Value, Path: "/"}})
	}
	if code, _ := get(t, &http.Client{Jar: jar, Transport: insecureTLS}, notes+"/", nil); code != 401 {
		t.Errorf("planted proxy cookie = %d", code)
	}
}

// expectClosed waits for a WebSocket to be closed by the proxy.
func expectClosed(t *testing.T, c *websocket.Conn, what string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := c.Read(ctx); err == nil || ctx.Err() != nil {
		t.Fatalf("%s: the WebSocket stayed open (%v)", what, err)
	}
}

func dialWS(t *testing.T, b *http.Client, base string) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.Dial(context.Background(), "wss"+strings.TrimPrefix(base, "https")+"/ws", &websocket.DialOptions{HTTPClient: b})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Write(context.Background(), websocket.MessageText, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	if _, m, err := c.Read(context.Background()); err != nil || string(m) != "hi" {
		t.Fatalf("websocket echo: %v %q", err, m)
	}
	t.Cleanup(func() { c.CloseNow() })
	return c
}

// WebSockets don't outlive the right to use the app.
func TestAppProxyWebSocketRevocation(t *testing.T) {
	withProxyTimes(t, time.Hour, 100*time.Millisecond)
	bport := secBackend(t)
	e := newAppsEnv(t)
	e.stub.webPortFrom = bport
	e.installNotes(t, nil) // everyone may use it
	// The reconcile timer never fires here: finished jobs must drop sessions.
	stop := startProxy(t, e, time.Hour)

	// Access removed: the kid's WebSocket closes at once.
	kidApp := openApp(t, e.kid, "notes")
	c := dialWS(t, browserOf(e.kid), kidApp)
	if code := e.admin.do("PUT", "/api/v1/apps/notes/access", AppAccess{Principals: []appstore.Principal{{Kind: "user", Name: "cade"}}}, nil); code != 200 {
		t.Fatal(code)
	}
	expectClosed(t, c, "access removed")

	// Sign-out.
	e.admin.do("PUT", "/api/v1/apps/notes/access", AppAccess{}, nil)
	kidApp = openApp(t, e.kid, "notes")
	c = dialWS(t, browserOf(e.kid), kidApp)
	e.kid.do("POST", "/api/v1/auth/logout", nil, nil)
	expectClosed(t, c, "signed out")

	// The desktop session ending any other way (expired, revoked): the sweep.
	e.kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kidApp = openApp(t, e.kid, "notes")
	c = dialWS(t, browserOf(e.kid), kidApp)
	if _, err := e.db.Exec(`DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = 'kid')`); err != nil {
		t.Fatal(err)
	}
	expectClosed(t, c, "session gone (sweep)")

	// An account turned off.
	e.kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kidApp = openApp(t, e.kid, "notes")
	c = dialWS(t, browserOf(e.kid), kidApp)
	var users []auth.User
	e.admin.do("GET", "/api/v1/users", nil, &users)
	for _, u := range users {
		if u.Username == "kid" {
			e.admin.do("PATCH", "/api/v1/users/"+itoa(int(u.ID)), map[string]bool{"disabled": true}, nil)
		}
	}
	expectClosed(t, c, "account disabled")

	// The app reconfigured: its listener and sessions go when the job ends,
	// not on the next reconcile.
	adminApp := openApp(t, e.admin, "notes")
	c = dialWS(t, browserOf(e.admin), adminApp)
	if j := e.runJob(t, "PATCH", "/api/v1/apps/notes/config", AppConfigUpdate{Settings: map[string]string{"TITLE": "New"}}); j["state"] != "succeeded" {
		t.Fatalf("reconfigure: %v", j)
	}
	expectClosed(t, c, "reconfigured")
	deadline := time.Now().Add(5 * time.Second)
	for {
		// The job's end drops the listener and the reconcile right after
		// starts it again: a refused connection in between is that gap,
		// not an answer, so try again (an answer must be 401).
		res, err := browserOf(e.admin).Get(adminApp + "/")
		code := 0
		if err == nil {
			code = res.StatusCode
			res.Body.Close()
		}
		if code == 401 {
			break // the old window session is gone; the listener is back
		}
		if time.Now().After(deadline) {
			t.Fatalf("after reconfigure the old session still answers %d", code)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The proxy stopping closes hijacked connections too (http.Server.Close
	// doesn't).
	adminApp = openApp(t, e.admin, "notes")
	c = dialWS(t, browserOf(e.admin), adminApp)
	stop()
	expectClosed(t, c, "proxy stopped")
}

// The proxy checks the desktop session without keeping it alive.
func TestPeekSessionMatchesValidate(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := New(Config{DB: db})
	u, err := s.users.Create(ctx, auth.NewUser{Username: "cade", Password: "supersecret1", Role: auth.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := s.sessions.Create(ctx, u.ID, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	old := store.FormatTime(time.Now().Add(-2 * time.Hour))
	exp := store.FormatTime(time.Now().Add(time.Hour))
	if _, err := db.Exec(`UPDATE sessions SET last_seen_at = ?, expires_at = ?`, old, exp); err != nil {
		t.Fatal(err)
	}
	info, err := s.peekSession(ctx, tok)
	if err != nil || info.UserID != u.ID {
		t.Fatalf("peek: %v %+v", err, info)
	}
	var seen, expires string
	_ = db.QueryRow(`SELECT last_seen_at, expires_at FROM sessions`).Scan(&seen, &expires)
	if seen != old || expires != exp {
		t.Fatalf("peek extended the session: %s %s", seen, expires)
	}
	// Validate reads the same row (and does extend it).
	if v, err := s.sessions.Validate(ctx, tok); err != nil || v.UserID != info.UserID {
		t.Fatalf("validate: %v", err)
	}
	if _, err := s.peekSession(ctx, tok+"x"); err != auth.ErrNoSession {
		t.Errorf("wrong token: %v", err)
	}
	if _, err := db.Exec(`UPDATE sessions SET expires_at = ?`, store.FormatTime(time.Now().Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.peekSession(ctx, tok); err != auth.ErrNoSession {
		t.Errorf("expired: %v", err)
	}
}
