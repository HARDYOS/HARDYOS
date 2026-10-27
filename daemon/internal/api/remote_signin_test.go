package api

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/publish"
)

var (
	ssoInputRE   = regexp.MustCompile(`name="(id|csrf|next|sub|exp|sig)" value="([^"]*)"`)
	ssoRefreshRE = regexp.MustCompile(`http-equiv="refresh" content="0;url=([^"]+)"`)
)

// openApp opens a published app in b, signing in at HardyOS's sign-in
// provider (sso.<base>) when it asks; it returns the app's last answer.
func (b *gwBrowser) openApp(t *testing.T, u, user, pw string) (int, string) {
	t.Helper()
	code, body, _ := b.nav(t, "GET", u, nil)
	if !strings.Contains(body, `action="/login"`) {
		return b.follow(t, code, body) // already signed in at sso, or refused before sign-in
	}
	form := url.Values{}
	for _, m := range ssoInputRE.FindAllStringSubmatch(body, -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	form.Set("username", user)
	form.Set("password", pw)
	req, _ := http.NewRequest("POST", "https://sso.home.example.net/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://sso.home.example.net")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	code, body = res.StatusCode, readAll(res)
	return b.follow(t, code, body)
}

// follow takes the provider's meta-refresh pages on (relative ones stay on
// sso.<base>) to the app.
func (b *gwBrowser) follow(t *testing.T, code int, body string) (int, string) {
	t.Helper()
	for i := 0; i < 5; i++ {
		m := ssoRefreshRE.FindStringSubmatch(body)
		if m == nil {
			return code, body
		}
		target := html.UnescapeString(m[1])
		if strings.HasPrefix(target, "/") {
			target = "https://sso.home.example.net" + target
		}
		code, body, _ = b.nav(t, "GET", target, map[string]string{"Sec-Fetch-Site": "same-site"})
	}
	return code, body
}

func readAll(res *http.Response) string {
	defer res.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := res.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			return sb.String()
		}
	}
}

func TestGatewaySignInThroughSSOAndCookieIsolation(t *testing.T) {
	withProxyTimes(t, 0, time.Hour)
	e := newRemoteEnv(t)
	secret := e.setUp(t)
	b := e.browser(t, secret)

	// A fetch (not a page load) without a session isn't sent to sign in.
	if code, _, _ := b.nav(t, "GET", "https://board.home.example.net/api", map[string]string{"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Site": "same-origin"}); code != 401 {
		t.Fatalf("fetch without session = %d", code)
	}
	// A page load goes to HardyOS's sign-in on sso.<base>.
	b.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	_, _, hdr := b.nav(t, "GET", "https://board.home.example.net/page?x=1", nil)
	loc, _ := url.Parse(hdr.Get("Location"))
	if loc == nil || loc.Host != "sso.home.example.net" || loc.Path != "/authorize" || loc.Query().Get("code_challenge_method") != "S256" ||
		loc.Query().Get("redirect_uri") != "https://board.home.example.net/__hardyos/callback" {
		t.Fatalf("sign-in starts at %q", hdr.Get("Location"))
	}
	b.client.CheckRedirect = nil

	code, body := b.openApp(t, "https://board.home.example.net/page?x=1", "cade", "supersecret1")
	if code != 200 || !strings.HasPrefix(body, "host=board.home.example.net xff=203.0.113.9 proto=https nb= cookies=") || !strings.HasSuffix(body, "cookies=") {
		t.Fatalf("board = %d %q", code, body)
	}
	bc := b.cookies("https://board.home.example.net/")
	if bc[gatewayCookie] == "" || bc[gatewayStateCookie] != "" {
		t.Fatalf("board cookies = %v", bc)
	}
	// The sign-in provider's session makes the second app's sign-in silent.
	if code, body := b.openApp(t, "https://notes.home.example.net/", "", ""); code != 200 || !strings.Contains(body, "host=notes.home.example.net") {
		t.Fatalf("notes after board = %d %q", code, body)
	}
	if !strings.Contains(strings.Join(auditActions(e.admin, "apps.open"), ","), "apps.open board") {
		t.Fatalf("audit = %v", auditActions(e.admin, "apps.open"))
	}

	// Each app sets its cookies on its own host only.
	b.nav(t, "GET", "https://board.home.example.net/set", nil)
	b.nav(t, "GET", "https://notes.home.example.net/set", nil)
	_, body, _ = b.nav(t, "GET", "https://board.home.example.net/", nil)
	if !strings.HasSuffix(body, "cookies=sid=board; wide=board") {
		t.Fatalf("board sees %q", body)
	}
	_, body, _ = b.nav(t, "GET", "https://notes.home.example.net/", nil)
	if !strings.HasSuffix(body, "cookies=sid=notes; wide=notes") {
		t.Fatalf("notes sees %q", body)
	}
	if b.cookies("https://nas.home.example.net/")["wide"] != "" || b.cookies("https://sso.home.example.net/")["wide"] != "" {
		t.Fatal("an app's cookie reached another host")
	}
	// One app's session cookie is no good on another app.
	nc := b.cookies("https://notes.home.example.net/")[gatewayCookie]
	other := e.browser(t, secret)
	other.jar.SetCookies(mustURL("https://board.home.example.net/"), []*http.Cookie{{Name: gatewayCookie, Value: nc, Path: "/"}})
	other.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if code, _, _ := other.nav(t, "GET", "https://board.home.example.net/", nil); code == 200 {
		t.Fatal("notes' session opened board")
	}

	// Frame headers: the desktop may frame the app.
	_, _, hdr = b.nav(t, "GET", "https://board.home.example.net/", nil)
	csp := strings.Join(hdr.Values("Content-Security-Policy"), ",")
	if hdr.Get("X-Frame-Options") != "" || !strings.Contains(csp, "frame-ancestors 'self' https://nas.home.example.net") || strings.Contains(csp, "'none'") {
		t.Fatalf("frame headers = %v", hdr)
	}
	// Redirects stay on the published address.
	b.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	_, _, hdr = b.nav(t, "GET", "https://board.home.example.net/go", nil)
	if hdr.Get("Location") != "https://board.home.example.net/there" {
		t.Fatalf("location = %q", hdr.Get("Location"))
	}
	b.client.CheckRedirect = nil
	// Another app's page can't post to it.
	if code, _, _ := b.nav(t, "POST", "https://board.home.example.net/", map[string]string{"Origin": "https://notes.home.example.net", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-site"}); code != 403 {
		t.Fatalf("cross-app post = %d", code)
	}
}

func TestGatewayAccessAndLoginCSRF(t *testing.T) {
	withProxyTimes(t, 0, time.Hour)
	e := newRemoteEnv(t)
	secret := e.setUp(t)
	kid := e.browser(t, secret)
	if code, body := kid.openApp(t, "https://notes.home.example.net/", "kid", "kidpassword1"); code != 403 || !strings.Contains(body, "been given this app") {
		t.Fatalf("kid opened notes: %d %s", code, body)
	}
	if code, _ := kid.openApp(t, "https://board.home.example.net/", "", ""); code != 200 {
		t.Fatalf("kid can't open board: %d", code)
	}

	// Login CSRF: the attacker's callback (code and state) in the victim's
	// browser fails: the victim's state cookie isn't the attacker's.
	attacker := e.browser(t, secret)
	attacker.openApp(t, "https://notes.home.example.net/", "kid", "kidpassword1") // signs in at sso
	attacker.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	_, _, hdr := attacker.nav(t, "GET", "https://board.home.example.net/", map[string]string{})
	if hdr.Get("Location") == "" {
		// Already signed in to board: sign out of board's host only.
		attacker.jar.SetCookies(mustURL("https://board.home.example.net/"), []*http.Cookie{{Name: gatewayCookie, Value: "x", Path: "/"}})
		_, _, hdr = attacker.nav(t, "GET", "https://board.home.example.net/", nil)
	}
	authorize := hdr.Get("Location")
	// Through the provider (already signed in there) up to the app's callback.
	attacker.client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Host != "sso.home.example.net" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	_, page, ahdr := attacker.nav(t, "GET", authorize, map[string]string{"Sec-Fetch-Site": "same-site"})
	attacker.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	callback := ahdr.Get("Location")
	if m := ssoRefreshRE.FindStringSubmatch(page); m != nil {
		callback = html.UnescapeString(m[1])
	}
	if !strings.HasPrefix(callback, "https://board.home.example.net/__hardyos/callback?") {
		t.Fatalf("callback = %q", callback)
	}
	victim := e.browser(t, secret)
	victim.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	victim.nav(t, "GET", "https://board.home.example.net/", nil) // the victim's own state cookie
	if code, body, _ := victim.nav(t, "GET", callback, map[string]string{"Sec-Fetch-Site": "cross-site"}); code != 403 || !strings.Contains(body, "somewhere else") {
		t.Fatalf("planted callback = %d %s", code, body)
	}
	if victim.cookies("https://board.home.example.net/")[gatewayCookie] != "" {
		t.Fatal("victim got the attacker's session")
	}
	// The attacker's own callback still works once (single use).
	if code, _, _ := attacker.nav(t, "GET", callback, map[string]string{"Sec-Fetch-Site": "same-site"}); code != http.StatusSeeOther {
		t.Fatalf("attacker's callback = %d", code)
	}
	if code, _, _ := attacker.nav(t, "GET", callback, map[string]string{"Sec-Fetch-Site": "same-site"}); code != 403 {
		t.Fatalf("callback used twice = %d", code)
	}
}

func TestGatewayWebSocketsEndWithAccess(t *testing.T) {
	withProxyTimes(t, 0, time.Hour)
	e := newRemoteEnv(t)
	secret := e.setUp(t)
	b := e.browser(t, secret)
	if code, _ := b.openApp(t, "https://board.home.example.net/", "kid", "kidpassword1"); code != 200 {
		t.Fatalf("open = %d", code)
	}
	ctx, cancel := context.WithTimeout(e.ctx, 10*time.Second)
	defer cancel()
	hdr := http.Header{}
	hdr.Set("Origin", "https://board.home.example.net")
	c, _, err := websocket.Dial(ctx, "wss://board.home.example.net/ws", &websocket.DialOptions{HTTPClient: b.client, HTTPHeader: hdr})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	if err := c.Write(ctx, websocket.MessageText, []byte("hi")); err != nil {
		t.Fatal(err)
	}
	if _, msg, err := c.Read(ctx); err != nil || string(msg) != "hi" {
		t.Fatalf("echo = %q %v", msg, err)
	}
	// A WebSocket from another app's page is refused.
	hdr.Set("Origin", "https://notes.home.example.net")
	if _, _, err := websocket.Dial(ctx, "wss://board.home.example.net/ws", &websocket.DialOptions{HTTPClient: b.client, HTTPHeader: hdr}); err == nil {
		t.Fatal("cross-app WebSocket accepted")
	}
	// The account turned off: the WebSocket closes and the session ends.
	var users []auth.User
	e.admin.do("GET", "/api/v1/users", nil, &users)
	for _, u := range users {
		if u.Username == "kid" {
			e.admin.do("PATCH", "/api/v1/users/"+itoa(int(u.ID)), map[string]bool{"disabled": true}, nil)
		}
	}
	rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
	defer rcancel()
	if _, _, err := c.Read(rctx); err == nil || rctx.Err() != nil {
		t.Fatalf("WebSocket still open after the account was turned off: %v", err)
	}
	if code, _, _ := b.nav(t, "GET", "https://board.home.example.net/", map[string]string{"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}); code == 200 {
		t.Fatal("the app session outlived the account")
	}
}

func TestPublishedAppsOpenAtTheirAddress(t *testing.T) {
	withProxyTimes(t, 0, time.Hour)
	e := newRemoteEnv(t)
	secret := e.setUp(t)
	b := e.browser(t, secret)
	b.signIn(t, "cade", "supersecret1")
	req, _ := http.NewRequest("POST", "https://nas.home.example.net/api/v1/apps/board/open", nil)
	req.Header.Set("X-HardyOS-Request", "1")
	res, err := b.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var open AppOpen
	_ = json.NewDecoder(res.Body).Decode(&open)
	res.Body.Close()
	if open.URL != "https://board.home.example.net/" || !open.Published || !open.Proxied {
		t.Fatalf("open through the desktop's name = %+v", open)
	}
	var lan AppOpen
	if code := e.admin.do("POST", "/api/v1/apps/board/open", nil, &lan); code != 200 || lan.Published {
		t.Fatalf("open on the LAN = %d %+v", code, lan)
	}
	var ov AppsOverview
	e.kid.do("GET", "/api/v1/apps", nil, &ov)
	if ov.Published["board"] != "https://board.home.example.net/" || ov.Published["notes"] != "" {
		t.Fatalf("kid's published = %v", ov.Published)
	}
	res, err = b.client.Get("https://nas.home.example.net/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if !strings.Contains(res.Header.Get("Content-Security-Policy"), "https://*.home.example.net") {
		t.Fatalf("csp = %q", res.Header.Get("Content-Security-Policy"))
	}
	// The desktop goes public only when confirmed.
	if code := e.admin.do("PUT", "/api/v1/remote/desktop", PublishRequest{Mode: publish.ModePublic, Auth: publish.AuthNone}, nil); code != 400 {
		t.Fatalf("desktop public without confirmation = %d", code)
	}
	if j, _ := e.submit(t, "PUT", "/api/v1/remote/desktop", PublishRequest{Mode: publish.ModePublic, Auth: publish.AuthNone, ConfirmPublic: true}); j["state"] != "succeeded" {
		t.Fatalf("desktop public = %v", j)
	}

	// An app without HardyOS sign-in (its own sign-in only).
	var pv AppPublishView
	e.admin.do("GET", "/api/v1/apps/board/publish", nil, &pv)
	if !pv.Enabled || pv.URL != "https://board.home.example.net" || !pv.Config.HardyOSSignIn || !pv.Published {
		t.Fatalf("publish view = %+v", pv)
	}
	// Public with nothing in front and HardyOS sign-in off needs a
	// confirmation (the app's own sign-in is all that's left).
	var er ErrorResponse
	if code := e.admin.do("PUT", "/api/v1/apps/board/publish", PublishRequest{Mode: publish.ModePublic, Auth: publish.AuthNone}, &er); code != 400 || er.Code != "confirm_required" {
		t.Fatalf("open without confirmation = %d %+v", code, er)
	}
	// Following a public default needs it too; NetBird-only or with a
	// sign-in in front doesn't.
	if code := e.admin.do("PUT", "/api/v1/apps/board/publish", PublishRequest{Auth: publish.AuthNone}, &er); code != 400 {
		t.Fatalf("open by default without confirmation = %d", code)
	}
	if j, _ := e.submit(t, "PUT", "/api/v1/apps/notes/publish", PublishRequest{Mode: publish.ModeNetBird, Auth: publish.AuthNone}); j["state"] != "succeeded" {
		t.Fatalf("notes NetBird-only without HardyOS sign-in = %v", j)
	}
	if j, _ := e.submit(t, "PUT", "/api/v1/apps/board/publish", PublishRequest{Mode: publish.ModePublic, Auth: publish.AuthNone, HardyOSSignIn: false, ConfirmOpen: true}); j["state"] != "succeeded" {
		t.Fatalf("publish board = %v", j)
	}
	anon := e.browser(t, secret)
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, _, _ := anon.nav(t, "GET", "https://board.home.example.net/", nil)
		if code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("board without HardyOS sign-in = %d", code)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(strings.Join(auditActions(e.admin, "remote.publish"), ","), "app:board mode=public auth=none hardyosSignIn=off") {
		t.Fatalf("audit = %v", auditActions(e.admin, "remote.publish"))
	}
	// Removing an app removes its service.
	if j := e.runJob(t, "DELETE", "/api/v1/apps/board", AppRemoveRequest{Confirm: "board"}); j["state"] != "succeeded" {
		t.Fatalf("remove: %v", j)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		gone := true
		for _, v := range e.api.ServiceList() {
			if v.Domain == "board.home.example.net" {
				gone = false
			}
		}
		if gone {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("board's NetBird service outlived the app")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestShareLinksHostOnlyOpensShareLinks(t *testing.T) {
	e := newRemoteEnv(t)
	secret := e.setUp(t)
	tok := testToken
	if j, _ := e.submit(t, "PUT", "/api/v1/remote/publishing", RemotePublishingRequest{Enabled: true, BaseDomain: "home.example.net",
		APIURL: e.api.URL, DefaultMode: publish.ModePublic, PublicShareLinks: true, Token: &tok}); j["state"] != "succeeded" {
		t.Fatalf("publish = %v", j)
	}
	found := false
	for _, v := range e.api.ServiceList() {
		if v.Domain == "files.home.example.net" {
			found = true
		}
	}
	if !found {
		t.Fatal("no files.<base> service")
	}
	b := e.browser(t, secret)
	// /s/... reaches the share link pages (a missing link is their answer).
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, body, _ := b.nav(t, "GET", "https://files.home.example.net/s/nosuchlinktoken", nil)
		if !strings.Contains(body, "Nothing is published here") && !strings.Contains(body, "only opens share links") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("files /s/ = %s", body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, path := range []string{"/", "/api/v1/health", "/api/v1/auth/me", "/apps"} {
		if code, body, _ := b.nav(t, "GET", "https://files.home.example.net"+path, nil); code != 404 || !strings.Contains(body, "only opens share links") {
			t.Fatalf("files %s = %d %s", path, code, body)
		}
	}
}
