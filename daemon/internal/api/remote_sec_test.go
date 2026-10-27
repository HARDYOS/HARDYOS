package api

// Security review of remote access (decisions 144-156): what the app
// gateway serves on sso.<base>, per-service secrets, forwarded addresses,
// the desktop cookie, public sign-in, gateway sessions and bounds.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/publish"
)

// waitFor polls cond for up to 5 seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// desktopAnswer: what hardyd's desktop routes would answer on any host.
func isDesktopAnswer(code int, body string) bool {
	return code == 200 && strings.Contains(body, `"status"`) || strings.Contains(body, "sign in required") || strings.Contains(body, "no such API endpoint")
}

// sso.<base> serves the sign-in provider or nothing: never the desktop's
// API, whatever the issuer is.
func TestSSOHostNeverServesTheDesktop(t *testing.T) {
	e := newRemoteEnv(t)
	secret := e.setUp(t)
	b := e.browser(t, secret)
	paths := []string{"/api/v1/health", "/api/v1/auth/me", "/api/v1/users", "/", "/index.html"}
	for _, p := range paths {
		code, body, _ := b.nav(t, "GET", "https://sso.home.example.net"+p, nil)
		if isDesktopAnswer(code, body) {
			t.Fatalf("sso%s with its own issuer = %d %s", p, code, body)
		}
	}
	// An administrator moves the issuer to the desktop's host: until the next
	// sync takes sso.<base> down, the gateway answers 404 there.
	if err := e.server.OIDC().SetIssuer(e.ctx, "https://nas.home.example.net/oidc"); err != nil {
		t.Fatal(err)
	}
	for _, p := range append(paths, "/oidc/.well-known/openid-configuration", "/.well-known/openid-configuration") {
		code, body, _ := b.nav(t, "GET", "https://sso.home.example.net"+p, nil)
		if code != 404 || isDesktopAnswer(code, body) {
			t.Fatalf("sso%s with another issuer = %d %s", p, code, body)
		}
	}
	// The next sync removes sso.<base> from NetBird.
	e.submit(t, "POST", "/api/v1/remote/sync", struct{}{})
	for _, v := range e.api.ServiceList() {
		if v.Domain == "sso.home.example.net" {
			t.Fatal("sso.<base> still published for another issuer")
		}
	}
	// The API refuses a path on the sso host.
	var er ErrorResponse
	if code := e.admin.do("PATCH", "/api/v1/oidc", map[string]any{"issuer": "https://sso.home.example.net/oidc"}, &er); code != 400 {
		t.Fatalf("issuer with /oidc on sso = %d %+v", code, er)
	}
}

// Without a sign-in provider at all, an sso route answers 404.
func TestSSORouteWithoutAProvider(t *testing.T) {
	s := New(Config{}) // no database: no provider, but the desktop's routes
	if s.oidc != nil {
		t.Fatal("expected no provider")
	}
	rt := s.remote
	rt.routes = map[string]*gwRoute{"sso.home.example.net": {key: publish.SSOKey, host: "sso.home.example.net", public: true}}
	rt.network, rt.secret = mustPrefix("127.0.0.0/8"), "k"
	for _, p := range []string{"/api/v1/health", "/", "/oidc/authorize"} {
		req := httptest.NewRequest("GET", "https://sso.home.example.net"+p, nil)
		req.RemoteAddr = "127.0.0.1:4000"
		req.Header.Set(publish.GatewayHeader, publish.GatewayValue("k", "sso.home.example.net"))
		rec := httptest.NewRecorder()
		rt.ServeHTTP(rec, req)
		if rec.Code != 404 || isDesktopAnswer(rec.Code, rec.Body.String()) {
			t.Fatalf("%s without a provider = %d %s", p, rec.Code, rec.Body.String())
		}
	}
}

func auditIPs(c *client, action string) []string {
	var list []struct {
		Action string `json:"action"`
		IP     string `json:"ip"`
	}
	c.do("GET", "/api/v1/audit?action="+action, nil, &list)
	var out []string
	for _, a := range list {
		out = append(out, a.IP)
	}
	return out
}

func TestGatewayForwardedForAndAuditAddress(t *testing.T) {
	withProxyTimes(t, 0, time.Hour)
	e := newRemoteEnv(t)
	secret := e.setUp(t)
	b := e.browser(t, secret)
	if code, _ := b.openApp(t, "https://board.home.example.net/", "kid", "kidpassword1"); code != 200 {
		t.Fatalf("open = %d", code)
	}
	// The app sign-in is audited with the client's address, not the proxy's.
	if ips := auditIPs(e.admin, "apps.open"); len(ips) == 0 || ips[0] != "203.0.113.9" {
		t.Fatalf("apps.open audited from %v", ips)
	}
	if ips := auditIPs(e.admin, "oidc.signin"); len(ips) == 0 || ips[0] != "203.0.113.9" {
		t.Fatalf("oidc.signin audited from %v", ips)
	}
	// Only the right-most entry counts, over several header lines too.
	b.client.Transport.(*proxyHop).xff = []string{"10.0.0.1", "192.0.2.1, 203.0.113.77"}
	if _, body, _ := b.nav(t, "GET", "https://board.home.example.net/", nil); !strings.Contains(body, "xff=203.0.113.77 ") {
		t.Fatalf("app saw %q", body)
	}
	// Without the per-service value nothing is believed (or served).
	other := e.browser(t, "wrong")
	other.client.Transport.(*proxyHop).xff = []string{"203.0.113.1"}
	if code, _, _ := other.nav(t, "GET", "https://board.home.example.net/", nil); code != 403 {
		t.Fatalf("without the secret = %d", code)
	}
}

func TestGatewaySecretRotation(t *testing.T) {
	e := newRemoteEnv(t)
	old := e.setUp(t)
	if code := e.kid.do("POST", "/api/v1/remote/gateway/rotate", nil, nil); code != 403 {
		t.Fatalf("kid rotated: %d", code)
	}
	if j, _ := e.submit(t, "POST", "/api/v1/remote/gateway/rotate", struct{}{}); j["state"] != "succeeded" {
		t.Fatalf("rotate = %v", j)
	}
	now, _ := e.pub.Store.GatewaySecret(e.ctx)
	if now == old {
		t.Fatal("secret unchanged")
	}
	for _, v := range e.api.ServiceList() {
		if v.Targets[0].Options.CustomHeaders[publish.GatewayHeader] != publish.GatewayValue(now, v.Domain) {
			t.Fatalf("%s kept the old value", v.Domain)
		}
	}
	waitFor(t, "the gateway to take the new secret", func() bool {
		code, _, _ := e.browser(t, old).nav(t, "GET", "https://sso.home.example.net/.well-known/openid-configuration", nil)
		return code == 403
	})
	if code, _, _ := e.browser(t, now).nav(t, "GET", "https://sso.home.example.net/.well-known/openid-configuration", nil); code != 200 {
		t.Fatalf("new secret = %d", code)
	}
	if !strings.Contains(strings.Join(auditActions(e.admin, "remote.gateway"), ","), "remote.gateway.rotate") {
		t.Fatal("rotation not audited")
	}
	// Turning publishing off replaces it too.
	tok := testToken
	e.submit(t, "PUT", "/api/v1/remote/publishing", RemotePublishingRequest{Enabled: false, BaseDomain: "home.example.net", APIURL: e.api.URL, Token: &tok})
	if off, _ := e.pub.Store.GatewaySecret(e.ctx); off == now {
		t.Fatal("secret kept after publishing was turned off")
	}
}

func TestDesktopCookieOnPublishedHosts(t *testing.T) {
	e := newRemoteEnv(t)
	secret := e.setUp(t)
	b := e.browser(t, secret)
	b.signIn(t, "cade", "supersecret1")
	jar := b.cookies("https://nas.home.example.net/")
	if jar[SessionCookie] == "" || jar[LegacySessionCookie] != "" {
		t.Fatalf("desktop cookies over HTTPS = %v", jar)
	}
	req, _ := http.NewRequest("GET", "https://nas.home.example.net/api/v1/auth/me", nil)
	if res, err := b.client.Do(req); err != nil || res.StatusCode != 200 {
		t.Fatalf("me with the new cookie: %v %v", res, err)
	}
	// A valid session under the old name (as a sibling app could plant it)
	// opens nothing on a published host.
	var token string
	for _, c := range e.admin.http.Jar.Cookies(mustURL(e.srv.URL)) {
		if c.Name == LegacySessionCookie {
			token = c.Value
		}
	}
	if token == "" {
		t.Fatal("no plain-HTTP session to plant (test setup)")
	}
	planted := e.browser(t, secret)
	planted.jar.SetCookies(mustURL("https://nas.home.example.net/"), []*http.Cookie{{Name: LegacySessionCookie, Value: token, Path: "/"}})
	req, _ = http.NewRequest("GET", "https://nas.home.example.net/api/v1/auth/me", nil)
	if res, err := planted.client.Do(req); err != nil || res.StatusCode != 401 {
		t.Fatalf("old-name cookie on a published host = %v %v", res, err)
	}
	// Migration: over HTTPS on the desktop's own (unpublished) address the
	// old name still works for one release; on a published name it doesn't.
	lan := httptest.NewRequest("GET", "https://192.168.1.5/api/v1/auth/me", nil)
	lan.AddCookie(&http.Cookie{Name: LegacySessionCookie, Value: token})
	if _, ok := e.server.sessionToken(lan); !ok {
		t.Fatal("old cookie refused on the LAN address during the migration")
	}
	pub := httptest.NewRequest("GET", "https://nas.home.example.net/api/v1/auth/me", nil)
	pub.AddCookie(&http.Cookie{Name: LegacySessionCookie, Value: token})
	if _, ok := e.server.sessionToken(pub); ok {
		t.Fatal("old cookie accepted on a published host")
	}
}

func TestPublicSSOFailuresDontLockTheLANAndAdminsAreRefused(t *testing.T) {
	e := newRemoteEnv(t)
	secret := e.setUp(t)
	for range 7 {
		e.browser(t, secret).openApp(t, "https://board.home.example.net/", "kid", "wrong-password")
	}
	// kid signs in at home all the same.
	home := e.client(t)
	if code := home.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil); code != 200 {
		t.Fatalf("kid at home after public failures = %d", code)
	}
	// Administrators: the uniform answer from the internet by default.
	if err := e.server.OIDC().SetPublicAdmins(e.ctx, false); err != nil {
		t.Fatal(err)
	}
	// (From another address: 203.0.113.9 is being slowed down now.)
	elsewhere := func() *gwBrowser {
		b := e.browser(t, secret)
		b.client.Transport.(*proxyHop).ip = "203.0.113.30"
		return b
	}
	code, body := elsewhere().openApp(t, "https://board.home.example.net/", "cade", "supersecret1")
	if code == 200 || !strings.Contains(body, "Incorrect username or password.") {
		t.Fatalf("admin from the internet = %d %s", code, body)
	}
	var st map[string]any
	if c := e.admin.do("PATCH", "/api/v1/oidc", map[string]any{"publicAdmins": true}, &st); c != 200 || st["publicAdmins"] != true {
		t.Fatalf("publicAdmins setting = %d %v", c, st)
	}
	if code, _ := elsewhere().openApp(t, "https://board.home.example.net/", "cade", "supersecret1"); code != 200 {
		t.Fatalf("admin with the setting on = %d", code)
	}
}

func TestGatewaySessionsFollowTheProvider(t *testing.T) {
	withProxyTimes(t, 0, time.Hour)
	e := newRemoteEnv(t)
	secret := e.setUp(t)
	fetch := map[string]string{"Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Site": "same-origin"}
	b := e.browser(t, secret)
	if code, _ := b.openApp(t, "https://board.home.example.net/", "kid", "kidpassword1"); code != 200 {
		t.Fatalf("open = %d", code)
	}
	// HardyOS accounts turned off for apps: kid's app session ends.
	if err := e.server.OIDC().SetLocalAccounts(e.ctx, false); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := b.nav(t, "GET", "https://board.home.example.net/", fetch); code == 200 {
		t.Fatal("app session outlived the local-accounts setting")
	}
	_ = e.server.OIDC().SetLocalAccounts(e.ctx, true)
	b = e.browser(t, secret)
	if code, _ := b.openApp(t, "https://board.home.example.net/", "kid", "kidpassword1"); code != 200 {
		t.Fatalf("reopen = %d", code)
	}
	// Every sign-in at the gateway's client revoked: the session ends.
	c, err := e.server.OIDC().Clients.Managed(e.ctx, gatewayClientKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.server.OIDC().RevokeClient(e.ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := b.nav(t, "GET", "https://board.home.example.net/", fetch); code == 200 {
		t.Fatal("app session outlived its revoked grant")
	}
}

func TestGatewayPendingSignInsBounded(t *testing.T) {
	e := newRemoteEnv(t)
	secret := e.setUp(t)
	b := e.browser(t, secret)
	b.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	last := 0
	for range maxGatewayPendingPerIP + 1 {
		last, _, _ = b.nav(t, "GET", "https://board.home.example.net/", nil)
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("sign-ins past the limit = %d", last)
	}
	// Another address isn't held up.
	other := e.browser(t, secret)
	other.client.Transport.(*proxyHop).ip = "203.0.113.200"
	other.client.CheckRedirect = b.client.CheckRedirect
	if code, _, _ := other.nav(t, "GET", "https://board.home.example.net/", nil); code != http.StatusSeeOther {
		t.Fatalf("another address = %d", code)
	}
}

func TestGatewayClientKeptAndAudited(t *testing.T) {
	e := newRemoteEnv(t)
	e.setUp(t)
	var list []struct {
		Action string `json:"action"`
		Actor  string `json:"actor"`
	}
	e.admin.do("GET", "/api/v1/audit?action=oidc.client", nil, &list)
	created := false
	for _, a := range list {
		if a.Action == "oidc.client.create" && a.Actor == "hardyos" {
			created = true
		}
	}
	if !created {
		t.Fatalf("the gateway's client wasn't audited as HardyOS's: %+v", list)
	}
	// No app asks for HardyOS sign-in any more: no redirect URI is left.
	e.submit(t, "PUT", "/api/v1/apps/notes/publish", PublishRequest{Mode: publish.ModeNetBird, Auth: publish.AuthNone})
	e.submit(t, "PUT", "/api/v1/apps/board/publish", PublishRequest{Mode: publish.ModePublic, Auth: publish.AuthSSO})
	waitFor(t, "the redirect URIs to go", func() bool {
		c, err := e.server.OIDC().Clients.Managed(e.ctx, gatewayClientKey)
		return err == nil && len(c.RedirectURIs) == 0
	})
	if !strings.Contains(strings.Join(auditActions(e.admin, "oidc.client.update"), ","), "HardyOS app gateway") {
		t.Fatal("removing the redirect URIs wasn't audited")
	}
}

func TestChangingNetBirdsAPIAddressNeedsTheToken(t *testing.T) {
	e := newRemoteEnv(t)
	e.setUp(t)
	var er ErrorResponse
	req := RemotePublishingRequest{Enabled: true, BaseDomain: "home.example.net", APIURL: "https://evil.example.net", DefaultMode: publish.ModePublic}
	if code := e.admin.do("PUT", "/api/v1/remote/publishing", req, &er); code != 400 || er.Code != "token_required" {
		t.Fatalf("new API address without the token = %d %+v", code, er)
	}
	// The same address (written differently) needs nothing.
	req.APIURL = e.api.URL + "/api/"
	if j, _ := e.submit(t, "PUT", "/api/v1/remote/publishing", req); j["state"] != "succeeded" {
		t.Fatalf("same address = %v", j)
	}
}

func TestSignInChangesRunAsJobs(t *testing.T) {
	e := newRemoteEnv(t)
	var created struct {
		Client map[string]any `json:"client"`
		Secret string         `json:"secret"`
	}
	if code := e.admin.do("POST", "/api/v1/oidc/clients", map[string]any{"name": "Grafana", "redirectUris": []string{"https://grafana.example.net/cb"}}, &created); code != 201 || created.Secret == "" {
		t.Fatalf("create = %d %+v", code, created)
	}
	var list []map[string]any
	e.admin.do("GET", "/api/v1/jobs", nil, &list)
	var all strings.Builder
	found := false
	for _, j := range list {
		if j["kind"] == JobKindOIDCClientCreate {
			// The request had its answer as the job finished; its record
			// follows a moment later.
			if done := waitJobDone(t, e.admin, j["id"].(string)); done["state"] == "succeeded" {
				found = true
			}
			all.WriteString(jobText(t, e.admin, j["id"].(string)))
		}
	}
	if !found {
		t.Fatalf("no sign-in job: %v", list)
	}
	if strings.Contains(all.String(), created.Secret) {
		t.Fatal("the client secret is in the job")
	}
	// Errors still come back as before.
	var er ErrorResponse
	if code := e.admin.do("POST", "/api/v1/oidc/clients", map[string]any{"name": "x", "redirectUris": []string{"http://evil.example"}}, &er); code != 400 || er.Code != "invalid" {
		t.Fatalf("invalid client = %d %+v", code, er)
	}
	_ = audit.Success
	_ = context.Background
}
