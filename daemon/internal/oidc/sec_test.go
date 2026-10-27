package oidc

// Security review of remote access (decisions 140-152): the issuer on its
// own host, public sign-in, account anchors, code exchange and bounds.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
)

func TestIssuerOnTheSSOHostHasNoPath(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_ = e.db.SetSetting(ctx, SettingRemoteBase, "home.example.net")
	e.p.dropSettings()
	for _, bad := range []string{"https://sso.home.example.net/oidc", "https://SSO.home.example.net/oidc"} {
		if err := e.p.SetIssuer(ctx, bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"https://sso.home.example.net", "https://nas.home.example.net/oidc", "https://login.example.org"} {
		if err := e.p.SetIssuer(ctx, good); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
}

// A code presented by another client, without the secret or with the
// wrong PKCE verifier is refused without being used up: the real client's
// exchange still works and nothing is revoked as a replay.
func TestCodeNotBurntByTheWrongClient(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	_, other := confidentialClient(e, ClientSpec{Name: "Other"})
	code := e.browser().login(f, "alice", "pw").Get("code")

	wrongVerifier := *f
	wrongVerifier.verifier = "another-verifier-0123456789-0123456789-0123456789"
	wrongSecret := *f
	wrongSecret.secret = "not-the-secret"
	wrongRedirect := *f
	wrongRedirect.redirect = "https://rp.example.net/elsewhere"
	for name, g := range map[string]*flow{"other client": other, "wrong verifier": &wrongVerifier, "wrong secret": &wrongSecret, "wrong redirect": &wrongRedirect} {
		if tok := e.exchange(g, code); tok.Status == 200 {
			t.Fatalf("%s exchanged the code", name)
		}
	}
	if tok := e.exchange(f, code); tok.Status != 200 || tok.IDToken == "" {
		t.Fatalf("the real client's exchange = %+v", tok)
	}
	if e.sawAudit("oidc.code.replay") {
		t.Fatal("a refused exchange counted as a replay")
	}
}

func TestPublicSignInSlowsDownWithoutLockingHomeOut(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	e.public.Store(true)
	b := e.browser()
	page := body(b.authorize(f))
	var resp *http.Response
	for range 5 { // 3 free, the 4th sets a 1 s wait, the 5th meets it
		resp, page = b.signIn(page, "alice", "wrong")
	}
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(page, "seconds") {
		t.Fatalf("public: %d %s", resp.StatusCode, page)
	}
	// Only slowed down: the next try after the wait is allowed again.
	e.p.cfg.PublicLimiter.Succeed("pub-ip:127.0.0.1")
	e.p.cfg.PublicLimiter.Succeed(`pub-user:home\alice`)
	// At home (or over NetBird) alice isn't locked out at all.
	if ok, _ := e.p.cfg.Limiter.Allowed(`user:home\alice`); !ok {
		t.Fatal("public failures locked the home bucket")
	}
	e.public.Store(false)
	if q := e.browser().login(newFlow(f.clientID, f.secret), "alice", "pw"); q.Get("code") == "" {
		t.Fatal("alice can't sign in at home")
	}
	if !e.sawAudit("oidc.signin failure bad credentials (alice); from a public address") {
		t.Fatalf("public failure not marked: %v", e.audits)
	}
}

func TestPublicSignInFailuresLookTheSame(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	off := e.domain.add("bob", "pw", "11111111-2222-3333-4444-555555555555")
	off.Enabled = false
	_, f := confidentialClient(e, ClientSpec{})
	answer := func(user, pw string) (int, string) {
		b := e.browser()
		resp, page := b.signIn(body(b.authorize(newFlow(f.clientID, f.secret))), user, pw)
		return resp.StatusCode, page
	}
	e.public.Store(true)
	for _, c := range [][2]string{{"alice", "wrong"}, {"bob", "pw"}, {"nobody", "pw"}, {"HOME\\bob", "pw"}} {
		code, page := answer(c[0], c[1])
		if code != http.StatusUnauthorized || !strings.Contains(page, uniformFailure) {
			t.Errorf("%s from the internet: %d", c[0], code)
		}
	}
}

func TestAdministratorsDontSignInFromTheInternet(t *testing.T) {
	e := newEnv(t)
	e.domain.add("boss", "pw", "22222222-3333-4444-5555-666666666666", "Domain Admins")
	_, f := confidentialClient(e, ClientSpec{})
	e.public.Store(true)
	b := e.browser()
	resp, page := b.signIn(body(b.authorize(f)), "boss", "pw")
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(page, uniformFailure) {
		t.Fatalf("admin from the internet: %d", resp.StatusCode)
	}
	var n int
	_ = e.db.QueryRow(`SELECT COUNT(*) FROM oidc_browser_sessions`).Scan(&n)
	if n != 0 {
		t.Fatal("an administrator got a sign-in session from the internet")
	}
	if !e.sawAudit("oidc.signin denied an administrator from a public address") {
		t.Fatalf("not audited: %v", e.audits)
	}
	// At home they sign in; that session isn't reused from the internet.
	e.public.Store(false)
	home := e.browser()
	if q := home.login(newFlow(f.clientID, f.secret), "boss", "pw"); q.Get("code") == "" {
		t.Fatal("admin at home")
	}
	e.public.Store(true)
	if resp := home.authorize(newFlow(f.clientID, f.secret)); resp.StatusCode != http.StatusOK || !strings.Contains(body(resp), `action="/oidc/login"`) {
		t.Fatal("the home session let an administrator in from the internet")
	}
	// Allowed by the setting.
	if err := e.p.SetPublicAdmins(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if q := e.browser().login(newFlow(f.clientID, f.secret), "boss", "pw"); q.Get("code") == "" {
		t.Fatal("admin from the internet with the setting on")
	}
}

// Someone signed in to HardyOS sign-in as alice; alice is deleted and the
// name given to someone else. The old browser session doesn't become the
// new person's: it ends, as does everything else of the old one.
func TestReplacedAccountEndsTheOldSessions(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	f.scopes = "openid offline_access"
	old := e.browser()
	tok := e.exchange(f, old.login(f, "alice", "pw").Get("code"))
	e.domain.add("alice", "pw2", "99999999-8888-7777-6666-555555555555")
	resp := old.authorize(newFlow(f.clientID, f.secret))
	page := body(resp)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(page, "Sign in again") {
		t.Fatalf("old session after the replacement: %d %s", resp.StatusCode, page)
	}
	if r := e.refresh(f, tok.RefreshToken); r.Status == 200 {
		t.Fatal("the old person's refresh token still works")
	}
	if st, _ := e.userinfo(tok.AccessToken); st == 200 {
		t.Fatal("the old person's access token still works")
	}
	if len(e.ended) == 0 || !e.sawAudit("oidc.subject.change") {
		t.Fatalf("desktop sessions not ended (%v) or not audited", e.ended)
	}
	// The new alice signs in with her password and gets her own subject.
	f2 := newFlow(f.clientID, f.secret)
	t2 := e.exchange(f2, e.browser().login(f2, "alice", "pw2").Get("code"))
	if c := e.verify(t2.IDToken); c["sub"] != "99999999-8888-7777-6666-555555555555" {
		t.Fatalf("sub %v", c["sub"])
	}
	// The anchor check also runs at a desktop-style refresh (SignIn.Anchor).
	u, _ := e.users.GetByName(context.Background(), `HOME\alice`)
	if err := e.p.CheckAnchor(context.Background(), u, aliceGUID, false); err != auth.ErrAccountReplaced {
		t.Fatalf("CheckAnchor with the old GUID = %v", err)
	}
}

func TestPasswordSetInTheDomainEndsOlderSignIns(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	f.scopes = "openid offline_access"
	b := e.browser()
	tok := e.exchange(f, b.login(f, "alice", "pw").Get("code"))
	e.clock.add(time.Minute)
	u, _ := e.users.GetByName(context.Background(), `HOME\alice`)
	if n := e.p.PasswordSet(context.Background(), u.ID, e.clock.now()); n < 2 {
		t.Fatalf("ended %d", n)
	}
	if r := e.refresh(f, tok.RefreshToken); r.Status == 200 {
		t.Fatal("a sign-in older than the password still refreshes")
	}
	if resp := b.authorize(newFlow(f.clientID, f.secret)); !strings.Contains(body(resp), `action="/oidc/login"`) {
		t.Fatal("the browser session outlived the password")
	}
	// What's newer than the password stays.
	f2 := newFlow(f.clientID, f.secret)
	f2.scopes = "openid offline_access"
	e.clock.add(time.Minute)
	t2 := e.exchange(f2, e.browser().login(f2, "alice", "pw").Get("code"))
	e.p.PasswordSet(context.Background(), u.ID, e.clock.now().Add(-30*time.Second))
	if r := e.refresh(f2, t2.RefreshToken); r.Status != 200 {
		t.Fatal("a sign-in newer than the password ended")
	}
}

func TestSignOutEndsManagedClientsGrants(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	ctx := context.Background()
	id, secret, err := e.p.Clients.Ensure(ctx, "remote-gateway", "Gateway", []string{rpCallback}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := newFlow(id, secret)
	tok := e.exchange(f, e.browser().login(f, "alice", "pw").Get("code"))
	jti := jwtID(t, tok.AccessToken)
	if !e.p.GrantActive(ctx, jti) {
		t.Fatal("grant not active")
	}
	u, _ := e.users.GetByName(ctx, `HOME\alice`)
	e.p.endManagedGrants(ctx, u.ID)
	if e.p.GrantActive(ctx, jti) {
		t.Fatal("grant outlived signing out")
	}
}

func jwtID(t *testing.T, raw string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", raw)
	}
	b, _ := decodeSeg(parts[1])
	var c struct {
		JTI string `json:"jti"`
	}
	_ = json.Unmarshal(b, &c)
	return c.JTI
}

func TestPendingSignInsAreBounded(t *testing.T) {
	e := newEnv(t)
	_, f := confidentialClient(e, ClientSpec{})
	hc := e.srv.Client()
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for range maxPendingPerIP + 5 {
		resp, err := hc.Get(e.issuer() + "/authorize?" + authorizeQuery(newFlow(f.clientID, f.secret)).Encode())
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	var n int
	_ = e.db.QueryRow(`SELECT COUNT(*) FROM oidc_auth_requests`).Scan(&n)
	if n != maxPendingPerIP {
		t.Fatalf("%d sign-ins in progress from one address", n)
	}
	// Another address may still start one.
	r, _ := http.NewRequest(http.MethodGet, e.issuer()+"/authorize", nil)
	r.RemoteAddr = "192.0.2.99:1234"
	ctx := context.WithValue(context.Background(), requestKey, r)
	if !e.p.admitAuthRequest(ctx) {
		t.Fatal("another address refused")
	}
}

func TestManagedClientsTakeManyOrNoRedirectURIs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var many []string
	for i := range 30 {
		many = append(many, "https://app"+url.PathEscape(string(rune('a'+i%26)))+itoa(i)+".home.example.net/__hardyos/callback")
	}
	if _, _, err := e.p.Clients.Ensure(ctx, "remote-gateway", "Gateway", many, nil); err != nil {
		t.Fatalf("30 redirect URIs for a managed client: %v", err)
	}
	if _, _, err := e.p.Clients.Ensure(ctx, "remote-gateway", "Gateway", nil, nil); err != nil {
		t.Fatalf("no redirect URIs for a managed client: %v", err)
	}
	c, _ := e.p.Clients.Managed(ctx, "remote-gateway")
	if len(c.RedirectURIs) != 0 {
		t.Fatalf("stale redirect URIs kept: %v", c.RedirectURIs)
	}
	if _, _, err := e.p.Clients.Create(ctx, ClientSpec{Name: "x", RedirectURIs: many}); err == nil {
		t.Fatal("an administrator's client took 30 redirect URIs")
	}
	if _, _, err := e.p.Clients.Create(ctx, ClientSpec{Name: "x"}); err == nil {
		t.Fatal("an administrator's client without redirect URIs")
	}
}

func itoa(i int) string {
	return strings.TrimLeft(strings.Repeat("0", 1)+string(rune('0'+i/10))+string(rune('0'+i%10)), "0")
}
