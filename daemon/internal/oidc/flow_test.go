package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
)

const aliceGUID = "6f9619ff-8b86-d011-b42d-00c04fc964ff"

func publicClient(e *env) (*Client, *flow) {
	c, _ := e.client(ClientSpec{Name: "Dashboard", Kind: KindPublic, RedirectURIs: []string{rpCallback}, FirstParty: true})
	return c, newFlow(c.ID, "")
}

func confidentialClient(e *env, spec ClientSpec) (*Client, *flow) {
	spec.Kind = KindConfidential
	spec.FirstParty = spec.Preset != "third-party"
	if spec.Name == "" {
		spec.Name = "NetBird"
	}
	if spec.RedirectURIs == nil {
		spec.RedirectURIs = []string{rpCallback}
	}
	c, secret := e.client(spec)
	if secret == "" {
		e.t.Fatal("a confidential client gets a secret")
	}
	return c, newFlow(c.ID, secret)
}

func TestDiscovery(t *testing.T) {
	e := newEnv(t)
	resp, err := e.srv.Client().Get(e.issuer() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&d)
	resp.Body.Close()
	if d["issuer"] != e.issuer() {
		t.Fatalf("issuer %v", d["issuer"])
	}
	for k, want := range map[string]string{
		"authorization_endpoint": e.issuer() + "/authorize", "token_endpoint": e.issuer() + "/oauth/token",
		"jwks_uri": e.issuer() + "/keys", "userinfo_endpoint": e.issuer() + "/userinfo",
		"revocation_endpoint": e.issuer() + "/revoke", "end_session_endpoint": e.issuer() + "/end_session",
	} {
		if d[k] != want {
			t.Errorf("%s = %v, want %s", k, d[k], want)
		}
	}
	if m, _ := d["code_challenge_methods_supported"].([]any); !slices.Contains(m, any("S256")) {
		t.Errorf("S256 not advertised: %v", d["code_challenge_methods_supported"])
	}
	set := e.jwks()
	if len(set.Keys) != 2 {
		t.Fatalf("JWKS has %d keys, want the active and the next one", len(set.Keys))
	}
}

func TestCodeFlowPKCEPublicClient(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw-alice", aliceGUID, "Family", "Domain Admins")
	_, f := publicClient(e)
	b := e.browser()
	cb := b.login(f, `HOME\alice`, "pw-alice")
	if cb.Get("state") != f.state || cb.Get("code") == "" {
		t.Fatalf("callback %v", cb)
	}
	tok := e.exchange(f, cb.Get("code"))
	if tok.Status != 200 || tok.IDToken == "" || tok.AccessToken == "" {
		t.Fatalf("token: %+v", tok)
	}
	if tok.RefreshToken != "" {
		t.Fatal("no refresh token without offline_access")
	}
	c := e.verify(tok.IDToken)
	if c["iss"] != e.issuer() || c["sub"] != aliceGUID || c["nonce"] != f.nonce || c["aud"] != f.clientID && !audHas(c["aud"], f.clientID) {
		t.Fatalf("claims %v", c)
	}
	if c["preferred_username"] != "alice" || c["name"] != "Alice" || c["hardyos_admin"] != true {
		t.Fatalf("profile claims %v", c)
	}
	groups, _ := c["groups"].([]any)
	if !slices.Contains(groups, any(`HOME\Family`)) || !slices.Contains(groups, any(`HOME\Domain Users`)) {
		t.Fatalf("groups %v", c["groups"])
	}
	// No email in the directory: the UPN, unverified.
	if c["email"] != "alice@home.example.net" || c["email_verified"] != false {
		t.Fatalf("email %v %v", c["email"], c["email_verified"])
	}
	// The access token is a JWT for the client with the groups.
	at := e.verify(tok.AccessToken)
	if !audHas(at["aud"], f.clientID) || at["sub"] != aliceGUID || at["groups"] == nil {
		t.Fatalf("access token claims %v", at)
	}
	st, info := e.userinfo(tok.AccessToken)
	if st != 200 || info["sub"] != aliceGUID || info["preferred_username"] != "alice" {
		t.Fatalf("userinfo %d %v", st, info)
	}
	if !e.sawAudit("oidc.signin success") {
		t.Fatalf("sign-in not audited: %v", e.audits)
	}

	// Signed in already: the next sign-in goes straight back.
	f2 := newFlow(f.clientID, "")
	cb2 := e.callback(b.authorize(f2))
	if cb2.Get("code") == "" {
		t.Fatal("no code for an existing session")
	}
	// A wrong verifier is refused.
	f2.verifier = "another-verifier-0123456789-0123456789-0123456789"
	if tok := e.exchange(f2, cb2.Get("code")); tok.Status != 400 || tok.Error != "invalid_grant" {
		t.Fatalf("wrong verifier: %+v", tok)
	}
}

func audHas(aud any, id string) bool {
	switch a := aud.(type) {
	case string:
		return a == id
	case []any:
		return slices.Contains(a, any(id))
	}
	return false
}

func TestPublicClientNeedsPKCE(t *testing.T) {
	e := newEnv(t)
	_, f := publicClient(e)
	f.noPKCE = true
	cb := e.callback(e.browser().authorize(f))
	if cb.Get("error") != "invalid_request" || cb.Get("code") != "" {
		t.Fatalf("callback %v", cb)
	}
	// plain isn't accepted either.
	f.noPKCE = false
	f.extra = url.Values{"code_challenge_method": {"plain"}, "code_challenge": {f.verifier}}
	if cb := e.callback(e.browser().authorize(f)); cb.Get("error") != "invalid_request" {
		t.Fatalf("plain PKCE: %v", cb)
	}
}

func TestWrongRedirectURINeverRedirects(t *testing.T) {
	e := newEnv(t)
	_, f := confidentialClient(e, ClientSpec{})
	for _, bad := range []string{"https://evil.example/cb", rpCallback + "/", rpCallback + "?x=1", "https://RP.example.net/callback"} {
		f.redirect = bad
		resp := e.browser().authorize(f)
		b := body(resp)
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Fatalf("%s: %d %q %s", bad, resp.StatusCode, resp.Header.Get("Location"), b)
		}
	}
	// Unknown client too.
	f = newFlow("hos-nope", "")
	if resp := e.browser().authorize(f); resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("unknown client: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestRefreshRotationAndReuse(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	f.scopes = "openid profile offline_access"
	cb := e.browser().login(f, "alice", "pw")
	tok := e.exchange(f, cb.Get("code"))
	if tok.RefreshToken == "" {
		t.Fatalf("no refresh token: %+v", tok)
	}
	t2 := e.refresh(f, tok.RefreshToken)
	if t2.Status != 200 || t2.RefreshToken == "" || t2.RefreshToken == tok.RefreshToken || t2.IDToken == "" {
		t.Fatalf("refresh: %+v", t2)
	}
	if c := e.verify(t2.IDToken); c["sub"] != aliceGUID {
		t.Fatalf("refreshed claims %v", c)
	}
	// The old one is used up; presenting it again ends the whole sign-in.
	if t3 := e.refresh(f, tok.RefreshToken); t3.Status != 400 || t3.Error != "invalid_grant" {
		t.Fatalf("reused refresh token: %+v", t3)
	}
	if t4 := e.refresh(f, t2.RefreshToken); t4.Status != 400 {
		t.Fatalf("the newer token should be revoked too: %+v", t4)
	}
	if st, _ := e.userinfo(t2.AccessToken); st == 200 {
		t.Fatal("access token of a revoked sign-in still works")
	}
	if !e.sawAudit("oidc.token.reuse denied") {
		t.Fatalf("reuse not audited: %v", e.audits)
	}
	// Another client's secret can't refresh it.
	_, other := confidentialClient(e, ClientSpec{Name: "Other"})
	cb = e.browser().login(f, "alice", "pw")
	tok = e.exchange(f, cb.Get("code"))
	if t5 := e.refresh(other, tok.RefreshToken); t5.Status == 200 {
		t.Fatal("refreshed with another client")
	}
}

func TestRevocation(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	f.scopes = "openid offline_access"
	tok := e.exchange(f, e.browser().login(f, "alice", "pw").Get("code"))
	// The access token alone.
	if st := e.revoke(f, tok.AccessToken, "access_token"); st != 200 {
		t.Fatalf("revoke access token: %d", st)
	}
	if st, _ := e.userinfo(tok.AccessToken); st == 200 {
		t.Fatal("revoked access token still works")
	}
	if r := e.refresh(f, tok.RefreshToken); r.Status != 200 {
		t.Fatalf("refresh after revoking an access token: %+v", r)
	} else {
		tok = r
	}
	// The refresh token ends the grant.
	if st := e.revoke(f, tok.RefreshToken, ""); st != 200 {
		t.Fatalf("revoke refresh token: %d", st)
	}
	if r := e.refresh(f, tok.RefreshToken); r.Status == 200 {
		t.Fatal("revoked refresh token still works")
	}
	if st, _ := e.userinfo(tok.AccessToken); st == 200 {
		t.Fatal("access token of a revoked grant still works")
	}
	// Unknown tokens: 200 (RFC 7009).
	if st := e.revoke(f, "nonsense", ""); st != 200 {
		t.Fatalf("unknown token: %d", st)
	}
	if !e.sawAudit("oidc.token.revoke success") {
		t.Fatalf("revocation not audited: %v", e.audits)
	}
}

func TestReplayedCodeRevokesTokens(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	f.scopes = "openid offline_access"
	code := e.browser().login(f, "alice", "pw").Get("code")
	tok := e.exchange(f, code)
	if tok.Status != 200 {
		t.Fatalf("first exchange: %+v", tok)
	}
	if again := e.exchange(f, code); again.Status != 400 || again.Error != "invalid_grant" {
		t.Fatalf("replayed code: %+v", again)
	}
	if st, _ := e.userinfo(tok.AccessToken); st == 200 {
		t.Fatal("tokens from a replayed code still work")
	}
	if r := e.refresh(f, tok.RefreshToken); r.Status == 200 {
		t.Fatal("refresh token from a replayed code still works")
	}
	if !e.sawAudit("oidc.code.replay denied") {
		t.Fatalf("replay not audited: %v", e.audits)
	}
}

func TestExpiredCode(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	code := e.browser().login(f, "alice", "pw").Get("code")
	e.clock.add(61 * time.Second)
	if tok := e.exchange(f, code); tok.Status != 400 || tok.Error != "invalid_grant" {
		t.Fatalf("expired code: %+v", tok)
	}
}

func TestExpiredSignInRequest(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	b := e.browser()
	page := body(b.authorize(f))
	e.clock.add(11 * time.Minute)
	resp, out := b.signIn(page, "alice", "pw")
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(out, "expired") {
		t.Fatalf("%d %s", resp.StatusCode, out)
	}
}

func TestConsentForThirdPartyClients(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{Name: "Photos", Preset: "third-party"})
	b := e.browser()
	page := body(b.authorize(f))
	resp, page := b.signIn(page, "alice", "pw")
	if resp.StatusCode != 200 || !strings.Contains(page, `action="/oidc/consent"`) || !strings.Contains(page, "Allow Photos?") {
		t.Fatalf("expected consent: %d %s", resp.StatusCode, page)
	}
	// Don't allow: the app hears access_denied.
	v := formValues(page)
	v.Set("decision", "deny")
	cb := e.callback(b.follow(body(b.post("/consent", v))))
	if cb.Get("error") != "access_denied" || cb.Get("state") != f.state {
		t.Fatalf("denied: %v", cb)
	}
	// Again, and allow.
	f2 := newFlow(f.clientID, f.secret)
	page = body(b.authorize(f2)) // signed in already: straight to consent
	if !strings.Contains(page, `action="/oidc/consent"`) {
		t.Fatalf("expected consent again: %s", page)
	}
	v = formValues(page)
	v.Set("decision", "allow")
	cb = e.callback(b.follow(body(b.post("/consent", v))))
	if tok := e.exchange(f2, cb.Get("code")); tok.Status != 200 {
		t.Fatalf("after consent: %+v", tok)
	}
	// Remembered: no screen the third time; prompt=consent asks anyway.
	f3 := newFlow(f.clientID, f.secret)
	if cb := e.callback(b.authorize(f3)); cb.Get("code") == "" {
		t.Fatalf("consent not remembered: %v", cb)
	}
	f4 := newFlow(f.clientID, f.secret)
	f4.extra = url.Values{"prompt": {"consent"}}
	if page := body(b.authorize(f4)); !strings.Contains(page, `action="/oidc/consent"`) {
		t.Fatal("prompt=consent didn't ask")
	}
	// More scopes than allowed: asked again.
	f5 := newFlow(f.clientID, f.secret)
	f5.scopes += " offline_access"
	if page := body(b.authorize(f5)); !strings.Contains(page, `action="/oidc/consent"`) {
		t.Fatal("new scopes didn't ask")
	}
	if !e.sawAudit("oidc.consent success") || !e.sawAudit("oidc.consent denied") {
		t.Fatalf("consent not audited: %v", e.audits)
	}
}

func TestAllowedGroups(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID, "Family")
	e.domain.add("bob", "pw", "11111111-2222-3333-4444-555555555555")
	_, f := confidentialClient(e, ClientSpec{AllowedGroups: []string{`home\family`}})
	if cb := e.browser().login(f, "alice", "pw"); cb.Get("code") == "" {
		t.Fatal("a member was refused")
	}
	b := e.browser()
	resp, page := b.signIn(body(b.authorize(f)), "bob", "pw")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(page, "isn&#39;t in a group allowed") {
		t.Fatalf("non-member: %d %s", resp.StatusCode, page)
	}
	if !e.sawAudit("oidc.signin denied") {
		t.Fatalf("not audited: %v", e.audits)
	}
}

func TestDisabledAccount(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	f.scopes = "openid offline_access"
	tok := e.exchange(f, e.browser().login(f, "alice", "pw").Get("code"))
	u, err := e.users.GetByName(context.Background(), `HOME\alice`)
	if err != nil {
		t.Fatal(err)
	}
	off := true
	if _, err := e.users.Update(context.Background(), u.ID, auth.UserUpdate{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	if r := e.refresh(f, tok.RefreshToken); r.Status == 200 {
		t.Fatal("a turned-off account refreshed")
	}
	if st, _ := e.userinfo(tok.AccessToken); st == 200 {
		t.Fatal("a turned-off account's token works")
	}
	b := e.browser()
	resp, page := b.signIn(body(b.authorize(newFlow(f.clientID, f.secret))), "alice", "pw")
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(page, "turned off in HardyOS") {
		t.Fatalf("disabled sign-in: %d %s", resp.StatusCode, page)
	}
	// Turned off in the domain.
	e.domain.add("carol", "pw", "22222222-2222-3333-4444-555555555555").Enabled = false
	resp, page = b.signIn(body(b.authorize(newFlow(f.clientID, f.secret))), "carol", "pw")
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(page, "turned off") {
		t.Fatalf("domain-disabled sign-in: %d %s", resp.StatusCode, page)
	}
}

func TestLocalAccountsOffByDefault(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.users.Create(ctx, auth.NewUser{Username: "admin", Password: "correct horse battery", Role: auth.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	_, f := confidentialClient(e, ClientSpec{})
	b := e.browser()
	resp, page := b.signIn(body(b.authorize(f)), "admin", "correct horse battery")
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(page, "Incorrect username or password") {
		t.Fatalf("local account with the setting off: %d %s", resp.StatusCode, page)
	}
	if err := e.p.SetLocalAccounts(ctx, true); err != nil {
		t.Fatal(err)
	}
	cb := b.login(newFlow(f.clientID, f.secret), "admin", "correct horse battery")
	tok := e.exchange(f, cb.Get("code"))
	c := e.verify(tok.IDToken)
	if sub, _ := c["sub"].(string); !strings.HasPrefix(sub, "local-") || c["hardyos_admin"] != true {
		t.Fatalf("local claims %v", c)
	}
	// Off again: the session and the tokens stop working.
	_ = e.p.SetLocalAccounts(ctx, false)
	if st, _ := e.userinfo(tok.AccessToken); st == 200 {
		t.Fatal("local account token works with the setting off")
	}
	if cb := b.authorize(newFlow(f.clientID, f.secret)); cb.StatusCode == http.StatusFound {
		t.Fatal("local session reused with the setting off")
	}
}

func TestPromptNoneAndLogin(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	f.extra = url.Values{"prompt": {"none"}}
	b := e.browser()
	if cb := e.callback(b.authorize(f)); cb.Get("error") != "login_required" {
		t.Fatalf("prompt=none without a session: %v", cb)
	}
	b.login(newFlow(f.clientID, f.secret), "alice", "pw")
	f2 := newFlow(f.clientID, f.secret)
	f2.extra = url.Values{"prompt": {"none"}}
	if cb := e.callback(b.authorize(f2)); cb.Get("code") == "" {
		t.Fatalf("prompt=none with a session: %v", cb)
	}
	f3 := newFlow(f.clientID, f.secret)
	f3.extra = url.Values{"prompt": {"login"}}
	if resp := b.authorize(f3); resp.StatusCode != 200 {
		t.Fatalf("prompt=login didn't ask for the password: %d", resp.StatusCode)
	}
	f4 := newFlow(f.clientID, f.secret)
	f4.extra = url.Values{"max_age": {"30"}}
	e.clock.add(time.Minute)
	if resp := b.authorize(f4); resp.StatusCode != 200 {
		t.Fatalf("max_age didn't ask for the password: %d", resp.StatusCode)
	}
}

func TestFormsNeedTheirBrowserAndToken(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	b := e.browser()
	page := body(b.authorize(f))
	v := formValues(page)
	// Another browser can't open or post it.
	other := e.browser()
	if resp := other.get(e.issuer() + "/login?id=" + url.QueryEscape(v.Get("id"))); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("another browser opened it: %d", resp.StatusCode)
	}
	v.Set("username", "alice")
	v.Set("password", "pw")
	if resp := other.post("/login", v); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("another browser posted it: %d", resp.StatusCode)
	}
	// Without the token, or from another site.
	bad := url.Values{"id": {v.Get("id")}, "username": {"alice"}, "password": {"pw"}, "csrf": {"x"}}
	if resp := b.post("/login", bad); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("bad token: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPost, e.issuer()+"/login", strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	if resp, _ := b.hc.Do(req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site post: %d", resp.StatusCode)
	}
	// Pages are script-free and can't be framed.
	resp := b.get(e.issuer() + "/login?id=" + url.QueryEscape(v.Get("id")))
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "script-src") {
		t.Fatalf("CSP %q", csp)
	}
}

func TestCodeOnlyForItsBrowser(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	b := e.browser()
	_, page := b.signIn(body(b.authorize(f)), "alice", "pw")
	m := refreshRE.FindStringSubmatch(page)
	if m == nil {
		t.Fatal(page)
	}
	cb := e.srv.URL + strings.ReplaceAll(m[1], "&amp;", "&")
	if resp := e.browser().get(cb); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("another browser collected the code: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if q := e.callback(b.get(cb)); q.Get("code") == "" {
		t.Fatal("its own browser didn't get the code")
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	b := e.browser()
	page := body(b.authorize(f))
	var resp *http.Response
	for range 6 {
		resp, page = b.signIn(page, "alice", "wrong")
	}
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(page, "Too many failed sign-ins") {
		t.Fatalf("%d %s", resp.StatusCode, page)
	}
	if resp, _ = b.signIn(page, `alice@home.example.net`, "pw"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatal("another spelling got past the lockout")
	}
}

func TestEndSession(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{PostLogoutRedirectURIs: []string{"https://rp.example.net/bye"}})
	f.scopes = "openid offline_access"
	b := e.browser()
	tok := e.exchange(f, b.login(f, "alice", "pw").Get("code"))
	q := url.Values{"id_token_hint": {tok.IDToken}, "post_logout_redirect_uri": {"https://rp.example.net/bye"}, "state": {"s1"}}
	resp := b.get(e.issuer() + "/end_session?" + q.Encode()) // -> /logout -> the app
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "https://rp.example.net/bye?state=s1") {
		t.Fatalf("end session: %d %q %s", resp.StatusCode, resp.Header.Get("Location"), body(resp))
	}
	if r := e.refresh(f, tok.RefreshToken); r.Status == 200 {
		t.Fatal("tokens survive the sign-out")
	}
	// The browser's session ended: the next sign-in asks again.
	if resp := b.authorize(newFlow(f.clientID, f.secret)); resp.StatusCode != 200 {
		t.Fatalf("still signed in: %d", resp.StatusCode)
	}
	// Not a registered address: refused, not followed.
	q.Set("post_logout_redirect_uri", "https://evil.example/")
	if resp := b.get(e.issuer() + "/end_session?" + q.Encode()); resp.StatusCode == http.StatusFound {
		t.Fatalf("redirected to an unregistered address: %q", resp.Header.Get("Location"))
	}
	// The sign-out page can't be pointed elsewhere.
	if resp := b.get(e.issuer() + "/logout?next=https://evil.example/&sub=&exp=9999999999&sig=x"); resp.StatusCode == http.StatusFound {
		t.Fatal("forged sign-out link followed")
	}
}

func TestKeyRotation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	first := e.exchange(f, e.browser().login(f, "alice", "pw").Get("code"))
	before := e.jwks()
	if err := e.p.CheckKeys(ctx, true); err != nil {
		t.Fatal(err)
	}
	after := e.jwks()
	// The old key is still published, so the earlier token still verifies.
	e.verify(first.IDToken)
	second := e.exchange(f, e.browser().login(newFlow(f.clientID, f.secret), "alice", "pw").Get("code"))
	k1 := kidOf(t, first.IDToken)
	k2 := kidOf(t, second.IDToken)
	if k1 == k2 {
		t.Fatal("the same key signs after a rotation")
	}
	// The new signing key was published before (it was the next key).
	if len(before.Key(k2)) == 0 {
		t.Fatal("the new key wasn't published ahead")
	}
	if len(after.Keys) != 3 {
		t.Fatalf("after rotation: %d keys, want retired + active + next", len(after.Keys))
	}
	// Two days later the retired key is gone.
	e.clock.add(49 * time.Hour)
	e.p.keys.invalidate()
	if err := e.p.CheckKeys(ctx, false); err != nil {
		t.Fatal(err)
	}
	if set := e.jwks(); len(set.Key(k1)) != 0 {
		t.Fatal("retired key still published")
	}
	// The schedule: 30 days after it started signing, the next key takes over.
	e.clock.add(31 * 24 * time.Hour)
	if err := e.p.CheckKeys(ctx, false); err != nil {
		t.Fatal(err)
	}
	third := e.exchange(f, e.browser().login(newFlow(f.clientID, f.secret), "alice", "pw").Get("code"))
	if kidOf(t, third.IDToken) == k2 {
		t.Fatal("no rotation after 30 days")
	}
	if !e.sawAudit("oidc.keys.rotate success") {
		t.Fatalf("rotation not audited: %v", e.audits)
	}
}

func kidOf(t *testing.T, raw string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	var h struct {
		Kid string `json:"kid"`
	}
	b, _ := decodeSeg(parts[0])
	_ = json.Unmarshal(b, &h)
	return h.Kid
}

func TestKeysSealedAndReplacedWithoutTheServerKey(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.p.CheckKeys(ctx, false); err != nil {
		t.Fatal(err)
	}
	// What's stored doesn't hold the private key in the clear.
	var seal []byte
	if err := e.db.QueryRowContext(ctx, `SELECT private_seal FROM oidc_keys WHERE state = 'active'`).Scan(&seal); err != nil {
		t.Fatal(err)
	}
	if seal[0] != 1 || len(seal) < 1000 || strings.Contains(string(seal), "PRIVATE") {
		t.Fatal("private key not sealed")
	}
	old := e.jwks()
	// A restore onto a server with another master key (a backup without keys).
	e.p.keys.secrets = secretbox.NewStaticSource()
	e.p.keys.invalidate()
	if err := e.p.CheckKeys(ctx, false); err != nil {
		t.Fatal(err)
	}
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	tok := e.exchange(f, e.browser().login(f, "alice", "pw").Get("code"))
	if tok.Status != 200 {
		t.Fatalf("signing after replacement: %+v", tok)
	}
	if len(old.Key(kidOf(t, tok.IDToken))) != 0 {
		t.Fatal("still signing with an old key")
	}
	e.verify(tok.IDToken)
	if !e.sawAudit("oidc.keys.replace success") {
		t.Fatalf("replacement not audited: %v", e.audits)
	}
}

func TestSubjectFollowsTheDomainAccount(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	f.scopes = "openid offline_access"
	tok := e.exchange(f, e.browser().login(f, "alice", "pw").Get("code"))
	// alice is deleted and someone else gets the name: a new subject, and the
	// old person's tokens stop.
	e.domain.add("alice", "pw2", "99999999-8888-7777-6666-555555555555")
	f2 := newFlow(f.clientID, f.secret)
	t2 := e.exchange(f2, e.browser().login(f2, "alice", "pw2").Get("code"))
	if c := e.verify(t2.IDToken); c["sub"] != "99999999-8888-7777-6666-555555555555" {
		t.Fatalf("sub %v", c["sub"])
	}
	if r := e.refresh(f, tok.RefreshToken); r.Status == 200 {
		t.Fatal("the old person's refresh token still works")
	}
}

func TestSSOHostAndIssuer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_ = e.p.SetIssuer(ctx, "")
	_ = e.db.SetSetting(ctx, SettingRemoteBase, "home.hardynetworks.net")
	e.p.dropSettings()
	if got := e.p.Issuer(ctx); got != "https://sso.home.hardynetworks.net" {
		t.Fatalf("issuer %s", got)
	}
	r, _ := http.NewRequest(http.MethodGet, "https://sso.home.hardynetworks.net/api/v1/users", nil)
	if !e.p.Owns(r) {
		t.Fatal("the sso host should be all the provider's")
	}
	r, _ = http.NewRequest(http.MethodGet, "https://nas.home.hardynetworks.net/oidc/authorize", nil)
	if e.p.Owns(r) {
		t.Fatal("the desktop's host isn't the provider's when it has its own")
	}
	for _, bad := range []string{"http://x.example", "https://x.example/other", "https://x.example/?a=1", "x.example"} {
		if err := e.p.SetIssuer(ctx, bad); err == nil {
			t.Errorf("issuer %q accepted", bad)
		}
	}
}

func TestEnsure(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	id, secret, err := e.p.Clients.Ensure(ctx, "remote:public-apps", "Public apps", []string{"https://a.example/cb"}, []string{`HOME\Family`})
	if err != nil || id == "" || secret == "" {
		t.Fatalf("ensure: %q %q %v", id, secret, err)
	}
	id2, secret2, err := e.p.Clients.Ensure(ctx, "remote:public-apps", "Public apps", []string{"https://a.example/cb", "https://b.example/cb"}, nil)
	if err != nil || id2 != id || secret2 != "" {
		t.Fatalf("second ensure: %q %q %v", id2, secret2, err)
	}
	c, _ := e.p.Clients.Get(ctx, id)
	if len(c.RedirectURIs) != 2 || len(c.AllowedGroups) != 0 || !c.FirstParty || c.ManagedBy != "remote:public-apps" || !c.checkSecret(secret) {
		t.Fatalf("ensured client %+v", c)
	}
	if err := e.p.Clients.Delete(ctx, id); err != ErrManaged {
		t.Fatalf("delete of a managed client: %v", err)
	}
	if _, _, err := e.p.Clients.Update(ctx, id, ClientSpec{Name: "x", RedirectURIs: []string{"https://x.example"}}); err != ErrManaged {
		t.Fatalf("update of a managed client: %v", err)
	}
	if err := e.p.Clients.Forget(ctx, "remote:public-apps"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.p.Clients.Get(ctx, id); err != ErrNotFound {
		t.Fatalf("after forget: %v", err)
	}
}

func TestClientValidation(t *testing.T) {
	e := newEnv(t)
	for _, spec := range []ClientSpec{
		{Name: "", RedirectURIs: []string{"https://a.example/cb"}},
		{Name: "x", RedirectURIs: nil},
		{Name: "x", RedirectURIs: []string{"http://a.example/cb"}},
		{Name: "x", RedirectURIs: []string{"https://a.example/cb#frag"}},
		{Name: "x", RedirectURIs: []string{"https://*.example/cb"}},
		{Name: "x", RedirectURIs: []string{"javascript:alert(1)"}},
		{Name: "x", RedirectURIs: []string{"http://localhost:53000"}, Kind: KindConfidential},
		{Name: "x", RedirectURIs: []string{"https://a.example/cb"}, AllowedGroups: []string{"Family"}},
	} {
		if _, _, err := e.p.Clients.Create(context.Background(), spec); err == nil {
			t.Errorf("accepted %+v", spec)
		}
	}
	if _, _, err := e.p.Clients.Create(context.Background(), ClientSpec{Name: "CLI", Kind: KindPublic, RedirectURIs: []string{"http://localhost:53000"}}); err != nil {
		t.Errorf("loopback for a public client: %v", err)
	}
	// Secrets: only a hash is kept.
	c, secret := e.client(ClientSpec{Name: "S", RedirectURIs: []string{rpCallback}})
	var stored string
	_ = e.db.QueryRowContext(context.Background(), `SELECT secret_hash FROM oidc_clients WHERE id = ?`, c.ID).Scan(&stored)
	if stored == secret || stored != hashHex(secret) {
		t.Fatal("secret stored in the clear")
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), stored) {
		t.Fatal("hash in the API view")
	}
}

func TestPresets(t *testing.T) {
	ps := Presets("https://vpn.hardynetworks.net/")
	nb, ok := PresetByID("https://vpn.hardynetworks.net", "netbird")
	if len(ps) != 2 || !ok || nb.Client.RedirectURIs[0] != "https://vpn.hardynetworks.net/oauth2/callback" {
		t.Fatalf("%+v", nb)
	}
	px, _ := PresetByID("https://vpn.hardynetworks.net", "netbird-proxy")
	if !slices.Contains(px.Client.RedirectURIs, "https://vpn.hardynetworks.net/api/reverse-proxy/callback") || px.Client.Kind != KindPublic {
		t.Fatalf("%+v", px.Client)
	}
	// Presets make valid clients.
	e := newEnv(t)
	for _, p := range ps {
		if _, _, err := e.p.Clients.Create(context.Background(), p.Client); err != nil {
			t.Errorf("preset %s: %v", p.ID, err)
		}
	}
	if Presets("javascript:x")[0].Client.RedirectURIs[0] != DefaultNetBirdURL+"/oauth2/callback" {
		t.Error("a bad NetBird address isn't replaced")
	}
}
