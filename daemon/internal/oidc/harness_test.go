package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// ---- a domain in memory -------------------------------------------------------

const testDomainSID = "S-1-5-21-1111-2222-3333"

type fakeDomain struct {
	mu       sync.Mutex
	accounts map[string]*auth.DomainAccount
	pw       map[string]string
}

func newFakeDomain() *fakeDomain {
	return &fakeDomain{accounts: map[string]*auth.DomainAccount{}, pw: map[string]string{}}
}

func (f *fakeDomain) add(name, pw, guid string, groups ...string) *auth.DomainAccount {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := &auth.DomainAccount{Exists: true, Username: name, DisplayName: strings.ToUpper(name[:1]) + name[1:], Enabled: true,
		DomainSID: testDomainSID, ObjectGUID: guid, SID: testDomainSID + "-" + fmt.Sprint(1100+len(f.accounts))}
	for i, g := range append([]string{"Domain Users"}, groups...) {
		sid := fmt.Sprintf("%s-%d", testDomainSID, 3000+i)
		switch g {
		case "Domain Users":
			sid = testDomainSID + "-513"
		case "Domain Admins":
			sid = testDomainSID + "-512"
		}
		a.Groups = append(a.Groups, g)
		a.GroupSIDs = append(a.GroupSIDs, sid)
	}
	f.accounts[strings.ToLower(name)] = a
	f.pw[strings.ToLower(name)] = pw
	return a
}

func (f *fakeDomain) Info(context.Context) (*auth.DomainInfo, error) {
	return &auth.DomainInfo{Realm: "HOME.EXAMPLE.NET", NetBIOS: "HOME", DNS: "home.example.net", LocalKDC: "192.0.2.20"}, nil
}

func (f *fakeDomain) Account(_ context.Context, name string) (*auth.DomainAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.accounts[strings.ToLower(name)]
	if !ok {
		return &auth.DomainAccount{}, nil
	}
	c := *a
	return &c, nil
}

func (f *fakeDomain) CheckPassword(_ context.Context, _ auth.DomainInfo, name, pw string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	want, ok := f.pw[strings.ToLower(name)]
	if !ok || want != pw {
		return auth.ErrBadCredentials
	}
	if a := f.accounts[strings.ToLower(name)]; !a.Enabled {
		return auth.ErrAccountRevoked
	}
	return nil
}

// ---- the provider under test ----------------------------------------------------

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t      *testing.T
	db     *store.DB
	users  *auth.Users
	domain *fakeDomain
	p      *Provider
	srv    *httptest.Server
	clock  *clock
	audits []string
	amu    sync.Mutex
	// public makes every request count as from the internet.
	public atomic.Bool
	// ended are the users whose desktop sessions EndSessions ended.
	ended []int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &env{t: t, db: db, users: &auth.Users{DB: db}, domain: newFakeDomain(), clock: &clock{t: time.Now()}}
	signin := &auth.SignIn{Users: e.users, Domain: e.domain, Kerberos: e.domain}
	p, err := New(Config{
		DB: db, Users: e.users, SignIn: signin, Secrets: secretbox.NewStaticSource(), Now: e.clock.now,
		LoadUser: func(ctx context.Context, id int64) (*auth.User, error) {
			u, err := e.users.Get(ctx, id)
			if err != nil || u.Disabled {
				return nil, errors.New("account unavailable")
			}
			if u.Source == auth.SourceDomain {
				return signin.Refresh(ctx, u)
			}
			return u, nil
		},
		Audit: func(_ context.Context, _ string, u *auth.User, action, target string, outcome audit.Outcome, detail string) {
			e.amu.Lock()
			e.audits = append(e.audits, fmt.Sprintf("%s %s %s", action, outcome, detail))
			e.amu.Unlock()
		},
		LoginError: func(err error) (string, int, bool, bool) {
			switch {
			case errors.Is(err, auth.ErrBadCredentials):
				return "bad_credentials", 401, true, true
			case errors.Is(err, auth.ErrDisabledHere), errors.Is(err, auth.ErrAccountDisabled):
				return "account_disabled", 401, false, true
			}
			return "", 0, false, false
		},
		PublicOrigin: func(*http.Request) bool { return e.public.Load() },
		EndSessions: func(_ context.Context, id int64) {
			e.amu.Lock()
			e.ended = append(e.ended, id)
			e.amu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.p = p
	signin.Anchor = p // as hardyd wires it
	e.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Owns(r) {
			p.ServeHTTP(w, r)
			return
		}
		http.Error(w, "desktop", http.StatusTeapot)
	}))
	t.Cleanup(e.srv.Close)
	if err := p.SetIssuer(ctx, e.srv.URL+"/oidc"); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) issuer() string { return e.srv.URL + "/oidc" }

func decodeSeg(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func (e *env) sawAudit(prefix string) bool {
	e.amu.Lock()
	defer e.amu.Unlock()
	for _, a := range e.audits {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

func (e *env) client(spec ClientSpec) (*Client, string) {
	e.t.Helper()
	c, secret, err := e.p.Clients.Create(context.Background(), spec)
	if err != nil {
		e.t.Fatal(err)
	}
	return c, secret
}

const rpCallback = "https://rp.example.net/callback"

// ---- a relying party --------------------------------------------------------------

// browser is a person's browser: its own cookies, stopping at the app's
// callback.
type browser struct {
	e  *env
	hc *http.Client
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	hc := e.srv.Client()
	c := *hc
	c.Jar = jar
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Host != strings.TrimPrefix(e.srv.URL, "https://") {
			return http.ErrUseLastResponse
		}
		return nil
	}
	return &browser{e: e, hc: &c}
}

type flow struct {
	clientID, secret, redirect string
	scopes                     string
	verifier                   string
	noPKCE                     bool
	state, nonce               string
	extra                      url.Values
}

func (f *flow) challenge() string {
	sum := sha256.Sum256([]byte(f.verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newFlow(clientID, secret string) *flow {
	return &flow{clientID: clientID, secret: secret, redirect: rpCallback, scopes: "openid profile email groups",
		verifier: "verifier-0123456789-0123456789-0123456789-abcdef", state: "st-" + fmt.Sprint(time.Now().UnixNano()), nonce: "n-123"}
}

func (b *browser) get(u string) *http.Response {
	b.e.t.Helper()
	resp, err := b.hc.Get(u)
	if err != nil {
		b.e.t.Fatal(err)
	}
	return resp
}

func body(r *http.Response) string {
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	return string(b)
}

// authorize starts a sign-in and returns the first response that isn't a
// redirect inside the provider.
func (b *browser) authorize(f *flow) *http.Response {
	return b.get(b.e.issuer() + "/authorize?" + authorizeQuery(f).Encode())
}

func authorizeQuery(f *flow) url.Values {
	q := url.Values{"client_id": {f.clientID}, "redirect_uri": {f.redirect}, "response_type": {"code"},
		"scope": {f.scopes}, "state": {f.state}, "nonce": {f.nonce}}
	if !f.noPKCE {
		q.Set("code_challenge", f.challenge())
		q.Set("code_challenge_method", "S256")
	}
	for k, v := range f.extra {
		q[k] = v
	}
	return q
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

var (
	inputRE   = regexp.MustCompile(`name="(id|csrf|next|sub|exp|sig)" value="([^"]*)"`)
	refreshRE = regexp.MustCompile(`http-equiv="refresh" content="0;url=([^"]+)"`)
)

func formValues(page string) url.Values {
	v := url.Values{}
	for _, m := range inputRE.FindAllStringSubmatch(page, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	return v
}

func (b *browser) post(path string, form url.Values) *http.Response {
	b.e.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, b.e.issuer()+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.e.srv.URL)
	resp, err := b.hc.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	return resp
}

// signIn posts the login form of page; it returns the page that follows.
func (b *browser) signIn(page, user, pw string) (*http.Response, string) {
	f := formValues(page)
	f.Set("username", user)
	f.Set("password", pw)
	resp := b.post("/login", f)
	return resp, body(resp)
}

// follow takes a meta refresh page on to its target.
func (b *browser) follow(page string) *http.Response {
	b.e.t.Helper()
	m := refreshRE.FindStringSubmatch(page)
	if m == nil {
		b.e.t.Fatalf("no refresh in page:\n%s", page)
	}
	target := html.UnescapeString(m[1])
	if strings.HasPrefix(target, "/") {
		target = b.e.srv.URL + target
	}
	if !strings.HasPrefix(target, b.e.srv.URL+"/") {
		// Straight to the app: what the browser would do.
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {target}}, Body: http.NoBody}
	}
	return b.get(target)
}

// callback reads the app's callback from a redirect.
func (e *env) callback(resp *http.Response) url.Values {
	e.t.Helper()
	if resp.StatusCode != http.StatusFound {
		e.t.Fatalf("expected a redirect to the app, got %d: %s", resp.StatusCode, body(resp))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(loc.String(), rpCallback) {
		e.t.Fatalf("redirect to %q, not the app", resp.Header.Get("Location"))
	}
	return loc.Query()
}

// login runs a whole sign-in with a password and returns the callback.
func (b *browser) login(f *flow, user, pw string) url.Values {
	b.e.t.Helper()
	resp := b.authorize(f)
	page := body(resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, `action="/oidc/login"`) {
		b.e.t.Fatalf("expected the sign-in page, got %d: %s", resp.StatusCode, page)
	}
	resp, page = b.signIn(page, user, pw)
	if resp.StatusCode != http.StatusOK {
		b.e.t.Fatalf("sign-in: %d %s", resp.StatusCode, page)
	}
	return b.e.callback(b.follow(page))
}

type tokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
	Status       int    `json:"-"`
}

func (e *env) token(f *flow, form url.Values) tokens {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.issuer()+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if f.secret != "" {
		req.SetBasicAuth(url.QueryEscape(f.clientID), url.QueryEscape(f.secret))
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	var t tokens
	_ = json.NewDecoder(resp.Body).Decode(&t)
	resp.Body.Close()
	t.Status = resp.StatusCode
	return t
}

func (e *env) exchange(f *flow, code string) tokens {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.redirect}}
	if !f.noPKCE {
		form.Set("code_verifier", f.verifier)
	}
	if f.secret == "" {
		form.Set("client_id", f.clientID)
	}
	return e.token(f, form)
}

func (e *env) refresh(f *flow, rt string) tokens {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
	if f.secret == "" {
		form.Set("client_id", f.clientID)
	}
	return e.token(f, form)
}

// verify checks an ID token's signature against the JWKS and returns its claims.
func (e *env) verify(raw string) map[string]any {
	e.t.Helper()
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		e.t.Fatal(err)
	}
	set := e.jwks()
	kid := jws.Signatures[0].Header.KeyID
	keys := set.Key(kid)
	if len(keys) == 0 {
		e.t.Fatalf("kid %s not in the JWKS", kid)
	}
	payload, err := jws.Verify(keys[0])
	if err != nil {
		e.t.Fatal(err)
	}
	var claims map[string]any
	_ = json.Unmarshal(payload, &claims)
	return claims
}

func (e *env) jwks() jose.JSONWebKeySet {
	e.t.Helper()
	resp, err := e.srv.Client().Get(e.issuer() + "/keys")
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		e.t.Fatal(err)
	}
	return set
}

func (e *env) userinfo(at string) (int, map[string]any) {
	e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.issuer()+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func (e *env) revoke(f *flow, token, hint string) int {
	e.t.Helper()
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	if f.secret == "" {
		form.Set("client_id", f.clientID)
	}
	req, _ := http.NewRequest(http.MethodPost, e.issuer()+"/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if f.secret != "" {
		req.SetBasicAuth(url.QueryEscape(f.clientID), url.QueryEscape(f.secret))
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}
