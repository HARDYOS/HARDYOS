package api

// Sign-in at the app gateway: each published app host is a redirect URI
// of one OIDC client of HardyOS's own sign-in provider (internal/oidc,
// kept with Clients.Ensure). A browser without a session on the app host
// goes through the provider at https://sso.<base> (public, so it works
// for people without NetBird, while the desktop stays NetBird-only) with
// the authorization code flow, PKCE and a nonce; the state is also in a
// __Host- cookie on the app host, so a code or state from another browser
// is useless (no login CSRF). The code is exchanged in-process (the
// provider runs in hardyd), and the ID token's subject gives the account,
// whose access to the app is then checked as at the desktop.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/oidc"
)

const (
	gatewayCallbackPath  = "/__hardyos/callback"
	gatewayClientKey     = "remote-gateway"
	settingGatewayClient = "remote.gateway_client" // sealed {"id","secret"}
	gatewaySignInTTL     = 10 * time.Minute
	// Sign-ins in progress at the gateway, per client address and in all.
	maxGatewayPendingPerIP = 20
	maxGatewayPending      = 5000
)

type gatewayClient struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

// ensureClient keeps the provider's client for the gateway with one
// redirect URI per app host that asks for a HardyOS sign-in, and none when
// no app does (stale addresses don't stay redirect URIs). Changes are
// audited as HardyOS's own.
func (rt *remoteRuntime) ensureClient(ctx context.Context, hosts []string) {
	s := rt.s
	if s.oidc == nil {
		return
	}
	uris := make([]string, 0, len(hosts))
	for _, h := range hosts {
		uris = append(uris, "https://"+h+gatewayCallbackPath)
	}
	slices.Sort(uris)
	rt.mu.Lock()
	same := rt.client != nil && slices.Equal(rt.clientURIs, uris)
	rt.mu.Unlock()
	if same {
		return
	}
	before, err := s.oidc.Clients.Managed(ctx, gatewayClientKey)
	if errors.Is(err, oidc.ErrNotFound) {
		if len(uris) == 0 {
			return // nothing to keep yet
		}
		before = nil
	} else if err != nil {
		s.log.Warn("app gateway sign-in client", "err", err)
		return
	}
	id, secret, err := s.oidc.Clients.Ensure(ctx, gatewayClientKey, "HardyOS app gateway", uris, nil)
	if err != nil {
		s.log.Warn("app gateway sign-in client", "err", err)
		return
	}
	switch {
	case before == nil:
		s.recordSystem(ctx, "oidc.client.create", "HardyOS app gateway ("+id+")", "kept by Remote Access; redirects "+strings.Join(uris, " "))
	default:
		old := slices.Clone(before.RedirectURIs)
		slices.Sort(old)
		if !slices.Equal(old, uris) {
			added, removed := diffLists(old, uris)
			s.recordSystem(ctx, "oidc.client.update", "HardyOS app gateway ("+id+")",
				"kept by Remote Access; redirects added: "+strings.Join(added, " ")+"; removed: "+strings.Join(removed, " "))
		}
	}
	store := s.cfg.Remote.Store
	if secret == "" {
		var saved gatewayClient
		if raw, err := store.SealedSetting(ctx, settingGatewayClient); err == nil && raw != "" {
			_ = json.Unmarshal([]byte(raw), &saved)
		}
		if saved.ID == id && saved.Secret != "" {
			secret = saved.Secret
		} else if id, secret, err = s.oidc.Clients.EnsuredSecret(ctx, gatewayClientKey); err != nil {
			s.log.Warn("app gateway sign-in client secret", "err", err)
			return
		}
	}
	b, _ := json.Marshal(gatewayClient{ID: id, Secret: secret})
	if err := store.SetSealedSetting(ctx, settingGatewayClient, string(b)); err != nil {
		s.log.Warn("saving the app gateway's client", "err", err)
		return
	}
	rt.mu.Lock()
	rt.client, rt.clientURIs = &gatewayClient{ID: id, Secret: secret}, uris
	rt.mu.Unlock()
}

// diffLists says what b has that a hasn't (added) and the other way round.
func diffLists(a, b []string) (added, removed []string) {
	for _, x := range b {
		if !slices.Contains(a, x) {
			added = append(added, x)
		}
	}
	for _, x := range a {
		if !slices.Contains(b, x) {
			removed = append(removed, x)
		}
	}
	return added, removed
}

func (rt *remoteRuntime) gatewayClient() *gatewayClient {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.client
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// gatewayStart sends a browser without a session to HardyOS's sign-in.
func (rt *remoteRuntime) gatewayStart(w http.ResponseWriter, r *http.Request, route *gwRoute) {
	if !isNavigation(r) {
		proxyPage(w, http.StatusUnauthorized, "Sign in to HardyOS first", "Open this app at its address in a browser.")
		return
	}
	s, c := rt.s, rt.gatewayClient()
	if s.oidc == nil || c == nil {
		proxyPage(w, http.StatusServiceUnavailable, "HardyOS sign-in isn't ready",
			"Apps sign in through HardyOS's sign-in provider (Control Panel › Sign-in). Try again in a minute.")
		return
	}
	state, verifier, nonce := randomToken(), randomToken(), randomToken()
	p := s.proxy
	now := time.Now()
	ip := s.clientIP(r)
	p.mu.Lock()
	pending, mine := 0, 0
	for k, t := range p.tokens {
		if now.After(t.expires) {
			delete(p.tokens, k)
			continue
		}
		if t.gateway {
			pending++
			if t.ip == ip {
				mine++
			}
		}
	}
	if mine >= maxGatewayPendingPerIP || pending >= maxGatewayPending {
		// Anyone on the internet can start sign-ins: each is memory for 10
		// minutes, so there's a ceiling per address and in all.
		p.mu.Unlock()
		w.Header().Set("Retry-After", "60")
		proxyPage(w, http.StatusTooManyRequests, "Too many sign-ins at once", "Wait a minute, then open the app again.")
		return
	}
	p.tokens["st:"+state] = proxyToken{appID: route.appID, next: safeNext(r.URL.RequestURI()), expires: now.Add(gatewaySignInTTL),
		gateway: true, verifier: verifier, nonce: nonce, ip: ip}
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: gatewayStateCookie, Value: state, Path: "/", MaxAge: int(gatewaySignInTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	q := url.Values{"client_id": {c.ID}, "redirect_uri": {"https://" + route.host + gatewayCallbackPath}, "response_type": {"code"},
		"scope": {"openid profile groups"}, "state": {state}, "nonce": {nonce},
		"code_challenge": {pkceChallenge(verifier)}, "code_challenge_method": {"S256"}}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, strings.TrimRight(s.oidc.Issuer(r.Context()), "/")+"/authorize?"+q.Encode(), http.StatusSeeOther)
}

// gatewayCallback finishes a sign-in: the provider sent the browser back
// with a code for this browser's state.
func (rt *remoteRuntime) gatewayCallback(w http.ResponseWriter, r *http.Request, route *gwRoute) {
	s, p := rt.s, rt.s.proxy
	if r.Method != http.MethodGet {
		proxyPage(w, http.StatusMethodNotAllowed, "This sign-in has expired", "Open the app again.")
		return
	}
	if dest := strings.ToLower(r.Header.Get("Sec-Fetch-Dest")); dest != "" && dest != "iframe" && dest != "document" {
		proxyPage(w, http.StatusForbidden, "Open this app at its address", "This sign-in only works as a page or window.")
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	c, err := r.Cookie(gatewayStateCookie)
	if state == "" || err != nil || !sameSecret(c.Value, state) {
		proxyPage(w, http.StatusForbidden, "This sign-in started somewhere else", "Open the app again in this browser.")
		return
	}
	now := time.Now()
	p.mu.Lock()
	t, ok := p.tokens["st:"+state]
	delete(p.tokens, "st:"+state)
	p.mu.Unlock()
	clearGatewayCookie(w, gatewayStateCookie)
	if !ok || !t.gateway || now.After(t.expires) || t.appID != route.appID {
		proxyPage(w, http.StatusForbidden, "This sign-in has expired", "Open the app again.")
		return
	}
	if e := q.Get("error"); e != "" {
		proxyPage(w, http.StatusForbidden, "Not signed in", "HardyOS sign-in answered: "+e+".")
		return
	}
	cl := rt.gatewayClient()
	if cl == nil || s.oidc == nil {
		proxyPage(w, http.StatusServiceUnavailable, "HardyOS sign-in isn't ready", "Try again in a minute.")
		return
	}
	sub, grant, err := rt.exchange(r.Context(), cl, q.Get("code"), "https://"+route.host+gatewayCallbackPath, t.verifier, t.nonce)
	if err != nil {
		s.log.Warn("app gateway sign-in", "app", route.appID, "err", err)
		proxyPage(w, http.StatusForbidden, "Couldn't sign you in", "Open the app again.")
		return
	}
	u, err := s.oidc.UserForSubject(r.Context(), sub)
	if err != nil {
		proxyPage(w, http.StatusForbidden, "You can't sign in here", "Your account can't use HardyOS sign-in.")
		return
	}
	if may, err := s.mayUse(r.Context(), "", u, route.appID); err != nil || !may {
		s.record(r, u, "apps.open", route.appID, audit.Denied, "published address")
		proxyPage(w, http.StatusForbidden, "You haven't been given this app", "Ask an administrator for access.")
		return
	}
	key := randomToken()
	p.mu.Lock()
	p.sessions[key] = &proxySession{appID: route.appID, userID: u.ID, gateway: true, sso: true, grant: grant,
		expires: now.Add(proxySessionTTL), checked: now}
	p.mu.Unlock()
	s.record(r, u, "apps.open", route.appID, audit.Success, "published address")
	http.SetCookie(w, &http.Cookie{Name: gatewayCookie, Value: key, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, safeNext(t.next), http.StatusSeeOther)
}

// exchange swaps a code for tokens at the provider (in-process) and
// returns the ID token's subject after checking issuer, audience, expiry
// and nonce, and the access token's id (its jti), which names the grant
// the gateway session rechecks. The tokens come straight from the
// provider's handler, not over a network, so signatures needn't be checked
// here.
func (rt *remoteRuntime) exchange(ctx context.Context, c *gatewayClient, code, redirect, verifier, nonce string) (string, string, error) {
	sub, jti, err := rt.exchangeTokens(ctx, c, code, redirect, verifier, nonce)
	if err != nil {
		return "", "", err
	}
	if jti == "" {
		return "", "", errors.New("no access token id")
	}
	return sub, jti, nil
}

func (rt *remoteRuntime) exchangeTokens(ctx context.Context, c *gatewayClient, code, redirect, verifier, nonce string) (string, string, error) {
	if code == "" {
		return "", "", errors.New("no code")
	}
	issuer := strings.TrimRight(rt.s.oidc.Issuer(ctx), "/")
	iu, err := url.Parse(issuer)
	if err != nil {
		return "", "", err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Host, req.RemoteAddr = iu.Host, "127.0.0.1:0"
	if iu.Scheme == "https" {
		req.TLS = &tls.ConnectionState{}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(c.ID), url.QueryEscape(c.Secret))
	rec := httptest.NewRecorder()
	rt.s.oidc.ServeHTTP(rec, req)
	var tok struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil || rec.Code != http.StatusOK || tok.IDToken == "" {
		return "", "", errors.New("token exchange failed: " + tok.Error)
	}
	var claims struct {
		Iss   string          `json:"iss"`
		Sub   string          `json:"sub"`
		Aud   json.RawMessage `json:"aud"`
		Exp   int64           `json:"exp"`
		Nonce string          `json:"nonce"`
	}
	if err := jwtPayload(tok.IDToken, &claims); err != nil {
		return "", "", err
	}
	var auds []string
	if json.Unmarshal(claims.Aud, &auds) != nil {
		var one string
		_ = json.Unmarshal(claims.Aud, &one)
		auds = []string{one}
	}
	switch {
	case strings.TrimRight(claims.Iss, "/") != issuer:
		return "", "", errors.New("wrong issuer")
	case !slices.Contains(auds, c.ID):
		return "", "", errors.New("wrong audience")
	case time.Now().Unix() > claims.Exp:
		return "", "", errors.New("expired ID token")
	case !sameSecret(claims.Nonce, nonce):
		return "", "", errors.New("wrong nonce")
	case claims.Sub == "":
		return "", "", errors.New("no subject")
	}
	var at struct {
		JTI string `json:"jti"`
		Sub string `json:"sub"`
	}
	if err := jwtPayload(tok.AccessToken, &at); err != nil || at.Sub != claims.Sub {
		return "", "", errors.New("malformed access token")
	}
	return claims.Sub, at.JTI, nil
}

// jwtPayload decodes a JWT's claims (no signature check: see exchange).
func jwtPayload(token string, v any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("malformed token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}
