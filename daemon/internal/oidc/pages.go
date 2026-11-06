package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

//go:embed page
var pageFS embed.FS

var pageTmpl = template.Must(template.ParseFS(pageFS, "page/page.html"))

// pageCSP: no scripts at all; styles, the logo and fonts from here; forms
// post only here. Redirects after a form are done by a meta refresh page,
// because browsers apply form-action to the redirects that follow a post.
const pageCSP = "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// Cookies. Host-only, Secure (except in development over HTTP), HttpOnly,
// SameSite=Lax: they must come along when an app sends the browser here.
const (
	cookieBrowser = "hardyos_oidc_b"
	cookieSession = "hardyos_sso"
	// desktopCookie is the desktop's session cookie over HTTPS
	// (api.SessionCookie); desktopCookieLegacy its name over plain HTTP and
	// before decision 155 (api.LegacySessionCookie).
	desktopCookie       = "__Host-hardyos_session"
	desktopCookieLegacy = "hardyos_session"
)

// hasDesktopCookie reports whether the request carries the desktop's
// session cookie under either name.
func hasDesktopCookie(r *http.Request) bool {
	for _, n := range []string{desktopCookie, desktopCookieLegacy} {
		if _, err := r.Cookie(n); err == nil {
			return true
		}
	}
	return false
}

// uniformFailure is the one answer to every failed sign-in from the
// internet: it doesn't say whether the name exists, is turned off, locked,
// an administrator's or a local account.
const uniformFailure = "Incorrect username or password."

func (p *Provider) cookieName(base string) string {
	if p.cfg.Insecure {
		return base
	}
	return "__Host-" + base
}

func (p *Provider) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: p.cookieName(name), Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: !p.cfg.Insecure, SameSite: http.SameSiteLaxMode})
}

func (p *Provider) cookie(r *http.Request, name string) string {
	c, err := r.Cookie(p.cookieName(name))
	if err != nil || len(c.Value) > 128 {
		return ""
	}
	return c.Value
}

// servePage handles the provider's own pages; false for everything else
// (the op package's endpoints).
func (p *Provider) servePage(w http.ResponseWriter, r *http.Request, rest, base string) bool {
	switch {
	case rest == "/login":
		w.Header().Set("Content-Security-Policy", pageCSP)
		w.Header().Set("Cache-Control", "no-store")
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			p.loginPage(w, r, base)
		case http.MethodPost:
			p.loginPost(w, r, base)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case rest == "/consent":
		w.Header().Set("Content-Security-Policy", pageCSP)
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return true
		}
		p.consentPost(w, r, base)
	case rest == "/logout":
		w.Header().Set("Content-Security-Policy", pageCSP)
		w.Header().Set("Cache-Control", "no-store")
		p.logout(w, r, base)
	case rest == "/logged-out":
		w.Header().Set("Content-Security-Policy", pageCSP)
		p.render(w, http.StatusOK, &page{Kind: "message", Base: base, Title: "Signed out",
			Heading: "You're signed out", Lead: "You can close this tab."})
	case rest == "/authorize/callback":
		// The op package hands out the code here; only the browser the
		// sign-in belongs to may collect it.
		w.Header().Set("Cache-Control", "no-store")
		if !p.callbackBrowserOK(r) {
			p.problem(w, base, http.StatusForbidden, "This sign-in was started in another browser",
				"Go back to the app and sign in again.")
			return true
		}
		return false
	case strings.HasPrefix(rest, "/assets/"):
		p.asset(w, r, strings.TrimPrefix(rest, "/assets/"))
	case rest == "/":
		if r.Method != http.MethodGet {
			return false
		}
		w.Header().Set("Content-Security-Policy", pageCSP)
		p.render(w, http.StatusOK, &page{Kind: "message", Base: base, Title: "HardyOS sign-in",
			Heading: "HardyOS sign-in", Lead: "This is the sign-in service of a HardyOS server. Apps send you here when you sign in to them with your HardyOS account."})
	default:
		return false
	}
	return true
}

func (p *Provider) asset(w http.ResponseWriter, r *http.Request, name string) {
	types := map[string]string{"style.css": "text/css; charset=utf-8", "mark.svg": "image/svg+xml",
		"jakarta-400.woff2": "font/woff2", "jakarta-600.woff2": "font/woff2", "jakarta-700.woff2": "font/woff2"}
	ct, ok := types[name]
	if !ok || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(pageFS, "page/"+name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; font-src 'self'")
	_, _ = w.Write(b)
}

// page is what the template shows.
type page struct {
	Kind     string // login, consent, message, continue, logout, bounce
	Base     string
	Title    string
	Heading  string
	Lead     string
	Error    string
	Notice   string
	ID       string
	CSRF     string
	Username string
	Client   string
	AppHost  string
	Scopes   []string
	Refresh  string
	Link     string
	LinkText string
	Next     string
	Sub      string
	Exp      string
	Sig      string
	Domain   bool
}

func (p *Provider) render(w http.ResponseWriter, status int, pg *page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pageTmpl.Execute(w, pg); err != nil {
		p.cfg.Log.Warn("oidc: page", "err", err)
	}
}

func (p *Provider) problem(w http.ResponseWriter, base string, status int, heading, lead string) {
	p.render(w, status, &page{Kind: "message", Base: base, Title: heading, Heading: heading, Lead: lead})
}

// ---- browser binding and CSRF ------------------------------------------------

// browser returns this browser's random id, setting one when it has none.
// A sign-in request belongs to the first browser that opens it; forms on
// it carry an HMAC of request and browser, so another site can't post
// them and another browser can't finish someone else's sign-in.
func (p *Provider) browser(w http.ResponseWriter, r *http.Request) string {
	if b := p.cookie(r, cookieBrowser); len(b) == 43 {
		return b
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	b := base64.RawURLEncoding.EncodeToString(raw)
	p.setCookie(w, cookieBrowser, b, int((24 * time.Hour).Seconds()))
	return b
}

func (p *Provider) mac(parts ...string) string {
	m := hmac.New(sha256.New, p.csrfKey)
	m.Write([]byte(strings.Join(parts, "\x00")))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (p *Provider) macOK(got string, parts ...string) bool {
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(p.mac(parts...))) == 1
}

// sameOrigin refuses posts another site's page made: a cross-site
// Sec-Fetch-Site, or an Origin that isn't this host.
func sameOrigin(r *http.Request) bool {
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" && s != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	return true
}

// callbackBrowserOK reports whether the callback comes from the browser
// the sign-in request is bound to.
func (p *Provider) callbackBrowserOK(r *http.Request) bool {
	b := p.cookie(r, cookieBrowser)
	if b == "" {
		return false
	}
	var stored string
	if err := p.cfg.DB.QueryRowContext(r.Context(), `SELECT browser_hash FROM oidc_auth_requests WHERE id = ?`, r.URL.Query().Get("id")).Scan(&stored); err != nil {
		return false
	}
	return stored != "" && subtle.ConstantTimeCompare([]byte(stored), []byte(hashHex(b))) == 1
}

// bind attaches the request to this browser (first come) and reports
// whether it is this browser's.
func (p *Provider) bind(ctx context.Context, id, browser, stored string) bool {
	h := hashHex(browser)
	if stored != "" {
		return subtle.ConstantTimeCompare([]byte(stored), []byte(h)) == 1
	}
	res, err := p.cfg.DB.ExecContext(ctx, `UPDATE oidc_auth_requests SET browser_hash = ? WHERE id = ? AND browser_hash = ''`, h, id)
	if err != nil {
		return false
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return true
	}
	var now string
	_ = p.cfg.DB.QueryRowContext(ctx, `SELECT browser_hash FROM oidc_auth_requests WHERE id = ?`, id).Scan(&now)
	return now == h
}

// ---- the provider's own browser session -----------------------------------------

// sessionUser is the person signed in to HardyOS sign-in in this browser.
func (p *Provider) sessionUser(r *http.Request) (*auth.User, time.Time, bool) {
	tok := p.cookie(r, cookieSession)
	if tok == "" {
		return nil, time.Time{}, false
	}
	var uid int64
	var authTime, expires string
	err := p.cfg.DB.QueryRowContext(r.Context(), `SELECT user_id, auth_time, expires_at FROM oidc_browser_sessions WHERE id_hash = ?`, hashHex(tok)).
		Scan(&uid, &authTime, &expires)
	if err != nil || p.now().After(store.ParseTime(expires)) {
		return nil, time.Time{}, false
	}
	u, err := p.cfg.LoadUser(r.Context(), uid)
	if err != nil || u.Disabled {
		_, _ = p.cfg.DB.ExecContext(r.Context(), `DELETE FROM oidc_browser_sessions WHERE id_hash = ?`, hashHex(tok))
		return nil, time.Time{}, false
	}
	return u, store.ParseTime(authTime), true
}

func (p *Provider) startSession(w http.ResponseWriter, r *http.Request, u *auth.User, authTime time.Time) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	tok := base64.RawURLEncoding.EncodeToString(raw)
	now := p.now()
	ua := r.UserAgent()
	if len(ua) > 256 {
		ua = ua[:256]
	}
	if old := p.cookie(r, cookieSession); old != "" {
		_, _ = p.cfg.DB.ExecContext(r.Context(), `DELETE FROM oidc_browser_sessions WHERE id_hash = ?`, hashHex(old))
	}
	_, err := p.cfg.DB.ExecContext(r.Context(), `INSERT INTO oidc_browser_sessions (id_hash, user_id, auth_time, created_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		hashHex(tok), u.ID, store.FormatTime(authTime), store.FormatTime(now), store.FormatTime(now.Add(browserTTL)), p.cfg.ClientIP(r), ua)
	if err != nil {
		p.cfg.Log.Warn("oidc: start session", "err", err)
		return
	}
	p.setCookie(w, cookieSession, tok, int(browserTTL.Seconds()))
}

func (p *Provider) endSession(w http.ResponseWriter, r *http.Request) {
	if tok := p.cookie(r, cookieSession); tok != "" {
		_, _ = p.cfg.DB.ExecContext(r.Context(), `DELETE FROM oidc_browser_sessions WHERE id_hash = ?`, hashHex(tok))
	}
	p.setCookie(w, cookieSession, "", -1)
}

// ---- sign-in ------------------------------------------------------------------

func (p *Provider) storage() *storage { return &storage{p: p} }

// openRequest loads the sign-in request a page is for and checks it
// belongs to this browser.
func (p *Provider) openRequest(w http.ResponseWriter, r *http.Request, base, id string) (*authRequest, *Client, string, bool) {
	a, stored, err := p.storage().loadAuthRequest(r.Context(), id)
	if err != nil || a.codeHash != "" {
		p.problem(w, base, http.StatusBadRequest, "This sign-in has expired",
			"Go back to the app and sign in again.")
		return nil, nil, "", false
	}
	c, err := p.Clients.Get(r.Context(), a.ClientID)
	if err != nil || c.Disabled {
		p.problem(w, base, http.StatusBadRequest, "This app can't sign in here", "It was removed or turned off in HardyOS.")
		return nil, nil, "", false
	}
	b := p.browser(w, r)
	if !p.bind(r.Context(), a.ID, b, stored) {
		p.problem(w, base, http.StatusForbidden, "This sign-in was started in another browser",
			"For your safety a sign-in can only be finished in the browser it began in. Go back to the app and sign in again.")
		return nil, nil, "", false
	}
	return a, c, b, true
}

func (p *Provider) loginPage(w http.ResponseWriter, r *http.Request, base string) {
	a, c, b, ok := p.openRequest(w, r, base, r.URL.Query().Get("id"))
	if !ok {
		return
	}
	if !a.hasPrompt(oidc.PromptLogin) {
		u, authTime, how, found := p.existingSession(r, base)
		if found && fresh(a, authTime, p.now()) {
			p.proceed(w, r, base, a, c, u, authTime, how, false)
			return
		}
	}
	if a.hasPrompt(oidc.PromptNone) {
		p.errorRedirect(w, r, base, a, oidc.ErrLoginRequired(), false)
		return
	}
	// On the desktop's host, a browser that arrived from another site
	// doesn't send the desktop's SameSite=Strict session cookie. Reloading
	// the page once from here does, so someone signed in to the desktop
	// isn't asked for their password again.
	if base != "" && r.URL.Query().Get("b") == "" && r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		if !hasDesktopCookie(r) {
			again := base + "/login?" + url.Values{"id": {a.ID}, "b": {"1"}}.Encode()
			p.render(w, http.StatusOK, &page{Kind: "bounce", Base: base, Title: "Signing in", Refresh: again, Link: again})
			return
		}
	}
	p.loginForm(w, http.StatusOK, base, a, c, b, loginHint(a.LoginHint), "")
}

func loginHint(h string) string {
	h = strings.TrimSpace(h)
	if len(h) > 128 || strings.ContainsAny(h, "\x00\r\n") {
		return ""
	}
	return h
}

// existingSession finds someone already signed in in this browser: to
// HardyOS sign-in, or to the desktop when the provider is on its host.
func (p *Provider) existingSession(r *http.Request, base string) (*auth.User, time.Time, string, bool) {
	local := p.loadSettings(r.Context()).localAccounts
	if u, t, ok := p.sessionUser(r); ok && (u.IdentitySource() == auth.SourceDomain || local) && !p.adminRefused(r, u) {
		return u, t, "existing HardyOS sign-in", true
	}
	if base != "" && p.cfg.DesktopUser != nil {
		if u, t, ok := p.cfg.DesktopUser(r); ok {
			if (u.IdentitySource() == auth.SourceDomain || local) && !p.adminRefused(r, u) {
				return u, t, "desktop session", true
			}
		}
	}
	return nil, time.Time{}, "", false
}

// fresh applies max_age.
func fresh(a *authRequest, authTime, now time.Time) bool {
	if a.MaxAge == nil {
		return true
	}
	return now.Sub(authTime) <= time.Duration(*a.MaxAge)*time.Second
}

func (p *Provider) loginForm(w http.ResponseWriter, status int, base string, a *authRequest, c *Client, browser, username, msg string) {
	domain := p.cfg.SignIn.Domain != nil
	notice := ""
	if !p.loadSettings(context.Background()).localAccounts {
		notice = "Sign in with your domain account."
	}
	p.render(w, status, &page{Kind: "login", Base: base, Title: "Sign in to " + c.Name, Heading: "Sign in",
		Lead: "to continue to " + c.Name, Client: c.Name, AppHost: appHost(a.RedirectURI), ID: a.ID,
		CSRF: p.mac("login", a.ID, browser), Username: username, Error: msg, Notice: notice, Domain: domain})
}

func appHost(redirect string) string {
	u, err := url.Parse(redirect)
	if err != nil {
		return ""
	}
	return u.Host
}

func (p *Provider) loginPost(w http.ResponseWriter, r *http.Request, base string) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		p.problem(w, base, http.StatusBadRequest, "Something went wrong", "Go back to the app and sign in again.")
		return
	}
	a, c, b, ok := p.openRequest(w, r, base, r.PostForm.Get("id"))
	if !ok {
		return
	}
	if !sameOrigin(r) || !p.macOK(r.PostForm.Get("csrf"), "login", a.ID, b) {
		p.problem(w, base, http.StatusForbidden, "This form has expired", "Go back to the app and sign in again.")
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("username"))
	pw := r.PostForm.Get("password")
	if len(name) > 256 {
		name = name[:256]
	}
	ip := p.cfg.ClientIP(r)
	ctx := r.Context()
	userKey := p.cfg.SignIn.LimitKey(ctx, name)
	// From the internet: buckets of their own that only slow guessing down,
	// so strangers can't lock anyone out of signing in at home or over
	// NetBird, and one answer for every failure.
	public := p.cfg.PublicOrigin(r)
	var lim limiter = p.cfg.Limiter
	prefix := ""
	if public {
		lim, prefix = p.cfg.PublicLimiter, "pub-"
	}
	for _, key := range []string{prefix + "ip:" + ip, prefix + userKey} {
		if ok, wait := lim.Allowed(key); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			p.audit(ctx, ip, nil, "oidc.signin", c.Name, audit.Denied, "rate limited ("+name+")"+publicNote(public))
			msg := fmt.Sprintf("Too many failed sign-ins. Try again in %d minutes.", int(math.Ceil(wait.Minutes())))
			if public {
				msg = fmt.Sprintf("Too many failed sign-ins. Try again in %d seconds.", int(math.Ceil(wait.Seconds())))
			}
			p.loginForm(w, http.StatusTooManyRequests, base, a, c, b, name, msg)
			return
		}
	}
	var u *auth.User
	var err error
	if p.loadSettings(ctx).localAccounts {
		u, err = p.cfg.SignIn.Authenticate(ctx, name, pw)
	} else {
		u, err = p.cfg.SignIn.AuthenticateDomain(ctx, name, pw)
	}
	if err == nil && p.adminRefused(r, u) {
		// The right password, but administrators don't sign in from the
		// internet (Control Panel › Sign-in): answered like a wrong one.
		p.audit(ctx, ip, u, "oidc.signin", c.Name, audit.Denied, "an administrator from a public address"+publicNote(public))
		lim.Fail(prefix + "ip:" + ip)
		lim.Fail(prefix + userKey)
		p.loginForm(w, http.StatusUnauthorized, base, a, c, b, name, uniformFailure)
		return
	}
	if err != nil {
		code, status, counts, known := "bad_credentials", http.StatusUnauthorized, true, true
		msg := uniformFailure
		if errors.Is(err, auth.ErrLocalAccount) {
			// Local accounts are off: answered like a wrong password, without
			// looking at it, and counted against their own key.
			userKey = "oidc-local:" + strings.ToLower(name)
		} else if p.cfg.LoginError != nil {
			code, status, counts, known = p.cfg.LoginError(err)
			if known && code != "bad_credentials" {
				msg = sentence(err.Error())
			}
		}
		if !known {
			p.cfg.Log.Error("oidc: sign-in", "err", err)
			code, status, counts, msg = "error", http.StatusInternalServerError, false, "Something went wrong. Try again."
		}
		if public && status < 500 {
			// Turned off, locked, expired, not this server's: all the same
			// from the internet.
			status, msg = http.StatusUnauthorized, uniformFailure
		}
		if counts {
			lim.Fail(prefix + "ip:" + ip)
			lim.Fail(prefix + userKey)
		}
		p.audit(ctx, ip, nil, "oidc.signin", c.Name, audit.Failure, strings.ReplaceAll(code, "_", " ")+" ("+name+")"+publicNote(public))
		p.loginForm(w, status, base, a, c, b, name, msg)
		return
	}
	lim.Succeed(prefix + "ip:" + ip)
	lim.Succeed(prefix + userKey)
	now := p.now()
	p.startSession(w, r, u, now)
	p.proceed(w, r, base, a, c, u, now, "password", true)
}

// limiter is auth.LoginLimiter or, for sign-ins from the internet,
// auth.DelayLimiter.
type limiter interface {
	Allowed(key string) (bool, time.Duration)
	Fail(key string)
	Succeed(key string)
}

func publicNote(public bool) string {
	if public {
		return "; from a public address"
	}
	return ""
}

func sentence(s string) string {
	if s == "" {
		return s
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// proceed takes a signed-in person on: access check, subject, consent,
// then back to the app.
func (p *Provider) proceed(w http.ResponseWriter, r *http.Request, base string, a *authRequest, c *Client, u *auth.User, authTime time.Time, how string, posted bool) {
	ctx := r.Context()
	ip := p.cfg.ClientIP(r)
	if p.adminRefused(r, u) {
		// loginPost and existingSession already keep administrators out from
		// the internet; this is the backstop.
		p.audit(ctx, ip, u, "oidc.signin", c.Name, audit.Denied, "an administrator from a public address")
		p.problem(w, base, http.StatusForbidden, "Sign in again", "Go back to the app and sign in again.")
		return
	}
	if err := p.allowed(ctx, c, u); err != nil {
		p.audit(ctx, ip, u, "oidc.signin", c.Name, audit.Denied, err.Error())
		back := p.errorURL(ctx, a, oidc.ErrAccessDenied().WithDescription("not allowed for this account"))
		p.render(w, http.StatusForbidden, &page{Kind: "message", Base: base, Title: "No access",
			Heading: "You can't use " + c.Name, Lead: sentence(err.Error()), Link: back, LinkText: "Back to " + c.Name})
		return
	}
	sub, err := p.subjectFor(ctx, u, how == "password")
	if errors.Is(err, auth.ErrAccountReplaced) {
		// This browser's sign-in was the previous owner of the name's.
		p.endSession(w, r)
		p.problem(w, base, http.StatusForbidden, "Sign in again", "Your sign-in here has ended. Go back to the app and sign in again.")
		return
	}
	if err != nil {
		p.cfg.Log.Warn("oidc: subject", "user", u.Username, "err", err)
		p.problem(w, base, http.StatusServiceUnavailable, "Can't sign you in right now", sentence(ErrNoSubject.Error()))
		return
	}
	a.UserID, a.Subject, a.AuthTime, a.AMR = u.ID, sub, authTime.UTC(), []string{"pwd"}
	// A sign-in for an app on another device (Immich's phone app, through
	// its mobile redirect) is always confirmed by the person: a link that
	// starts one can't finish silently on an existing sign-in.
	if c.ManagedBy != "" && p.cfg.ConfirmRedirect != nil && p.cfg.ConfirmRedirect(c.ManagedBy, a.RedirectURI) {
		if a.hasPrompt(oidc.PromptNone) {
			p.errorRedirect(w, r, base, a, consentRequired(), posted)
			return
		}
		if err := p.storage().saveAuthRequest(ctx, a, false); err != nil {
			p.problem(w, base, http.StatusInternalServerError, "Something went wrong", "Go back to the app and sign in again.")
			return
		}
		b := p.browser(w, r)
		p.render(w, http.StatusOK, &page{Kind: "confirm", Base: base, Title: "Continue to " + c.Name + "?", Heading: "Continue to " + c.Name + "?",
			Lead: "Signed in as " + displayName(u), Client: c.Name, AppHost: appHost(a.RedirectURI), ID: a.ID,
			CSRF: p.mac("consent", a.ID, b)})
		return
	}
	if !c.FirstParty && (a.hasPrompt(oidc.PromptConsent) || !p.consented(ctx, u.ID, c.ID, a.Scopes)) {
		if a.hasPrompt(oidc.PromptNone) {
			p.errorRedirect(w, r, base, a, consentRequired(), posted)
			return
		}
		if err := p.storage().saveAuthRequest(ctx, a, false); err != nil {
			p.problem(w, base, http.StatusInternalServerError, "Something went wrong", "Go back to the app and sign in again.")
			return
		}
		b := p.browser(w, r)
		p.render(w, http.StatusOK, &page{Kind: "consent", Base: base, Title: "Allow " + c.Name + "?", Heading: "Allow " + c.Name + "?",
			Lead: "Signed in as " + displayName(u), Client: c.Name, AppHost: appHost(a.RedirectURI), ID: a.ID,
			CSRF: p.mac("consent", a.ID, b), Scopes: scopeLines(a.Scopes)})
		return
	}
	p.finish(w, r, base, a, c, u, how, posted)
}

func displayName(u *auth.User) string {
	if u.DisplayName != "" {
		return u.DisplayName + " (" + u.IdentityPrincipal() + ")"
	}
	return u.IdentityPrincipal()
}

func (p *Provider) finish(w http.ResponseWriter, r *http.Request, base string, a *authRequest, c *Client, u *auth.User, how string, posted bool) {
	ctx := r.Context()
	if err := p.storage().saveAuthRequest(ctx, a, true); err != nil {
		p.problem(w, base, http.StatusInternalServerError, "Something went wrong", "Go back to the app and sign in again.")
		return
	}
	p.audit(ctx, p.cfg.ClientIP(r), u, "oidc.signin", c.Name, audit.Success, "signed in to "+c.Name+" ("+how+")")
	cb := base + "/authorize/callback?" + url.Values{"id": {a.ID}}.Encode()
	if posted {
		p.render(w, http.StatusOK, &page{Kind: "continue", Base: base, Title: "Signing in", Heading: "Signed in",
			Lead: "Taking you back to " + c.Name + "…", Refresh: cb, Link: cb, LinkText: "Continue to " + c.Name})
		return
	}
	http.Redirect(w, r, cb, http.StatusFound)
}

func (p *Provider) consented(ctx context.Context, userID int64, clientID string, scopes []string) bool {
	var raw string
	if err := p.cfg.DB.QueryRowContext(ctx, `SELECT scopes FROM oidc_consents WHERE user_id = ? AND client_id = ?`, userID, clientID).Scan(&raw); err != nil {
		return false
	}
	have := jsonList(raw)
	for _, s := range scopes {
		if s != oidc.ScopeOpenID && !slices.Contains(have, s) {
			return false
		}
	}
	return true
}

func scopeLines(scopes []string) []string {
	out := []string{"Know who you are (a stable ID for your account)"}
	for _, s := range scopes {
		switch s {
		case oidc.ScopeProfile:
			out = append(out, "Your name and user name, your groups and whether you're an administrator")
		case oidc.ScopeEmail:
			out = append(out, "Your email address")
		case ScopeGroups:
			if !slices.Contains(scopes, oidc.ScopeProfile) {
				out = append(out, "Your groups and whether you're an administrator")
			}
		case oidc.ScopeOfflineAccess:
			out = append(out, "Stay signed in when you're not using it (up to 30 days)")
		}
	}
	return out
}

func (p *Provider) consentPost(w http.ResponseWriter, r *http.Request, base string) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		p.problem(w, base, http.StatusBadRequest, "Something went wrong", "Go back to the app and sign in again.")
		return
	}
	a, c, b, ok := p.openRequest(w, r, base, r.PostForm.Get("id"))
	if !ok {
		return
	}
	if !sameOrigin(r) || !p.macOK(r.PostForm.Get("csrf"), "consent", a.ID, b) || a.UserID == 0 {
		p.problem(w, base, http.StatusForbidden, "This form has expired", "Go back to the app and sign in again.")
		return
	}
	ctx := r.Context()
	u, err := p.cfg.LoadUser(ctx, a.UserID)
	if err != nil {
		p.problem(w, base, http.StatusForbidden, "Your account can't sign in", "Go back to the app and sign in again.")
		return
	}
	if r.PostForm.Get("decision") != "allow" {
		p.audit(ctx, p.cfg.ClientIP(r), u, "oidc.consent", c.Name, audit.Denied, "declined")
		p.errorRedirect(w, r, base, a, oidc.ErrAccessDenied().WithDescription("the person declined"), true)
		return
	}
	scopes := slices.DeleteFunc(slices.Clone(a.Scopes), func(s string) bool { return s == oidc.ScopeOpenID })
	_, err = p.cfg.DB.ExecContext(ctx, `INSERT INTO oidc_consents (user_id, client_id, scopes, granted_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id, client_id) DO UPDATE SET scopes = excluded.scopes, granted_at = excluded.granted_at`,
		u.ID, c.ID, jsonString(scopes), store.Now())
	if err != nil {
		p.problem(w, base, http.StatusInternalServerError, "Something went wrong", "Go back to the app and sign in again.")
		return
	}
	p.audit(ctx, p.cfg.ClientIP(r), u, "oidc.consent", c.Name, audit.Success, "allowed: "+strings.Join(scopes, " "))
	p.finish(w, r, base, a, c, u, "consent", true)
}

// errorURL is the app's redirect URI with an error (the redirect URI was
// checked when the request was made).
func (p *Provider) errorURL(ctx context.Context, a *authRequest, e *oidc.Error) string {
	e.State = a.State
	u, err := op.AuthResponseURL(a.RedirectURI, a.ResponseType, a.ResponseMode, e, p.op.Encoder())
	if err != nil {
		return ""
	}
	_, _ = p.cfg.DB.ExecContext(ctx, `DELETE FROM oidc_auth_requests WHERE id = ? AND code_hash IS NULL`, a.ID)
	return u
}

func (p *Provider) errorRedirect(w http.ResponseWriter, r *http.Request, base string, a *authRequest, e *oidc.Error, posted bool) {
	u := p.errorURL(r.Context(), a, e)
	if u == "" {
		p.problem(w, base, http.StatusBadRequest, "Something went wrong", "Go back to the app and try again.")
		return
	}
	if posted {
		p.render(w, http.StatusOK, &page{Kind: "continue", Base: base, Title: "Returning", Heading: "Returning to the app",
			Lead: "Taking you back…", Refresh: u, Link: u, LinkText: "Continue"})
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

// ---- sign-out -------------------------------------------------------------------

// signLogout makes the parameters of the sign-out page: where to go next
// (already checked), whose sign-in to end (from a verified id_token_hint;
// empty: ask), and an HMAC so the page can't be used to send anyone
// anywhere else.
func (p *Provider) signLogout(sub, next string) url.Values {
	exp := strconv.FormatInt(p.now().Add(10*time.Minute).Unix(), 10)
	return url.Values{"next": {next}, "sub": {sub}, "exp": {exp}, "sig": {p.mac("logout", sub, next, exp)}}
}

func (p *Provider) logout(w http.ResponseWriter, r *http.Request, base string) {
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	}
	if err := r.ParseForm(); err != nil {
		p.problem(w, base, http.StatusBadRequest, "Something went wrong", "")
		return
	}
	q := r.Form
	next, sub, exp, sig := q.Get("next"), q.Get("sub"), q.Get("exp"), q.Get("sig")
	expAt, _ := strconv.ParseInt(exp, 10, 64)
	if !p.macOK(sig, "logout", sub, next, exp) || p.now().Unix() > expAt {
		p.problem(w, base, http.StatusBadRequest, "This sign-out link has expired", "You can close this tab.")
		return
	}
	ctx := r.Context()
	u, _, signedIn := p.sessionUser(r)
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if !signedIn {
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		if sub != "" && p.subjectOf(ctx, u.ID) == sub {
			p.endSession(w, r)
			p.endManagedGrants(ctx, u.ID)
			p.audit(ctx, p.cfg.ClientIP(r), u, "oidc.signout", u.Username, audit.Success, "signed out by an app")
			http.Redirect(w, r, next, http.StatusFound)
			return
		}
		// No proof the app's user is this browser's: ask.
		b := p.browser(w, r)
		p.render(w, http.StatusOK, &page{Kind: "logout", Base: base, Title: "Sign out", Heading: "Sign out of HardyOS?",
			Lead: "Signed in as " + displayName(u), CSRF: p.mac("logout-confirm", sig, b), Next: next, Sub: sub, Exp: exp, Sig: sig,
			Link: next, LinkText: "Stay signed in"})
	case http.MethodPost:
		b := p.browser(w, r)
		if !sameOrigin(r) || !p.macOK(q.Get("csrf"), "logout-confirm", sig, b) {
			p.problem(w, base, http.StatusForbidden, "This form has expired", "You can close this tab.")
			return
		}
		p.endSession(w, r)
		if signedIn {
			p.endManagedGrants(ctx, u.ID)
			p.audit(ctx, p.cfg.ClientIP(r), u, "oidc.signout", u.Username, audit.Success, "")
		}
		p.render(w, http.StatusOK, &page{Kind: "continue", Base: base, Title: "Signed out", Heading: "You're signed out",
			Lead: "Taking you back…", Refresh: next, Link: next, LinkText: "Continue"})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// endManagedGrants revokes a person's sign-ins at the clients HardyOS keeps
// itself (Remote Access's app gateway): signing out of HardyOS sign-in
// signs them out of every published app within the gateway's 30-second
// recheck. Apps an administrator registered keep their own sessions (they
// learn of it through RP-initiated logout, or at their next refresh).
func (p *Provider) endManagedGrants(ctx context.Context, userID int64) {
	n, _ := revokeWhere(ctx, p.cfg.DB, p.now(), `user_id = ? AND client_id IN (SELECT id FROM oidc_clients WHERE managed_by != '')`, userID)
	if n > 0 {
		p.audit(ctx, "", nil, "oidc.token.revoke", "published apps", audit.Success, fmt.Sprintf("signed out of HardyOS sign-in: %d app sign-in(s) ended", n))
	}
}

func (p *Provider) subjectOf(ctx context.Context, userID int64) string {
	var sub string
	if err := p.cfg.DB.QueryRowContext(ctx, `SELECT sub FROM oidc_subjects WHERE user_id = ?`, userID).Scan(&sub); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ""
	}
	return sub
}
