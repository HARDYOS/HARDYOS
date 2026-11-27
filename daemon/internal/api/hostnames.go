package api

// Per-app hostnames on the desktop's own listener (decisions 450-459).
//
// Once Control Panel › Hostnames has a Cloudflare token (root's), the
// wildcard certificate for *.<base> and is turned on, hardyd's HTTPS
// listener (every address: LAN and NetBird) routes by Host:
//
//	<desktop>.<base>  the desktop (and /__hardyos/bind for the hosts below)
//	sso.<base>        HardyOS's sign-in provider, nothing else
//	files.<base>      share link pages (/s/...), nothing else
//	office.<base>     the office editor's origin (was port 44250)
//	mail.<base>       mail-app settings and calendars to hardyd, else webmail
//	photos.<base>     Photos (Immich)
//	<app id>.<base>   any app with a web page (was its window proxy port)
//
// Anything else under the base is a 404, never the desktop. Requests that
// came through the app gateway (NetBird's proxy) are routed by the gateway
// as before.
//
// Sign-in on an app host is a bounce through the desktop host, whose
// session cookie (__Host-, SameSite=Strict) only the desktop's host
// receives:
//
//  1. The app host, without a session, sets a random state cookie
//     (__Host-hardyos_host_state) and redirects to
//     https://<desktop>.<base>/__hardyos/bind?app=<id>&s=<SHA-256(state)>.
//  2. The desktop host checks its own session (without sliding it), the
//     account and the app's access list, and redirects to the app's own
//     host (derived from the app id, never from the request) with a
//     single-use 60-second code bound to that state hash.
//  3. The app host's callback needs the code and the state cookie whose
//     hash it is bound to, then sets __Host-hardyos_host for that app.
//
// So a code is only good in the browser that started the sign-in, and a
// browser only ever gets a session for its own desktop session: another
// page can't sign someone into an account of its choosing (login CSRF), and
// a stolen code is useless. App sessions follow the desktop session like
// window proxy sessions (rechecks, WebSocket closing; decision 81).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"html"
	"io"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/cfdns"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/hostnames"
	"github.com/hardyos/hardyos/daemon/internal/photos"
	"github.com/hardyos/hardyos/daemon/internal/publish"
	"github.com/hardyos/hardyos/daemon/internal/tlscert"
)

const (
	hostCookie      = "__Host-hardyos_host"
	hostStateCookie = "__Host-hardyos_host_state"
	hostBindPath    = "/__hardyos/bind"
	hostCallback    = "/__hardyos/callback"
	hostCodeTTL     = time.Minute
	// hostOfficeID is the office editor's "app" for host sessions (not a
	// valid app id, so no app can be it).
	hostOfficeID = ".office"
	maxHostCodes = 10000
)

// hostRefresh is how often the hostnames' state is read again.
var hostRefresh = 30 * time.Second

type hostCode struct {
	appID        string
	userID       int64
	desktopToken string
	stateHash    string
	next         string
	ip           string
	expires      time.Time
	// remote: the app runs on this other member (decision 494).
	remote cluster.NodeID
}

// maxCodesEach bounds the codes waiting per desktop session and per
// address (decision 457).
const maxCodesEach = 5

type hostProxy struct {
	target string
	rp     *httputil.ReverseProxy
}

// hostRuntime is the hostnames' state as the listener uses it.
type hostRuntime struct {
	s *Server

	mu       sync.Mutex
	active   bool
	base     string
	desktop  string // the desktop's label
	apps     map[string]apps.App
	appsKnow bool
	codes    map[string]hostCode
	proxies  map[string]*hostProxy
	problem  string
	// cookies are the cookie names each app host's own responses set
	// (decision 450 amended): a request cookie another app host set and
	// this one never did was tossed in from a sibling and is dropped.
	cookies map[string]map[string]bool
}

// maxLearnedCookies bounds the names remembered per app.
const maxLearnedCookies = 200

// hostsOffPage refuses a name under the base while hostnames are off
// (decision 450 amended): never the desktop on an app's name, and the
// browser forgets what an app stored there.
func hostsOffPage(w http.ResponseWriter) {
	w.Header().Set("Clear-Site-Data", `"storage", "cache"`)
	proxyPage(w, http.StatusNotFound, "Hostnames are off", "Open apps from the HardyOS desktop at the server's own address.")
}

func (h *hostRuntime) snapshot() (active bool, base, desktop string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.active, h.base, h.desktop
}

// desktopHost is <desktop>.<base> while hostnames are on.
func (h *hostRuntime) desktopHost() string {
	active, base, desk := h.snapshot()
	if !active {
		return ""
	}
	return desk + "." + base
}

// onDesktopHost reports whether r reached the desktop by its hostname (the
// only place app hosts can bind sessions from).
func (h *hostRuntime) onDesktopHost(r *http.Request) bool {
	d := h.desktopHost()
	return d != "" && strings.EqualFold(strings.TrimSuffix(hostOnly(r.Host), "."), d)
}

// underBase reports whether host is a name one label under the base while
// hostnames are on.
func (h *hostRuntime) underBase(host string) bool {
	active, base, _ := h.snapshot()
	return active && tlscert.Covers(base, hostOnly(host))
}

// labelFor is the hostname label an app is reached at.
func labelFor(appID string) string {
	switch appID {
	case photos.AppID:
		return hostnames.PhotosLabel
	case WebmailAppID:
		return hostnames.MailLabel
	case hostOfficeID:
		return hostnames.OfficeLabel
	}
	return appID
}

// hostURL is https://<label>.<base> for an app ("" while off).
func (h *hostRuntime) hostURL(appID string) string {
	active, base, desk := h.snapshot()
	l := labelFor(appID)
	if !active || l == desk || (l == appID && hostnames.Reserved(l)) || !cfdns.ValidDomain(l+"."+base) {
		return ""
	}
	return "https://" + l + "." + base
}

// frameSrc lets the desktop frame the app hosts.
func (h *hostRuntime) frameSrc() string {
	active, base, _ := h.snapshot()
	if !active {
		return ""
	}
	return " https://*." + base
}

// connectSrc lets the desktop (used at another address) check that its
// hostname answers before offering to move there.
func (h *hostRuntime) connectSrc() string {
	if d := h.desktopHost(); d != "" {
		return " https://" + d
	}
	return ""
}

// refresh reads the settings, root's DNS state, the certificate and the
// apps again.
func (h *hostRuntime) refresh(ctx context.Context) {
	s := h.s
	m := s.cfg.Hostnames
	if m == nil {
		return
	}
	set, err := m.Store.Load(ctx)
	if err != nil {
		return
	}
	certBase, leaf := m.Certs.Wildcard()
	desk := "nas"
	if v, err := s.cfg.DB.GetSetting(ctx, publish.SettingDesktopName); err == nil && v != "" {
		desk = v
	}
	remoteBase, _ := s.cfg.DB.GetSetting(ctx, publish.SettingBaseDomain)
	// The last base the hostnames were for: names under it are refused
	// while they're off, even after the token is gone.
	lastBase, _ := s.cfg.DB.GetSetting(ctx, settingLastBase)
	if st, err := m.DNS.Status(ctx); err == nil && st.Set && st.Base != "" && st.Base != lastBase {
		lastBase = st.Base
		_ = s.cfg.DB.SetSetting(ctx, settingLastBase, lastBase)
	}
	problem := ""
	active := set.Enabled && leaf != nil && certBase != ""
	if active && remoteBase != "" && remoteBase != certBase {
		active, problem = false, "Remote Access's base domain ("+remoteBase+") isn't the hostnames' ("+certBase+")"
	}
	if active && hostnames.Reserved(desk) {
		active, problem = false, "the desktop's name ("+desk+") is one of HardyOS's own names; change it in Remote Access"
	}
	// The wildcard is only ever served while the names are (decision 450).
	m.Certs.SetActive(active)
	base := certBase
	if !active || base == "" {
		base = lastBase
	}
	var list map[string]apps.App
	known := false
	if o, err := s.appsStatus(ctx); err == nil {
		list, known = map[string]apps.App{}, true
		for _, a := range o.Apps {
			if a.Web != nil {
				list[a.ID] = a
			}
		}
	}
	h.mu.Lock()
	changed := h.active != active || (active && h.base != base)
	h.active, h.base, h.desktop, h.problem = active, base, desk, problem
	if known {
		h.apps, h.appsKnow = list, true
	}
	if !active {
		h.proxies = map[string]*hostProxy{}
	}
	h.mu.Unlock()
	if changed {
		// Immich's redirect URIs follow photos.<base> (decision 458).
		s.photosNudge()
	}
}

const settingLastBase = "hostnames.last_base"

func (h *hostRuntime) app(id string) (apps.App, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	a, ok := h.apps[id]
	return a, ok
}

// appForLabel finds the app a label names.
func (h *hostRuntime) appForLabel(label string) (apps.App, bool) {
	switch label {
	case hostnames.PhotosLabel:
		return h.app(photos.AppID)
	case hostnames.MailLabel:
		return h.app(WebmailAppID)
	}
	if hostnames.Reserved(label) || !validAppLabel(label) {
		return apps.App{}, false
	}
	return h.app(label)
}

// appIDForLabel is the app id a label names, whether or not the app is
// here (photos and mail are their apps' names).
func appIDForLabel(label string) (string, bool) {
	switch label {
	case hostnames.PhotosLabel:
		return photos.AppID, true
	case hostnames.MailLabel:
		// Webmail is each server's own (its mail server, decision 472).
		return "", false
	}
	if label == WebmailAppID || hostnames.Reserved(label) || !validAppLabel(label) || apps.ValidID(label) != nil {
		return "", false
	}
	return label, true
}

func validAppLabel(l string) bool {
	return cfdns.ValidDomain(l+".x.example") && !strings.Contains(l, ".")
}

// RunHostnames keeps the hostnames' state current and the certificate
// renewed until ctx ends.
func (s *Server) RunHostnames(ctx context.Context) {
	m := s.cfg.Hostnames
	if m == nil {
		return
	}
	if err := m.LoadInstalled(ctx); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.log.Info("hostnames: no certificate in service yet", "err", err)
	}
	h := s.hosts
	h.refresh(ctx)
	sub := s.cfg.Events.Subscribe(0, true, 256)
	defer s.cfg.Events.Unsubscribe(sub)
	t := time.NewTicker(hostRefresh)
	defer t.Stop()
	renew := time.NewTimer(time.Minute)
	defer renew.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if b, _ := m.Certs.Wildcard(); b == "" {
				// hardyd-priv may not have answered at start.
				_ = m.LoadInstalled(ctx)
			}
			h.refresh(ctx)
			h.sweepCodes()
		case e, ok := <-sub.C:
			if !ok {
				return
			}
			if id := finishedAppJob(e); id != "" {
				h.dropProxy(id)
				h.refresh(ctx)
			}
		case <-renew.C:
			s.renewHostnames(ctx)
			renew.Reset(12 * time.Hour)
		}
	}
}

// renewHostnames starts a certificate job when one is due (none yet, another
// base, or within 30 days of expiry), unless one failed recently.
func (s *Server) renewHostnames(ctx context.Context) {
	m := s.cfg.Hostnames
	set, err := m.Store.Load(ctx)
	if err != nil || !set.Enabled || s.cfg.Jobs == nil {
		return
	}
	st, err := m.DNS.Status(ctx)
	if err != nil || !st.Set || !m.Due(st.Base) {
		return
	}
	if _, failed, err := m.Store.Last(ctx); err == nil && failed != nil && time.Since(failed.At) < hostnames.RetryAfter {
		return
	}
	if _, err := s.cfg.Jobs.Submit(ctx, JobKindHostnamesIssue, "Renew the hostnames' certificate", hostIssueParams{Auto: true}, nil); err != nil {
		s.log.Warn("hostnames: renewal", "err", err)
		return
	}
	s.recordSystem(ctx, "hostnames.renew", "*."+st.Base, "certificate due")
}

func (h *hostRuntime) sweepCodes() {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, c := range h.codes {
		if now.After(c.expires) {
			delete(h.codes, k)
		}
	}
}

func (h *hostRuntime) dropProxy(appID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.proxies, appID)
}

// serve handles a request whose Host is a name under the base, reporting
// whether it did (false: the desktop's own routes).
func (h *hostRuntime) serve(w http.ResponseWriter, r *http.Request) bool {
	active, base, desk := h.snapshot()
	if base == "" || r.TLS == nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(hostOnly(r.Host), "."))
	label, ok := strings.CutSuffix(host, "."+base)
	if !ok || label == "" {
		return false
	}
	s := h.s
	if strings.Contains(label, ".") {
		// x.photos.<base>: no name of HardyOS's (decision 456).
		proxyPage(w, http.StatusNotFound, "Nothing is here", "No HardyOS app has this address.")
		return true
	}
	if !active {
		switch label {
		case desk:
			return false
		case hostnames.SSOLabel:
			// The provider may still be reached here (NetBird's name); never
			// the desktop.
			if s.oidc != nil && s.oidc.Owns(r) {
				s.serveProvider(w, r, time.Now())
				return true
			}
		}
		hostsOffPage(w)
		return true
	}
	switch label {
	case desk:
		switch {
		case r.URL.Path == hostBindPath:
			h.bind(w, r)
			return true
		case r.URL.Path == "/oidc" || strings.HasPrefix(r.URL.Path, "/oidc/"):
			// The old path-based issuer: the provider lives at sso.<base>.
			if s.oidc != nil && s.oidc.Issuer(r.Context()) == publish.SSOIssuerFor(base) && !s.oidc.Owns(r) {
				u := url.URL{Scheme: "https", Host: hostnames.SSOLabel + "." + base, Path: strings.TrimPrefix(r.URL.Path, "/oidc"), RawQuery: r.URL.RawQuery}
				if u.Path == "" {
					u.Path = "/"
				}
				http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
				return true
			}
		}
		return false
	case hostnames.SSOLabel:
		if s.oidc == nil || !s.oidc.Owns(r) {
			proxyPage(w, http.StatusNotFound, "Nothing here", "This address is HardyOS's sign-in.")
			return true
		}
		s.serveProvider(w, r, time.Now())
		return true
	case hostnames.FilesLabel:
		if !strings.HasPrefix(r.URL.Path, "/s/") || strings.HasPrefix(r.URL.Path, "/s/-/ds/") {
			proxyPage(w, http.StatusNotFound, "Nothing here", "This address only opens share links.")
			return true
		}
		r2 := r.Clone(r.Context())
		dropCookie(r2.Header, SessionCookie)
		dropCookie(r2.Header, LegacySessionCookie)
		s.serveDesktop(w, r2)
		return true
	case hostnames.OfficeLabel:
		h.serveOffice(w, r)
		return true
	case hostnames.MailLabel:
		if mailPublicPath(r.URL.Path) {
			r2 := r.Clone(r.Context())
			dropCookie(r2.Header, SessionCookie)
			dropCookie(r2.Header, LegacySessionCookie)
			s.serveDesktop(w, r2)
			return true
		}
	}
	a, ok := h.appForLabel(label)
	if !ok {
		// Not this server's: in a cluster, the member running it (decision
		// 494).
		if id, ok := appIDForLabel(label); ok && h.s.windows != nil {
			node, many := h.s.windows.route(r.Context(), id)
			switch {
			case node != "":
				if canon := labelFor(id); canon != label {
					u := url.URL{Scheme: "https", Host: canon + "." + base, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
					http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
					return true
				}
				h.serveRemote(w, r, node, id)
				return true
			case len(many) > 1:
				names := make([]string, len(many))
				for i, n := range many {
					names[i] = string(n)
				}
				proxyPage(w, http.StatusConflict, "This app runs on several servers",
					"It is installed on "+strings.Join(names, ", ")+". Open it from the HardyOS desktop on the server you want.")
				return true
			}
		}
		proxyPage(w, http.StatusNotFound, "Nothing is here", "No HardyOS app has this address.")
		return true
	}
	if canon := labelFor(a.ID); canon != label {
		// immich.<base> (its id, as NetBird publishes it) is photos.<base>
		// here: one origin per app.
		u := url.URL{Scheme: "https", Host: canon + "." + base, Path: r.URL.Path, RawQuery: r.URL.RawQuery}
		http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
		return true
	}
	h.serveApp(w, r, a)
	return true
}

// stateHash is the hash of a state cookie as the bind request carries it.
func stateHash(v string) string {
	s := sha256.Sum256([]byte("hardyos host state\x00" + v))
	return hex.EncodeToString(s[:])
}

// startBind sends a browser without a session on an app host to the
// desktop host to get one.
func (h *hostRuntime) startBind(w http.ResponseWriter, r *http.Request, appID string) {
	desk := h.desktopHost()
	if desk == "" || !isNavigation(r) {
		proxyPage(w, http.StatusUnauthorized, "Sign in to HardyOS first", "Open this app from the HardyOS desktop.")
		return
	}
	state := randomToken()
	http.SetCookie(w, &http.Cookie{Name: hostStateCookie, Value: state, Path: "/", MaxAge: 300,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	q := url.Values{"app": {appID}, "s": {stateHash(state)}, "next": {safeNext(r.URL.RequestURI())}}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, "https://"+desk+hostBindPath+"?"+q.Encode(), http.StatusSeeOther)
}

var stateHashOK = func(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

// bind runs on the desktop host: the desktop session there becomes a code
// for the app host the browser came from.
func (h *hostRuntime) bind(w http.ResponseWriter, r *http.Request) {
	s := h.s
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	if r.Method != http.MethodGet {
		proxyPage(w, http.StatusMethodNotAllowed, "Open the app again", "Open it from the HardyOS desktop.")
		return
	}
	q := r.URL.Query()
	if site := strings.ToLower(r.Header.Get("Sec-Fetch-Site")); site == "cross-site" {
		// Started from another site: one click on this page makes it
		// same-origin. Safe either way: the code only ever goes to the app
		// host, and only the browser holding the state cookie can use it.
		q.Del("again")
		hostContinuePage(w, hostBindPath+"?"+q.Encode())
		return
	}
	appID, sh, next := q.Get("app"), q.Get("s"), safeNext(q.Get("next"))
	if !stateHashOK(sh) {
		proxyPage(w, http.StatusBadRequest, "Open the app again", "This sign-in link isn't complete.")
		return
	}
	target := h.hostURL(appID)
	if target == "" {
		proxyPage(w, http.StatusNotFound, "No such app", "Open the app from the HardyOS desktop.")
		return
	}
	tok, ok := s.sessionToken(r)
	if !ok && q.Get("again") == "" {
		// Opened from another site (a link in an email): the desktop's
		// SameSite=Strict cookie stayed behind. One click here is
		// same-site and brings it along.
		q.Set("again", "1")
		hostContinuePage(w, hostBindPath+"?"+q.Encode())
		return
	}
	if !ok {
		proxyPage(w, http.StatusUnauthorized, "Sign in to HardyOS first",
			"Sign in to the desktop at https://"+h.desktopHost()+" in this browser, then open the app again.")
		return
	}
	info, err := s.peekSession(r.Context(), tok)
	if err != nil {
		proxyPage(w, http.StatusUnauthorized, "Sign in to HardyOS first", "Your desktop session has ended. Sign in again.")
		return
	}
	u, err := s.sessionUser(r, tok, info.UserID)
	if err != nil {
		proxyPage(w, http.StatusForbidden, "You can't use this app right now", "Your account can't be used right now.")
		return
	}
	// The two-factor rules of the desktop session hold for what it hands
	// out (decisions 441, 442): no app-host session from a session without
	// a second factor from outside, nor for an administrator who must set
	// one up first.
	switch s.sessionGate(r, info, u) {
	case gateOutside:
		proxyPage(w, http.StatusUnauthorized, "Sign in again", "From outside, sign in to the desktop again with two-factor sign-in, then open the app.")
		return
	case gateEnroll:
		proxyPage(w, http.StatusForbidden, "Set up two-factor sign-in first", "Administrators must set up two-factor sign-in on the desktop before opening apps.")
		return
	}
	var remote cluster.NodeID
	if appID == hostOfficeID {
		if s.office == nil || !s.office.enabled(r.Context()) {
			proxyPage(w, http.StatusNotFound, "The office suite is off", "Turn it on in Control Panel › Office.")
			return
		}
	} else if _, ok := h.app(appID); ok {
		may, err := s.mayUse(r.Context(), tok, u, appID)
		if err != nil || !may {
			s.record(r, u, "apps.open", appID, audit.Denied, "hostname")
			proxyPage(w, http.StatusForbidden, "You can't use this app", "An administrator hasn't given you this app.")
			return
		}
	} else {
		// An app another member runs (decision 494): its owner decides,
		// as the person this desktop session is.
		node := cluster.NodeID("")
		if s.windows != nil && appID != WebmailAppID { // webmail is each server's own
			node, _ = s.windows.route(r.Context(), appID)
		}
		if node == "" {
			proxyPage(w, http.StatusNotFound, "No such app", "Open the app from the HardyOS desktop.")
			return
		}
		if _, err := s.windows.check(r.Context(), r, u, tok, node, appID); err != nil {
			s.record(r, u, "apps.open", appID, audit.Denied, "hostname, on "+string(node))
			msg := "An administrator hasn't given you this app."
			if !errors.Is(err, errWindowForbidden) {
				msg = err.Error()
			}
			proxyPage(w, http.StatusForbidden, "You can't use this app", msg)
			return
		}
		remote = node
	}
	code := randomToken()
	h.mu.Lock()
	if h.codes == nil {
		h.codes = map[string]hostCode{}
	}
	ip := s.clientIP(r)
	now := time.Now()
	perSession, perIP := 0, 0
	for k, c := range h.codes {
		if now.After(c.expires) {
			delete(h.codes, k)
			continue
		}
		if c.desktopToken == tok {
			perSession++
		}
		if c.ip == ip {
			perIP++
		}
	}
	full := len(h.codes) >= maxHostCodes || perSession >= maxCodesEach || perIP >= maxCodesEach
	if !full {
		h.codes[stateHash(code)] = hostCode{appID: appID, userID: u.ID, desktopToken: tok, stateHash: sh, next: next, ip: ip, expires: now.Add(hostCodeTTL), remote: remote}
	}
	h.mu.Unlock()
	if full {
		proxyPage(w, http.StatusTooManyRequests, "Try again in a minute", "Too many sign-ins are waiting.")
		return
	}
	http.Redirect(w, r, target+hostCallback+"?code="+url.QueryEscape(code), http.StatusSeeOther)
}

// hostContinuePage asks for one click to carry on signing in to an app.
func hostContinuePage(w http.ResponseWriter, next string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Open the app</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0B0F19;color:#E6EAF2;font:15px/1.5 "Plus Jakarta Sans",system-ui,sans-serif}
main{max-width:420px;padding:28px 32px;border-radius:16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12)}
h1{margin:0 0 8px;font-size:18px}p{margin:0 0 16px;color:#A7B0C2}a{display:inline-block;padding:8px 16px;border-radius:10px;background:linear-gradient(90deg,#00F0FF,#8B5CFF);color:#0B0F19;font-weight:600;text-decoration:none}</style></head>
<body><main><h1>Open the app</h1><p>This app opens with your HardyOS sign-in.</p><a href="`+html.EscapeString(next)+`">Continue</a></main></body></html>`)
}

// callback runs on an app host: a code from the desktop host plus the
// state cookie it was made for become this host's session.
func (h *hostRuntime) callback(w http.ResponseWriter, r *http.Request, appID string, remote cluster.NodeID) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	code := r.URL.Query().Get("code")
	h.mu.Lock()
	c, ok := h.codes[stateHash(code)]
	delete(h.codes, stateHash(code)) // single use
	h.mu.Unlock()
	st, err := r.Cookie(hostStateCookie)
	http.SetCookie(w, &http.Cookie{Name: hostStateCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	if !ok || code == "" || time.Now().After(c.expires) || c.appID != appID || c.remote != remote || err != nil || !sameSecret(stateHash(st.Value), c.stateHash) {
		proxyPage(w, http.StatusForbidden, "Open the app again", "This sign-in was started in another browser or has expired.")
		return
	}
	p := h.s.proxy
	p.init()
	key := randomToken()
	now := time.Now()
	p.mu.Lock()
	p.sessions[key] = &proxySession{appID: appID, userID: c.userID, desktopToken: c.desktopToken, expires: now.Add(proxySessionTTL), checked: now, host: true, remote: remote}
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: hostCookie, Value: key, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, safeNext(c.next), http.StatusSeeOther)
}

// session finds a request's host session for an app, as it routes now
// (remote: the member running it; "" this server): a session made for an
// app on another member is never good once the app is here, and the
// other way round.
func (h *hostRuntime) session(r *http.Request, appID string, remote cluster.NodeID) (*proxySession, string) {
	c, err := r.Cookie(hostCookie)
	if err != nil {
		return nil, ""
	}
	p := h.s.proxy
	p.mu.Lock()
	defer p.mu.Unlock()
	ss := p.sessions[c.Value]
	if ss == nil || !ss.host || ss.appID != appID || ss.remote != remote || time.Now().After(ss.expires) {
		return nil, ""
	}
	return ss, c.Value
}

// checkSession finds and rechecks the request's session; false means the
// response was written (sign-in started or refused).
func (h *hostRuntime) checkSession(w http.ResponseWriter, r *http.Request, appID string, remote cluster.NodeID) (*proxySession, string, bool) {
	ss, key := h.session(r, appID, remote)
	if ss == nil {
		h.startBind(w, r, appID)
		return nil, "", false
	}
	p := h.s.proxy
	if !p.recheck(r, ss) {
		p.end(key, ss)
		http.SetCookie(w, &http.Cookie{Name: hostCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
		proxyPage(w, http.StatusForbidden, "You can't use this app right now",
			"Your HardyOS sign-in ended or an administrator changed who may use it. Open it again from the desktop.")
		return nil, "", false
	}
	return ss, key, true
}

// serveRemote serves an app another member runs at its hostname here
// (decision 494): the same bounce and host session as a local app (this
// server's desktop session and two-factor gate), each request relayed to
// the owner as the person, whose access list the owner checks.
func (h *hostRuntime) serveRemote(w http.ResponseWriter, r *http.Request, node cluster.NodeID, appID string) {
	if r.URL.Path == hostCallback {
		h.callback(w, r, appID, node)
		return
	}
	if why := crossSiteRequest(r, "https://"+r.Host); why != "" {
		proxyPage(w, http.StatusForbidden, "Blocked a request from another page", why)
		return
	}
	ss, key, ok := h.checkSession(w, r, appID, node)
	if !ok {
		return
	}
	if filterAppRequest(w, r, appID) {
		return
	}
	ctx := context.WithValue(r.Context(), windowUserKey{}, ss.userID)
	ctx = context.WithValue(ctx, windowDeskKey{}, ss.desktopToken)
	r = r.WithContext(ctx)
	h.remoteProxyFor(node, appID).ServeHTTP(&trackingWriter{ResponseWriter: w, p: h.s.proxy, key: key, ss: ss}, r)
}

// remoteProxyFor is the reverse proxy to an app on another member, over
// the cluster relay (made per request: the owner can change).
func (h *hostRuntime) remoteProxyFor(node cluster.NodeID, appID string) *httputil.ReverseProxy {
	h.mu.Lock()
	frame := "frame-ancestors 'self' https://" + h.desktop + "." + h.base
	h.mu.Unlock()
	target := &url.URL{Scheme: "https", Host: string(node)}
	return &httputil.ReverseProxy{
		Transport: h.s.windows.transport(node, appID),
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // signed into the relay's assertion
			pr.Out.Header.Del("Forwarded")
			gatewayRequestCookies(pr.Out.Header)
			h.dropTossedCookies(pr.Out.Header, appID)
		},
		ModifyResponse: func(resp *http.Response) error {
			gatewayFixResponse(resp, target, hostOnly(resp.Request.Host), frame)
			h.learnCookies(resp.Header, appID)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			proxyPage(w, http.StatusBadGateway, "The app isn't answering",
				"It runs on "+string(node)+", which may be starting or unreachable. Reload in a moment.")
		},
	}
}

func (h *hostRuntime) serveApp(w http.ResponseWriter, r *http.Request, a apps.App) {
	if r.URL.Path == hostCallback {
		h.callback(w, r, a.ID, "")
		return
	}
	if why := crossSiteRequest(r, "https://"+r.Host); why != "" {
		proxyPage(w, http.StatusForbidden, "Blocked a request from another page", why)
		return
	}
	ss, key, ok := h.checkSession(w, r, a.ID, "")
	if !ok {
		return
	}
	if filterAppRequest(w, r, a.ID) {
		return
	}
	p := h.s.proxy
	webmail := a.ID == WebmailAppID && a.Source == apps.SourceCatalog
	if webmail {
		if c, ok := p.webmailCreds(r, ss, key); ok {
			r = r.WithContext(context.WithValue(r.Context(), webmailKey{}, c))
		}
	}
	r = r.WithContext(context.WithValue(r.Context(), hostClientKey{}, h.s.clientIP(r)))
	h.proxyFor(a, webmail).ServeHTTP(&trackingWriter{ResponseWriter: w, p: p, key: key, ss: ss}, r)
}

type hostClientKey struct{}

// proxyFor is the reverse proxy to an app (made once per target).
func (h *hostRuntime) proxyFor(a apps.App, webmail bool) *httputil.ReverseProxy {
	target := appTarget(a)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.proxies == nil {
		h.proxies = map[string]*hostProxy{}
	}
	key := target.String() + " " + h.desktop + "." + h.base
	if hp := h.proxies[a.ID]; hp != nil && hp.target == key {
		return hp.rp
	}
	frame := "frame-ancestors 'self' https://" + h.desktop + "." + h.base
	appID := a.ID
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			client, _ := pr.In.Context().Value(hostClientKey{}).(string)
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Set("X-Forwarded-For", client)
			pr.Out.Header.Set("X-Real-Ip", client)
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			gatewayRequestCookies(pr.Out.Header)
			h.dropTossedCookies(pr.Out.Header, appID)
			if webmail {
				// Only HardyOS signs people in to webmail (decision 305).
				pr.Out.Header.Del("Authorization")
				if c, ok := pr.In.Context().Value(webmailKey{}).(webmailCreds); ok {
					pr.Out.SetBasicAuth(c.address, c.token)
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			gatewayFixResponse(resp, target, hostOnly(resp.Request.Host), frame)
			h.learnCookies(resp.Header, appID)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			proxyPage(w, http.StatusBadGateway, "The app isn't answering",
				"It may be starting or stopped. Check it in the App Store, then reload.")
		},
	}
	h.proxies[a.ID] = &hostProxy{target: key, rp: rp}
	return rp
}

// learnCookies remembers the cookie names an app host's own responses set.
func (h *hostRuntime) learnCookies(hdr http.Header, appID string) {
	lines := hdr.Values("Set-Cookie")
	if len(lines) == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cookies == nil {
		h.cookies = map[string]map[string]bool{}
	}
	set := h.cookies[appID]
	if set == nil {
		set = map[string]bool{}
		h.cookies[appID] = set
	}
	for _, l := range lines {
		nv, _, _ := strings.Cut(l, ";")
		name, _, _ := strings.Cut(nv, "=")
		if name = strings.TrimSpace(name); name != "" && len(set) < maxLearnedCookies {
			set[name] = true
		}
	}
}

// dropTossedCookies removes cookies a sibling app host could have set for
// the whole base (a script's document.cookie with Domain=<base>): names
// another app host's responses set and this one's never did, and every
// name sent more than once (one of them isn't this host's own).
func (h *hostRuntime) dropTossedCookies(hdr http.Header, appID string) {
	lines := hdr.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	h.mu.Lock()
	own := h.cookies[appID]
	others := map[string]bool{}
	for id, set := range h.cookies {
		if id == appID {
			continue
		}
		for n := range set {
			others[n] = true
		}
	}
	h.mu.Unlock()
	type kv struct{ name, part string }
	var parts []kv
	count := map[string]int{}
	for _, line := range lines {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			name, _, _ := strings.Cut(part, "=")
			name = strings.TrimSpace(name)
			if part == "" {
				continue
			}
			parts = append(parts, kv{name, part})
			count[name]++
		}
	}
	var keep []string
	for _, p := range parts {
		if count[p.name] > 1 || (others[p.name] && !own[p.name]) {
			continue
		}
		keep = append(keep, p.part)
	}
	hdr.Del("Cookie")
	if len(keep) > 0 {
		hdr.Set("Cookie", strings.Join(keep, "; "))
	}
}

// serveOffice is office.<base>: the office origin's routes, with the
// desktop's editor window signed in through the bounce.
func (h *hostRuntime) serveOffice(w http.ResponseWriter, r *http.Request) {
	rt := h.s.office
	if rt == nil || !rt.enabled(r.Context()) {
		proxyPage(w, http.StatusNotFound, "The office suite is off", "Turn it on in Control Panel › Office.")
		return
	}
	switch r.URL.Path {
	case hostCallback:
		h.callback(w, r, hostOfficeID, "")
		return
	case "/s/-/office/editor":
		ss, _, ok := h.checkSession(w, r, hostOfficeID, "")
		if !ok {
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), officeDesktopKey{}, ss.desktopToken))
	}
	rt.handler().ServeHTTP(w, r)
}

// officeDesktopKey carries the desktop session an office host session
// follows (the editor ticket must have been made for it).
type officeDesktopKey struct{}

// redirectOld sends a request that reached an app's window proxy port, or
// the office port, by a name under the base to the app's own hostname,
// reporting whether it did. By address (or another name) the old origins
// keep working: those devices may not resolve the hostnames.
func (h *hostRuntime) redirectOld(w http.ResponseWriter, r *http.Request, appID string) bool {
	if h == nil || !h.underBase(r.Host) {
		return false
	}
	target := h.hostURL(appID)
	if target == "" {
		return false
	}
	path := r.URL.RequestURI()
	if r.URL.Path == proxyAuthPath {
		path = "/" // the old one-time token is the window proxy's
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		path = "/"
	}
	http.Redirect(w, r, target+path, http.StatusPermanentRedirect)
	return true
}

// appOpenURL is where the desktop opens an app while it is used by its
// hostname.
func (h *hostRuntime) appOpenURL(r *http.Request, a apps.App) (string, bool) {
	if viaGateway(r) || !h.onDesktopHost(r) {
		return "", false
	}
	if _, ok := h.app(a.ID); !ok {
		return "", false
	}
	u := h.hostURL(a.ID)
	if u == "" {
		return "", false
	}
	return u + webPath(a.Web), true
}

// officeOrigin is the office editor's origin for a desktop on its hostname.
func (h *hostRuntime) officeOrigin(r *http.Request) (string, bool) {
	if viaGateway(r) || !h.onDesktopHost(r) {
		return "", false
	}
	u := h.hostURL(hostOfficeID)
	return u, u != ""
}

// officeHost is office.<base> while hostnames are on.
func (h *hostRuntime) officeHost() string {
	return strings.TrimPrefix(h.hostURL(hostOfficeID), "https://")
}

// lanLabels lists every name the hostnames serve now.
func (h *hostRuntime) lanLabels(ctx context.Context) []string {
	_, _, desk := h.snapshot()
	out := []string{desk, hostnames.SSOLabel, hostnames.FilesLabel}
	if h.s.office != nil && h.s.office.enabled(ctx) {
		out = append(out, hostnames.OfficeLabel)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.apps[photos.AppID]; ok {
		out = append(out, hostnames.PhotosLabel)
	}
	if _, ok := h.apps[WebmailAppID]; ok {
		out = append(out, hostnames.MailLabel)
	}
	for id := range h.apps {
		if id != desk && labelFor(id) == id && !hostnames.Reserved(id) && validAppLabel(id) {
			out = append(out, id)
		}
	}
	return out
}

// serveDesktop is hardyd's own routes without the hostnames' (share links
// and mail settings on their hosts).
func (s *Server) serveDesktop(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(context.WithValue(r.Context(), hostsDoneKey{}, true))
	s.ServeHTTP(w, r)
}

type hostsDoneKey struct{}
