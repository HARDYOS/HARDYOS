package api

// The app window proxy. The desktop is served over HTTPS, so an app's own
// http:// page can't be shown in a desktop window (browsers block mixed
// content, and many apps refuse to be framed). hardyd runs a small HTTPS
// reverse proxy for every installed app with a web page, on its own port
// (44300 + n, kept in hardyd's database), with the desktop's certificate.
//
// Ports don't isolate apps. Browsers keep cookies per host, not per port,
// and SameSite counts every port of a host as the same site, so the
// desktop and every app proxy share one cookie jar and are "same-site" to
// each other. Per-app subdomains (with the reverse proxy, later) are the
// real fix; until then the proxy hardens what it can:
//
//   - Cookies: every Set-Cookie from an app is renamed a_<app id>_<name>
//     (after a __Host-/__Secure- prefix), loses any Domain attribute, and is
//     dropped if it is named hardyos_*. Requests to an app's proxy carry only
//     that app's cookies, renamed back; HardyOS's own cookies and other
//     apps' never reach it. Cookies an app's page sets from JavaScript can't
//     be renamed: they stay shared by every port on the host (docs/apps.md).
//   - Cross-app requests: non-GET/HEAD requests and every WebSocket upgrade
//     with an Origin other than the proxy's own are refused, and so is any
//     same-site or cross-site request that isn't a navigation (Sec-Fetch-*),
//     so another app's page can't post to, embed or read this one.
//   - Sign-in: the desktop's session cookie must never reach an app, so
//     POST /apps/{id}/open mints a short-lived, single-use token bound to the
//     desktop session. The proxy swaps it for an HttpOnly, SameSite=Strict
//     cookie for that app only, and only for a frame or page load (not a
//     fetch, image or script) in a browser that holds that same desktop
//     session (its hardyos_session cookie reaches every port), so another
//     app can't sign someone into its own token (login CSRF).
//   - The proxy session follows the desktop session: every request needs
//     the same desktop session cookie, which is checked (without extending
//     its idle timeout) together with the account and the app's access
//     list at most every 30 seconds. WebSockets are tracked and closed when
//     a check fails, on a 30-second sweep, on sign-out, when access
//     changes, and when the app is removed, reconfigured, updated or rolled
//     back.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
)

// Window proxy settings.
const (
	DefaultAppProxyBase = 44300
	proxyAuthPath       = "/__hardyos/auth"
	proxyCookiePrefix   = "hardyos_app_"
	proxyTokenTTL       = time.Minute
	proxySessionTTL     = 12 * time.Hour
)

// proxyRecheck is how often a proxy session checks the desktop session and
// the app's access list again on a request, and proxySweep how often every
// session (WebSockets included) is checked (variables for tests).
var (
	proxyRecheck = 30 * time.Second
	proxySweep   = 30 * time.Second
)

// AppProxyOptions configures the window proxy.
type AppProxyOptions struct {
	// TLS is the desktop's certificate; nil serves plain HTTP (development).
	TLS *tls.Config
	// BasePort is the first proxy port (default 44300).
	BasePort int
	// ListenHost is the address to listen on ("" = every address); hardyd
	// passes the desktop's own listen host.
	ListenHost string
	// DesktopPort is the desktop's own port, for frame-ancestors (0 = the
	// scheme's default).
	DesktopPort int
	// Interval between checks for installed and removed apps (default 20s).
	Interval time.Duration
}

type appProxy struct {
	s *Server

	mu        sync.Mutex
	opts      AppProxyOptions
	running   bool
	listeners map[string]*proxyListener
	tokens    map[string]proxyToken
	sessions  map[string]*proxySession
}

type proxyListener struct {
	appID  string
	port   int
	target atomic.Pointer[url.URL]
	srv    *http.Server
}

type proxyToken struct {
	appID        string
	userID       int64
	desktopToken string
	next         string
	expires      time.Time
}

type proxySession struct {
	appID        string
	userID       int64
	desktopToken string
	expires      time.Time
	checked      time.Time
	// conns are the session's hijacked connections (WebSockets).
	conns map[*trackedConn]struct{}
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// RunAppProxy serves every installed app's window proxy until ctx ends.
func (s *Server) RunAppProxy(ctx context.Context, opts AppProxyOptions) {
	p := s.proxy
	if opts.BasePort == 0 {
		opts.BasePort = DefaultAppProxyBase
	}
	if opts.Interval == 0 {
		opts.Interval = 20 * time.Second
	}
	// Finished app jobs change what the proxy serves: watch for them.
	sub := s.cfg.Events.Subscribe(0, true, 256)
	defer s.cfg.Events.Unsubscribe(sub)
	p.mu.Lock()
	p.opts, p.running = opts, true
	p.listeners = map[string]*proxyListener{}
	p.tokens = map[string]proxyToken{}
	p.sessions = map[string]*proxySession{}
	p.mu.Unlock()
	defer p.stop()
	t := time.NewTicker(opts.Interval)
	defer t.Stop()
	sweep := time.NewTicker(proxySweep)
	defer sweep.Stop()
	p.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.reconcile(ctx)
		case <-sweep.C:
			p.sweep(ctx)
		case e, ok := <-sub.C:
			if !ok {
				return
			}
			if id := finishedAppJob(e); id != "" {
				p.dropApp(id)
				p.reconcile(ctx)
			}
		}
	}
}

// finishedAppJob returns the app id of an app job that just finished (it
// may have changed or removed the app), or "".
func finishedAppJob(e events.Event) string {
	if e.Type != events.TypeJobUpdated {
		return ""
	}
	var j struct {
		Kind   string     `json:"kind"`
		State  jobs.State `json:"state"`
		Params struct {
			ID string `json:"id"`
		} `json:"params"`
	}
	if json.Unmarshal(e.Data, &j) != nil || !j.State.Done() {
		return ""
	}
	switch j.Kind {
	case JobKindAppInstall, JobKindAppUpdate, JobKindAppRemove, JobKindAppReconfigure, JobKindAppRollback:
		return j.Params.ID
	}
	return ""
}

func (p *appProxy) stop() {
	p.mu.Lock()
	p.running = false
	var conns []*trackedConn
	for id, l := range p.listeners {
		_ = l.srv.Close() // doesn't close hijacked connections: those follow
		delete(p.listeners, id)
	}
	for k, ss := range p.sessions {
		conns = append(conns, p.endLocked(k, ss)...)
	}
	p.tokens = map[string]proxyToken{}
	p.mu.Unlock()
	closeAll(conns)
}

func (p *appProxy) isRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

func (p *appProxy) scheme() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.opts.TLS != nil {
		return "https"
	}
	return "http"
}

// endLocked forgets a session and returns its connections for closing
// (outside p.mu: closing a tracked connection takes it).
func (p *appProxy) endLocked(key string, ss *proxySession) []*trackedConn {
	delete(p.sessions, key)
	out := make([]*trackedConn, 0, len(ss.conns))
	for c := range ss.conns {
		out = append(out, c)
	}
	ss.conns = nil
	return out
}

func closeAll(conns []*trackedConn) {
	for _, c := range conns {
		_ = c.Close()
	}
}

// endSessions ends every session that match picks, closing its WebSockets.
func (p *appProxy) endSessions(match func(*proxySession) bool) {
	p.mu.Lock()
	var conns []*trackedConn
	for k, ss := range p.sessions {
		if match(ss) {
			conns = append(conns, p.endLocked(k, ss)...)
		}
	}
	p.mu.Unlock()
	closeAll(conns)
}

// endDesktopSession ends the app sessions opened from a desktop session
// (signing out).
func (p *appProxy) endDesktopSession(token string) {
	if token == "" {
		return
	}
	p.endSessions(func(ss *proxySession) bool { return ss.desktopToken == token })
}

// endUser ends every app session of an account (disabled, deleted, new
// password).
func (p *appProxy) endUser(userID int64) {
	p.endSessions(func(ss *proxySession) bool { return ss.userID == userID })
}

// dropApp stops an app's listener and ends its sessions and tokens; the
// next reconcile starts the listener again if the app still has a page.
func (p *appProxy) dropApp(appID string) {
	p.mu.Lock()
	if l := p.listeners[appID]; l != nil {
		_ = l.srv.Close()
		delete(p.listeners, appID)
	}
	for k, t := range p.tokens {
		if t.appID == appID {
			delete(p.tokens, k)
		}
	}
	p.mu.Unlock()
	p.endSessions(func(ss *proxySession) bool { return ss.appID == appID })
}

// recheckApp checks every session of an app now (its access list changed).
func (p *appProxy) recheckApp(ctx context.Context, appID string) {
	p.checkAll(ctx, func(ss *proxySession) bool { return ss.appID == appID })
}

// sweep checks every session, so open WebSockets end within proxySweep of
// the desktop session or the person's access ending.
func (p *appProxy) sweep(ctx context.Context) {
	p.checkAll(ctx, func(*proxySession) bool { return true })
}

func (p *appProxy) checkAll(ctx context.Context, which func(*proxySession) bool) {
	type item struct {
		key string
		ss  *proxySession
	}
	p.mu.Lock()
	var list []item
	for k, ss := range p.sessions {
		if which(ss) {
			list = append(list, item{k, ss})
		}
	}
	p.mu.Unlock()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	for _, it := range list {
		if time.Now().After(it.ss.expires) || !p.verify(req, it.ss) {
			p.end(it.key, it.ss)
		}
	}
}

// end forgets one session (if it's still there) and closes its WebSockets.
func (p *appProxy) end(key string, ss *proxySession) {
	p.mu.Lock()
	var conns []*trackedConn
	if cur := p.sessions[key]; cur == ss {
		conns = p.endLocked(key, ss)
	}
	p.mu.Unlock()
	closeAll(conns)
}

// reconcile starts proxies for new apps, stops them for removed ones and
// forgets expired sign-ins.
func (p *appProxy) reconcile(ctx context.Context) {
	o, err := p.s.appsStatus(ctx)
	if err != nil {
		return // the root helper may be restarting; try again later
	}
	want := map[string]bool{}
	for _, a := range o.Apps {
		if a.Web == nil {
			continue
		}
		want[a.ID] = true
		if _, err := p.ensure(ctx, a); err != nil {
			p.s.log.Warn("app window proxy", "app", a.ID, "err", err)
		}
	}
	now := time.Now()
	p.mu.Lock()
	for id, l := range p.listeners {
		if !want[id] {
			_ = l.srv.Close()
			delete(p.listeners, id)
		}
	}
	for k, t := range p.tokens {
		if now.After(t.expires) || !want[t.appID] {
			delete(p.tokens, k)
		}
	}
	var conns []*trackedConn
	for k, ss := range p.sessions {
		if now.After(ss.expires) || !want[ss.appID] {
			conns = append(conns, p.endLocked(k, ss)...)
		}
	}
	p.mu.Unlock()
	closeAll(conns)
}

func appTarget(a apps.App) *url.URL {
	scheme := "http"
	if a.Web.Scheme == "https" {
		scheme = "https"
	}
	return &url.URL{Scheme: scheme, Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(a.Web.Port))}
}

// ensure makes sure an app's proxy is listening and returns its port.
func (p *appProxy) ensure(ctx context.Context, a apps.App) (int, error) {
	if a.Web == nil {
		return 0, errors.New(a.Name + " has no web page")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return 0, errors.New("the window proxy isn't running")
	}
	target := appTarget(a)
	if l := p.listeners[a.ID]; l != nil {
		l.target.Store(target)
		return l.port, nil
	}
	st := p.s.appStore()
	ports, err := st.ProxyPorts(ctx)
	if err != nil {
		return 0, err
	}
	port := ports[a.ID]
	avoid := map[int]bool{}
	var ln net.Listener
	for try := 0; try < 20; try++ {
		if port == 0 {
			if port, err = st.AllocateProxyPort(ctx, a.ID, p.opts.BasePort, avoid); err != nil {
				return 0, err
			}
		}
		ln, err = net.Listen("tcp", net.JoinHostPort(p.opts.ListenHost, strconv.Itoa(port)))
		if err == nil {
			break
		}
		// Something else has that port: take the next one.
		avoid[port], port = true, 0
	}
	if err != nil {
		return 0, fmt.Errorf("no port to listen on: %w", err)
	}
	if p.opts.TLS != nil {
		cfg := p.opts.TLS.Clone()
		cfg.NextProtos = []string{"http/1.1"} // WebSockets over HTTP/2 aren't proxied
		ln = tls.NewListener(ln, cfg)
	}
	l := &proxyListener{appID: a.ID, port: port}
	l.target.Store(target)
	l.srv = &http.Server{
		Handler:           p.handler(l),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0), // TLS handshake noise from scanners
	}
	p.listeners[a.ID] = l
	go func() { _ = l.srv.Serve(ln) }()
	return port, nil
}

// mint returns a single-use sign-in token for an app's proxy.
func (p *appProxy) mint(appID string, userID int64, desktopToken, next string) string {
	tok := randomToken()
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, t := range p.tokens {
		if now.After(t.expires) {
			delete(p.tokens, k)
		}
	}
	p.tokens[tok] = proxyToken{appID: appID, userID: userID, desktopToken: desktopToken, next: next, expires: now.Add(proxyTokenTTL)}
	return tok
}

func proxyCookie(appID string) string { return proxyCookiePrefix + appID }

func (p *appProxy) handler(l *proxyListener) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(l.target.Load())
			pr.Out.Host = pr.In.Host // links the app builds point back at the proxy
			pr.SetXForwarded()
			appRequestCookies(pr.Out.Header, l.appID)
		},
		ModifyResponse: func(resp *http.Response) error {
			p.fixResponse(resp, l)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			proxyPage(w, http.StatusBadGateway, "The app isn't answering",
				"It may be starting or stopped. Check it in the App Store, then reload this window.")
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if why := p.crossAppRequest(r); why != "" {
			proxyPage(w, http.StatusForbidden, "Blocked a request from another page", why)
			return
		}
		if r.URL.Path == proxyAuthPath {
			p.signIn(w, r, l)
			return
		}
		ss, key := p.session(r, l)
		if ss == nil {
			proxyPage(w, http.StatusUnauthorized, "Sign in to HardyOS first",
				"Open this app from the HardyOS desktop to use it here.")
			return
		}
		if !p.recheck(r, ss) {
			p.end(key, ss)
			proxyPage(w, http.StatusForbidden, "You can't use this app right now",
				"Your HardyOS sign-in ended or an administrator changed who may use it. Open it again from the desktop.")
			return
		}
		rp.ServeHTTP(&trackingWriter{ResponseWriter: w, p: p, key: key, ss: ss}, r)
	})
}

// crossAppRequest says why a request looks like it comes from another page
// on this host (another app's proxy, which is "same-site" to this one), or "".
// The app's own requests are same-origin and pass; navigations (opening the
// app, links into it) pass, everything else from another origin doesn't.
func (p *appProxy) crossAppRequest(r *http.Request) string {
	own := p.scheme() + "://" + r.Host
	origin := r.Header.Get("Origin")
	upgrade := r.Header.Get("Upgrade") != "" && headerHasToken(r.Header, "Connection", "upgrade")
	if origin != "" && !strings.EqualFold(origin, own) {
		if upgrade {
			return "A WebSocket from another page can't connect to this app."
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			return "Another page can't send changes to this app."
		}
	}
	site := strings.ToLower(r.Header.Get("Sec-Fetch-Site"))
	if (site == "same-site" || site == "cross-site") && !strings.EqualFold(r.Header.Get("Sec-Fetch-Mode"), "navigate") {
		return "Another page can't load this app's content. Open the app from the HardyOS desktop."
	}
	return ""
}

func headerHasToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// desktopCookie is the desktop session cookie the browser sent (it reaches
// every port on the host).
func desktopCookie(r *http.Request) string {
	if c, err := r.Cookie(SessionCookie); err == nil {
		return c.Value
	}
	return ""
}

func sameSecret(a, b string) bool {
	return a != "" && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// signIn swaps a token from the desktop for this app's proxy cookie. Only
// for loading a frame or a page (Sec-Fetch-Dest iframe or document) that
// the desktop or the person started (Sec-Fetch-Site same-site or none), and
// only in the browser that holds the desktop session the token was minted
// for: the desktop's session cookie reaches this port too, so another app
// can't plant its own token in someone's window (login CSRF). Browsers that
// send no Sec-Fetch headers (plain http) rely on the session binding.
func (p *appProxy) signIn(w http.ResponseWriter, r *http.Request, l *proxyListener) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		proxyPage(w, http.StatusMethodNotAllowed, "This link has expired", "Open the app again from the HardyOS desktop.")
		return
	}
	dest := strings.ToLower(r.Header.Get("Sec-Fetch-Dest"))
	site := strings.ToLower(r.Header.Get("Sec-Fetch-Site"))
	if (dest != "" && dest != "iframe" && dest != "document") || (site != "" && site != "same-site" && site != "none") {
		proxyPage(w, http.StatusForbidden, "Open this app from the HardyOS desktop",
			"This sign-in link only works when the desktop opens it.")
		return
	}
	tok := r.URL.Query().Get("token")
	now := time.Now()
	p.mu.Lock()
	t, ok := p.tokens[tok]
	delete(p.tokens, tok) // single use, even when it's for another app
	p.mu.Unlock()
	if !ok || now.After(t.expires) || t.appID != l.appID {
		proxyPage(w, http.StatusForbidden, "This link has expired",
			"Open the app again from the HardyOS desktop.")
		return
	}
	if !sameSecret(desktopCookie(r), t.desktopToken) {
		proxyPage(w, http.StatusForbidden, "Open this app from your HardyOS desktop",
			"This link was made for another sign-in. Open the app from the desktop in this browser.")
		return
	}
	key := randomToken()
	p.mu.Lock()
	p.sessions[key] = &proxySession{appID: t.appID, userID: t.userID, desktopToken: t.desktopToken,
		expires: now.Add(proxySessionTTL), checked: now}
	tlsOn := p.opts.TLS != nil
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: proxyCookie(l.appID), Value: key, Path: "/",
		HttpOnly: true, Secure: tlsOn, SameSite: http.SameSiteStrictMode,
	})
	next := t.next
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, `\`) {
		next = "/"
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// session finds the request's proxy session. The browser must also send the
// desktop session it was opened from: a proxy cookie planted from another
// app's page (cookies set by scripts are shared by every port) is useless
// without the victim's own desktop session.
func (p *appProxy) session(r *http.Request, l *proxyListener) (*proxySession, string) {
	c, err := r.Cookie(proxyCookie(l.appID))
	if err != nil {
		return nil, ""
	}
	desk := desktopCookie(r)
	p.mu.Lock()
	defer p.mu.Unlock()
	ss := p.sessions[c.Value]
	if ss == nil || ss.appID != l.appID || time.Now().After(ss.expires) || !sameSecret(desk, ss.desktopToken) {
		return nil, ""
	}
	return ss, c.Value
}

// recheck confirms, at most every proxyRecheck, that the desktop session is
// still signed in and its user may still use the app.
func (p *appProxy) recheck(r *http.Request, ss *proxySession) bool {
	p.mu.Lock()
	fresh := time.Since(ss.checked) < proxyRecheck
	p.mu.Unlock()
	if fresh {
		return true
	}
	return p.verify(r, ss)
}

// verify checks a proxy session now: the desktop session (without
// extending its idle timeout), the account (with the same domain refresh
// as the desktop's own requests) and the app's access list.
func (p *appProxy) verify(r *http.Request, ss *proxySession) bool {
	s := p.s
	ctx := r.Context()
	info, err := s.peekSession(ctx, ss.desktopToken)
	if err != nil || info.UserID != ss.userID {
		return false
	}
	u, err := s.sessionUser(r, ss.desktopToken, info.UserID)
	if err != nil {
		return false
	}
	may, err := s.mayUse(ctx, ss.desktopToken, u, ss.appID)
	if err != nil || !may {
		return false
	}
	p.mu.Lock()
	ss.checked = time.Now()
	p.mu.Unlock()
	return true
}

// trackingWriter records connections the reverse proxy hijacks for
// WebSockets with their session, so they can be closed when it ends.
type trackingWriter struct {
	http.ResponseWriter
	p   *appProxy
	key string
	ss  *proxySession
}

func (w *trackingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *trackingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, brw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	tc := &trackedConn{Conn: c, p: w.p, ss: w.ss}
	w.p.mu.Lock()
	live := w.p.sessions[w.key] == w.ss // not ended while the request ran
	if live {
		if w.ss.conns == nil {
			w.ss.conns = map[*trackedConn]struct{}{}
		}
		w.ss.conns[tc] = struct{}{}
	}
	w.p.mu.Unlock()
	if !live {
		_ = c.Close()
		return nil, nil, errors.New("the app session ended")
	}
	return tc, brw, nil
}

// trackedConn is a hijacked connection of a proxy session.
type trackedConn struct {
	net.Conn
	p    *appProxy
	ss   *proxySession
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.p.mu.Lock()
		delete(c.ss.conns, c)
		c.p.mu.Unlock()
	})
	return c.Conn.Close()
}

// appCookiePrefix is what an app's cookies are renamed with in the browser.
// App ids have no "_", so one app's prefix is never the start of another's.
func appCookiePrefix(appID string) string { return "a_" + appID + "_" }

// splitCookiePrefix separates a __Host- or __Secure- prefix (which must stay
// first for the browser to enforce it) from the rest of a cookie name.
func splitCookiePrefix(name string) (prefix, base string) {
	for _, pre := range []string{"__Host-", "__Secure-"} {
		if len(name) >= len(pre) && strings.EqualFold(name[:len(pre)], pre) {
			return name[:len(pre)], name[len(pre):]
		}
	}
	return "", name
}

func isHardyCookie(base string) bool {
	return strings.HasPrefix(strings.ToLower(base), "hardyos_")
}

// rewriteSetCookie scopes one Set-Cookie line from an app to that app:
// name a_<id>_<name> (after a __Host-/__Secure- prefix), no Domain, every
// other attribute kept. Nameless cookies and ones named hardyos_* are
// dropped (ok false).
func rewriteSetCookie(line, appID string) (string, bool) {
	nv, attrs, _ := strings.Cut(line, ";")
	name, val, ok := strings.Cut(nv, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return "", false
	}
	pre, base := splitCookiePrefix(name)
	if base == "" || isHardyCookie(base) {
		return "", false
	}
	var b strings.Builder
	b.WriteString(pre + appCookiePrefix(appID) + base + "=" + strings.TrimSpace(val))
	for _, a := range strings.Split(attrs, ";") {
		a = strings.TrimSpace(a)
		k, _, _ := strings.Cut(a, "=")
		if a == "" || strings.EqualFold(strings.TrimSpace(k), "domain") {
			continue
		}
		b.WriteString("; " + a)
	}
	return b.String(), true
}

// appRequestCookies keeps only an app's own cookies on a request to it,
// under the names the app gave them. HardyOS's cookies (the desktop session,
// every app's proxy cookie) and other apps' cookies never reach it.
func appRequestCookies(h http.Header, appID string) {
	lines := h.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	prefix := appCookiePrefix(appID)
	var keep []string
	for _, line := range lines {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			name, val, _ := strings.Cut(part, "=")
			pre, base := splitCookiePrefix(strings.TrimSpace(name))
			if !strings.HasPrefix(base, prefix) {
				continue
			}
			orig := base[len(prefix):]
			if orig == "" || isHardyCookie(orig) {
				continue
			}
			keep = append(keep, pre+orig+"="+val)
		}
	}
	h.Del("Cookie")
	if len(keep) > 0 {
		h.Set("Cookie", strings.Join(keep, "; "))
	}
}

// fixResponse lets the desktop frame the app, scopes its cookies to it and
// keeps the app's redirects on the proxy.
func (p *appProxy) fixResponse(resp *http.Response, l *proxyListener) {
	h := resp.Header
	if lines := h.Values("Set-Cookie"); len(lines) > 0 {
		h.Del("Set-Cookie")
		for _, line := range lines {
			if nl, ok := rewriteSetCookie(line, l.appID); ok {
				h.Add("Set-Cookie", nl)
			}
		}
	}
	h.Del("X-Frame-Options")
	for _, key := range []string{"Content-Security-Policy", "Content-Security-Policy-Report-Only"} {
		vals := h.Values(key)
		h.Del(key)
		for _, v := range vals {
			if nv := stripFrameAncestors(v); nv != "" {
				h.Add(key, nv)
			}
		}
	}
	host := hostOnly(resp.Request.Host)
	h.Add("Content-Security-Policy", "frame-ancestors 'self' "+p.desktopOrigin(host))

	if loc := h.Get("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil && u.IsAbs() {
			target := l.target.Load()
			_, tport, _ := net.SplitHostPort(target.Host)
			// The app's own address, or the proxy's with http:// (apps that
			// ignore X-Forwarded-Proto).
			if u.Host == target.Host || u.Port() == tport || strings.EqualFold(u.Host, resp.Request.Host) {
				u.Scheme, u.Host = p.scheme(), resp.Request.Host
				h.Set("Location", u.String())
			}
		}
	}
}

// desktopOrigin is the desktop's origin as the browser reaches it.
func (p *appProxy) desktopOrigin(host string) string {
	p.mu.Lock()
	tlsOn, port := p.opts.TLS != nil, p.opts.DesktopPort
	p.mu.Unlock()
	scheme := "http"
	if tlsOn {
		scheme = "https"
	}
	if strings.Contains(host, ":") {
		// CSP can't name an IPv6 address; the proxy cookie is SameSite, so
		// other sites framing the app only get the sign-in page anyway.
		return scheme + ":"
	}
	o := scheme + "://" + host
	if port != 0 && !(tlsOn && port == 443) && !(!tlsOn && port == 80) {
		o += ":" + strconv.Itoa(port)
	}
	return o
}

// stripFrameAncestors removes frame-ancestors from a CSP header value (which
// may hold several policies separated by commas).
func stripFrameAncestors(v string) string {
	var policies []string
	for _, pol := range strings.Split(v, ",") {
		var dirs []string
		for _, d := range strings.Split(pol, ";") {
			d = strings.TrimSpace(d)
			name, _, _ := strings.Cut(d, " ")
			if d == "" || strings.EqualFold(name, "frame-ancestors") {
				continue
			}
			dirs = append(dirs, d)
		}
		if len(dirs) > 0 {
			policies = append(policies, strings.Join(dirs, "; "))
		}
	}
	return strings.Join(policies, ", ")
}

// proxyPage is the proxy's own small page (sign-in needed, app down).
func proxyPage(w http.ResponseWriter, status int, title, body string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>%s</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0B0F19;color:#E6EAF2;font:15px/1.5 "Plus Jakarta Sans",system-ui,sans-serif}
main{max-width:420px;padding:28px 32px;border-radius:16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12)}
h1{margin:0 0 8px;font-size:18px}p{margin:0;color:#A7B0C2}</style></head>
<body><main><h1>%s</h1><p>%s</p></main></body></html>`, html.EscapeString(title), html.EscapeString(title), html.EscapeString(body))
}

// frameSrc is the desktop's frame-src: itself and the app proxies on the
// same host.
func frameSrc(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := hostOnly(r.Host)
	if host == "" || strings.ContainsAny(host, ":;, '\"") {
		return "'self' " + scheme + ":"
	}
	return "'self' " + scheme + "://" + host + ":*"
}
