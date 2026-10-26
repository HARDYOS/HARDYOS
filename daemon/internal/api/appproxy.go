package api

// The app window proxy. The desktop is served over HTTPS, so an app's own
// http:// page can't be shown in a desktop window (browsers block mixed
// content, and many apps refuse to be framed). hardyd runs a small HTTPS
// reverse proxy for every installed app with a web page, on its own port
// (44300 + n, kept in hardyd's database), with the desktop's certificate.
//
// Sign-in: the desktop's session cookie isn't usable there (it belongs to
// the desktop and must never reach an app), so POST /apps/{id}/open mints a
// short-lived, single-use token. The first URL carries it; the proxy swaps it
// for an HttpOnly cookie for that app only. The proxy session follows the
// desktop session: it ends when that one does, and the app's access list is
// checked again every 30 seconds.

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
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
// the app's access list again (a variable for tests).
var proxyRecheck = 30 * time.Second

// AppProxyOptions configures the window proxy.
type AppProxyOptions struct {
	// TLS is the desktop's certificate; nil serves plain HTTP (development).
	TLS *tls.Config
	// BasePort is the first proxy port (default 44300).
	BasePort int
	// ListenHost is the address to listen on ("" = every address).
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
	p.mu.Lock()
	p.opts, p.running = opts, true
	p.listeners = map[string]*proxyListener{}
	p.tokens = map[string]proxyToken{}
	p.sessions = map[string]*proxySession{}
	p.mu.Unlock()
	defer p.stop()
	t := time.NewTicker(opts.Interval)
	defer t.Stop()
	for {
		p.reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *appProxy) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running = false
	for id, l := range p.listeners {
		_ = l.srv.Close()
		delete(p.listeners, id)
	}
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
	defer p.mu.Unlock()
	for id, l := range p.listeners {
		if !want[id] {
			_ = l.srv.Close()
			delete(p.listeners, id)
		}
	}
	for k, t := range p.tokens {
		if now.After(t.expires) {
			delete(p.tokens, k)
		}
	}
	for k, ss := range p.sessions {
		if now.After(ss.expires) || !want[ss.appID] {
			delete(p.sessions, k)
		}
	}
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
			stripHardyCookies(pr.Out.Header)
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
		if !p.recheck(r.Context(), ss) {
			p.mu.Lock()
			delete(p.sessions, key)
			p.mu.Unlock()
			proxyPage(w, http.StatusForbidden, "You can't use this app right now",
				"Your HardyOS sign-in ended or an administrator changed who may use it. Open it again from the desktop.")
			return
		}
		rp.ServeHTTP(w, r)
	})
}

// signIn swaps a token from the desktop for this app's proxy cookie.
func (p *appProxy) signIn(w http.ResponseWriter, r *http.Request, l *proxyListener) {
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
	key := randomToken()
	p.mu.Lock()
	p.sessions[key] = &proxySession{appID: t.appID, userID: t.userID, desktopToken: t.desktopToken,
		expires: now.Add(proxySessionTTL), checked: now}
	tlsOn := p.opts.TLS != nil
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: proxyCookie(l.appID), Value: key, Path: "/",
		HttpOnly: true, Secure: tlsOn, SameSite: http.SameSiteLaxMode,
	})
	next := t.next
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, `\`) {
		next = "/"
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (p *appProxy) session(r *http.Request, l *proxyListener) (*proxySession, string) {
	c, err := r.Cookie(proxyCookie(l.appID))
	if err != nil {
		return nil, ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ss := p.sessions[c.Value]
	if ss == nil || ss.appID != l.appID || time.Now().After(ss.expires) {
		return nil, ""
	}
	return ss, c.Value
}

// recheck confirms, at most every 30 seconds, that the desktop session is
// still signed in and its user may still use the app.
func (p *appProxy) recheck(ctx context.Context, ss *proxySession) bool {
	p.mu.Lock()
	fresh := time.Since(ss.checked) < proxyRecheck
	p.mu.Unlock()
	if fresh {
		return true
	}
	s := p.s
	info, err := s.sessions.Validate(ctx, ss.desktopToken)
	if err != nil || info.UserID != ss.userID {
		return false
	}
	u, err := s.users.Get(ctx, info.UserID)
	if err != nil || u.Disabled {
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

// stripHardyCookies keeps HardyOS's own cookies (the desktop session and
// every app's proxy cookie) away from the app.
func stripHardyCookies(h http.Header) {
	lines := h.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	var keep []string
	for _, line := range lines {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			name, _, _ := strings.Cut(part, "=")
			if part == "" || strings.HasPrefix(strings.TrimSpace(name), "hardyos_") {
				continue
			}
			keep = append(keep, part)
		}
	}
	h.Del("Cookie")
	if len(keep) > 0 {
		h.Set("Cookie", strings.Join(keep, "; "))
	}
}

// fixResponse lets the desktop frame the app and keeps the app's redirects
// on the proxy.
func (p *appProxy) fixResponse(resp *http.Response, l *proxyListener) {
	h := resp.Header
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
