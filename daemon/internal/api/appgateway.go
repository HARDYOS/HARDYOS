package api

// The app gateway: hardyd's one entry point for NetBird's reverse proxy.
//
// NetBird's proxy (on the NetBird server) reaches this server over the
// NetBird network (WireGuard) at <NetBird address>:44200, HTTPS with the
// desktop's self-signed certificate (the service's target skips verifying
// it), with the original Host passed through and a shared secret header
// HardyOS put in every target it created. The gateway:
//
//   - accepts a request only from the NetBird network carrying that
//     secret (so only NetBird's proxy, for a service HardyOS made, gets
//     through; NetBird doesn't say which peers are its proxies), and takes
//     the client's address from the proxy's X-Forwarded-For;
//   - routes by Host: <desktop>.<base> to the desktop (hardyd's own
//     handler, so its sign-in, rate limits and audit see the real client),
//     <app id>.<base> to the app's web port on 127.0.0.1;
//   - for apps, keeps what the window proxy does (access checks every 30
//     seconds, frame headers for the desktop, WebSocket tracking and
//     closing, HardyOS cookies never forwarded) with one difference: each
//     app has its own host, so its cookies are its own and aren't renamed.
//     Sign-in is a round trip to the desktop: the app host sets a
//     host-only state cookie and sends the browser to
//     <desktop>/apps/<id>/signin, which (with the desktop session) mints a
//     single-use token bound to that state and sends the browser back to
//     <app>/__hardyos/auth; the gateway checks the state cookie and sets the
//     app host's own session cookie (__Host-, HttpOnly, Secure, Lax).

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/clientip"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/netbird"
	"github.com/hardyos/hardyos/daemon/internal/publish"
)

// Gateway cookies. __Host- cookies must be Secure, Path=/ and host-only,
// and a sibling host can't set one, so no other app (or page on another
// subdomain) can plant them.
const (
	gatewayCookie      = "__Host-hardyos_gw"
	gatewayStateCookie = "__Host-hardyos_gw_state"
)

// RemoteOptions configures the gateway and the publishing loop.
type RemoteOptions struct {
	// TLS is the desktop's certificate (required: NetBird's proxy speaks
	// HTTPS to the gateway).
	TLS *tls.Config
	// Port is the gateway's port (default 44200).
	Port int
	// SyncEvery is the drift repair interval (default 10 minutes);
	// StatusEvery how often the NetBird address is checked (default 30 s).
	SyncEvery   time.Duration
	StatusEvery time.Duration
	// ListenHost and Network replace the NetBird address and network
	// (tests only).
	ListenHost string
	Network    string
}

type gwRoute struct {
	key    string
	appID  string // "" for the desktop
	host   string
	target *url.URL
	signin bool
	rp     *httputil.ReverseProxy
}

// remoteRuntime runs the publishing loop and the gateway.
type remoteRuntime struct {
	s *Server

	mu          sync.Mutex
	opts        RemoteOptions
	base        string
	desktopHost string
	routes      map[string]*gwRoute // by host
	byApp       map[string]*gwRoute
	network     netip.Prefix
	secret      string
	srv         *http.Server
	addr        string
	problem     string
	last        *RemoteSyncInfo
	kick        chan struct{}
}

func (rt *remoteRuntime) info() (*RemoteSyncInfo, RemoteGatewayInfo) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	g := RemoteGatewayInfo{Listening: rt.srv != nil, Address: rt.addr, Problem: rt.problem}
	return rt.last, g
}

// frameSrc lets the desktop frame published apps.
func (rt *remoteRuntime) frameSrc() string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.base == "" || len(rt.byApp) == 0 {
		return ""
	}
	return " https://*." + rt.base
}

// publishedURL is where the desktop at r's address opens an app, if it is
// published and the desktop is being used through its published name.
func (rt *remoteRuntime) publishedURL(r *http.Request, appID string) (string, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	route := rt.byApp[appID]
	if route == nil || rt.srv == nil || rt.desktopHost == "" || !strings.EqualFold(hostOnly(r.Host), rt.desktopHost) {
		return "", false
	}
	return "https://" + route.host + "/", true
}

// publishedApps maps published apps to their addresses.
func (rt *remoteRuntime) publishedApps() map[string]string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := map[string]string{}
	if rt.srv == nil {
		return out
	}
	for id, r := range rt.byApp {
		out[id] = "https://" + r.host + "/"
	}
	return out
}

func (rt *remoteRuntime) trigger() {
	rt.mu.Lock()
	k := rt.kick
	rt.mu.Unlock()
	if k == nil {
		return
	}
	select {
	case k <- struct{}{}:
	default:
	}
}

// RunRemote keeps NetBird's services in line (every SyncEvery, after app
// jobs, at start) and serves the gateway on the NetBird address until ctx
// ends. It needs Config.Remote.
func (s *Server) RunRemote(ctx context.Context, opts RemoteOptions) {
	if s.cfg.Remote == nil || opts.TLS == nil {
		return
	}
	if opts.Port == 0 {
		opts.Port = publish.DefaultGatewayPort
	}
	if opts.SyncEvery == 0 {
		opts.SyncEvery = 10 * time.Minute
	}
	if opts.StatusEvery == 0 {
		opts.StatusEvery = 30 * time.Second
	}
	rt := s.remote
	s.proxy.init()
	rt.mu.Lock()
	rt.opts, rt.kick = opts, make(chan struct{}, 1)
	rt.mu.Unlock()
	sub := s.cfg.Events.Subscribe(0, true, 256)
	defer s.cfg.Events.Unsubscribe(sub)
	defer rt.stopListener()
	status := time.NewTicker(opts.StatusEvery)
	defer status.Stop()
	syncT := time.NewTicker(opts.SyncEvery)
	defer syncT.Stop()
	var debounce <-chan time.Time
	rt.sync(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-status.C:
			rt.refresh(ctx)
		case <-syncT.C:
			rt.sync(ctx)
		case <-rt.kick:
			rt.sync(ctx)
		case <-debounce:
			debounce = nil
			rt.sync(ctx)
		case e, ok := <-sub.C:
			if !ok {
				return
			}
			if finishedAppJob(e) != "" {
				// Lifecycle: an app was installed, changed or removed.
				debounce = time.After(2 * time.Second)
			} else if finishedRemoteJob(e) {
				rt.refresh(ctx)
			}
		}
	}
}

func finishedRemoteJob(e events.Event) bool {
	if e.Type != events.TypeJobUpdated {
		return false
	}
	var j struct {
		Kind  string     `json:"kind"`
		State jobs.State `json:"state"`
	}
	return json.Unmarshal(e.Data, &j) == nil && j.State.Done() && strings.HasPrefix(j.Kind, "remote.")
}

// sync repairs NetBird's services and refreshes the gateway.
func (rt *remoteRuntime) sync(ctx context.Context) {
	pub := rt.s.cfg.Remote
	in, st, list := remoteInputs(ctx, rt.s.cfg.Priv)
	sctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	res, err := pub.Sync(sctx, in)
	cancel()
	info := &RemoteSyncInfo{At: time.Now().UTC()}
	if err != nil {
		info.Problem = err.Error()
	} else {
		info.Problem, info.Created, info.Updated, info.Deleted = res.Problem, res.Created, res.Updated, res.Deleted
		if n := res.Created + res.Updated + res.Deleted; n > 0 {
			rt.s.recordSystem(ctx, "remote.sync", "netbird",
				fmt.Sprintf("created=%d updated=%d deleted=%d", res.Created, res.Updated, res.Deleted))
		}
	}
	if info.Problem != "" {
		rt.s.log.Warn("publishing through NetBird", "problem", info.Problem)
	}
	rt.mu.Lock()
	rt.last = info
	rt.mu.Unlock()
	rt.apply(ctx, st, list)
}

// refresh re-reads the NetBird address and the settings without talking
// to NetBird.
func (rt *remoteRuntime) refresh(ctx context.Context) {
	_, st, list := remoteInputs(ctx, rt.s.cfg.Priv)
	rt.apply(ctx, st, list)
}

// apply builds the gateway's routes and listens where it should.
func (rt *remoteRuntime) apply(ctx context.Context, st *netbird.ClientStatus, list []apps.App) {
	pub := rt.s.cfg.Remote
	set, err := pub.Store.Load(ctx)
	if err != nil {
		return
	}
	var appList []publish.App
	web := map[string]apps.App{}
	for _, a := range list {
		appList = append(appList, publish.App{ID: a.ID, Name: a.Name})
		web[a.ID] = a
	}
	items, err := pub.Items(ctx, appList)
	if err != nil {
		return
	}
	secret := ""
	if set.Enabled {
		secret, _ = pub.Store.GatewaySecret(ctx)
	}
	routes, byApp := map[string]*gwRoute{}, map[string]*gwRoute{}
	desktopHost := ""
	if set.Enabled && set.BaseDomain != "" && secret != "" {
		for _, it := range items {
			if it.Config.Mode == publish.ModeOff || it.Domain == "" || it.Error != "" && !it.Published {
				continue
			}
			host := strings.ToLower(it.Domain)
			if it.Key == publish.DesktopKey || it.Key == publish.SSOKey {
				// hardyd's own handler (the sign-in provider takes its host).
				routes[host] = &gwRoute{key: it.Key, host: host}
				if it.Key == publish.DesktopKey {
					desktopHost = host
				}
				continue
			}
			a, ok := web[strings.TrimPrefix(it.Key, "app:")]
			if !ok || a.Web == nil {
				continue
			}
			r := &gwRoute{key: it.Key, appID: a.ID, host: host, target: appTarget(a), signin: it.Config.HardyOSSignIn}
			routes[host], byApp[a.ID] = r, r
		}
	}
	rt.mu.Lock()
	opts := rt.opts
	// Keep proxies whose route didn't change (open connections).
	for host, r := range routes {
		if old := rt.routes[host]; old != nil && rt.desktopHost == desktopHost && old.appID == r.appID && old.signin == r.signin && old.target != nil && r.target != nil &&
			old.target.String() == r.target.String() {
			routes[host] = old
			if r.appID != "" {
				byApp[r.appID] = old
			}
		}
	}
	rt.base, rt.desktopHost, rt.routes, rt.byApp, rt.secret = set.BaseDomain, desktopHost, routes, byApp, secret
	if rt.base != "" && !set.Enabled {
		rt.base = ""
	}
	listenHost, network := opts.ListenHost, opts.Network
	if listenHost == "" && st != nil && st.Connected {
		listenHost, network = st.IP, st.Network
	}
	if network == "" {
		network = "100.64.0.0/10" // NetBird's default range
	}
	rt.network, _ = netip.ParsePrefix(network)
	want := ""
	if len(routes) > 0 && listenHost != "" {
		want = net.JoinHostPort(listenHost, strconv.Itoa(opts.Port))
	}
	rt.mu.Unlock()
	rt.listen(want)
}

func (rt *remoteRuntime) stopListener() { rt.listen("") }

// listen makes the gateway listen at addr ("" stops it).
func (rt *remoteRuntime) listen(addr string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.addr == addr && (addr == "" || rt.srv != nil) {
		return
	}
	if rt.srv != nil {
		_ = rt.srv.Close()
		rt.srv, rt.addr = nil, ""
	}
	rt.problem = ""
	if addr == "" {
		return
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		rt.problem = "the app gateway can't listen on " + addr + ": " + err.Error()
		rt.s.log.Warn("app gateway", "addr", addr, "err", err)
		return
	}
	cfg := rt.opts.TLS.Clone()
	cfg.NextProtos = []string{"http/1.1"} // WebSockets over HTTP/2 aren't proxied
	srv := &http.Server{
		Handler:           rt,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	rt.srv, rt.addr = srv, addr
	go func() { _ = srv.Serve(tls.NewListener(ln, cfg)) }()
}

// fromProxy reports whether a request came from NetBird's proxy for one of
// HardyOS's services.
func (rt *remoteRuntime) fromProxy(r *http.Request, network netip.Prefix, secret string) bool {
	a, err := netip.ParseAddr(clientip.Peer(r))
	if err != nil || !network.IsValid() || !network.Contains(a.Unmap()) {
		return false
	}
	return sameSecret(r.Header.Get(publish.GatewayHeader), secret)
}

// forwardedClient is the client's address as NetBird's proxy saw it: the
// right-most X-Forwarded-For entry (the one the proxy added), else the
// connection's peer.
func forwardedClient(r *http.Request) string {
	vals := r.Header.Values("X-Forwarded-For")
	if len(vals) > 0 {
		parts := strings.Split(vals[len(vals)-1], ",")
		if a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
			return a.Unmap().String()
		}
	}
	return clientip.Peer(r)
}

func (rt *remoteRuntime) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt.mu.Lock()
	network, secret, desktopHost := rt.network, rt.secret, rt.desktopHost
	route := rt.routes[strings.ToLower(hostOnly(r.Host))]
	rt.mu.Unlock()
	if !rt.fromProxy(r, network, secret) {
		proxyPage(w, http.StatusForbidden, "Use the published address",
			"This port only takes requests from NetBird's reverse proxy.")
		return
	}
	client := forwardedClient(r)
	h := r.Header
	h.Del(publish.GatewayHeader)
	h.Del("X-Netbird-User")
	h.Del("X-Netbird-Groups")
	h.Set("X-Forwarded-For", client)
	if route == nil {
		proxyPage(w, http.StatusNotFound, "Nothing is published here", "No HardyOS app or desktop has this address.")
		return
	}
	if route.appID == "" {
		// The desktop: hardyd's own handler, seeing the real client.
		r2 := r.Clone(r.Context())
		r2.RemoteAddr = net.JoinHostPort(client, "0")
		r2.Header.Del("X-Forwarded-For")
		rt.s.ServeHTTP(w, r2)
		return
	}
	rt.s.proxy.serveGateway(w, r, rt.proxyFor(route, desktopHost), desktopHost)
}

// proxyFor makes (once) the reverse proxy for an app route.
func (rt *remoteRuntime) proxyFor(route *gwRoute, desktopHost string) *gwRoute {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if route.rp != nil {
		return route
	}
	target, host := route.target, route.host
	frame := "frame-ancestors 'self'"
	if desktopHost != "" {
		frame += " https://" + desktopHost
	}
	route.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.Header.Set("X-Forwarded-For", pr.In.Header.Get("X-Forwarded-For"))
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			gatewayRequestCookies(pr.Out.Header)
		},
		ModifyResponse: func(resp *http.Response) error {
			gatewayFixResponse(resp, target, host, frame)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			proxyPage(w, http.StatusBadGateway, "The app isn't answering",
				"It may be starting or stopped. Check it in the App Store, then reload.")
		},
	}
	return route
}

// gatewayRequestCookies drops HardyOS's own cookies from a request to an
// app (the gateway's, and any hardyos_* a sibling page planted).
func gatewayRequestCookies(h http.Header) {
	lines := h.Values("Cookie")
	if len(lines) == 0 {
		return
	}
	var keep []string
	for _, line := range lines {
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			name, _, _ := strings.Cut(part, "=")
			_, base := splitCookiePrefix(strings.TrimSpace(name))
			if part == "" || isHardyCookie(base) {
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

// gatewayFixResponse keeps an app's cookies on its own host, lets the
// desktop frame it and keeps its redirects on its published address.
func gatewayFixResponse(resp *http.Response, target *url.URL, host, frame string) {
	h := resp.Header
	if lines := h.Values("Set-Cookie"); len(lines) > 0 {
		h.Del("Set-Cookie")
		for _, line := range lines {
			if nl, ok := hostOnlyCookie(line); ok {
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
	h.Add("Content-Security-Policy", frame)
	if loc := h.Get("Location"); loc != "" {
		if u, err := url.Parse(loc); err == nil && u.IsAbs() {
			_, tport, _ := net.SplitHostPort(target.Host)
			if u.Host == target.Host || (isLoopback(u.Hostname()) && u.Port() == tport) || strings.EqualFold(u.Hostname(), host) {
				u.Scheme, u.Host = "https", host
				h.Set("Location", u.String())
			}
		}
	}
}

func isLoopback(h string) bool {
	a, err := netip.ParseAddr(h)
	return h == "localhost" || (err == nil && a.IsLoopback())
}

// hostOnlyCookie removes Domain from an app's Set-Cookie (so it can't set
// cookies for its sibling apps or the desktop) and drops hardyos_* ones.
func hostOnlyCookie(line string) (string, bool) {
	nv, attrs, _ := strings.Cut(line, ";")
	name, _, ok := strings.Cut(nv, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return "", false
	}
	if _, base := splitCookiePrefix(name); base == "" || isHardyCookie(base) {
		return "", false
	}
	var b strings.Builder
	b.WriteString(strings.TrimSpace(nv))
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

func stateHash(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

// serveGateway serves one request to a published app.
func (p *appProxy) serveGateway(w http.ResponseWriter, r *http.Request, route *gwRoute, desktopHost string) {
	if why := crossSiteRequest(r, "https://"+r.Host); why != "" {
		proxyPage(w, http.StatusForbidden, "Blocked a request from another page", why)
		return
	}
	if r.URL.Path == proxyAuthPath {
		p.gatewayAuth(w, r, route)
		return
	}
	var ss *proxySession
	key := ""
	if route.signin {
		ss, key = p.gatewaySession(r, route.appID)
		if ss == nil {
			p.gatewayStart(w, r, route, desktopHost)
			return
		}
		if !p.recheck(r, ss) {
			p.end(key, ss)
			clearGatewayCookie(w, gatewayCookie)
			proxyPage(w, http.StatusForbidden, "You can't use this app right now",
				"Your HardyOS sign-in ended or an administrator changed who may use it. Open it again.")
			return
		}
	}
	var rw http.ResponseWriter = w
	if ss != nil {
		rw = &trackingWriter{ResponseWriter: w, p: p, key: key, ss: ss}
	}
	route.rp.ServeHTTP(rw, r)
}

func clearGatewayCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// isNavigation: a page or frame load (a browser's Sec-Fetch-Mode, or an
// HTML GET from one that doesn't send it).
func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" {
		return strings.EqualFold(m, "navigate")
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// gatewayStart sends a browser without a session to the desktop to sign
// in, remembering a state only this browser (this app host) holds.
func (p *appProxy) gatewayStart(w http.ResponseWriter, r *http.Request, route *gwRoute, desktopHost string) {
	if !isNavigation(r) {
		proxyPage(w, http.StatusUnauthorized, "Sign in to HardyOS first", "Open this app from the HardyOS desktop or its address.")
		return
	}
	if desktopHost == "" {
		proxyPage(w, http.StatusServiceUnavailable, "HardyOS sign-in isn't published",
			"Apps sign in through the HardyOS desktop's published address. Publish the desktop in Control Panel › Remote Access.")
		return
	}
	state := randomToken()
	http.SetCookie(w, &http.Cookie{Name: gatewayStateCookie, Value: state, Path: "/", MaxAge: 600,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	q := url.Values{"state": {stateHash(state)}, "return": {safeNext(r.URL.RequestURI())}}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, "https://"+desktopHost+"/apps/"+route.appID+"/signin?"+q.Encode(), http.StatusSeeOther)
}

func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.Contains(next, `\`) ||
		strings.HasPrefix(next, proxyAuthPath) || len(next) > 2048 {
		return "/"
	}
	return next
}

// gatewaySession finds a request's gateway session for an app.
func (p *appProxy) gatewaySession(r *http.Request, appID string) (*proxySession, string) {
	c, err := r.Cookie(gatewayCookie)
	if err != nil {
		return nil, ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ss := p.sessions[c.Value]
	if ss == nil || !ss.gateway || ss.appID != appID || time.Now().After(ss.expires) {
		return nil, ""
	}
	return ss, c.Value
}

// mintGateway makes a single-use sign-in token for an app host, bound to
// the state the app host gave the browser.
func (p *appProxy) mintGateway(appID string, userID int64, desktopToken, state, next string) string {
	tok := randomToken()
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, t := range p.tokens {
		if now.After(t.expires) {
			delete(p.tokens, k)
		}
	}
	p.tokens[tok] = proxyToken{appID: appID, userID: userID, desktopToken: desktopToken, next: next,
		expires: now.Add(proxyTokenTTL), gateway: true, state: state}
	return tok
}

// gatewayAuth swaps a token from the desktop for the app host's session.
func (p *appProxy) gatewayAuth(w http.ResponseWriter, r *http.Request, route *gwRoute) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		proxyPage(w, http.StatusMethodNotAllowed, "This link has expired", "Open the app again.")
		return
	}
	dest := strings.ToLower(r.Header.Get("Sec-Fetch-Dest"))
	site := strings.ToLower(r.Header.Get("Sec-Fetch-Site"))
	if (dest != "" && dest != "iframe" && dest != "document") || (site != "" && site != "same-site" && site != "none" && site != "same-origin") {
		proxyPage(w, http.StatusForbidden, "Open this app from its address", "This sign-in link only works as a page or window.")
		return
	}
	tok := r.URL.Query().Get("token")
	now := time.Now()
	p.mu.Lock()
	t, ok := p.tokens[tok]
	delete(p.tokens, tok)
	p.mu.Unlock()
	if !ok || !t.gateway || now.After(t.expires) || t.appID != route.appID {
		proxyPage(w, http.StatusForbidden, "This link has expired", "Open the app again.")
		return
	}
	c, err := r.Cookie(gatewayStateCookie)
	if err != nil || !sameSecret(stateHash(c.Value), t.state) {
		proxyPage(w, http.StatusForbidden, "This sign-in started somewhere else",
			"Open the app again in this browser.")
		return
	}
	key := randomToken()
	p.mu.Lock()
	p.sessions[key] = &proxySession{appID: t.appID, userID: t.userID, desktopToken: t.desktopToken, gateway: true,
		expires: now.Add(proxySessionTTL), checked: now}
	p.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: gatewayCookie, Value: key, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	clearGatewayCookie(w, gatewayStateCookie)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, safeNext(t.next), http.StatusSeeOther)
}

// handleGatewaySignin is the desktop's half of an app host's sign-in: with
// the desktop session it mints a token for the app host and sends the
// browser back there. The address it sends to is the app's published one,
// never one from the request.
func (s *Server) handleGatewaySignin(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if apps.ValidID(id) != nil {
		proxyPage(w, http.StatusNotFound, "No such app", "")
		return
	}
	s.remote.mu.Lock()
	route := s.remote.byApp[id]
	desktop := s.remote.desktopHost
	s.remote.mu.Unlock()
	if route == nil || !route.signin || !strings.EqualFold(hostOnly(r.Host), desktop) {
		proxyPage(w, http.StatusNotFound, "This app isn't published", "Open it from the HardyOS desktop.")
		return
	}
	if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		proxyPage(w, http.StatusForbidden, "Open the app from its address", "Another site can't start a HardyOS sign-in.")
		return
	}
	state := r.URL.Query().Get("state")
	if len(state) != 64 || strings.Trim(state, "0123456789abcdef") != "" {
		proxyPage(w, http.StatusBadRequest, "This link is broken", "Open the app again.")
		return
	}
	token := sessionToken(r)
	info, err := s.sessions.Validate(r.Context(), token)
	if err != nil {
		w.Header().Set("Cache-Control", "no-store")
		signinPage(w, "https://"+desktop+"/")
		return
	}
	u, err := s.sessionUser(r, token, info.UserID)
	if err != nil {
		signinPage(w, "https://"+desktop+"/")
		return
	}
	may, err := s.mayUse(r.Context(), token, u, id)
	if err != nil || !may {
		s.record(r, u, "apps.open", id, audit.Denied, "published address")
		proxyPage(w, http.StatusForbidden, "You haven't been given this app", "Ask an administrator for access.")
		return
	}
	next := safeNext(r.URL.Query().Get("return"))
	tok := s.proxy.mintGateway(id, u.ID, token, state, next)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, "https://"+route.host+proxyAuthPath+"?token="+tok, http.StatusSeeOther)
}

// signinPage asks the person to sign in to the desktop first.
func signinPage(w http.ResponseWriter, desktop string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in to HardyOS</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0B0F19;color:#E6EAF2;font:15px/1.5 "Plus Jakarta Sans",system-ui,sans-serif}
main{max-width:420px;padding:28px 32px;border-radius:16px;background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12)}
h1{margin:0 0 8px;font-size:18px}p{margin:0 0 16px;color:#A7B0C2}a{display:inline-block;padding:9px 16px;border-radius:10px;background:linear-gradient(90deg,#00F0FF,#8B5CFF);color:#05060A;font-weight:600;text-decoration:none}</style></head>
<body><main><h1>Sign in to HardyOS first</h1><p>This app uses your HardyOS sign-in. Sign in on the desktop, then open the app again.</p><a href="%s" target="_top" rel="noopener">Open the HardyOS desktop</a></main></body></html>`,
		strings.ReplaceAll(desktop, `"`, ""))
}
