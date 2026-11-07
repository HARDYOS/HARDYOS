package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// The cluster desktop (docs/plans/cluster.md 4, decision 324). The person
// signs in on one member (the entry node); /api/v1/nodes/{node}/<path> is
// served there when {node} is the entry node and otherwise forwarded over
// the relay protocol to the member's /api/v1/<path>, with the session
// cookie and every credential stripped and a 60-second assertion bound to
// the request added. The target authorizes the person itself: a domain
// account by SID against its own view of the domain, an administrator of
// any member as an administrator, a local non-admin not at all.

type clusterUserKey struct{}

// clusterUserFrom is the person a verified relayed request acts for (only
// ever set by relayHandler, in this process).
func clusterUserFrom(ctx context.Context) *auth.User {
	u, _ := ctx.Value(clusterUserKey{}).(*auth.User)
	return u
}

type relayedKey struct{}

// relayedRequest is a verified relayed request's context: its assertion
// and how to check again that the person may still act (long requests:
// VM consoles).
type relayedRequest struct {
	rel   *cluster.Relayed
	still func(ctx context.Context) (*auth.User, bool)
	// selfHost is this server's LAN address (its own origins, such as the
	// office editor, are reached there); self its node id.
	selfHost string
	self     cluster.NodeID
}

// apiBase is where the browser reaches this server's API for r: through
// the entry node's node scope for a relayed request (paths handed back to
// the browser, such as a VM console's WebSocket, must name this node).
func apiBase(r *http.Request) string {
	if rr := relayedFrom(r); rr != nil && rr.self != "" {
		return "/api/v1/nodes/" + url.PathEscape(string(rr.self))
	}
	return "/api/v1"
}

// relayedFrom is the relayed request r is, or nil.
func relayedFrom(r *http.Request) *relayedRequest {
	rr, _ := r.Context().Value(relayedKey{}).(*relayedRequest)
	return rr
}

// requestScheme is how the browser reached this server for r: for a
// relayed request, how it reached the entry node (signed).
func requestScheme(r *http.Request) string {
	if rr := relayedFrom(r); rr != nil && rr.rel.Assertion.Proto != "" {
		return rr.rel.Assertion.Proto
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// SourceCluster marks an administrator of another member acting here.
const SourceCluster = "cluster"

// Paths never forwarded: signing in and out, the first-run setup, and the
// proxy itself (no chains).
func proxyable(path string) bool {
	if !strings.HasPrefix(path, "/api/v1/") || strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") {
		return false
	}
	for _, p := range []string{"/api/v1/nodes/", "/api/v1/auth/", "/api/v1/setup", "/api/v1/installer", "/api/v1/health"} {
		if strings.HasPrefix(path, p) {
			return false
		}
	}
	return true
}

// principal is who u is for other members.
func (c *clusterAPI) principal(ctx context.Context, u *auth.User) (cluster.Principal, error) {
	if u.Source == SourceCluster {
		return cluster.Principal{}, errors.New("an administrator from another server can't be forwarded again")
	}
	if u.Source != auth.SourceDomain {
		return cluster.Principal{Kind: "local", Name: u.Username, Admin: u.IsAdmin()}, nil
	}
	sid, err := c.sidOf(ctx, u)
	if err != nil {
		return cluster.Principal{}, err
	}
	return cluster.Principal{Kind: "domain", Name: u.Principal, SID: sid, Admin: u.IsAdmin()}, nil
}

// sidOf looks a domain account's SID up (cached for five minutes).
func (c *clusterAPI) sidOf(ctx context.Context, u *auth.User) (string, error) {
	c.sidMu.Lock()
	e, ok := c.sids[u.Principal]
	c.sidMu.Unlock()
	if ok && time.Since(e.at) < 5*time.Minute {
		return e.sid, nil
	}
	if c.s.signin == nil || c.s.signin.Domain == nil {
		return "", errors.New("the domain can't be asked about this account")
	}
	_, name, _ := strings.Cut(u.Principal, `\`)
	a, err := c.s.signin.Domain.Account(ctx, name)
	if err != nil || a == nil || !a.Exists || a.SID == "" {
		return "", errors.New("the domain doesn't know this account's SID")
	}
	c.sidMu.Lock()
	c.sids[u.Principal] = sidEntry{sid: a.SID, at: time.Now()}
	c.sidMu.Unlock()
	return a.SID, nil
}

func sessionHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ---- the entry node ------------------------------------------------------------

func (c *clusterAPI) handleNodeProxy(w http.ResponseWriter, r *http.Request, u *auth.User) {
	node := cluster.NodeID(r.PathValue("node"))
	path := "/api/v1/" + r.PathValue("rest")
	if !proxyable(path) {
		writeError(w, http.StatusNotFound, "not_found", "no such API endpoint")
		return
	}
	core := c.core()
	info := core.Info()
	if info == nil || node == info.Node {
		// This server: the same handler as without the node scope.
		r2 := r.Clone(r.Context())
		r2.URL.Path, r2.URL.RawPath = path, ""
		c.s.mux.ServeHTTP(w, r2)
		return
	}
	m, ok := core.Member(node)
	if !ok || m.Role == cluster.RoleWitness {
		writeError(w, http.StatusNotFound, "not_found", "no server called "+string(node)+" in the cluster")
		return
	}
	// Who the person is for other members, decided before anything is
	// read, spooled or opened (decision 371): local accounts that aren't
	// administrators exist only on their own server.
	p, err := c.principal(r.Context(), u)
	if err != nil {
		writeError(w, http.StatusForbidden, "forbidden", err.Error())
		return
	}
	if p.Kind == "local" && !p.Admin {
		writeError(w, http.StatusForbidden, "forbidden", "local accounts are per server: sign in on "+m.Name)
		return
	}
	upgrade := cluster.IsUpgrade(r)
	release, ok := c.limits.take(u.Username, upgrade)
	if !ok {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "too_many", "too many requests to other servers at once; try again shortly")
		return
	}
	defer release()
	if app, ok := strings.CutPrefix(path, "/api/v1/apps/"); ok && r.Method == http.MethodPost && strings.HasSuffix(app, "/open") {
		// An app window: through this node's window proxy, relayed.
		c.openRemoteWindow(w, r, u, p, node, strings.TrimSuffix(app, "/open"))
		return
	}
	token, _ := c.s.sessionToken(r)
	f := &cluster.Forward{Node: node, Principal: p, SessionHash: sessionHash(token), Method: r.Method, Path: path,
		RawQuery: r.URL.RawQuery, Header: r.Header.Clone(), Body: r.Body, Host: r.Host, Proto: requestScheme(r)}
	if upgrade {
		c.relayUpgrade(w, r, u, p, f, token)
		return
	}
	stripHopHeaders(f.Header)
	req, sb, err := core.RelayRequest(r.Context(), f)
	if err != nil {
		c.err(w, err)
		return
	}
	defer sb.Close()
	resp, err := core.RoundTripRelay(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "unreachable", fmt.Sprintf("%s isn't answering: %v", node, err))
		return
	}
	defer resp.Body.Close()
	copyResponse(w, resp)
}

var hopHeaders = []string{"Connection", "Upgrade", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding"}

func stripHopHeaders(h http.Header) {
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

// relayedHeaders are the only response headers that cross from another
// member to the browser (decision 369): what the API's answers and
// downloads need. Never cookies, never the member's security headers
// (this node's stay), never anything that would change how the browser
// treats the desktop's origin.
var relayedHeaders = []string{"Content-Type", "Content-Length", "Content-Disposition", "Content-Range", "Content-Encoding",
	"Accept-Ranges", "Cache-Control", "Expires", "Etag", "Last-Modified", "Retry-After", "Vary", "Allow"}

// relayedUpgradeHeaders are the only headers of a member's 101 answer that
// reach the browser.
var relayedUpgradeHeaders = []string{"Upgrade", "Connection", "Sec-Websocket-Accept", "Sec-Websocket-Protocol", "Sec-Websocket-Extensions"}

// sandboxCSP is put on every relayed answer that isn't JSON: a page or an
// SVG a member sends runs in an opaque origin without scripts, never as
// the desktop.
const sandboxCSP = "default-src 'none'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'unsafe-inline'; sandbox"

// relayResponseHeaders copies the allowed headers of a member's answer and
// (re)applies this node's security headers.
func relayResponseHeaders(dst, src http.Header) {
	for _, k := range relayedHeaders {
		if v := src.Values(k); len(v) > 0 {
			dst[http.CanonicalHeaderKey(k)] = append([]string(nil), v...)
		}
	}
	dst.Set("X-Content-Type-Options", "nosniff")
	dst.Set("X-Frame-Options", "SAMEORIGIN")
	dst.Set("Referrer-Policy", "same-origin")
	mt, _, _ := mime.ParseMediaType(src.Get("Content-Type"))
	if mt != "application/json" && mt != "application/problem+json" {
		dst.Set("Content-Security-Policy", sandboxCSP)
	} else if dst.Get("Content-Security-Policy") == "" {
		dst.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'self'")
	}
}

// copyResponse hands a member's answer to the browser: only the allowed
// headers, this node's security headers.
func copyResponse(w http.ResponseWriter, resp *http.Response) {
	relayResponseHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	fl := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			_ = fl.Flush()
		}
		if err != nil {
			return
		}
	}
}

// sameOrigin is the WebSocket check the desktop's own upgrades get (the
// library's default): the Origin, when sent, is this host.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

// sessionCheck is how often a relayed WebSocket rechecks the session.
var sessionCheck = 15 * time.Second

// relayUpgrade forwards a WebSocket (events, VM console) and closes it
// within sessionCheck of the session ending or the person changing (signed
// out, demoted, turned off; decision 370).
func (c *clusterAPI) relayUpgrade(w http.ResponseWriter, r *http.Request, u *auth.User, p cluster.Principal, f *cluster.Forward, token string) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "forbidden", "cross-origin WebSocket refused")
		return
	}
	core := c.core()
	f.Body = nil
	req, sb, err := core.RelayRequest(r.Context(), f)
	if err != nil {
		c.err(w, err)
		return
	}
	defer sb.Close()
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	resp, err := core.RoundTripRelay(req.WithContext(context.WithoutCancel(r.Context())))
	if err != nil {
		writeError(w, http.StatusBadGateway, "unreachable", err.Error())
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		copyResponse(w, resp)
		return
	}
	back, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		resp.Body.Close()
		writeError(w, http.StatusBadGateway, "unreachable", "the member didn't switch protocols")
		return
	}
	defer back.Close()
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	h := http.Header{}
	for _, k := range relayedUpgradeHeaders {
		if v := resp.Header.Values(k); len(v) > 0 {
			h[http.CanonicalHeaderKey(k)] = v
		}
	}
	fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\n")
	_ = h.Write(brw)
	fmt.Fprintf(brw, "\r\n")
	if brw.Flush() != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(back, brw); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, back); done <- struct{}{} }()
	t := time.NewTicker(sessionCheck)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			if !c.samePerson(r, token, u, p) {
				return
			}
		}
	}
}

// samePerson reports whether a session still belongs to the person a relay
// was opened for, with the same standing for other members: not signed
// out, turned off, renamed, demoted or promoted.
func (c *clusterAPI) samePerson(r *http.Request, token string, u *auth.User, p cluster.Principal) bool {
	info, err := c.s.peekSession(context.WithoutCancel(r.Context()), token)
	if err != nil || info == nil || info.UserID != u.ID {
		return false
	}
	cur, err := c.s.sessionUser(r, token, info.UserID)
	if err != nil {
		return false
	}
	p2, err := c.principal(r.Context(), cur)
	return err == nil && p2 == p
}

// ---- the merged event stream ----------------------------------------------------

// handleEvents streams this member's events and every other member's
// (relayed as the person), each tagged with its node.
func (c *clusterAPI) handleEvents(w http.ResponseWriter, r *http.Request, u *auth.User) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ctx := conn.CloseRead(r.Context())
	out := make(chan []byte, 256)
	send := func(node cluster.NodeID, raw json.RawMessage) {
		b, _ := json.Marshal(map[string]any{"node": node, "event": raw})
		select {
		case out <- b:
		default:
		}
	}
	core := c.core()
	self := core.ID()
	sub := c.s.cfg.Events.Subscribe(u.ID, u.IsAdmin(), 256)
	defer c.s.cfg.Events.Unsubscribe(sub)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-sub.C:
				if !ok {
					return
				}
				b, _ := json.Marshal(e)
				send(self, b)
			}
		}
	}()
	token, _ := c.s.sessionToken(r)
	p, perr := c.principal(ctx, u)
	// Local accounts that aren't administrators exist only here: no member
	// would accept them (decision 370).
	if perr == nil && core.Info() != nil && (p.Kind == "domain" || p.Admin) {
		var wg sync.WaitGroup
		for _, m := range core.Machine().Snapshot().Nodes {
			if m.ID == self || m.Role == cluster.RoleWitness {
				continue
			}
			wg.Add(1)
			go func(node cluster.NodeID) {
				defer wg.Done()
				c.followMember(ctx, node, p, token, send)
			}(m.ID)
		}
		defer wg.Wait()
	}
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "")
			return
		case b := <-out:
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := conn.Write(wctx, websocket.MessageText, b)
			cancel()
			if err != nil {
				return
			}
		case <-ping.C:
			if _, err := c.s.peekSession(ctx, sessionTokenOr(r)); err != nil {
				conn.Close(websocket.StatusPolicyViolation, "signed out")
				return
			}
			if perr == nil && !c.samePerson(r, token, u, p) {
				// Demoted, turned off or another person: the relayed
				// streams were opened for who they were.
				conn.Close(websocket.StatusPolicyViolation, "the account changed")
				return
			}
		}

	}
}

func sessionTokenOr(r *http.Request) string { return anySessionCookie(r) }

// relayRT sends one request to a member as the person (an assertion per
// request).
type relayRT struct {
	core *cluster.Core
	node cluster.NodeID
	p    cluster.Principal
	sess string
	// keepCookies: an app window's own cookies cross (they are the app's).
	keepCookies bool
}

func (t relayRT) RoundTrip(r *http.Request) (*http.Response, error) {
	var cookies []string
	if t.keepCookies {
		cookies = r.Header.Values("Cookie")
	}
	f := &cluster.Forward{Node: t.node, Principal: t.p, SessionHash: t.sess, Method: r.Method, Path: r.URL.Path,
		RawQuery: r.URL.RawQuery, Header: r.Header.Clone(), Body: r.Body, Host: r.Host, Proto: requestScheme(r)}
	req, sb, err := t.core.RelayRequest(r.Context(), f)
	if err != nil {
		return nil, err
	}
	for _, c := range cookies {
		req.Header.Add("Cookie", c)
	}
	if cluster.IsUpgrade(r) {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", r.Header.Get("Upgrade"))
	}
	resp, err := t.core.RoundTripRelay(req)
	if err != nil {
		sb.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		resp.Body = &closeAlso{ReadCloser: resp.Body, f: sb.Close}
	} else {
		sb.Close()
	}
	return resp, nil
}

type closeAlso struct {
	io.ReadCloser
	f func()
}

func (c *closeAlso) Close() error { err := c.ReadCloser.Close(); c.f(); return err }

// followMember relays one member's /events, reconnecting with backoff.
func (c *clusterAPI) followMember(ctx context.Context, node cluster.NodeID, p cluster.Principal, token string, send func(cluster.NodeID, json.RawMessage)) {
	backoff := time.Second
	for ctx.Err() == nil {
		hc := &http.Client{Transport: relayRT{core: c.core(), node: node, p: p, sess: sessionHash(token)}}
		conn, _, err := websocket.Dial(ctx, "http://"+string(node)+"/api/v1/events", &websocket.DialOptions{HTTPClient: hc,
			CompressionMode: websocket.CompressionDisabled})
		if err == nil {
			backoff = time.Second
			conn.SetReadLimit(1 << 20)
			for {
				_, b, err := conn.Read(ctx)
				if err != nil {
					break
				}
				send(node, b)
			}
			conn.CloseNow()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// ---- the target -------------------------------------------------------------------

// relayHandler serves requests other members relay here: the API
// (/api/v1/...) and app windows (/cluster/v1/window/{app}/...).
func (c *clusterAPI) relayHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		core := c.core()
		rel, done, err := core.VerifyRelay(r)
		defer done()
		if err != nil {
			c.s.log.Warn("cluster: refused a relayed request", "path", r.URL.Path, "err", err)
			writeError(w, http.StatusForbidden, "forbidden", "the request couldn't be verified")
			return
		}
		u, err := c.userFor(r.Context(), rel)
		if err != nil {
			writeError(w, http.StatusForbidden, "forbidden", err.Error())
			return
		}
		r.Header.Del("Origin")
		selfHost := ""
		if self, err := c.core().Self(); err == nil && self.Addresses.LAN.IsValid() {
			selfHost = self.Addresses.LAN.String()
		}
		r = r.WithContext(context.WithValue(r.Context(), relayedKey{}, &relayedRequest{rel: rel, selfHost: selfHost, self: c.core().ID(), still: func(ctx context.Context) (*auth.User, bool) {

			// The member must still be one that may forward, and the
			// person still usable here (decision 373).
			from, ok := c.core().TLSPeer(cluster.RelayTLS(r))
			if !ok || from.ID != rel.From.ID || from.Role == cluster.RoleWitness || from.State == cluster.NodeDead || from.State == cluster.NodeFenced {
				return nil, false
			}
			cur, err := c.userFor(ctx, rel)
			return cur, err == nil
		}}))
		if rest, ok := strings.CutPrefix(r.URL.Path, cluster.PeerPathPrefix+"window/"); ok {
			c.serveWindow(w, r, u, rel, rest)
			return
		}
		if app, ok := strings.CutPrefix(r.URL.Path, cluster.PeerPathPrefix+"windowcheck/"); ok && r.Method == http.MethodGet {
			c.checkWindow(w, r, u, app)
			return
		}
		if !proxyable(r.URL.Path) {
			writeError(w, http.StatusNotFound, "not_found", "no such API endpoint")
			return
		}
		if u.Source == SourceCluster && !clusterAdminMay(r.Method, r.URL.Path) {
			// An administrator of another member manages this one's
			// workloads and data, not its accounts, sign-in, network,
			// updates or membership (decision 368).
			c.recordOutcome(r, u, "cluster.proxied", r.Method+" "+r.URL.Path, audit.Denied, "not open to administrators of other servers")
			writeError(w, http.StatusForbidden, "forbidden", "administrators of other servers can't do this here: sign in on "+string(c.core().ID()))
			return
		}
		r.Header.Del("Cookie")
		r.Header.Set("X-HardyOS-Request", "1")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			c.record(r, u, "cluster.proxied", r.Method+" "+r.URL.Path, "")
		}
		c.s.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clusterUserKey{}, u)))
	})
}

func (c *clusterAPI) record(r *http.Request, u *auth.User, action, target, detail string) {
	c.recordOutcome(r, u, action, target, audit.Success, detail)
}

func (c *clusterAPI) recordOutcome(r *http.Request, u *auth.User, action, target string, outcome audit.Outcome, detail string) {
	e := audit.Entry{Action: action, Target: target, Outcome: outcome, Detail: detail, IP: r.RemoteAddr, Actor: u.Username}
	if u.ID > 0 {
		id := u.ID
		e.ActorID = &id
	}
	if err := c.s.audit.Record(r.Context(), e); err != nil {
		c.s.log.Error("audit write failed", "action", action, "err", err)
	}
}

// userFor authorizes the person of a relayed request on this member.
func (c *clusterAPI) userFor(ctx context.Context, rel *cluster.Relayed) (*auth.User, error) {
	sub := rel.Assertion.Subject
	via := " (via " + string(rel.From.ID) + ")"
	switch sub.Kind {
	case "domain":
		// The same directory (replicated DCs): resolved by name, bound by
		// SID, and given what signing in here would give.
		if c.s.signin == nil || c.s.signin.Domain == nil {
			return nil, errors.New("this server isn't in the domain: sign in on " + string(c.core().ID()))
		}
		info, err := c.s.signin.Domain.Info(ctx)
		if err != nil || info == nil {
			return nil, errors.New("this server can't reach the domain right now")
		}
		netbios, name, ok := strings.Cut(sub.Name, `\`)
		if !ok || !strings.EqualFold(netbios, info.NetBIOS) {
			return nil, errors.New("that account isn't in this server's domain")
		}
		a, err := c.s.signin.Domain.Account(ctx, name)
		if err != nil || a == nil || !a.Exists || !a.Enabled || a.Expired {
			return nil, errors.New("the domain account isn't usable here")
		}
		if !strings.EqualFold(a.SID, sub.SID) {
			return nil, errors.New("the domain account isn't the one the other server named")
		}
		u, err := c.s.users.UpsertDomain(ctx, clusterDomainUpdate(info, a))
		if err != nil {
			return nil, err
		}
		if u.Disabled {
			return nil, errors.New("this account is turned off on this server")
		}
		return u, nil
	case "local":
		if !sub.Admin {
			return nil, errors.New("local accounts are per server: sign in on " + string(c.core().ID()))
		}
		if !c.acceptsAdminsFrom(ctx, rel.From.ID) {
			return nil, errors.New("this server doesn't accept administrators of " + string(rel.From.ID) + ": sign in on " + string(c.core().ID()))
		}
		// An administrator of any member is an administrator here
		// (decision 324); recorded with the server they came through.
		return &auth.User{ID: 0, Username: sub.Name + via, DisplayName: sub.Name + via, Role: auth.RoleAdmin,
			Source: SourceCluster, Principal: sub.Name + via}, nil
	}
	return nil, errors.New("unknown kind of account")
}

// clusterDomainUpdate is what domain sign-in records for an account.
func clusterDomainUpdate(info *auth.DomainInfo, a *auth.DomainAccount) auth.DomainUpdate {
	groups := make([]string, 0, len(a.Groups))
	for _, g := range a.Groups {
		groups = append(groups, info.NetBIOS+`\`+g)
	}
	role := auth.RoleUser
	if auth.AdminBySID(a.DomainSID, info.AdminsGroupSID, a.GroupSIDs) {
		role = auth.RoleAdmin
	}
	return auth.DomainUpdate{Principal: info.NetBIOS + `\` + a.Username, DisplayName: a.DisplayName, Email: a.Email, Role: role, Groups: groups}
}

// ---- app windows for apps on other members ----------------------------------------

// serveWindow is the owner's side of a remote app window: the person must
// be allowed to use the app here; the request goes to the app's local
// port with the app's own cookies (renamed back by the entry node).
func (c *clusterAPI) serveWindow(w http.ResponseWriter, r *http.Request, u *auth.User, rel *cluster.Relayed, rest string) {
	appID, sub, _ := strings.Cut(rest, "/")
	if apps.ValidID(appID) != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such app")
		return
	}
	o, err := c.s.appsStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "unavailable", "the apps aren't available")
		return
	}
	var app *apps.App
	for i := range o.Apps {
		if o.Apps[i].ID == appID {
			app = &o.Apps[i]
		}
	}
	if app == nil || app.Web == nil {
		writeError(w, http.StatusNotFound, "not_found", appID+" has no window here")
		return
	}
	if may, err := c.s.mayUse(r.Context(), "", u, appID); err != nil || !may {
		writeError(w, http.StatusForbidden, "forbidden", "you haven't been given "+app.Name)
		return
	}
	r.URL.Path = "/" + sub
	r.URL.RawPath = ""
	if filterAppRequest(w, r, appID) {
		return
	}
	target := appTarget(*app)
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // the entry node's window address
			pr.Out.Header.Del("X-HardyOS-Request")
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeError(w, http.StatusBadGateway, "unavailable", app.Name+" isn't answering")
		},
	}
	rp.ServeHTTP(w, r)
}

// remoteWindowKey names a remote app's window on the entry node.
func remoteWindowKey(node cluster.NodeID, app string) string { return "~" + string(node) + "." + app }

func isRemoteWindow(key string) bool { return strings.HasPrefix(key, "~") }

// remoteWindow is a window proxy listener's remote app.
type remoteWindow struct {
	c    *clusterAPI
	node cluster.NodeID
	app  string
	// used is when the window last relayed a request (Unix seconds): idle
	// remote listeners are closed (decision 371).
	used atomic.Int64
}

// Remote windows: at most maxRemoteWindows listeners at once, each closed
// after remoteWindowIdle without a request.
const (
	maxRemoteWindows = 16
	remoteWindowIdle = 30 * time.Minute
)

func (rw *remoteWindow) idle(now time.Time) bool {
	return now.Sub(time.Unix(rw.used.Load(), 0)) > remoteWindowIdle
}

// checkWindow is the owner's answer to "may this person open this app's
// window" before the entry node opens a listener for it.
func (c *clusterAPI) checkWindow(w http.ResponseWriter, r *http.Request, u *auth.User, appID string) {
	if apps.ValidID(appID) != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such app")
		return
	}
	o, err := c.s.appsStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "unavailable", "the apps aren't available")
		return
	}
	for _, a := range o.Apps {
		if a.ID != appID {
			continue
		}
		if a.Web == nil {
			break
		}
		if may, err := c.s.mayUse(r.Context(), "", u, appID); err != nil || !may {
			writeError(w, http.StatusForbidden, "forbidden", "you haven't been given "+a.Name)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeError(w, http.StatusNotFound, "not_found", appID+" has no window here")
}

type windowUserKey struct{}

// RoundTrip relays one window request as the window session's person.
func (rw *remoteWindow) RoundTrip(r *http.Request) (*http.Response, error) {
	s := rw.c.s
	uid, _ := r.Context().Value(windowUserKey{}).(int64)
	u, err := s.users.Get(r.Context(), uid)
	if err != nil || u.Disabled {
		return nil, errors.New("the account is unavailable")
	}
	p, err := rw.c.principal(r.Context(), u)
	if err != nil {
		return nil, err
	}
	rw.used.Store(time.Now().Unix())
	desk, _ := r.Context().Value(windowDeskKey{}).(string)
	r2 := r.Clone(r.Context())
	r2.URL.Path = cluster.PeerPathPrefix + "window/" + rw.app + r.URL.Path
	return relayRT{core: rw.c.core(), node: rw.node, p: p, sess: sessionHash(desk), keepCookies: true}.RoundTrip(r2)
}

type windowDeskKey struct{}

// openRemoteWindow answers POST /nodes/{node}/apps/{id}/open for an app on
// another member: a window proxy on this (the entry) node that relays to
// the owner, with this node's own sign-in token.
func (c *clusterAPI) openRemoteWindow(w http.ResponseWriter, r *http.Request, u *auth.User, pr cluster.Principal, node cluster.NodeID, app string) {
	if apps.ValidID(app) != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such app")
		return
	}
	p := c.s.proxy
	if !p.isRunning() {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "the window proxy isn't running")
		return
	}
	// The owner says whether the app has a window and the person may use
	// it before a listener is opened here (decision 371).
	token, _ := c.s.sessionToken(r)
	creq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "http://"+string(node)+cluster.PeerPathPrefix+"windowcheck/"+app, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", "no such app")
		return
	}
	creq.Host = r.Host
	cresp, err := relayRT{core: c.core(), node: node, p: pr, sess: sessionHash(token)}.RoundTrip(creq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "unreachable", fmt.Sprintf("%s isn't answering: %v", node, err))
		return
	}
	cresp.Body.Close()
	switch {
	case cresp.StatusCode == http.StatusForbidden:
		writeError(w, http.StatusForbidden, "forbidden", "you haven't been given that app on "+string(node))
		return
	case cresp.StatusCode != http.StatusNoContent:
		writeError(w, http.StatusNotFound, "not_found", app+" has no window on "+string(node))
		return
	}
	rw := &remoteWindow{c: c, node: node, app: app}
	rw.used.Store(time.Now().Unix())
	port, err := p.ensureRemote(r.Context(), rw)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "couldn't open the window: "+err.Error())
		return
	}
	host := requestHost(r)
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	tok := p.mint(remoteWindowKey(node, app), u.ID, sessionToken(r), "/")
	writeJSON(w, http.StatusOK, AppOpen{URL: fmt.Sprintf("%s://%s:%d%s?token=%s", p.scheme(), host, port, proxyAuthPath, tok), Proxied: true})
}

// ensureRemote makes sure a remote app's window proxy listens here.
func (p *appProxy) ensureRemote(ctx context.Context, rw *remoteWindow) (int, error) {
	key := remoteWindowKey(rw.node, rw.app)
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return 0, errors.New("the window proxy isn't running")
	}
	if l := p.listeners[key]; l != nil {
		if l.remote != nil {
			l.remote.used.Store(time.Now().Unix())
		}
		return l.port, nil
	}
	remotes := 0
	for id := range p.listeners {
		if isRemoteWindow(id) {
			remotes++
		}
	}
	if remotes >= maxRemoteWindows {
		return 0, fmt.Errorf("%d windows of apps on other servers are open already; close some first", remotes)
	}
	st := p.s.appStore()

	ports, err := st.ProxyPorts(ctx)
	if err != nil {
		return 0, err
	}
	port := ports[key]
	avoid := map[int]bool{}
	var ln net.Listener
	for try := 0; try < 20; try++ {
		if port == 0 {
			if port, err = st.AllocateProxyPort(ctx, key, p.opts.BasePort, avoid); err != nil {
				return 0, err
			}
		}
		ln, err = net.Listen("tcp", net.JoinHostPort(p.opts.ListenHost, fmt.Sprint(port)))
		if err == nil {
			break
		}
		avoid[port], port = true, 0
	}
	if err != nil {
		return 0, fmt.Errorf("no port to listen on: %w", err)
	}
	if p.opts.TLS != nil {
		cfg := p.opts.TLS.Clone()
		cfg.NextProtos = []string{"http/1.1"}
		ln = tls.NewListener(ln, cfg)
	}
	l := &proxyListener{appID: key, port: port, remote: rw}
	l.target.Store(&url.URL{Scheme: "https", Host: string(rw.node)})
	l.srv = &http.Server{Handler: p.handler(l), ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 120 * time.Second,
		ErrorLog: log.New(io.Discard, "", 0)}
	p.listeners[key] = l
	go func() { _ = l.srv.Serve(ln) }()
	return port, nil
}
