package mail

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/ports"
)

// Sign-in for the mail server (decisions 241, 301). Dovecot never checks a
// password itself: every IMAP and SMTP sign-in becomes an OAuth2 password
// grant to hardyd (passdb oauth2), and every attempt is first put to
// hardyd's auth policy endpoint with the client's real address and the
// port it came in on (rate limits). Both go over a Unix socket only
// Dovecot's auth process may open (AuthSocket). hardyd checks domain
// passwords with its own domain controller exactly like a desktop sign-in
// (decision 78), webmail tokens against the desktop session they were made
// for, and HardyOS's notification sign-in against its sealed password.

// ErrBadLogin is a wrong name or password (one message for both).
var ErrBadLogin = errors.New("wrong address or password")

// Checker verifies what someone typed into a mail app.
type Checker interface {
	// CheckLogin returns nil when secret is right for login (a mailbox
	// address or NotifyLogin) and the mailbox may be used now.
	CheckLogin(ctx context.Context, login, secret string) error
}

// Inside says whether an address is inside (loopback, the LAN, NetBird's
// 100.64.0.0/10, Docker's networks) rather than the internet.
func Inside(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || cgnat.Contains(a)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Source is where a sign-in comes from.
type Source struct {
	Addr netip.Addr // the client (invalid: unknown, e.g. doveadm)
	// Internet: from outside, either by its address or because it came in
	// through the VPS or the app gateway, whatever address it claims.
	Internet bool
}

// From classifies a client address; forced marks a connection that came
// through the VPS (a forwarded port) or NetBird's reverse proxy.
func From(a netip.Addr, forced bool) Source {
	a = a.Unmap()
	return Source{Addr: a, Internet: forced || (a.IsValid() && !Inside(a))}
}

// ipKey is the address a limit counts by: an IPv4 address, or an IPv6
// address's /64 (one home or one server gets a /64, so counting single
// IPv6 addresses would give an attacker billions of fresh ones).
func ipKey(a netip.Addr) string {
	if !a.IsValid() {
		return "unknown"
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// AlertKey is what blocked addresses are grouped by in alerts: IPv4 /24
// and IPv6 /48 (one network trying many addresses is one alert).
func AlertKey(a netip.Addr) string {
	a = a.Unmap()
	if !a.IsValid() {
		return "unknown"
	}
	bits := 24
	if a.Is6() {
		bits = 48
	}
	p, _ := a.Prefix(bits)
	return p.String()
}

// SignInName reports whether login can be a mail sign-in at all: an
// address or HardyOS's notification sign-in. Anything else is refused
// before any password is checked and never gets a per-mailbox counter.
func SignInName(login string) bool {
	if login == NotifyLogin {
		return true
	}
	_, _, err := SplitAddress(login)
	return err == nil
}

// Throttle limits failed mail sign-ins (decisions 241, 303). From the
// internet: 10 failures in 15 minutes block an address (an IPv6 /64) for an
// hour, and each mailbox is slowed down (doubling waits) on its own. From
// inside: never blocked, only slowed down, per address and per mailbox, in
// buckets of their own, so nobody outside can lock a family member (or
// the administrator on the LAN) out of their mail. A sign-in that has to
// wait is refused until the wait is over (Dovecot would otherwise just
// pause it and let the guess through).
type Throttle struct {
	block    *auth.LoginLimiter // internet, per address
	userSlow *auth.DelayLimiter // internet, per mailbox
	lanSlow  *auth.DelayLimiter // inside, per address
	lanUser  *auth.DelayLimiter // inside, per mailbox
	davUser  *auth.DelayLimiter // calendars from the internet, per mailbox (soft)
}

// NewThrottle returns HardyOS's defaults.
func NewThrottle() *Throttle {
	return &Throttle{
		block:    &auth.LoginLimiter{MaxFailures: 10, Window: 15 * time.Minute, Lockout: time.Hour},
		userSlow: &auth.DelayLimiter{Free: 5, MaxDelay: 5 * time.Minute, Window: time.Hour},
		lanSlow:  &auth.DelayLimiter{Free: 5, MaxDelay: 30 * time.Second, Window: 15 * time.Minute},
		lanUser:  &auth.DelayLimiter{Free: 10, MaxDelay: time.Minute, Window: 15 * time.Minute},
		davUser:  &auth.DelayLimiter{Free: 10, MaxDelay: 30 * time.Second, Window: time.Hour},
	}
}

// Verdict is the answer to a sign-in attempt: Refuse it, or let it go on
// after Delay (0: at once).
type Verdict struct {
	Refuse bool
	// RetryAfter: when refused, roughly when trying again makes sense.
	RetryAfter time.Duration
	Delay      time.Duration
}

func key(prefix, s string) string { return prefix + strings.ToLower(s) }

// Check says whether a mail app's sign-in (IMAP, SMTP) as login from src may
// go ahead now: refused while any of its limits says wait.
func (t *Throttle) Check(login string, src Source) Verdict {
	user := SignInName(login)
	if !src.Internet {
		ip := ipKey(src.Addr)
		if ok, wait := t.lanSlow.Allowed(key("lan-ip:", ip)); !ok {
			return Verdict{Refuse: true, RetryAfter: wait}
		}
		if user {
			if ok, wait := t.lanUser.Allowed(key("lan-user:", login)); !ok {
				return Verdict{Refuse: true, RetryAfter: wait}
			}
		}
		return Verdict{}
	}
	if ok, wait := t.block.Allowed(key("ip:", ipKey(src.Addr))); !ok {
		return Verdict{Refuse: true, RetryAfter: wait}
	}
	if user {
		if ok, wait := t.userSlow.Allowed(key("user:", login)); !ok {
			return Verdict{Refuse: true, RetryAfter: wait}
		}
	}
	return Verdict{}
}

// CheckDAV is Check for calendars and contacts (decision 303): only an
// address's block refuses; a mailbox's failures from the internet only slow
// it down (a short pause, then the attempt goes on), so nobody outside can
// shut a person out of their calendar.
func (t *Throttle) CheckDAV(login string, src Source) Verdict {
	if !src.Internet {
		return t.Check(login, src)
	}
	if ok, wait := t.block.Allowed(key("ip:", ipKey(src.Addr))); !ok {
		return Verdict{Refuse: true, RetryAfter: wait}
	}
	if SignInName(login) {
		if ok, wait := t.davUser.Allowed(key("dav-user:", login)); !ok {
			return Verdict{Delay: min(wait, 5*time.Second)}
		}
	}
	return Verdict{}
}

// Result records the outcome of a sign-in. It returns true when this
// failure just blocked an internet address.
func (t *Throttle) Result(login string, src Source, ok bool) (blocked bool) {
	return t.result(login, src, ok, t.userSlow, "user:")
}

// ResultDAV is Result for calendars and contacts.
func (t *Throttle) ResultDAV(login string, src Source, ok bool) (blocked bool) {
	if !src.Internet {
		return t.Result(login, src, ok)
	}
	return t.result(login, src, ok, t.davUser, "dav-user:")
}

func (t *Throttle) result(login string, src Source, ok bool, users *auth.DelayLimiter, userPrefix string) bool {
	user := SignInName(login)
	ip := ipKey(src.Addr)
	if !src.Internet {
		if ok {
			t.lanSlow.Succeed(key("lan-ip:", ip))
			t.lanUser.Succeed(key("lan-user:", login))
			return false
		}
		t.lanSlow.Fail(key("lan-ip:", ip))
		if user {
			t.lanUser.Fail(key("lan-user:", login))
		}
		return false
	}
	if ok {
		t.block.Succeed(key("ip:", ip))
		users.Succeed(key(userPrefix, login))
		return false
	}
	before, _ := t.block.Allowed(key("ip:", ip))
	t.block.Fail(key("ip:", ip))
	if user {
		users.Fail(key(userPrefix, login))
	}
	after, _ := t.block.Allowed(key("ip:", ip))
	return before && !after
}

// Refused records an attempt the policy refused: from the internet it
// counts against the address (never the mailbox); from inside it's ignored.
// It returns true when this blocked the address.
func (t *Throttle) Refused(src Source) (blocked bool) {
	if !src.Internet {
		return false
	}
	ip := key("ip:", ipKey(src.Addr))
	before, _ := t.block.Allowed(ip)
	t.block.Fail(ip)
	after, _ := t.block.Allowed(ip)
	return before && !after
}

// AuthEvent is told about blocked addresses (alerts) and every result
// (counters).
type AuthEvent struct {
	Login    string
	Remote   string
	Protocol string
	OK       bool
	Blocked  bool // this failure blocked the address
}

// AuthServer is hardyd's mail sign-in listener: /token (password grant),
// /introspect and /policy. It answers on a Unix socket only (AuthSocket).
type AuthServer struct {
	// Secret is the current shared secret Dovecot proves itself with ("":
	// mail is off, everything is refused).
	Secret  func() string
	Checker Checker
	Limits  *Throttle
	OnEvent func(AuthEvent)
	Log     *slog.Logger
	// WebmailNet is the webmail app's network (default
	// ports.WebmailSubnet): only webmail tokens are accepted from it, and
	// only from it.
	WebmailNet netip.Prefix

	mu     sync.Mutex
	tokens map[string]grant
}

type grant struct {
	login   string
	expires time.Time
}

// tokenTTL is how long a grant's access token is good for: Dovecot
// introspects it at once.
const tokenTTL = time.Minute

func (s *AuthServer) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *AuthServer) webmailNet() netip.Prefix {
	if s.WebmailNet.IsValid() {
		return s.WebmailNet
	}
	return ports.WebmailSubnet
}

func (s *AuthServer) secretOK(got string) bool {
	if s.Secret == nil {
		return false
	}
	want := s.Secret()
	if want == "" || got == "" {
		return false
	}
	a, b := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// ServeHTTP implements the three endpoints. Requests that didn't come in
// over a Unix socket are refused, whatever listener this is served on.
func (s *AuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if la, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr); la == nil || la.Network() != "unix" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	switch r.URL.Path {
	case "/token":
		s.token(w, r)
	case "/introspect":
		s.introspect(w, r)
	case "/policy":
		s.policy(w, r)
	default:
		http.NotFound(w, r)
	}
}

func writeAuthJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// clientSecret is the OAuth2 client's secret: form fields or HTTP Basic.
func clientSecret(r *http.Request) string {
	if _, p, ok := r.BasicAuth(); ok {
		return p
	}
	return r.PostForm.Get("client_secret")
}

// parseRemote reads "addr", "addr:port" or "[v6]:port".
func parseRemote(s string) netip.Addr {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap()
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	a, _ := netip.ParseAddr(strings.Trim(s, "[]"))
	return a.Unmap()
}

// secretAllowed is decision 302: the webmail app's network signs in with
// webmail tokens only, and webmail tokens work from there only. Mail sent
// signed in as HardyOS's notifications comes from this server itself.
func (s *AuthServer) secretAllowed(login, secret string, remote netip.Addr) bool {
	webmail := remote.IsValid() && s.webmailNet().Contains(remote)
	token := strings.HasPrefix(secret, WebmailTokenPrefix)
	if webmail != token {
		return false
	}
	if login == NotifyLogin && !(remote.IsValid() && remote.IsLoopback()) {
		return false
	}
	return true
}

func (s *AuthServer) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if !s.secretOK(clientSecret(r)) {
		writeAuthJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if r.PostForm.Get("grant_type") != "password" {
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	bad := func() {
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "wrong address or password"})
	}
	login := strings.ToLower(strings.TrimSpace(r.PostForm.Get("username")))
	pw := r.PostForm.Get("password")
	if login == "" || pw == "" || len(login) > 320 || len(pw) > 1024 || !SignInName(login) {
		bad()
		return
	}
	// Dovecot names the client in a header (send_auth_headers).
	remote := parseRemote(r.Header.Get("X-Dovecot-Auth-Remote"))
	if !s.secretAllowed(login, pw, remote) {
		s.log().Info("mail sign-in refused: not allowed from there", "login", login, "remote", remote)
		bad()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.Checker.CheckLogin(ctx, login, pw); err != nil {
		if !errors.Is(err, ErrBadLogin) {
			s.log().Info("mail sign-in refused", "login", login, "err", err)
		}
		bad()
		return
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	now := time.Now()
	s.mu.Lock()
	if s.tokens == nil {
		s.tokens = map[string]grant{}
	}
	for k, g := range s.tokens {
		if now.After(g.expires) {
			delete(s.tokens, k)
		}
	}
	s.tokens[hashToken(tok)] = grant{login: login, expires: now.Add(tokenTTL)}
	s.mu.Unlock()
	// Dovecot reads the grant's answer like an introspection: active and
	// the user name must be in it.
	writeAuthJSON(w, http.StatusOK, map[string]any{"access_token": tok, "token_type": "Bearer",
		"expires_in": int(tokenTTL.Seconds()), "active": "true", "username": login})
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func (s *AuthServer) introspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeAuthJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	tok := r.PostForm.Get("token")
	if tok == "" {
		// Some clients send the token as a bearer header.
		tok = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	s.mu.Lock()
	g, ok := s.tokens[hashToken(tok)]
	s.mu.Unlock()
	if !ok || time.Now().After(g.expires) {
		writeAuthJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	writeAuthJSON(w, http.StatusOK, map[string]any{"active": "true", "username": g.login})
}

// policyRequest is what Dovecot's auth policy client sends.
type policyRequest struct {
	Login     string          `json:"login"`
	Remote    string          `json:"remote"`
	LocalPort json.RawMessage `json:"local_port"`
	Protocol  string          `json:"protocol"`
	FailType  string          `json:"fail_type"`
	Success   *bool           `json:"success"`
}

// source classifies a policy request: through a port the VPS forwards to,
// or Postfix's forwarded submission (its own SASL service name), it is the
// internet's, whatever address the PROXY header gave.
func (req policyRequest) source() Source {
	port, _ := strconv.Atoi(strings.Trim(string(req.LocalPort), `" `))
	forced := ProxiedPort(port) || strings.EqualFold(req.Protocol, ProxySASLService)
	return From(parseRemote(req.Remote), forced)
}

func (s *AuthServer) policy(w http.ResponseWriter, r *http.Request) {
	if !s.secretOK(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
		writeAuthJSON(w, http.StatusUnauthorized, map[string]any{"status": -1, "msg": "unauthorized"})
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeAuthJSON(w, http.StatusBadRequest, map[string]any{"status": -1})
		return
	}
	var req policyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeAuthJSON(w, http.StatusBadRequest, map[string]any{"status": -1})
		return
	}
	src := req.source()
	login := strings.ToLower(strings.TrimSpace(req.Login))
	switch r.URL.Query().Get("command") {
	case "allow":
		if v := s.Limits.Check(login, src); v.Refuse {
			writeAuthJSON(w, http.StatusOK, map[string]any{"status": -1, "msg": "Too many failed sign-ins; try again later."})
			return
		}
		writeAuthJSON(w, http.StatusOK, map[string]any{"status": 0, "msg": ""})
	case "report":
		ok := req.Success != nil && *req.Success
		// A sign-in the policy refused counts against its address only (an
		// address that keeps trying while refused is blocked; the mailbox
		// isn't held back any longer for it).
		if !ok && req.FailType == "policy" {
			if blocked := s.Limits.Refused(src); blocked && s.OnEvent != nil {
				s.OnEvent(AuthEvent{Login: login, Remote: src.Addr.String(), Protocol: req.Protocol, Blocked: true})
			}
			writeAuthJSON(w, http.StatusOK, map[string]any{"status": 0})
			return
		}
		blocked := s.Limits.Result(login, src, ok)
		if s.OnEvent != nil {
			s.OnEvent(AuthEvent{Login: login, Remote: src.Addr.String(), Protocol: req.Protocol, OK: ok, Blocked: blocked})
		}
		writeAuthJSON(w, http.StatusOK, map[string]any{"status": 0})
	default:
		writeAuthJSON(w, http.StatusBadRequest, map[string]any{"status": -1})
	}
}
