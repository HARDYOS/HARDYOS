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
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// Sign-in for the mail server (decision 232). Dovecot never checks a
// password itself: every IMAP and SMTP sign-in becomes an OAuth2 password
// grant to hardyd on 127.0.0.1 (passdb oauth2), and every attempt is first
// put to hardyd's auth policy endpoint with the client's real address
// (rate limits). hardyd checks domain passwords with its own domain
// controller exactly like a desktop sign-in (decision 78), webmail tokens
// against the desktop session they were made for, and HardyOS's
// notification sign-in against its sealed password.

// ErrBadLogin is a wrong name or password (one message for both).
var ErrBadLogin = errors.New("wrong address or password")

// Checker verifies what someone typed into a mail app.
type Checker interface {
	// CheckLogin returns nil when secret is right for login (a mailbox
	// address or NotifyLogin) and the mailbox may be used now.
	CheckLogin(ctx context.Context, login, secret string) error
}

// Remote says where a sign-in comes from: inside (loopback, the LAN,
// NetBird's 100.64.0.0/10, Docker's networks) or the internet.
func Inside(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || cgnat.Contains(a)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Throttle limits failed mail sign-ins (decision 233). Sign-ins from the
// internet: per address 10 failures in 15 minutes block that address for
// an hour; per mailbox they're slowed down (doubling delays). Sign-ins from
// inside are only ever slowed down, per address, and never share a bucket
// with the internet: nobody outside can lock a family member (or the
// administrator on the LAN) out of their mail.
type Throttle struct {
	block    *auth.LoginLimiter // internet, per address
	userSlow *auth.DelayLimiter // internet, per mailbox
	lanSlow  *auth.DelayLimiter // inside, per address
}

// NewThrottle returns HardyOS's defaults.
func NewThrottle() *Throttle {
	return &Throttle{
		block:    &auth.LoginLimiter{MaxFailures: 10, Window: 15 * time.Minute, Lockout: time.Hour},
		userSlow: &auth.DelayLimiter{Free: 5, MaxDelay: 5 * time.Minute, Window: time.Hour},
		lanSlow:  &auth.DelayLimiter{Free: 5, MaxDelay: 30 * time.Second, Window: 15 * time.Minute},
	}
}

// Verdict is the policy server's answer: Block (-1), a delay in seconds,
// or 0 to go ahead.
type Verdict struct {
	Block bool
	Wait  time.Duration
}

func key(prefix, s string) string { return prefix + strings.ToLower(s) }

// Check says whether a sign-in from remote as login may go ahead now.
func (t *Throttle) Check(login string, remote netip.Addr) Verdict {
	if !remote.IsValid() || Inside(remote) {
		ip := "unknown"
		if remote.IsValid() {
			ip = remote.Unmap().String()
		}
		if ok, wait := t.lanSlow.Allowed(key("lan-ip:", ip)); !ok {
			return Verdict{Wait: wait}
		}
		return Verdict{}
	}
	ip := remote.Unmap().String()
	if ok, _ := t.block.Allowed(key("ip:", ip)); !ok {
		return Verdict{Block: true}
	}
	if ok, wait := t.userSlow.Allowed(key("user:", login)); !ok {
		return Verdict{Wait: wait}
	}
	return Verdict{}
}

// Result records the outcome of a sign-in. It returns true when this
// failure just blocked an internet address.
func (t *Throttle) Result(login string, remote netip.Addr, ok bool) (blocked bool) {
	inside := !remote.IsValid() || Inside(remote)
	ip := "unknown"
	if remote.IsValid() {
		ip = remote.Unmap().String()
	}
	if inside {
		if ok {
			t.lanSlow.Succeed(key("lan-ip:", ip))
		} else {
			t.lanSlow.Fail(key("lan-ip:", ip))
		}
		return false
	}
	if ok {
		t.block.Succeed(key("ip:", ip))
		t.userSlow.Succeed(key("user:", login))
		return false
	}
	before, _ := t.block.Allowed(key("ip:", ip))
	t.block.Fail(key("ip:", ip))
	t.userSlow.Fail(key("user:", login))
	after, _ := t.block.Allowed(key("ip:", ip))
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
// /introspect and /policy. It listens on 127.0.0.1 only.
type AuthServer struct {
	// Secret is the current shared secret Dovecot proves itself with ("":
	// mail is off, everything is refused).
	Secret  func() string
	Checker Checker
	Limits  *Throttle
	OnEvent func(AuthEvent)
	Log     *slog.Logger

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

// ServeHTTP implements the three endpoints.
func (s *AuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !loopback(r.RemoteAddr) {
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

func loopback(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback()
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
	login := strings.ToLower(strings.TrimSpace(r.PostForm.Get("username")))
	pw := r.PostForm.Get("password")
	if login == "" || pw == "" || len(login) > 320 || len(pw) > 1024 {
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.Checker.CheckLogin(ctx, login, pw); err != nil {
		if !errors.Is(err, ErrBadLogin) {
			s.log().Info("mail sign-in refused", "login", login, "err", err)
		}
		writeAuthJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "wrong address or password"})
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
	Login    string `json:"login"`
	Remote   string `json:"remote"`
	Protocol string `json:"protocol"`
	FailType string `json:"fail_type"`
	Success  *bool  `json:"success"`
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
	remote, _ := netip.ParseAddr(req.Remote)
	login := strings.ToLower(strings.TrimSpace(req.Login))
	switch r.URL.Query().Get("command") {
	case "allow":
		v := s.Limits.Check(login, remote)
		switch {
		case v.Block:
			writeAuthJSON(w, http.StatusOK, map[string]any{"status": -1, "msg": "Too many failed sign-ins from your address; try again later."})
		case v.Wait > 0:
			sec := int(v.Wait.Seconds()) + 1
			sec = min(sec, 30)
			writeAuthJSON(w, http.StatusOK, map[string]any{"status": sec, "msg": ""})
		default:
			writeAuthJSON(w, http.StatusOK, map[string]any{"status": 0, "msg": ""})
		}
	case "report":
		ok := req.Success != nil && *req.Success
		// A failure caused by the policy itself isn't counted again.
		if !ok && req.FailType == "policy" {
			writeAuthJSON(w, http.StatusOK, map[string]any{"status": 0})
			return
		}
		blocked := s.Limits.Result(login, remote, ok)
		if s.OnEvent != nil {
			s.OnEvent(AuthEvent{Login: login, Remote: req.Remote, Protocol: req.Protocol, OK: ok, Blocked: blocked})
		}
		writeAuthJSON(w, http.StatusOK, map[string]any{"status": 0})
	default:
		writeAuthJSON(w, http.StatusBadRequest, map[string]any{"status": -1})
	}
}
