package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/qrsvg"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Two-factor sign-in and app passwords (decisions 440-449,
// docs/plans/totp.md).

// secretSealer seals authenticator secrets with secretbox (purpose
// "totp"; the key comes from hardyd-priv's master key, so a copy of the
// database alone opens nothing).
type secretSealer struct{ src secretbox.Source }

func (s secretSealer) key(ctx context.Context) ([]byte, error) {
	return s.src.Key(ctx, auth.TOTPPurpose)
}

func (s secretSealer) Seal(ctx context.Context, plain, aad []byte) ([]byte, error) {
	k, err := s.key(ctx)
	if err != nil {
		return nil, err
	}
	return secretbox.Seal(k, plain, aad)
}

func (s secretSealer) Open(ctx context.Context, sealed, aad []byte) ([]byte, error) {
	k, err := s.key(ctx)
	if err != nil {
		return nil, err
	}
	return secretbox.Open(k, sealed, aad)
}

// newMFA wires two-factor sign-in.
func (s *Server) newMFA() {
	src := s.cfg.Secrets
	if src == nil {
		src = secretbox.NewStaticSource()
	}
	s.mfa = &auth.MFA{DB: s.cfg.DB, Sealer: secretSealer{src: src}, Notify: s.mfaNotify}
	s.appPw = &auth.AppPasswords{DB: s.cfg.DB}
	s.challenges = &auth.Challenges{}
}

func (s *Server) totpIssuer() string {
	host := ""
	if s.cfg.PublicHost != nil {
		host = s.cfg.PublicHost()
	}
	if host == "" {
		return "HardyOS"
	}
	return "HardyOS (" + host + ")"
}

func (s *Server) mfaRoutes() {
	m := s.mux
	m.HandleFunc("POST /api/v1/auth/login/2fa", s.handleLogin2FA)
	m.HandleFunc("POST /api/v1/auth/login/enroll", s.handleLoginEnroll)
	m.HandleFunc("POST /api/v1/auth/login/enroll/confirm", s.handleLoginEnrollConfirm)

	m.Handle("GET /api/v1/auth/2fa", s.authed(s.handle2FAStatus))
	m.Handle("POST /api/v1/auth/2fa/enroll", s.authed(s.handle2FAEnroll))
	m.Handle("POST /api/v1/auth/2fa/confirm", s.authed(s.handle2FAConfirm))
	m.Handle("POST /api/v1/auth/2fa/disable", s.authed(s.handle2FADisable))
	m.Handle("POST /api/v1/auth/2fa/recovery-codes", s.authed(s.handle2FARecoveryCodes))
	m.Handle("POST /api/v1/auth/2fa/notice/dismiss", s.authed(s.handle2FANoticeDismiss))
	m.Handle("GET /api/v1/auth/2fa/policy", s.admin(s.handle2FAPolicy))
	m.Handle("PUT /api/v1/auth/2fa/policy", s.admin(s.handle2FAPolicySet))

	m.Handle("GET /api/v1/auth/app-passwords", s.authed(s.handleAppPasswords))
	m.Handle("POST /api/v1/auth/app-passwords", s.authed(s.handleAppPasswordCreate))
	m.Handle("DELETE /api/v1/auth/app-passwords/{id}", s.authed(s.handleAppPasswordDelete))

	m.Handle("POST /api/v1/users/{id}/2fa/reset", s.admin(s.handleUser2FAReset))
	m.Handle("POST /api/v1/users/{id}/2fa/setup-code", s.admin(s.handleUser2FASetupCode))
	m.Handle("GET /api/v1/users/{id}/app-passwords", s.admin(s.handleUserAppPasswords))
	m.Handle("DELETE /api/v1/users/{id}/app-passwords/{pid}", s.admin(s.handleUserAppPasswordDelete))
}

// withMFA fills in u.TwoFactor.
func (s *Server) withMFA(ctx context.Context, u *auth.User) *auth.User {
	if s.mfa == nil || u == nil {
		return u
	}
	st, err := s.mfa.Status(ctx, u)
	if err != nil {
		s.log.Warn("two-factor status", "user", u.Username, "err", err)
		return u
	}
	cp := *u
	cp.TwoFactor = st
	return &cp
}

// ---- the gate on sessions ------------------------------------------------------

// Why a session can't be used (decisions 441, 442).
const (
	gateOK = iota
	// gateOutside: used from outside without a second factor.
	gateOutside
	// gateEnroll: an administrator past the grace period: enrollment only.
	gateEnroll
)

// sessionGate says whether a desktop session may be used for this request.
func (s *Server) sessionGate(r *http.Request, info *auth.SessionInfo, u *auth.User) int {
	return s.sessionGateAt(r, info, u, s.outside(r))
}

// sessionGateAt is sessionGate when where the request comes from is known
// otherwise (the app proxy's background sweep has no client: every real
// request it let through was checked with its own address).
func (s *Server) sessionGateAt(r *http.Request, info *auth.SessionInfo, u *auth.User, outside bool) int {
	if s.mfa == nil || info.MFA {
		return gateOK
	}
	if outside {
		return gateOutside
	}
	must, err := s.mfa.MustEnroll(r.Context(), u)
	if err != nil {
		s.log.Warn("two-factor gate", "user", u.Username, "err", err)
		return gateEnroll // fail closed
	}
	if must {
		return gateEnroll
	}
	return gateOK
}

// enrollOnlyPath lists what an administrator who must enroll may still do:
// see who they are, set up two-factor sign-in, and sign out.
func enrollOnlyPath(r *http.Request) bool {
	p := r.URL.Path
	switch {
	case r.Method == http.MethodGet && p == "/api/v1/auth/me":
	case r.Method == http.MethodGet && p == "/api/v1/auth/2fa":
	case r.Method == http.MethodPost && (p == "/api/v1/auth/2fa/enroll" || p == "/api/v1/auth/2fa/confirm"):
	default:
		return false
	}
	return true
}

// ---- desktop sign-in -----------------------------------------------------------

// LoginChallenge answers a right password that needs a second step.
type LoginChallenge struct {
	Challenge string    `json:"challenge"`
	Step      auth.Need `json:"step"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// afterPassword finishes a desktop sign-in whose password was right: a
// session now, or a challenge for the second factor.
func (s *Server) afterPassword(w http.ResponseWriter, r *http.Request, u *auth.User, detail string) {
	outside := s.outside(r)
	need := auth.NeedNothing
	if s.mfa != nil {
		var err error
		if need, err = s.mfa.Requirement(r.Context(), u, outside); err != nil {
			internalError(s, w, err)
			return
		}
	}
	if need == auth.NeedNothing {
		s.record(r, u, "auth.login", u.Username, audit.Success, detail)
		s.startSession(w, r, u, false)
		writeJSON(w, http.StatusOK, s.withMFA(r.Context(), u))
		return
	}
	tok, exp, err := s.challenges.Issue(u.ID, need, outside)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "busy", err.Error())
		return
	}
	note := "password right; two-factor code asked"
	if need != auth.NeedCode {
		note = "password right; two-factor sign-in must be set up first"
	}
	if outside {
		note += "; from outside"
	}
	s.record(r, u, "auth.login.password", u.Username, audit.Success, note)
	writeJSON(w, http.StatusAccepted, LoginChallenge{Challenge: tok, Step: need, ExpiresAt: exp})
}

// challengeFor loads the challenge and account of a second step; it
// answers the request itself when it can't go on.
func (s *Server) challengeFor(w http.ResponseWriter, r *http.Request, tok string, needs ...auth.Need) (*auth.Challenge, *auth.User, bool) {
	ch, err := s.challenges.Get(tok)
	if err == nil && ch.Outside != s.outside(r) {
		// A challenge from home can't be finished from outside, nor the
		// other way round.
		err = auth.ErrNoChallenge
	}
	ok := false
	if err == nil {
		for _, n := range needs {
			ok = ok || ch.Need == n
		}
	}
	if err != nil || !ok {
		writeError(w, http.StatusUnauthorized, "challenge_expired", auth.ErrNoChallenge.Error())
		return nil, nil, false
	}
	u, err := s.users.Get(r.Context(), ch.UserID)
	if err != nil || u.Disabled {
		s.challenges.Done(tok)
		writeError(w, http.StatusUnauthorized, "challenge_expired", auth.ErrNoChallenge.Error())
		return nil, nil, false
	}
	return ch, u, true
}

// writeCodeError answers a wrong, rate-limited or refused code.
func (s *Server) writeCodeError(w http.ResponseWriter, err error) {
	var rl *auth.CodeRateLimited
	switch {
	case errors.As(err, &rl):
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(rl.Wait.Seconds()))))
		writeError(w, http.StatusTooManyRequests, "rate_limited", rl.Error())
	case errors.Is(err, auth.ErrCodeLocked):
		writeError(w, http.StatusUnauthorized, "code_locked", err.Error())
	case errors.Is(err, auth.ErrSecretUnusable):
		writeError(w, http.StatusUnauthorized, "secret_unusable", err.Error())
	case errors.Is(err, auth.ErrBadSetupCode):
		writeError(w, http.StatusUnauthorized, "bad_setup_code", err.Error())
	case errors.Is(err, auth.ErrNoPending):
		writeError(w, http.StatusConflict, "no_pending", err.Error())
	case errors.Is(err, auth.ErrNotEnrolled):
		writeError(w, http.StatusConflict, "not_enrolled", err.Error())
	case errors.Is(err, auth.ErrBadCode):
		writeError(w, http.StatusUnauthorized, "bad_code", "that code isn't right; check your authenticator app's clock and try the newest code")
	default:
		internalError(s, w, err)
	}
}

type login2FARequest struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
}

func (s *Server) handleLogin2FA(w http.ResponseWriter, r *http.Request) {
	var req login2FARequest
	if !decodeJSON(w, r, &req) {
		return
	}
	_, u, ok := s.challengeFor(w, r, req.Challenge, auth.NeedCode)
	if !ok {
		return
	}
	fac, err := s.mfa.Verify(r.Context(), u, req.Code, s.origin(r))
	if err != nil {
		s.record(r, u, "auth.login", u.Username, audit.Failure, "two-factor code: "+err.Error())
		s.writeCodeError(w, err)
		return
	}
	s.challenges.Done(req.Challenge)
	detail := "two-factor: authenticator code"
	if fac == auth.FactorRecovery {
		detail = "two-factor: recovery code"
	}
	if s.outside(r) {
		detail += "; from outside"
	}
	s.record(r, u, "auth.login", u.Username, audit.Success, detail)
	s.startSession(w, r, u, true)
	writeJSON(w, http.StatusOK, s.withMFA(r.Context(), u))
}

// EnrollmentInfo is a started authenticator setup.
type EnrollmentInfo struct {
	Secret string      `json:"secret"`
	URI    string      `json:"uri"`
	QR     *qrsvg.Code `json:"qr"`
}

func (s *Server) enrollmentInfo(e *auth.Enrollment) (*EnrollmentInfo, error) {
	q, err := qrsvg.Encode(e.URI)
	if err != nil {
		return nil, err
	}
	return &EnrollmentInfo{Secret: e.Secret, URI: e.URI, QR: q}, nil
}

type loginEnrollRequest struct {
	Challenge string `json:"challenge"`
	SetupCode string `json:"setupCode"`
}

// handleLoginEnroll starts setting up an authenticator during sign-in: an
// administrator past the grace period at home, or anyone from outside
// with an administrator's one-time setup code (never with the password
// alone from outside: decision 443).
func (s *Server) handleLoginEnroll(w http.ResponseWriter, r *http.Request) {
	var req loginEnrollRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ch, u, ok := s.challengeFor(w, r, req.Challenge, auth.NeedEnroll, auth.NeedSetupCode)
	if !ok {
		return
	}
	if ch.Need == auth.NeedSetupCode && !ch.SetupOK {
		// Used up the moment it's accepted (one compare-and-clear); the
		// pending secret then belongs to this challenge only.
		if err := s.mfa.ConsumeSetupCode(r.Context(), u.ID, req.SetupCode, s.origin(r)); err != nil {
			s.record(r, u, "auth.2fa.enable", u.Username, audit.Failure, "setup code at sign-in: "+err.Error())
			s.writeCodeError(w, err)
			return
		}
		s.challenges.Update(req.Challenge, func(c *auth.Challenge) { c.SetupOK = true })
		s.record(r, u, "users.2fa.setup_code", u.Username, audit.Success, "setup code used at sign-in from outside")
	}
	e, err := s.mfa.BeginEnroll(r.Context(), u, s.totpIssuer(), auth.BindHash("challenge", req.Challenge))
	if err != nil {
		internalError(s, w, err)
		return
	}
	info, err := s.enrollmentInfo(e)
	if err != nil {
		internalError(s, w, err)
		return
	}
	s.challenges.Update(req.Challenge, func(c *auth.Challenge) { c.Started, c.SetupOK = true, true })
	s.record(r, u, "auth.2fa.enroll_start", u.Username, audit.Success, "at sign-in"+outsideNote(ch.Outside))
	writeJSON(w, http.StatusOK, info)
}

// EnrollResult is a finished setup: who signed in and the recovery codes
// (shown once).
type EnrollResult struct {
	User          *auth.User `json:"user"`
	RecoveryCodes []string   `json:"recoveryCodes"`
}

func (s *Server) handleLoginEnrollConfirm(w http.ResponseWriter, r *http.Request) {
	var req login2FARequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ch, u, ok := s.challengeFor(w, r, req.Challenge, auth.NeedEnroll, auth.NeedSetupCode)
	if !ok {
		return
	}
	if !ch.Started || !ch.SetupOK {
		writeError(w, http.StatusConflict, "no_pending", auth.ErrNoPending.Error())
		return
	}
	codes, err := s.mfa.ConfirmEnroll(r.Context(), u, req.Code, auth.BindHash("challenge", req.Challenge), s.origin(r))
	if err != nil {
		s.record(r, u, "auth.2fa.enable", u.Username, audit.Failure, "at sign-in: "+err.Error())
		s.writeCodeError(w, err)
		return
	}
	s.challenges.Done(req.Challenge)
	// Everything signed in before ends (decision 442).
	s.secondFactorSet(r.Context(), u.ID)
	where := ""
	if ch.Outside {
		where = "; from outside with a setup code"
	}
	s.record(r, u, "auth.2fa.enable", u.Username, audit.Success, "set up at sign-in"+where)
	s.record(r, u, "auth.login", u.Username, audit.Success, "two-factor: set up at sign-in"+where)
	s.startSession(w, r, u, true)
	writeJSON(w, http.StatusOK, EnrollResult{User: s.withMFA(r.Context(), u), RecoveryCodes: codes})
}

// ---- your own two-factor sign-in -------------------------------------------------

// reauth checks the signed-in person's password again (rate-limited per
// account like the terminal's); false means it answered.
func (s *Server) reauth(w http.ResponseWriter, r *http.Request, u *auth.User, pw, action string) bool {
	key := "reauth:" + strconv.FormatInt(u.ID, 10)
	if ok, wait := s.cfg.Limiter.Allowed(key); !ok {
		s.record(r, u, action, u.Username, audit.Denied, "rate limited")
		writeError(w, http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("too many wrong passwords; try again in %d minutes", int(wait.Minutes())+1))
		return false
	}
	if err := s.signin.Verify(r.Context(), u, pw); err != nil {
		if errors.Is(err, auth.ErrDomainUnavailable) || errors.Is(err, auth.ErrClockSkew) || errors.Is(err, auth.ErrNoLocalDC) {
			writeError(w, http.StatusServiceUnavailable, "domain_unavailable", err.Error())
			return false
		}
		s.cfg.Limiter.Fail(key)
		s.record(r, u, action, u.Username, audit.Failure, "wrong password")
		writeError(w, http.StatusUnauthorized, "bad_credentials", "that password isn't right")
		return false
	}
	s.cfg.Limiter.Succeed(key)
	return true
}

func (s *Server) handle2FAStatus(w http.ResponseWriter, r *http.Request, u *auth.User) {
	st, err := s.mfa.Status(r.Context(), u)
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

type enroll2FARequest struct {
	Password string `json:"password"`
	// Code is a current authenticator or recovery code, needed to replace
	// an authenticator that is set up.
	Code string `json:"code"`
}

func (s *Server) handle2FAEnroll(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req enroll2FARequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.reauth(w, r, u, req.Password, "auth.2fa.enable") {
		return
	}
	on, err := s.mfa.Enabled(r.Context(), u.ID)
	if err != nil {
		internalError(s, w, err)
		return
	}
	if on {
		if _, err := s.mfa.Verify(r.Context(), u, req.Code, s.origin(r)); err != nil {
			s.record(r, u, "auth.2fa.replace", u.Username, audit.Failure, err.Error())
			s.writeCodeError(w, err)
			return
		}
	}
	tok, _ := s.sessionToken(r)
	e, err := s.mfa.BeginEnroll(r.Context(), u, s.totpIssuer(), auth.BindHash("session", tok))
	if err != nil {
		internalError(s, w, err)
		return
	}
	info, err := s.enrollmentInfo(e)
	if err != nil {
		internalError(s, w, err)
		return
	}
	s.record(r, u, "auth.2fa.enroll_start", u.Username, audit.Success, map[bool]string{true: "new authenticator", false: "first authenticator"}[on]+outsideNote(s.outside(r)))
	writeJSON(w, http.StatusOK, info)
}

type codeRequest struct {
	Code string `json:"code"`
}

// RecoveryCodes are shown once.
type RecoveryCodes struct {
	RecoveryCodes []string `json:"recoveryCodes"`
}

func (s *Server) handle2FAConfirm(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req codeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	was, _ := s.mfa.Enabled(r.Context(), u.ID)
	tok, _ := s.sessionToken(r)
	codes, err := s.mfa.ConfirmEnroll(r.Context(), u, req.Code, auth.BindHash("session", tok), s.origin(r))
	if err != nil {
		s.record(r, u, "auth.2fa.enable", u.Username, audit.Failure, err.Error())
		s.writeCodeError(w, err)
		return
	}
	// Everything signed in before ends (desktop and app sessions, WebDAV,
	// Office, app sign-ins and tokens); this browser gets a new two-factor
	// session (decision 442).
	s.secondFactorSet(r.Context(), u.ID)
	s.startSession(w, r, u, true)
	action := "auth.2fa.enable"
	if was {
		action = "auth.2fa.replace"
	}
	s.record(r, u, action, u.Username, audit.Success, "")
	writeJSON(w, http.StatusOK, RecoveryCodes{RecoveryCodes: codes})
}

type disable2FARequest struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (s *Server) handle2FADisable(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req disable2FARequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if u.IsAdmin() {
		writeError(w, http.StatusForbidden, "required", auth.ErrAdminMustKeep.Error())
		return
	}
	if !s.reauth(w, r, u, req.Password, "auth.2fa.disable") {
		return
	}
	if _, err := s.mfa.Verify(r.Context(), u, req.Code, s.origin(r)); err != nil {
		s.record(r, u, "auth.2fa.disable", u.Username, audit.Failure, err.Error())
		s.writeCodeError(w, err)
		return
	}
	if err := s.mfa.Disable(r.Context(), u); err != nil {
		writeError(w, http.StatusForbidden, "required", err.Error())
		return
	}
	s.record(r, u, "auth.2fa.disable", u.Username, audit.Success, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handle2FARecoveryCodes(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req disable2FARequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.reauth(w, r, u, req.Password, "auth.2fa.recovery_codes") {
		return
	}
	if _, err := s.mfa.Verify(r.Context(), u, req.Code, s.origin(r)); err != nil {
		s.record(r, u, "auth.2fa.recovery_codes", u.Username, audit.Failure, err.Error())
		s.writeCodeError(w, err)
		return
	}
	codes, err := s.mfa.RegenerateRecoveryCodes(r.Context(), u.ID)
	if err != nil {
		s.writeCodeError(w, err)
		return
	}
	s.record(r, u, "auth.2fa.recovery_codes", u.Username, audit.Success, "new recovery codes")
	writeJSON(w, http.StatusOK, RecoveryCodes{RecoveryCodes: codes})
}

// TwoFactorPolicy is Control Panel › Security's two-factor settings.
type TwoFactorPolicy struct {
	AdminGraceDays int `json:"adminGraceDays"`
	// OutsideRequired is fixed: everyone needs a second factor from
	// outside (the owner's choice, decision 440).
	OutsideRequired bool `json:"outsideRequired"`
	// RouterSeenAt is when a request last came from the router's own
	// address (hairpin NAT, a port forward, a tunnel on the router): such
	// requests count as outside unless TrustRouter is on (nil: never seen;
	// kept across restarts).
	RouterSeenAt *time.Time `json:"routerSeenAt"`
	// TrustRouter is "this server is behind NAT: trust the router's
	// address" (off by default, decision 441).
	TrustRouter RouterTrust `json:"trustRouter"`
	// CanChangeTrustRouter: this request is from home itself (not the
	// router, not outside), where the setting may be changed.
	CanChangeTrustRouter bool `json:"canChangeTrustRouter"`
}

func (s *Server) policy(r *http.Request, days int) TwoFactorPolicy {
	ctx := r.Context()
	p := TwoFactorPolicy{AdminGraceDays: days, OutsideRequired: true, TrustRouter: s.routerTrust(ctx),
		CanChangeTrustRouter: s.placeOfRequest(r) == placeHome}
	if t := s.routerSeen(ctx); !t.IsZero() {
		p.RouterSeenAt = &t
	}
	return p
}

func (s *Server) handle2FAPolicy(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	writeJSON(w, http.StatusOK, s.policy(r, s.mfa.GraceDays(r.Context())))
}

type twoFactorPolicyRequest struct {
	AdminGraceDays int `json:"adminGraceDays"`
	// TrustRouter turns "this server is behind NAT: trust the router's
	// address" on or off (nil: unchanged). Only from home itself.
	TrustRouter *bool `json:"trustRouter,omitempty"`
}

func (s *Server) handle2FAPolicySet(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req twoFactorPolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	// A change: on when it isn't on for this router (off, or lapsed), off
	// when it's saved at all (on or lapsed).
	if req.TrustRouter != nil && (*req.TrustRouter && !s.routerTrust(r.Context()).On ||
		!*req.TrustRouter && s.loadTrustedRouter(r.Context()) != nil) {

		// Changed only from home itself: never from outside, nor from the
		// router's address (whatever comes through it would vouch for
		// itself).
		if s.placeOfRequest(r) != placeHome {
			s.record(r, u, "auth.2fa.trust_router", "", audit.Failure, "refused: not from this server's own network")
			writeError(w, http.StatusForbidden, "not_from_home", "the router's address can only be trusted from this server's own network (not through the router or from outside), or with hardyctl trust-router on")
			return
		}
		if err := s.setRouterTrust(r.Context(), *req.TrustRouter, u.Username); err != nil {
			if errors.Is(err, errNoRouter) {
				writeError(w, http.StatusConflict, "no_router", err.Error())
				return
			}
			internalError(s, w, err)
			return
		}
		detail := "the router's address is no longer trusted"
		if *req.TrustRouter {
			detail = "this server is behind NAT: the router's address (" + s.routerTrust(r.Context()).IP + ") is trusted"
		}
		s.record(r, u, "auth.2fa.trust_router", "", audit.Success, detail)
	}
	old := s.mfa.GraceDays(r.Context())
	if err := s.mfa.SetGraceDays(r.Context(), req.AdminGraceDays); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if old != req.AdminGraceDays {
		s.record(r, u, "auth.2fa.policy", "", audit.Success, fmt.Sprintf("administrators' grace period %d → %d days", old, req.AdminGraceDays))
	}
	writeJSON(w, http.StatusOK, s.policy(r, req.AdminGraceDays))
}

// ---- administrators: reset and setup codes ------------------------------------

type reset2FARequest struct {
	// Confirm must be the account's username (destructive: the person
	// can't sign in with their authenticator any more).
	Confirm string `json:"confirm"`
	// RevokeAppPasswords also removes the account's app passwords (default
	// true: a lost phone usually holds some).
	RevokeAppPasswords *bool `json:"revokeAppPasswords,omitempty"`
}

func (s *Server) handleUser2FAReset(w http.ResponseWriter, r *http.Request, admin *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req reset2FARequest
	if !decodeJSON(w, r, &req) {
		return
	}
	t, err := s.users.Get(r.Context(), id)
	if err != nil {
		writeUserError(s, w, err)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(req.Confirm), t.Username) {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the account's username ("+t.Username+") to reset its two-factor sign-in")
		return
	}
	// An administrator sets up a new authenticator at their next sign-in,
	// with no new grace period.
	if err := s.mfa.Reset(r.Context(), t.ID, t.IsAdmin()); err != nil {
		internalError(s, w, err)
		return
	}
	s.challenges.DropUser(t.ID)
	// Desktop and app sessions, WebDAV, Office, and every app sign-in and
	// refresh token end.
	s.endUserEverywhere(r.Context(), t.ID)
	s.dav.dropUser(t.ID)
	detail := "authenticator, recovery codes and the record of wrong codes removed; signed out everywhere and app sign-ins revoked"
	if req.RevokeAppPasswords == nil || *req.RevokeAppPasswords {
		n, err := s.appPw.DeleteAll(r.Context(), t.ID)
		if err != nil {
			internalError(s, w, err)
			return
		}
		detail += fmt.Sprintf("; %d app passwords revoked", n)
	} else {
		detail += "; app passwords kept"
	}
	s.record(r, admin, "users.2fa.reset", t.Username, audit.Success, detail)
	writeJSON(w, http.StatusOK, s.withMFA(r.Context(), t))
}

// SetupCode is a one-time code for enrolling from outside (shown once).
type SetupCode struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (s *Server) handleUser2FASetupCode(w http.ResponseWriter, r *http.Request, admin *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	t, err := s.users.Get(r.Context(), id)
	if err != nil {
		writeUserError(s, w, err)
		return
	}
	if t.Disabled {
		writeError(w, http.StatusConflict, "disabled", "this account is turned off")
		return
	}
	if on, err := s.mfa.Enabled(r.Context(), t.ID); err != nil {
		internalError(s, w, err)
		return
	} else if on {
		writeError(w, http.StatusConflict, "already_enrolled", "this account already has two-factor sign-in; reset it first if the authenticator is lost")
		return
	}
	code, until, err := s.mfa.IssueSetupCode(r.Context(), t.ID)
	if err != nil {
		internalError(s, w, err)
		return
	}
	s.record(r, admin, "users.2fa.setup_code", t.Username, audit.Success, "one-time code for setting up two-factor sign-in from outside, until "+until.UTC().Format(time.RFC3339))
	writeJSON(w, http.StatusOK, SetupCode{Code: code, ExpiresAt: until})
}

// ---- app passwords --------------------------------------------------------------

func (s *Server) handleAppPasswords(w http.ResponseWriter, r *http.Request, u *auth.User) {
	list, err := s.appPw.List(r.Context(), u.ID)
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

type appPasswordRequest struct {
	Name     string   `json:"name"`
	Scopes   []string `json:"scopes"`
	Password string   `json:"password"`
}

// AppPasswordCreated carries the new password (shown once).
type AppPasswordCreated struct {
	AppPassword *auth.AppPassword `json:"appPassword"`
	Password    string            `json:"password"`
}

func (s *Server) handleAppPasswordCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req appPasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if u.Source != auth.SourceDomain {
		writeError(w, http.StatusBadRequest, "invalid", auth.ErrAppPasswordLocal.Error())
		return
	}
	if !s.reauth(w, r, u, req.Password, "auth.app_password.create") {
		return
	}
	p, secret, err := s.appPw.Create(r.Context(), u, req.Name, req.Scopes)
	if err != nil {
		if isErr(err, auth.ErrAppPasswordName, auth.ErrAppPasswordScopes, auth.ErrTooManyAppPw, auth.ErrAppPasswordLocal) {
			writeError(w, http.StatusBadRequest, "invalid", err.Error())
			return
		}
		internalError(s, w, err)
		return
	}
	s.record(r, u, "auth.app_password.create", p.Name, audit.Success, "scopes "+strings.Join(p.Scopes, ", "))
	writeJSON(w, http.StatusCreated, AppPasswordCreated{AppPassword: p, Password: secret})
}

func (s *Server) appPasswordDelete(w http.ResponseWriter, r *http.Request, actor *auth.User, uid int64, rawID string) {
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid id")
		return
	}
	if err := s.appPw.Delete(r.Context(), uid, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such app password")
			return
		}
		internalError(s, w, err)
		return
	}
	// WebDAV remembers a working password for a short while.
	s.dav.dropUser(uid)
	s.record(r, actor, "auth.app_password.delete", strconv.FormatInt(uid, 10)+"/"+rawID, audit.Success, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAppPasswordDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.appPasswordDelete(w, r, u, u.ID, r.PathValue("id"))
}

func (s *Server) handleUserAppPasswords(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.users.Get(r.Context(), id); err != nil {
		writeUserError(s, w, err)
		return
	}
	list, err := s.appPw.List(r.Context(), id)
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleUserAppPasswordDelete(w http.ResponseWriter, r *http.Request, admin *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	s.appPasswordDelete(w, r, admin, id, r.PathValue("pid"))
}

// ---- services that can't ask for a code ------------------------------------------

// errAppPasswordRequired: the account's own password isn't accepted here
// (from outside, or the account has two-factor sign-in).
var errAppPasswordRequired = errors.New("use an app password: this account's own password doesn't work here (Two-factor sign-in > App passwords on the HardyOS desktop)")

// servicePassword decides a sign-in by a service that can't ask for a code
// (WebDAV, mail, calendars) for a domain account named typed. An app
// password with scope always works; the account's own password only from
// inside and only without two-factor sign-in. u is non-nil when an app
// password matched (then the directory was asked whether the account may
// still sign in); passwordOK says whether the password may be checked the
// usual way.
func (s *Server) servicePassword(ctx context.Context, typed, pw, scope, ip string, outside bool) (u *auth.User, passwordOK bool, err error) {
	if s.mfa == nil || s.signin == nil {
		return nil, true, nil
	}
	row, err := s.signin.DomainUser(ctx, typed)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, false, auth.ErrDomainUnavailable
	}
	if row != nil && auth.LooksLikeAppPassword(pw) {
		ok, err := s.appPw.Check(ctx, row.ID, pw, scope, ip)
		if err != nil {
			return nil, false, err
		}
		if ok {
			if err := s.signin.CheckDomainAccount(ctx, row); err != nil {
				return nil, false, err
			}
			return row, false, nil
		}
	}
	ok, err := s.mfa.PasswordAllowed(ctx, row, outside)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, errAppPasswordRequired
	}
	return nil, true, nil
}

// passwordStillAllowed is checked again after an own password worked for
// such a service (the account may have set up two-factor sign-in, or come
// due for it, while Kerberos was being asked; and a first sign-in only
// makes the row then).
func (s *Server) passwordStillAllowed(ctx context.Context, u *auth.User) error {
	if s.mfa == nil || u == nil {
		return nil
	}
	ok, err := s.mfa.PasswordAllowed(ctx, u, false)
	if err != nil {
		return err
	}
	if !ok {
		return errAppPasswordRequired
	}
	return nil
}

// ---- helpers --------------------------------------------------------------------

// origin is where r's codes count (decision 444).
func (s *Server) origin(r *http.Request) auth.Origin {
	// Codes from a trusted router aren't home's: their own bucket, and
	// they count in the 60-day budget.
	return auth.Origin{Outside: s.notHome(r), IP: s.clientIP(r)}

}

func outsideNote(outside bool) string {
	if outside {
		return "; from outside"
	}
	return ""
}

// secondFactorSet ends everything signed in before an authenticator was
// set up or replaced: desktop sessions and app windows, WebDAV's
// remembered sign-ins, Office sessions, HardyOS sign-in sessions and every
// app sign-in and refresh token (decision 442).
func (s *Server) secondFactorSet(ctx context.Context, uid int64) {
	s.endUserEverywhere(ctx, uid)
	s.dav.dropUser(uid)
}

// mfaNotify tells administrators (Notifications) and the person (their
// account menu) about locks and wrong codes from outside, and audits it.
func (s *Server) mfaNotify(ctx context.Context, e auth.MFAEvent) {
	name := "an account"
	if u, err := s.users.Get(ctx, e.UserID); err == nil {
		name = u.Username
	}
	where := "at home"
	if e.Outside {
		where = "from outside (" + e.IP + ")"
	}
	var title, body, mine string
	switch e.Kind {
	case "short_lock":
		title = "Two-factor codes paused for " + name
		body = fmt.Sprintf("Too many wrong codes %s: code entry from there is paused for 15 minutes. Codes from other places keep working.", where)
		mine = fmt.Sprintf("Someone typed several wrong two-factor codes for your account %s. If it wasn't you, change your password.", where)
	case "outside_failures":
		title = fmt.Sprintf("%d wrong two-factor codes from outside for %s", e.Count, name)
		body = fmt.Sprintf("In the last 60 days, the latest from %s. Whoever types them knows the password.", e.IP)
		mine = fmt.Sprintf("%d wrong two-factor codes were typed for your account from outside in the last 60 days (latest from %s). Someone may know your password: change it.", e.Count, e.IP)
	case "outside_lock":
		title = "Two-factor codes from outside turned off for " + name
		body = fmt.Sprintf("%d wrong codes from outside in 60 days (latest from %s). Codes still work at home; changing the password or resetting two-factor sign-in turns them back on.", e.Count, e.IP)
		mine = "Too many wrong two-factor codes from outside: codes from outside are off for your account. Change your password (or ask an administrator) to turn them back on; at home they still work."
	default:
		return
	}
	if s.cfg.Alerts != nil {
		s.cfg.Alerts.Notify(ctx, notify.Event{Kind: "security.2fa", Severity: notify.SeverityWarning, Title: title, Body: body, Link: "control/security", Time: time.Now()})
	} else if s.cfg.Notify != nil {
		_ = s.cfg.Notify.Send(ctx, notify.Notification{Level: notify.Warning, Title: title, Body: body, Source: "security", AdminOnly: true, Kind: "security.2fa", Link: "control/security"})
	}
	s.mfa.SetNotice(ctx, e.UserID, mine)
	s.recordSystem(ctx, "auth.2fa."+e.Kind, name, body)
}

func (s *Server) handle2FANoticeDismiss(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if err := s.mfa.DismissNotice(r.Context(), u.ID); err != nil {
		internalError(s, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
