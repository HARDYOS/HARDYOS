package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/mail"
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
	s.mfa = &auth.MFA{DB: s.cfg.DB, Sealer: secretSealer{src: src}}
	s.appPw = &auth.AppPasswords{DB: s.cfg.DB}
	s.challenges = &auth.Challenges{}
}

// outside reports whether a request is from outside: through the app
// gateway (any published service: NetBird's proxy terminated it), or from
// an address that isn't loopback, private, link-local or NetBird's. There
// everyone needs a second factor, and passwords never work for services
// that can't ask for one.
func (s *Server) outside(r *http.Request) bool {
	if viaGateway(r) {
		return true
	}
	a, err := netip.ParseAddr(s.clientIP(r))
	if err != nil {
		// An address we can't read is not trusted as inside.
		return true
	}
	return !mail.Inside(a)
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
	fac, err := s.mfa.Verify(r.Context(), u, req.Code)
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
	if ch.Need == auth.NeedSetupCode {
		if err := s.mfa.CheckSetupCode(r.Context(), u.ID, req.SetupCode); err != nil {
			s.record(r, u, "auth.2fa.enable", u.Username, audit.Failure, "setup code at sign-in: "+err.Error())
			s.writeCodeError(w, err)
			return
		}
	}
	e, err := s.mfa.BeginEnroll(r.Context(), u, s.totpIssuer())
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
	codes, err := s.mfa.ConfirmEnroll(r.Context(), u, req.Code)
	if err != nil {
		s.record(r, u, "auth.2fa.enable", u.Username, audit.Failure, "at sign-in: "+err.Error())
		s.writeCodeError(w, err)
		return
	}
	s.challenges.Done(req.Challenge)
	// What was signed in with the password alone ends.
	s.endUserEverywhere(r.Context(), u.ID)
	s.dav.dropUser(u.ID)
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
		if _, err := s.mfa.Verify(r.Context(), u, req.Code); err != nil {
			s.record(r, u, "auth.2fa.replace", u.Username, audit.Failure, err.Error())
			s.writeCodeError(w, err)
			return
		}
	}
	e, err := s.mfa.BeginEnroll(r.Context(), u, s.totpIssuer())
	if err != nil {
		internalError(s, w, err)
		return
	}
	info, err := s.enrollmentInfo(e)
	if err != nil {
		internalError(s, w, err)
		return
	}
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
	codes, err := s.mfa.ConfirmEnroll(r.Context(), u, req.Code)
	if err != nil {
		s.record(r, u, "auth.2fa.enable", u.Username, audit.Failure, err.Error())
		s.writeCodeError(w, err)
		return
	}
	// This browser has proved the new factor; every other session (signed
	// in with the password alone, or with the old authenticator) ends.
	if tok, ok := s.sessionToken(r); ok {
		_ = s.sessions.MarkMFA(r.Context(), tok)
		_ = s.sessions.RevokeOthers(r.Context(), u.ID, tok)
	}
	s.dav.dropUser(u.ID)
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
	if _, err := s.mfa.Verify(r.Context(), u, req.Code); err != nil {
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
	if _, err := s.mfa.Verify(r.Context(), u, req.Code); err != nil {
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
}

func (s *Server) handle2FAPolicy(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	writeJSON(w, http.StatusOK, TwoFactorPolicy{AdminGraceDays: s.mfa.GraceDays(r.Context()), OutsideRequired: true})
}

type twoFactorPolicyRequest struct {
	AdminGraceDays int `json:"adminGraceDays"`
}

func (s *Server) handle2FAPolicySet(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req twoFactorPolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	old := s.mfa.GraceDays(r.Context())
	if err := s.mfa.SetGraceDays(r.Context(), req.AdminGraceDays); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	s.record(r, u, "auth.2fa.policy", "", audit.Success, fmt.Sprintf("administrators' grace period %d → %d days", old, req.AdminGraceDays))
	writeJSON(w, http.StatusOK, TwoFactorPolicy{AdminGraceDays: req.AdminGraceDays, OutsideRequired: true})
}

// ---- administrators: reset and setup codes ------------------------------------

type reset2FARequest struct {
	// Confirm must be the account's username (destructive: the person
	// can't sign in with their authenticator any more).
	Confirm string `json:"confirm"`
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
	s.endUserEverywhere(r.Context(), t.ID)
	s.dav.dropUser(t.ID)
	s.record(r, admin, "users.2fa.reset", t.Username, audit.Success, "authenticator and recovery codes removed; signed out everywhere")
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
	enrolled := false
	if row != nil {
		if enrolled, err = s.mfa.Enabled(ctx, row.ID); err != nil {
			return nil, false, err
		}
	}
	if !auth.PasswordPolicy(enrolled, outside) {
		return nil, false, errAppPasswordRequired
	}
	return nil, true, nil
}
