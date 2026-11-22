package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Two-factor sign-in (decisions 440-449, docs/plans/totp.md).

// Factor is a kind of second factor. Passkeys (WebAuthn) would be another
// one: a factor, its own table, and a step the sign-in pages know.
type Factor string

const (
	FactorTOTP     Factor = "totp"
	FactorRecovery Factor = "recovery"
)

// Need is what a sign-in still needs after the password.
type Need string

const (
	// NeedNothing: the password is enough here.
	NeedNothing Need = ""
	// NeedCode: an authenticator or recovery code.
	NeedCode Need = "totp"
	// NeedEnroll: set up an authenticator now (an administrator past the
	// grace period, at home).
	NeedEnroll Need = "enroll"
	// NeedSetupCode: from outside without two-factor sign-in: only an
	// administrator's one-time setup code leads to enrollment.
	NeedSetupCode Need = "setup_code"
)

// Defaults and limits.
const (
	// DefaultAdminGraceDays is how long an administrator may sign in
	// without two-factor sign-in after the first time it was asked for.
	DefaultAdminGraceDays = 7
	MaxAdminGraceDays     = 30
	// RecoveryCodeCount codes are made at each enrollment.
	RecoveryCodeCount = 10
	// OutsideFailureBudget wrong authenticator codes from outside within
	// OutsideFailureWindow turn authenticator codes off from outside until
	// the password changes or an administrator resets two-factor sign-in
	// (decision 444). Codes at home keep working.
	OutsideFailureBudget = 20
	OutsideFailureWindow = 60 * 24 * time.Hour
	// NoticeEvery: the person (and administrators) hear about every this
	// many wrong codes from outside.
	NoticeEvery = 5
	// pendingTTL is how long a started enrollment waits for its first code.
	pendingTTL = 15 * time.Minute
	// SetupCodeTTL is how long an administrator's setup code is good for.
	SetupCodeTTL = 24 * time.Hour
	// settingGraceDays is the settings key of the grace period.
	settingGraceDays = "auth.mfa.admin_grace_days"
	// totpPurpose is the secretbox purpose of authenticator secrets.
	totpPurpose = "totp"
)

// Errors.
var (
	ErrBadCode         = errors.New("that code isn't right")
	ErrCodeLocked      = errors.New("too many wrong codes from outside: authenticator codes are turned off from outside for this account until its password is changed or an administrator resets two-factor sign-in; at home they still work, and so do recovery codes")
	ErrNotEnrolled     = errors.New("two-factor sign-in isn't set up for this account")
	ErrNoPending       = errors.New("start setting up two-factor sign-in again: the setup has expired")
	ErrAdminMustKeep   = errors.New("administrators must keep two-factor sign-in on; set up a new authenticator instead")
	ErrBadSetupCode    = errors.New("that setup code isn't right or has expired; ask an administrator for a new one")
	ErrSecretUnusable  = errors.New("this server can't read the authenticator secret (restored without keys?); use a recovery code")
	ErrInvalidGraceDay = fmt.Errorf("the grace period must be 0-%d days", MaxAdminGraceDays)
)

// CodeRateLimited means too many wrong codes in a short time.
type CodeRateLimited struct{ Wait time.Duration }

func (e *CodeRateLimited) Error() string {
	return fmt.Sprintf("too many wrong codes; try again in %d minutes", int((e.Wait+time.Minute-1)/time.Minute))
}

// Origin is where a code was typed: at home (inside) or from outside, and
// the client's address. Wrong codes count per account and origin (from
// outside per address, IPv6 per /64), so guesses from the internet never
// lock the owner out at home (decision 444).
type Origin struct {
	Outside bool
	IP      string
}

// Inside is a code typed at home.
var Inside = Origin{}

func (o Origin) bucket(kind string, uid int64) string {
	k := kind + ":" + strconv.FormatInt(uid, 10)
	if !o.Outside {
		return k + ":in"
	}
	return k + ":out:" + addrKey(o.IP)
}

// addrKey is an address as limits count it: IPv4 as is, IPv6 by /64.
func addrKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "unknown"
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// MFAEvent is something people should hear about (MFA.Notify).
type MFAEvent struct {
	UserID int64
	// Kind: "short_lock" (code entry paused for an origin), "outside_failures"
	// (every NoticeEvery wrong codes from outside), "outside_lock" (codes
	// from outside turned off).
	Kind    string
	Outside bool
	IP      string
	// Count is the wrong codes from outside in the window.
	Count int
}

// MFA keeps accounts' second factors.
type MFA struct {
	DB *store.DB
	// Sealer encrypts authenticator secrets at rest (hardyd: secretbox with
	// the purpose "totp").
	Sealer Sealer
	// Limiter counts wrong authenticator codes per account and origin
	// (default: 5 in 15 minutes pause code entry from there for 15
	// minutes), shared by every sign-in path.
	Limiter *LoginLimiter
	// Notify hears about locks and wrong codes from outside (nil: nobody).
	Notify func(ctx context.Context, e MFAEvent)
	// Now replaces the clock (tests).
	Now func() time.Time

	once sync.Once
	// recovery and enroll are the limits for recovery codes and for
	// enrollment and setup codes (their own buckets: decision 444).
	recovery, enroll *LoginLimiter
	// caps bounds recovery and enrollment/setup codes from outside per
	// account across all addresses (many addresses can't buy unlimited
	// tries; home has its own bucket and is never capped by these).
	caps *LoginLimiter
}

func (m *MFA) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *MFA) init() {
	m.once.Do(func() {
		if m.Limiter == nil {
			m.Limiter = NewLoginLimiter()
		}
		m.recovery = &LoginLimiter{MaxFailures: 10, Window: 15 * time.Minute, Lockout: 15 * time.Minute}
		m.enroll = NewLoginLimiter()
		m.caps = &LoginLimiter{MaxFailures: 30, Window: 15 * time.Minute, Lockout: 15 * time.Minute}
	})
}

func (m *MFA) notify(ctx context.Context, e MFAEvent) {
	if m.Notify != nil {
		m.Notify(context.WithoutCancel(ctx), e)
	}
}

// Status is an account's two-factor state as people see it.
type MFAStatus struct {
	Enabled           bool       `json:"enabled"`
	EnabledAt         *time.Time `json:"enabledAt"`
	RecoveryCodesLeft int        `json:"recoveryCodesLeft"`
	// Required: an administrator, who must have it.
	Required bool `json:"required"`
	// GraceUntil is an administrator's deadline to set it up (nil: none yet
	// or enabled).
	GraceUntil *time.Time `json:"graceUntil"`
	// Locked: too many wrong codes from outside; authenticator codes work
	// only at home until the password changes or an administrator resets
	// two-factor sign-in.
	Locked bool `json:"locked"`
	// OutsideFailures are wrong authenticator codes from outside in the
	// last OutsideFailureWindow.
	OutsideFailures int `json:"outsideFailures"`
	// SetupCodeExpires: an administrator's setup code is waiting.
	SetupCodeExpires *time.Time `json:"setupCodeExpires"`
	// MustEnroll: an administrator past the grace period, who can use
	// nothing but enrollment until it is set up.
	MustEnroll bool `json:"mustEnroll"`
	// Notice is the latest thing the person should know (wrong codes from
	// outside), with when; empty when there is none.
	Notice   string     `json:"notice,omitempty"`
	NoticeAt *time.Time `json:"noticeAt,omitempty"`
}

type totpRow struct {
	secret, pending       []byte
	enabledAt, pendingAt  sql.NullString
	pendingBind           sql.NullString
	lastStep              int64
	graceUntil            sql.NullString
	setupHash, setupUntil sql.NullString
	outLockedAt           sql.NullString
	notice, noticeAt      sql.NullString
}

func (m *MFA) row(ctx context.Context, uid int64) (*totpRow, error) {
	var r totpRow
	err := m.DB.QueryRowContext(ctx, `SELECT secret, pending_secret, enabled_at, pending_at, pending_bind, last_step, grace_until,
		setup_code_hash, setup_code_expires, out_locked_at, notice, notice_at FROM user_totp WHERE user_id = ?`, uid).
		Scan(&r.secret, &r.pending, &r.enabledAt, &r.pendingAt, &r.pendingBind, &r.lastStep, &r.graceUntil,
			&r.setupHash, &r.setupUntil, &r.outLockedAt, &r.notice, &r.noticeAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &r, err
}

func (r *totpRow) enabled() bool { return r != nil && r.enabledAt.Valid && len(r.secret) > 0 }

func timePtr(ns sql.NullString) *time.Time {
	if !ns.Valid || ns.String == "" {
		return nil
	}
	t := store.ParseTime(ns.String)
	return &t
}

// ensureRow makes the account's row if it has none.
func (m *MFA) ensureRow(ctx context.Context, uid int64) error {
	_, err := m.DB.ExecContext(ctx, `INSERT INTO user_totp (user_id, updated_at) VALUES (?, ?) ON CONFLICT(user_id) DO NOTHING`, uid, store.Now())
	return err
}

// Enabled reports whether u has two-factor sign-in.
func (m *MFA) Enabled(ctx context.Context, uid int64) (bool, error) {
	r, err := m.row(ctx, uid)
	if err != nil {
		return false, err
	}
	return r.enabled(), nil
}

func (m *MFA) outsideFailures(ctx context.Context, uid int64) (int, error) {
	var n int
	err := m.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_totp_failures WHERE user_id = ? AND at >= ?`,
		uid, store.FormatTime(m.now().Add(-OutsideFailureWindow))).Scan(&n)
	return n, err
}

// Status is u's two-factor state.
func (m *MFA) Status(ctx context.Context, u *User) (*MFAStatus, error) {
	r, err := m.row(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	st := &MFAStatus{Required: u.IsAdmin()}
	if r == nil {
		return st, nil
	}
	st.Enabled = r.enabled()
	st.Locked = st.Enabled && r.outLockedAt.Valid
	if st.Enabled {
		st.EnabledAt = timePtr(r.enabledAt)
		if err := m.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL`, u.ID).Scan(&st.RecoveryCodesLeft); err != nil {
			return nil, err
		}
		if st.OutsideFailures, err = m.outsideFailures(ctx, u.ID); err != nil {
			return nil, err
		}
	} else if u.IsAdmin() {
		st.GraceUntil = timePtr(r.graceUntil)
		st.MustEnroll = st.GraceUntil != nil && !m.now().Before(*st.GraceUntil)
	}
	if t := timePtr(r.setupUntil); t != nil && r.setupHash.Valid && m.now().Before(*t) {
		st.SetupCodeExpires = t
	}
	if r.notice.Valid && r.notice.String != "" {
		st.Notice, st.NoticeAt = r.notice.String, timePtr(r.noticeAt)
	}
	return st, nil
}

// SetNotice records what the person should know (shown in their account
// menu until DismissNotice).
func (m *MFA) SetNotice(ctx context.Context, uid int64, text string) {
	if err := m.ensureRow(ctx, uid); err != nil {
		return
	}
	_, _ = m.DB.ExecContext(ctx, `UPDATE user_totp SET notice = ?, notice_at = ?, updated_at = ? WHERE user_id = ?`,
		text, store.FormatTime(m.now()), store.Now(), uid)
}

// DismissNotice clears it.
func (m *MFA) DismissNotice(ctx context.Context, uid int64) error {
	_, err := m.DB.ExecContext(ctx, `UPDATE user_totp SET notice = NULL, notice_at = NULL, updated_at = ? WHERE user_id = ?`, store.Now(), uid)
	return err
}

// GraceDays is the administrators' grace period.
func (m *MFA) GraceDays(ctx context.Context) int {
	v, err := m.DB.GetSetting(ctx, settingGraceDays)
	if err != nil {
		return DefaultAdminGraceDays
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > MaxAdminGraceDays {
		return DefaultAdminGraceDays
	}
	return n
}

// SetGraceDays changes it. Deadlines already given keep their date.
func (m *MFA) SetGraceDays(ctx context.Context, days int) error {
	if days < 0 || days > MaxAdminGraceDays {
		return ErrInvalidGraceDay
	}
	return m.DB.SetSetting(ctx, settingGraceDays, strconv.Itoa(days))
}

// graceDeadline is an administrator's deadline, starting the grace period
// the first time it's asked for.
func (m *MFA) graceDeadline(ctx context.Context, uid int64, r *totpRow) (time.Time, error) {
	if r != nil && r.graceUntil.Valid {
		return store.ParseTime(r.graceUntil.String), nil
	}
	if err := m.ensureRow(ctx, uid); err != nil {
		return time.Time{}, err
	}
	until := m.now().Add(time.Duration(m.GraceDays(ctx)) * 24 * time.Hour)
	if _, err := m.DB.ExecContext(ctx, `UPDATE user_totp SET grace_until = ?, updated_at = ? WHERE user_id = ? AND grace_until IS NULL`,
		store.FormatTime(until), store.Now(), uid); err != nil {
		return time.Time{}, err
	}
	nr, err := m.row(ctx, uid)
	if err != nil || nr == nil || !nr.graceUntil.Valid {
		return until, err
	}
	return store.ParseTime(nr.graceUntil.String), nil
}

// Requirement is what u still needs after a correct password, from inside
// or outside.
func (m *MFA) Requirement(ctx context.Context, u *User, outside bool) (Need, error) {
	r, err := m.row(ctx, u.ID)
	if err != nil {
		return NeedNothing, err
	}
	switch {
	case r.enabled():
		return NeedCode, nil
	case outside:
		return NeedSetupCode, nil
	case u.IsAdmin():
		until, err := m.graceDeadline(ctx, u.ID, r)
		if err != nil {
			return NeedNothing, err
		}
		if !m.now().Before(until) {
			return NeedEnroll, nil
		}
	}
	return NeedNothing, nil
}

// MustEnroll reports whether a session of u (signed in without a second
// factor) may only be used to set one up: an administrator whose grace
// period is over.
func (m *MFA) MustEnroll(ctx context.Context, u *User) (bool, error) {
	if !u.IsAdmin() {
		return false, nil
	}
	r, err := m.row(ctx, u.ID)
	if err != nil {
		return false, err
	}
	if r.enabled() {
		return false, nil
	}
	until, err := m.graceDeadline(ctx, u.ID, r)
	if err != nil {
		return false, err
	}
	return !m.now().Before(until), nil
}

// PasswordAllowed reports whether u's own password may be used by a
// service that can't ask for a code (WebDAV, mail, calendars): never
// from outside, never once u has two-factor sign-in, and never while u
// must set it up (decisions 445, L3 of the review).
func (m *MFA) PasswordAllowed(ctx context.Context, u *User, outside bool) (bool, error) {
	if outside {
		return false, nil
	}
	if u == nil {
		return true, nil
	}
	if on, err := m.Enabled(ctx, u.ID); err != nil || on {
		return false, err
	}
	must, err := m.MustEnroll(ctx, u)
	return !must, err
}

// ---- codes --------------------------------------------------------------------

// Sealer encrypts and decrypts small secrets bound to aad. (It's an
// interface because the secretbox package can't be imported here.)
type Sealer interface {
	Seal(ctx context.Context, plain, aad []byte) ([]byte, error)
	Open(ctx context.Context, sealed, aad []byte) ([]byte, error)
}

// TOTPPurpose is the secretbox purpose hardyd seals authenticator secrets
// with.
const TOTPPurpose = totpPurpose

func (m *MFA) seal(ctx context.Context, plain, aad []byte) ([]byte, error) {
	if m.Sealer == nil {
		return nil, errors.New("no key for authenticator secrets")
	}
	return m.Sealer.Seal(ctx, plain, aad)
}

func totpAAD(uid int64, kind string) []byte {
	return []byte("user_totp:" + strconv.FormatInt(uid, 10) + ":" + kind)
}

func (m *MFA) open(ctx context.Context, uid int64, sealed []byte, kind string) ([]byte, error) {
	if m.Sealer == nil {
		return nil, ErrSecretUnusable
	}
	plain, err := m.Sealer.Open(ctx, sealed, totpAAD(uid, kind))
	if err != nil {
		return nil, ErrSecretUnusable
	}
	return plain, nil
}

// try reserves one attempt in lim for key (counted as a failure until
// Succeed), reporting a short-lock trip to Notify.
func (m *MFA) try(lim *LoginLimiter, key string) error {
	if ok, wait := lim.Try(key); !ok {
		return &CodeRateLimited{Wait: wait}
	}
	return nil
}

// capOutside reserves a try in the per-account cap for kind from outside
// (nothing at home) and returns its key for uncap.
func (m *MFA) capOutside(kind string, uid int64, o Origin) (string, error) {
	if !o.Outside {
		return "", nil
	}
	k := kind + ":" + strconv.FormatInt(uid, 10) + ":out-all"
	if ok, wait := m.caps.Try(k); !ok {
		return "", &CodeRateLimited{Wait: wait}
	}
	return k, nil
}

func (m *MFA) uncap(k string) {
	if k != "" {
		m.caps.Succeed(k)
	}
}

// tripped tells Notify when a failure just paused code entry.
func (m *MFA) tripped(ctx context.Context, lim *LoginLimiter, key string, uid int64, o Origin) {
	if ok, _ := lim.Allowed(key); !ok {
		m.notify(ctx, MFAEvent{UserID: uid, Kind: "short_lock", Outside: o.Outside, IP: o.IP})
	}
}

// Verify checks a second factor for u typed at o: a 6-digit authenticator
// code or a recovery code, and returns the factor that worked.
//
// Authenticator codes count wrong tries per account and origin (5 in 15
// minutes pause that origin); from outside each wrong code also goes into
// a rolling 60-day budget that success doesn't reset, and at
// OutsideFailureBudget authenticator codes stop working from outside
// until the password changes or an administrator resets (decision 444).
// Recovery codes have their own bucket and work when codes are paused.
// A replayed code is a wrong code.
func (m *MFA) Verify(ctx context.Context, u *User, code string, o Origin) (Factor, error) {
	m.init()
	r, err := m.row(ctx, u.ID)
	if err != nil {
		return "", err
	}
	if !r.enabled() {
		return "", ErrNotEnrolled
	}
	c := normalizeCode(code)
	if len(c) == TOTPDigits && isDigits(c) {
		if o.Outside && r.outLockedAt.Valid {
			return "", ErrCodeLocked
		}
		key := o.bucket("mfa", u.ID)
		if err := m.try(m.Limiter, key); err != nil {
			return "", err
		}
		secret, err := m.open(ctx, u.ID, r.secret, "active")
		if err != nil {
			return "", err
		}
		step, ok := TOTPMatch(secret, c, m.now(), r.lastStep)
		if ok {
			res, err := m.DB.ExecContext(ctx, `UPDATE user_totp SET last_step = ?, updated_at = ? WHERE user_id = ? AND last_step < ?`,
				step, store.Now(), u.ID, step)
			if err != nil {
				return "", err
			}
			if n, _ := res.RowsAffected(); n == 1 {
				m.Limiter.Succeed(key)
				return FactorTOTP, nil
			}
		}
		m.tripped(ctx, m.Limiter, key, u.ID, o)
		if o.Outside {
			if err := m.outsideFailure(ctx, u.ID, o); err != nil {
				return "", err
			}
		}
		return "", ErrBadCode
	}
	key := o.bucket("mfa-rc", u.ID)
	capKey, err := m.capOutside("mfa-rc", u.ID, o)
	if err != nil {
		return "", err
	}
	if err := m.try(m.recovery, key); err != nil {
		return "", err
	}
	if ok, err := m.useRecoveryCode(ctx, u.ID, c); err != nil {
		return "", err
	} else if ok {
		m.recovery.Succeed(key)
		m.uncap(capKey)
		// The owner proved themselves: the budget starts again, unless it
		// already ran out (then only a new password or a reset lifts it).
		_, _ = m.DB.ExecContext(ctx, `DELETE FROM user_totp_failures WHERE user_id = ? AND NOT EXISTS (
			SELECT 1 FROM user_totp WHERE user_id = ? AND out_locked_at IS NOT NULL)`, u.ID, u.ID)
		return FactorRecovery, nil
	}
	m.tripped(ctx, m.recovery, key, u.ID, o)
	return "", ErrBadCode
}

// outsideFailure records a wrong code from outside, tells people every
// NoticeEvery, and turns codes from outside off at the budget.
func (m *MFA) outsideFailure(ctx context.Context, uid int64, o Origin) error {
	if _, err := m.DB.ExecContext(ctx, `INSERT INTO user_totp_failures (user_id, at, ip) VALUES (?, ?, ?)`,
		uid, store.FormatTime(m.now()), clip(o.IP, 64)); err != nil {
		return err
	}
	n, err := m.outsideFailures(ctx, uid)
	if err != nil {
		return err
	}
	if n >= OutsideFailureBudget {
		var locked int64
		err := m.DB.QueryRowContext(ctx, `UPDATE user_totp SET out_locked_at = ?, updated_at = ? WHERE user_id = ? AND out_locked_at IS NULL RETURNING user_id`,
			store.FormatTime(m.now()), store.Now(), uid).Scan(&locked)
		if err == nil && locked == uid {
			m.notify(ctx, MFAEvent{UserID: uid, Kind: "outside_lock", Outside: true, IP: o.IP, Count: n})
			return nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	if n%NoticeEvery == 0 {
		m.notify(ctx, MFAEvent{UserID: uid, Kind: "outside_failures", Outside: true, IP: o.IP, Count: n})
	}
	return nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ClearOutsideLock lifts the stop on codes from outside and forgets the
// failures, when the account's password was changed at or after since
// (the directory's pwdLastSet, or now for a HardyOS password change).
// It reports whether a lock was lifted.
func (m *MFA) ClearOutsideLock(ctx context.Context, uid int64, since time.Time) bool {
	ts := store.FormatTime(since)
	res, err := m.DB.ExecContext(ctx, `UPDATE user_totp SET out_locked_at = NULL, updated_at = ? WHERE user_id = ? AND out_locked_at IS NOT NULL AND out_locked_at <= ?`,
		store.Now(), uid, ts)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		_, _ = m.DB.ExecContext(ctx, `DELETE FROM user_totp_failures WHERE user_id = ? AND at <= ?`, uid, ts)
	}
	return n > 0
}

func codeHash(c string) string {
	h := sha256.Sum256([]byte(c))
	return hex.EncodeToString(h[:])
}

func (m *MFA) useRecoveryCode(ctx context.Context, uid int64, c string) (bool, error) {
	if len(c) != recoveryCodeLen {
		return false, nil
	}
	res, err := m.DB.ExecContext(ctx, `UPDATE user_recovery_codes SET used_at = ? WHERE id = (
		SELECT id FROM user_recovery_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL LIMIT 1) AND used_at IS NULL`,
		store.Now(), uid, codeHash(c))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// ---- enrollment ----------------------------------------------------------------

// Enrollment is a started setup: what the person scans or types.
type Enrollment struct {
	Secret string `json:"secret"` // base32 in groups of four
	URI    string `json:"uri"`    // otpauth://totp/...
}

// BindHash names what a pending enrollment belongs to (a sign-in
// challenge or a desktop session) without keeping the token itself.
func BindHash(kind, token string) string { return kind + ":" + codeHash(token) }

// BeginEnroll makes a new pending secret for u, tied to bind (the sign-in
// challenge or desktop session it was started from: only that one can
// finish it). Any pending one is replaced; an enabled authenticator stays
// in use until ConfirmEnroll.
func (m *MFA) BeginEnroll(ctx context.Context, u *User, issuer, bind string) (*Enrollment, error) {
	if bind == "" {
		return nil, errors.New("enrollment needs a binding")
	}
	secret, err := NewTOTPSecret()
	if err != nil {
		return nil, err
	}
	sealed, err := m.seal(ctx, secret, totpAAD(u.ID, "pending"))
	if err != nil {
		return nil, err
	}
	if err := m.ensureRow(ctx, u.ID); err != nil {
		return nil, err
	}
	if _, err := m.DB.ExecContext(ctx, `UPDATE user_totp SET pending_secret = ?, pending_at = ?, pending_bind = ?, updated_at = ? WHERE user_id = ?`,
		sealed, store.FormatTime(m.now()), bind, store.Now(), u.ID); err != nil {
		return nil, err
	}
	account := u.IdentityPrincipal()
	return &Enrollment{Secret: TOTPSecretText(secret), URI: TOTPURI(issuer, account, secret)}, nil
}

// ConfirmEnroll checks the first code from the pending secret started for
// bind and makes it u's authenticator, with fresh recovery codes
// (returned once). The grace deadline is cleared; a stop on codes from
// outside isn't (only a new password or a reset lifts it).
func (m *MFA) ConfirmEnroll(ctx context.Context, u *User, code, bind string, o Origin) ([]string, error) {
	m.init()
	key := o.bucket("mfa-enroll", u.ID)
	capKey, err := m.capOutside("mfa-enroll", u.ID, o)
	if err != nil {
		return nil, err
	}
	if err := m.try(m.enroll, key); err != nil {
		return nil, err
	}
	r, err := m.row(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if r == nil || len(r.pending) == 0 || !r.pendingAt.Valid || m.now().Sub(store.ParseTime(r.pendingAt.String)) > pendingTTL ||
		bind == "" || !r.pendingBind.Valid || !constEq(r.pendingBind.String, bind) {
		return nil, ErrNoPending
	}
	secret, err := m.open(ctx, u.ID, r.pending, "pending")
	if err != nil {
		return nil, err
	}
	c := normalizeCode(code)
	step, ok := TOTPMatch(secret, c, m.now(), 0)
	if !ok || !isDigits(c) {
		m.tripped(ctx, m.enroll, key, u.ID, o)
		return nil, ErrBadCode
	}
	sealed, err := m.seal(ctx, secret, totpAAD(u.ID, "active"))
	if err != nil {
		return nil, err
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	tx, err := m.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	now := store.Now()
	res, err := tx.ExecContext(ctx, `UPDATE user_totp SET secret = ?, enabled_at = ?, pending_secret = NULL, pending_at = NULL, pending_bind = NULL,
		last_step = ?, grace_until = NULL, setup_code_hash = NULL, setup_code_expires = NULL, updated_at = ?
		WHERE user_id = ? AND pending_secret = ? AND pending_bind = ?`, sealed, now, step, now, u.ID, r.pending, bind)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, ErrNoPending
	}
	if err := replaceRecoveryCodes(ctx, tx, u.ID, hashes); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	m.enroll.Succeed(key)
	m.uncap(capKey)
	return codes, nil
}

// RegenerateRecoveryCodes replaces u's recovery codes.
func (m *MFA) RegenerateRecoveryCodes(ctx context.Context, uid int64) ([]string, error) {
	if ok, err := m.Enabled(ctx, uid); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrNotEnrolled
	}
	codes, hashes, err := newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	tx, err := m.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := replaceRecoveryCodes(ctx, tx, uid, hashes); err != nil {
		return nil, err
	}
	return codes, tx.Commit()
}

func replaceRecoveryCodes(ctx context.Context, tx *sql.Tx, uid int64, hashes []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id = ?`, uid); err != nil {
		return err
	}
	now := store.Now()
	for _, h := range hashes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)`, uid, h, now); err != nil {
			return err
		}
	}
	return nil
}

// Disable turns u's two-factor sign-in off (users only: administrators
// must keep it, ErrAdminMustKeep). The record of wrong codes from outside
// stays.
func (m *MFA) Disable(ctx context.Context, u *User) error {
	if u.IsAdmin() {
		return ErrAdminMustKeep
	}
	tx, err := m.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id = ?`, u.ID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_totp SET secret = NULL, enabled_at = NULL, pending_secret = NULL, pending_at = NULL, pending_bind = NULL,
		setup_code_hash = NULL, setup_code_expires = NULL, updated_at = ? WHERE user_id = ?`, store.Now(), u.ID); err != nil {
		return err
	}
	return tx.Commit()
}

// Reset removes an account's authenticator, recovery codes, setup code,
// stop on codes from outside and record of wrong codes (an administrator's
// reset, hardyctl reset-2fa). With enrollNow, an administrator gets no new
// grace period: they set one up at their next sign-in.
func (m *MFA) Reset(ctx context.Context, uid int64, enrollNow bool) error {
	tx, err := m.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, q := range []string{`DELETE FROM user_recovery_codes WHERE user_id = ?`, `DELETE FROM user_totp_failures WHERE user_id = ?`, `DELETE FROM user_totp WHERE user_id = ?`} {
		if _, err := tx.ExecContext(ctx, q, uid); err != nil {
			return err
		}
	}
	if enrollNow {
		now := store.FormatTime(m.now())
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_totp (user_id, grace_until, updated_at) VALUES (?, ?, ?)`, uid, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---- setup codes ---------------------------------------------------------------

// IssueSetupCode makes a one-time code that lets uid enroll from outside
// (shown once, SetupCodeTTL, replacing an earlier one).
func (m *MFA) IssueSetupCode(ctx context.Context, uid int64) (string, time.Time, error) {
	code, err := randomCode(setupCodeLen)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := m.ensureRow(ctx, uid); err != nil {
		return "", time.Time{}, err
	}
	until := m.now().Add(SetupCodeTTL)
	if _, err := m.DB.ExecContext(ctx, `UPDATE user_totp SET setup_code_hash = ?, setup_code_expires = ?, updated_at = ? WHERE user_id = ?`,
		codeHash(code), store.FormatTime(until), store.Now(), uid); err != nil {
		return "", time.Time{}, err
	}
	return groupCode(code), until, nil
}

// ConsumeSetupCode uses up uid's setup code if code is it (one
// compare-and-clear, so it works exactly once). Wrong codes count in the
// enrollment bucket of o.
func (m *MFA) ConsumeSetupCode(ctx context.Context, uid int64, code string, o Origin) error {
	m.init()
	key := o.bucket("mfa-enroll", uid)
	capKey, err := m.capOutside("mfa-enroll", uid, o)
	if err != nil {
		return err
	}
	if err := m.try(m.enroll, key); err != nil {
		return err
	}
	c := normalizeCode(code)
	if len(c) == setupCodeLen {
		res, err := m.DB.ExecContext(ctx, `UPDATE user_totp SET setup_code_hash = NULL, setup_code_expires = NULL, updated_at = ?
			WHERE user_id = ? AND setup_code_hash = ? AND setup_code_expires > ?`, store.Now(), uid, codeHash(c), store.FormatTime(m.now()))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			m.enroll.Succeed(key)
			m.uncap(capKey)
			return nil
		}
	}
	m.tripped(ctx, m.enroll, key, uid, o)
	return ErrBadSetupCode
}

// ---- random codes --------------------------------------------------------------

// codeAlphabet has 32 letters and digits that can't be mistaken for each
// other (no l, o, 0, 1): 5 bits a character.
const codeAlphabet = "abcdefghijkmnpqrstuvwxyz23456789"

const (
	recoveryCodeLen = 16 // 80 bits
	setupCodeLen    = 16 // 80 bits
	appPasswordLen  = 20 // 100 bits
)

func randomCode(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = codeAlphabet[b[i]&31]
	}
	return string(b), nil
}

// groupCode writes a code in groups of four: abcd-efgh-...
func groupCode(c string) string {
	var parts []string
	for i := 0; i < len(c); i += 4 {
		parts = append(parts, c[i:min(i+4, len(c))])
	}
	return strings.Join(parts, "-")
}

func newRecoveryCodes() (codes, hashes []string, err error) {
	for range RecoveryCodeCount {
		c, err := randomCode(recoveryCodeLen)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, groupCode(c))
		hashes = append(hashes, codeHash(c))
	}
	return codes, hashes, nil
}

func constEq(a, b string) bool {
	return len(a) == len(b) && subtleEq(a, b)
}
