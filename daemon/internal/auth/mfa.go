package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
	// MaxCodeFailures wrong authenticator codes in a row stop authenticator
	// codes until a recovery code or an administrator's reset.
	MaxCodeFailures = 20
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
	ErrCodeLocked      = errors.New("too many wrong codes: authenticator codes are turned off for this account until you use a recovery code or an administrator resets two-factor sign-in")
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

// MFA keeps accounts' second factors.
type MFA struct {
	DB *store.DB
	// Sealer encrypts authenticator secrets at rest (hardyd: secretbox with
	// the purpose "totp").
	Sealer Sealer
	// Limiter counts wrong codes per account (default: 5 in 15 minutes
	// locks code entry for 15 minutes), shared by every sign-in path.
	Limiter *LoginLimiter
	// Now replaces the clock (tests).
	Now func() time.Time
}

func (m *MFA) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *MFA) limiter() *LoginLimiter {
	if m.Limiter == nil {
		m.Limiter = NewLoginLimiter()
	}
	return m.Limiter
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
	// Locked: too many wrong codes; only a recovery code works.
	Locked bool `json:"locked"`
	// SetupCodeExpires: an administrator's setup code is waiting.
	SetupCodeExpires *time.Time `json:"setupCodeExpires"`
	// MustEnroll: an administrator past the grace period, who can use
	// nothing but enrollment until it is set up.
	MustEnroll bool `json:"mustEnroll"`
}

type totpRow struct {
	secret, pending       []byte
	enabledAt, pendingAt  sql.NullString
	lastStep              int64
	failures              int
	graceUntil            sql.NullString
	setupHash, setupUntil sql.NullString
}

func (m *MFA) row(ctx context.Context, uid int64) (*totpRow, error) {
	var r totpRow
	err := m.DB.QueryRowContext(ctx, `SELECT secret, pending_secret, enabled_at, pending_at, last_step, failures, grace_until, setup_code_hash, setup_code_expires
		FROM user_totp WHERE user_id = ?`, uid).
		Scan(&r.secret, &r.pending, &r.enabledAt, &r.pendingAt, &r.lastStep, &r.failures, &r.graceUntil, &r.setupHash, &r.setupUntil)
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
	st.Locked = st.Enabled && r.failures >= MaxCodeFailures
	if st.Enabled {
		st.EnabledAt = timePtr(r.enabledAt)
		if err := m.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used_at IS NULL`, u.ID).Scan(&st.RecoveryCodesLeft); err != nil {
			return nil, err
		}
	} else if u.IsAdmin() {
		st.GraceUntil = timePtr(r.graceUntil)
		st.MustEnroll = st.GraceUntil != nil && !m.now().Before(*st.GraceUntil)
	}
	if t := timePtr(r.setupUntil); t != nil && r.setupHash.Valid && m.now().Before(*t) {
		st.SetupCodeExpires = t
	}
	return st, nil
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

func (m *MFA) limitKey(uid int64) string { return "mfa:" + strconv.FormatInt(uid, 10) }

// Verify checks a second factor for u: a 6-digit authenticator code or a
// recovery code. It returns the factor that worked. Wrong codes count
// against the account (CodeRateLimited), a replayed code is a wrong code,
// and after MaxCodeFailures wrong authenticator codes in a row only
// recovery codes work.
func (m *MFA) Verify(ctx context.Context, u *User, code string) (Factor, error) {
	lim := m.limiter()
	key := m.limitKey(u.ID)
	if ok, wait := lim.Allowed(key); !ok {
		return "", &CodeRateLimited{Wait: wait}
	}
	r, err := m.row(ctx, u.ID)
	if err != nil {
		return "", err
	}
	if !r.enabled() {
		return "", ErrNotEnrolled
	}
	c := normalizeCode(code)
	if len(c) == TOTPDigits && isDigits(c) {
		if r.failures >= MaxCodeFailures {
			return "", ErrCodeLocked
		}
		secret, err := m.open(ctx, u.ID, r.secret, "active")
		if err != nil {
			return "", err
		}
		step, ok := TOTPMatch(secret, c, m.now(), r.lastStep)
		if ok {
			res, err := m.DB.ExecContext(ctx, `UPDATE user_totp SET last_step = ?, failures = 0, updated_at = ? WHERE user_id = ? AND last_step < ?`,
				step, store.Now(), u.ID, step)
			if err != nil {
				return "", err
			}
			if n, _ := res.RowsAffected(); n == 1 {
				lim.Succeed(key)
				return FactorTOTP, nil
			}
		}
		lim.Fail(key)
		_, _ = m.DB.ExecContext(ctx, `UPDATE user_totp SET failures = failures + 1, updated_at = ? WHERE user_id = ?`, store.Now(), u.ID)
		if r.failures+1 >= MaxCodeFailures {
			return "", ErrCodeLocked
		}
		return "", ErrBadCode
	}
	if ok, err := m.useRecoveryCode(ctx, u.ID, c); err != nil {
		return "", err
	} else if ok {
		lim.Succeed(key)
		_, _ = m.DB.ExecContext(ctx, `UPDATE user_totp SET failures = 0, updated_at = ? WHERE user_id = ?`, store.Now(), u.ID)
		return FactorRecovery, nil
	}
	lim.Fail(key)
	return "", ErrBadCode
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

// BeginEnroll makes a new pending secret for u (replacing any pending one;
// an enabled authenticator stays in use until ConfirmEnroll).
func (m *MFA) BeginEnroll(ctx context.Context, u *User, issuer string) (*Enrollment, error) {
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
	if _, err := m.DB.ExecContext(ctx, `UPDATE user_totp SET pending_secret = ?, pending_at = ?, updated_at = ? WHERE user_id = ?`,
		sealed, store.FormatTime(m.now()), store.Now(), u.ID); err != nil {
		return nil, err
	}
	account := u.IdentityPrincipal()
	return &Enrollment{Secret: TOTPSecretText(secret), URI: TOTPURI(issuer, account, secret)}, nil
}

// ConfirmEnroll checks the first code from the pending secret and makes it
// u's authenticator, with fresh recovery codes (returned once). Any setup
// code and grace deadline are cleared.
func (m *MFA) ConfirmEnroll(ctx context.Context, u *User, code string) ([]string, error) {
	lim := m.limiter()
	key := m.limitKey(u.ID)
	if ok, wait := lim.Allowed(key); !ok {
		return nil, &CodeRateLimited{Wait: wait}
	}
	r, err := m.row(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if r == nil || len(r.pending) == 0 || !r.pendingAt.Valid || m.now().Sub(store.ParseTime(r.pendingAt.String)) > pendingTTL {
		return nil, ErrNoPending
	}
	secret, err := m.open(ctx, u.ID, r.pending, "pending")
	if err != nil {
		return nil, err
	}
	c := normalizeCode(code)
	step, ok := TOTPMatch(secret, c, m.now(), 0)
	if !ok || !isDigits(c) {
		lim.Fail(key)
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
	res, err := tx.ExecContext(ctx, `UPDATE user_totp SET secret = ?, enabled_at = ?, pending_secret = NULL, pending_at = NULL,
		last_step = ?, failures = 0, grace_until = NULL, setup_code_hash = NULL, setup_code_expires = NULL, updated_at = ?
		WHERE user_id = ? AND pending_secret = ?`, sealed, now, step, now, u.ID, r.pending)
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
	lim.Succeed(key)
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
// must keep it, ErrAdminMustKeep).
func (m *MFA) Disable(ctx context.Context, u *User) error {
	if u.IsAdmin() {
		return ErrAdminMustKeep
	}
	return m.Reset(ctx, u.ID, false)
}

// Reset removes an account's authenticator, recovery codes and setup code
// (an administrator's reset, hardyctl reset-2fa). With enrollNow, an
// administrator gets no new grace period: they set one up at their next
// sign-in.
func (m *MFA) Reset(ctx context.Context, uid int64, enrollNow bool) error {
	tx, err := m.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id = ?`, uid); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_totp WHERE user_id = ?`, uid); err != nil {
		return err
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

// CheckSetupCode verifies (without using up) uid's setup code. Wrong codes
// count like wrong authenticator codes.
func (m *MFA) CheckSetupCode(ctx context.Context, uid int64, code string) error {
	lim := m.limiter()
	key := m.limitKey(uid)
	if ok, wait := lim.Allowed(key); !ok {
		return &CodeRateLimited{Wait: wait}
	}
	r, err := m.row(ctx, uid)
	if err != nil {
		return err
	}
	c := normalizeCode(code)
	if r == nil || !r.setupHash.Valid || !r.setupUntil.Valid || !m.now().Before(store.ParseTime(r.setupUntil.String)) ||
		len(c) != setupCodeLen || !constEq(codeHash(c), r.setupHash.String) {
		lim.Fail(key)
		return ErrBadSetupCode
	}
	return nil
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
