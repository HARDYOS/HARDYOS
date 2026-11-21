package auth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testSealer is AES-GCM with a random key, like secretbox.
type testSealer struct{ key []byte }

func newTestSealer() *testSealer {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return &testSealer{key: k}
}

func (s *testSealer) gcm() cipher.AEAD {
	b, _ := aes.NewCipher(s.key)
	g, _ := cipher.NewGCM(b)
	return g
}

func (s *testSealer) Seal(_ context.Context, plain, aad []byte) ([]byte, error) {
	g := s.gcm()
	n := make([]byte, g.NonceSize())
	_, _ = rand.Read(n)
	return g.Seal(n, n, plain, aad), nil
}

func (s *testSealer) Open(_ context.Context, sealed, aad []byte) ([]byte, error) {
	g := s.gcm()
	if len(sealed) < g.NonceSize() {
		return nil, errors.New("short")
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad)
}

// RFC 6238 appendix B (SHA-1, 8 digits, secret "12345678901234567890").
func TestHOTPMatchesRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, v := range []struct {
		t    int64
		want string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		if got := hotp(secret, v.t/TOTPPeriod, 8); got != v.want {
			t.Errorf("T=%d: %s, want %s", v.t, got, v.want)
		}
	}
	// RFC 4226 appendix D, 6 digits.
	for i, want := range []string{"755224", "287082", "359152", "969429", "338314"} {
		if got := hotp(secret, int64(i), 6); got != want {
			t.Errorf("counter %d: %s, want %s", i, got, want)
		}
	}
}

func TestTOTPMatchSkewAndReplay(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1_700_000_000, 0)
	cur := TOTPStep(now)
	for d := int64(-1); d <= 1; d++ {
		if step, ok := TOTPMatch(secret, TOTPCode(secret, cur+d), now, 0); !ok || step != cur+d {
			t.Errorf("skew %d refused", d)
		}
	}
	for _, d := range []int64{-2, 2} {
		if _, ok := TOTPMatch(secret, TOTPCode(secret, cur+d), now, 0); ok {
			t.Errorf("skew %d accepted", d)
		}
	}
	// A step at or before the last accepted one never matches.
	if _, ok := TOTPMatch(secret, TOTPCode(secret, cur), now, cur); ok {
		t.Error("replayed code accepted")
	}
	if _, ok := TOTPMatch(secret, TOTPCode(secret, cur-1), now, cur-1); ok {
		t.Error("older code accepted after a newer one")
	}
	if _, ok := TOTPMatch(secret, "12345", now, 0); ok {
		t.Error("short code accepted")
	}
}

func TestTOTPURI(t *testing.T) {
	uri := TOTPURI("HardyOS (nas)", `HOME\alice`, []byte("12345678901234567890"))
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("bad uri %q: %v", uri, err)
	}
	q := u.Query()
	if q.Get("secret") != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" || q.Get("digits") != "6" || q.Get("period") != "30" || q.Get("issuer") != "HardyOS (nas)" {
		t.Errorf("query %v", q)
	}
	if !strings.Contains(u.Path, `HOME\alice`) {
		t.Errorf("label %q", u.Path)
	}
}

type mfaFixture struct {
	m      *MFA
	now    time.Time
	u      *User
	adm    *User
	mu     sync.Mutex
	events []MFAEvent
}

var (
	home = Inside
	away = Origin{Outside: true, IP: "203.0.113.7"}
)

func newMFA(t *testing.T) *mfaFixture {
	t.Helper()
	db := newDB(t)
	users := &Users{DB: db}
	ctx := context.Background()
	u, err := users.Create(ctx, NewUser{Username: "kid", Password: "kidpassword1", Role: RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	adm, err := users.Create(ctx, NewUser{Username: "owner", Password: "ownerpassword1", Role: RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	f := &mfaFixture{now: time.Unix(1_800_000_000, 0), u: u, adm: adm}
	f.m = &MFA{DB: db, Sealer: newTestSealer(), Now: func() time.Time { return f.now },
		Notify: func(_ context.Context, e MFAEvent) { f.mu.Lock(); f.events = append(f.events, e); f.mu.Unlock() }}
	f.m.init()
	f.m.Limiter.now = func() time.Time { return f.now }
	f.m.recovery.now = f.m.Limiter.now
	f.m.enroll.now = f.m.Limiter.now
	return f
}

func (f *mfaFixture) sawEvent(kind string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.events {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// enroll sets up u and returns its raw secret and recovery codes.
func (f *mfaFixture) enroll(t *testing.T, u *User) ([]byte, []string) {
	t.Helper()
	ctx := context.Background()
	e, err := f.m.BeginEnroll(ctx, u, "HardyOS", "b1")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := b32.DecodeString(strings.ReplaceAll(e.Secret, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.ConfirmEnroll(ctx, u, "000000x", "b1", home); !errors.Is(err, ErrBadCode) {
		t.Fatalf("bad first code: %v", err)
	}
	// Only what started the setup can finish it.
	if _, err := f.m.ConfirmEnroll(ctx, u, TOTPCode(secret, TOTPStep(f.now)), "other", home); !errors.Is(err, ErrNoPending) {
		t.Fatalf("finished from another challenge: %v", err)
	}
	codes, err := f.m.ConfirmEnroll(ctx, u, TOTPCode(secret, TOTPStep(f.now)), "b1", home)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("%d recovery codes", len(codes))
	}
	return secret, codes
}

// code is the authenticator code n steps from now.
func (f *mfaFixture) code(secret []byte, n int64) string { return TOTPCode(secret, TOTPStep(f.now)+n) }

func TestMFAEnrollVerifyReplay(t *testing.T) {
	f := newMFA(t)
	ctx := context.Background()
	if need, _ := f.m.Requirement(ctx, f.u, false); need != NeedNothing {
		t.Fatalf("user without 2FA at home: %q", need)
	}
	if need, _ := f.m.Requirement(ctx, f.u, true); need != NeedSetupCode {
		t.Fatalf("user without 2FA outside: %q", need)
	}
	secret, _ := f.enroll(t, f.u)
	if need, _ := f.m.Requirement(ctx, f.u, false); need != NeedCode {
		t.Fatalf("enrolled: %q", need)
	}
	// The enrollment code itself can't be used again.
	if _, err := f.m.Verify(ctx, f.u, f.code(secret, 0), home); !errors.Is(err, ErrBadCode) {
		t.Fatalf("enrollment code replayed: %v", err)
	}
	f.now = f.now.Add(30 * time.Second)
	code := f.code(secret, 0)
	if fac, err := f.m.Verify(ctx, f.u, code[:3]+" "+code[3:], home); err != nil || fac != FactorTOTP {
		t.Fatalf("verify: %v %v", fac, err)
	}
	if _, err := f.m.Verify(ctx, f.u, code, home); !errors.Is(err, ErrBadCode) {
		t.Fatalf("replay: %v", err)
	}
	// Concurrent use of one fresh code: exactly one wins.
	f.now = f.now.Add(30 * time.Second)
	code = f.code(secret, 0)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.m.Verify(ctx, f.u, code, home); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d concurrent uses of one code succeeded", wins)
	}
	st, err := f.m.Status(ctx, f.u)
	if err != nil || !st.Enabled || st.RecoveryCodesLeft != RecoveryCodeCount {
		t.Fatalf("status %+v %v", st, err)
	}
}

func TestMFASecretSealedAtRest(t *testing.T) {
	f := newMFA(t)
	secret, _ := f.enroll(t, f.u)
	var stored []byte
	if err := f.m.DB.QueryRow(`SELECT secret FROM user_totp WHERE user_id = ?`, f.u.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, secret) || len(stored) <= len(secret) {
		t.Fatal("secret stored in the clear")
	}
	// Moved to another account's row, it doesn't open.
	f.m.DB.Exec(`INSERT INTO user_totp (user_id, secret, enabled_at, updated_at) VALUES (?, ?, 'x', 'x')`, f.adm.ID, stored)
	if _, err := f.m.Verify(context.Background(), f.adm, f.code(secret, 1), home); !errors.Is(err, ErrSecretUnusable) {
		t.Fatalf("moved secret: %v", err)
	}
}

func TestMFARecoveryCodesSingleUse(t *testing.T) {
	f := newMFA(t)
	ctx := context.Background()
	_, codes := f.enroll(t, f.u)
	if fac, err := f.m.Verify(ctx, f.u, strings.ToUpper(codes[0]), away); err != nil || fac != FactorRecovery {
		t.Fatalf("recovery code: %v %v", fac, err)
	}
	if _, err := f.m.Verify(ctx, f.u, codes[0], home); !errors.Is(err, ErrBadCode) {
		t.Fatalf("recovery code reused: %v", err)
	}
	st, _ := f.m.Status(ctx, f.u)
	if st.RecoveryCodesLeft != RecoveryCodeCount-1 {
		t.Fatalf("left %d", st.RecoveryCodesLeft)
	}
	var n int
	f.m.DB.QueryRow(`SELECT COUNT(*) FROM user_recovery_codes WHERE code_hash LIKE ?`, "%"+strings.ReplaceAll(codes[1], "-", "")+"%").Scan(&n)
	if n != 0 {
		t.Fatal("recovery code stored in the clear")
	}
	fresh, err := f.m.RegenerateRecoveryCodes(ctx, f.u.ID)
	if err != nil || len(fresh) != RecoveryCodeCount {
		t.Fatal(err)
	}
	if _, err := f.m.Verify(ctx, f.u, codes[1], home); !errors.Is(err, ErrBadCode) {
		t.Fatal("old recovery code still works after regenerating")
	}
}

// Wrong codes from outside never lock the owner out at home (review H1).
func TestMFAOutsideFailuresDontLockHome(t *testing.T) {
	f := newMFA(t)
	ctx := context.Background()
	secret, codes := f.enroll(t, f.u)
	for i := range 5 {
		if _, err := f.m.Verify(ctx, f.u, "000000", away); !errors.Is(err, ErrBadCode) {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	var rl *CodeRateLimited
	if _, err := f.m.Verify(ctx, f.u, f.code(secret, 1), away); !errors.As(err, &rl) {
		t.Fatalf("outside address not paused: %v", err)
	}
	if f.sawEvent("short_lock") != 1 {
		t.Fatalf("pause not reported: %+v", f.events)
	}
	// Another address and home are separate buckets.
	if _, err := f.m.Verify(ctx, f.u, f.code(secret, 1), home); err != nil {
		t.Fatalf("home blocked by outside failures: %v", err)
	}
	other := Origin{Outside: true, IP: "198.51.100.9"}
	f.now = f.now.Add(30 * time.Second)
	if _, err := f.m.Verify(ctx, f.u, f.code(secret, 1), other); err != nil {
		t.Fatalf("another address blocked: %v", err)
	}
	// IPv6 counts per /64.
	v6a, v6b := Origin{Outside: true, IP: "2001:db8:1:2::1"}, Origin{Outside: true, IP: "2001:db8:1:2::ffff"}
	for range 5 {
		_, _ = f.m.Verify(ctx, f.u, "000000", v6a)
	}
	if _, err := f.m.Verify(ctx, f.u, "000000", v6b); !errors.As(err, &rl) {
		t.Fatalf("same /64 not shared: %v", err)
	}
	// Recovery codes have their own bucket: they work while codes are paused.
	if _, err := f.m.Verify(ctx, f.u, codes[0], away); err != nil {
		t.Fatalf("recovery code while paused: %v", err)
	}
	// Wrong codes at home don't count toward the budget.
	f.now = f.now.Add(time.Hour)
	for range 4 {
		_, _ = f.m.Verify(ctx, f.u, "000001", home)
	}
	st, _ := f.m.Status(ctx, f.u)
	if st.OutsideFailures != 0 {
		// The recovery code above started the budget again.
		t.Fatalf("outside failures %d", st.OutsideFailures)
	}
}

// The rolling budget: a right code doesn't reset it; at the budget codes
// from outside stop until a new password or a reset, never at home
// (review H1, M1).
func TestMFAOutsideBudget(t *testing.T) {
	f := newMFA(t)
	ctx := context.Background()
	secret, codes := f.enroll(t, f.u)
	fail := func(n int) {
		for range n {
			f.now = f.now.Add(16 * time.Minute) // past each pause
			_, _ = f.m.Verify(ctx, f.u, "000000", away)
		}
	}
	fail(OutsideFailureBudget - 1)
	if f.sawEvent("outside_failures") != (OutsideFailureBudget-1)/NoticeEvery {
		t.Fatalf("notices %+v", f.events)
	}
	// A right code from outside works but doesn't reset the budget.
	f.now = f.now.Add(16 * time.Minute)
	if _, err := f.m.Verify(ctx, f.u, f.code(secret, 0), away); err != nil {
		t.Fatalf("right code: %v", err)
	}
	fail(1)
	if f.sawEvent("outside_lock") != 1 {
		t.Fatalf("lock not reported: %+v", f.events)
	}
	f.now = f.now.Add(16 * time.Minute)
	if _, err := f.m.Verify(ctx, f.u, f.code(secret, 0), away); !errors.Is(err, ErrCodeLocked) {
		t.Fatalf("codes from outside after the budget: %v", err)
	}
	if st, _ := f.m.Status(ctx, f.u); !st.Locked {
		t.Fatal("status doesn't show the lock")
	}
	// At home codes still work; a recovery code doesn't lift the lock.
	if _, err := f.m.Verify(ctx, f.u, f.code(secret, 0), home); err != nil {
		t.Fatalf("home after the lock: %v", err)
	}
	if _, err := f.m.Verify(ctx, f.u, codes[3], away); err != nil {
		t.Fatalf("recovery code: %v", err)
	}
	f.now = f.now.Add(30 * time.Second)
	if _, err := f.m.Verify(ctx, f.u, f.code(secret, 0), away); !errors.Is(err, ErrCodeLocked) {
		t.Fatalf("lock lifted by a recovery code: %v", err)
	}
	// Re-enrolling doesn't lift it either.
	f.now = f.now.Add(time.Minute)
	e, _ := f.m.BeginEnroll(ctx, f.u, "HardyOS", "b2")
	ns, _ := b32.DecodeString(strings.ReplaceAll(e.Secret, " ", ""))
	if _, err := f.m.ConfirmEnroll(ctx, f.u, f.code(ns, 0), "b2", home); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(30 * time.Second)
	if _, err := f.m.Verify(ctx, f.u, f.code(ns, 0), away); !errors.Is(err, ErrCodeLocked) {
		t.Fatalf("lock lifted by re-enrolling: %v", err)
	}
	// A password set before the lock doesn't lift it; one after does.
	if f.m.ClearOutsideLock(ctx, f.u.ID, f.now.Add(-24*time.Hour)) {
		t.Fatal("an older password lifted the lock")
	}
	if !f.m.ClearOutsideLock(ctx, f.u.ID, f.now) {
		t.Fatal("new password didn't lift the lock")
	}
	f.now = f.now.Add(30 * time.Second)
	if _, err := f.m.Verify(ctx, f.u, f.code(ns, 0), away); err != nil {
		t.Fatalf("after a new password: %v", err)
	}
	// Failures older than the window fall out.
	fail(3)
	f.now = f.now.Add(OutsideFailureWindow + time.Hour)
	if st, _ := f.m.Status(ctx, f.u); st.OutsideFailures != 0 {
		t.Fatalf("old failures still counted: %d", st.OutsideFailures)
	}
}

// Attempts are reserved atomically: concurrent wrong codes can't buy more
// than the limit (review L1).
func TestMFAConcurrentTriesBounded(t *testing.T) {
	f := newMFA(t)
	ctx := context.Background()
	f.enroll(t, f.u)
	var wg sync.WaitGroup
	var mu sync.Mutex
	tried := 0
	for range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.m.Verify(ctx, f.u, "000000", away)
			if errors.Is(err, ErrBadCode) {
				mu.Lock()
				tried++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if tried != 5 {
		t.Fatalf("%d codes were checked, want 5", tried)
	}
}

func TestMFAAdminGraceAndReset(t *testing.T) {
	f := newMFA(t)
	ctx := context.Background()
	if err := f.m.SetGraceDays(ctx, 31); !errors.Is(err, ErrInvalidGraceDay) {
		t.Fatal("31 days accepted")
	}
	if err := f.m.SetGraceDays(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if need, _ := f.m.Requirement(ctx, f.adm, false); need != NeedNothing {
		t.Fatalf("admin in grace: %q", need)
	}
	st, _ := f.m.Status(ctx, f.adm)
	if st.GraceUntil == nil || !st.GraceUntil.Equal(f.now.Add(72*time.Hour).Truncate(time.Millisecond)) || !st.Required {
		t.Fatalf("grace %+v", st)
	}
	if ok, _ := f.m.PasswordAllowed(ctx, f.adm, false); !ok {
		t.Fatal("service password refused in grace")
	}
	f.now = f.now.Add(73 * time.Hour)
	if need, _ := f.m.Requirement(ctx, f.adm, false); need != NeedEnroll {
		t.Fatalf("admin past grace: %q", need)
	}
	if must, _ := f.m.MustEnroll(ctx, f.adm); !must {
		t.Fatal("session not limited to enrollment")
	}
	if ok, _ := f.m.PasswordAllowed(ctx, f.adm, false); ok {
		t.Fatal("service password allowed while enrollment is due")
	}
	f.enroll(t, f.adm)
	if err := f.m.Disable(ctx, f.adm); !errors.Is(err, ErrAdminMustKeep) {
		t.Fatal("admin turned 2FA off")
	}
	if err := f.m.Reset(ctx, f.adm.ID, true); err != nil {
		t.Fatal(err)
	}
	if need, _ := f.m.Requirement(ctx, f.adm, false); need != NeedEnroll {
		t.Fatalf("after reset an admin enrolls at once: %q", need)
	}
	f.enroll(t, f.u)
	if ok, _ := f.m.PasswordAllowed(ctx, f.u, false); ok {
		t.Fatal("service password allowed with 2FA on")
	}
	if err := f.m.Disable(ctx, f.u); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.m.Enabled(ctx, f.u.ID); ok {
		t.Fatal("still enabled")
	}
	if ok, _ := f.m.PasswordAllowed(ctx, f.u, true); ok {
		t.Fatal("service password allowed from outside")
	}
}

func TestMFASetupCode(t *testing.T) {
	f := newMFA(t)
	ctx := context.Background()
	if err := f.m.ConsumeSetupCode(ctx, f.u.ID, "abcd-efgh-ijkm-npqr", away); !errors.Is(err, ErrBadSetupCode) {
		t.Fatal("code accepted with none issued")
	}
	code, until, err := f.m.IssueSetupCode(ctx, f.u.ID)
	if err != nil || !until.Equal(f.now.Add(SetupCodeTTL)) {
		t.Fatal(err)
	}
	if err := f.m.ConsumeSetupCode(ctx, f.adm.ID, code, away); err == nil {
		t.Fatal("another account's code accepted")
	}
	// Exactly one of several concurrent uses wins.
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o := Origin{Outside: true, IP: "203.0.113." + strconv.Itoa(10+i)}
			if f.m.ConsumeSetupCode(ctx, f.u.ID, code, o) == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("setup code used %d times", wins)
	}
	code, _, _ = f.m.IssueSetupCode(ctx, f.adm.ID)
	f.now = f.now.Add(SetupCodeTTL + time.Second)
	if err := f.m.ConsumeSetupCode(ctx, f.adm.ID, code, away); !errors.Is(err, ErrBadSetupCode) {
		t.Fatal("expired setup code accepted")
	}
}

func TestMFAPendingExpires(t *testing.T) {
	f := newMFA(t)
	ctx := context.Background()
	e, _ := f.m.BeginEnroll(ctx, f.u, "HardyOS", "b1")
	secret, _ := b32.DecodeString(strings.ReplaceAll(e.Secret, " ", ""))
	f.now = f.now.Add(pendingTTL + time.Minute)
	if _, err := f.m.ConfirmEnroll(ctx, f.u, f.code(secret, 0), "b1", home); !errors.Is(err, ErrNoPending) {
		t.Fatalf("stale enrollment confirmed: %v", err)
	}
}

func TestChallenges(t *testing.T) {
	now := time.Unix(1000, 0)
	c := &Challenges{Now: func() time.Time { return now }}
	tok, _, err := c.Issue(7, NeedCode, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := range MaxChallengeTries {
		if ch, err := c.Get(tok); err != nil || ch.UserID != 7 {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	if _, err := c.Get(tok); !errors.Is(err, ErrNoChallenge) {
		t.Fatal("challenge outlived its tries")
	}
	tok, _, _ = c.Issue(7, NeedCode, false)
	now = now.Add(ChallengeTTL + time.Second)
	if _, err := c.Get(tok); !errors.Is(err, ErrNoChallenge) {
		t.Fatal("expired challenge accepted")
	}
	tok, _, _ = c.Issue(8, NeedCode, true)
	c.DropUser(8)
	if _, err := c.Get(tok); !errors.Is(err, ErrNoChallenge) {
		t.Fatal("dropped challenge accepted")
	}
	if _, err := c.Get("short"); !errors.Is(err, ErrNoChallenge) {
		t.Fatal("short token")
	}
}

func TestAppPasswords(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	users := &Users{DB: db}
	local, _ := users.Create(ctx, NewUser{Username: "kid", Password: "kidpassword1", Role: RoleUser})
	alice, err := users.UpsertDomain(ctx, DomainUpdate{Principal: `HOME\alice`, Role: RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	ap := &AppPasswords{DB: db}
	if _, _, err := ap.Create(ctx, local, "Phone", []string{ScopeMail}); !errors.Is(err, ErrAppPasswordLocal) {
		t.Fatal("local account got an app password")
	}
	if _, _, err := ap.Create(ctx, alice, "", []string{ScopeMail}); !errors.Is(err, ErrAppPasswordName) {
		t.Fatal("empty name")
	}
	if _, _, err := ap.Create(ctx, alice, "Phone", []string{"root"}); !errors.Is(err, ErrAppPasswordScopes) {
		t.Fatal("unknown scope")
	}
	p, secret, err := ap.Create(ctx, alice, "Phone", []string{ScopeMail, ScopeMail, ScopeCalendars})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Scopes) != 2 || !LooksLikeAppPassword(secret) || LooksLikeAppPassword("correct horse battery staple") {
		t.Fatalf("%+v %q", p, secret)
	}
	if ok, _ := ap.Check(ctx, alice.ID, secret, ScopeMail, "192.168.1.5"); !ok {
		t.Fatal("app password refused")
	}
	if ok, _ := ap.Check(ctx, alice.ID, strings.ToUpper(strings.ReplaceAll(secret, "-", " ")), ScopeCalendars, "10.0.0.2"); !ok {
		t.Fatal("app password typed with spaces refused")
	}
	if ok, _ := ap.Check(ctx, alice.ID, secret, ScopeFiles, ""); ok {
		t.Fatal("out-of-scope use accepted")
	}
	if ok, _ := ap.Check(ctx, local.ID, secret, ScopeMail, ""); ok {
		t.Fatal("another account's app password accepted")
	}
	list, _ := ap.List(ctx, alice.ID)
	if len(list) != 1 || list[0].LastUsedAt == nil || list[0].LastUsedIP == "" {
		t.Fatalf("list %+v", list)
	}
	if err := ap.Delete(ctx, local.ID, p.ID); err == nil {
		t.Fatal("deleted another account's app password")
	}
	if n := ap.RevokeBefore(ctx, alice.ID, time.Now().Add(time.Minute)); n != 1 {
		t.Fatalf("revoked %d", n)
	}
	if ok, _ := ap.Check(ctx, alice.ID, secret, ScopeMail, ""); ok {
		t.Fatal("revoked app password works")
	}
	if PasswordPolicy(false, true) || PasswordPolicy(true, false) || !PasswordPolicy(false, false) {
		t.Fatal("password policy")
	}
}
