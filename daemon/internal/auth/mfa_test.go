package auth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"net/url"
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
	m   *MFA
	now time.Time
	u   *User
	adm *User
}

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
	f.m = &MFA{DB: db, Sealer: newTestSealer(), Now: func() time.Time { return f.now }}
	return f
}

// enroll sets up u and returns its raw secret and recovery codes.
func (f *mfaFixture) enroll(t *testing.T, u *User) ([]byte, []string) {
	t.Helper()
	ctx := context.Background()
	e, err := f.m.BeginEnroll(ctx, u, "HardyOS")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := b32.DecodeString(strings.ReplaceAll(e.Secret, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.ConfirmEnroll(ctx, u, "000000x"); !errors.Is(err, ErrBadCode) {
		t.Fatalf("bad first code: %v", err)
	}
	codes, err := f.m.ConfirmEnroll(ctx, u, TOTPCode(secret, TOTPStep(f.now)))
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("%d recovery codes", len(codes))
	}
	return secret, codes
}

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
	if _, err := f.m.Verify(ctx, f.u, TOTPCode(secret, TOTPStep(f.now))); !errors.Is(err, ErrBadCode) {
		t.Fatalf("enrollment code replayed: %v", err)
	}
	f.now = f.now.Add(30 * time.Second)
	code := TOTPCode(secret, TOTPStep(f.now))
	if fac, err := f.m.Verify(ctx, f.u, code[:3]+" "+code[3:]); err != nil || fac != FactorTOTP {
		t.Fatalf("verify: %v %v", fac, err)
	}
	if _, err := f.m.Verify(ctx, f.u, code); !errors.Is(err, ErrBadCode) {
		t.Fatalf("replay: %v", err)
	}
	// Concurrent use of one fresh code: exactly one wins.
	f.now = f.now.Add(30 * time.Second)
	code = TOTPCode(secret, TOTPStep(f.now))
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.m.Verify(ctx, f.u, code); err == nil {
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
	if _, err := f.m.Verify(context.Background(), f.adm, TOTPCode(secret, TOTPStep(f.now)+1)); !errors.Is(err, ErrSecretUnusable) {
		t.Fatalf("moved secret: %v", err)
	}
}

func TestMFARecoveryCodesSingleUse(t *testing.T) {
	f := newMFA(t)
	ctx := context.Background()
	_, codes := f.enroll(t, f.u)
	if fac, err := f.m.Verify(ctx, f.u, strings.ToUpper(codes[0])); err != nil || fac != FactorRecovery {
		t.Fatalf("recovery code: %v %v", fac, err)
	}
	if _, err := f.m.Verify(ctx, f.u, codes[0]); !errors.Is(err, ErrBadCode) {
		t.Fatalf("recovery code reused: %v", err)
	}
	st, _ := f.m.Status(ctx, f.u)
	if st.RecoveryCodesLeft != RecoveryCodeCount-1 {
		t.Fatalf("left %d", st.RecoveryCodesLeft)
	}
	// Only hashes are stored.
	var n int
	f.m.DB.QueryRow(`SELECT COUNT(*) FROM user_recovery_codes WHERE code_hash LIKE ?`, "%"+strings.ReplaceAll(codes[1], "-", "")+"%").Scan(&n)
	if n != 0 {
		t.Fatal("recovery code stored in the clear")
	}
	fresh, err := f.m.RegenerateRecoveryCodes(ctx, f.u.ID)
	if err != nil || len(fresh) != RecoveryCodeCount {
		t.Fatal(err)
	}
	if _, err := f.m.Verify(ctx, f.u, codes[1]); !errors.Is(err, ErrBadCode) {
		t.Fatal("old recovery code still works after regenerating")
	}
}

func TestMFARateLimitAndLockout(t *testing.T) {
	f := newMFA(t)
	ctx := context.Background()
	secret, codes := f.enroll(t, f.u)
	clock := f.now
	f.m.Limiter.now = func() time.Time { return clock }
	for i := range 5 {
		if _, err := f.m.Verify(ctx, f.u, "000000"); !errors.Is(err, ErrBadCode) {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	var rl *CodeRateLimited
	good := TOTPCode(secret, TOTPStep(f.now)+1)
	if _, err := f.m.Verify(ctx, f.u, good); !errors.As(err, &rl) {
		t.Fatalf("not rate limited: %v", err)
	}
	// Wrong codes in a row, across lockout windows, stop authenticator
	// codes entirely.
	for i := 0; i < MaxCodeFailures; i++ {
		clock = clock.Add(16 * time.Minute)
		_, _ = f.m.Verify(ctx, f.u, "000001")
	}
	clock = clock.Add(16 * time.Minute)
	f.now = f.now.Add(time.Hour)
	if _, err := f.m.Verify(ctx, f.u, TOTPCode(secret, TOTPStep(f.now))); !errors.Is(err, ErrCodeLocked) {
		t.Fatalf("not locked: %v", err)
	}
	st, _ := f.m.Status(ctx, f.u)
	if !st.Locked {
		t.Fatal("status doesn't show the lock")
	}
	// A recovery code still works and lifts it.
	if _, err := f.m.Verify(ctx, f.u, codes[2]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Verify(ctx, f.u, TOTPCode(secret, TOTPStep(f.now))); err != nil {
		t.Fatalf("after recovery: %v", err)
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
	f.now = f.now.Add(73 * time.Hour)
	if need, _ := f.m.Requirement(ctx, f.adm, false); need != NeedEnroll {
		t.Fatalf("admin past grace: %q", need)
	}
	if must, _ := f.m.MustEnroll(ctx, f.adm); !must {
		t.Fatal("session not limited to enrollment")
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
	if err := f.m.Disable(ctx, f.u); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.m.Enabled(ctx, f.u.ID); ok {
		t.Fatal("still enabled")
	}
}

func TestMFASetupCode(t *testing.T) {
	f := newMFA(t)
	ctx := context.Background()
	if err := f.m.CheckSetupCode(ctx, f.u.ID, "abcd-efgh-ijkm-npqr"); !errors.Is(err, ErrBadSetupCode) {
		t.Fatal("code accepted with none issued")
	}
	code, until, err := f.m.IssueSetupCode(ctx, f.u.ID)
	if err != nil || !until.Equal(f.now.Add(SetupCodeTTL)) {
		t.Fatal(err)
	}
	if err := f.m.CheckSetupCode(ctx, f.u.ID, code); err != nil {
		t.Fatal(err)
	}
	if err := f.m.CheckSetupCode(ctx, f.adm.ID, code); err == nil {
		t.Fatal("another account's code accepted")
	}
	f.enroll(t, f.u) // uses it up
	if err := f.m.CheckSetupCode(ctx, f.u.ID, code); !errors.Is(err, ErrBadSetupCode) {
		t.Fatal("setup code reusable after enrollment")
	}
	code, _, _ = f.m.IssueSetupCode(ctx, f.adm.ID)
	f.now = f.now.Add(SetupCodeTTL + time.Second)
	if err := f.m.CheckSetupCode(ctx, f.adm.ID, code); !errors.Is(err, ErrBadSetupCode) {
		t.Fatal("expired setup code accepted")
	}
}

func TestMFAPendingExpires(t *testing.T) {
	f := newMFA(t)
	ctx := context.Background()
	e, _ := f.m.BeginEnroll(ctx, f.u, "HardyOS")
	secret, _ := b32.DecodeString(strings.ReplaceAll(e.Secret, " ", ""))
	f.now = f.now.Add(pendingTTL + time.Minute)
	if _, err := f.m.ConfirmEnroll(ctx, f.u, TOTPCode(secret, TOTPStep(f.now))); !errors.Is(err, ErrNoPending) {
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
