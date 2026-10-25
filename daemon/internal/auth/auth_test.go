package auth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

func newDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery", h) {
		t.Fatal("correct password rejected")
	}
	if VerifyPassword("wrong horse battery", h) {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("hashes must be salted")
	}
	if VerifyPassword("x", "not-a-hash") {
		t.Fatal("garbage hash accepted")
	}
}

func TestUsernameRules(t *testing.T) {
	for _, ok := range []string{"cade", "Cade", "mom.h", "kid_2", "a1"} {
		if _, err := NormalizeUsername(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a", "1abc", "root", "hardyd", "has space", "semi;colon", "averyveryveryveryveryverylongusername"} {
		if _, err := NormalizeUsername(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUserLifecycleAndLastAdminGuard(t *testing.T) {
	ctx := context.Background()
	users := &Users{DB: newDB(t)}

	admin, err := users.Create(ctx, NewUser{Username: "Cade", Role: RoleAdmin, Password: "supersecret1"})
	if err != nil {
		t.Fatal(err)
	}
	if admin.Username != "cade" {
		t.Fatalf("username not normalized: %q", admin.Username)
	}
	if _, err := users.Create(ctx, NewUser{Username: "cade", Role: RoleUser, Password: "supersecret1"}); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate err = %v", err)
	}
	if _, err := users.Create(ctx, NewUser{Username: "short", Role: RoleUser, Password: "abc"}); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("weak password err = %v", err)
	}

	userRole := RoleUser
	if _, err := users.Update(ctx, admin.ID, UserUpdate{Role: &userRole}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demoting last admin err = %v", err)
	}
	if err := users.Delete(ctx, admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("deleting last admin err = %v", err)
	}

	second, err := users.Create(ctx, NewUser{Username: "wife", Role: RoleAdmin, Password: "anothersecret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.Update(ctx, admin.ID, UserUpdate{Role: &userRole}); err != nil {
		t.Fatalf("demote with another admin: %v", err)
	}
	if err := users.Delete(ctx, second.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("second is now the last admin, err = %v", err)
	}
}

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()
	users := &Users{DB: newDB(t)}
	u, _ := users.Create(ctx, NewUser{Username: "cade", Role: RoleAdmin, Password: "supersecret1"})

	if _, err := users.Authenticate(ctx, "CADE", "supersecret1"); err != nil {
		t.Fatalf("valid login: %v", err)
	}
	if _, err := users.Authenticate(ctx, "cade", "nope-nope-nope"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong password err = %v", err)
	}
	if _, err := users.Authenticate(ctx, "ghost", "whatever123"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("unknown user err = %v", err)
	}

	other, _ := users.Create(ctx, NewUser{Username: "other", Role: RoleAdmin, Password: "supersecret2"})
	_ = other
	yes := true
	if _, err := users.Update(ctx, u.ID, UserUpdate{Disabled: &yes}); err != nil {
		t.Fatal(err)
	}
	if _, err := users.Authenticate(ctx, "cade", "supersecret1"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("disabled user err = %v", err)
	}
}

func TestSessions(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	users := &Users{DB: db}
	sessions := &Sessions{DB: db}
	u, _ := users.Create(ctx, NewUser{Username: "cade", Role: RoleAdmin, Password: "supersecret1"})

	token, _, err := sessions.Create(ctx, u.ID, "192.168.1.5", "test")
	if err != nil {
		t.Fatal(err)
	}
	info, err := sessions.Validate(ctx, token)
	if err != nil || info.UserID != u.ID {
		t.Fatalf("validate: %+v %v", info, err)
	}
	if _, err := sessions.Validate(ctx, token+"x"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("tampered token err = %v", err)
	}

	// Expired sessions are rejected and removed.
	if _, err := db.Exec(`UPDATE sessions SET expires_at = ?`, store.FormatTime(time.Now().Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Validate(ctx, token); !errors.Is(err, ErrNoSession) {
		t.Fatalf("expired err = %v", err)
	}

	token2, _, _ := sessions.Create(ctx, u.ID, "", "")
	if err := sessions.RevokeUser(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Validate(ctx, token2); !errors.Is(err, ErrNoSession) {
		t.Fatalf("revoked err = %v", err)
	}
}

func TestLoginLimiter(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	l := NewLoginLimiter()
	l.now = func() time.Time { return now }

	for i := 0; i < 4; i++ {
		l.Fail("1.2.3.4")
	}
	if ok, _ := l.Allowed("1.2.3.4"); !ok {
		t.Fatal("locked too early")
	}
	l.Fail("1.2.3.4")
	if ok, wait := l.Allowed("1.2.3.4"); ok || wait <= 0 {
		t.Fatalf("not locked after 5 failures (ok=%v wait=%v)", ok, wait)
	}
	now = now.Add(16 * time.Minute)
	if ok, _ := l.Allowed("1.2.3.4"); !ok {
		t.Fatal("still locked after lockout")
	}
	l.Fail("5.6.7.8")
	l.Succeed("5.6.7.8")
	if ok, _ := l.Allowed("5.6.7.8"); !ok {
		t.Fatal("success should clear failures")
	}
}
