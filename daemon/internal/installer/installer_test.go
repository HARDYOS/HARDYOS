package installer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/install"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func TestApplySeed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(dir, "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	users := &auth.Users{DB: db}
	path := filepath.Join(dir, "install-seed.json")

	// No seed: nothing happens.
	if u, err := ApplySeed(ctx, users, path); u != nil || err != nil {
		t.Fatalf("no seed: %v %v", u, err)
	}

	hash, _ := auth.HashPassword("supersecret1")
	b, _ := json.Marshal(install.Seed{Username: "cade", DisplayName: "Cade Hardy", PasswordHash: hash})
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	u, err := ApplySeed(ctx, users, path)
	if err != nil || u == nil || u.Username != "cade" || u.Role != auth.RoleAdmin || !u.BreakGlass {
		t.Fatalf("seeded user %+v, %v", u, err)
	}
	if _, err := users.Authenticate(ctx, "cade", "supersecret1"); err != nil {
		t.Fatalf("seeded password does not work: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("seed file was not removed")
	}

	// A seed never adds an account to a system that already has some.
	b, _ = json.Marshal(install.Seed{Username: "intruder", PasswordHash: hash})
	_ = os.WriteFile(path, b, 0o600)
	if u, err := ApplySeed(ctx, users, path); u != nil || err != nil {
		t.Fatalf("second seed: %v %v", u, err)
	}
	if n, _ := users.Count(ctx); n != 1 {
		t.Fatalf("users = %d", n)
	}

	_ = os.WriteFile(path, []byte(`{"username":"x","passwordHash":"plain"}`), 0o600)
	if _, err := ApplySeed(ctx, users, path); err == nil {
		t.Fatal("expected an error for a bad seed")
	}
}

func TestUnlockSessions(t *testing.T) {
	root := t.TempDir()
	s := &Service{Limiter: auth.NewLoginLimiter(), Root: root}
	if _, err := s.Unlock("1.2.3.4", "K7QM-4TXP"); err != ErrNoCode {
		t.Fatalf("before the code exists: %v", err)
	}
	_ = os.MkdirAll(filepath.Join(root, "run/hardyos"), 0o755)
	_ = os.WriteFile(filepath.Join(root, install.CodeFile), []byte("K7QM-4TXP\n"), 0o640)
	if _, err := s.Unlock("1.2.3.4", "K7QM-4TXQ"); err != ErrBadCode {
		t.Fatalf("wrong code: %v", err)
	}
	tok, err := s.Unlock("1.2.3.4", "k7qm4txp")
	if err != nil || !s.Valid(tok) {
		t.Fatalf("unlock: %v", err)
	}
	if s.Valid("") || s.Valid(tok+"x") {
		t.Fatal("invalid tokens accepted")
	}
}
