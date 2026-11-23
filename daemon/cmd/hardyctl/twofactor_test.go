package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

var codeRE = regexp.MustCompile(`[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}-[a-z2-9]{4}`)

func newDB(t *testing.T) (string, *store.DB) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hardyd.db")
	db, err := store.Open(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return p, db
}

func auditCount(t *testing.T, db *store.DB, action string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_log WHERE action = ?`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The first boot shows one setup code for the only administrator, once;
// the code works for enrolling from outside (re-review HIGH 1).
func TestFirstBootCode(t *testing.T) {
	ctx := context.Background()
	path, db := newDB(t)
	issue := filepath.Join(t.TempDir(), "run", "code.issue")
	var out bytes.Buffer
	// No administrator yet: nothing.
	if err := firstBootCode(path, issue, "", 0, &out); err != nil || out.Len() != 0 {
		t.Fatalf("no admin: %v %q", err, out.String())
	}
	u, err := (&auth.Users{DB: db}).Create(ctx, auth.NewUser{Username: "cade", Password: "supersecret1", Role: auth.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if err := firstBootCode(path, issue, "", 0, &out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(issue)
	code := codeRE.FindString(string(b))
	if code == "" || err != nil || codeRE.MatchString(out.String()) {
		t.Fatalf("issue %q %v; output (no code there) %q", b, err, out.String())
	}

	if fi, _ := os.Stat(issue); fi.Mode().Perm() != 0o600 {
		t.Fatalf("issue mode %v", fi.Mode())
	}
	if auditCount(t, db, "recovery.2fa_setup_code") != 1 {
		t.Fatal("not audited")
	}
	// Once: the next boot clears the screen and issues nothing.
	out.Reset()
	if err := firstBootCode(path, issue, "", 0, &out); err != nil || out.Len() != 0 {
		t.Fatalf("second boot: %v %q", err, out.String())
	}
	if _, err := os.Stat(issue); !os.IsNotExist(err) {
		t.Fatal("the code stayed on the login screen")
	}
	m := &auth.MFA{DB: db}
	if err := m.ConsumeSetupCode(ctx, u.ID, code, auth.Origin{Outside: true, IP: "203.0.113.9"}); err != nil {
		t.Fatalf("first-boot code: %v", err)
	}
}

// On a real first boot hardyd makes the installer's administrator from the
// seed only once it starts: the code waits for it (the CI smoke test's
// first failure).
func TestFirstBootCodeWaitsForTheSeed(t *testing.T) {
	ctx := context.Background()
	path, db := newDB(t)
	dir := t.TempDir()
	seed, issue := filepath.Join(dir, "install-seed.json"), filepath.Join(dir, "code.issue")
	if err := os.WriteFile(seed, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		if _, err := (&auth.Users{DB: db}).Create(ctx, auth.NewUser{Username: "smoke", Password: "supersecret1", Role: auth.RoleAdmin}); err != nil {
			t.Error(err)
		}
		os.Remove(seed)
	}()
	var out bytes.Buffer
	if err := firstBootCode(path, issue, seed, 10*time.Second, &out); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(issue); err != nil || !codeRE.Match(b) || !strings.Contains(string(b), "smoke") {
		t.Fatalf("no code after the seed: %q %v", b, err)
	}
}

func TestSetupCodeCommand(t *testing.T) {
	ctx := context.Background()
	path, db := newDB(t)
	u, err := (&auth.Users{DB: db}).Create(ctx, auth.NewUser{Username: "kid", Password: "kidpassword1", Role: auth.RoleUser})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := setupCode(path, []string{"kid"}, &out); err != nil {
		t.Fatal(err)
	}
	code := codeRE.FindString(out.String())
	if code == "" || auditCount(t, db, "recovery.2fa_setup_code") != 1 {
		t.Fatalf("setup-code: %q", out.String())
	}
	m := &auth.MFA{DB: db}
	o := auth.Origin{Outside: true, IP: "203.0.113.9"}
	if err := m.ConsumeSetupCode(ctx, u.ID, code, o); err != nil {
		t.Fatal(err)
	}
	if err := m.ConsumeSetupCode(ctx, u.ID, code, o); err == nil {
		t.Fatal("used twice")
	}
	if err := setupCode(path, []string{"nobody"}, &out); err == nil {
		t.Fatal("unknown user")
	}
}

func TestTrustRouterCommand(t *testing.T) {
	path, db := newDB(t)
	var out bytes.Buffer
	if err := trustRouter(path, []string{"maybe"}, &out); err == nil {
		t.Fatal("bad argument accepted")
	}
	if err := trustRouter(path, []string{"status"}, &out); err != nil || !strings.HasPrefix(out.String(), "Off") {
		t.Fatalf("status: %v %q", err, out.String())
	}
	if err := trustRouter(path, []string{"off"}, &out); err != nil || auditCount(t, db, "auth.2fa.trust_router") != 1 {
		t.Fatalf("off: %v", err)
	}
	// "on" needs this machine's real router; it's either trusted or
	// refused for want of one, never anything else.
	out.Reset()
	err := trustRouter(path, []string{"on"}, &out)
	if err != nil && !strings.Contains(err.Error(), "no default router") {
		t.Fatalf("on: %v", err)
	}
}
