package rootauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/domain"
)

type fakeDomain struct {
	cfg *domain.Config
	ug  map[string]*domain.UserGroups
}

func (f *fakeDomain) Load() (*domain.Config, error) { return f.cfg, nil }
func (f *fakeDomain) UserGroups(_ context.Context, u string) (*domain.UserGroups, error) {
	if g, ok := f.ug[u]; ok {
		return g, nil
	}
	return nil, errors.New("no such user")
}

func TestLocalVerifiers(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	c := &Checker{Dir: dir}
	if err := c.Check(ctx, "admin", "correct horse"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("nobody enrolled: %v", err)
	}
	// The installer's seed (a hash made like internal/auth's).
	h, _ := hash("correct horse")
	seed := filepath.Join(dir, "seed.json")
	if err := os.WriteFile(seed, []byte(`{"username":"Admin","passwordHash":"`+h+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Seed(seed); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(ctx, "admin", "correct horse"); err != nil {
		t.Fatalf("seeded admin: %v", err)
	}
	if err := c.Check(ctx, "admin", "wrong"); !errors.Is(err, ErrWrong) {
		t.Fatalf("wrong password: %v", err)
	}
	// A seed written later (hardyd owns the file) is never read again.
	h2, _ := hash("other")
	_ = os.WriteFile(seed, []byte(`{"username":"evil","passwordHash":"`+h2+`"}`), 0o600)
	_ = c.Seed(seed)
	if err := c.Check(ctx, "evil", "other"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("a later seed was taken: %v", err)
	}
	// Without a seed at the first start: nobody, and still never again.
	c2 := &Checker{Dir: t.TempDir()}
	if err := c2.Seed(filepath.Join(dir, "missing.json")); err != nil {
		t.Fatal(err)
	}
	if err := c2.Seed(seed); err != nil {
		t.Fatal(err)
	}
	if err := c2.Check(ctx, "evil", "other"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("a seed after the first start was taken: %v", err)
	}
	// Changing needs the old password root has.
	if err := c.Change(ctx, "admin", "wrong", "new password 1"); err == nil {
		t.Fatal("changed without the old password")
	}
	if err := c.Change(ctx, "admin", "correct horse", "new password 1"); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(ctx, "admin", "new password 1"); err != nil {
		t.Fatal(err)
	}
	// Root counts failures itself.
	for i := 0; i < maxFails; i++ {
		_ = c.Check(ctx, "admin", "nope")
	}
	if err := c.Check(ctx, "admin", "new password 1"); !errors.Is(err, ErrTooMany) {
		t.Fatalf("after %d failures: %v", maxFails, err)
	}
}

func TestDomainAdmins(t *testing.T) {
	ctx := context.Background()
	fd := &fakeDomain{
		cfg: &domain.Config{Enabled: true, Realm: "HOME.EXAMPLE", NetBIOS: "HOME", Domain: "home.example", Address: "192.168.1.250/24", AdminsGroupSID: "S-1-5-21-1-2-3-1105"},
		ug: map[string]*domain.UserGroups{
			"alice": {Enabled: true, DomainSID: "S-1-5-21-1-2-3", GroupSIDs: []string{"S-1-5-21-1-2-3-513", "S-1-5-21-1-2-3-512"}},
			"bob":   {Enabled: true, DomainSID: "S-1-5-21-1-2-3", GroupSIDs: []string{"S-1-5-21-1-2-3-1105"}},
			"carol": {Enabled: true, DomainSID: "S-1-5-21-1-2-3", GroupSIDs: []string{"S-1-5-21-1-2-3-513"}},
			"dave":  {Enabled: false, DomainSID: "S-1-5-21-1-2-3", GroupSIDs: []string{"S-1-5-21-1-2-3-512"}},
		},
	}
	var asked []string
	c := &Checker{Dir: t.TempDir(), Domain: fd, Login: func(_ context.Context, cfg *domain.Config, user, pw string) error {
		asked = append(asked, user)
		if pw != "pw-"+user {
			return ErrWrong
		}
		return nil
	}}
	for user, want := range map[string]error{
		`HOME\alice`: nil, `home\bob`: nil, `HOME\carol`: ErrNotAdmin, `HOME\dave`: ErrWrong, `OTHER\alice`: ErrWrong,
	} {
		name := user[len(`HOME\`):]
		if err := c.Check(ctx, user, "pw-"+name); !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Errorf("%s: %v, want %v", user, err, want)
		}
	}
	if err := c.Check(ctx, `HOME\alice`, "wrong"); !errors.Is(err, ErrWrong) {
		t.Errorf("wrong domain password: %v", err)
	}
	fd.cfg.Enabled = false
	if err := c.Check(ctx, `HOME\alice`, "pw-alice"); !errors.Is(err, ErrDomain) {
		t.Errorf("no domain: %v", err)
	}
}
