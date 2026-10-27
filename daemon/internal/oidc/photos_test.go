package oidc

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// The Photos scope gives Immich a role, a storage label and an e-mail
// address for every account, in the ID token (Immich reads the ID token
// when it has an address) and at userinfo.
func TestPhotosScopeClaims(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.domain.add("alice", "pw-alice", aliceGUID, "Family", "Domain Admins")
	if _, err := e.users.Create(ctx, auth.NewUser{Username: "bob.k", Password: "correct horse battery", Role: auth.RoleUser}); err != nil {
		t.Fatal(err)
	}
	if err := e.p.SetLocalAccounts(ctx, true); err != nil {
		t.Fatal(err)
	}
	id, secret, err := e.p.Clients.Ensure(ctx, "photos-immich", "Photos (Immich)", []string{rpCallback}, nil)
	if err != nil {
		t.Fatal(err)
	}
	flowFor := func() *flow {
		f := newFlow(id, secret)
		f.scopes = "openid email profile " + ScopePhotos
		return f
	}

	f := flowFor()
	tok := e.exchange(f, e.browser().login(f, `HOME\alice`, "pw-alice").Get("code"))
	c := e.verify(tok.IDToken)
	if c[ClaimPhotosRole] != "admin" || c[ClaimStorageLabel] != "alice" || c["email"] != "alice@home.example.net" {
		t.Fatalf("alice's photos claims: %v", c)
	}
	st, info := e.userinfo(tok.AccessToken)
	if st != 200 || info[ClaimPhotosRole] != "admin" || info[ClaimStorageLabel] != "alice" {
		t.Fatalf("userinfo %d %v", st, info)
	}

	f = flowFor()
	tok = e.exchange(f, e.browser().login(f, "bob.k", "correct horse battery").Get("code"))
	c = e.verify(tok.IDToken)
	if c[ClaimPhotosRole] != "user" || c[ClaimStorageLabel] != "bob.k" || c["email"] != "bob.k@hardyos.invalid" || c["email_verified"] != false {
		t.Fatalf("bob's photos claims (no e-mail: a placeholder): %v", c)
	}

	// Without the scope, none of it (NetBird and others see what they did).
	f = newFlow(id, secret)
	tok = e.exchange(f, e.browser().login(f, "bob.k", "correct horse battery").Get("code"))
	c = e.verify(tok.IDToken)
	if _, ok := c[ClaimPhotosRole]; ok || c["email"] != nil {
		t.Fatalf("photos claims without the scope: %v", c)
	}

	// ProfileFor matches what a sign-in says.
	u, err := e.users.GetByName(ctx, "bob.k")
	if err != nil {
		t.Fatal(err)
	}
	prof, err := e.p.ProfileFor(ctx, u)
	if err != nil || prof.Email != "bob.k@hardyos.invalid" || prof.StorageLabel != "bob.k" || prof.Admin || !strings.HasPrefix(prof.Subject, "local-") {
		t.Fatalf("profile %+v %v", prof, err)
	}
}

// ManagedAccess refuses people a managed client's owner doesn't let in,
// before any code is handed out.
func TestManagedAccess(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.domain.add("alice", "pw-alice", aliceGUID, "Family")
	e.p.cfg.ManagedAccess = func(_ context.Context, key string, u *auth.User) error {
		if key == "photos-immich" && strings.EqualFold(u.IdentityPrincipal(), `HOME\alice`) {
			return errors.New("not for alice")
		}
		return nil
	}
	id, secret, err := e.p.Clients.Ensure(ctx, "photos-immich", "Photos (Immich)", []string{rpCallback}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := newFlow(id, secret)
	b := e.browser()
	resp, page := b.signIn(body(b.authorize(f)), `HOME\alice`, "pw-alice")
	if resp.StatusCode == http.StatusFound || !strings.Contains(page, "Not for alice") {
		t.Fatalf("refused person signed in: %d %s", resp.StatusCode, page)
	}
}

func TestStorageLabel(t *testing.T) {
	for in, want := range map[string]string{
		"alice": "alice", "Bob.K": "bob.k", "joe smith": "joe-smith", "..": "user", "": "user",
		".hidden": "hidden", "Ünïcode": "-n-code", strings.Repeat("a", 80): strings.Repeat("a", 64),
	} {
		if got := StorageLabel(in); got != want {
			t.Errorf("StorageLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
