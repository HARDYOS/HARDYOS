package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/oidc"

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
	id, secret, err := e.p.Clients.Ensure(ctx, PhotosClientKey, "Photos (Immich)", []string{rpCallback}, nil)
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
	if c[ClaimPhotosRole] != "user" || c[ClaimStorageLabel] != "bob.k" || c["email"] != "bob.k@local.hardyos.invalid" || c["email_verified"] != false {
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
	if err != nil || prof.Email != "bob.k@local.hardyos.invalid" || prof.StorageLabel != "bob.k" || prof.Admin || !strings.HasPrefix(prof.Subject, "local-") {
		t.Fatalf("profile %+v %v", prof, err)
	}

	// A domain account without an address gets no placeholder.
	e.p.cfg.SignIn = &auth.SignIn{Users: e.users}
	ui := new(oidc.UserInfo)
	e.p.fillUserinfo(ctx, ui, &auth.User{ID: 99, Username: `HOME\nomail`, Principal: `HOME\nomail`, Source: auth.SourceDomain}, "sub", []string{"openid", "email", ScopePhotos})
	if ui.Email != "" {
		t.Fatalf("domain account got %q", ui.Email)
	}
}

// Only the Photos client gets the Photos scope: any other client asking
// for it gets none of its claims.
func TestPhotosScopeOnlyForPhotos(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.users.Create(ctx, auth.NewUser{Username: "bob", Password: "correct horse battery", Role: auth.RoleUser}); err != nil {
		t.Fatal(err)
	}
	_ = e.p.SetLocalAccounts(ctx, true)
	id, secret, err := e.p.Clients.Ensure(ctx, "remote-gateway", "Gateway", []string{rpCallback}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := newFlow(id, secret)
	f.scopes = "openid email profile " + ScopePhotos
	tok := e.exchange(f, e.browser().login(f, "bob", "correct horse battery").Get("code"))
	c := e.verify(tok.IDToken)
	if _, ok := c[ClaimPhotosRole]; ok || c["email"] != nil {
		t.Fatalf("another client got the photos claims: %v", c)
	}
	if _, info := e.userinfo(tok.AccessToken); info[ClaimStorageLabel] != nil {
		t.Fatalf("userinfo %v", info)
	}
}

// A redirect ConfirmRedirect names is always confirmed on a page, even
// with an existing sign-in, and prompt=none can't skip it.
func TestConfirmRedirect(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.domain.add("alice", "pw-alice", aliceGUID, "Family")
	const mobile = "https://rp.example.net/api/oauth/mobile-redirect"
	e.p.cfg.ConfirmRedirect = func(key, uri string) bool { return key == PhotosClientKey && uri == mobile }
	id, secret, err := e.p.Clients.Ensure(ctx, PhotosClientKey, "Photos (Immich)", []string{rpCallback, mobile}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := e.browser()
	b.login(newFlow(id, secret), `HOME\alice`, "pw-alice") // the web redirect: no question
	f := newFlow(id, secret)
	f.redirect = mobile
	resp := b.authorize(f)
	page := body(resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Continue to Photos (Immich)?") {
		t.Fatalf("mobile redirect with a session: %d %s", resp.StatusCode, page)
	}
	none := newFlow(id, secret)
	none.redirect = mobile
	none.extra = url.Values{"prompt": {"none"}}
	if r := b.authorize(none); r.StatusCode != http.StatusFound || !strings.Contains(r.Header.Get("Location"), "error=") {
		t.Fatalf("prompt=none skipped the question: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	form := formValues(page)
	form.Set("decision", "allow")
	r := b.post("/consent", form)
	p := body(r)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("confirmed: %d %s", r.StatusCode, p)
	}
	if loc := b.follow(p).Header.Get("Location"); !strings.HasPrefix(loc, mobile+"?code=") {
		t.Fatalf("after confirming: %q", loc)
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
		"alice": "alice", "Bob.K": "bob.k", "joe smith": "joe-smith", "..": "u-user", "": "u-user",
		".hidden": "hidden", "Ünïcode": "-n-code", strings.Repeat("a", 80): strings.Repeat("a", 64),
		"admin": "u-admin", "Family": "u-family", "hardyos-admin": "u-hardyos-admin", "unlinked-x": "u-unlinked-x",
	} {
		if got := StorageLabel(in); got != want {
			t.Errorf("StorageLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
