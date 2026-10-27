package photos

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/oidc"
	"github.com/hardyos/hardyos/daemon/internal/photos/immichfake"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// fakeDir stands in for HardyOS's accounts: alice (admin, domain, in
// HOME\Family), bob (local, no e-mail) and carol (domain, not family).
type fakeDir struct {
	users map[int64]*auth.User
	subs  map[string]int64
}

func newFakeDir() *fakeDir {
	d := &fakeDir{users: map[int64]*auth.User{}, subs: map[string]int64{}}
	d.users[1] = &auth.User{ID: 1, Username: `HOME\alice`, Principal: `HOME\alice`, Source: auth.SourceDomain, Role: auth.RoleAdmin,
		DisplayName: "Alice", Email: "alice@home.example.net", Groups: []string{`HOME\Family`, `HOME\Domain Users`}}
	d.users[2] = &auth.User{ID: 2, Username: "bob", Role: auth.RoleUser, DisplayName: "Bob"}
	d.users[3] = &auth.User{ID: 3, Username: `HOME\carol`, Principal: `HOME\carol`, Source: auth.SourceDomain, Role: auth.RoleUser,
		DisplayName: "Carol", Email: "carol@home.example.net", Groups: []string{`HOME\Domain Users`}}
	for id := range d.users {
		d.subs[fmt.Sprintf("sub-%d", id)] = id
	}
	return d
}

func (d *fakeDir) UserByID(_ context.Context, id int64) (*auth.User, error) { return d.users[id], nil }

func (d *fakeDir) Profile(_ context.Context, u *auth.User) (*oidc.AppProfile, error) {
	short := u.Username
	if _, n, ok := strings.Cut(short, `\`); ok {
		short = n
	}
	email := u.Email
	if email == "" {
		email = oidc.PlaceholderEmail(oidc.StorageLabel(short))
	}
	return &oidc.AppProfile{Subject: fmt.Sprintf("sub-%d", u.ID), Email: email, Name: u.DisplayName, StorageLabel: oidc.StorageLabel(short), Admin: u.IsAdmin()}, nil
}

func (d *fakeDir) UserForSubject(_ context.Context, sub string) (*auth.User, error) {
	if id, ok := d.subs[sub]; ok {
		return d.users[id], nil
	}
	return nil, errors.New("unknown subject")
}

type testEnv struct {
	f     *immichfake.Fake
	dir   *fakeDir
	store *Store
	rec   *Reconciler
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	db, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	e := &testEnv{f: immichfake.New(), dir: newFakeDir(), store: &Store{DB: db}}
	t.Cleanup(e.f.Close)
	e.rec = &Reconciler{Immich: &Immich{Base: e.f.URL}, Store: e.store, Dir: e.dir, Ready: 5 * time.Second}
	return e
}

func (e *testEnv) plan(t *testing.T, set Settings) Plan {
	t.Helper()
	set, err := set.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	return Plan{
		Settings: set,
		Wanted: Wanted{OAuth: &OAuth{Issuer: "https://sso.home.example.net", ClientID: "hos-abc", ClientSecret: "s3cret",
			MobileRedirect: "https://immich.home.example.net/api/oauth/mobile-redirect"},
			MLURLs: MLURLs(MLCPU), ScanCron: set.ScanCron()},
		Access:         []appstore.Principal{},
		Shares:         map[string]bool{"PHOTOS": true, "EXISTING": true, "FAMILY": true},
		CheckOAuthFrom: "https://immich.home.example.net/auth/login",
	}
}

func (e *testEnv) run(t *testing.T, p Plan) *Status {
	t.Helper()
	st := &Status{Notes: []string{}}
	if err := e.rec.Run(context.Background(), p, st); err != nil {
		t.Fatalf("sync: %v (status %+v)", err, st)
	}
	return st
}

func cfgAt(m map[string]any, p string) any { return lookup(m, p) }

func TestReconcileFreshImmich(t *testing.T) {
	e := newTestEnv(t)
	set := Defaults()
	set.Libraries = []Library{{OwnerID: 2, Share: "EXISTING", Path: "Bob/Pictures", Name: "Bob's old photos"}}
	set.Family = Family{Enabled: true, Name: "Family Photos", Members: []appstore.Principal{{Kind: "group", Name: `HOME\Family`}, {Kind: "user", Name: "bob"}}}
	p := e.plan(t, set)

	st := e.run(t, p)

	acct, _ := e.store.Account(context.Background())
	if acct.AdminEmail != AdminEmail || acct.AdminPassword == "" || acct.AdminKey == "" || acct.Linked {
		t.Fatalf("admin account %+v", acct)
	}
	if k := e.f.Keys[acct.AdminKey]; !slices.Equal(k.Perms, AdminKeyPermissions) {
		t.Fatalf("admin key permissions %v", k.Perms)
	}
	if k := e.f.Keys[acct.FamilyKey]; k.User != acct.FamilyUserID || !slices.Equal(k.Perms, FamilyKeyPermissions) {
		t.Fatalf("family key %+v (family %s)", k, acct.FamilyUserID)
	}
	if len(e.f.Sessions) != 0 {
		t.Fatalf("password sessions left open: %v", e.f.Sessions)
	}

	// Immich's configuration: sign-in with HardyOS, passwords off (they
	// were on for the family key and are off again), templates, ML.
	c := e.f.Config
	for path, want := range map[string]any{
		"oauth.enabled": true, "oauth.issuerUrl": "https://sso.home.example.net", "oauth.clientId": "hos-abc",
		"oauth.clientSecret": "s3cret", "oauth.scope": "openid email profile hardyos_photos", "oauth.autoRegister": true,
		"oauth.mobileOverrideEnabled": true, "oauth.mobileRedirectUri": "https://immich.home.example.net/api/oauth/mobile-redirect",
		"oauth.roleClaim": "hardyos_photos_role", "oauth.storageLabelClaim": "hardyos_storage_label",
		"oauth.allowInsecureRequests": false, "passwordLogin.enabled": false, "storageTemplate.enabled": true,
		"storageTemplate.template": "{{y}}/{{filename}}", "library.scan.cronExpression": "0 */6 * * *",
		"backup.database.enabled": true, "trash.days": float64(30),
	} {
		if got := cfgAt(c, path); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s = %v, want %v", path, got, want)
		}
	}
	if !st.SSO.Active {
		t.Fatalf("OAuth check: %+v", st.SSO)
	}

	// Bob's library: owned by a pre-made account with his placeholder
	// address and storage label, scanned.
	var bob *immichfake.User
	for i := range e.f.Users {
		if e.f.Users[i].Email == "bob@hardyos.invalid" {
			bob = &e.f.Users[i]
		}
	}
	if bob == nil || bob.StorageLabel != "bob" || bob.IsAdmin {
		t.Fatalf("bob's account %+v", e.f.Users)
	}
	var bobLib, famLib *immichfake.Library
	for i := range e.f.Libs {
		switch e.f.Libs[i].OwnerID {
		case bob.ID:
			bobLib = &e.f.Libs[i]
		case acct.FamilyUserID:
			famLib = &e.f.Libs[i]
		}
	}
	if bobLib == nil || !slices.Equal(bobLib.ImportPaths, []string{"/mnt/existing/Bob/Pictures"}) || bobLib.Name != "Bob's old photos" {
		t.Fatalf("bob's library %+v", e.f.Libs)
	}
	if famLib == nil || !slices.Equal(famLib.ImportPaths, []string{FamilyMount}) || famLib.Name != "Family Photos" {
		t.Fatalf("family library %+v", e.f.Libs)
	}
	if !slices.Contains(e.f.Scans, bobLib.ID) || !slices.Contains(e.f.Scans, famLib.ID) {
		t.Fatalf("scans %v", e.f.Scans)
	}

	bobLibID, famLibID := bobLib.ID, famLib.ID
	// Nobody has signed in with HardyOS yet: no partners.
	if len(e.f.Partners[acct.FamilyUserID]) != 0 {
		t.Fatalf("partners before anyone signed in: %v", e.f.Partners)
	}
	// Alice and Carol sign in; Bob's first sign-in links his account.
	alice := e.f.SignInWithOAuth("sub-1", "alice@home.example.net", "Alice")
	carol := e.f.SignInWithOAuth("sub-3", "carol@home.example.net", "Carol")
	if id := e.f.SignInWithOAuth("sub-2", "bob@hardyos.invalid", "Bob"); id != bob.ID {
		t.Fatal("bob's first sign-in didn't link the account HardyOS made")
	}
	st = e.run(t, p)
	got := e.f.Partners[acct.FamilyUserID]
	slices.Sort(got)
	want := []string{alice, bob.ID}
	slices.Sort(want)
	if !slices.Equal(got, want) || slices.Contains(got, carol) {
		t.Fatalf("family partners %v, want alice and bob (not carol %s)", got, carol)
	}
	if st.Family.Members != 2 || !st.Family.Active {
		t.Fatalf("family status %+v", st.Family)
	}

	// Idempotent: nothing more changes.
	before := len(e.f.Libs)
	st = e.run(t, p)
	if len(st.Notes) != 0 || len(e.f.Libs) != before {
		t.Fatalf("second sync changed things: %v", st.Notes)
	}

	// Bob leaves the family list: HardyOS stops the sharing it added, and
	// leaves a partner someone added by hand.
	e.f.Partners[acct.FamilyUserID] = append(e.f.Partners[acct.FamilyUserID], carol)
	set.Family.Members = []appstore.Principal{{Kind: "group", Name: `HOME\Family`}}
	p = e.plan(t, set)
	e.run(t, p)
	got = e.f.Partners[acct.FamilyUserID]
	if slices.Contains(got, bob.ID) || !slices.Contains(got, alice) || !slices.Contains(got, carol) {
		t.Fatalf("partners after bob left %v", got)
	}

	// The library leaves the settings: HardyOS removes it.
	set.Libraries = nil
	p = e.plan(t, set)
	st = e.run(t, p)
	if slices.ContainsFunc(e.f.Libs, func(l immichfake.Library) bool { return l.ID == bobLibID }) {
		t.Fatalf("removed library still there: %v (%v)", e.f.Libs, st.Notes)
	}

	// The family library off: its library and HardyOS's partners go.
	set.Family.Enabled = false
	p = e.plan(t, set)
	e.run(t, p)
	if slices.ContainsFunc(e.f.Libs, func(l immichfake.Library) bool { return l.ID == famLibID }) || slices.Contains(e.f.Partners[acct.FamilyUserID], alice) {
		t.Fatalf("family off: libs %v partners %v", e.f.Libs, e.f.Partners)
	}
}

func TestReconcileSSOOffKeepsPasswords(t *testing.T) {
	e := newTestEnv(t)
	p := e.plan(t, Defaults())
	e.run(t, p)
	p.Wanted.OAuth = nil
	p.Wanted.PasswordLogin = false // asked off, but without OAuth no one could sign in
	e.run(t, p)
	if cfgAt(e.f.Config, "oauth.enabled") != false || cfgAt(e.f.Config, "passwordLogin.enabled") != true || cfgAt(e.f.Config, "oauth.clientSecret") != "" {
		t.Fatalf("config %v", e.f.Config["oauth"])
	}
}

func TestReconcileImmichSetUpBeforePhotos(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	// Someone made an administrator before HardyOS looked.
	e.f.Users = append(e.f.Users, immichfake.User{ID: "admin-1", Email: "dad@example.com", IsAdmin: true}, immichfake.User{ID: "kid-1", Email: "kid@example.com"})
	e.f.Keys["key-of-dad-0123456789"] = immichfake.Key{User: "admin-1", Perms: []string{"all"}}
	e.f.Keys["key-of-kid-0123456789"] = immichfake.Key{User: "kid-1", Perms: []string{"all"}}
	st := &Status{}
	if err := e.rec.Run(ctx, e.plan(t, Defaults()), st); !errors.Is(err, ErrNeedsLink) || !st.NeedsLink {
		t.Fatalf("unknown administrator: %v %+v", err, st)
	}
	if err := e.rec.Link(ctx, "key-of-kid-0123456789"); err == nil || !strings.Contains(err.Error(), "isn't an Immich administrator") {
		t.Fatalf("a non-administrator's key: %v", err)
	}
	if err := e.rec.Link(ctx, "key-of-dad-0123456789"); err != nil {
		t.Fatal(err)
	}
	e.run(t, e.plan(t, Defaults()))
	if cfgAt(e.f.Config, "oauth.enabled") != true {
		t.Fatal("linked Immich not configured")
	}
	// The key is revoked in Immich: HardyOS has no password for that
	// account, so it asks for a link again.
	delete(e.f.Keys, "key-of-dad-0123456789")
	st = &Status{}
	if err := e.rec.Run(ctx, e.plan(t, Defaults()), st); !errors.Is(err, ErrNeedsLink) {
		t.Fatalf("revoked linked key: %v", err)
	}
}

func TestReconcileNewKeyWhenRevoked(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	e.run(t, e.plan(t, Defaults()))
	acct, _ := e.store.Account(ctx)
	delete(e.f.Keys, acct.AdminKey)
	// Password sign-in is off now; HardyOS can't turn it on without a key,
	// so the sync fails clearly rather than guessing.
	st := &Status{}
	err := e.rec.Run(ctx, e.plan(t, Defaults()), st)
	if err == nil || !strings.Contains(err.Error(), "signing in to Immich as HardyOS") {
		t.Fatalf("revoked key with passwords off: %v", err)
	}
	// With passwords on (SSO off) a new key is made.
	p := e.plan(t, Defaults())
	e.f.Config["passwordLogin"] = map[string]any{"enabled": true}
	e.run(t, p)
	acct2, _ := e.store.Account(ctx)
	if acct2.AdminKey == "" || acct2.AdminKey == acct.AdminKey {
		t.Fatalf("no new key: %+v", acct2)
	}
}

func TestReconcileLibraryProblems(t *testing.T) {
	e := newTestEnv(t)
	set := Defaults()
	set.Libraries = []Library{
		{OwnerID: 2, Share: "EXISTING_2", Name: "Not given"},
		{OwnerID: 9, Share: "EXISTING", Name: "Gone owner"},
	}
	st := e.run(t, e.plan(t, set))
	if len(st.Libraries) != 2 || !strings.Contains(st.Libraries[0].Problem, "wasn't given a shared folder") || !strings.Contains(st.Libraries[1].Problem, "gone") {
		t.Fatalf("library problems %+v", st.Libraries)
	}
	if len(e.f.Libs) != 0 {
		t.Fatalf("libraries made anyway: %v", e.f.Libs)
	}
}
