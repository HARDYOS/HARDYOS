package photos

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/oidc"
	"github.com/hardyos/hardyos/daemon/internal/photos/immichfake"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// fakeDir stands in for HardyOS's accounts: alice (admin, domain, in
// HOME\Family), bob (local, no e-mail) and carol (domain, not family).
// Subjects are sub-<id> unless subs says otherwise.
type fakeDir struct {
	mu    sync.Mutex
	users map[int64]*auth.User
	subOf map[int64]string
}

func newFakeDir() *fakeDir {
	d := &fakeDir{users: map[int64]*auth.User{}, subOf: map[int64]string{}}
	d.users[1] = &auth.User{ID: 1, Username: `HOME\alice`, Principal: `HOME\alice`, Source: auth.SourceDomain, Role: auth.RoleAdmin,
		DisplayName: "Alice", Email: "alice@home.example.net", Groups: []string{`HOME\Family`, `HOME\Domain Users`}}
	d.users[2] = &auth.User{ID: 2, Username: "bob", Role: auth.RoleUser, DisplayName: "Bob"}
	d.users[3] = &auth.User{ID: 3, Username: `HOME\carol`, Principal: `HOME\carol`, Source: auth.SourceDomain, Role: auth.RoleUser,
		DisplayName: "Carol", Email: "carol@home.example.net", Groups: []string{`HOME\Domain Users`}}
	return d
}

func (d *fakeDir) sub(id int64) string {
	if s := d.subOf[id]; s != "" {
		return s
	}
	return fmt.Sprintf("sub-%d", id)
}

func (d *fakeDir) UserByID(_ context.Context, id int64) (*auth.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.users[id], nil
}

func (d *fakeDir) People(context.Context) ([]*auth.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []*auth.User
	for _, u := range d.users {
		out = append(out, u)
	}
	return out, nil
}

func (d *fakeDir) Profile(_ context.Context, u *auth.User) (*oidc.AppProfile, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	short := u.Username
	if _, n, ok := strings.Cut(short, `\`); ok {
		short = n
	}
	email := u.Email
	if email == "" {
		if u.Source == auth.SourceDomain {
			return nil, oidc.ErrNoEmail
		}
		email = oidc.PlaceholderEmail(oidc.StorageLabel(short))
	}
	return &oidc.AppProfile{Subject: d.sub(u.ID), Email: strings.ToLower(email), Name: u.DisplayName, StorageLabel: oidc.StorageLabel(short), Admin: u.IsAdmin()}, nil
}

func (d *fakeDir) UserForSubject(_ context.Context, sub string) (*auth.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, u := range d.users {
		if d.sub(id) == sub && !u.Disabled {
			return u, nil
		}
	}
	return nil, errors.New("unknown subject")
}

type testEnv struct {
	f      *immichfake.Fake
	dir    *fakeDir
	store  *Store
	rec    *Reconciler
	audits []string
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
	e.rec = &Reconciler{Immich: &Immich{Base: e.f.URL}, Store: e.store, Dir: e.dir, Ready: 5 * time.Second,
		Audit: func(_ context.Context, action, target, detail string) {
			e.audits = append(e.audits, action+" "+target+" "+detail)
		}}
	return e
}

func (e *testEnv) sawAudit(prefix string) bool {
	return slices.ContainsFunc(e.audits, func(a string) bool { return strings.HasPrefix(a, prefix) })
}

func noLinks() map[string]*shares.LinkScan {
	return map[string]*shares.LinkScan{"EXISTING": {Escaping: []string{}}, "EXISTING_2": {Escaping: []string{}},
		"EXISTING_3": {Escaping: []string{}}, "FAMILY": {Escaping: []string{}}}
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
		Links:          noLinks(),
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

// byEmail finds an account in the fake (live or not).
func (e *testEnv) byEmail(email string) *immichfake.User {
	e.f.Mu.Lock()
	defer e.f.Mu.Unlock()
	for i := range e.f.Users {
		if strings.EqualFold(e.f.Users[i].Email, email) {
			u := e.f.Users[i]
			return &u
		}
	}
	return nil
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
	if acct.AdminEmail != AdminEmail || acct.AdminPassword == "" || acct.AdminKey == "" || acct.Linked || acct.AdminUserID == "" {
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
	if !e.sawAudit("photos.account.create "+AdminEmail) || !e.sawAudit("photos.account.create "+FamilyEmail) {
		t.Fatalf("service accounts not audited: %v", e.audits)
	}

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

	// Everyone who may use Immich has an account holding their address,
	// made by HardyOS ahead of their first sign-in.
	alice, bob, carol := e.byEmail("alice@home.example.net"), e.byEmail("bob@local.hardyos.invalid"), e.byEmail("carol@home.example.net")
	if alice == nil || bob == nil || carol == nil || !alice.IsAdmin || bob.IsAdmin || bob.StorageLabel != "bob" {
		t.Fatalf("accounts %+v", e.f.Users)
	}
	if !e.sawAudit("photos.account.create bob@local.hardyos.invalid") {
		t.Fatalf("pre-made account not audited: %v", e.audits)
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
	// The family library goes to the family members' accounts.
	got := slices.Clone(e.f.Partners[acct.FamilyUserID])
	slices.Sort(got)
	want := []string{alice.ID, bob.ID}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("family partners %v, want alice and bob (not carol %s)", got, carol.ID)
	}
	if !e.sawAudit("photos.family.share") {
		t.Fatalf("partner change not audited: %v", e.audits)
	}

	// First sign-ins link the accounts HardyOS made, by address.
	if id := e.f.SignInWithOAuth("sub-1", "alice@home.example.net", "Alice"); id != alice.ID {
		t.Fatal("alice's first sign-in didn't link her account")
	}
	if id := e.f.SignInWithOAuth("sub-2", "bob@local.hardyos.invalid", "Bob"); id != bob.ID {
		t.Fatal("bob's first sign-in didn't link his account")
	}
	before := len(e.f.Libs)
	st = e.run(t, p)
	if len(e.f.Libs) != before || st.Family.Members != 2 || !st.Family.Active {
		t.Fatalf("second sync: %v %+v", st.Notes, st.Family)
	}

	// Bob leaves the family list: HardyOS stops the sharing it added, and
	// leaves a partner someone added by hand.
	e.f.Partners[acct.FamilyUserID] = append(e.f.Partners[acct.FamilyUserID], carol.ID)
	set.Family.Members = []appstore.Principal{{Kind: "group", Name: `HOME\Family`}}
	e.run(t, e.plan(t, set))
	got = e.f.Partners[acct.FamilyUserID]
	if slices.Contains(got, bob.ID) || !slices.Contains(got, alice.ID) || !slices.Contains(got, carol.ID) {
		t.Fatalf("partners after bob left %v", got)
	}

	// The library leaves the settings: HardyOS removes it.
	set.Libraries = nil
	st = e.run(t, e.plan(t, set))
	if slices.ContainsFunc(e.f.Libs, func(l immichfake.Library) bool { return l.ID == bobLibID }) {
		t.Fatalf("removed library still there: %v (%v)", e.f.Libs, st.Notes)
	}

	// The family library off: its library and HardyOS's partners go.
	set.Family.Enabled = false
	e.run(t, e.plan(t, set))
	if slices.ContainsFunc(e.f.Libs, func(l immichfake.Library) bool { return l.ID == famLibID }) || slices.Contains(e.f.Partners[acct.FamilyUserID], alice.ID) {
		t.Fatalf("family off: libs %v partners %v", e.f.Libs, e.f.Partners)
	}
}

// H1: an address can't lead a first sign-in to someone else's account.
func TestReconcileAddressTakeover(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	p := e.plan(t, Defaults())
	e.run(t, p)
	// Mallory signed up with Immich on her own (not a HardyOS account), and
	// gives herself the address of Dave, who isn't on HardyOS yet.
	mallory := e.f.AddUser(immichfake.User{Email: "mallory@example.com", Name: "Mallory"}, "pw")
	e.f.SetOwnEmail(mallory, "dave@home.example.net")
	// Carol signs in (linked), then takes Dave's address too and unlinks
	// her account.
	carol := e.f.SignInWithOAuth("sub-3", "carol@home.example.net", "Carol")
	// An account holding a HardyOS service-like address.
	sneaky := e.f.AddUser(immichfake.User{Email: "admin2@service.hardyos.invalid"}, "pw")

	// Dave joins HardyOS; the next sync runs before his first sign-in.
	e.dir.users[4] = &auth.User{ID: 4, Username: `HOME\dave`, Principal: `HOME\dave`, Source: auth.SourceDomain, Role: auth.RoleUser,
		DisplayName: "Dave", Email: "dave@home.example.net"}
	st := e.run(t, p)
	if got := e.f.Get(mallory).Email; got != unlinkedEmail(mallory) {
		t.Fatalf("mallory's account still has %q", got)
	}
	if got := e.f.Get(sneaky).Email; got != unlinkedEmail(sneaky) {
		t.Fatalf("sneaky account kept %q", got)
	}
	if !e.sawAudit("photos.account.unlink mallory") && !e.sawAudit("photos.account.unlink dave@home.example.net") {
		t.Fatalf("rename not audited: %v", e.audits)
	}
	flagged := slices.ContainsFunc(st.People, func(ps PersonState) bool { return ps.ImmichID == mallory && strings.Contains(ps.Flag, "renamed") })
	if !flagged {
		t.Fatalf("mallory's account not flagged: %+v", st.People)
	}
	dave := e.byEmail("dave@home.example.net")
	if dave == nil || dave.ID == mallory {
		t.Fatalf("dave has no account of his own: %+v", dave)
	}
	if id := e.f.SignInWithOAuth("sub-4", "dave@home.example.net", "Dave"); id != dave.ID {
		t.Fatal("dave's sign-in went to another account")
	}

	// Carol, signed in, changes her own address to Dave's? Immich refuses
	// (it's taken). To another one: HardyOS puts hers back.
	e.f.SetOwnEmail(carol, "carol2@example.com")
	e.run(t, p)
	if got := e.f.Get(carol).Email; got != "carol@home.example.net" {
		t.Fatalf("carol's address %q", got)
	}
	// Carol unlinks OAuth: her account is HardyOS-made, so it keeps her
	// address and stays hers.
	e.f.Unlink(carol)
	e.run(t, p)
	if id := e.f.SignInWithOAuth("sub-3", "carol@home.example.net", "Carol"); id != carol {
		t.Fatal("carol's account changed hands")
	}
	_ = ctx
}

// H3: losing Photos loses Immich; getting it back restores the account.
func TestReconcileAccessFollowsHardyOS(t *testing.T) {
	e := newTestEnv(t)
	p := e.plan(t, Defaults())
	e.run(t, p)
	alice := e.f.SignInWithOAuth("sub-1", "alice@home.example.net", "Alice")
	carol := e.f.SignInWithOAuth("sub-3", "carol@home.example.net", "Carol")
	bob := e.byEmail("bob@local.hardyos.invalid").ID
	e.f.Mu.Lock()
	carolPW := e.f.Password[carol]
	e.f.Mu.Unlock()

	// Passwords are rotated while Immich's own sign-in is off.
	e.run(t, p)
	e.f.Mu.Lock()
	rotated := e.f.Password[carol] != carolPW
	e.f.Mu.Unlock()
	if !rotated {
		t.Fatal("carol's password wasn't rotated")
	}

	// Carol is off the access list, Bob's account is turned off, Alice
	// stops being an administrator.
	p.Access = []appstore.Principal{{Kind: "user", Name: `HOME\alice`}, {Kind: "user", Name: "bob"}}
	e.dir.users[2].Disabled = true
	e.dir.users[1].Role = auth.RoleUser
	st := e.run(t, p)
	if e.f.Get(carol).DeletedAt == "" || e.f.Get(bob).DeletedAt == "" {
		t.Fatalf("carol %+v bob %+v not suspended (%v)", e.f.Get(carol), e.f.Get(bob), st.Notes)
	}
	if e.f.Get(alice).IsAdmin || e.f.Get(alice).DeletedAt != "" {
		t.Fatalf("alice %+v", e.f.Get(alice))
	}
	if !e.sawAudit("photos.account.suspend carol@home.example.net") || !e.sawAudit("photos.account.role alice@home.example.net") {
		t.Fatalf("audits %v", e.audits)
	}
	// A soft-deleted account's keys stop working.
	e.f.Mu.Lock()
	e.f.Keys["carols-key"] = immichfake.Key{User: carol, Perms: []string{"all"}}
	e.f.Mu.Unlock()
	if _, err := e.rec.Immich.WithAPIKey("carols-key").Me(context.Background()); !IsStatus(err, 401) {
		t.Fatalf("suspended account's key: %v", err)
	}

	// A HardyOS account removed altogether (its subject is gone).
	delete(e.dir.users, 1)
	e.run(t, p)
	if e.f.Get(alice).DeletedAt == "" {
		t.Fatal("alice's account wasn't suspended when her HardyOS account went")
	}

	// Carol may use Photos again: her account comes back with everything.
	p.Access = []appstore.Principal{}
	e.dir.users[2].Disabled = false
	st = e.run(t, p)
	if e.f.Get(carol).DeletedAt != "" || e.f.Get(bob).DeletedAt != "" {
		t.Fatalf("not restored: carol %+v bob %+v (%v)", e.f.Get(carol), e.f.Get(bob), st.Notes)
	}
	if !e.sawAudit("photos.account.restore carol@home.example.net") {
		t.Fatalf("restore not audited: %v", e.audits)
	}
}

// M5: a library follows the person, not the account row.
func TestReconcileLibraryFollowsSubject(t *testing.T) {
	e := newTestEnv(t)
	set := Defaults()
	set.Libraries = []Library{{OwnerID: 3, Share: "EXISTING", Path: "Carol", Name: "Carol's"}}
	p := e.plan(t, set)
	e.run(t, p)
	first := e.f.Libs[0]
	// HOME\carol is now another directory object: a new subject.
	e.dir.subOf[3] = "sub-3-new"
	e.run(t, p)
	if len(e.f.Libs) != 1 || e.f.Libs[0].ID == first.ID || e.f.Libs[0].OwnerID == first.OwnerID {
		t.Fatalf("library not rehomed: before %+v after %+v", first, e.f.Libs)
	}
}

// H2: links leading out of a share are excluded, or the library refused.
func TestReconcileLibraryLinks(t *testing.T) {
	e := newTestEnv(t)
	set := Defaults()
	set.Libraries = []Library{{OwnerID: 2, Share: "EXISTING", Path: "Bob", Name: "Bob's"}}
	p := e.plan(t, set)
	p.Links["EXISTING"] = &shares.LinkScan{Escaping: []string{"Bob/evil[1].jpg", "Other/x"}, Count: 2}
	e.run(t, p)
	ex := e.f.Libs[0].ExclusionPatterns
	if !slices.Contains(ex, `/mnt/existing/Bob/evil\[1\].jpg`) || !slices.Contains(ex, `/mnt/existing/Bob/evil\[1\].jpg/**`) ||
		slices.ContainsFunc(ex, func(s string) bool { return strings.Contains(s, "Other") }) || !slices.Contains(ex, "**/.zfs/**") {
		t.Fatalf("exclusions %v", ex)
	}
	// The scan couldn't finish: the library goes until it can.
	p.Links["EXISTING"] = &shares.LinkScan{Escaping: []string{}, Truncated: true}
	st := e.run(t, p)
	if len(e.f.Libs) != 0 || !strings.Contains(st.Libraries[0].Problem, "too big") {
		t.Fatalf("truncated scan: libs %v status %+v", e.f.Libs, st.Libraries)
	}
	delete(p.Links, "EXISTING")
	p.LinkErrors = map[string]string{"EXISTING": "the pool is locked"}
	if st := e.run(t, p); !strings.Contains(st.Libraries[0].Problem, "the pool is locked") {
		t.Fatalf("unchecked share: %+v", st.Libraries)
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
	// On an Immich HardyOS installed fresh, it's an incident instead.
	fresh := e.plan(t, Defaults())
	fresh.FreshInstall = true
	st = &Status{}
	if err := e.rec.Run(ctx, fresh, st); !errors.Is(err, ErrUnexpectedAdmin) || st.Incident == "" || st.NeedsLink {
		t.Fatalf("unexpected administrator on a fresh install: %v %+v", err, st)
	}
	if err := e.rec.Link(ctx, "key-of-kid-0123456789"); err == nil || !strings.Contains(err.Error(), "isn't an Immich administrator") {
		t.Fatalf("a non-administrator's key: %v", err)
	}
	if err := e.rec.Link(ctx, "key-of-dad-0123456789"); err != nil {
		t.Fatal(err)
	}
	e.run(t, e.plan(t, Defaults()))
	if cfgAt(e.f.Config, "oauth.enabled") != true || e.f.Get("admin-1").DeletedAt != "" {
		t.Fatal("linked Immich not configured, or its administrator touched")
	}
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
	p := e.plan(t, Defaults())
	e.f.Config["passwordLogin"] = map[string]any{"enabled": true}
	e.run(t, p)
	acct2, _ := e.store.Account(ctx)
	if acct2.AdminKey == "" || acct2.AdminKey == acct.AdminKey {
		t.Fatalf("no new key: %+v", acct2)
	}
}

// The family account is the one HardyOS recorded, never one found by its
// address; making its key leaves Immich's passwords as they were.
func TestReconcileFamilyAccountByID(t *testing.T) {
	e := newTestEnv(t)
	set := Defaults()
	set.Family = Family{Enabled: true, Name: "Family Photos"}
	p := e.plan(t, set)
	e.run(t, p)
	acct, _ := e.store.Account(context.Background())
	if cfgAt(e.f.Config, "passwordLogin.enabled") != false {
		t.Fatal("passwords left on after making the family key")
	}
	// The family account's key is lost, and an impostor appears.
	delete(e.f.Keys, acct.FamilyKey)
	e.f.Mu.Lock()
	e.f.User(acct.FamilyUserID).Email = "old-family@service.hardyos.invalid"
	e.f.Mu.Unlock()
	imp := e.f.AddUser(immichfake.User{Email: FamilyEmail, Name: "Family Photos"}, "known")
	if st := e.run(t, p); st.Family.Problem != "" {
		t.Fatalf("family: %s", st.Family.Problem)
	}
	acct2, _ := e.store.Account(context.Background())
	if acct2.FamilyUserID != acct.FamilyUserID || e.f.Keys[acct2.FamilyKey].User != acct.FamilyUserID {
		t.Fatalf("family account %s (impostor %s), key for %s", acct2.FamilyUserID, imp, e.f.Keys[acct2.FamilyKey].User)
	}
	if cfgAt(e.f.Config, "passwordLogin.enabled") != false {
		t.Fatal("passwords left on")
	}
}

func TestReconcileLibraryProblems(t *testing.T) {
	e := newTestEnv(t)
	set := Defaults()
	set.Libraries = []Library{
		{OwnerID: 2, Share: "EXISTING_2", Name: "Not given"},
		{OwnerID: 9, Share: "EXISTING", Name: "Gone owner"},
	}
	p := e.plan(t, set)
	st := e.run(t, p)
	if len(st.Libraries) != 2 || !strings.Contains(st.Libraries[0].Problem, "wasn't given a shared folder") || !strings.Contains(st.Libraries[1].Problem, "gone") {
		t.Fatalf("library problems %+v", st.Libraries)
	}
	// An owner who may not use Photos gets no library (or account).
	set.Libraries = []Library{{OwnerID: 3, Share: "EXISTING", Name: "Carol's"}}
	p = e.plan(t, set)
	p.Access = []appstore.Principal{{Kind: "user", Name: "bob"}}
	st = e.run(t, p)
	if !strings.Contains(st.Libraries[0].Problem, "may not use Photos") || len(e.f.Libs) != 0 {
		t.Fatalf("owner without access: %+v %v", st.Libraries, e.f.Libs)
	}
}
