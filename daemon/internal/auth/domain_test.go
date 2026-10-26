package auth

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// fakeDomain is a domain controller in memory: the directory and the KDC.
type fakeDomain struct {
	mu       sync.Mutex
	info     *DomainInfo
	infoErr  error
	accounts map[string]*DomainAccount // lower-case name
	pw       map[string]string
	revoked  map[string]bool
	down     bool
	acctErr  error
	checks   []string
}

// The fake domain's SIDs.
const (
	testDomainSID = "S-1-5-21-1111-2222-3333"
	testAdminsSID = testDomainSID + "-1105" // the recorded HardyOS Admins
)

// testGroupSIDs are the fake domain's groups by name.
var testGroupSIDs = map[string]string{
	"domain users":   testDomainSID + "-513",
	"domain admins":  testDomainSID + "-512",
	"hardyos admins": testAdminsSID,
	"family":         testDomainSID + "-1104",
}

func newFakeDomain() *fakeDomain {
	return &fakeDomain{
		info: &DomainInfo{Realm: "HOME.EXAMPLE.NET", NetBIOS: "HOME", DNS: "home.example.net", LocalKDC: "192.0.2.20",
			AdminsGroupSID: testAdminsSID},
		accounts: map[string]*DomainAccount{},
		pw:       map[string]string{},
		revoked:  map[string]bool{},
	}
}

// add creates an account in the named groups (SIDs from testGroupSIDs).
func (f *fakeDomain) add(name, pw string, groups ...string) *DomainAccount {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := &DomainAccount{Exists: true, Username: name, DisplayName: strings.ToUpper(name[:1]) + name[1:], Enabled: true,
		DomainSID: testDomainSID}
	for _, g := range append([]string{"Domain Users"}, groups...) {
		sid, ok := testGroupSIDs[strings.ToLower(g)]
		if !ok {
			sid = fmt.Sprintf("%s-%d", testDomainSID, 2000+len(testGroupSIDs)+len(a.Groups))
		}
		a.Groups = append(a.Groups, g)
		a.GroupSIDs = append(a.GroupSIDs, sid)
	}
	f.accounts[strings.ToLower(name)] = a
	f.pw[strings.ToLower(name)] = pw
	return a
}

// join puts an account in a group with the given SID.
func (f *fakeDomain) join(a *DomainAccount, group, sid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a.Groups = append(a.Groups, group)
	a.GroupSIDs = append(a.GroupSIDs, sid)
}

func (f *fakeDomain) Info(context.Context) (*DomainInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.info, f.infoErr
}

func (f *fakeDomain) Account(_ context.Context, name string) (*DomainAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.acctErr != nil {
		return nil, f.acctErr
	}
	a, ok := f.accounts[strings.ToLower(name)]
	if !ok {
		return &DomainAccount{}, nil
	}
	c := *a
	c.Groups = append([]string(nil), a.Groups...)
	c.GroupSIDs = append([]string(nil), a.GroupSIDs...)
	return &c, nil
}

func (f *fakeDomain) CheckPassword(_ context.Context, d DomainInfo, name, pw string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checks = append(f.checks, d.Realm+"/"+name)
	if f.down {
		return ErrDomainUnavailable
	}
	key := strings.ToLower(name)
	a, ok := f.accounts[key]
	if !ok {
		return ErrBadCredentials // KDC_ERR_C_PRINCIPAL_UNKNOWN
	}
	if f.revoked[key] || !a.Enabled {
		return ErrAccountRevoked
	}
	if f.pw[key] != pw {
		return ErrBadCredentials
	}
	return nil
}

func newSignIn(t *testing.T) (*SignIn, *fakeDomain) {
	t.Helper()
	f := newFakeDomain()
	return &SignIn{Users: &Users{DB: newDB(t)}, Domain: f, Kerberos: f}, f
}

func TestDomainSignInForms(t *testing.T) {
	ctx := context.Background()
	s, f := newSignIn(t)
	f.add("alice", "Al1ce-Passw0rd!", "Family")

	for _, typed := range []string{`HOME\alice`, `home\Alice`, "alice@home.example.net", "alice@HOME.EXAMPLE.NET", "alice", `home.example.net\alice`} {
		u, err := s.Authenticate(ctx, typed, "Al1ce-Passw0rd!")
		if err != nil {
			t.Fatalf("%s: %v", typed, err)
		}
		if u.Source != SourceDomain || u.Principal != `HOME\alice` || u.Username != `HOME\alice` || u.Role != RoleUser {
			t.Errorf("%s signed in as %+v", typed, u)
		}
		if strings.Join(u.Groups, ",") != `HOME\Domain Users,HOME\Family` {
			t.Errorf("groups = %v", u.Groups)
		}
		if u.DisplayName != "Alice" || u.LastLoginAt != nil && u.LastLoginAt.IsZero() {
			t.Errorf("user = %+v", u)
		}
	}
	// One row however it was spelled.
	list, _ := s.Users.List(ctx)
	if len(list) != 1 {
		t.Fatalf("users = %+v", list)
	}

	keys := map[string]bool{}
	for _, typed := range []string{"alice", `HOME\alice`, "Alice@home.example.net"} {
		keys[s.LimitKey(ctx, typed)] = true
	}
	if len(keys) != 1 || !keys[`user:home\alice`] {
		t.Errorf("rate-limit keys differ: %v", keys)
	}

	for typed, want := range map[string]error{
		`OTHER\alice`:            ErrUnknownDomain,
		"alice@other.example":    ErrUnknownDomain,
		`HOME\nobody`:            ErrBadCredentials,
		"nobody":                 ErrBadCredentials,
		`HOME\bad;name`:          ErrBadCredentials,
		`HOME\`:                  ErrBadCredentials,
		"alice@home.example.net": ErrBadCredentials, // wrong password below
	} {
		if _, err := s.Authenticate(ctx, typed, "wrong-password"); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", typed, err, want)
		}
	}
}

func TestLocalAccountWinsForBareNames(t *testing.T) {
	ctx := context.Background()
	s, f := newSignIn(t)
	if _, err := s.Users.Create(ctx, NewUser{Username: "alice", Role: RoleUser, Password: "local-password1"}); err != nil {
		t.Fatal(err)
	}
	f.add("alice", "Al1ce-Passw0rd!")
	u, err := s.Authenticate(ctx, "alice", "local-password1")
	if err != nil || u.Source != SourceLocal {
		t.Fatalf("bare name: %+v, %v", u, err)
	}
	if _, err := s.Authenticate(ctx, "alice", "Al1ce-Passw0rd!"); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("the domain password worked for the local account: %v", err)
	}
	if len(f.checks) != 0 {
		t.Errorf("asked the domain about a local name: %v", f.checks)
	}
	u, err = s.Authenticate(ctx, `HOME\alice`, "Al1ce-Passw0rd!")
	if err != nil || u.Source != SourceDomain {
		t.Fatalf("qualified name: %+v, %v", u, err)
	}
	// The local password check never matches the domain row.
	if _, err := s.Users.Authenticate(ctx, `HOME\alice`, ""); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("local check on a domain row: %v", err)
	}
}

func TestDomainRolesAndStates(t *testing.T) {
	ctx := context.Background()
	s, f := newSignIn(t)
	f.add("admin1", "Adm1n-Passw0rd!", "Domain Admins")
	f.add("admin2", "Adm2n-Passw0rd!", "hardyos admins")
	off := f.add("off", "0ff-Passw0rd!")
	locked := f.add("locked", "L0cked-Passw0rd!")
	f.add("gone", "G0ne-Passw0rd!")

	for _, n := range []string{"admin1", "admin2"} {
		pw := map[string]string{"admin1": "Adm1n-Passw0rd!", "admin2": "Adm2n-Passw0rd!"}[n]
		u, err := s.Authenticate(ctx, `HOME\`+n, pw)
		if err != nil || !u.IsAdmin() || u.BreakGlass {
			t.Errorf("%s: %+v, %v", n, u, err)
		}
	}

	off.Enabled = false
	if _, err := s.Authenticate(ctx, `HOME\off`, "0ff-Passw0rd!"); !errors.Is(err, ErrAccountDisabled) {
		t.Errorf("disabled: %v", err)
	}
	locked.LockedOut = true
	f.revoked["locked"] = true
	if _, err := s.Authenticate(ctx, `HOME\locked`, "L0cked-Passw0rd!"); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("locked: %v", err)
	}

	// Kerberos lets it in, but the directory says it's expired.
	f.accounts["gone"].Expired = true
	if _, err := s.Authenticate(ctx, `HOME\gone`, "G0ne-Passw0rd!"); !errors.Is(err, ErrAccountExpired) {
		t.Errorf("expired: %v", err)
	}

	f.down = true
	if _, err := s.Authenticate(ctx, `HOME\admin1`, "Adm1n-Passw0rd!"); !errors.Is(err, ErrDomainUnavailable) {
		t.Errorf("unreachable: %v", err)
	}
	f.down = false

	f.acctErr = errors.New("helper broke")
	if _, err := s.Authenticate(ctx, `HOME\admin1`, "Adm1n-Passw0rd!"); !errors.Is(err, ErrDomainUnavailable) {
		t.Errorf("lookup failure: %v", err)
	}
	f.acctErr = nil

	// Turned off in HardyOS: the domain's yes isn't enough.
	u, _ := s.Users.GetByName(ctx, `HOME\admin1`)
	tr := true
	if _, err := s.Users.Update(ctx, u.ID, UserUpdate{Disabled: &tr}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, `HOME\admin1`, "Adm1n-Passw0rd!"); !errors.Is(err, ErrDisabledHere) {
		t.Errorf("disabled here: %v", err)
	}
}

// The role comes from SIDs: a group anyone could name "HardyOS Admins" or
// "Domain Admins" grants nothing, the recorded group keeps working when
// it's renamed, and Domain Admins counts only as this domain's -512.
func TestDomainAdminRoleBySID(t *testing.T) {
	ctx := context.Background()
	s, f := newSignIn(t)
	cases := []struct {
		name, group, sid string
		admin            bool
	}{
		{"fake1", "HardyOS Admins", testDomainSID + "-1200", false}, // made by an Account Operator
		{"fake2", "Domain Admins", testDomainSID + "-1201", false},
		{"fake3", "Domain Admins", "S-1-5-21-9-9-9-512", false}, // another domain's
		{"fake4", "Administrators", "S-1-5-32-544", false},
		{"renamed", "Desktop Bosses", testAdminsSID, true},
		{"da", "Domain Admins", testDomainSID + "-512", true},
		{"lower", "domain admins", strings.ToLower(testDomainSID) + "-512", true},
	}
	for _, c := range cases {
		a := f.add(c.name, "Passw0rd-"+c.name)
		f.join(a, c.group, c.sid)
		u, err := s.Authenticate(ctx, `HOME\`+c.name, "Passw0rd-"+c.name)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if u.IsAdmin() != c.admin {
			t.Errorf("%s in %q (%s): admin = %v, want %v", c.name, c.group, c.sid, u.IsAdmin(), c.admin)
		}
		if !strings.Contains(strings.Join(u.Groups, ","), `HOME\`+c.group) {
			t.Errorf("%s: groups = %v", c.name, u.Groups)
		}
	}

	// No HardyOS Admins recorded: its members are users.
	f.info.AdminsGroupSID = ""
	if u, err := s.Authenticate(ctx, `HOME\renamed`, "Passw0rd-renamed"); err != nil || u.IsAdmin() {
		t.Errorf("unrecorded HardyOS Admins: %+v %v", u, err)
	}
	// A helper that doesn't say SIDs (an old one) gives no administrators.
	a := f.add("old", "Passw0rd-old", "Domain Admins")
	a.DomainSID, a.GroupSIDs = "", nil
	if u, err := s.Authenticate(ctx, `HOME\old`, "Passw0rd-old"); err != nil || u.IsAdmin() {
		t.Errorf("no SIDs: %+v %v", u, err)
	}
	if AdminBySID("", "", []string{"-512"}) || AdminBySID("S-1-5-21-1", "", nil) {
		t.Error("AdminBySID without SIDs")
	}
}

// Without a domain controller of its own, the server can't tell a real DC
// from an impostor, so domain sign-in is refused and Kerberos isn't asked.
func TestNoLocalDC(t *testing.T) {
	ctx := context.Background()
	s, f := newSignIn(t)
	f.add("alice", "Al1ce-Passw0rd!", "Domain Admins")
	u, err := s.Authenticate(ctx, `HOME\alice`, "Al1ce-Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	f.checks = nil
	f.info.LocalKDC = ""
	for _, typed := range []string{"alice", `HOME\alice`, "alice@home.example.net"} {
		if _, err := s.Authenticate(ctx, typed, "Al1ce-Passw0rd!"); !errors.Is(err, ErrNoLocalDC) {
			t.Errorf("%s: %v", typed, err)
		}
	}
	if err := s.Verify(ctx, u, "Al1ce-Passw0rd!"); !errors.Is(err, ErrNoLocalDC) {
		t.Errorf("terminal check: %v", err)
	}
	if len(f.checks) != 0 {
		t.Errorf("Kerberos was asked: %v", f.checks)
	}
	if err := (KerberosChecker{}).CheckPassword(ctx, *f.info, "alice", "pw"); !errors.Is(err, ErrNoLocalDC) {
		t.Errorf("KerberosChecker without a local DC: %v", err)
	}
	// Local accounts still sign in.
	if _, err := s.Users.Create(ctx, NewUser{Username: "cade", Role: RoleAdmin, Password: "supersecret1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "cade", "supersecret1"); err != nil {
		t.Errorf("local: %v", err)
	}
}

func TestNoDomain(t *testing.T) {
	ctx := context.Background()
	s, f := newSignIn(t)
	f.info = nil
	if _, err := s.Authenticate(ctx, `HOME\alice`, "x"); !errors.Is(err, ErrUnknownDomain) {
		t.Errorf("qualified without a domain: %v", err)
	}
	if _, err := s.Authenticate(ctx, "alice", "x"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("bare without a domain: %v", err)
	}
	f.info, f.infoErr = nil, errors.New("root helper down")
	if _, err := s.Authenticate(ctx, `HOME\alice`, "x"); !errors.Is(err, ErrDomainUnavailable) {
		t.Errorf("qualified, helper down: %v", err)
	}
	if _, err := s.Authenticate(ctx, "alice", "x"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("bare, helper down: %v", err)
	}
	local := &SignIn{Users: s.Users}
	if _, err := local.Authenticate(ctx, `HOME\alice`, "x"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("no directory at all: %v", err)
	}
	if len(f.checks) != 0 {
		t.Errorf("Kerberos ran: %v", f.checks)
	}
}

func agedGroups(t *testing.T, s *SignIn, id int64) {
	t.Helper()
	if _, err := s.Users.DB.Exec(`UPDATE users SET groups_checked_at = ? WHERE id = ?`, "2000-01-01T00:00:00.000Z", id); err != nil {
		t.Fatal(err)
	}
}

func TestGroupRefresh(t *testing.T) {
	ctx := context.Background()
	s, f := newSignIn(t)
	a := f.add("alice", "Al1ce-Passw0rd!")
	u, err := s.Authenticate(ctx, `HOME\alice`, "Al1ce-Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	u, _ = s.Users.Get(ctx, u.ID)
	f.join(a, "HardyOS Admins", testAdminsSID)

	// Fresh groups aren't looked up again.
	if got, err := s.Refresh(ctx, u); err != nil || got.IsAdmin() {
		t.Fatalf("fresh refresh: %+v, %v", got, err)
	}
	agedGroups(t, s, u.ID)
	u, _ = s.Users.Get(ctx, u.ID)
	got, err := s.Refresh(ctx, u)
	if err != nil || !got.IsAdmin() || len(got.Groups) != 2 {
		t.Fatalf("aged refresh: %+v, %v", got, err)
	}

	// The domain can't be asked: keep what we know (within the trust
	// window), try again later.
	setGroupsCheckedAt(t, s, u.ID, time.Now().Add(-GroupRefreshInterval-time.Minute))
	u, _ = s.Users.Get(ctx, u.ID)
	f.acctErr = errors.New("down")
	if got, err := s.Refresh(ctx, u); err != nil || got != u {
		t.Fatalf("refresh while down: %+v, %v", got, err)
	}
	f.acctErr = nil
	if got, _ := s.Refresh(ctx, u); got != u {
		t.Error("retried at once instead of a minute later")
	}

	s2 := &SignIn{Users: s.Users, Domain: f, Kerberos: f}
	a.Enabled = false
	if _, err := s2.Refresh(ctx, u); !errors.Is(err, ErrAccountGone) {
		t.Errorf("turned off in the domain: %v", err)
	}
	a.Enabled = true
	delete(f.accounts, "alice")
	if _, err := (&SignIn{Users: s.Users, Domain: f}).Refresh(ctx, u); !errors.Is(err, ErrAccountGone) {
		t.Errorf("deleted in the domain: %v", err)
	}
	f.info = &DomainInfo{Realm: "NEW.EXAMPLE.NET", NetBIOS: "NEW", DNS: "new.example.net", LocalKDC: "192.0.2.9"}
	if _, err := (&SignIn{Users: s.Users, Domain: f}).Refresh(ctx, u); !errors.Is(err, ErrAccountGone) {
		t.Errorf("another domain now: %v", err)
	}

	local, _ := s.Users.Create(ctx, NewUser{Username: "cade", Role: RoleAdmin, Password: "supersecret1"})
	if got, err := s.Refresh(ctx, local); err != nil || got != local {
		t.Errorf("local refresh: %+v %v", got, err)
	}
}

func setGroupsCheckedAt(t *testing.T, s *SignIn, id int64, at time.Time) {
	t.Helper()
	if _, err := s.Users.DB.Exec(`UPDATE users SET groups_checked_at = ? WHERE id = ?`, store.FormatTime(at), id); err != nil {
		t.Fatal(err)
	}
}

// A failing group lookup keeps the role for GroupTrustWindow, then holds
// administrator rights back until a lookup works again.
func TestGroupRefreshFailsClosed(t *testing.T) {
	ctx := context.Background()
	s, f := newSignIn(t)
	f.add("boss", "B0ss-Passw0rd!", "Domain Admins")
	f.add("kid", "K1d-Passw0rd!x", "Family")
	boss, err := s.Authenticate(ctx, `HOME\boss`, "B0ss-Passw0rd!")
	if err != nil || !boss.IsAdmin() {
		t.Fatalf("boss: %+v %v", boss, err)
	}
	kid, _ := s.Authenticate(ctx, `HOME\kid`, "K1d-Passw0rd!x")
	f.acctErr = errors.New("helper broke")
	reload := func(id int64) *User {
		u, err := s.Users.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	fresh := func() { s.refreshing = sync.Map{} } // skip the minute between retries

	// Within the window: still an administrator.
	setGroupsCheckedAt(t, s, boss.ID, time.Now().Add(-GroupTrustWindow+5*time.Minute))
	got, err := s.Refresh(ctx, reload(boss.ID))
	if err != nil || !got.IsAdmin() || got.RoleNote != "" {
		t.Fatalf("inside the window: %+v %v", got, err)
	}

	// Past it: a user, saying why, and the row says so too.
	fresh()
	setGroupsCheckedAt(t, s, boss.ID, time.Now().Add(-GroupTrustWindow-time.Minute))
	got, err = s.Refresh(ctx, reload(boss.ID))
	if err != nil || got.IsAdmin() || got.Role != RoleUser || !strings.Contains(got.RoleNote, "30 minutes") {
		t.Fatalf("past the window: %+v %v", got, err)
	}
	if reload(boss.ID).Role != RoleUser {
		t.Error("the held-back role wasn't recorded")
	}
	// Retries that are too soon (or a lookup already running) don't give it back.
	if got, _ := s.Refresh(ctx, reload(boss.ID)); got.IsAdmin() || got.RoleNote == "" {
		t.Errorf("between retries: %+v", got)
	}
	// A user just gets the note.
	fresh()
	setGroupsCheckedAt(t, s, kid.ID, time.Now().Add(-time.Hour))
	if got, _ := s.Refresh(ctx, reload(kid.ID)); got.IsAdmin() || got.RoleNote == "" {
		t.Errorf("kid: %+v", got)
	}

	// The next lookup that works restores the role.
	fresh()
	f.acctErr = nil
	got, err = s.Refresh(ctx, reload(boss.ID))
	if err != nil || !got.IsAdmin() || got.RoleNote != "" {
		t.Fatalf("after the domain answered again: %+v %v", got, err)
	}
	if !reload(boss.ID).IsAdmin() {
		t.Error("the row wasn't restored")
	}
	// A broken directory (no Info) counts the same.
	fresh()
	f.infoErr = errors.New("root helper down")
	setGroupsCheckedAt(t, s, boss.ID, time.Now().Add(-2*time.Hour))
	if got, _ := s.Refresh(ctx, reload(boss.ID)); got.IsAdmin() {
		t.Errorf("Info failing: %+v", got)
	}
}

func TestVerifyDomainPassword(t *testing.T) {
	ctx := context.Background()
	s, f := newSignIn(t)
	f.add("alice", "Al1ce-Passw0rd!", "Domain Admins")
	u, err := s.Authenticate(ctx, "alice", "Al1ce-Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(ctx, u, "Al1ce-Passw0rd!"); err != nil {
		t.Errorf("right password: %v", err)
	}
	if err := s.Verify(ctx, u, "nope"); !errors.Is(err, ErrBadCredentials) {
		t.Errorf("wrong password: %v", err)
	}
	local, _ := s.Users.Create(ctx, NewUser{Username: "cade", Role: RoleAdmin, Password: "supersecret1"})
	if err := s.Verify(ctx, local, "supersecret1"); err != nil {
		t.Errorf("local: %v", err)
	}
}

func TestDomainRowsAreManagedByTheDomain(t *testing.T) {
	ctx := context.Background()
	s, f := newSignIn(t)
	f.add("boss", "B0ss-Passw0rd!", "Domain Admins")
	cade, _ := s.Users.Create(ctx, NewUser{Username: "cade", Role: RoleAdmin, Password: "supersecret1", BreakGlass: true})
	boss, err := s.Authenticate(ctx, `HOME\boss`, "B0ss-Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Users.Count(ctx); n != 1 {
		t.Errorf("Count = %d, domain rows counted", n)
	}
	if err := s.Users.SetPassword(ctx, boss.ID, "new-password-1"); !errors.Is(err, ErrDomainManaged) {
		t.Errorf("SetPassword: %v", err)
	}
	user := RoleUser
	if _, err := s.Users.Update(ctx, boss.ID, UserUpdate{Role: &user}); !errors.Is(err, ErrDomainManaged) {
		t.Errorf("role change: %v", err)
	}
	name := "Someone Else"
	if _, err := s.Users.Update(ctx, boss.ID, UserUpdate{DisplayName: &name}); !errors.Is(err, ErrDomainManaged) {
		t.Errorf("name change: %v", err)
	}
	same, admin := boss.DisplayName, RoleAdmin
	if _, err := s.Users.Update(ctx, boss.ID, UserUpdate{DisplayName: &same, Role: &admin}); err != nil {
		t.Errorf("unchanged fields refused: %v", err)
	}
	// A domain admin doesn't stand in for the last local administrator.
	if _, err := s.Users.Update(ctx, cade.ID, UserUpdate{Role: &user}); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demoted the last local admin: %v", err)
	}
	if err := s.Users.Delete(ctx, boss.ID); err != nil {
		t.Errorf("forgetting a domain account: %v", err)
	}
}

func TestIdentityMatches(t *testing.T) {
	ctx := context.Background()
	s, f := newSignIn(t)
	f.add("alice", "Al1ce-Passw0rd!", "Family")
	d, _ := s.Authenticate(ctx, `HOME\alice`, "Al1ce-Passw0rd!")
	l, _ := s.Users.Create(ctx, NewUser{Username: "alice", Role: RoleUser, Password: "supersecret1"})
	var id Identity = d
	cases := []struct {
		who        Identity
		kind, name string
		want       bool
	}{
		{id, PrincipalUser, `home\ALICE`, true},
		{id, PrincipalUser, "alice", false},
		{id, PrincipalGroup, `HOME\family`, true},
		{id, PrincipalGroup, `HOME\Domain Users`, true},
		{id, PrincipalGroup, "Family", false},
		{id, PrincipalEveryone, "", true},
		{l, PrincipalUser, "alice", true},
		{l, PrincipalUser, `HOME\alice`, false},
		{l, PrincipalGroup, `HOME\Family`, false},
		{l, "bogus", "alice", false},
	}
	for _, c := range cases {
		if got := c.who.Matches(c.kind, c.name); got != c.want {
			t.Errorf("%s matches %s %q = %v", c.who.IdentityPrincipal(), c.kind, c.name, got)
		}
	}
	if d.IdentitySource() != SourceDomain || l.IdentitySource() != SourceLocal || l.IdentityGroups() != nil {
		t.Errorf("sources: %s %s %v", d.IdentitySource(), l.IdentitySource(), l.IdentityGroups())
	}
}

func TestMapKerberosError(t *testing.T) {
	krb := func(code int32) error {
		e := messages.NewKRBError(types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", "HOME"}}, "HOME", code, "")
		return krberror.Errorf(e, krberror.KDCError, "AS Exchange Error: kerberos error response from KDC")
	}
	for _, c := range []struct{ err, want error }{
		{krb(errorcode.KDC_ERR_PREAUTH_FAILED), ErrBadCredentials},
		{krb(errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN), ErrBadCredentials},
		{krb(errorcode.KDC_ERR_CLIENT_REVOKED), ErrAccountRevoked},
		{krb(errorcode.KDC_ERR_KEY_EXPIRED), ErrPasswordExpired},
		{krb(errorcode.KRB_AP_ERR_SKEW), ErrClockSkew},
		{krberror.Errorf(fmt.Errorf("dial tcp: refused"), krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC"), ErrDomainUnavailable},
		{krberror.NewErrorf(krberror.KRBMsgError, "AS_REP is not valid or client password/keytab incorrect"), ErrBadCredentials},
	} {
		if got := MapKerberosError(c.err); !errors.Is(got, c.want) {
			t.Errorf("%v -> %v, want %v", c.err, got, c.want)
		}
	}
	if got := MapKerberosError(krb(errorcode.KDC_ERR_ETYPE_NOSUPP)); got == nil || isAny(got, ErrBadCredentials, ErrDomainUnavailable) {
		t.Errorf("unexpected code -> %v", got)
	}
	if MapKerberosError(nil) != nil {
		t.Error("nil error mapped")
	}
}

// fakeKDC answers every AS-REQ on loopback with one KRB-ERROR, so the real
// Kerberos client's framing and error handling are exercised without a DC.
func fakeKDC(t *testing.T, code int32) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	reply, err := func() ([]byte, error) {
		e := messages.NewKRBError(types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"krbtgt", "HOME.EXAMPLE.NET"}}, "HOME.EXAMPLE.NET", code, "")
		return e.Marshal()
	}()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				var n uint32
				if binary.Read(c, binary.BigEndian, &n) != nil || n > 1<<20 {
					return // the reachability probe connects and hangs up
				}
				if _, err := io.CopyN(io.Discard, c, int64(n)); err != nil {
					return
				}
				_ = binary.Write(c, binary.BigEndian, uint32(len(reply)))
				_, _ = c.Write(reply)
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestKerberosCheckerAgainstFakeKDC(t *testing.T) {
	ctx := context.Background()
	d := DomainInfo{Realm: "HOME.EXAMPLE.NET", NetBIOS: "HOME", DNS: "home.example.net", LocalKDC: "127.0.0.1"}
	for code, want := range map[int32]error{
		errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN: ErrBadCredentials,
		errorcode.KDC_ERR_CLIENT_REVOKED:      ErrAccountRevoked,
		errorcode.KDC_ERR_KEY_EXPIRED:         ErrPasswordExpired,
	} {
		k := KerberosChecker{Port: fakeKDC(t, code), Timeout: 5 * time.Second}
		if err := k.CheckPassword(ctx, d, "alice", "pw"); !errors.Is(err, want) {
			t.Errorf("code %d: %v, want %v", code, err, want)
		}
	}

	// Nothing listening: unreachable, quickly.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	start := time.Now()
	k := KerberosChecker{Port: port, ProbeTimeout: 500 * time.Millisecond}
	if err := k.CheckPassword(ctx, d, "alice", "pw"); !errors.Is(err, ErrDomainUnavailable) {
		t.Errorf("no KDC: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("took %s to give up", time.Since(start))
	}
	if err := k.CheckPassword(ctx, DomainInfo{LocalKDC: "127.0.0.1"}, "alice", "pw"); !errors.Is(err, ErrDomainUnavailable) {
		t.Errorf("no realm: %v", err)
	}
}
