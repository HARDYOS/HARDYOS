package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

// signinDC is a root helper and KDC that pretend to be the domain.
type signinDC struct {
	mu          sync.Mutex
	provisioned bool
	reachable   bool
	accounts    map[string]*domain.UserGroups // lower-case name
	passwords   map[string]string
	lookups     int
}

func (d *signinDC) add(name, pw string, groups ...string) *domain.UserGroups {
	d.mu.Lock()
	defer d.mu.Unlock()
	g := &domain.UserGroups{Exists: true, Username: name, DisplayName: name + " Hardy", Enabled: true, Groups: append([]string{"Domain Users"}, groups...)}
	d.accounts[strings.ToLower(name)] = g
	d.passwords[strings.ToLower(name)] = pw
	return g
}

func (d *signinDC) register(ps *priv.Server) {
	ps.Handle(priv.OpDomainStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if !d.provisioned {
			return domain.Status{Available: true}, nil
		}
		c := &domain.Config{Domain: "home.example.net", Realm: "HOME.EXAMPLE.NET", NetBIOS: "HOME", Address: "192.0.2.20/24", Enabled: true,
			Others: []domain.DC{{Name: "dc2.home.example.net", Address: "192.0.2.21"}}}
		return domain.Status{Available: true, Provisioned: true, Config: c, Running: true, Responding: true}, nil
	})
	ps.Handle(priv.OpDomainUserGroups, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a priv.DomainUserRef
		_ = json.Unmarshal(raw, &a)
		if err := domain.CheckUsername(a.Username); err != nil {
			return nil, priv.Errorf(priv.CodeBadArgs, "%v", err)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		d.lookups++
		g, ok := d.accounts[strings.ToLower(a.Username)]
		if !ok {
			return domain.UserGroups{Groups: []string{}}, nil
		}
		return g, nil
	})
}

// CheckPassword is the fake KDC.
func (d *signinDC) CheckPassword(_ context.Context, info auth.DomainInfo, name, pw string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.reachable || info.Realm != "HOME.EXAMPLE.NET" || len(info.KDCs) != 2 || info.KDCs[0] != "192.0.2.20" {
		return auth.ErrDomainUnavailable
	}
	g, ok := d.accounts[strings.ToLower(name)]
	if !ok {
		return auth.ErrBadCredentials
	}
	if !g.Enabled || g.LockedOut {
		return auth.ErrAccountRevoked
	}
	if d.passwords[strings.ToLower(name)] != pw {
		return auth.ErrBadCredentials
	}
	return nil
}

func newSigninEnv(t *testing.T) (*testEnv, *signinDC) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	dc := &signinDC{provisioned: true, reachable: true, accounts: map[string]*domain.UserGroups{}, passwords: map[string]string{}}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	priv.RegisterBuiltins(ps)
	dc.register(ps)
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	RegisterJobKinds(m, pc)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	upd := &updates.Service{Priv: pc, Jobs: m, DB: db, Dir: t.TempDir(), Notify: &notify.Center{DB: db, Events: broker}}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Updates: upd, Insecure: true,
		Kerberos: dc, DomainInfoTTL: time.Millisecond}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &testEnv{srv: srv, db: db, broker: broker}, dc
}

func TestDomainSignInAPI(t *testing.T) {
	env, dc := newSigninEnv(t)
	admin := env.client(t)
	var setup map[string]bool
	admin.do("GET", "/api/v1/setup", nil, &setup)
	if setup["domainSignIn"] {
		t.Error("domain sign-in offered before an administrator exists")
	}
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	dc.add("alice", "Al1ce-Passw0rd!", "Family")
	dc.add("boss", "B0ss-Passw0rd!", "HardyOS Admins")

	anon := env.client(t)
	if code := anon.do("GET", "/api/v1/setup", nil, &setup); code != 200 || !setup["domainSignIn"] || setup["needsAdmin"] {
		t.Fatalf("setup = %d %v", code, setup)
	}

	// Sign in with each spelling; /me carries source, principal and groups.
	for _, name := range []string{"alice", `HOME\alice`, "alice@home.example.net"} {
		c := env.client(t)
		var me auth.User
		if code := c.do("POST", "/api/v1/auth/login", map[string]string{"username": name, "password": "Al1ce-Passw0rd!"}, &me); code != 200 {
			t.Fatalf("login %s = %d", name, code)
		}
		if code := c.do("GET", "/api/v1/auth/me", nil, &me); code != 200 || me.Source != "domain" || me.Principal != `HOME\alice` ||
			me.Role != auth.RoleUser || strings.Join(me.Groups, ",") != `HOME\Domain Users,HOME\Family` {
			t.Fatalf("me (%s) = %d %+v", name, code, me)
		}
		// A domain user isn't an administrator here.
		if code := c.do("GET", "/api/v1/users", nil, nil); code != 403 {
			t.Errorf("domain user GET /users = %d", code)
		}
	}
	var sessSource, sessPrincipal string
	if err := env.db.QueryRow(`SELECT s.source, s.principal FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.username = ? LIMIT 1`, `HOME\alice`).
		Scan(&sessSource, &sessPrincipal); err != nil || sessSource != "domain" || sessPrincipal != `HOME\alice` {
		t.Errorf("session record = %q %q %v", sessSource, sessPrincipal, err)
	}

	// Errors: wrong password and unknown name look alike; other states say what's wrong.
	var e ErrorResponse
	c := env.client(t)
	if code := c.do("POST", "/api/v1/auth/login", map[string]string{"username": `HOME\alice`, "password": "nope"}, &e); code != 401 || e.Code != "bad_credentials" {
		t.Errorf("wrong password = %d %+v", code, e)
	}
	if code := c.do("POST", "/api/v1/auth/login", map[string]string{"username": `HOME\nobody`, "password": "nope"}, &e); code != 401 || e.Code != "bad_credentials" {
		t.Errorf("unknown user = %d %+v", code, e)
	}
	if code := c.do("POST", "/api/v1/auth/login", map[string]string{"username": `WORK\alice`, "password": "nope"}, &e); code != 401 || e.Code != "unknown_domain" {
		t.Errorf("other domain = %d %+v", code, e)
	}
	dc.mu.Lock()
	dc.reachable = false
	dc.mu.Unlock()
	if code := c.do("POST", "/api/v1/auth/login", map[string]string{"username": `HOME\alice`, "password": "Al1ce-Passw0rd!"}, &e); code != 503 || e.Code != "domain_unavailable" {
		t.Errorf("unreachable = %d %+v", code, e)
	}
	dc.mu.Lock()
	dc.reachable = true
	dc.accounts["alice"].Enabled = false
	dc.mu.Unlock()
	if code := c.do("POST", "/api/v1/auth/login", map[string]string{"username": `HOME\alice`, "password": "Al1ce-Passw0rd!"}, &e); code != 401 || e.Code != "account_disabled" {
		t.Errorf("disabled = %d %+v", code, e)
	}
	dc.mu.Lock()
	dc.accounts["alice"].Enabled = true
	dc.mu.Unlock()

	// A domain admin: admin role, the terminal with the domain password,
	// but no HardyOS password changes.
	boss := env.client(t)
	var me auth.User
	if code := boss.do("POST", "/api/v1/auth/login", map[string]string{"username": `HOME\boss`, "password": "B0ss-Passw0rd!"}, &me); code != 200 || !me.IsAdmin() {
		t.Fatalf("boss = %d %+v", code, me)
	}
	if code := boss.do("GET", "/api/v1/users", nil, nil); code != 200 {
		t.Errorf("domain admin GET /users = %d", code)
	}
	if code := boss.do("POST", "/api/v1/terminal/session", map[string]string{"password": "wrong"}, &e); code != 401 {
		t.Errorf("terminal with a wrong password = %d", code)
	}
	var tk map[string]string
	if code := boss.do("POST", "/api/v1/terminal/session", map[string]string{"password": "B0ss-Passw0rd!"}, &tk); code != 200 || tk["ticket"] == "" {
		t.Errorf("terminal with the domain password = %d %v", code, tk)
	}
	if code := boss.do("POST", "/api/v1/auth/password", map[string]string{"currentPassword": "B0ss-Passw0rd!", "newPassword": "something-new-1"}, &e); code != 403 || e.Code != "domain_account" {
		t.Errorf("own password change = %d %+v", code, e)
	}
	if code := admin.do("POST", "/api/v1/users/"+itoa(int(me.ID))+"/password", map[string]string{"password": "something-new-1"}, &e); code != 409 || e.Code != "domain_account" {
		t.Errorf("admin reset of a domain password = %d %+v", code, e)
	}
	if code := admin.do("PATCH", "/api/v1/users/"+itoa(int(me.ID)), map[string]any{"role": "user"}, &e); code != 409 || e.Code != "domain_account" {
		t.Errorf("role change of a domain account = %d %+v", code, e)
	}

	// Groups are looked up again after 10 minutes: losing HardyOS Admins
	// demotes, a disabled account is signed out.
	age := func() {
		if _, err := env.db.Exec(`UPDATE users SET groups_checked_at = '2000-01-01T00:00:00.000Z' WHERE source = 'domain'`); err != nil {
			t.Fatal(err)
		}
	}
	dc.mu.Lock()
	dc.accounts["boss"].Groups = []string{"Domain Users"}
	dc.mu.Unlock()
	if code := boss.do("GET", "/api/v1/users", nil, nil); code != 200 {
		t.Errorf("fresh groups trusted: %d", code)
	}
	age()
	if code := boss.do("GET", "/api/v1/users", nil, nil); code != 403 {
		t.Errorf("after losing HardyOS Admins GET /users = %d", code)
	}
	dc.mu.Lock()
	dc.accounts["boss"].Enabled = false
	dc.mu.Unlock()
	age()
	if code := boss.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("disabled in the domain, still signed in: %d", code)
	}

	// The user list shows domain accounts that signed in.
	var list []auth.User
	admin.do("GET", "/api/v1/users", nil, &list)
	var domainRows int
	for _, u := range list {
		if u.Source == "domain" {
			domainRows++
		}
	}
	if domainRows != 2 || list[0].Username != "cade" {
		t.Errorf("users = %+v", list)
	}

	// Local sign-in still works, and its /me says local.
	if code := admin.do("GET", "/api/v1/auth/me", nil, &me); code != 200 || me.Source != "local" || me.Principal != "cade" || me.Groups == nil {
		t.Errorf("local me = %+v", me)
	}
	var audit []map[string]any
	admin.do("GET", "/api/v1/audit?limit=100", nil, &audit)
	raw, _ := json.Marshal(audit)
	for _, want := range []string{`HOME\\alice`, "account disabled", "auth.session.end"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("audit lacks %s", want)
		}
	}
	if strings.Contains(string(raw), "Al1ce-Passw0rd!") || strings.Contains(string(raw), "B0ss-Passw0rd!") {
		t.Error("a password reached the audit log")
	}
}

func TestDomainSpellingsShareALimit(t *testing.T) {
	env, dc := newSigninEnv(t)
	env.client(t).do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	dc.add("alice", "Al1ce-Passw0rd!")
	for i, name := range []string{"alice", `HOME\alice`, "alice@home.example.net", `home\ALICE`, "Alice"} {
		var e ErrorResponse
		if code := env.client(t).do("POST", "/api/v1/auth/login", map[string]string{"username": name, "password": "wrong"}, &e); code != 401 {
			t.Fatalf("attempt %d = %d %+v", i, code, e)
		}
	}
	// Five wrong guesses in any spelling lock them all, even with the right password.
	var e ErrorResponse
	if code := env.client(t).do("POST", "/api/v1/auth/login", map[string]string{"username": "ALICE@home.example.net", "password": "Al1ce-Passw0rd!"}, &e); code != 429 {
		t.Errorf("after five guesses = %d %+v", code, e)
	}
}

func TestNoDomainSignIn(t *testing.T) {
	env, dc := newSigninEnv(t)
	dc.provisioned = false
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	var setup map[string]bool
	if env.client(t).do("GET", "/api/v1/setup", nil, &setup); setup["domainSignIn"] {
		t.Error("domain sign-in offered without a domain")
	}
	var e ErrorResponse
	if code := env.client(t).do("POST", "/api/v1/auth/login", map[string]string{"username": `HOME\alice`, "password": "x"}, &e); code != 401 || e.Code != "unknown_domain" {
		t.Errorf("domain name without a domain = %d %+v", code, e)
	}
	if code := env.client(t).do("POST", "/api/v1/auth/login", map[string]string{"username": "cade", "password": "supersecret1"}, nil); code != 200 {
		t.Errorf("local sign-in = %d", code)
	}
}
