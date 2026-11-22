package api

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/mail"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// mfaEnv is a server with a domain (alice), WebDAV, a local admin (cade)
// and a local user (kid), that believes X-Forwarded-For from loopback so
// tests can come "from outside".
type mfaEnv struct {
	*davEnv
	totp  *totpKit
	admin *client
}

const outsideIP = "203.0.113.50"

func newMFAEnv(t *testing.T) *mfaEnv {
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
	dc := &signinDC{provisioned: true, reachable: true, accounts: map[string]*domain.UserGroups{}, passwords: map[string]string{}, adminsSID: signinAdminsSID}
	df := &davFiles{enabled: true, on: map[string]bool{"media": true}}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	priv.RegisterBuiltins(ps)
	dc.register(ps)
	df.register(ps)
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	fk := &fakeFiles{dirs: map[string]string{"media": t.TempDir(), files.HomeShare: t.TempDir()}, recycle: map[string]bool{}}
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	s := New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Files: fk, Insecure: true, Kerberos: dc, DomainInfoTTL: time.Millisecond,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	srv := httptest.NewServer(s)
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	// The LAN is 192.168.1.0/24 behind the router 192.168.1.1.
	s.inside.lanFor = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")} }
	s.inside.routerFor = func() (netip.Addr, string) { return netip.MustParseAddr("192.168.1.1"), testRouterMAC }
	env := &mfaEnv{davEnv: &davEnv{testEnv: &testEnv{srv: srv, db: db, broker: broker}, server: s, fk: fk, dc: dc, df: df}}
	env.totp = newTOTPKit(s)
	env.admin = env.client(t)
	env.admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	env.admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	dc.add("alice", alicePW, "Family")
	return env
}

// doFrom is client.do from an address (X-Forwarded-For; "" for loopback).
func doFrom(c *client, ip, method, path string, body, out any) int {
	c.t.Helper()
	var r *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	} else {
		r = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.base+path, r)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HardyOS-Request", "1")
	if ip != "" {
		req.Header.Set("X-Forwarded-For", ip)
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	if out != nil {
		_ = json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

// login signs c in with a code when one is asked for.
func (e *mfaEnv) login(t *testing.T, c *client, ip, user, pw string) *auth.User {
	t.Helper()
	var raw json.RawMessage
	code := doFrom(c, ip, "POST", "/api/v1/auth/login", map[string]string{"username": user, "password": pw}, &raw)
	if code == 200 {
		var u auth.User
		_ = json.Unmarshal(raw, &u)
		return &u
	}
	var ch LoginChallenge
	if code != 202 || json.Unmarshal(raw, &ch) != nil || ch.Step != auth.NeedCode {
		t.Fatalf("login %s from %q = %d %s", user, ip, code, raw)
	}
	var u auth.User
	if code := doFrom(c, ip, "POST", "/api/v1/auth/login/2fa", map[string]string{"challenge": ch.Challenge, "code": e.totp.code(t, user)}, &u); code != 200 {
		t.Fatalf("code for %s = %d", user, code)
	}
	return &u
}

func TestMFAAdminForcedEnrollment(t *testing.T) {
	e := newMFAEnv(t)
	// In the grace period: signed in, and the deadline is visible.
	c := e.client(t)
	u := e.login(t, c, "", "cade", "supersecret1")
	if u.TwoFactor == nil || !u.TwoFactor.Required || u.TwoFactor.Enabled || u.TwoFactor.GraceUntil == nil || u.TwoFactor.MustEnroll {
		t.Fatalf("admin in grace: %+v", u.TwoFactor)
	}
	var users []auth.User
	if code := c.do("GET", "/api/v1/users", nil, &users); code != 200 || users[0].TwoFactor == nil || users[0].TwoFactor.GraceUntil == nil {
		t.Fatalf("users list: %d %+v", code, users)
	}
	// Past it, the open session can do nothing but set it up.
	e.totp.advance(8 * 24 * time.Hour)
	var er ErrorResponse
	if code := c.do("GET", "/api/v1/users", nil, &er); code != 403 || er.Code != "mfa_enrollment_required" {
		t.Fatalf("admin past grace = %d %+v", code, er)
	}
	var me auth.User
	if code := c.do("GET", "/api/v1/auth/me", nil, &me); code != 200 || !me.TwoFactor.MustEnroll {
		t.Fatalf("me past grace = %d %+v", code, me.TwoFactor)
	}
	// A new sign-in goes straight to enrollment.
	c2 := e.client(t)
	var ch LoginChallenge
	if code := c2.do("POST", "/api/v1/auth/login", map[string]string{"username": "cade", "password": "supersecret1"}, &ch); code != 202 || ch.Step != auth.NeedEnroll {
		t.Fatalf("login past grace = %d %+v", code, ch)
	}
	// A code step can't be skipped with the enrollment challenge.
	if code := c2.do("POST", "/api/v1/auth/login/2fa", map[string]string{"challenge": ch.Challenge, "code": "123456"}, &er); code != 401 || er.Code != "challenge_expired" {
		t.Fatalf("code with an enrollment challenge = %d %+v", code, er)
	}
	var en EnrollmentInfo
	if code := c2.do("POST", "/api/v1/auth/login/enroll", map[string]string{"challenge": ch.Challenge}, &en); code != 200 || en.QR == nil || !strings.HasPrefix(en.URI, "otpauth://totp/") {
		t.Fatalf("enroll at sign-in = %d %+v", code, en)
	}
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(en.Secret, " ", ""))
	e.totp.setSecret("cade", secret)
	var res EnrollResult
	if code := c2.do("POST", "/api/v1/auth/login/enroll/confirm", map[string]string{"challenge": ch.Challenge, "code": e.totp.code(t, "cade")}, &res); code != 200 ||
		len(res.RecoveryCodes) != auth.RecoveryCodeCount || res.User == nil || !res.User.TwoFactor.Enabled {
		t.Fatalf("confirm at sign-in = %d %+v", code, res)
	}
	// Everything signed in with the password alone ended; this one works.
	if code := c.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Fatalf("old session = %d", code)
	}
	if code := c2.do("GET", "/api/v1/users", nil, nil); code != 200 {
		t.Fatalf("new session = %d", code)
	}
	// Administrators can't turn it off.
	if code := c2.do("POST", "/api/v1/auth/2fa/disable", map[string]string{"password": "supersecret1", "code": e.totp.code(t, "cade")}, &er); code != 403 {
		t.Fatalf("admin disable = %d", code)
	}
	// Sign-in now asks for a code; a recovery code works once.
	c3 := e.client(t)
	c3.do("POST", "/api/v1/auth/login", map[string]string{"username": "cade", "password": "supersecret1"}, &ch)
	if code := c3.do("POST", "/api/v1/auth/login/2fa", map[string]string{"challenge": ch.Challenge, "code": res.RecoveryCodes[0]}, nil); code != 200 {
		t.Fatalf("recovery code = %d", code)
	}
	c4 := e.client(t)
	c4.do("POST", "/api/v1/auth/login", map[string]string{"username": "cade", "password": "supersecret1"}, &ch)
	if code := c4.do("POST", "/api/v1/auth/login/2fa", map[string]string{"challenge": ch.Challenge, "code": res.RecoveryCodes[0]}, &er); code != 401 || er.Code != "bad_code" {
		t.Fatalf("reused recovery code = %d %+v", code, er)
	}
}

func TestMFACodesReplayAndLimits(t *testing.T) {
	e := newMFAEnv(t)
	e.totp.enroll(t, "kid")
	c := e.client(t)
	var ch LoginChallenge
	c.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &ch)
	code := e.totp.code(t, "kid")
	if got := c.do("POST", "/api/v1/auth/login/2fa", map[string]string{"challenge": ch.Challenge, "code": code}, nil); got != 200 {
		t.Fatalf("code = %d", got)
	}
	// The same code can't sign in again (another browser, same window).
	c2 := e.client(t)
	c2.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &ch)
	var er ErrorResponse
	if got := c2.do("POST", "/api/v1/auth/login/2fa", map[string]string{"challenge": ch.Challenge, "code": code}, &er); got != 401 || er.Code != "bad_code" {
		t.Fatalf("replayed code = %d %+v", got, er)
	}
	// Five tries per challenge, then it's gone.
	for range 4 {
		c2.do("POST", "/api/v1/auth/login/2fa", map[string]string{"challenge": ch.Challenge, "code": "000000"}, nil)
	}
	if got := c2.do("POST", "/api/v1/auth/login/2fa", map[string]string{"challenge": ch.Challenge, "code": e.totp.code(t, "kid")}, &er); got != 401 || er.Code != "challenge_expired" {
		t.Fatalf("after 5 tries = %d %+v", got, er)
	}
	// Five wrong codes lock code entry for the account, whatever challenge.
	c3 := e.client(t)
	c3.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &ch)
	if got := c3.do("POST", "/api/v1/auth/login/2fa", map[string]string{"challenge": ch.Challenge, "code": e.totp.code(t, "kid")}, &er); got != 429 {
		t.Fatalf("after 5 wrong codes = %d %+v", got, er)
	}
	// Every failure is audited.
	if n := len(auditActions(e.admin, "auth.login")); n < 6 {
		t.Fatalf("audited %d", n)
	}
}

func TestMFAOutside(t *testing.T) {
	e := newMFAEnv(t)
	// At home, kid needs nothing more.
	home := e.client(t)
	e.login(t, home, "", "kid", "kidpassword1")
	// That session doesn't work from outside.
	var er ErrorResponse
	if code := doFrom(home, outsideIP, "GET", "/api/v1/auth/me", nil, &er); code != 401 {
		t.Fatalf("home session from outside = %d", code)
	}
	// From outside without two-factor: only an administrator's setup code
	// leads to enrollment.
	out := e.client(t)
	var ch LoginChallenge
	if code := doFrom(out, outsideIP, "POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &ch); code != 202 || ch.Step != auth.NeedSetupCode {
		t.Fatalf("outside without 2FA = %d %+v", code, ch)
	}
	if code := doFrom(out, outsideIP, "POST", "/api/v1/auth/login/enroll", map[string]string{"challenge": ch.Challenge}, &er); code != 401 || er.Code != "bad_setup_code" {
		t.Fatalf("enroll without a setup code = %d %+v", code, er)
	}
	if code := doFrom(out, outsideIP, "POST", "/api/v1/auth/login/enroll/confirm", map[string]string{"challenge": ch.Challenge, "code": "123456"}, &er); code != 409 {
		t.Fatalf("confirm without enrolling = %d %+v", code, er)
	}
	var users []auth.User
	e.admin.do("GET", "/api/v1/users", nil, &users)
	kidID := ""
	for _, u := range users {
		if u.Username == "kid" {
			kidID = itoa(int(u.ID))
		}
	}
	var sc SetupCode
	if code := e.admin.do("POST", "/api/v1/users/"+kidID+"/2fa/setup-code", nil, &sc); code != 200 || len(sc.Code) != 19 {
		t.Fatalf("setup code = %d %+v", code, sc)
	}
	// A challenge from outside can't be finished from home.
	doFrom(out, outsideIP, "POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &ch)
	var en EnrollmentInfo
	if code := doFrom(out, "", "POST", "/api/v1/auth/login/enroll", map[string]string{"challenge": ch.Challenge, "setupCode": sc.Code}, &er); code != 401 || er.Code != "challenge_expired" {
		t.Fatalf("outside challenge from home = %d %+v", code, er)
	}
	doFrom(out, outsideIP, "POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &ch)
	if code := doFrom(out, outsideIP, "POST", "/api/v1/auth/login/enroll", map[string]string{"challenge": ch.Challenge, "setupCode": strings.ToUpper(sc.Code)}, &en); code != 200 {
		t.Fatalf("enroll with setup code = %d", code)
	}
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(en.Secret, " ", ""))
	e.totp.setSecret("kid", secret)
	var res EnrollResult
	if code := doFrom(out, outsideIP, "POST", "/api/v1/auth/login/enroll/confirm", map[string]string{"challenge": ch.Challenge, "code": e.totp.code(t, "kid")}, &res); code != 200 {
		t.Fatalf("confirm outside = %d", code)
	}
	if code := doFrom(out, outsideIP, "GET", "/api/v1/auth/me", nil, nil); code != 200 {
		t.Fatalf("outside session = %d", code)
	}
	// The setup code is used up.
	if code := e.admin.do("POST", "/api/v1/users/"+kidID+"/2fa/setup-code", nil, &er); code != 409 || er.Code != "already_enrolled" {
		t.Fatalf("setup code for an enrolled account = %d", code)
	}
	// From outside, a code is asked for from now on.
	e.login(t, e.client(t), outsideIP, "kid", "kidpassword1")

	// Admin reset: confirmation required, audited, signs out everywhere.
	if code := e.admin.do("POST", "/api/v1/users/"+kidID+"/2fa/reset", map[string]string{"confirm": "kidd"}, &er); code != 400 || er.Code != "confirm_required" {
		t.Fatalf("reset without confirmation = %d", code)
	}
	var after auth.User
	if code := e.admin.do("POST", "/api/v1/users/"+kidID+"/2fa/reset", map[string]string{"confirm": "kid"}, &after); code != 200 || after.TwoFactor.Enabled {
		t.Fatalf("reset = %d %+v", code, after.TwoFactor)
	}
	if code := doFrom(out, outsideIP, "GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Fatalf("session after reset = %d", code)
	}
	if got := auditActions(e.admin, "users.2fa"); len(got) != 3 {
		t.Fatalf("audit %v", got)
	}
	// Non-admins can't reset anyone.
	kid := e.client(t)
	e.login(t, kid, "", "kid", "kidpassword1")
	if code := kid.do("POST", "/api/v1/users/1/2fa/reset", map[string]string{"confirm": "cade"}, nil); code != 403 {
		t.Fatalf("kid reset = %d", code)
	}
}

func TestMFASelfServiceAndPolicy(t *testing.T) {
	e := newMFAEnv(t)
	kid := e.client(t)
	e.login(t, kid, "", "kid", "kidpassword1")
	var er ErrorResponse
	if code := kid.do("POST", "/api/v1/auth/2fa/enroll", map[string]string{"password": "wrong"}, &er); code != 401 {
		t.Fatalf("enroll with a wrong password = %d", code)
	}
	var en EnrollmentInfo
	if code := kid.do("POST", "/api/v1/auth/2fa/enroll", map[string]string{"password": "kidpassword1"}, &en); code != 200 {
		t.Fatalf("enroll = %d", code)
	}
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(en.Secret, " ", ""))
	e.totp.setSecret("kid", secret)
	other := e.client(t)
	e.login(t, other, "", "kid", "kidpassword1")
	var rc RecoveryCodes
	if code := kid.do("POST", "/api/v1/auth/2fa/confirm", map[string]string{"code": e.totp.code(t, "kid")}, &rc); code != 200 || len(rc.RecoveryCodes) != 10 {
		t.Fatalf("confirm = %d", code)
	}
	// This browser stays (and now counts as two-factor); the other ends.
	if code := doFrom(kid, outsideIP, "GET", "/api/v1/auth/me", nil, nil); code != 200 {
		t.Fatalf("this session from outside = %d", code)
	}
	if code := other.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Fatalf("other session = %d", code)
	}
	// Replacing the authenticator needs a current code.
	if code := kid.do("POST", "/api/v1/auth/2fa/enroll", map[string]string{"password": "kidpassword1", "code": "000000"}, &er); code != 401 {
		t.Fatalf("replace without a code = %d", code)
	}
	if code := kid.do("POST", "/api/v1/auth/2fa/recovery-codes", map[string]string{"password": "kidpassword1", "code": e.totp.code(t, "kid")}, &rc); code != 200 {
		t.Fatalf("new recovery codes = %d", code)
	}
	if code := kid.do("POST", "/api/v1/auth/2fa/disable", map[string]string{"password": "kidpassword1", "code": e.totp.code(t, "kid")}, nil); code != 204 {
		t.Fatalf("disable = %d", code)
	}
	// Policy: admins only, 0-30 days, audited.
	if code := kid.do("PUT", "/api/v1/auth/2fa/policy", map[string]int{"adminGraceDays": 0}, nil); code != 403 {
		t.Fatalf("kid policy = %d", code)
	}
	if code := e.admin.do("PUT", "/api/v1/auth/2fa/policy", map[string]int{"adminGraceDays": 31}, nil); code != 400 {
		t.Fatalf("31 days = %d", code)
	}
	var pol TwoFactorPolicy
	if code := e.admin.do("PUT", "/api/v1/auth/2fa/policy", map[string]int{"adminGraceDays": 2}, &pol); code != 200 || pol.AdminGraceDays != 2 || !pol.OutsideRequired {
		t.Fatalf("policy = %d %+v", code, pol)
	}
}

func TestAppPasswordsForServices(t *testing.T) {
	e := newMFAEnv(t)
	alice := e.client(t)
	e.login(t, alice, "", "alice", alicePW)
	// Local accounts don't get them.
	var er ErrorResponse
	kid := e.client(t)
	e.login(t, kid, "", "kid", "kidpassword1")
	if code := kid.do("POST", "/api/v1/auth/app-passwords", map[string]any{"name": "Phone", "scopes": []string{"files"}, "password": "kidpassword1"}, &er); code != 400 {
		t.Fatalf("local app password = %d", code)
	}
	if code := alice.do("POST", "/api/v1/auth/app-passwords", map[string]any{"name": "Phone", "scopes": []string{"files"}, "password": "nope"}, &er); code != 401 {
		t.Fatalf("app password without the right password = %d", code)
	}
	var made AppPasswordCreated
	if code := alice.do("POST", "/api/v1/auth/app-passwords", map[string]any{"name": "Laptop", "scopes": []string{"files", "calendars"}, "password": alicePW}, &made); code != 201 || !auth.LooksLikeAppPassword(made.Password) {
		t.Fatalf("create = %d %+v", code, made)
	}
	dav := func(ip, pw string) int {
		r, _ := http.NewRequest("PROPFIND", e.srv.URL+"/dav/", nil)
		r.SetBasicAuth("alice", pw)
		r.Header.Set("Depth", "0")
		if ip != "" {
			r.Header.Set("X-Forwarded-For", ip)
		}
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	// At home without two-factor: both work. From outside: only the app
	// password.
	if code := dav("", alicePW); code != 207 {
		t.Fatalf("password at home = %d", code)
	}
	if code := dav(outsideIP, alicePW); code != 401 {
		t.Fatalf("password from outside = %d", code)
	}
	if code := dav(outsideIP, made.Password); code != 207 {
		t.Fatalf("app password from outside = %d", code)
	}
	// Once alice has two-factor sign-in, her password stops working at
	// home too.
	e.totp.enroll(t, `HOME\alice`)
	// (Enrolling through the API drops WebDAV's remembered sign-ins; done
	// directly here, so by hand.)
	var me auth.User
	alice.do("GET", "/api/v1/auth/me", nil, &me)
	e.server.dav.dropUser(me.ID)
	if code := dav("", alicePW); code != 401 {
		t.Fatalf("password at home with 2FA = %d", code)
	}
	if code := dav("", made.Password); code != 207 {
		t.Fatalf("app password at home = %d", code)
	}
	// Revoked: gone at once.
	var list []auth.AppPassword
	if code := alice.do("GET", "/api/v1/auth/app-passwords", nil, &list); code != 200 || len(list) != 1 || list[0].LastUsedAt == nil {
		t.Fatalf("list = %d %+v", code, list)
	}
	// Someone else's id isn't theirs to revoke.
	if code := kid.do("DELETE", "/api/v1/auth/app-passwords/"+itoa(int(list[0].ID)), nil, nil); code != 404 {
		t.Fatalf("kid revoking alice's = %d", code)
	}
	if code := alice.do("DELETE", "/api/v1/auth/app-passwords/"+itoa(int(list[0].ID)), nil, nil); code != 204 {
		t.Fatalf("revoke = %d", code)
	}
	if code := dav("", made.Password); code != 401 {
		t.Fatalf("revoked app password = %d", code)
	}

	// Mail: the same rule through the password check behind Dovecot.
	mp := mailPasswords{s: e.server}
	alice.do("POST", "/api/v1/auth/app-passwords", map[string]any{"name": "Phone mail", "scopes": []string{"mail"}, "password": alicePW}, &made)
	inside := mail.WithSignIn(context.Background(), mail.From(netip.MustParseAddr("192.168.1.20"), false), mail.ScopeMail)
	internet := mail.WithSignIn(context.Background(), mail.From(netip.MustParseAddr("192.168.1.20"), true), mail.ScopeMail)
	calendars := mail.WithSignIn(context.Background(), mail.From(netip.MustParseAddr("192.168.1.20"), false), mail.ScopeCalendars)
	if _, err := mp.CheckDomainPassword(inside, "alice", alicePW); err == nil {
		t.Fatal("mail password with 2FA accepted")
	}
	if _, err := mp.CheckDomainPassword(internet, "alice", made.Password); err != nil {
		t.Fatalf("mail app password from the internet: %v", err)
	}
	if _, err := mp.CheckDomainPassword(calendars, "alice", made.Password); err == nil {
		t.Fatal("mail-only app password accepted for calendars")
	}
	if _, err := mp.CheckDomainPassword(context.Background(), "alice", alicePW); err == nil {
		t.Fatal("password accepted without a known source")
	}
}
