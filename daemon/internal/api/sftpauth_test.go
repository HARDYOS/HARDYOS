package api

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/sftpauth"
)

// SFTP sign-ins follow WebDAV's rule (decisions 445, 514, 519): an app
// password with the sftp scope always works, rate limits or not; the own
// password only at home and only without two-factor sign-in, an attempt
// reserved before winbind sees it; refusals are audited (throttled) and
// counted against the address (per /64 from outside) only.
func TestSFTPSignInRule(t *testing.T) {
	e := newMFAEnv(t)
	alice := e.client(t)
	e.login(t, alice, "", "alice", alicePW)
	var sftpPw, filesPw AppPasswordCreated
	if code := alice.do("POST", "/api/v1/auth/app-passwords", map[string]any{"name": "Laptop SFTP", "scopes": []string{"sftp"}, "password": alicePW}, &sftpPw); code != 201 {
		t.Fatalf("create sftp = %d", code)
	}
	alice.do("POST", "/api/v1/auth/app-passwords", map[string]any{"name": "Phone files", "scopes": []string{"files"}, "password": alicePW}, &filesPw)
	s := e.server
	ctx := context.Background()
	askAs := func(user, op, rhost, pw string) bool {
		return s.sftpAnswer(ctx, sftpauth.Request{Op: op, User: user, RHost: rhost, Password: pw}).OK
	}
	ask := func(op, rhost, pw string) bool { return askAs(`HOME\alice`, op, rhost, pw) }
	const home = "192.168.1.20"
	// At home without two-factor: the own password may go to winbind.
	if !ask(sftpauth.OpOwn, home, "") || !ask(sftpauth.OpAfter, home, "") {
		t.Fatal("own password at home refused")
	}
	// From outside, the router (NAT reflection) and this server itself:
	// only app passwords.
	for _, ip := range []string{outsideIP, "192.168.1.1", "127.0.0.1", "", "host.example"} {
		if ask(sftpauth.OpOwn, ip, "") {
			t.Errorf("own password from %q allowed", ip)
		}
	}
	if !ask(sftpauth.OpApp, outsideIP, sftpPw.Password) {
		t.Fatal("sftp app password from outside refused")
	}
	if ask(sftpauth.OpApp, outsideIP, filesPw.Password) {
		t.Fatal("a WebDAV-only app password worked for SFTP")
	}
	if ask(sftpauth.OpApp, home, "zzzz-zzzz-zzzz-zzzz-zzzz") {
		t.Fatal("a wrong app password worked")
	}
	if askAs(`HOME\bob`, sftpauth.OpApp, home, sftpPw.Password) {
		t.Fatal("alice's app password worked for another account")
	}

	// Rate limits: each own-password attempt at home is reserved before
	// winbind sees it; five without a success pause the address, but a
	// right app password still works; a success clears it.
	for i := 0; i < 5; i++ {
		ask(sftpauth.OpOwn, "192.168.1.30", "")
	}
	if ask(sftpauth.OpOwn, "192.168.1.30", "") {
		t.Fatal("own-password attempts weren't limited")
	}
	if !ask(sftpauth.OpApp, "192.168.1.30", sftpPw.Password) {
		t.Fatal("a right app password was refused by the rate limit")
	}
	if !ask(sftpauth.OpOwn, "192.168.1.30", "") {
		t.Fatal("the app password's success didn't clear the address")
	}
	// From outside, refusals count per /64.
	for _, ip := range []string{"2001:db8:aa::1", "2001:db8:aa::2", "2001:db8:aa::3", "2001:db8:aa::4", "2001:db8:aa::5"} {
		ask(sftpauth.OpOwn, ip, "")
	}
	if ok, _ := s.cfg.Limiter.Allowed("ip:2001:db8:aa::/64"); ok {
		t.Fatal("refusals from one /64 weren't counted together")
	}
	if ok, _ := s.cfg.Limiter.Allowed(s.signin.LimitKey(ctx, `HOME\alice`)); !ok {
		t.Fatal("refused own passwords counted against the account")
	}

	// Two-factor sign-in: the own password stops at home too; the app
	// password keeps working.
	e.totp.enroll(t, `HOME\alice`)
	if ask(sftpauth.OpOwn, home, "") || ask(sftpauth.OpAfter, home, "") {
		t.Fatal("own password with two-factor sign-in allowed")
	}
	if !ask(sftpauth.OpApp, home, sftpPw.Password) {
		t.Fatal("app password with two-factor sign-in refused")
	}

	// An account that never signed in to HardyOS: after winbind said yes,
	// its row is made from the directory (like a desktop sign-in) ...
	e.dc.add("bob", "B0b-Passw0rd!x", "Family")
	if !askAs(`HOME\bob`, sftpauth.OpOwn, home, "") || !askAs(`HOME\bob`, sftpauth.OpAfter, home, "") {
		t.Fatal("bob's first SFTP sign-in at home")
	}
	bob, err := s.users.GetByName(ctx, `HOME\bob`)
	if err != nil || bob.Source != auth.SourceDomain {
		t.Fatalf("bob's row: %+v %v", bob, err)
	}
	// ... and an administrator past the grace period can't use the own
	// password either.
	e.dc.setGroups("bob", "Family", "Domain Admins")
	e.db.Exec(`INSERT INTO user_totp (user_id, grace_until, updated_at) VALUES (?, '2000-01-01T00:00:00.000Z', 'x') ON CONFLICT(user_id) DO UPDATE SET grace_until = excluded.grace_until`, bob.ID)
	if askAs(`HOME\bob`, sftpauth.OpAfter, home, "") {
		t.Fatal("an administrator past the grace period used the own password")
	}
	// A disabled domain account: refused after winbind.
	e.dc.mu.Lock()
	e.dc.accounts["bob"].Enabled = false
	e.dc.mu.Unlock()
	if askAs(`HOME\bob`, sftpauth.OpAfter, home, "") {
		t.Fatal("a turned-off account signed in")
	}

	// Audited, off the answer path; refusals at most once a minute per
	// kind, address and name.
	if !s.sftpAnswer(ctx, sftpauth.Request{Op: sftpauth.OpFail, User: `HOME\alice`, RHost: home}).OK {
		t.Fatal("fail op")
	}
	s.sftpAudits.Wait()
	entries, err := s.audit.List(ctx, audit.Query{Action: "sftp.login", Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	var ok, refusedOutside, wrong int
	for _, en := range entries {
		switch {
		case en.Outcome == audit.Success && strings.Contains(en.Detail, "app password"):
			ok++
		case en.Outcome == audit.Failure && strings.Contains(en.Detail, "use an app password") && en.IP == outsideIP:
			refusedOutside++
		case en.Outcome == audit.Failure && strings.Contains(en.Detail, "wrong password"):
			wrong++
		}
	}
	if ok < 3 || refusedOutside != 1 || wrong != 1 {
		t.Fatalf("audit: %d app-password sign-ins, %d refusals from outside, %d wrong: %+v", ok, refusedOutside, wrong, entries)
	}
	if !strings.Contains(strings.Join(auth.AppPasswordScopes, ","), "sftp") {
		t.Fatal("no sftp scope")
	}
}

// The socket answers root alone; anyone else is told no without the rule
// being asked.
func TestSFTPAuthSocketOnlyRoot(t *testing.T) {
	e := newMFAEnv(t)
	sock := filepath.Join(t.TempDir(), "sftp.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	old := sftpPeerUID
	t.Cleanup(func() { sftpPeerUID = old })
	var uid atomic.Uint32
	uid.Store(1000)
	sftpPeerUID = func(net.Conn) (uint32, error) { return uid.Load(), nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.server.RunSFTPAuth(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	env := func(k string) string {
		return map[string]string{"PAM_TYPE": "auth", "PAM_USER": `HOME\alice`, "PAM_RHOST": "192.168.1.20"}[k]
	}
	if rc := sftpauth.PAM(ctx, sftpauth.OpOwn, env, nil, sock, io.Discard); rc != 1 {
		t.Fatalf("not root: %d", rc)
	}
	uid.Store(0)
	if rc := sftpauth.PAM(ctx, sftpauth.OpOwn, env, nil, sock, io.Discard); rc != 0 {
		t.Fatalf("root at home: %d", rc)
	}
}
