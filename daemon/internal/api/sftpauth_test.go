package api

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/sftpauth"
)

// SFTP sign-ins follow WebDAV's rule (decisions 445, 514): an app password
// with the sftp scope always works; the own password only at home and
// only without two-factor sign-in; refusals are audited and counted
// against the address only.
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
	ask := func(op, rhost, pw string) bool {
		return s.sftpAnswer(ctx, sftpauth.Request{Op: op, User: `HOME\alice`, RHost: rhost, Password: pw}).OK
	}
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
	if s.sftpAnswer(ctx, sftpauth.Request{Op: sftpauth.OpApp, User: `HOME\bob`, RHost: home, Password: sftpPw.Password}).OK {
		t.Fatal("alice's app password worked for another account")
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
	// Audited.
	entries, err := s.audit.List(ctx, audit.Query{Action: "sftp.login", Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	var ok, refused int
	for _, en := range entries {
		switch {
		case en.Outcome == audit.Success && strings.Contains(en.Detail, "app password"):
			ok++
		case en.Outcome == audit.Failure && strings.Contains(en.Detail, "app password"):
			refused++
		}
	}
	if ok < 2 || refused < 5 {
		t.Fatalf("audit: %d app-password sign-ins, %d refusals: %+v", ok, refused, entries)
	}
	// Refused own passwords count against the address, never the account:
	// from outside the address is soon paused, at home alice isn't.
	for range 20 {
		ask(sftpauth.OpOwn, "198.51.100.7", "")
	}
	if ask(sftpauth.OpApp, "198.51.100.7", sftpPw.Password) {
		t.Fatal("an address that kept failing wasn't paused")
	}
	if !ask(sftpauth.OpApp, home, sftpPw.Password) {
		t.Fatal("alice was locked out by someone else's refusals")
	}
	// Wrong domain passwords (winbind said no) count like WebDAV's.
	if !s.sftpAnswer(ctx, sftpauth.Request{Op: sftpauth.OpFail, User: `HOME\alice`, RHost: home}).OK {
		t.Fatal("fail op")
	}
	// The scope is offered and checked.
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
	uid := uint32(1000)
	sftpPeerUID = func(net.Conn) (uint32, error) { return uid, nil }
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
	uid = 0
	if rc := sftpauth.PAM(ctx, sftpauth.OpOwn, env, nil, sock, io.Discard); rc != 0 {
		t.Fatalf("root at home: %d", rc)
	}
}
