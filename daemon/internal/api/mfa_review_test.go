package api

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/mail"
	"github.com/hardyos/hardyos/daemon/internal/ports"
)

// Inside is the server's loopback, LAN and NetBird; Docker's networks
// (webmail's included) and the router's own address are outside
// (review M3, L7).
func TestInsideAddresses(t *testing.T) {
	e := newMFAEnv(t)
	s := e.server
	for addr, want := range map[string]bool{
		"127.0.0.1": true, "::1": true, "192.168.1.20": true, "100.64.3.4": true,
		"172.17.0.5": false, ports.WebmailAddr.String(): false, "10.9.0.1": false, "203.0.113.5": false,
		"192.168.1.1": true, // the router: on the LAN, but noted for the warning
	} {
		if got := s.insideAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s inside = %v, want %v", addr, got, want)
		}
	}
	var pol TwoFactorPolicy
	if code := e.admin.do("GET", "/api/v1/auth/2fa/policy", nil, &pol); code != 200 || pol.RouterSeenAt == nil {
		t.Fatalf("router warning = %d %+v", code, pol)
	}
	// From a container (or the router) a domain password doesn't work for
	// mail even without two-factor sign-in.
	mp := mailPasswords{s: s}
	docker := mail.WithSignIn(context.Background(), mail.From(netip.MustParseAddr("172.17.0.5"), false), mail.ScopeMail)
	if _, err := mp.CheckDomainPassword(docker, "alice", alicePW); err == nil {
		t.Fatal("mail password accepted from a Docker network")
	}
	lan := mail.WithSignIn(context.Background(), mail.From(netip.MustParseAddr("192.168.1.20"), false), mail.ScopeMail)
	if _, err := mp.CheckDomainPassword(lan, "alice", alicePW); err != nil {
		t.Fatalf("mail password at home without 2FA: %v", err)
	}
}

// Wrong codes from outside don't lock the owner out at home; locks are
// reported to administrators and the person (review H1).
func TestMFAOutsideLockoutSparesHome(t *testing.T) {
	e := newMFAEnv(t)
	e.totp.enroll(t, "kid")
	var ch LoginChallenge
	for i := 0; i < 5; i++ {
		out := e.client(t)
		doFrom(out, outsideIP, "POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &ch)
		doFrom(out, outsideIP, "POST", "/api/v1/auth/login/2fa", map[string]string{"challenge": ch.Challenge, "code": "000000"}, nil)
	}
	out := e.client(t)
	doFrom(out, outsideIP, "POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, &ch)
	if code := doFrom(out, outsideIP, "POST", "/api/v1/auth/login/2fa", map[string]string{"challenge": ch.Challenge, "code": e.totp.code(t, "kid")}, nil); code != 429 {
		t.Fatalf("outside after 5 wrong codes = %d", code)
	}
	// At home: fine.
	e.login(t, e.client(t), "", "kid", "kidpassword1")
	// The person sees a notice; it was audited for administrators.
	kid := e.client(t)
	e.login(t, kid, "", "kid", "kidpassword1")
	var st auth.MFAStatus
	if code := kid.do("GET", "/api/v1/auth/2fa", nil, &st); code != 200 || st.Notice == "" || st.OutsideFailures != 5 {
		t.Fatalf("notice = %d %+v", code, st)
	}
	if got := auditActions(e.admin, "auth.2fa.short_lock"); len(got) == 0 {
		t.Fatal("pause not audited")
	}
	if code := kid.do("POST", "/api/v1/auth/2fa/notice/dismiss", nil, nil); code != 204 {
		t.Fatalf("dismiss = %d", code)
	}
}

// Setting up an authenticator ends everything else; the browser that did
// it keeps a fresh two-factor session (review M4).
func TestMFAEnrollEndsEverythingElse(t *testing.T) {
	e := newMFAEnv(t)
	kid, other := e.client(t), e.client(t)
	e.login(t, kid, "", "kid", "kidpassword1")
	e.login(t, other, "", "kid", "kidpassword1")
	var en EnrollmentInfo
	kid.do("POST", "/api/v1/auth/2fa/enroll", map[string]string{"password": "kidpassword1"}, &en)
	// Another session can't finish what this one started.
	if code := other.do("POST", "/api/v1/auth/2fa/confirm", map[string]string{"code": "123456"}, nil); code != 409 {
		t.Fatalf("confirm from another session = %d", code)
	}
	secretFromEnrollment(t, e, "kid", en)
	if code := kid.do("POST", "/api/v1/auth/2fa/confirm", map[string]string{"code": e.totp.code(t, "kid")}, nil); code != 200 {
		t.Fatalf("confirm = %d", code)
	}
	if code := other.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Fatalf("other session = %d", code)
	}
	if code := doFrom(kid, outsideIP, "GET", "/api/v1/auth/me", nil, nil); code != 200 {
		t.Fatalf("this browser (two-factor) from outside = %d", code)
	}
}

// Admin reset revokes app passwords unless told not to; an administrator
// past the grace period can't use the own password for WebDAV (review L3,
// L4).
func TestMFAResetAndDueAdmins(t *testing.T) {
	e := newMFAEnv(t)
	alice := e.client(t)
	me := e.login(t, alice, "", "alice", alicePW)
	var made AppPasswordCreated
	alice.do("POST", "/api/v1/auth/app-passwords", map[string]any{"name": "Phone", "scopes": []string{"files"}, "password": alicePW}, &made)
	e.totp.enroll(t, `HOME\alice`)
	id := strconv.FormatInt(me.ID, 10)
	if code := e.admin.do("POST", "/api/v1/users/"+id+"/2fa/reset", map[string]any{"confirm": me.Username, "revokeAppPasswords": false}, nil); code != 200 {
		t.Fatalf("reset keeping app passwords = %d", code)
	}
	var list []auth.AppPassword
	e.admin.do("GET", "/api/v1/users/"+id+"/app-passwords", nil, &list)
	if len(list) != 1 {
		t.Fatalf("app passwords after reset (kept) = %d", len(list))
	}
	if code := e.admin.do("POST", "/api/v1/users/"+id+"/2fa/reset", map[string]any{"confirm": me.Username}, nil); code != 200 {
		t.Fatalf("reset = %d", code)
	}
	e.admin.do("GET", "/api/v1/users/"+id+"/app-passwords", nil, &list)
	if len(list) != 0 {
		t.Fatalf("app passwords after reset = %d", len(list))
	}

	// Make alice a domain admin past the grace period.
	e.dc.setGroups("alice", "Family", "Domain Admins")
	e.server.dav.dropUser(me.ID)
	e.db.Exec(`UPDATE users SET role = 'admin', groups_checked_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339Nano), me.ID)
	e.db.Exec(`INSERT INTO user_totp (user_id, grace_until, updated_at) VALUES (?, '2000-01-01T00:00:00.000Z', 'x') ON CONFLICT(user_id) DO UPDATE SET grace_until = excluded.grace_until`, me.ID)
	r, _ := http.NewRequest("PROPFIND", e.srv.URL+"/dav/", nil)
	r.SetBasicAuth("alice", alicePW)
	r.Header.Set("Depth", "0")
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 401 || !strings.Contains(string(body), "app password") {
		t.Fatalf("WebDAV password for an admin who must enroll = %d %s", res.StatusCode, body)
	}
}

func secretFromEnrollment(t *testing.T, e *mfaEnv, user string, en EnrollmentInfo) {
	t.Helper()
	raw, err := b32NoPad(en.Secret)
	if err != nil {
		t.Fatal(err)
	}
	e.totp.setSecret(user, raw)
}
