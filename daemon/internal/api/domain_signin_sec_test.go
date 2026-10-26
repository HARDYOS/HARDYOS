package api

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/domain"
)

// countingKDC accepts connections on addr and counts them: something
// answering for a DC's address on the LAN.
func countingKDC(t *testing.T, addr string) (port int, accepted *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("can't listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted = &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, accepted
}

// With this server's own DC down, a partner DC (or whatever answers for
// its address) is never asked for a password: sign-in fails with a clear
// message, and local accounts still work.
func TestDomainSignInAsksOnlyThisServersDC(t *testing.T) {
	port, partner := countingKDC(t, "127.0.0.2:0")
	// Nothing listens on 127.0.0.1 at that port: the local DC is down.
	env, dc := newSigninEnvWith(t, auth.KerberosChecker{Port: port, ProbeTimeout: 500 * time.Millisecond, Timeout: 3 * time.Second})
	dc.cfg = &domain.Config{Domain: "home.example.net", Realm: "HOME.EXAMPLE.NET", NetBIOS: "HOME", Address: "127.0.0.1/8", Enabled: true,
		Others: []domain.DC{{Name: "dc2.home.example.net", Address: "127.0.0.2"}}}
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	dc.add("boss", "B0ss-Passw0rd!", "Domain Admins")

	for _, name := range []string{`HOME\boss`, "boss", "boss@home.example.net"} {
		var e ErrorResponse
		code := env.client(t).do("POST", "/api/v1/auth/login", map[string]string{"username": name, "password": "B0ss-Passw0rd!"}, &e)
		if code != 503 || e.Code != "domain_unavailable" || !strings.Contains(e.Message, "domain controller on this server isn't answering") {
			t.Errorf("%s with the local DC down = %d %+v", name, code, e)
		}
	}
	if n := partner.Load(); n != 0 {
		t.Errorf("the partner DC was asked %d times", n)
	}
	if code := env.client(t).do("POST", "/api/v1/auth/login", map[string]string{"username": "cade", "password": "supersecret1"}, nil); code != 200 {
		t.Errorf("local sign-in with the DC down = %d", code)
	}
	// The terminal's password check for a signed-in domain admin follows
	// the same rule (checked in internal/auth); here, the control: the
	// listener is reachable, so a checker pointed at it would have used it.
	_ = auth.KerberosChecker{Port: port, Timeout: time.Second}.CheckPassword(context.Background(),
		auth.DomainInfo{Realm: "HOME.EXAMPLE.NET", LocalKDC: "127.0.0.2"}, "boss", "x")
	if partner.Load() == 0 {
		t.Error("control: the listener on 127.0.0.2 wasn't reachable, so the test proves nothing")
	}
}

// A server without a DC of its own (member mode, later) refuses domain
// sign-in.
func TestDomainSignInNeedsALocalDC(t *testing.T) {
	env, dc := newSigninEnv(t)
	dc.cfg = &domain.Config{Domain: "home.example.net", Realm: "HOME.EXAMPLE.NET", NetBIOS: "HOME", Address: "", Enabled: true}
	env.client(t).do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	dc.add("alice", "Al1ce-Passw0rd!")
	var e ErrorResponse
	if code := env.client(t).do("POST", "/api/v1/auth/login", map[string]string{"username": `HOME\alice`, "password": "Al1ce-Passw0rd!"}, &e); code != 503 || e.Code != "no_local_dc" {
		t.Errorf("no local DC = %d %+v", code, e)
	}
}

// Admin by SID: a group merely named "HardyOS Admins" grants nothing;
// failing lookups hold the role back after the trust window, and /me says
// why.
func TestDomainAdminRoleAPI(t *testing.T) {
	env, dc := newSigninEnv(t)
	env.client(t).do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	dc.add("mallory", "Mall0ry-Passw0rd!")
	dc.mu.Lock()
	m := dc.accounts["mallory"]
	m.Groups = append(m.Groups, "HardyOS Admins", "Domain Admins")
	m.GroupSIDs = append(m.GroupSIDs, signinDomainSID+"-1300", signinDomainSID+"-1301")
	dc.mu.Unlock()
	c := env.client(t)
	var me auth.User
	if code := c.do("POST", "/api/v1/auth/login", map[string]string{"username": `HOME\mallory`, "password": "Mall0ry-Passw0rd!"}, &me); code != 200 || me.IsAdmin() {
		t.Fatalf("look-alike groups = %d %+v", code, me)
	}
	if code := c.do("GET", "/api/v1/users", nil, nil); code != 403 {
		t.Errorf("look-alike admin GET /users = %d", code)
	}

	dc.add("boss", "B0ss-Passw0rd!", "Domain Admins")
	boss := env.client(t)
	if code := boss.do("POST", "/api/v1/auth/login", map[string]string{"username": `HOME\boss`, "password": "B0ss-Passw0rd!"}, &me); code != 200 || !me.IsAdmin() {
		t.Fatalf("boss = %d %+v", code, me)
	}
	dc.mu.Lock()
	dc.lookupErr = errFake("the directory helper broke")
	dc.mu.Unlock()
	if _, err := env.db.Exec(`UPDATE users SET groups_checked_at = '2000-01-01T00:00:00.000Z' WHERE username = ?`, `HOME\boss`); err != nil {
		t.Fatal(err)
	}
	if code := boss.do("GET", "/api/v1/users", nil, nil); code != 403 {
		t.Errorf("groups unchecked for too long, GET /users = %d", code)
	}
	var raw map[string]any
	if code := boss.do("GET", "/api/v1/auth/me", nil, &raw); code != 200 || raw["role"] != "user" || !strings.Contains(raw["roleNote"].(string), "30 minutes") {
		t.Errorf("me while held back = %d %v", code, raw)
	}
	// Signing in again (the domain answers again) gives it back.
	dc.mu.Lock()
	dc.lookupErr = nil
	dc.mu.Unlock()
	if code := env.client(t).do("POST", "/api/v1/auth/login", map[string]string{"username": `HOME\boss`, "password": "B0ss-Passw0rd!"}, &me); code != 200 || !me.IsAdmin() || me.RoleNote != "" {
		t.Errorf("signed in again = %d %+v", code, me)
	}
}

type errFake string

func (e errFake) Error() string { return string(e) }

func TestDomainAdminsGroupAPI(t *testing.T) {
	env, dc := newSigninEnv(t)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)
	dc.mu.Lock()
	dc.adminsSID = ""
	dc.groups = []domain.Group{{Name: "HardyOS Admins", SID: signinDomainSID + "-1300", Members: []string{"mallory"}}}
	dc.mu.Unlock()

	// A user can't.
	dc.add("kim", "K1m-Passw0rd!x")
	kim := env.client(t)
	kim.do("POST", "/api/v1/auth/login", map[string]string{"username": `HOME\kim`, "password": "K1m-Passw0rd!x"}, nil)
	if code := kim.do("POST", "/api/v1/domain/admins-group", map[string]any{}, nil); code != 403 {
		t.Errorf("user = %d", code)
	}

	// A group with the name that HardyOS didn't make: say who's in it.
	var e ErrorResponse
	if code := admin.do("POST", "/api/v1/domain/admins-group", map[string]any{}, &e); code != 409 || e.Code != "admins_group_exists" ||
		!strings.Contains(e.Message, "mallory") {
		t.Fatalf("existing group = %d %+v", code, e)
	}
	var acc struct {
		Job struct {
			ID string `json:"id"`
		} `json:"job"`
	}
	if code := admin.do("POST", "/api/v1/domain/admins-group", map[string]any{"adopt": true}, &acc); code != 202 {
		t.Fatalf("adopt = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("adopt job: %v", j)
	}
	dc.mu.Lock()
	got := dc.adminsSID
	dc.mu.Unlock()
	if got != signinDomainSID+"-1300" {
		t.Fatalf("recorded SID = %q", got)
	}
	if code := admin.do("POST", "/api/v1/domain/admins-group", map[string]any{}, &e); code != 409 || e.Code != "admins_group_recorded" {
		t.Errorf("again = %d %+v", code, e)
	}

	// Its members (renamed or not) are administrators now.
	dc.mu.Lock()
	k := dc.accounts["kim"]
	k.Groups = append(k.Groups, "Renamed Admins")
	k.GroupSIDs = append(k.GroupSIDs, signinDomainSID+"-1300")
	dc.mu.Unlock()
	var me auth.User
	if code := env.client(t).do("POST", "/api/v1/auth/login", map[string]string{"username": `HOME\kim`, "password": "K1m-Passw0rd!x"}, &me); code != 200 || !me.IsAdmin() {
		t.Errorf("member of the recorded group = %d %+v", code, me)
	}

	// No group yet: HardyOS creates it.
	dc.mu.Lock()
	dc.adminsSID, dc.groups = "", nil
	dc.mu.Unlock()
	if code := admin.do("POST", "/api/v1/domain/admins-group", map[string]any{}, &acc); code != 202 {
		t.Fatalf("create = %d", code)
	}
	j := waitJobDone(t, admin, acc.Job.ID)
	res, _ := json.Marshal(j["result"])
	if j["state"] != "succeeded" || !strings.Contains(string(res), `"created":true`) {
		t.Fatalf("create job: %v", j)
	}

	var audit []map[string]any
	admin.do("GET", "/api/v1/audit?limit=100", nil, &audit)
	raw, _ := json.Marshal(audit)
	if strings.Count(string(raw), "domain.admins_group.create") < 3 {
		t.Errorf("audit: %s", raw)
	}
}
