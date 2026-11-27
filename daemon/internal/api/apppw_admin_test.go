package api

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/sftpauth"
)

// Users & Groups › App passwords (decision 517): administrators list and
// revoke someone's app passwords, audited with what was revoked; others
// can't; a revoked one stops working at once.
func TestAdminRevokesAppPasswords(t *testing.T) {
	e := newMFAEnv(t)
	alice := e.client(t)
	me := e.login(t, alice, "", "alice", alicePW)
	var sftpPw, mailPw AppPasswordCreated
	alice.do("POST", "/api/v1/auth/app-passwords", map[string]any{"name": "Laptop SFTP", "scopes": []string{"sftp"}, "password": alicePW}, &sftpPw)
	alice.do("POST", "/api/v1/auth/app-passwords", map[string]any{"name": "Phone mail", "scopes": []string{"mail"}, "password": alicePW}, &mailPw)
	ctx := context.Background()
	if !e.server.sftpAnswer(ctx, sftpauth.Request{Op: sftpauth.OpApp, User: `HOME\alice`, RHost: outsideIP, Password: sftpPw.Password}).OK {
		t.Fatal("app password before the revoke")
	}
	id := strconv.FormatInt(me.ID, 10)
	base := "/api/v1/users/" + id + "/app-passwords"

	kid := e.client(t)
	e.login(t, kid, "", "kid", "kidpassword1")
	if code := kid.do("GET", base, nil, nil); code != 403 {
		t.Fatalf("a user listing someone's app passwords = %d", code)
	}
	if code := kid.do("DELETE", base+"/"+strconv.FormatInt(sftpPw.AppPassword.ID, 10), nil, nil); code != 403 {
		t.Fatalf("a user revoking someone's app password = %d", code)
	}

	var list []auth.AppPassword
	if code := e.admin.do("GET", base, nil, &list); code != 200 || len(list) != 2 {
		t.Fatalf("list = %d %+v", code, list)
	}
	var got *auth.AppPassword
	for i := range list {
		if list[i].ID == sftpPw.AppPassword.ID {
			got = &list[i]
		}
	}
	if got == nil || got.Name != "Laptop SFTP" || strings.Join(got.Scopes, ",") != "sftp" || got.LastUsedAt == nil || got.LastUsedIP != outsideIP {
		t.Fatalf("listed %+v", got)
	}
	// Another account's id under alice: not found, nothing revoked.
	if code := e.admin.do("DELETE", "/api/v1/users/1/app-passwords/"+strconv.FormatInt(sftpPw.AppPassword.ID, 10), nil, nil); code != 404 {
		t.Fatalf("revoking under the wrong account = %d", code)
	}
	if code := e.admin.do("DELETE", base+"/"+strconv.FormatInt(sftpPw.AppPassword.ID, 10), nil, nil); code != 204 {
		t.Fatalf("revoke = %d", code)
	}
	if e.server.sftpAnswer(ctx, sftpauth.Request{Op: sftpauth.OpApp, User: `HOME\alice`, RHost: outsideIP, Password: sftpPw.Password}).OK {
		t.Fatal("a revoked app password still works")
	}
	// alice's open SFTP sessions end too (decision 519).
	deadline := time.Now().Add(5 * time.Second)
	for len(e.df.ended()) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := e.df.ended(); len(got) == 0 || got[0].Account != me.Principal || !got[0].Before.IsZero() {
		t.Fatalf("SFTP sessions ended: %+v", got)
	}
	e.admin.do("GET", base, nil, &list)
	if len(list) != 1 || list[0].Name != "Phone mail" {
		t.Fatalf("after the revoke %+v", list)
	}
	entries, _ := e.server.audit.List(ctx, audit.Query{Action: "auth.app_password.delete"})
	if len(entries) != 1 || entries[0].Actor != "cade" || !strings.Contains(entries[0].Detail, `"Laptop SFTP" (sftp) of `+me.Username+" by an administrator") {
		t.Fatalf("audit %+v", entries)
	}
}
