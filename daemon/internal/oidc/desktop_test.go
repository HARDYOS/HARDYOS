package oidc

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// On the desktop's host the provider reuses the desktop's session: someone
// signed in there isn't asked for a password again.
func TestDesktopSessionReused(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	ctx := context.Background()
	// alice signed in to the desktop once (her users row exists).
	signin := &auth.SignIn{Users: e.users, Domain: e.domain, Kerberos: e.domain}
	alice, err := signin.Authenticate(ctx, "alice", "pw")
	if err != nil {
		t.Fatal(err)
	}
	e.p.cfg.DesktopUser = func(r *http.Request) (*auth.User, time.Time, bool) {
		if c, err := r.Cookie(desktopCookie); err == nil && c.Value == "desk" {
			return alice, e.clock.now(), true
		}
		return nil, time.Time{}, false
	}
	_, f := confidentialClient(e, ClientSpec{})
	b := e.browser()
	// Arriving from another site without the desktop cookie: one reload
	// from here, then the form.
	req, _ := http.NewRequest(http.MethodGet, e.issuer()+"/authorize?"+authorizeQuery(f).Encode(), nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := b.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page := body(resp)
	if !strings.Contains(page, `http-equiv="refresh"`) || !strings.Contains(page, "b=1") {
		t.Fatalf("expected the reload page: %s", page)
	}
	// With the desktop's cookie the sign-in goes straight back to the app.
	u := mustURL(t, e.srv.URL)
	b.hc.Jar.SetCookies(u, []*http.Cookie{{Name: desktopCookie, Value: "desk", Path: "/"}})
	cb := e.callback(b.authorize(newFlow(f.clientID, f.secret)))
	if cb.Get("code") == "" {
		t.Fatalf("desktop session not reused: %v", cb)
	}
	if !e.sawAudit("oidc.signin success signed in to NetBird (desktop session)") {
		t.Fatalf("not audited as a desktop session: %v", e.audits)
	}
}
