package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/photos"
)

// Per-app hosts follow the desktop session's two-factor gate: an
// administrator who must set up two-factor sign-in gets no app-host
// session, and one already made ends at its next request.
func TestHostBindFollowsTwoFactorGate(t *testing.T) {
	withProxyTimes(t, 0, time.Hour)
	e := newHostsEnv(t)
	e.activate()
	admin := e.browser(false)
	admin.req("POST", desk+"/api/v1/auth/login", map[string]string{"username": "cade", "password": "supersecret1"})
	open := func() (*http.Response, string) {
		r, _ := admin.req("GET", "https://photos.home.example.net/x", nil)
		loc, _ := url.Parse(r.Header.Get("Location"))
		return admin.req("GET", loc.String(), nil)
	}
	// In the grace period: the bind hands out a code, the app host a session.
	r, _ := open()
	cb, _ := url.Parse(r.Header.Get("Location"))
	if r.StatusCode != http.StatusSeeOther || cb.Path != hostCallback {
		t.Fatalf("bind in the grace period = %d %s", r.StatusCode, cb)
	}
	if r, _ := admin.req("GET", cb.String(), nil); r.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback = %d", r.StatusCode)
	}
	if r, _ := admin.req("GET", "https://photos.home.example.net/x", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("app with a host session = %d", r.StatusCode)
	}
	// The grace period is over.
	if _, err := e.db.Exec(`UPDATE user_totp SET grace_until = '2000-01-01T00:00:00.000Z' WHERE user_id = (SELECT id FROM users WHERE username = 'cade')`); err != nil {
		t.Fatal(err)
	}
	if r, body := admin.req("GET", "https://photos.home.example.net/x", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("host session after the grace period = %d %s", r.StatusCode, body)
	}
	_, body := open()
	if !strings.Contains(body, "Set up two-factor sign-in first") {
		t.Fatalf("bind after the grace period: %.200s", body)
	}
	_ = photos.AppID
}
