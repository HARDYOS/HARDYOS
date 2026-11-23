package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// relayedForTest marks r as a request another member relayed (what
// relayHandler adds after verifying it).
func relayedForTest(r *http.Request) *http.Request {
	rr := &relayedRequest{rel: &cluster.Relayed{Assertion: &cluster.Assertion{Proto: "https"}}, self: "c1"}
	return r.WithContext(context.WithValue(r.Context(), relayedKey{}, rr))
}

// A relayed request carries the entry node's Host, such as its desktop's
// hostname under the same base; it reaches this server's API, never one
// of this server's host routes (decision 474).
func TestRelayedRequestsSkipHostRouting(t *testing.T) {
	e := newHostsEnv(t)
	e.activate()
	serve := func(r *http.Request) (int, string) {
		w := httptest.NewRecorder()
		e.server.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	// The entry node's desktop is c9.home.example.net; this one's is nas.
	r := httptest.NewRequest("GET", "https://c9.home.example.net/api/v1/health", nil)
	if code, body := serve(r); code != 404 || !strings.Contains(body, "No HardyOS app") {
		t.Fatalf("a browser at another name: %d %s", code, body)
	}
	if code, body := serve(relayedForTest(httptest.NewRequest("GET", "https://c9.home.example.net/api/v1/health", nil))); code != 200 || !strings.Contains(body, "ok") {
		t.Fatalf("relayed with the entry's Host: %d %s", code, body)
	}
	// Even a name this server routes to an app.
	if code, body := serve(relayedForTest(httptest.NewRequest("GET", "https://photos.home.example.net/api/v1/health", nil))); code != 200 || strings.Contains(body, "app:") {
		t.Fatalf("relayed with an app's Host: %d %s", code, body)
	}
}

// Over the cluster port the address is the relaying member's, so a
// relayed request is never "home" for two-factor sign-in (decision 475).
func TestRelayedRequestsAreNeverHome(t *testing.T) {
	e := newHostsEnv(t)
	s := e.server
	s.inside.lanFor = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")} }
	s.inside.at = time.Time{}
	r := httptest.NewRequest("GET", "https://nas.home.example.net/api/v1/vms", nil)
	r.RemoteAddr = "192.168.1.21:44500"
	if s.outside(r) || s.notHome(r) {
		t.Fatal("a LAN address isn't home")
	}
	if rr := relayedForTest(r); !s.outside(rr) || !s.notHome(rr) {
		t.Fatal("a relayed request counted as home by the member's address")
	}
}

// A relayed WebSocket (a VM console, the merged events) ends once the
// entry node's two-factor rules no longer let the session be used, such
// as an administrator's grace period ending (decision 475); a new
// relayed request is refused at the entry.
func TestRelayEndsWhenTheEntryGateCloses(t *testing.T) {
	nas, _ := twoNodeCluster(t)
	cade := nas.env.client(t)
	if code := cade.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil); code != 201 {
		t.Fatalf("setup = %d", code)
	}
	if code := cade.do("GET", "/api/v1/nodes/c1/jobs", nil, nil); code != 200 {
		t.Fatalf("relayed = %d", code)
	}
	base, _ := url.Parse(nas.env.srv.URL)
	token := ""
	for _, ck := range cade.http.Jar.Cookies(base) {
		if strings.Contains(ck.Name, "hardyos_session") {
			token = ck.Value
		}
	}
	if token == "" {
		t.Fatal("no session cookie")
	}
	ctx := context.Background()
	s := nas.s
	s.inside.lanFor = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")} }
	s.inside.at = time.Time{}
	info, err := s.peekSession(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.users.Get(ctx, info.UserID)
	if err != nil {
		t.Fatal(err)
	}
	c := nas.api.c
	p, err := c.principal(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/nodes/c1/events", nil)
	r.RemoteAddr = "192.168.1.50:5000"
	if !c.samePerson(r, token, u, p) {
		t.Fatal("the session should still be good")
	}
	if _, err := nas.env.db.ExecContext(ctx, `UPDATE user_totp SET grace_until = ? WHERE user_id = ?`,
		store.FormatTime(time.Now().Add(-time.Hour)), u.ID); err != nil {
		t.Fatal(err)
	}
	if c.samePerson(r, token, u, p) {
		t.Fatal("a relay outlived the end of the grace period")
	}
	var e ErrorResponse
	if code := cade.do("GET", "/api/v1/nodes/c1/jobs", nil, &e); code != 403 || e.Code != "mfa_enrollment_required" {
		t.Fatalf("relayed after the grace period = %d %+v", code, e)
	}
}
