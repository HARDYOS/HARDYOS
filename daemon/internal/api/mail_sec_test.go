package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/mail"
	"github.com/hardyos/hardyos/daemon/internal/mail/manage"
)

// Decision 302: Roundcube's own sign-in form is refused by HardyOS's
// proxies, and the gateway never passes a client's credentials to it.
func TestWebmailFormAndGatewayCredentials(t *testing.T) {
	for _, c := range []struct {
		method, target, body string
		refused              bool
	}{
		{"POST", "/?_task=login", "_task=login&_action=login&_user=a%40example.net&_pass=pw", true},
		{"POST", "/?_task=login&_action=login", "_user=a&_pass=pw", true},
		{"POST", "/?_task=mail&_action=refresh", "_remote=1", false},
		{"GET", "/?_task=login&_action=login", "", false},
	} {
		r := httptest.NewRequest(c.method, c.target, strings.NewReader(c.body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		got := webmailFilter(r) != ""
		if got != c.refused {
			t.Errorf("%s %s %q: refused %v", c.method, c.target, c.body, got)
		}
	}
	var seen http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = r.Header.Clone() }))
	defer backend.Close()
	target, _ := url.Parse(backend.URL)
	rt := &remoteRuntime{}
	for _, appID := range []string{WebmailAppID, "notes"} {
		route := rt.proxyFor(&gwRoute{appID: appID, target: target, host: "x.example.net"}, "")
		req := httptest.NewRequest("GET", "https://x.example.net/", nil)
		req.SetBasicAuth("alice@example.net", "her-password")
		route.rp.ServeHTTP(httptest.NewRecorder(), req)
		if got := seen.Get("Authorization") != ""; got == (appID == WebmailAppID) {
			t.Errorf("%s: Authorization passed = %v", appID, got)
		}
	}
}

// Calendars: never a webmail token or the notification sign-in, and a
// mailbox is deleted off the server first, then its files, the row last.
func TestMailDAVAndDeleteOrder(t *testing.T) {
	env, svc, etc := newMailEnv(t)
	admin := adminClient(t, env)
	ctx := context.Background()
	if code := admin.do("POST", "/api/v1/mail/domains", map[string]any{"name": "example.net"}, nil); code != 200 {
		t.Fatalf("add domain %d", code)
	}
	st := manage.DefaultSettings()
	st.Enabled, st.Pool, st.Hostname, st.VPSPeer, st.DefaultDomain = true, "tank", "mail.example.net", "100.90.1.2", "example.net"
	var acc JobAccepted
	if code := admin.do("PUT", "/api/v1/mail/settings", map[string]any{"settings": st}, &acc); code != 202 {
		t.Fatalf("enable %d", code)
	}
	if j := waitJob(t, admin, acc.Job.(map[string]any)["id"].(string)); j["state"] != "succeeded" {
		t.Fatalf("apply %v", j)
	}
	for _, creds := range [][2]string{{"alice@example.net", mail.WebmailTokenPrefix + "anything"}, {mail.NotifyLogin, "x"}, {"Administrator", "x"}} {
		req, _ := http.NewRequest("PROPFIND", env.srv.URL+"/dav-mail/", nil)
		req.SetBasicAuth(creds[0], creds[1])
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("%s: %d", creds[0], resp.StatusCode)
		}
	}

	mb, err := svc.Store.CreateMailbox(ctx, manage.Mailbox{Account: "gone", Address: "gone@example.net", Enabled: true, AccountState: "deleted"})
	if err != nil {
		t.Fatal(err)
	}
	pool := filepath.Join(etc, "pool")
	msg := filepath.Join(pool, "vmail", mb.Key, "Maildir", "cur", "1")
	if err := os.MkdirAll(filepath.Dir(msg), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(msg, []byte("x"), 0o644)
	if code := admin.do("DELETE", "/api/v1/mail/mailboxes/"+itoa(int(mb.ID)), map[string]string{"confirm": "gone@example.net"}, &acc); code != 202 {
		t.Fatalf("delete %d", code)
	}
	if j := waitJob(t, admin, acc.Job.(map[string]any)["id"].(string)); j["state"] != "succeeded" {
		t.Fatalf("delete job %v", j)
	}
	if _, err := os.Stat(filepath.Dir(filepath.Dir(filepath.Dir(msg)))); err == nil {
		t.Fatal("the mailbox's folder is still there")
	}
	if _, err := svc.Store.GetMailbox(ctx, mb.ID); err == nil {
		t.Fatal("the row is still there")
	}
}
