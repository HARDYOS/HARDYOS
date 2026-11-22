package api

import (
	"encoding/base32"
	"html"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// The sign-in provider's two-factor pages at sso.<base> (always outside).
func TestProviderTwoFactorPages(t *testing.T) {
	withProxyTimes(t, 0, time.Hour)
	e := newRemoteEnv(t)
	secret := e.setUp(t)
	b := e.browser(t, secret)
	// kid has no second factor: from outside, the setup page.
	_, body, _ := b.nav(t, "GET", "https://board.home.example.net/", nil)
	form := ssoForm(body)
	form.Set("username", "kid")
	form.Set("password", "kidpassword1")
	code, body := b.ssoPost(t, "/login", form)
	if code != 200 || !strings.Contains(body, `action="/login/setup"`) || !strings.Contains(body, `name="setup_code"`) {
		t.Fatalf("outside without 2FA = %d %s", code, body)
	}
	setup := ssoForm(body)
	setup.Set("setup_code", "abcd-efgh-ijkm-npqr")
	if code, body = b.ssoPost(t, "/login/setup", setup); code != 401 || !strings.Contains(body, "setup code") {
		t.Fatalf("wrong setup code = %d", code)
	}
	var users []auth.User
	e.admin.do("GET", "/api/v1/users", nil, &users)
	var sc SetupCode
	for _, u := range users {
		if u.Username == "kid" {
			e.admin.do("POST", "/api/v1/users/"+itoa(int(u.ID))+"/2fa/setup-code", nil, &sc)
		}
	}
	if sc.Code == "" {
		t.Fatal("no setup code")
	}
	setup = ssoForm(body)
	setup.Set("setup_code", sc.Code)
	code, body = b.ssoPost(t, "/login/setup", setup)
	if code != 200 || !strings.Contains(body, `<svg xmlns="http://www.w3.org/2000/svg"`) || strings.Contains(body, "<script") {
		t.Fatalf("enroll page = %d %s", code, body)
	}
	enroll := ssoForm(body)
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ReplaceAll(enroll.Get("secret"), " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	e.totp.setSecret("kid", raw)
	// A wrong code shows the page again (with the code to scan).
	enroll.Set("code", "000000")
	if code, body = b.ssoPost(t, "/login/enroll", enroll); code != 401 || !strings.Contains(body, "<svg") {
		t.Fatalf("wrong first code = %d", code)
	}
	enroll = ssoForm(body)
	enroll.Set("code", e.totp.code(t, "kid"))
	code, body = b.ssoPost(t, "/login/enroll", enroll)
	if code != 200 || strings.Count(body, "<li>") != auth.RecoveryCodeCount {
		t.Fatalf("recovery page = %d %s", code, body)
	}
	// Continue: the new (two-factor) sign-in is reused and the app opens.
	m := regexp.MustCompile(`class="btn" href="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no continue link")
	}
	code, body, _ = b.nav(t, "GET", "https://sso.home.example.net"+html.UnescapeString(m[1]), map[string]string{"Sec-Fetch-Site": "same-origin"})
	if code, body = b.follow(t, code, body); code != 200 || !strings.HasPrefix(body, "host=board.home.example.net") {
		t.Fatalf("app after enrolling = %d %.300s", code, body)
	}
	if got := auditActions(e.admin, "auth.2fa.enable"); len(got) != 2 {
		t.Fatalf("enrollment audit %v", got)
	}
	// A code page from now on, and a wrong code is refused.
	b2 := e.browser(t, secret)
	_, body, _ = b2.nav(t, "GET", "https://board.home.example.net/", nil)
	form = ssoForm(body)
	form.Set("username", "kid")
	form.Set("password", "kidpassword1")
	_, body = b2.ssoPost(t, "/login", form)
	cf := ssoForm(body)
	cf.Set("code", "999999")
	if code, body = b2.ssoPost(t, "/login/code", cf); code != 401 || !strings.Contains(body, `action="/login/code"`) {
		t.Fatalf("wrong code = %d", code)
	}
	// The form is bound to this browser: another one can't post it.
	b3 := e.browser(t, secret)
	stolen := ssoForm(body)
	stolen.Set("code", e.totp.code(t, "kid"))
	if code, _ = b3.ssoPost(t, "/login/code", stolen); code == 200 {
		t.Fatal("code form accepted from another browser")
	}
	cf = ssoForm(body)
	cf.Set("code", e.totp.code(t, "kid"))
	code, body = b2.ssoPost(t, "/login/code", cf)
	if code, body = b2.follow(t, code, body); code != 200 || !strings.HasPrefix(body, "host=board.home.example.net") {
		t.Fatalf("app with a code = %d %.300s", code, body)
	}
}
