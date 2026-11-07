package mail

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/ports"
)

func internet(a string) Source { return From(netip.MustParseAddr(a), false) }

func TestThrottleNeverLocksOutTheLAN(t *testing.T) {
	th := NewThrottle()
	attacker := internet("198.51.100.66")
	lan := internet("192.168.1.20")
	if attacker.Internet == false || lan.Internet {
		t.Fatal("classification")
	}
	for i := 0; i < 10; i++ {
		th.Result("admin@example.net", attacker, false)
	}
	if v := th.Check("admin@example.net", attacker); !v.Refuse {
		t.Fatal("the attacker isn't blocked")
	}
	if v := th.Check("admin@example.net", lan); v.Refuse || v.Delay > 0 {
		t.Fatalf("the LAN is held back by an internet attack: %+v", v)
	}
	// Mistakes on the LAN are refused only while their short wait lasts:
	// at most 30 s per address, a minute per mailbox; never an hour.
	for i := 0; i < 50; i++ {
		th.Result("admin@example.net", lan, false)
	}
	v := th.Check("admin@example.net", lan)
	if !v.Refuse || v.RetryAfter > time.Minute+time.Second {
		t.Fatalf("LAN after many mistakes: %+v", v)
	}
	for _, a := range []string{"10.0.0.1", "172.17.0.2", "100.90.1.2", "fd00::1", "127.0.0.1"} {
		if !Inside(netip.MustParseAddr(a)) {
			t.Errorf("%s isn't inside", a)
		}
	}
	if Inside(attacker.Addr) {
		t.Error("an internet address counts as inside")
	}
}

// A wait is a refusal (Dovecot would only pause the guess), and failures
// from inside get a per-mailbox bucket of their own: many LAN addresses
// guessing one mailbox are slowed down, the internet's bucket untouched.
func TestThrottleWaitRefusesAndLANMailboxBucket(t *testing.T) {
	th := NewThrottle()
	user := "bob@example.net"
	// Internet: the per-mailbox wait (5 free failures, from many addresses)
	// refuses the next attempt from yet another address.
	for i := 0; i < 6; i++ {
		th.Result(user, internet("203.0.113."+string(rune('1'+i))), false)
	}
	if v := th.Check(user, internet("203.0.113.99")); !v.Refuse {
		t.Fatalf("a waiting mailbox let a sign-in through: %+v", v)
	}
	// Inside: other LAN addresses one failure each.
	th2 := NewThrottle()
	for i := 0; i < 12; i++ {
		th2.Result(user, From(netip.AddrFrom4([4]byte{10, 0, 1, byte(i)}), false), false)
	}
	if v := th2.Check(user, internet("10.0.2.1")); !v.Refuse {
		t.Fatal("rotating LAN addresses guess a mailbox freely")
	}
	if v := th2.Check(user, internet("198.51.100.1")); v.Refuse {
		t.Fatal("LAN failures spilled into the internet's bucket")
	}
	if v := th2.Check("carol@example.net", internet("10.0.2.1")); v.Refuse {
		t.Fatal("another mailbox is held back")
	}
}

func TestThrottleIPv6By64AndNames(t *testing.T) {
	th := NewThrottle()
	for i := 0; i < 10; i++ {
		// Ten different addresses in one /64, ten different (made-up) names.
		a := netip.MustParseAddr(fmt.Sprintf("2001:db8:1:2::%x", i+1))
		th.Result(fmt.Sprintf("not an address %d", i), From(a, false), false)
	}
	if v := th.Check("alice@example.net", internet("2001:db8:1:2:ffff::1")); !v.Refuse {
		t.Fatal("a /64 isn't blocked as one")
	}
	if v := th.Check("alice@example.net", internet("2001:db8:1:3::1")); v.Refuse {
		t.Fatal("the next /64 is blocked too")
	}
	if AlertKey(netip.MustParseAddr("2001:db8:1:2::1")) != "2001:db8:1::/48" || AlertKey(netip.MustParseAddr("198.51.100.7")) != "198.51.100.0/24" {
		t.Fatal("alert keys")
	}
	if SignInName("x y") || SignInName("") || !SignInName(NotifyLogin) || !SignInName("a@example.net") {
		t.Fatal("SignInName")
	}
}

// A forwarded port or the gateway makes a sign-in the internet's even when
// it claims a LAN address.
func TestForwardedSignInsAreInternet(t *testing.T) {
	for _, req := range []policyRequest{
		{Remote: "192.168.1.5", LocalPort: []byte("10993")},
		{Remote: "192.168.1.5", LocalPort: []byte(`"10465"`)},
		{Remote: "10.0.0.5", Protocol: ProxySASLService},
		{Remote: "203.0.113.5", LocalPort: []byte("993")},
	} {
		if !req.source().Internet {
			t.Errorf("%+v isn't the internet's", req)
		}
	}
	if (policyRequest{Remote: "192.168.1.5", LocalPort: []byte("993"), Protocol: "imap"}).source().Internet {
		t.Error("a LAN sign-in on 993 is the internet's")
	}
	if !From(netip.MustParseAddr("192.168.1.5"), true).Internet {
		t.Error("forced")
	}
}

func TestThrottleDAVIsSoft(t *testing.T) {
	th := NewThrottle()
	user := "alice@example.net"
	for i := 0; i < 30; i++ {
		th.ResultDAV(user, internet("203.0.113."+string(rune('1'+i%9))), false)
	}
	// From a fresh internet address: slowed down, never refused because of
	// the mailbox.
	v := th.CheckDAV(user, internet("198.51.100.200"))
	if v.Refuse || v.Delay <= 0 || v.Delay > 5*time.Second {
		t.Fatalf("calendar sign-in for a guessed mailbox: %+v", v)
	}
	// An address that guessed ten times is refused.
	for i := 0; i < 10; i++ {
		th.ResultDAV(user, internet("198.51.100.201"), false)
	}
	if !th.CheckDAV(user, internet("198.51.100.201")).Refuse {
		t.Fatal("the guessing address isn't blocked")
	}
	// Calendar failures don't touch mail apps' buckets.
	if th.Check(user, internet("198.51.100.200")).Refuse {
		t.Fatal("calendar guesses lock mail apps")
	}
}

type checker map[string]string

func (c checker) CheckLogin(_ context.Context, l, s string) error {
	if c[l] == s && s != "" {
		return nil
	}
	return ErrBadLogin
}

// unixServer serves h on a Unix socket and returns a client for it.
func unixServer(t *testing.T, h http.Handler) *http.Client {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
}

func TestAuthServer(t *testing.T) {
	secret := strings.Repeat("s", 40)
	as := &AuthServer{Secret: func() string { return secret }, Limits: NewThrottle(),
		Checker: checker{"alice@example.net": "pw1", NotifyLogin: "npw"}}
	cl := unixServer(t, as)
	post := func(path string, form url.Values, hdr map[string]string) (int, string) {
		req, _ := http.NewRequest("POST", "http://hardyd.invalid"+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	grant := func(user, pw string) url.Values {
		return url.Values{"grant_type": {"password"}, "username": {user}, "password": {pw}, "client_id": {"dovecot"}, "client_secret": {secret}}
	}
	lan := map[string]string{"X-Dovecot-Auth-Remote": "192.168.1.9:51000"}
	if code, body := post("/token", grant("Alice@example.net", "pw1"), lan); code != 200 || !strings.Contains(body, `"username":"alice@example.net"`) || !strings.Contains(body, `"active":"true"`) {
		t.Fatalf("grant %d %s", code, body)
	}
	if code, _ := post("/token", grant("alice@example.net", "nope"), lan); code != 400 {
		t.Fatalf("wrong password: %d", code)
	}
	noClient := grant("alice@example.net", "pw1")
	noClient.Set("client_secret", "guess")
	if code, _ := post("/token", noClient, lan); code != 401 {
		t.Fatalf("without the client secret: %d", code)
	}
	// Decision 302: from the webmail network, passwords never work (only
	// webmail tokens), and webmail tokens work from there only.
	webmail := map[string]string{"X-Dovecot-Auth-Remote": ports.WebmailSubnet.Addr().Next().Next().String() + ":40000"}
	if code, _ := post("/token", grant("alice@example.net", "pw1"), webmail); code != 400 {
		t.Fatalf("a password from the webmail container: %d", code)
	}
	tokChecker := checker{"alice@example.net": WebmailTokenPrefix + "abc"}
	as.Checker = tokChecker
	if code, _ := post("/token", grant("alice@example.net", WebmailTokenPrefix+"abc"), webmail); code != 200 {
		t.Fatalf("a webmail token from the webmail container: %d", code)
	}
	if code, _ := post("/token", grant("alice@example.net", WebmailTokenPrefix+"abc"), lan); code != 400 {
		t.Fatalf("a webmail token from elsewhere: %d", code)
	}
	as.Checker = checker{"alice@example.net": "pw1", NotifyLogin: "npw"}
	// The notification sign-in only from this server itself.
	if code, _ := post("/token", grant(NotifyLogin, "npw"), lan); code != 400 {
		t.Fatalf("notification sign-in from the LAN: %d", code)
	}
	if code, _ := post("/token", grant(NotifyLogin, "npw"), map[string]string{"X-Dovecot-Auth-Remote": "127.0.0.1:5000"}); code != 200 {
		t.Fatalf("notification sign-in from here: %d", code)
	}
	// Names that can't be a mailbox are refused before any check.
	if code, _ := post("/token", grant("administrator", "pw1"), lan); code != 400 {
		t.Fatalf("non-address login: %d", code)
	}

	policy := func(cmd, body string, auth bool) string {
		req, _ := http.NewRequest("POST", "http://hardyd.invalid/policy?command="+cmd, strings.NewReader(body))
		if auth {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return string(b)
	}
	if got := policy("allow", `{"login":"a@example.net","remote":"198.51.100.66"}`, false); !strings.Contains(got, "unauthorized") {
		t.Fatalf("policy without the secret: %s", got)
	}
	// Forwarded IMAP claiming a LAN address counts as the internet's.
	for i := 0; i < 10; i++ {
		policy("report", `{"login":"a@example.net","remote":"192.168.7.7","local_port":"10993","success":false,"fail_type":"credentials"}`, true)
	}
	if got := policy("allow", `{"login":"a@example.net","remote":"192.168.7.7","local_port":"10993"}`, true); !strings.Contains(got, `"status":-1`) {
		t.Fatalf("blocked forwarded address allowed: %s", got)
	}
	// The real LAN address isn't.
	if got := policy("allow", `{"login":"a@example.net","remote":"192.168.7.7","local_port":"993"}`, true); !strings.Contains(got, `"status":0`) {
		t.Fatalf("LAN blocked by forwarded failures: %s", got)
	}
	// Mail off: everything refused.
	as.Secret = func() string { return "" }
	if code, _ := post("/token", grant("alice@example.net", "pw1"), lan); code != 401 {
		t.Fatalf("grant while off: %d", code)
	}
}

func TestAuthServerUnixSocketOnly(t *testing.T) {
	as := &AuthServer{Secret: func() string { return strings.Repeat("s", 40) }, Checker: checker{}, Limits: NewThrottle()}
	srv := httptest.NewServer(as) // TCP on 127.0.0.1
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader("grant_type=password"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("the sign-in listener answered over TCP: %d", resp.StatusCode)
	}
}
