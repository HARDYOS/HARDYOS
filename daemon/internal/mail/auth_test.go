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
	if !attacker.Internet || lan.Internet {
		t.Fatal("classification")
	}
	for i := 0; i < 10; i++ {
		th.Result("admin@example.net", attacker, false)
	}
	if v := th.Check("admin@example.net", attacker); !v.Refuse {
		t.Fatal("the attacker isn't blocked")
	}
	// The LAN is at most slowed down by the mailbox's soft delay.
	if v := th.Check("admin@example.net", lan); v.Refuse || v.Delay > MaxSoftDelay {
		t.Fatalf("the LAN is held back by an internet attack: %+v", v)
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

// Decision 317: inside, a device that guesses is refused for itself only;
// others (and the webmail app) only see the mailbox's soft delay.
func TestThrottleInsideIsPerSource(t *testing.T) {
	th := NewThrottle()
	user := "mom@example.net"
	guesser := internet("192.168.1.66")
	for i := 0; i < 30; i++ {
		th.Result(user, guesser, false)
	}
	if v := th.Check(user, guesser); !v.Refuse {
		t.Fatal("the guessing device isn't held back")
	}
	moms := internet("192.168.1.20")
	v := th.Check(user, moms)
	if v.Refuse || v.Delay <= 0 || v.Delay > MaxSoftDelay {
		t.Fatalf("mom's own device: %+v (want a short delay, never a refusal)", v)
	}
	webmail := From(th.WebmailAddr, false)
	if v := th.Check(user, webmail); v.Refuse || v.Delay != 0 {
		t.Fatalf("webmail held back: %+v", v)
	}
	// A webmail address claimed through the VPS gets no exemption.
	if fw := From(th.WebmailAddr, true); th.webmail(fw) {
		t.Fatal("forwarded webmail address exempt")
	}
}

// Decision 317: from the internet, a mailbox is refused per network; a
// network it signed in from successfully is exempt, so one stranger can't
// keep mom's phone out.
func TestThrottleOutsideIsPerNetwork(t *testing.T) {
	th := NewThrottle()
	user := "mom@example.net"
	phone := internet("203.0.113.40")
	th.Result(user, phone, true) // her phone signed in before
	// A stranger elsewhere guesses slowly (one address, under the address
	// block), for a long time.
	stranger := internet("198.51.100.7")
	for i := 0; i < 9; i++ {
		th.Result(user, stranger, false)
	}
	if v := th.Check(user, stranger); !v.Refuse {
		t.Fatal("the stranger's network isn't refused for the mailbox")
	}
	if v := th.Check(user, phone); v.Refuse || v.Delay != 0 {
		t.Fatalf("mom's phone network: %+v", v)
	}
	// Another of mom's networks she never used yet: delay only.
	if v := th.Check(user, internet("192.0.2.9")); v.Refuse {
		t.Fatalf("an unrelated network is refused: %+v", v)
	}
	// Networks are /24 and /48.
	if th.netKey(user, internet("198.51.100.200")) != th.netKey(user, stranger) {
		t.Fatal("/24 not grouped")
	}
	// Trust ends after 30 days.
	now := time.Now()
	th.now = func() time.Time { return now.Add(TrustFor + time.Hour) }
	if th.isTrusted(user, phone) {
		t.Fatal("trust doesn't expire")
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
// it claims a LAN address; the real local port counts, not the claimed one.
func TestForwardedSignInsAreInternet(t *testing.T) {
	for _, req := range []policyRequest{
		{Remote: "192.168.1.5", LocalPort: []byte("993"), RealLocalPort: []byte("10993")},
		{Remote: "192.168.1.5", RealLocalPort: []byte(`"10465"`)},
		{Remote: "10.0.0.5", Protocol: ProxySASLService},
		{Remote: "203.0.113.5", LocalPort: []byte("993")},
	} {
		if !req.source().Internet {
			t.Errorf("%+v isn't the internet's", req)
		}
	}
	if (policyRequest{Remote: "192.168.1.5", LocalPort: []byte("993"), RealLocalPort: []byte("993"), Protocol: "imap"}).source().Internet {
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
		th.ResultDAV(user, internet(fmt.Sprintf("203.0.%d.1", i)), false)
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
	// Dovecot asks the policy first (with the real local port), then for
	// the grant (with only the claimed address).
	allow := func(login, remote, realPort string) {
		t.Helper()
		got := policy("allow", fmt.Sprintf(`{"login":%q,"remote":%q,"local_port":"993","real_local_port":%q}`, login, remote, realPort), true)
		if strings.Contains(got, `"status":-1`) {
			t.Fatalf("policy refused %s from %s: %s", login, remote, got)
		}
	}
	grant := func(user, pw string) url.Values {
		return url.Values{"grant_type": {"password"}, "username": {user}, "password": {pw}, "client_id": {"dovecot"}, "client_secret": {secret}}
	}
	hdr := func(remote string) map[string]string {
		return map[string]string{"X-Dovecot-Auth-Remote": remote + ":40000"}
	}
	lanIP, webIP := "192.168.1.9", ports.WebmailAddr.String()

	allow("alice@example.net", lanIP, "993")
	if code, body := post("/token", grant("Alice@example.net", "pw1"), hdr(lanIP)); code != 200 || !strings.Contains(body, `"username":"alice@example.net"`) || !strings.Contains(body, `"active":"true"`) {
		t.Fatalf("grant %d %s", code, body)
	}
	if code, _ := post("/token", grant("alice@example.net", "nope"), hdr(lanIP)); code != 400 {
		t.Fatalf("wrong password: %d", code)
	}
	noClient := grant("alice@example.net", "pw1")
	noClient.Set("client_secret", "guess")
	if code, _ := post("/token", noClient, hdr(lanIP)); code != 401 {
		t.Fatalf("without the client secret: %d", code)
	}
	// Decisions 305, 317: from the webmail app, passwords never work (only
	// webmail tokens), and webmail tokens work from its address only, never
	// through the VPS.
	allow("alice@example.net", webIP, "993")
	if code, _ := post("/token", grant("alice@example.net", "pw1"), hdr(webIP)); code != 400 {
		t.Fatalf("a password from the webmail container: %d", code)
	}
	as.Checker = checker{"alice@example.net": WebmailTokenPrefix + "abc"}
	if code, _ := post("/token", grant("alice@example.net", WebmailTokenPrefix+"abc"), hdr(webIP)); code != 200 {
		t.Fatalf("a webmail token from the webmail container: %d", code)
	}
	if code, _ := post("/token", grant("alice@example.net", WebmailTokenPrefix+"abc"), hdr("172.16.253.3")); code != 400 {
		t.Fatalf("a webmail token from another address in the webmail network: %d", code)
	}
	if code, _ := post("/token", grant("alice@example.net", WebmailTokenPrefix+"abc"), hdr(lanIP)); code != 400 {
		t.Fatalf("a webmail token from elsewhere: %d", code)
	}
	// A compromised VPS claims the webmail address through 10993: refused,
	// and it stays refused even if a real webmail attempt comes in between.
	allow("alice@example.net", webIP, "10993")
	allow("alice@example.net", webIP, "993")
	if code, _ := post("/token", grant("alice@example.net", WebmailTokenPrefix+"abc"), hdr(webIP)); code != 400 {
		t.Fatalf("a forwarded webmail token: %d", code)
	}
	// Without a policy check first, it fails closed.
	if code, _ := post("/token", grant("alice@example.net", WebmailTokenPrefix+"abc"), hdr("172.16.253.2")); code != 400 {
		t.Fatalf("a token without a policy check: %d", code)
	}
	as.Checker = checker{"alice@example.net": "pw1", NotifyLogin: "npw"}
	// The notification sign-in only from this server itself, never forwarded.
	allow(NotifyLogin, lanIP, "587")
	if code, _ := post("/token", grant(NotifyLogin, "npw"), hdr(lanIP)); code != 400 {
		t.Fatalf("notification sign-in from the LAN: %d", code)
	}
	allow(NotifyLogin, "127.0.0.1", "587")
	if code, _ := post("/token", grant(NotifyLogin, "npw"), hdr("127.0.0.1")); code != 200 {
		t.Fatalf("notification sign-in from here: %d", code)
	}
	policy("allow", `{"login":"hardyos-notify","remote":"127.0.0.2","protocol":"`+ProxySASLService+`"}`, true)
	if code, _ := post("/token", grant(NotifyLogin, "npw"), hdr("127.0.0.2")); code != 400 {
		t.Fatalf("forwarded notification sign-in claiming loopback: %d", code)
	}
	// Names that can't be a mailbox are refused before any check.
	if code, _ := post("/token", grant("administrator", "pw1"), hdr(lanIP)); code != 400 {
		t.Fatalf("non-address login: %d", code)
	}

	if got := policy("allow", `{"login":"a@example.net","remote":"198.51.100.66"}`, false); !strings.Contains(got, "unauthorized") {
		t.Fatalf("policy without the secret: %s", got)
	}
	// Forwarded IMAP (real port 10993) claiming a LAN address counts as the
	// internet's.
	for i := 0; i < 10; i++ {
		policy("report", `{"login":"a@example.net","remote":"192.168.7.7","local_port":"993","real_local_port":"10993","success":false,"fail_type":"credentials"}`, true)
	}
	if got := policy("allow", `{"login":"a@example.net","remote":"192.168.7.7","local_port":"993","real_local_port":"10993"}`, true); !strings.Contains(got, `"status":-1`) {
		t.Fatalf("blocked forwarded address allowed: %s", got)
	}
	// The real LAN address isn't refused (at most delayed).
	if got := policy("allow", `{"login":"a@example.net","remote":"192.168.7.7","local_port":"993","real_local_port":"993"}`, true); strings.Contains(got, `"status":-1`) {
		t.Fatalf("LAN blocked by forwarded failures: %s", got)
	}
	// Mail off: everything refused.
	as.Secret = func() string { return "" }
	if code, _ := post("/token", grant("alice@example.net", "pw1"), hdr(lanIP)); code != 401 {
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
