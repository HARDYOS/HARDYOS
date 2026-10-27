//go:build mailintegration

// The mail server's integration test: real Postfix, Dovecot, Rspamd, Redis
// and Radicale from Debian 13, configured by Root.Apply, with hardyd's mail
// sign-in (AuthServer) in front of a fake password checker. It needs root,
// the packages installed and no other mail server running; CI runs it in a
// debian:trixie container (.github/workflows/ci.yml, job mail-integration):
//
//	go test -c -tags mailintegration -o mail.test ./internal/mail
//	sudo ./mail.test -test.v
//
// It checks what decision 230-240 promise: no open relay on any port,
// submission only with TLS and a sign-in, senders only their own
// addresses, the relay port only from the VPS, PROXY headers only from the
// VPS, internet brute force blocked without locking out the LAN, spam to
// Junk, DKIM signatures on what people send.
package mail

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

const (
	itVPS      = "10.99.0.1"
	itDomain   = "example.test"
	itHost     = "mail.example.test"
	itMailRoot = "/srv/hardyos-mail-it"
)

var itPasswords = map[string]string{
	"alice@example.test": "alice-password-1",
	"bob@example.test":   "bob-password-1",
	NotifyLogin:          "notify-password-1",
}

type fakeChecker struct{}

func (fakeChecker) CheckLogin(_ context.Context, login, secret string) error {
	if pw, ok := itPasswords[login]; ok && pw == secret {
		return nil
	}
	return ErrBadLogin
}

func itRun(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// itDaemon runs a command that leaves a daemon behind: its output goes to
// this process's stderr (a pipe would stay open as long as the daemon).
func itDaemon(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %v: %v", name, args, err)
	}
}

func startDaemons(t *testing.T) func(ctx context.Context, cfg RootConfig, res *ApplyResult) error {
	return func(ctx context.Context, cfg RootConfig, res *ApplyResult) error {
		for _, d := range []struct{ dir, owner string }{{"/run/redis-hardyos-mail", "redis"}, {"/run/rspamd", "_rspamd"}, {RedisDataDir, "redis"}} {
			_ = os.MkdirAll(d.dir, 0o750)
			itRun(t, "chown", d.owner+":", d.dir)
		}
		itDaemon(t, "runuser", "-u", "redis", "--", "redis-server", RedisConf, "--daemonize", "yes", "--supervised", "no")
		itDaemon(t, "rspamd", "-u", "_rspamd", "-g", "_rspamd")
		itDaemon(t, "dovecot")
		itDaemon(t, "postfix", "start")
		rad := exec.Command("runuser", "-u", "radicale", "--", "radicale", "--config", RadicaleConf)
		rad.Stdout, rad.Stderr = os.Stderr, os.Stderr
		if err := rad.Start(); err != nil {
			return err
		}
		t.Cleanup(func() { _ = rad.Process.Kill() })
		// Rspamd takes a moment to load its maps.
		for i := 0; i < 60; i++ {
			if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", PortRspamdMilter), time.Second); err == nil {
				c.Close()
				break
			}
			time.Sleep(time.Second)
		}
		time.Sleep(3 * time.Second)
		return nil
	}
}

func stopDaemons() {
	_ = exec.Command("postfix", "stop").Run()
	_ = exec.Command("doveadm", "stop").Run()
	_ = exec.Command("pkill", "-x", "rspamd").Run()
	_ = exec.Command("pkill", "-x", "redis-server").Run()
}

func TestMailServerIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root and the mail packages (see the comment at the top)")
	}
	// The VPS's NetBird address, on this host for the test.
	if out, err := exec.Command("ip", "addr", "add", itVPS+"/32", "dev", "lo").CombinedOutput(); err != nil && !strings.Contains(string(out), "File exists") && !strings.Contains(string(out), "already assigned") {
		t.Fatalf("adding the VPS address: %v %s", err, out)
	}
	defer exec.Command("ip", "addr", "del", itVPS+"/32", "dev", "lo").Run()
	stopDaemons()
	defer stopDaemons()

	secret := "it-secret-0123456789abcdefghijklmnopqrstuvwxyz"
	limits := NewThrottle()
	authSrv := &AuthServer{Secret: func() string { return secret }, Checker: fakeChecker{}, Limits: limits}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", DefaultAuthPort))
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("MAIL_IT_DEBUG") != "" {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			t.Logf("auth request %s %s %v %s", r.Method, r.URL, r.Header, body)
		}
		authSrv.ServeHTTP(w, r)
	})}
	go hs.Serve(ln)
	defer hs.Close()

	_ = os.RemoveAll(itMailRoot)
	if err := os.MkdirAll(itMailRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	r := &Root{
		Runner:        sysexec.Exec{},
		StateFile:     filepath.Join(t.TempDir(), "mail.json"),
		Dataset:       func(context.Context, string) (string, error) { return itMailRoot, nil },
		StartServices: startDaemons(t),
		DovecotLog:    "/var/log/dovecot-it.log",
	}
	// The real Root writes through rootfile, which wants root-owned
	// folders all the way: true in the container.
	cfg := RootConfig{
		Pool: "tank", Hostname: itHost, VPSPeer: itVPS,
		Domains: []RootDomain{{Name: itDomain, Selector: "hardyos1"}},
		Mailboxes: []RootMailbox{
			{Address: "alice@example.test", Aliases: []string{"mom@example.test"}, QuotaMB: 100},
			{Address: "bob@example.test", QuotaMB: 100},
		},
		GroupAliases:   []RootGroupAlias{{Address: "family@example.test", Targets: []string{"alice@example.test", "bob@example.test"}}},
		Postmaster:     "alice@example.test",
		SharedCalendar: true,
		NotifyFrom:     "hardyos@example.test",
	}
	ctx := context.Background()
	res, err := r.Apply(ctx, ApplyArgs{Config: cfg, Secrets: RootSecrets{AuthSecret: secret,
		DAV: map[string]string{"alice@example.test": "dav-secret-alice-0123456789abcdefgh"}}})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if res.DKIM[itDomain] == "" {
		t.Fatal("no DKIM key")
	}

	t.Run("relay port refuses everything but this server's domains", func(t *testing.T) {
		c := smtpFrom(t, itVPS, PortRelay, false)
		defer c.Close()
		mustOK(t, c.Mail("someone@sender.test"))
		mustCode(t, c.Rcpt("victim@elsewhere.test"), 554)
		mustCode(t, c.Rcpt("nobody@example.test"), 550)
		mustOK(t, c.Rcpt("alice@example.test"))
		writeMsg(t, c, "someone@sender.test", "alice@example.test", "Hello from outside", "Plain mail.")
	})
	t.Run("relay port only from the VPS", func(t *testing.T) {
		c := smtpFrom(t, "127.0.0.1", PortRelay, false)
		defer c.Close()
		_ = c.Mail("someone@sender.test")
		mustCode(t, c.Rcpt("alice@example.test"), 554)
	})
	t.Run("submission offers no sign-in before TLS", func(t *testing.T) {
		c := smtpFrom(t, "127.0.0.1", PortSubmission, false)
		defer c.Close()
		if ok, _ := c.Extension("AUTH"); ok {
			t.Fatal("AUTH offered without TLS")
		}
		mustOK(t, c.StartTLS(&tls.Config{InsecureSkipVerify: true}))
		_ = c.Mail("alice@example.test")
		mustCode(t, c.Rcpt("victim@elsewhere.test"), 554)
	})
	t.Run("signed in: own addresses only, relaying allowed", func(t *testing.T) {
		c := smtpFrom(t, "127.0.0.1", PortSubmissions, true)
		defer c.Close()
		mustOK(t, c.Auth(smtp.PlainAuth("", "alice@example.test", "alice-password-1", itHost)))
		mustOK(t, c.Mail("bob@example.test"))
		mustCode(t, c.Rcpt("bob@example.test"), 553)
		_ = c.Reset()
		mustOK(t, c.Mail("mom@example.test")) // an alias of hers
		mustOK(t, c.Rcpt("bob@example.test"))
		writeMsg(t, c, "mom@example.test", "bob@example.test", "Dinner", "At six.")
	})
	t.Run("notifications sign in and send only as their sender", func(t *testing.T) {
		c := smtpFrom(t, "127.0.0.1", PortSubmission, false)
		defer c.Close()
		mustOK(t, c.StartTLS(&tls.Config{InsecureSkipVerify: true}))
		mustOK(t, c.Auth(smtp.PlainAuth("", NotifyLogin, "notify-password-1", itHost)))
		mustOK(t, c.Mail("alice@example.test"))
		mustCode(t, c.Rcpt("bob@example.test"), 553)
		_ = c.Reset()
		mustOK(t, c.Mail("hardyos@example.test"))
		mustOK(t, c.Rcpt("bob@example.test"))
		writeMsg(t, c, "hardyos@example.test", "bob@example.test", "A disk is failing", "Replace it.")
	})
	t.Run("wrong password refused", func(t *testing.T) {
		c := smtpFrom(t, "127.0.0.1", PortSubmissions, true)
		defer c.Close()
		if err := c.Auth(smtp.PlainAuth("", "alice@example.test", "nope", itHost)); err == nil {
			t.Fatal("wrong password accepted")
		}
	})
	t.Run("IMAP sign-in", func(t *testing.T) {
		out, err := exec.Command("doveadm", "auth", "test", "-x", "service=imap", "alice@example.test", "alice-password-1").CombinedOutput()
		t.Logf("doveadm auth test: %v\n%s", err, out)
		if !imapLogin(t, "127.0.0.1", PortIMAPS, "", "alice@example.test", "alice-password-1") {
			t.Fatal("alice can't sign in")
		}
		if imapLogin(t, "127.0.0.1", PortIMAPS, "", "alice@example.test", "wrong") {
			t.Fatal("wrong password accepted")
		}
	})
	t.Run("PROXY header only from the VPS", func(t *testing.T) {
		if imapLogin(t, "127.0.0.1", PortProxyIMAPS, "203.0.113.7", "alice@example.test", "alice-password-1") {
			t.Fatal("a PROXY header from outside the VPS was believed")
		}
		if !imapLogin(t, itVPS, PortProxyIMAPS, "203.0.113.7", "alice@example.test", "alice-password-1") {
			t.Fatal("the VPS's forwarded connection doesn't work")
		}
	})
	t.Run("internet brute force is blocked, the LAN isn't", func(t *testing.T) {
		for i := 0; i < 11; i++ {
			imapLogin(t, itVPS, PortProxyIMAPS, "198.51.100.66", "bob@example.test", "guess")
		}
		if imapLogin(t, itVPS, PortProxyIMAPS, "198.51.100.66", "bob@example.test", "bob-password-1") {
			t.Fatal("the attacking address wasn't blocked")
		}
		if !imapLogin(t, "127.0.0.1", PortIMAPS, "", "bob@example.test", "bob-password-1") {
			t.Fatal("the LAN was locked out by an attack from the internet")
		}
	})
	t.Run("delivered, signed and filtered", func(t *testing.T) {
		c := smtpFrom(t, itVPS, PortRelay, false)
		mustOK(t, c.Mail("spammer@sender.test"))
		mustOK(t, c.Rcpt("family@example.test"))
		writeMsg(t, c, "spammer@sender.test", "family@example.test", "Win now",
			"YJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X")
		c.Close()
		deadline := time.Now().Add(60 * time.Second)
		for {
			inbox, _ := filepath.Glob(filepath.Join(itMailRoot, "vmail", itDomain, "alice", "Maildir", "new", "*"))
			junk, _ := filepath.Glob(filepath.Join(itMailRoot, "vmail", itDomain, "bob", "Maildir", ".Junk", "new", "*"))
			bobIn, _ := filepath.Glob(filepath.Join(itMailRoot, "vmail", itDomain, "bob", "Maildir", "new", "*"))
			if len(inbox) >= 1 && len(junk) >= 1 && len(bobIn) >= 1 {
				signed := false
				for _, f := range bobIn {
					b, _ := os.ReadFile(f)
					if strings.Contains(string(b), "DKIM-Signature:") && strings.Contains(string(b), "d=example.test") {
						signed = true
					}
				}
				if !signed {
					t.Fatal("mail alice sent isn't DKIM-signed")
				}
				return
			}
			if time.Now().After(deadline) {
				q, _ := exec.Command("postqueue", "-p").CombinedOutput()
				t.Fatalf("not delivered: inbox=%d junk=%d bob=%d\n%s", len(inbox), len(junk), len(bobIn), q)
			}
			time.Sleep(time.Second)
		}
	})
	t.Run("calendar through Radicale", func(t *testing.T) {
		req, _ := http.NewRequest("PROPFIND", fmt.Sprintf("http://127.0.0.1:%d/family/", PortRadicale), nil)
		req.SetBasicAuth("alice@example.test", "dav-secret-alice-0123456789abcdefgh")
		req.Header.Set("Depth", "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 207 {
			t.Fatalf("PROPFIND /family/: %d", resp.StatusCode)
		}
		req.SetBasicAuth("alice@example.test", "wrong")
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("wrong calendar password: %d", resp.StatusCode)
		}
	})
	_ = netip.Addr{}
}

func smtpFrom(t *testing.T, src string, port int, implicitTLS bool) *smtp.Client {
	t.Helper()
	d := net.Dialer{Timeout: 10 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	conn, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if src == itVPS {
		conn, err = d.Dial("tcp", fmt.Sprintf("%s:%d", itVPS, port))
	}
	if err != nil {
		t.Fatal(err)
	}
	if implicitTLS {
		conn = tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	}
	c, err := smtp.NewClient(conn, itHost)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Hello("client.test"); err != nil {
		t.Fatal(err)
	}
	return c
}

func mustOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustCode(t *testing.T, err error, code int) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted, want %d", code)
	}
	if !strings.HasPrefix(err.Error(), fmt.Sprint(code)) {
		t.Fatalf("got %v, want %d", err, code)
	}
}

func writeMsg(t *testing.T, c *smtp.Client, from, to, subject, body string) {
	t.Helper()
	w, err := c.Data()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(w, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%d@client.test>\r\n\r\n%s\r\n",
		from, to, subject, time.Now().Format(time.RFC1123Z), time.Now().UnixNano(), body)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// proxyV2 is a PROXY protocol v2 header for a TCP/IPv4 client.
func proxyV2(client string, dstPort int) []byte {
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	h := append([]byte{}, sig...)
	h = append(h, 0x21, 0x11, 0, 12)
	src := net.ParseIP(client).To4()
	h = append(h, src...)
	h = append(h, 127, 0, 0, 1)
	h = binary.BigEndian.AppendUint16(h, 40000)
	h = binary.BigEndian.AppendUint16(h, uint16(dstPort))
	return h
}

// imapLogin signs in over IMAPS (with a PROXY header for proxied).
func imapLogin(t *testing.T, src string, port int, proxied, user, pass string) bool {
	t.Helper()
	d := net.Dialer{Timeout: 10 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	dst := "127.0.0.1"
	if src == itVPS {
		dst = itVPS
	}
	conn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", dst, port))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	if proxied != "" {
		if _, err := conn.Write(proxyV2(proxied, port)); err != nil {
			return false
		}
	}
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	br := bufio.NewReader(tc)
	if _, err := br.ReadString('\n'); err != nil {
		return false
	}
	fmt.Fprintf(tc, "a LOGIN %q %q\r\n", user, pass)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				t.Logf("imap: %v", err)
			}
			return false
		}
		if strings.HasPrefix(line, "a ") {
			return strings.HasPrefix(line, "a OK")
		}
	}
}
