//go:build mailintegration

package mail

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// securityReview checks the fixes of the mail server's security review
// (decisions 303-316) against the real programs; run by
// TestMailServerIntegration once the server is up.
func securityReview(t *testing.T) {
	t.Run("no TCP listener between the mail programs", func(t *testing.T) {
		for _, port := range []int{5232, 11332, 11333, 11334, 44250} {
			if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
				c.Close()
				t.Errorf("something listens on 127.0.0.1:%d", port)
			}
		}
	})
	t.Run("sockets only for who needs them", func(t *testing.T) {
		type want struct {
			path  string
			group string
			mode  os.FileMode // the socket's or, for a folder, the folder's
		}
		for _, w := range []want{
			{AuthSocket, "dovecot", 0o660},
			{RspamdMilterDir, "postfix", 0o750},
			{RspamdMilterSocket, "postfix", 0o660},
			{RspamdCtlDir, VMailUser, 0o750},
			{RspamdCtlSocket, VMailUser, 0o660},
			{RadicaleSocketDir, "hardyd", 0o750},
		} {
			st, err := os.Stat(w.path)
			if err != nil {
				t.Errorf("%s: %v", w.path, err)
				continue
			}
			if st.Mode().Perm() != w.mode {
				t.Errorf("%s: mode %o, want %o", w.path, st.Mode().Perm(), w.mode)
			}
			if g := groupName(st); g != w.group {
				t.Errorf("%s: group %s, want %s", w.path, g, w.group)
			}
		}
		// Dovecot's own sockets: nothing anyone on the server may use to
		// look mailboxes up or deliver mail.
		for _, s := range []string{"lmtp", "auth-userdb"} {
			st, err := os.Stat(filepath.Join("/run/dovecot", s))
			if err != nil {
				t.Errorf("%s: %v", s, err)
				continue
			}
			if st.Mode().Perm()&0o006 != 0 {
				t.Errorf("/run/dovecot/%s is %o: anyone may use it", s, st.Mode().Perm())
			}
		}
		// Nobody else may reach Rspamd's controller (learning) or hardyd.
		if out, err := exec.Command("runuser", "-u", "nobody", "--", "/usr/bin/rspamc", "-h", RspamdCtlSocket, "stat").CombinedOutput(); err == nil {
			t.Errorf("nobody reached Rspamd's controller: %s", out)
		}
		learn := filepath.Join(DovecotDir, "sieve-pipe", "rspamd-learn")
		msg := "From: a@sender.test\r\nTo: alice@example.test\r\nSubject: x\r\n\r\nbody\r\n"
		cmd := exec.Command("runuser", "-u", VMailUser, "--", learn, "ham")
		cmd.Stdin = strings.NewReader(msg)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("the mail user can't teach Rspamd: %v %s", err, out)
		}
		cmd = exec.Command("runuser", "-u", "nobody", "--", learn, "ham")
		cmd.Stdin = strings.NewReader(msg)
		if err := cmd.Run(); err == nil {
			t.Error("nobody ran the learning script")
		}
	})
	t.Run("From header must be the sender's own", func(t *testing.T) {
		c := smtpFrom(t, "127.0.0.1", PortSubmissions, true)
		defer c.Close()
		mustOK(t, c.Auth(smtp.PlainAuth("", "alice@example.test", "alice-password-1", itHost)))
		mustOK(t, c.Mail("mom@example.test"))
		mustOK(t, c.Rcpt("bob@example.test"))
		w, err := c.Data()
		mustOK(t, err)
		fmt.Fprintf(w, "From: Bob <bob@example.test>\r\nTo: bob@example.test\r\nSubject: forged\r\nMessage-ID: <%d@x>\r\n\r\nhi\r\n", time.Now().UnixNano())
		if err := w.Close(); err == nil || !strings.HasPrefix(err.Error(), "5") {
			t.Fatalf("a forged From header was accepted: %v", err)
		}
		// Her own (an alias of hers, a group she's in) goes.
		_ = c.Reset()
		mustOK(t, c.Mail("alice@example.test"))
		mustOK(t, c.Rcpt("bob@example.test"))
		writeMsg(t, c, "family@example.test", "bob@example.test", "From the family", "Hi.")
	})
	t.Run("signed-in senders need a return address", func(t *testing.T) {
		c := smtpFrom(t, "127.0.0.1", PortSubmissions, true)
		defer c.Close()
		mustOK(t, c.Auth(smtp.PlainAuth("", "alice@example.test", "alice-password-1", itHost)))
		mustOK(t, c.Mail(""))
		if err := c.Rcpt("someone@elsewhere.test"); err == nil || !strings.HasPrefix(err.Error(), "5") {
			t.Fatalf("a null sender was accepted: %v", err)
		}
	})
	t.Run("forwarded ports are the internet's whatever the PROXY header says", func(t *testing.T) {
		const claimed = "192.168.50.50" // a LAN address in the PROXY header
		for i := 0; i < 11; i++ {
			imapLogin(t, itVPS, PortProxyIMAPS, claimed, "bob@example.test", "guess")
		}
		if imapLogin(t, itVPS, PortProxyIMAPS, claimed, "bob@example.test", "bob-password-1") {
			t.Fatal("a forwarded attacker claiming a LAN address wasn't blocked")
		}
		// The forwarded submission port, which names itself to the policy.
		for i := 0; i < 12; i++ {
			_ = proxiedSMTPAuth(t, PortProxySubms, "192.168.50.51", "bob@example.test", "guess")
		}
		if err := proxiedSMTPAuth(t, PortProxySubms, "192.168.50.51", "bob@example.test", "bob-password-1"); err == nil {
			t.Fatal("forwarded submission: the attacker isn't blocked")
		}
		// A real LAN client isn't.
		if !imapLogin(t, itLAN, PortIMAPS, "", "bob@example.test", "bob-password-1") {
			t.Fatal("the LAN was locked out")
		}
	})
	t.Run("From header tricks", func(t *testing.T) {
		send := func(headers string) error {
			c := smtpFrom(t, "127.0.0.1", PortSubmissions, true)
			defer c.Close()
			mustOK(t, c.Auth(smtp.PlainAuth("", "alice@example.test", "alice-password-1", itHost)))
			mustOK(t, c.Mail("alice@example.test"))
			mustOK(t, c.Rcpt("bob@example.test"))
			w, err := c.Data()
			mustOK(t, err)
			fmt.Fprintf(w, "%sTo: bob@example.test\r\nSubject: x\r\nMessage-ID: <%d@x>\r\n\r\nhi\r\n", headers, time.Now().UnixNano())
			return w.Close()
		}
		for name, h := range map[string]string{
			"two From headers":                    "From: alice@example.test\r\nFrom: bob@example.test\r\n",
			"another address in the display name": "From: \"bob@example.test\" <alice@example.test>\r\n",
			"an encoded display name":             "From: =?utf-8?b?Ym9iQGV4YW1wbGUudGVzdA==?= <alice@example.test>\r\n",
			"group syntax":                        "From: Friends: alice@example.test, bob@example.test;\r\n",
			"someone else's Sender":               "From: alice@example.test\r\nSender: bob@example.test\r\n",
			"someone else's Resent-From":          "From: alice@example.test\r\nResent-From: bob@example.test\r\n",
		} {
			if err := send(h); err == nil || !strings.HasPrefix(err.Error(), "5") {
				t.Errorf("%s: accepted (%v)", name, err)
			}
		}
		if err := send("From: \"Alice (mom@example.test)\" <alice@example.test>\r\nSender: mom@example.test\r\n"); err == nil {
			t.Error("a display name naming an address of hers was accepted (it shows another address)")
		}
		if err := send("From: Alice <alice@example.test>\r\nSender: mom@example.test\r\n"); err != nil {
			t.Errorf("her own Sender address: %v", err)
		}
	})
	t.Run("webmail tokens only from the webmail network, no passwords from it", func(t *testing.T) {
		if !imapLogin(t, itWebmail, PortIMAPS, "", "alice@example.test", itToken) {
			t.Fatal("webmail can't sign in with its token")
		}
		if imapLogin(t, itWebmail, PortIMAPS, "", "alice@example.test", "alice-password-1") {
			t.Fatal("a password from the webmail network was accepted")
		}
		if imapLogin(t, itLAN, PortIMAPS, "", "alice@example.test", itToken) {
			t.Fatal("a webmail token from elsewhere was accepted")
		}
	})
	t.Run("a forwarded connection claiming the webmail app or this server gets nothing", func(t *testing.T) {
		// A compromised VPS can put any address in the PROXY header; the
		// real local port gives it away (decision 317).
		if imapLogin(t, itVPS, PortProxyIMAPS, itWebmail, "alice@example.test", itToken) {
			t.Fatal("a forwarded webmail token was accepted")
		}
		if err := proxiedSMTPAuth(t, PortProxySubms, "127.0.0.1", NotifyLogin, "notify-password-1"); err == nil {
			t.Fatal("the notification sign-in was accepted through the VPS")
		}
	})
	t.Run("a full mailbox defers, it doesn't bounce", func(t *testing.T) {
		c := smtpFrom(t, itVPS, PortRelay, false)
		defer c.Close()
		// quota-status: the relay port asks Dovecot at RCPT. A message that
		// doesn't fit carol's 1 MB (and Dovecot's 10 MB grace for the last
		// one) is deferred there: it waits on the VPS, nothing bounces.
		if err := c.Text.PrintfLine("MAIL FROM:<someone@sender.test> SIZE=30000000"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Text.ReadResponse(250); err != nil {
			t.Fatal(err)
		}
		err := c.Rcpt("carol@example.test")
		if err == nil || !strings.HasPrefix(err.Error(), "452") {
			t.Fatalf("RCPT for a mailbox too small: %v", err)
		}
		// Within the quota it goes ahead.
		_ = c.Reset()
		if err := c.Text.PrintfLine("MAIL FROM:<someone@sender.test> SIZE=2000"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Text.ReadResponse(250); err != nil {
			t.Fatal(err)
		}
		mustOK(t, c.Rcpt("carol@example.test"))
	})
	t.Run("no bounces to the internet", func(t *testing.T) {
		main, _ := exec.Command("postconf", "-h", "sender_dependent_default_transport_maps").Output()
		if !strings.Contains(string(main), "bounce_transport") {
			t.Fatal("bounce transport not configured")
		}
		out, err := exec.Command("postmap", "-q", "<>", "texthash:"+filepath.Join(PostfixMapsDir, "bounce_transport")).Output()
		if err != nil || strings.TrimSpace(string(out)) != BounceTransport {
			t.Fatalf("null sender transport: %v %q", err, out)
		}
		// A bounce for someone outside fails here, and the postmaster
		// (alice) gets a copy instead of it leaving through SES.
		before, _ := filepath.Glob(filepath.Join(itMailRoot, "vmail", itKeyAlice, "Maildir", "new", "*"))
		cmd := exec.Command("/usr/sbin/sendmail", "-f", "<>", "forged-sender@elsewhere.test")
		cmd.Stdin = strings.NewReader("From: MAILER-DAEMON@" + itHost + "\r\nTo: forged-sender@elsewhere.test\r\nSubject: Undelivered Mail Returned to Sender\r\n\r\nbounce\r\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sendmail: %v %s", err, out)
		}
		_, _ = exec.Command("postqueue", "-f").CombinedOutput()
		deadline := time.Now().Add(60 * time.Second)
		for {
			after, _ := filepath.Glob(filepath.Join(itMailRoot, "vmail", itKeyAlice, "Maildir", "new", "*"))
			if len(after) > len(before) {
				break
			}
			if time.Now().After(deadline) {
				q, _ := exec.Command("postqueue", "-p").CombinedOutput()
				t.Fatalf("the postmaster got no copy of the failed bounce\n%s", q)
			}
			time.Sleep(time.Second)
		}
	})
}

func groupName(st os.FileInfo) string {
	gid := st.Sys().(*syscall.Stat_t).Gid
	out, err := exec.Command("getent", "group", fmt.Sprint(gid)).Output()
	if err != nil {
		return fmt.Sprint(gid)
	}
	return strings.SplitN(string(out), ":", 2)[0]
}

// proxiedSMTPAuth signs in on a forwarded submission port (implicit TLS)
// with a PROXY header naming client.
func proxiedSMTPAuth(t *testing.T, port int, client, user, pass string) error {
	t.Helper()
	d := net.Dialer{Timeout: 10 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(itVPS)}}
	conn, err := d.Dial("tcp", net.JoinHostPort(itVPS, fmt.Sprint(port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	// As HAProxy sends it: the VPS's own port (465), not the forwarded one.
	if _, err := conn.Write(proxyV2(client, PortSubmissions)); err != nil {
		return err
	}
	tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	c, err := smtp.NewClient(tc, itHost)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello("client.test"); err != nil {
		return err
	}
	return c.Auth(smtp.PlainAuth("", user, pass, itHost))
}
