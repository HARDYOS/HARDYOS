package notify

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"mime"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// smtpServer is a small SMTP server for tests: EHLO, STARTTLS, AUTH PLAIN
// and LOGIN, MAIL, RCPT, DATA. It records what it received.
type smtpServer struct {
	ln        net.Listener
	tls       *tls.Config
	implicit  bool // TLS from the first byte
	starttls  bool // offer STARTTLS
	mechs     string
	user, pw  string
	mu        sync.Mutex
	authed    string
	from      string
	rcpt      []string
	data      string
	sawTLS    bool
	authPlain bool // AUTH arrived over a plain connection
}

func selfSigned(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

func newSMTPServer(t *testing.T, implicit, starttls bool) (*smtpServer, *x509.CertPool) {
	t.Helper()
	cfg, pool := selfSigned(t)
	var ln net.Listener
	var err error
	if implicit {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", cfg)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpServer{ln: ln, tls: cfg, implicit: implicit, starttls: starttls, mechs: "PLAIN LOGIN", user: "cade@gmail.com", pw: "app password"}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s, pool
}

func (s *smtpServer) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *smtpServer) serve(c net.Conn) {
	defer c.Close()
	secure := s.implicit
	r, w := bufio.NewReader(c), bufio.NewWriter(c)
	say := func(line string) { w.WriteString(line + "\r\n"); w.Flush() }
	say("220 test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(strings.SplitN(line, " ", 2)[0])
		switch cmd {
		case "EHLO":
			w.WriteString("250-test\r\n")
			if s.starttls && !secure {
				w.WriteString("250-STARTTLS\r\n")
			}
			say("250 AUTH " + s.mechs)
		case "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, s.tls)
			if tc.Handshake() != nil {
				return
			}
			c, secure = tc, true
			r, w = bufio.NewReader(c), bufio.NewWriter(c)
			s.mu.Lock()
			s.sawTLS = true
			s.mu.Unlock()
		case "AUTH":
			f := strings.Fields(line)
			s.mu.Lock()
			s.authPlain = s.authPlain || !secure
			s.mu.Unlock()
			var user, pw string
			if strings.ToUpper(f[1]) == "PLAIN" {
				var raw string
				if len(f) > 2 {
					raw = f[2]
				} else {
					say("334 ")
					raw, _ = r.ReadString('\n')
				}
				b, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
				parts := strings.Split(string(b), "\x00")
				if len(parts) == 3 {
					user, pw = parts[1], parts[2]
				}
			} else {
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
				u, _ := r.ReadString('\n')
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
				p, _ := r.ReadString('\n')
				ub, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(u))
				pb, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(p))
				user, pw = string(ub), string(pb)
			}
			if user == s.user && pw == s.pw {
				s.mu.Lock()
				s.authed = user
				s.mu.Unlock()
				say("235 ok")
			} else {
				say("535 5.7.8 Username and Password not accepted")
			}
		case "MAIL":
			s.mu.Lock()
			s.from = line
			s.mu.Unlock()
			say("250 ok")
		case "RCPT":
			s.mu.Lock()
			s.rcpt = append(s.rcpt, line)
			s.mu.Unlock()
			say("250 ok")
		case "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			s.mu.Lock()
			s.data = b.String()
			s.mu.Unlock()
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func smtpChannel(port int, security string, user, pw string) *channelRow {
	return &channelRow{Channel: Channel{Type: TypeSMTP, Config: ChannelConfig{Host: "localhost", Port: port, Security: security, Username: user,
		From: "nas@example.com", To: []string{"cade@example.com", "wife@example.com"}}}, secrets: Secrets{Password: pw}}
}

func testMessage() message {
	return message{Event: Event{Kind: "ups.power", Severity: SeverityWarning, Title: "UPS on battery — 92%", Body: "Power went out at 21:04.\nRuntime 41 minutes.", Link: "ups", Time: time.Now()}.normalize(),
		Server: "nas", ServerURL: "https://nas.example.com"}
}

func TestSMTPStartTLS(t *testing.T) {
	srv, pool := newSMTPServer(t, false, true)
	d, _ := newTestDispatcher(t)
	d.smtpTLS = &tls.Config{RootCAs: pool}
	if err := d.sendSMTP(t.Context(), smtpChannel(srv.port(), SecuritySTARTTLS, "cade@gmail.com", "app password"), testMessage()); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !srv.sawTLS || srv.authPlain || srv.authed != "cade@gmail.com" || len(srv.rcpt) != 2 {
		t.Fatalf("tls=%v authPlain=%v authed=%q rcpt=%v", srv.sawTLS, srv.authPlain, srv.authed, srv.rcpt)
	}
	msg, err := mail.ReadMessage(strings.NewReader(srv.data))
	if err != nil {
		t.Fatal(err)
	}
	subj, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if subj != "[nas] Warning: UPS on battery — 92%" {
		t.Errorf("subject %q", subj)
	}
	if !strings.Contains(msg.Header.Get("Content-Type"), "multipart/alternative") || msg.Header.Get("Auto-Submitted") != "auto-generated" {
		t.Errorf("headers %v", msg.Header)
	}
	if !strings.Contains(srv.data, "Runtime 41 minutes.") || !strings.Contains(srv.data, "https://nas.example.com/#open=3Dups") {
		t.Errorf("body:\n%s", srv.data)
	}
}

func TestSMTPImplicitTLSAndLogin(t *testing.T) {
	srv, pool := newSMTPServer(t, true, false)
	srv.mechs = "LOGIN"
	d, _ := newTestDispatcher(t)
	d.smtpTLS = &tls.Config{RootCAs: pool}
	if err := d.sendSMTP(t.Context(), smtpChannel(srv.port(), SecurityTLS, "cade@gmail.com", "app password"), testMessage()); err != nil {
		t.Fatal(err)
	}
	if srv.authed == "" {
		t.Error("LOGIN didn't authenticate")
	}
}

func TestSMTPRefusals(t *testing.T) {
	// STARTTLS required but not offered: never fall back to plain text.
	srv, pool := newSMTPServer(t, false, false)
	d, _ := newTestDispatcher(t)
	d.smtpTLS = &tls.Config{RootCAs: pool}
	err := d.sendSMTP(t.Context(), smtpChannel(srv.port(), SecuritySTARTTLS, "cade@gmail.com", "app password"), testMessage())
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("want a STARTTLS error, got %v", err)
	}
	// Wrong password: a clear, permanent error.
	srv2, pool2 := newSMTPServer(t, false, true)
	d.smtpTLS = &tls.Config{RootCAs: pool2}
	err = d.sendSMTP(t.Context(), smtpChannel(srv2.port(), SecuritySTARTTLS, "cade@gmail.com", "wrong"), testMessage())
	if err == nil || temporary(err) || !strings.Contains(err.Error(), "app password") {
		t.Fatalf("want a permanent auth error, got %v", err)
	}
	// A certificate the server can't prove: refused.
	d.smtpTLS = nil
	err = d.sendSMTP(t.Context(), smtpChannel(srv2.port(), SecuritySTARTTLS, "", ""), testMessage())
	if err == nil {
		t.Fatal("an untrusted certificate was accepted")
	}
	// No encryption, no password: fine for a local mail server.
	srv3, _ := newSMTPServer(t, false, false)
	if err := d.sendSMTP(t.Context(), smtpChannel(srv3.port(), SecurityNone, "", ""), testMessage()); err != nil {
		t.Fatalf("plain local relay: %v", err)
	}
}

func TestBuildEmailHeaderSafety(t *testing.T) {
	m := testMessage()
	m.Title = "evil\r\nBcc: attacker@example.com"
	m = message{Event: m.Event.normalize(), Server: "nas\r\nX: y"}
	b, err := buildEmail("nas@example.com", []string{"a@example.com"}, m, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	head, _, _ := strings.Cut(string(b), "\r\n\r\n")
	if strings.Contains(head, "\r\nBcc:") || strings.Contains(head, "\r\nX: y") {
		t.Errorf("header injection:\n%s", head)
	}
	if !strings.Contains(strconv.Quote(head), "Subject:") {
		t.Error("no subject")
	}
}
