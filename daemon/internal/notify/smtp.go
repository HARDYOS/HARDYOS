package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// Email goes out over SMTP to any server: Gmail or Google Workspace
// (smtp.gmail.com:587 with an app password), Amazon SES's SMTP interface
// (email-smtp.<region>.amazonaws.com:587 with SES SMTP credentials), a
// provider's relay, or later the family's own mail server (phase 7) on
// this machine or the LAN. Unlike webhooks, the server may be local: the
// administrator chose it, and a mail server on the LAN is the point.
//
// Encryption: "starttls" requires the server to offer STARTTLS (never a
// silent fallback to plain text); "tls" is TLS from the first byte (465);
// "none" sends in the clear and is meant for a mail server on this machine
// or its network, and even then a password is only sent over TLS or to
// this machine (net/smtp's PLAIN rule, which LOGIN follows too).

// What a mail server may send: 64 KiB per answer (reset whenever HardyOS
// sends a command) and 1 MiB for the whole conversation. A hostile or
// broken server can't make hardyd buffer more.
const (
	smtpAnswerMax = 64 << 10
	smtpTotalMax  = 1 << 20
)

var errSMTPTooMuch = errors.New("the mail server sent more than any SMTP answer needs")

// limitedConn caps what's read from a mail server.
type limitedConn struct {
	net.Conn
	answer, total int64
}

func newLimitedConn(c net.Conn) *limitedConn {
	return &limitedConn{Conn: c, answer: smtpAnswerMax, total: smtpTotalMax}
}

func (c *limitedConn) Read(p []byte) (int, error) {
	if c.answer <= 0 || c.total <= 0 {
		return 0, errSMTPTooMuch
	}
	if int64(len(p)) > c.answer {
		p = p[:c.answer]
	}
	if int64(len(p)) > c.total {
		p = p[:c.total]
	}
	n, err := c.Conn.Read(p)
	c.answer -= int64(n)
	c.total -= int64(n)
	return n, err
}

func (c *limitedConn) Write(p []byte) (int, error) {
	c.answer = smtpAnswerMax
	return c.Conn.Write(p)
}

// SMTPPorts are the ports an email channel may use without AllowAnyPort.
var SMTPPorts = map[int]bool{25: true, 465: true, 587: true, 2525: true}

// loginAuth is the LOGIN mechanism (Microsoft 365 and some relays offer
// only it).
type loginAuth struct {
	user, pass, host string
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS && !isLocalName(server.Name) {
		return "", nil, errors.New("refusing to send the password over an unencrypted connection")
	}
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(fromServer))) {
	case "username:", "user name", "username":
		return []byte(a.user), nil
	case "password:", "password":
		return []byte(a.pass), nil
	}
	return nil, fmt.Errorf("unexpected server challenge %q", fromServer)
}

func isLocalName(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
}

// buildEmail renders the message (multipart text + HTML) with headers that
// can't be broken by what an event says.
func buildEmail(from string, to []string, m message, now time.Time) ([]byte, error) {
	var buf bytes.Buffer
	fromAddr := mail.Address{Name: "HardyOS (" + oneLine(m.Server) + ")", Address: from}
	var tos []string
	for _, t := range to {
		tos = append(tos, (&mail.Address{Address: t}).String())
	}
	idb := make([]byte, 12)
	_, _ = rand.Read(idb)
	domain := "hardyos.local"
	if at := strings.LastIndexByte(from, '@'); at >= 0 {
		domain = from[at+1:]
	}
	mw := multipart.NewWriter(nil)
	boundary := mw.Boundary()
	h := []string{
		"From: " + fromAddr.String(),
		"To: " + strings.Join(tos, ", "),
		"Subject: " + mime.QEncoding.Encode("utf-8", m.subject()),
		"Date: " + now.Format(time.RFC1123Z),
		"Message-ID: <" + hex.EncodeToString(idb) + "@" + domain + ">",
		"MIME-Version: 1.0",
		"Auto-Submitted: auto-generated",
		"X-HardyOS-Kind: " + m.Kind,
		"X-HardyOS-Severity: " + m.Severity,
		`Content-Type: multipart/alternative; boundary="` + boundary + `"`,
	}
	for _, line := range h {
		if strings.ContainsAny(line, "\r\n") {
			return nil, errors.New("invalid header")
		}
		buf.WriteString(line + "\r\n")
	}
	buf.WriteString("\r\n")
	w := multipart.NewWriter(&buf)
	if err := w.SetBoundary(boundary); err != nil {
		return nil, err
	}
	for _, part := range []struct{ ctype, body string }{{"text/plain", textBody(m)}, {"text/html", htmlBody(m)}} {
		pw, err := w.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.ctype + "; charset=utf-8"},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		qp := quotedprintable.NewWriter(pw)
		if _, err := qp.Write([]byte(strings.ReplaceAll(part.body, "\n", "\r\n"))); err != nil {
			return nil, err
		}
		if err := qp.Close(); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// smtpError turns a server's answer into a sendError: 4xx and network
// trouble are retried, 5xx are not.
func smtpError(step string, err error) error {
	var te *textproto.Error
	if errors.As(err, &te) {
		msg := fmt.Sprintf("%s: the mail server answered %d %s", step, te.Code, oneLine(te.Msg))
		if te.Code == 535 || te.Code == 534 {
			msg += " (check the user name and password; Gmail needs an app password)"
		}
		return &sendError{Msg: clip(msg, 400), Temporary: te.Code >= 400 && te.Code < 500}
	}
	var ne net.Error
	if errors.As(err, &ne) || errors.Is(err, context.DeadlineExceeded) {
		return &sendError{Msg: step + ": " + err.Error(), Temporary: true}
	}
	return &sendError{Msg: step + ": " + err.Error()}
}

func (d *Dispatcher) sendSMTP(ctx context.Context, ch *channelRow, m message) error {
	cfg := ch.Config
	msg, err := buildEmail(cfg.From, cfg.To, m, d.now())
	if err != nil {
		return &sendError{Msg: err.Error()}
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	if d.smtpTLS != nil {
		tlsCfg = d.smtpTLS.Clone()
		tlsCfg.ServerName = cfg.Host
	}
	if isLocalName(cfg.Host) && d.LoopbackTLS != nil {
		if c := d.LoopbackTLS(ctx); c != nil {
			tlsCfg = c
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if !SMTPPorts[cfg.Port] && !cfg.AllowAnyPort {
		return &sendError{Msg: fmt.Sprintf("port %d isn't a mail port (25, 465, 587, 2525)", cfg.Port)}
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return smtpError("connecting to "+addr, err)
	}
	var conn net.Conn = newLimitedConn(raw)
	if cfg.Security == SecurityTLS {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return smtpError("TLS with "+addr, err)
		}
		conn = tc
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		// Whatever answered isn't speaking SMTP; don't repeat what it said.
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return &sendError{Msg: addr + " didn't greet like a mail server (timed out)", Temporary: true}
		}
		return &sendError{Msg: addr + " isn't an SMTP server (no SMTP greeting)"}
	}
	defer c.Close()
	helo, _ := osHostname()
	if err := c.Hello(helo); err != nil {
		return smtpError("EHLO", err)
	}
	if cfg.Security == "" || cfg.Security == SecuritySTARTTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return &sendError{Msg: "the mail server doesn't offer STARTTLS; choose TLS (port 465) or check the port"}
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return smtpError("STARTTLS", err)
		}
	}
	if cfg.Username != "" {
		ok, mechs := c.Extension("AUTH")
		if !ok {
			return &sendError{Msg: "the mail server doesn't accept sign-in (AUTH); clear the user name or check the port"}
		}
		var a smtp.Auth
		switch {
		case strings.Contains(" "+strings.ToUpper(mechs)+" ", " PLAIN "):
			a = smtp.PlainAuth("", cfg.Username, ch.secrets.Password, cfg.Host)
		case strings.Contains(" "+strings.ToUpper(mechs)+" ", " LOGIN "):
			a = &loginAuth{user: cfg.Username, pass: ch.secrets.Password, host: cfg.Host}
		default:
			return &sendError{Msg: "the mail server offers no sign-in method HardyOS supports (PLAIN or LOGIN): " + mechs}
		}
		if err := c.Auth(a); err != nil {
			return smtpError("signing in", err)
		}
	}
	if err := c.Mail(cfg.From); err != nil {
		return smtpError("MAIL FROM", err)
	}
	for _, t := range cfg.To {
		if err := c.Rcpt(t); err != nil {
			return smtpError("RCPT TO "+t, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return smtpError("DATA", err)
	}
	if _, err := w.Write(msg); err != nil {
		return smtpError("sending the message", err)
	}
	if err := w.Close(); err != nil {
		return smtpError("sending the message", err)
	}
	_ = c.Quit()
	return nil
}
