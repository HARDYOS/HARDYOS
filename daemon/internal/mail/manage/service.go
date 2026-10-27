package manage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/hardyos/hardyos/daemon/internal/mail"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/hardyos/hardyos/daemon/internal/notify"
	"golang.org/x/text/unicode/norm"
)

// Caller is hardyd-priv's client (priv.Client).
type Caller interface {
	Call(ctx context.Context, op string, args, out any) error
}

// DirUser is a domain account as mail needs it.
type DirUser struct {
	Username    string
	GivenName   string
	DisplayName string
	Enabled     bool
	Builtin     bool
}

// Directory lists the domain's accounts (nil, nil without a domain).
type Directory interface {
	Users(ctx context.Context) ([]DirUser, error)
}

// Passwords checks a domain account's password the way desktop sign-in
// does (this server's own domain controller only).
type Passwords interface {
	CheckDomainPassword(ctx context.Context, account, password string) error
}

// WebmailPrefix starts every webmail token (so a password can never be
// mistaken for one).
const WebmailPrefix = "hwm1."

// webmailTTL bounds a webmail token even while its window stays open.
const webmailTTL = 12 * time.Hour

// Service is the mail server's hardyd side.
type Service struct {
	Store     *Store
	Priv      Caller
	Notify    notify.Notifier
	Dir       Directory
	Passwords Passwords
	// NetBirdAddr is this server's NetBird address ("" when not on
	// NetBird).
	NetBirdAddr func(ctx context.Context) string
	Resolver    mail.Resolver
	Log         *slog.Logger
	Throttle    *mail.Throttle
	// SessionAlive says whether a Mail app window session (the window
	// proxy's) is still signed in: a webmail token lasts as long.
	SessionAlive func(key string) bool
	// Submit queues a job (jobs.Manager.Submit without a user).
	Submit func(ctx context.Context, kind, title string, params any) error
	// Channels gets the "HardyOS Mail" notification channel (nil: none).
	Channels *notify.Channels

	mu       sync.Mutex
	webmail  map[string]webmailGrant // token hash -> grant
	conds    map[string]string       // alert key -> last body
	certPin  []byte                  // the server's leaf (DER), for LoopbackTLS
	certTime time.Time
}

type webmailGrant struct {
	mailbox int64
	session string
	expires time.Time
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// ---- sign-in ----

// AuthSecret is the secret Dovecot proves itself with ("" while mail is
// off).
func (s *Service) AuthSecret(ctx context.Context) string {
	st, err := s.Store.LoadSettings(ctx)
	if err != nil || !st.Enabled {
		return ""
	}
	v, _ := s.Store.Secret(ctx, SecretAuth)
	return v
}

// CheckLogin implements Checker.
func (s *Service) CheckLogin(ctx context.Context, login, secret string) error {
	if login == mail.NotifyLogin {
		want, err := s.Store.Secret(ctx, SecretNotify)
		st, _ := s.Store.LoadSettings(ctx)
		if err != nil || want == "" || st.NotifyFrom == "" {
			return mail.ErrBadLogin
		}
		a, b := sha256.Sum256([]byte(secret)), sha256.Sum256([]byte(want))
		if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
			return mail.ErrBadLogin
		}
		return nil
	}
	m, err := s.Store.MailboxByAddress(ctx, login)
	if errors.Is(err, ErrNotFound) {
		return mail.ErrBadLogin
	}
	if err != nil {
		return err
	}
	if !m.CanSignIn() {
		return fmt.Errorf("%w (mailbox turned off or account %s)", mail.ErrBadLogin, m.AccountState)
	}
	if strings.HasPrefix(secret, WebmailPrefix) {
		if s.checkWebmail(m.ID, secret) {
			return nil
		}
		return mail.ErrBadLogin
	}
	if s.Passwords == nil {
		return mail.ErrBadLogin
	}
	if err := s.Passwords.CheckDomainPassword(ctx, m.Account, secret); err != nil {
		return fmt.Errorf("%w: %v", mail.ErrBadLogin, err)
	}
	return nil
}

func tokenHash(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// WebmailLogin gives the Mail app's window session (key) the address and
// a token to sign in to IMAP and SMTP with, for the account's mailbox. It
// is the same token for the whole session.
func (s *Service) WebmailLogin(ctx context.Context, account, session string) (address, token string, err error) {
	m, err := s.Store.MailboxByAccount(ctx, account)
	if err != nil {
		return "", "", err
	}
	if !m.CanSignIn() {
		return "", "", errors.New("this mailbox is turned off")
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.webmail == nil {
		s.webmail = map[string]webmailGrant{}
	}
	for k, g := range s.webmail {
		if now.After(g.expires) || (s.SessionAlive != nil && !s.SessionAlive(g.session)) {
			delete(s.webmail, k)
		}
	}
	// A token derived from the session: the same one on every request,
	// nothing to look up but its hash.
	key, err := s.Store.EnsureSecret(ctx, SecretDAV)
	if err != nil {
		return "", "", err
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte("webmail\x00" + session))
	token = WebmailPrefix + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	h := tokenHash(token)
	if g, ok := s.webmail[h]; !ok || g.mailbox != m.ID {
		s.webmail[h] = webmailGrant{mailbox: m.ID, session: session, expires: now.Add(webmailTTL)}
	}
	return m.Address, token, nil
}

func (s *Service) checkWebmail(mailbox int64, token string) bool {
	s.mu.Lock()
	g, ok := s.webmail[tokenHash(token)]
	s.mu.Unlock()
	if !ok || g.mailbox != mailbox || time.Now().After(g.expires) {
		return false
	}
	return s.SessionAlive == nil || s.SessionAlive(g.session)
}

// EndWebmail forgets a session's token (its window closed or ended).
func (s *Service) EndWebmail(session string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, g := range s.webmail {
		if g.session == session {
			delete(s.webmail, k)
		}
	}
}

// DAVPassword is the password hardyd uses with Radicale for a mailbox.
func (s *Service) DAVPassword(ctx context.Context, address string) (string, error) {
	key, err := s.Store.EnsureSecret(ctx, SecretDAV)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte("dav\x00" + address))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// ---- building root's configuration ----

// RootArgs builds what hardyd-priv's mail.apply gets.
func (s *Service) RootArgs(ctx context.Context) (*mail.ApplyArgs, error) {
	st, err := s.Store.LoadSettings(ctx)
	if err != nil {
		return nil, err
	}
	doms, err := s.Store.Domains(ctx)
	if err != nil {
		return nil, err
	}
	mbs, err := s.Store.Mailboxes(ctx)
	if err != nil {
		return nil, err
	}
	gs, err := s.Store.Groups(ctx)
	if err != nil {
		return nil, err
	}
	authSecret, err := s.Store.EnsureSecret(ctx, SecretAuth)
	if err != nil {
		return nil, err
	}
	cfg := mail.RootConfig{Pool: st.Pool, Hostname: st.Hostname, VPSPeer: st.VPSPeer, Postmaster: st.Postmaster,
		ClamAV: st.ClamAV, JunkScore: st.JunkScore, MaxMessageMB: st.MaxMessageMB, SendPerHour: st.SendPerHour,
		NotifyFrom: st.NotifyFrom, SharedCalendar: st.SharedCalendar}
	sec := mail.RootSecrets{AuthSecret: authSecret, DAV: map[string]string{}}
	for _, d := range doms {
		cfg.Domains = append(cfg.Domains, mail.RootDomain{Name: d.Name, Selector: d.Selector})
	}
	for _, m := range mbs {
		cfg.Mailboxes = append(cfg.Mailboxes, mail.RootMailbox{Address: m.Address, Aliases: m.Aliases, QuotaMB: m.QuotaMB})
		if m.CanSignIn() {
			if sec.DAV[m.Address], err = s.DAVPassword(ctx, m.Address); err != nil {
				return nil, err
			}
		}
	}
	for _, g := range gs {
		cfg.GroupAliases = append(cfg.GroupAliases, mail.RootGroupAlias{Address: g.Address, Targets: g.Targets})
	}
	if st.SESRegion != "" && st.SESAccessID != "" {
		secret, err := s.Store.Secret(ctx, SecretSES)
		if err != nil {
			return nil, err
		}
		if secret != "" {
			cfg.SES = &mail.RootSES{Host: SESSMTPHost(st.SESRegion), Port: 587, Username: st.SESAccessID}
			sec.SESPassword = SESSMTPPassword(secret, st.SESRegion)
		}
	}
	return &mail.ApplyArgs{Config: cfg, Secrets: sec}, nil
}

// Apply renders and starts the mail server through hardyd-priv (the
// mail.apply job's work).
func (s *Service) Apply(ctx context.Context, progress func(float64, string)) (*mail.ApplyResult, error) {
	args, err := s.RootArgs(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := args.Config.Normalize(args.Secrets); err != nil {
		return nil, err
	}
	progress(30, "Writing the mail server's settings and starting it")
	var res mail.ApplyResult
	if err := s.Priv.Call(ctx, mail.OpApply, args, &res); err != nil {
		return nil, err
	}
	for _, d := range args.Config.Domains {
		if pub := res.DKIM[d.Name]; pub != "" {
			if err := s.Store.SetDKIM(ctx, d.Name, d.Selector, pub); err != nil {
				return nil, err
			}
		}
	}
	progress(80, "Ending sign-ins of turned-off mailboxes")
	mbs, _ := s.Store.Mailboxes(ctx)
	for _, m := range mbs {
		if !m.CanSignIn() {
			_ = s.Priv.Call(ctx, mail.OpKick, mail.AddressArgs{Address: m.Address}, nil)
		}
	}
	s.mu.Lock()
	s.certTime = time.Time{}
	s.mu.Unlock()
	if err := s.ensureNotifyChannel(ctx); err != nil {
		res.Warnings = append(res.Warnings, "the HardyOS Mail notification channel: "+err.Error())
	}
	return &res, nil
}

// NotifyChannelName is the notification channel that sends through this
// server.
const NotifyChannelName = "HardyOS Mail"

// ensureNotifyChannel keeps an SMTP notification channel that sends
// through this server (127.0.0.1:587, signed in as NotifyLogin) while a
// notification sender is set.
func (s *Service) ensureNotifyChannel(ctx context.Context) error {
	if s.Channels == nil {
		return nil
	}
	st, err := s.Store.LoadSettings(ctx)
	if err != nil || st.NotifyFrom == "" {
		return err
	}
	pw, err := s.NotifyPassword(ctx)
	if err != nil {
		return err
	}
	to := st.Postmaster
	if to == "" {
		to = st.NotifyFrom
	}
	in := notify.ChannelInput{Type: notify.TypeSMTP, Name: NotifyChannelName,
		Config: notify.ChannelConfig{From: st.NotifyFrom, To: []string{to}, Host: "127.0.0.1", Port: 587,
			Security: notify.SecuritySTARTTLS, Username: mail.NotifyLogin},
		Secrets: &notify.SecretsInput{Password: &pw}}
	if raw, err := s.Store.DB.GetSetting(ctx, notifyChannelKey); err == nil && raw != "" {
		var id int64
		if _, err := fmt.Sscan(raw, &id); err == nil {
			if ch, err := s.Channels.Get(ctx, id); err == nil {
				// Keep the administrator's recipients and on/off choice.
				in.Config.To = ch.Config.To
				in.Enabled = &ch.Enabled
				_, err := s.Channels.Update(ctx, id, in)
				return err
			}
		}
	}
	ch, err := s.Channels.Create(ctx, in)
	if err != nil {
		return err
	}
	return s.Store.DB.SetSetting(ctx, notifyChannelKey, fmt.Sprint(ch.ID))
}

// ---- accounts ----

// addressFor makes a mailbox address for an account.
func addressFor(u DirUser, style, domain string, used map[string]bool) string {
	base := ""
	if style != "username" {
		base = localFrom(u.GivenName)
	}
	if base == "" {
		base = localFrom(u.Username)
	}
	if base == "" {
		base = "user"
	}
	a := base + "@" + domain
	for i := 2; used[a] || base == "postmaster" || base == "abuse"; i++ {
		a = fmt.Sprintf("%s%d@%s", base, i, domain)
		if !used[a] {
			break
		}
	}
	return a
}

// localFrom turns a name into a local part: lower case ASCII letters,
// digits and dots, accents dropped.
func localFrom(name string) string {
	var b strings.Builder
	for _, r := range norm.NFD.String(strings.ToLower(strings.TrimSpace(name))) {
		switch {
		case unicode.Is(unicode.Mn, r):
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-' || r == '_' || r == ' ':
			if b.Len() > 0 && !strings.HasSuffix(b.String(), ".") {
				b.WriteByte('.')
			}
		}
	}
	out := strings.Trim(b.String(), ".")
	if len(out) > 64 {
		out = strings.Trim(out[:64], ".")
	}
	if !mail.ValidLocalPart(out) {
		return ""
	}
	return out
}

// SyncResult is what an account sync did.
type AccountSync struct {
	Created  []string `json:"created"`
	Disabled []string `json:"disabled"`
	Deleted  []string `json:"deleted"`
	Restored []string `json:"restored"`
}

// Changed reports whether the server's configuration must be applied.
func (a AccountSync) Changed() bool { return len(a.Created) > 0 }

// SyncAccounts gives every domain account a mailbox and follows accounts
// being turned off, on or deleted (decision 244).
func (s *Service) SyncAccounts(ctx context.Context) (*AccountSync, error) {
	out := &AccountSync{Created: []string{}, Disabled: []string{}, Deleted: []string{}, Restored: []string{}}
	if s.Dir == nil {
		return out, nil
	}
	st, err := s.Store.LoadSettings(ctx)
	if err != nil || !st.Enabled {
		return out, err
	}
	users, err := s.Dir.Users(ctx)
	if err != nil || users == nil {
		return out, err
	}
	mbs, err := s.Store.Mailboxes(ctx)
	if err != nil {
		return nil, err
	}
	used, err := s.Store.usedAddresses(ctx, 0)
	if err != nil {
		return nil, err
	}
	byAccount := map[string]*Mailbox{}
	for i := range mbs {
		byAccount[mbs[i].Account] = &mbs[i]
	}
	seen := map[string]bool{}
	for _, u := range users {
		if u.Builtin {
			continue
		}
		acct := strings.ToLower(u.Username)
		seen[acct] = true
		state := "active"
		if !u.Enabled {
			state = "disabled"
		}
		m := byAccount[acct]
		if m == nil {
			if st.DefaultDomain == "" {
				continue
			}
			addr := addressFor(u, st.AddressStyle, st.DefaultDomain, used)
			used[addr] = true
			if _, err := s.Store.CreateMailbox(ctx, Mailbox{Account: acct, Address: addr, DisplayName: u.DisplayName,
				Aliases: []string{}, QuotaMB: st.DefaultQuotaMB, Enabled: true, AccountState: state}); err != nil {
				return nil, err
			}
			out.Created = append(out.Created, addr)
			continue
		}
		if m.AccountState != state || m.DisplayName != u.DisplayName {
			if err := s.Store.SetAccountState(ctx, m.ID, state, u.DisplayName); err != nil {
				return nil, err
			}
			switch {
			case state == "disabled" && m.AccountState != "disabled":
				out.Disabled = append(out.Disabled, m.Address)
			case state == "active" && m.AccountState != "active":
				out.Restored = append(out.Restored, m.Address)
			}
		}
	}
	for _, m := range mbs {
		if !seen[m.Account] && m.AccountState != "deleted" {
			if err := s.Store.SetAccountState(ctx, m.ID, "deleted", m.DisplayName); err != nil {
				return nil, err
			}
			out.Deleted = append(out.Deleted, m.Address)
		}
	}
	for _, a := range append(append([]string{}, out.Disabled...), out.Deleted...) {
		if err := s.Priv.Call(ctx, mail.OpKick, mail.AddressArgs{Address: a}, nil); err != nil {
			s.log().Warn("mail: ending sign-ins", "address", a, "err", err)
		}
	}
	return out, nil
}

// ---- DNS ----

// DomainRecords lists a domain's records with this server's settings.
func (s *Service) DomainRecords(ctx context.Context, d *Domain) ([]mail.Record, error) {
	st, err := s.Store.LoadSettings(ctx)
	if err != nil {
		return nil, err
	}
	dd := mail.DomainDNS{Domain: d.Name, Hostname: st.Hostname, DKIMSelector: d.Selector, DKIMPublicKey: d.DKIMPublic,
		DMARCPolicy: d.DMARCPolicy, DMARCReports: "postmaster@" + d.Name, SES: st.SESAccessID != "", SESRegion: st.SESRegion,
		SESDKIM: d.SESDKIM, SESMailFrom: st.SESMailFrom && st.SESAccessID != "", MTASTS: d.MTASTS, MTASTSID: d.MTASTSID,
		ReportsEmail: "postmaster@" + d.Name}
	recs := mail.Records(dd)
	if st.Hostname != "" && strings.HasSuffix(st.Hostname, "."+d.Name) || st.Hostname == d.Name {
		recs = append(mail.ServerRecords(st.Hostname, st.VPSIPv4, st.VPSIPv6), recs...)
	}
	return recs, nil
}

// CheckDomain looks a domain's records up in public DNS and stores the
// result.
func (s *Service) CheckDomain(ctx context.Context, name string) (*DNSState, error) {
	d, err := s.Store.GetDomain(ctx, name)
	if err != nil {
		return nil, err
	}
	recs, err := s.DomainRecords(ctx, d)
	if err != nil {
		return nil, err
	}
	res := s.Resolver
	if res == nil {
		res = mail.PublicResolver()
	}
	checks := mail.CheckRecords(ctx, res, recs)
	state := DNSState{At: time.Now().UTC(), Summary: mail.Summarize(checks), Checks: checks}
	if err := s.Store.SetCheck(ctx, name, state); err != nil {
		return nil, err
	}
	return &state, nil
}

// ---- TLS on this server ----

// LoopbackTLS is notify's TLS configuration for the "HardyOS Mail"
// channel (127.0.0.1:587): the mail server's own leaf certificate, pinned.
func (s *Service) LoopbackTLS(ctx context.Context) *tls.Config {
	s.mu.Lock()
	pin, at := s.certPin, s.certTime
	s.mu.Unlock()
	if pin == nil || time.Since(at) > 5*time.Minute {
		st, _ := s.Store.LoadSettings(ctx)
		var status mail.Status
		if err := s.Priv.Call(ctx, mail.OpStatus, mail.StatusArgs{Pool: st.Pool}, &status); err == nil && status.Cert != nil {
			if blk, _ := pem.Decode([]byte(status.Cert.PEM)); blk != nil {
				pin = blk.Bytes
				s.mu.Lock()
				s.certPin, s.certTime = pin, time.Now()
				s.mu.Unlock()
			}
		}
	}
	if pin == nil {
		return nil
	}
	want := pin
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // pinned below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 || subtle.ConstantTimeCompare(raw[0], want) != 1 {
				return errors.New("the mail server's certificate isn't the one HardyOS installed")
			}
			return nil
		},
	}
}

// ---- alerts ----

// raise sends an alert when key's condition is new or changed; clear sends
// one "resolved" notice when it goes away.
func (s *Service) raise(ctx context.Context, key, kind, sev, title, body, link string) {
	s.mu.Lock()
	if s.conds == nil {
		s.conds = map[string]string{}
	}
	prev, had := s.conds[key]
	s.conds[key] = sev + "\x00" + body
	s.mu.Unlock()
	if had && prev == sev+"\x00"+body {
		return
	}
	if s.Notify != nil {
		s.Notify.Notify(ctx, notify.Event{Kind: kind, Severity: sev, Title: title, Body: body, Link: link, Time: time.Now()})
	}
}

func (s *Service) clear(ctx context.Context, key, kind, title, link string) {
	s.mu.Lock()
	_, had := s.conds[key]
	delete(s.conds, key)
	s.mu.Unlock()
	if had && s.Notify != nil {
		s.Notify.Notify(ctx, notify.Event{Kind: kind, Severity: notify.SeverityInfo, Title: title, Body: "Resolved.", Link: link, Time: time.Now()})
	}
}

// AuthEvent raises an alert when an internet address was blocked.
func (s *Service) AuthEvent(e mail.AuthEvent) {
	if !e.Blocked {
		return
	}
	s.raise(context.Background(), "signin:"+e.Remote, "mail.signin", notify.SeverityWarning,
		"Mail sign-ins blocked from "+e.Remote,
		fmt.Sprintf("%s tried wrong passwords for mail (%s, last as %s) and is blocked for an hour. People on your network aren't affected.",
			e.Remote, e.Protocol, e.Login), "control-panel/mail")
}

// QueueStuckAfter is how long a deferred message may wait before an alert.
const QueueStuckAfter = time.Hour

// CheckHealth looks at the services, the queue, SES and the certificate,
// and raises or clears alerts (every few minutes).
func (s *Service) CheckHealth(ctx context.Context) {
	st, err := s.Store.LoadSettings(ctx)
	if err != nil || !st.Enabled {
		return
	}
	var status mail.Status
	if err := s.Priv.Call(ctx, mail.OpStatus, mail.StatusArgs{Pool: st.Pool}, &status); err != nil {
		return
	}
	var down []string
	for u, a := range status.Services {
		if a != "active" && (st.ClamAV || !strings.HasPrefix(u, "clamav")) {
			down = append(down, strings.TrimSuffix(u, ".service"))
		}
	}
	if len(down) > 0 {
		s.raise(ctx, "service", "mail.service", notify.SeverityCritical, "The mail server isn't fully running",
			"Not running: "+strings.Join(down, ", ")+". Mail may not arrive or send.", "control-panel/mail")
	} else {
		s.clear(ctx, "service", "mail.service", "The mail server is running again", "control-panel/mail")
	}
	stuck, sesErr := 0, ""
	for _, q := range status.Queue {
		if q.Queue == "deferred" && time.Since(q.ArrivedAt) > QueueStuckAfter {
			stuck++
		}
		r := strings.ToLower(q.Reason)
		if sesErr == "" && strings.Contains(r, "amazonaws.com") && (strings.Contains(r, "said: 5") || strings.Contains(r, "said: 4") || strings.Contains(r, "authentication")) {
			sesErr = q.Reason
		}
	}
	if stuck > 0 {
		s.raise(ctx, "queue", "mail.queue", notify.SeverityWarning, fmt.Sprintf("%d messages are stuck in the mail queue", stuck),
			"Messages have been waiting over an hour to be delivered. Check Control Panel > Mail > Queue for the reason.", "control-panel/mail")
	} else {
		s.clear(ctx, "queue", "mail.queue", "The mail queue is moving again", "control-panel/mail")
	}
	if sesErr != "" {
		s.raise(ctx, "ses", "mail.ses", notify.SeverityCritical, "Amazon SES refuses outgoing mail", mail.ClipText(sesErr, 400), "control-panel/mail")
	} else {
		s.clear(ctx, "ses", "mail.ses", "Amazon SES accepts outgoing mail again", "control-panel/mail")
	}
	if c := status.Cert; c != nil {
		left := time.Until(c.NotAfter)
		switch {
		case left < 0:
			s.raise(ctx, "cert", "mail.certificate", notify.SeverityCritical, "The mail server's certificate has expired",
				"Mail apps refuse to connect. Renew it in Control Panel > Mail > Certificate.", "control-panel/mail")
		case left < 14*24*time.Hour && !c.SelfSigned:
			s.raise(ctx, "cert", "mail.certificate", notify.SeverityWarning, "The mail server's certificate expires soon",
				fmt.Sprintf("It expires on %s. HardyOS renews Let's Encrypt certificates by itself; an uploaded one must be replaced.", c.NotAfter.Format("2 Jan 2006")), "control-panel/mail")
		default:
			s.clear(ctx, "cert", "mail.certificate", "The mail server's certificate is valid", "control-panel/mail")
		}
	}
}

// CheckAllDNS checks every domain and alerts on missing required records
// (daily).
func (s *Service) CheckAllDNS(ctx context.Context) {
	st, err := s.Store.LoadSettings(ctx)
	if err != nil || !st.Enabled {
		return
	}
	doms, err := s.Store.Domains(ctx)
	if err != nil {
		return
	}
	for _, d := range doms {
		state, err := s.CheckDomain(ctx, d.Name)
		if err != nil {
			continue
		}
		key := "dns:" + d.Name
		if state.Summary.Problems > 0 {
			var bad []string
			for _, c := range state.Checks {
				if c.Required && c.Status != "ok" && c.Status != "error" {
					bad = append(bad, c.Type+" "+c.Name)
				}
			}
			if len(bad) == 0 {
				continue
			}
			s.raise(ctx, key, "mail.dns", notify.SeverityWarning, "DNS records for "+d.Name+" need attention",
				"Missing or wrong: "+strings.Join(bad, ", ")+". Mail may be rejected or not arrive.", "control-panel/mail")
		} else {
			s.clear(ctx, key, "mail.dns", "DNS records for "+d.Name+" are right", "control-panel/mail")
		}
	}
}

// Run keeps accounts in step and watches the server until ctx ends.
func (s *Service) Run(ctx context.Context) {
	sync := time.NewTicker(2 * time.Minute)
	health := time.NewTicker(5 * time.Minute)
	daily := time.NewTicker(24 * time.Hour)
	defer sync.Stop()
	defer health.Stop()
	defer daily.Stop()
	syncOnce := func() {
		res, err := s.SyncAccounts(ctx)
		if err != nil {
			s.log().Warn("mail: syncing accounts", "err", err)
			return
		}
		if res.Changed() && s.Submit != nil {
			if err := s.Submit(ctx, "mail.apply", "Add mailboxes for new accounts", map[string]any{"reason": "accounts"}); err != nil {
				s.log().Warn("mail: queueing apply", "err", err)
			}
		}
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}
	syncOnce()
	s.CheckHealth(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sync.C:
			syncOnce()
		case <-health.C:
			s.CheckHealth(ctx)
		case <-daily.C:
			s.CheckAllDNS(ctx)
			if s.Submit != nil {
				st, _ := s.Store.LoadSettings(ctx)
				if st.Enabled && st.TLSMode == "acme" {
					_ = s.Submit(ctx, "mail.certificate", "Renew the mail server's certificate", map[string]any{"renew": true})
				}
			}
		}
	}
}
