package manage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hardyos/hardyos/daemon/internal/mail"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Settings are the mail server's settings (Control Panel › Mail). Secrets
// are kept apart, sealed.
type Settings struct {
	Enabled bool `json:"enabled"`
	// Pool holds <pool>/mail.
	Pool string `json:"pool"`
	// Hostname is the mail server's public name (MX target, mail apps).
	Hostname string `json:"hostname"`
	// DefaultDomain is where new mailboxes get their address.
	DefaultDomain string `json:"defaultDomain"`
	// AddressStyle: "firstname" (alice@ from the account's first name) or
	// "username" (the account name).
	AddressStyle string `json:"addressStyle"`
	// DefaultQuotaMB is a new mailbox's size limit (0: none).
	DefaultQuotaMB int `json:"defaultQuotaMb"`
	// VPS: its NetBird address (where relayed mail and forwarded mail apps
	// come from), its public addresses (DNS) and its name (for the docs).
	VPSPeer string `json:"vpsPeer"`
	VPSIPv4 string `json:"vpsIpv4"`
	VPSIPv6 string `json:"vpsIpv6"`
	// SES: region and access key ID (the secret key is sealed);
	// MailFrom uses bounce.<domain> as SES's MAIL FROM.
	SESRegion   string `json:"sesRegion"`
	SESAccessID string `json:"sesAccessKeyId"`
	SESMailFrom bool   `json:"sesMailFrom"`
	// Spam and limits.
	ClamAV       bool    `json:"clamav"`
	JunkScore    float64 `json:"junkScore"`
	MaxMessageMB int     `json:"maxMessageMb"`
	SendPerHour  int     `json:"sendPerHour"`
	// Postmaster receives postmaster@, abuse@ and reports.
	Postmaster string `json:"postmaster"`
	// SharedCalendar makes the family calendar and address book.
	SharedCalendar bool `json:"sharedCalendar"`
	// TLS: "acme" (Let's Encrypt through Cloudflare DNS), "manual"
	// (uploaded) or "self" (self-signed, until one of the others).
	TLSMode     string `json:"tlsMode"`
	ACMEEmail   string `json:"acmeEmail"`
	ACMEStaging bool   `json:"acmeStaging"`
	// NotifyFrom is the address HardyOS's notifications are sent from.
	NotifyFrom string `json:"notifyFrom"`
}

// Defaults for a new setup.
func DefaultSettings() Settings {
	return Settings{AddressStyle: "firstname", DefaultQuotaMB: mail.DefaultQuotaMB, JunkScore: 6,
		MaxMessageMB: mail.DefaultMessageMB, SendPerHour: mail.DefaultSendHour, SharedCalendar: true, TLSMode: "self", SESMailFrom: true}
}

// Secret names (settings keys; sealed with purpose "mail", the key name as
// additional data).
const (
	SecretSES        = "mail.ses_secret"       // IAM secret access key
	SecretCloudflare = "mail.cloudflare_token" // Zone › DNS › Edit token
	SecretAuth       = "mail.auth_secret"      // Dovecot <-> hardyd
	SecretNotify     = "mail.notify_password"  // the notification sign-in
	SecretDAV        = "mail.dav_key"          // derives Radicale passwords
	SecretACME       = "mail.acme_account"     // Let's Encrypt account key
	settingsKey      = "mail.settings"
	notifyChannelKey = "mail.notify_channel_id" // the "HardyOS Mail" channel
)

// SealPurpose is the secretbox purpose of mail's secrets.
const SealPurpose = "mail"

// Domain is a mail domain as the API shows it.
type Domain struct {
	Name        string    `json:"name"`
	Selector    string    `json:"selector"`
	DKIMPublic  string    `json:"dkimPublicKey"`
	DMARCPolicy string    `json:"dmarcPolicy"`
	MTASTS      string    `json:"mtaSts"`
	MTASTSID    string    `json:"-"`
	Cloudflare  bool      `json:"cloudflare"`
	SESDKIM     []string  `json:"sesDkimTokens"`
	SESStatus   string    `json:"sesStatus"`
	SESMailFrom bool      `json:"-"`
	LastCheck   *DNSState `json:"lastCheck,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

// DNSState is a stored DNS check.
type DNSState struct {
	At      time.Time    `json:"at"`
	Summary mail.Summary `json:"summary"`
	Checks  []mail.Check `json:"checks"`
}

// Mailbox is one person's mailbox.
type Mailbox struct {
	ID          int64    `json:"id"`
	Account     string   `json:"account"` // domain account name
	Address     string   `json:"address"`
	DisplayName string   `json:"displayName"`
	Aliases     []string `json:"aliases"`
	QuotaMB     int      `json:"quotaMb"`
	// Enabled: an administrator lets this mailbox sign in (mail apps,
	// webmail). The account's own state comes on top.
	Enabled bool `json:"enabled"`
	// AccountState: active, disabled (turned off in the domain) or deleted
	// (gone from the domain; the mailbox and its mail stay until deleted).
	AccountState  string    `json:"accountState"`
	CustomAddress bool      `json:"customAddress"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

// CanSignIn reports whether the mailbox may be used now.
func (m *Mailbox) CanSignIn() bool { return m.Enabled && m.AccountState == "active" }

// Group delivers to several mailboxes.
type Group struct {
	Address   string    `json:"address"`
	Targets   []string  `json:"targets"`
	CreatedAt time.Time `json:"createdAt"`
}

// Store keeps the mail server's state in hardyd's database.
type Store struct {
	DB   *store.DB
	Keys secretbox.Source
}

// ErrNotFound is a missing domain, mailbox or group.
var ErrNotFound = errors.New("not found")

// LoadSettings returns the settings (defaults when never saved).
func (s *Store) LoadSettings(ctx context.Context) (Settings, error) {
	raw, err := s.DB.GetSetting(ctx, settingsKey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return DefaultSettings(), nil
		}
		return Settings{}, err
	}
	if raw == "" {
		return DefaultSettings(), nil
	}
	st := DefaultSettings()
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return Settings{}, err
	}
	return st, nil
}

// SaveSettings stores settings (already validated).
func (s *Store) SaveSettings(ctx context.Context, st Settings) error {
	b, _ := json.Marshal(st)
	return s.DB.SetSetting(ctx, settingsKey, string(b))
}

func (s *Store) key(ctx context.Context) ([]byte, error) {
	if s.Keys == nil {
		return nil, errors.New("no key source for mail secrets")
	}
	return s.Keys.Key(ctx, SealPurpose)
}

// Secret opens a sealed secret ("" when unset).
func (s *Store) Secret(ctx context.Context, name string) (string, error) {
	raw, err := s.DB.GetSetting(ctx, name)
	if err != nil || raw == "" {
		if err == nil || errors.Is(err, store.ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	sealed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	k, err := s.key(ctx)
	if err != nil {
		return "", err
	}
	plain, err := secretbox.Open(k, sealed, []byte(name))
	if err != nil {
		return "", fmt.Errorf("%s can't be opened (restored without its key?): %w", name, err)
	}
	return string(plain), nil
}

// SetSecret seals and stores a secret ("" clears it).
func (s *Store) SetSecret(ctx context.Context, name, value string) error {
	if value == "" {
		return s.DB.SetSetting(ctx, name, "")
	}
	k, err := s.key(ctx)
	if err != nil {
		return err
	}
	sealed, err := secretbox.Seal(k, []byte(value), []byte(name))
	if err != nil {
		return err
	}
	return s.DB.SetSetting(ctx, name, base64.StdEncoding.EncodeToString(sealed))
}

// HasSecret reports whether a secret is stored.
func (s *Store) HasSecret(ctx context.Context, name string) bool {
	raw, err := s.DB.GetSetting(ctx, name)
	return err == nil && raw != ""
}

// RandomSecret is 32 random bytes, hex.
func RandomSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// EnsureSecret returns a secret, making a random one first if there is none.
func (s *Store) EnsureSecret(ctx context.Context, name string) (string, error) {
	v, err := s.Secret(ctx, name)
	if err != nil || v != "" {
		return v, err
	}
	v = RandomSecret()
	return v, s.SetSecret(ctx, name, v)
}

// ---- domains ----

func scanDomain(sc interface{ Scan(...any) error }) (*Domain, error) {
	var d Domain
	var sesDKIM, check, created string
	var checked sql.NullString
	var cf, mf int
	if err := sc.Scan(&d.Name, &d.Selector, &d.DKIMPublic, &d.DMARCPolicy, &d.MTASTS, &d.MTASTSID, &cf, &sesDKIM, &d.SESStatus, &mf, &check, &checked, &created); err != nil {
		return nil, err
	}
	d.Cloudflare, d.SESMailFrom = cf == 1, mf == 1
	_ = json.Unmarshal([]byte(sesDKIM), &d.SESDKIM)
	if d.SESDKIM == nil {
		d.SESDKIM = []string{}
	}
	if check != "" {
		var st DNSState
		if json.Unmarshal([]byte(check), &st) == nil {
			d.LastCheck = &st
		}
	}
	d.CreatedAt = store.ParseTime(created)
	return &d, nil
}

const domainCols = `name, selector, dkim_public, dmarc_policy, mta_sts, mta_sts_id, cloudflare, ses_dkim, ses_status, ses_mail_from, last_check, checked_at, created_at`

// Domains lists the mail domains.
func (s *Store) Domains(ctx context.Context) ([]Domain, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+domainCols+` FROM mail_domains ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Domain{}
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// GetDomain returns one domain.
func (s *Store) GetDomain(ctx context.Context, name string) (*Domain, error) {
	d, err := scanDomain(s.DB.QueryRowContext(ctx, `SELECT `+domainCols+` FROM mail_domains WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// AddDomain adds a domain with a fresh DKIM selector.
func (s *Store) AddDomain(ctx context.Context, name string, dmarc string, cloudflare bool) (*Domain, error) {
	if !mail.ValidDomain(name) {
		return nil, mail.Invalid("%q isn't a valid domain (like example.net)", name)
	}
	if dmarc == "" {
		dmarc = "quarantine"
	}
	if !validDMARC(dmarc) {
		return nil, mail.Invalid("the DMARC policy must be none, quarantine or reject")
	}
	n := 0
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM mail_domains`).Scan(&n)
	if n >= mail.MaxDomains {
		return nil, mail.Invalid("at most %d mail domains", mail.MaxDomains)
	}
	sel := "hardyos" + time.Now().UTC().Format("200601")
	_, err := s.DB.ExecContext(ctx, `INSERT INTO mail_domains (name, selector, dmarc_policy, cloudflare, created_at) VALUES (?, ?, ?, ?, ?)`,
		name, sel, dmarc, boolInt(cloudflare), store.FormatTime(time.Now()))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, mail.Invalid("%s is already a mail domain", name)
		}
		return nil, err
	}
	return s.GetDomain(ctx, name)
}

func validDMARC(p string) bool { return p == "none" || p == "quarantine" || p == "reject" }

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// DomainUpdate changes a domain's DNS choices.
type DomainUpdate struct {
	DMARCPolicy *string `json:"dmarcPolicy,omitempty"`
	MTASTS      *string `json:"mtaSts,omitempty"`
	Cloudflare  *bool   `json:"cloudflare,omitempty"`
	// RotateDKIM starts a new key under a new selector.
	RotateDKIM bool `json:"rotateDkim,omitempty"`
}

// UpdateDomain applies u.
func (s *Store) UpdateDomain(ctx context.Context, name string, u DomainUpdate) (*Domain, error) {
	d, err := s.GetDomain(ctx, name)
	if err != nil {
		return nil, err
	}
	if u.DMARCPolicy != nil {
		if !validDMARC(*u.DMARCPolicy) {
			return nil, mail.Invalid("the DMARC policy must be none, quarantine or reject")
		}
		d.DMARCPolicy = *u.DMARCPolicy
	}
	if u.MTASTS != nil {
		switch *u.MTASTS {
		case "off", "testing", "enforce":
		default:
			return nil, mail.Invalid("MTA-STS must be off, testing or enforce")
		}
		if *u.MTASTS != d.MTASTS {
			d.MTASTSID = time.Now().UTC().Format("20060102T150405")
		}
		d.MTASTS = *u.MTASTS
	}
	if u.Cloudflare != nil {
		d.Cloudflare = *u.Cloudflare
	}
	if u.RotateDKIM {
		d.Selector = "hardyos" + time.Now().UTC().Format("20060102150405")
		d.DKIMPublic = ""
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE mail_domains SET selector = ?, dkim_public = ?, dmarc_policy = ?, mta_sts = ?, mta_sts_id = ?, cloudflare = ? WHERE name = ?`,
		d.Selector, d.DKIMPublic, d.DMARCPolicy, d.MTASTS, d.MTASTSID, boolInt(d.Cloudflare), name)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// SetDKIM stores a domain's public key (from root).
func (s *Store) SetDKIM(ctx context.Context, name, selector, pub string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE mail_domains SET dkim_public = ? WHERE name = ? AND selector = ?`, pub, name, selector)
	return err
}

// SetSES stores what SES said about a domain.
func (s *Store) SetSES(ctx context.Context, name string, tokens []string, status string, mailFrom bool) error {
	if tokens == nil {
		tokens = []string{}
	}
	b, _ := json.Marshal(tokens)
	_, err := s.DB.ExecContext(ctx, `UPDATE mail_domains SET ses_dkim = ?, ses_status = ?, ses_mail_from = ? WHERE name = ?`, string(b), status, boolInt(mailFrom), name)
	return err
}

// SetCheck stores a DNS check.
func (s *Store) SetCheck(ctx context.Context, name string, st DNSState) error {
	b, _ := json.Marshal(st)
	_, err := s.DB.ExecContext(ctx, `UPDATE mail_domains SET last_check = ?, checked_at = ? WHERE name = ?`, string(b), store.FormatTime(st.At), name)
	return err
}

// DeleteDomain removes a domain. Refused while mailboxes or groups use it.
func (s *Store) DeleteDomain(ctx context.Context, name string) error {
	var n int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM mail_mailboxes WHERE address LIKE ?`, "%@"+name).Scan(&n)
	if n > 0 {
		return mail.Invalid("%d mailboxes still use %s; change their addresses first", n, name)
	}
	var g int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM mail_groups WHERE address LIKE ?`, "%@"+name).Scan(&g)
	if g > 0 {
		return mail.Invalid("group addresses still use %s", name)
	}
	mbs, err := s.Mailboxes(ctx)
	if err != nil {
		return err
	}
	for _, m := range mbs {
		for _, a := range m.Aliases {
			if strings.HasSuffix(a, "@"+name) {
				return mail.Invalid("%s has the alias %s; remove it first", m.Address, a)
			}
		}
	}
	res, err := s.DB.ExecContext(ctx, `DELETE FROM mail_domains WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- mailboxes ----

const mailboxCols = `id, account, address, display_name, aliases, quota_mb, enabled, account_state, custom_address, created_at, updated_at`

func scanMailbox(sc interface{ Scan(...any) error }) (*Mailbox, error) {
	var m Mailbox
	var aliases, created, updated string
	var en, custom int
	if err := sc.Scan(&m.ID, &m.Account, &m.Address, &m.DisplayName, &aliases, &m.QuotaMB, &en, &m.AccountState, &custom, &created, &updated); err != nil {
		return nil, err
	}
	m.Enabled, m.CustomAddress = en == 1, custom == 1
	_ = json.Unmarshal([]byte(aliases), &m.Aliases)
	if m.Aliases == nil {
		m.Aliases = []string{}
	}
	m.CreatedAt, m.UpdatedAt = store.ParseTime(created), store.ParseTime(updated)
	return &m, nil
}

// Mailboxes lists every mailbox.
func (s *Store) Mailboxes(ctx context.Context) ([]Mailbox, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+mailboxCols+` FROM mail_mailboxes ORDER BY address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Mailbox{}
	for rows.Next() {
		m, err := scanMailbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// GetMailbox returns one mailbox by ID.
func (s *Store) GetMailbox(ctx context.Context, id int64) (*Mailbox, error) {
	m, err := scanMailbox(s.DB.QueryRowContext(ctx, `SELECT `+mailboxCols+` FROM mail_mailboxes WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}

// MailboxByAddress finds the mailbox whose own address is addr.
func (s *Store) MailboxByAddress(ctx context.Context, addr string) (*Mailbox, error) {
	m, err := scanMailbox(s.DB.QueryRowContext(ctx, `SELECT `+mailboxCols+` FROM mail_mailboxes WHERE address = ?`, strings.ToLower(addr)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}

// MailboxByAccount finds an account's mailbox.
func (s *Store) MailboxByAccount(ctx context.Context, account string) (*Mailbox, error) {
	m, err := scanMailbox(s.DB.QueryRowContext(ctx, `SELECT `+mailboxCols+` FROM mail_mailboxes WHERE account = ?`, strings.ToLower(account)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return m, err
}

// usedAddresses is every address in use (mailboxes, aliases, groups),
// except the mailbox skip's own.
func (s *Store) usedAddresses(ctx context.Context, skip int64) (map[string]bool, error) {
	used := map[string]bool{}
	mbs, err := s.Mailboxes(ctx)
	if err != nil {
		return nil, err
	}
	for _, m := range mbs {
		if m.ID == skip {
			continue
		}
		used[m.Address] = true
		for _, a := range m.Aliases {
			used[a] = true
		}
	}
	gs, err := s.Groups(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range gs {
		used[g.Address] = true
	}
	return used, nil
}

// CreateMailbox adds a mailbox for an account.
func (s *Store) CreateMailbox(ctx context.Context, m Mailbox) (*Mailbox, error) {
	now := store.FormatTime(time.Now())
	al, _ := json.Marshal(m.Aliases)
	if m.Aliases == nil {
		al = []byte("[]")
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO mail_mailboxes (account, address, display_name, aliases, quota_mb, enabled, account_state, custom_address, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, strings.ToLower(m.Account), m.Address, m.DisplayName, string(al), m.QuotaMB,
		boolInt(m.Enabled), m.AccountState, boolInt(m.CustomAddress), now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetMailbox(ctx, id)
}

// MailboxUpdate changes what an administrator may change.
type MailboxUpdate struct {
	Address *string   `json:"address,omitempty"`
	Aliases *[]string `json:"aliases,omitempty"`
	QuotaMB *int      `json:"quotaMb,omitempty"`
	Enabled *bool     `json:"enabled,omitempty"`
}

// UpdateMailbox validates and applies u against the domains in use.
func (s *Store) UpdateMailbox(ctx context.Context, id int64, u MailboxUpdate) (*Mailbox, error) {
	m, err := s.GetMailbox(ctx, id)
	if err != nil {
		return nil, err
	}
	doms, err := s.Domains(ctx)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, d := range doms {
		have[d.Name] = true
	}
	used, err := s.usedAddresses(ctx, id)
	if err != nil {
		return nil, err
	}
	check := func(a string) (string, error) {
		a, err := mail.NormalizeAddress(a)
		if err != nil {
			return "", err
		}
		local, dom, _ := mail.SplitAddress(a)
		if !have[dom] {
			return "", mail.Invalid("%s isn't one of the mail domains", dom)
		}
		if local == "postmaster" || local == "abuse" || a == strings.ToLower(mail.NotifyLogin) {
			return "", mail.Invalid("%s is kept for the postmaster", a)
		}
		if used[a] {
			return "", mail.Invalid("%s is already used", a)
		}
		return a, nil
	}
	if u.Address != nil && *u.Address != m.Address {
		a, err := check(*u.Address)
		if err != nil {
			return nil, err
		}
		m.Address, m.CustomAddress = a, true
	}
	if u.Aliases != nil {
		if len(*u.Aliases) > mail.MaxAliases {
			return nil, mail.Invalid("at most %d aliases", mail.MaxAliases)
		}
		seen := map[string]bool{m.Address: true}
		out := []string{}
		for _, a := range *u.Aliases {
			if strings.TrimSpace(a) == "" {
				continue
			}
			na, err := check(a)
			if err != nil {
				return nil, err
			}
			if !seen[na] {
				seen[na] = true
				out = append(out, na)
			}
		}
		sort.Strings(out)
		m.Aliases = out
	}
	if u.QuotaMB != nil {
		if *u.QuotaMB < 0 || *u.QuotaMB > mail.MaxQuotaMB {
			return nil, mail.Invalid("the quota must be 0 (none) to %d MB", mail.MaxQuotaMB)
		}
		m.QuotaMB = *u.QuotaMB
	}
	if u.Enabled != nil {
		m.Enabled = *u.Enabled
	}
	al, _ := json.Marshal(m.Aliases)
	_, err = s.DB.ExecContext(ctx, `UPDATE mail_mailboxes SET address = ?, aliases = ?, quota_mb = ?, enabled = ?, custom_address = ?, updated_at = ? WHERE id = ?`,
		m.Address, string(al), m.QuotaMB, boolInt(m.Enabled), boolInt(m.CustomAddress), store.FormatTime(time.Now()), id)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, mail.Invalid("%s is already used", m.Address)
		}
		return nil, err
	}
	return s.GetMailbox(ctx, id)
}

// SetAccountState records the account's state in the domain.
func (s *Store) SetAccountState(ctx context.Context, id int64, state, display string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE mail_mailboxes SET account_state = ?, display_name = ?, updated_at = ? WHERE id = ?`,
		state, display, store.FormatTime(time.Now()), id)
	return err
}

// DeleteMailboxRow forgets a mailbox (its messages are root's to delete).
func (s *Store) DeleteMailboxRow(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM mail_mailboxes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- groups ----

// Groups lists the group addresses.
func (s *Store) Groups(ctx context.Context) ([]Group, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT address, targets, created_at FROM mail_groups ORDER BY address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		var t, c string
		if err := rows.Scan(&g.Address, &t, &c); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(t), &g.Targets)
		if g.Targets == nil {
			g.Targets = []string{}
		}
		g.CreatedAt = store.ParseTime(c)
		out = append(out, g)
	}
	return out, rows.Err()
}

// SetGroup creates or replaces a group address.
func (s *Store) SetGroup(ctx context.Context, g Group) (*Group, error) {
	addr, err := mail.NormalizeAddress(g.Address)
	if err != nil {
		return nil, err
	}
	_, dom, _ := mail.SplitAddress(addr)
	if _, err := s.GetDomain(ctx, dom); err != nil {
		return nil, mail.Invalid("%s isn't one of the mail domains", dom)
	}
	used, err := s.usedAddresses(ctx, 0)
	if err != nil {
		return nil, err
	}
	gs, _ := s.Groups(ctx)
	isGroup := false
	for _, x := range gs {
		if x.Address == addr {
			isGroup = true
		}
	}
	if used[addr] && !isGroup {
		return nil, mail.Invalid("%s is already used", addr)
	}
	mbs, err := s.Mailboxes(ctx)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, m := range mbs {
		known[m.Address] = true
	}
	var targets []string
	seen := map[string]bool{}
	for _, t := range g.Targets {
		t = strings.ToLower(strings.TrimSpace(t))
		if !known[t] {
			return nil, mail.Invalid("%s isn't a mailbox on this server", t)
		}
		if !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 || len(targets) > mail.MaxGroupTargets {
		return nil, mail.Invalid("choose 1 to %d mailboxes", mail.MaxGroupTargets)
	}
	sort.Strings(targets)
	b, _ := json.Marshal(targets)
	_, err = s.DB.ExecContext(ctx, `INSERT INTO mail_groups (address, targets, created_at) VALUES (?, ?, ?)
		ON CONFLICT(address) DO UPDATE SET targets = excluded.targets`, addr, string(b), store.FormatTime(time.Now()))
	if err != nil {
		return nil, err
	}
	return &Group{Address: addr, Targets: targets}, nil
}

// DeleteGroup removes a group address.
func (s *Store) DeleteGroup(ctx context.Context, addr string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM mail_groups WHERE address = ?`, strings.ToLower(addr))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// PruneGroups drops a deleted mailbox from every group (and groups left
// empty).
func (s *Store) PruneGroups(ctx context.Context, addr string) error {
	gs, err := s.Groups(ctx)
	if err != nil {
		return err
	}
	for _, g := range gs {
		var keep []string
		for _, t := range g.Targets {
			if t != addr {
				keep = append(keep, t)
			}
		}
		if len(keep) == len(g.Targets) {
			continue
		}
		if len(keep) == 0 {
			if _, err := s.DB.ExecContext(ctx, `DELETE FROM mail_groups WHERE address = ?`, g.Address); err != nil {
				return err
			}
			continue
		}
		b, _ := json.Marshal(keep)
		if _, err := s.DB.ExecContext(ctx, `UPDATE mail_groups SET targets = ? WHERE address = ?`, string(b), g.Address); err != nil {
			return err
		}
	}
	return nil
}

// ---- settings validation ----

// ValidateSettings checks settings an administrator saves.
func ValidateSettings(st Settings, domains []Domain) (Settings, error) {
	st.Hostname = strings.ToLower(strings.TrimSpace(st.Hostname))
	if st.Hostname != "" && !mail.ValidDomain(st.Hostname) {
		return st, mail.Invalid("the mail server's name %q isn't a valid host name (like mail.example.net)", st.Hostname)
	}
	if st.Pool != "" && !mail.ValidPool(st.Pool) {
		return st, mail.Invalid("invalid pool")
	}
	switch st.AddressStyle {
	case "":
		st.AddressStyle = "firstname"
	case "firstname", "username":
	default:
		return st, mail.Invalid("addresses are made from the first name or the account name")
	}
	if st.DefaultQuotaMB < 0 || st.DefaultQuotaMB > mail.MaxQuotaMB {
		return st, mail.Invalid("the default quota must be 0 (none) to %d MB", mail.MaxQuotaMB)
	}
	for _, ip := range []struct {
		v    *string
		what string
		six  bool
	}{{&st.VPSPeer, "the VPS's NetBird address", false}, {&st.VPSIPv4, "the VPS's IPv4 address", false}, {&st.VPSIPv6, "the VPS's IPv6 address", true}} {
		*ip.v = strings.TrimSpace(*ip.v)
		if *ip.v == "" {
			continue
		}
		a, err := netip.ParseAddr(*ip.v)
		if err != nil || a.IsUnspecified() || a.IsLoopback() {
			return st, mail.Invalid("%s isn't valid", ip.what)
		}
		if ip.what == "the VPS's IPv4 address" && !a.Is4() || ip.six && !a.Is6() {
			return st, mail.Invalid("%s isn't the right kind of address", ip.what)
		}
		*ip.v = a.String()
	}
	if st.SESRegion != "" && !ValidRegion(st.SESRegion) {
		return st, mail.Invalid("the AWS region %q isn't valid (like us-east-1)", st.SESRegion)
	}
	if st.SESAccessID != "" && !mail.ValidSESUser(st.SESAccessID) {
		return st, mail.Invalid("the access key ID isn't valid (like AKIA…)")
	}
	if st.JunkScore == 0 {
		st.JunkScore = 6
	}
	if st.JunkScore < 1 || st.JunkScore > 50 {
		return st, mail.Invalid("the junk score must be 1 to 50")
	}
	if st.MaxMessageMB == 0 {
		st.MaxMessageMB = mail.DefaultMessageMB
	}
	if st.MaxMessageMB < 1 || st.MaxMessageMB > mail.MaxMessageMB {
		return st, mail.Invalid("the largest message must be 1 to %d MB", mail.MaxMessageMB)
	}
	if st.SendPerHour == 0 {
		st.SendPerHour = mail.DefaultSendHour
	}
	if st.SendPerHour < 1 || st.SendPerHour > mail.MaxSendHour {
		return st, mail.Invalid("messages per hour must be 1 to %d", mail.MaxSendHour)
	}
	switch st.TLSMode {
	case "":
		st.TLSMode = "self"
	case "self", "manual", "acme":
	default:
		return st, mail.Invalid("the certificate is self-signed, uploaded or from Let's Encrypt")
	}
	if st.ACMEEmail != "" {
		if _, _, err := mail.SplitAddress(strings.ToLower(st.ACMEEmail)); err != nil {
			return st, mail.Invalid("the Let's Encrypt contact address isn't valid")
		}
		st.ACMEEmail = strings.ToLower(st.ACMEEmail)
	}
	have := map[string]bool{}
	for _, d := range domains {
		have[d.Name] = true
	}
	if st.DefaultDomain != "" && !have[st.DefaultDomain] {
		return st, mail.Invalid("the default domain %s isn't one of the mail domains", st.DefaultDomain)
	}
	for _, a := range []*string{&st.Postmaster, &st.NotifyFrom} {
		if *a == "" {
			continue
		}
		v, err := mail.NormalizeAddress(*a)
		if err != nil {
			return st, err
		}
		_, d, _ := mail.SplitAddress(v)
		if !have[d] {
			return st, mail.Invalid("%s isn't at one of the mail domains", v)
		}
		*a = v
	}
	if st.Enabled {
		switch {
		case st.Pool == "":
			return st, mail.Invalid("choose the pool mail is kept on")
		case st.Hostname == "":
			return st, mail.Invalid("set the mail server's name")
		case st.VPSPeer == "":
			return st, mail.Invalid("enter the VPS's NetBird address")
		case len(domains) == 0:
			return st, mail.Invalid("add a mail domain first")
		}
	}
	return st, nil
}
