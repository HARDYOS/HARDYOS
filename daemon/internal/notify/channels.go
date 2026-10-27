package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Channel types.
const (
	TypeDesktop = "desktop"
	TypeDiscord = "discord"
	TypeSlack   = "slack"
	TypeTeams   = "teams"
	TypeWebhook = "webhook" // any https endpoint, only with AllowAnyHost
	TypeSMTP    = "smtp"    // Gmail / Google Workspace, Amazon SES's SMTP interface, any mail server
	TypeSES     = "ses"     // Amazon SES API v2, signed with SigV4
)

// ChannelTypes lists the types in the order the UI offers them.
var ChannelTypes = []string{TypeDesktop, TypeDiscord, TypeSlack, TypeTeams, TypeWebhook, TypeSMTP, TypeSES}

// SMTP security modes.
const (
	SecuritySTARTTLS = "starttls" // plain connection upgraded with STARTTLS (port 587); required, never optional
	SecurityTLS      = "tls"      // TLS from the first byte (port 465)
	SecurityNone     = "none"     // no encryption: only for a mail server on this machine or its own network
)

// ChannelConfig is a channel's settings without secrets. Fields apply to
// the types noted.
type ChannelConfig struct {
	// Webhooks (discord, slack, teams, webhook): the URL is a secret (it
	// carries the token); URLHost shows where it points. Read-only.
	URLHost string `json:"urlHost,omitempty"`
	// AllowAnyHost lets a generic webhook post to any https host (not on
	// this server or its networks). Required for TypeWebhook.
	AllowAnyHost bool `json:"allowAnyHost,omitempty"`

	// Email (smtp, ses).
	From string   `json:"from,omitempty"`
	To   []string `json:"to,omitempty"`

	// SMTP.
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Security string `json:"security,omitempty"`
	Username string `json:"username,omitempty"`
	// AllowAnyPort allows a port other than 25, 465, 587 and 2525.
	AllowAnyPort bool `json:"allowAnyPort,omitempty"`

	// Amazon SES API v2.
	Region           string `json:"region,omitempty"`
	AccessKeyID      string `json:"accessKeyId,omitempty"`
	ConfigurationSet string `json:"configurationSet,omitempty"`
}

// Secrets are what a channel keeps sealed: never returned by the API.
type Secrets struct {
	URL             string `json:"url,omitempty"`             // webhooks
	Password        string `json:"password,omitempty"`        // smtp (an app password for Gmail)
	SecretAccessKey string `json:"secretAccessKey,omitempty"` // ses
}

// SecretsInput changes secrets: a nil field keeps the stored value, ""
// clears it.
type SecretsInput struct {
	URL             *string `json:"url,omitempty"`
	Password        *string `json:"password,omitempty"`
	SecretAccessKey *string `json:"secretAccessKey,omitempty"`
}

// Channel is a channel as the API shows it.
type Channel struct {
	ID      int64         `json:"id"`
	Type    string        `json:"type"`
	Name    string        `json:"name"`
	Enabled bool          `json:"enabled"`
	Config  ChannelConfig `json:"config"`
	// SecretsSet says which secrets are stored (their values never leave).
	SecretsSet map[string]bool `json:"secretsSet"`
	LastAt     *time.Time      `json:"lastAt"`
	LastOK     *bool           `json:"lastOk"`
	LastError  string          `json:"lastError"`
}

// ChannelInput creates or changes a channel.
type ChannelInput struct {
	Type    string        `json:"type"`
	Name    string        `json:"name"`
	Enabled *bool         `json:"enabled,omitempty"`
	Config  ChannelConfig `json:"config"`
	Secrets *SecretsInput `json:"secrets,omitempty"`
}

// ValidationError is a problem with what the caller sent.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}

// ErrNotFound: no such channel.
var ErrNotFound = store.ErrNotFound

// secretPurpose is the secretbox purpose for channel secrets.
const secretPurpose = "notify"

func secretAAD(id int64) []byte { return []byte("notify_channels:" + strconv.FormatInt(id, 10)) }

// Webhook hosts each type accepts without AllowAnyHost.
var (
	discordHosts = map[string]bool{"discord.com": true, "discordapp.com": true, "canary.discord.com": true, "ptb.discord.com": true}
	// Teams: Office 365 connectors (*.webhook.office.com, being retired by
	// Microsoft) and Workflows (Power Automate: *.logic.azure.com,
	// *.powerautomate.com, *.api.powerplatform.com).
	teamsSuffixes = []string{".webhook.office.com", ".logic.azure.com", ".powerautomate.com", ".api.powerplatform.com"}
)

var (
	hostnameRE  = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	regionRE    = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-[0-9]{1,2}$`)
	accessKeyRE = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
	configSetRE = regexp.MustCompile(`^[A-Za-z0-9_-]{0,64}$`)
)

// checkWebhookURL validates a webhook URL for a channel type and returns
// its host.
func checkWebhookURL(typ, raw string, anyHost bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", invalid("the webhook URL is required")
	}
	if len(raw) > 2048 {
		return "", invalid("the webhook URL is too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", invalid("the webhook URL isn't a valid URL")
	}
	if u.Scheme != "https" {
		return "", invalid("webhooks must use https")
	}
	if u.User != nil {
		return "", invalid("the webhook URL can't contain a user name or password")
	}
	if u.Fragment != "" {
		return "", invalid("the webhook URL can't contain a #fragment")
	}
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip == nil && !hostnameRE.MatchString(host) {
		return "", invalid("the webhook URL's host %q isn't valid", host)
	}
	if a, err := netip.ParseAddr(host); err == nil && !publicAddr(a) {
		return "", invalid("%s is on this server or a private network; webhooks go to public https services only", host)
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return "", invalid("%s is on this server or its network; webhooks go to public https services only", host)
	}
	port := u.Port()
	known := false
	switch typ {
	case TypeDiscord:
		known = discordHosts[host] && strings.HasPrefix(u.EscapedPath(), "/api/webhooks/")
		if !known && !anyHost {
			return "", invalid("a Discord webhook URL looks like https://discord.com/api/webhooks/…")
		}
	case TypeSlack:
		p := u.EscapedPath()
		known = host == "hooks.slack.com" && (strings.HasPrefix(p, "/services/") || strings.HasPrefix(p, "/triggers/") || strings.HasPrefix(p, "/workflows/"))
		if !known && !anyHost {
			return "", invalid("a Slack webhook URL looks like https://hooks.slack.com/services/…")
		}
	case TypeTeams:
		for _, s := range teamsSuffixes {
			if strings.HasSuffix(host, s) {
				known = true
			}
		}
		if !known && !anyHost {
			return "", invalid("a Microsoft Teams webhook URL is on webhook.office.com, logic.azure.com or powerautomate.com (from Teams' Workflows app)")
		}
	case TypeWebhook:
		if !anyHost {
			return "", invalid("a generic webhook can post to any https host only when you allow that explicitly")
		}
	default:
		return "", invalid("channel type %q has no webhook", typ)
	}
	if known && port != "" && port != "443" {
		return "", invalid("the webhook URL must use the standard https port")
	}
	return host, nil
}

func checkAddress(field, s string) error {
	if len(s) > 254 {
		return invalid("%s is too long", field)
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || strings.ContainsAny(s, "\r\n<>") {
		return invalid("%s %q isn't an email address", field, s)
	}
	return nil
}

func checkRecipients(to []string) error {
	if len(to) == 0 {
		return invalid("add at least one recipient")
	}
	if len(to) > 20 {
		return invalid("at most 20 recipients")
	}
	for _, t := range to {
		if err := checkAddress("recipient", t); err != nil {
			return err
		}
	}
	return nil
}

// normalizeConfig validates a channel's settings and secrets together and
// returns the config as stored (only the fields its type uses).
func normalizeConfig(typ string, in ChannelConfig, sec Secrets) (ChannelConfig, error) {
	var out ChannelConfig
	switch typ {
	case TypeDesktop:
		return out, nil
	case TypeDiscord, TypeSlack, TypeTeams, TypeWebhook:
		out.AllowAnyHost = in.AllowAnyHost
		host, err := checkWebhookURL(typ, sec.URL, in.AllowAnyHost)
		if err != nil {
			return out, err
		}
		out.URLHost = host
		return out, nil
	case TypeSMTP:
		out.Host = strings.ToLower(strings.TrimSpace(in.Host))
		if net.ParseIP(out.Host) == nil && !hostnameRE.MatchString(out.Host) {
			return out, invalid("the mail server %q isn't a valid host name", in.Host)
		}
		out.Security = in.Security
		switch out.Security {
		case "":
			out.Security = SecuritySTARTTLS
		case SecuritySTARTTLS, SecurityTLS, SecurityNone:
		default:
			return out, invalid("security must be starttls, tls or none")
		}
		out.Port = in.Port
		if out.Port == 0 {
			out.Port = map[string]int{SecuritySTARTTLS: 587, SecurityTLS: 465, SecurityNone: 25}[out.Security]
		}
		if out.Port < 1 || out.Port > 65535 {
			return out, invalid("the port must be between 1 and 65535")
		}
		out.AllowAnyPort = in.AllowAnyPort
		if !SMTPPorts[out.Port] && !out.AllowAnyPort {
			return out, invalid("mail servers use port 25, 465, 587 or 2525; allow another port explicitly if yours differs")
		}
		out.Username = strings.TrimSpace(in.Username)
		if len(out.Username) > 256 || strings.ContainsAny(out.Username, "\r\n") {
			return out, invalid("the user name is too long")
		}
		if out.Username != "" && sec.Password == "" {
			return out, invalid("enter the password for %s (for Gmail, an app password)", out.Username)
		}
		if len(sec.Password) > 512 {
			return out, invalid("the password is too long")
		}
	case TypeSES:
		out.Region = strings.TrimSpace(in.Region)
		if !regionRE.MatchString(out.Region) {
			return out, invalid("the AWS region %q isn't valid (like us-east-1)", in.Region)
		}
		out.AccessKeyID = strings.TrimSpace(in.AccessKeyID)
		if !accessKeyRE.MatchString(out.AccessKeyID) {
			return out, invalid("the access key ID isn't valid (like AKIA…)")
		}
		if sec.SecretAccessKey == "" {
			return out, invalid("enter the secret access key")
		}
		if len(sec.SecretAccessKey) > 256 || strings.ContainsAny(sec.SecretAccessKey, " \r\n") {
			return out, invalid("the secret access key isn't valid")
		}
		out.ConfigurationSet = strings.TrimSpace(in.ConfigurationSet)
		if !configSetRE.MatchString(out.ConfigurationSet) {
			return out, invalid("the configuration set name isn't valid")
		}
	default:
		return out, invalid("unknown channel type %q", typ)
	}
	// Email (smtp, ses).
	out.From = strings.TrimSpace(in.From)
	if err := checkAddress("the sender", out.From); err != nil {
		return out, err
	}
	for _, t := range in.To {
		if t = strings.TrimSpace(t); t != "" {
			out.To = append(out.To, t)
		}
	}
	return out, checkRecipients(out.To)
}

func checkName(name string) (string, error) {
	name = oneLine(name)
	if name == "" {
		return "", invalid("give the channel a name")
	}
	if len(name) > 64 {
		return "", invalid("the name is at most 64 characters")
	}
	return name, nil
}

// channelRow is a channel with its opened secrets, for sending.
type channelRow struct {
	Channel
	secrets Secrets
}

// Channels keeps channels in the database with their secrets sealed.
type Channels struct {
	DB *store.DB
	// Keys gives the sealing key (secretbox purpose "notify"); nil uses a
	// key that lasts as long as the process (tests, development).
	Keys secretbox.Source
}

func (c *Channels) key(ctx context.Context) ([]byte, error) {
	if c.Keys == nil {
		c.Keys = secretbox.NewStaticSource()
	}
	return c.Keys.Key(ctx, secretPurpose)
}

func (c *Channels) seal(ctx context.Context, id int64, s Secrets) ([]byte, error) {
	if s == (Secrets{}) {
		return nil, nil
	}
	k, err := c.key(ctx)
	if err != nil {
		return nil, err
	}
	plain, _ := json.Marshal(s)
	return secretbox.Seal(k, plain, secretAAD(id))
}

func (c *Channels) open(ctx context.Context, id int64, sealed []byte) (Secrets, error) {
	var s Secrets
	if len(sealed) == 0 {
		return s, nil
	}
	k, err := c.key(ctx)
	if err != nil {
		return s, err
	}
	plain, err := secretbox.Open(k, sealed, secretAAD(id))
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(plain, &s)
}

const channelCols = `id, type, name, enabled, config, secrets, last_at, last_ok, last_error`

func (c *Channels) scan(ctx context.Context, sc interface{ Scan(...any) error }, withSecrets bool) (*channelRow, error) {
	var r channelRow
	var en int
	var cfg string
	var sealed []byte
	var lastAt sql.NullString
	var lastOK sql.NullInt64
	if err := sc.Scan(&r.ID, &r.Type, &r.Name, &en, &cfg, &sealed, &lastAt, &lastOK, &r.LastError); err != nil {
		return nil, err
	}
	r.Enabled = en != 0
	_ = json.Unmarshal([]byte(cfg), &r.Config)
	if lastAt.Valid {
		t := store.ParseTime(lastAt.String)
		r.LastAt = &t
	}
	if lastOK.Valid {
		ok := lastOK.Int64 != 0
		r.LastOK = &ok
	}
	r.SecretsSet = map[string]bool{}
	if len(sealed) > 0 {
		s, err := c.open(ctx, r.ID, sealed)
		if err != nil {
			// The value is still there; it needs entering again.
			r.LastError = secretbox.ErrOpen.Error() + "; enter the channel's secrets again"
		} else if withSecrets {
			r.secrets = s
		}
		if err == nil {
			r.SecretsSet["url"] = s.URL != ""
			r.SecretsSet["password"] = s.Password != ""
			r.SecretsSet["secretAccessKey"] = s.SecretAccessKey != ""
		}
	}
	return &r, nil
}

// List returns every channel, the desktop first.
func (c *Channels) List(ctx context.Context) ([]Channel, error) {
	rows, err := c.DB.QueryContext(ctx, `SELECT `+channelCols+` FROM notify_channels ORDER BY type != 'desktop', id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		r, err := c.scan(ctx, rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, r.Channel)
	}
	return out, rows.Err()
}

// Get returns one channel.
func (c *Channels) Get(ctx context.Context, id int64) (*Channel, error) {
	r, err := c.get(ctx, id, false)
	if err != nil {
		return nil, err
	}
	return &r.Channel, nil
}

func (c *Channels) get(ctx context.Context, id int64, withSecrets bool) (*channelRow, error) {
	r, err := c.scan(ctx, c.DB.QueryRowContext(ctx, `SELECT `+channelCols+` FROM notify_channels WHERE id = ?`, id), withSecrets)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

func applySecrets(s Secrets, in *SecretsInput) Secrets {
	if in == nil {
		return s
	}
	if in.URL != nil {
		s.URL = strings.TrimSpace(*in.URL)
	}
	if in.Password != nil {
		s.Password = *in.Password
	}
	if in.SecretAccessKey != nil {
		s.SecretAccessKey = strings.TrimSpace(*in.SecretAccessKey)
	}
	return s
}

// keepSecrets drops secrets a type doesn't use.
func keepSecrets(typ string, s Secrets) Secrets {
	switch typ {
	case TypeDiscord, TypeSlack, TypeTeams, TypeWebhook:
		return Secrets{URL: s.URL}
	case TypeSMTP:
		return Secrets{Password: s.Password}
	case TypeSES:
		return Secrets{SecretAccessKey: s.SecretAccessKey}
	}
	return Secrets{}
}

// Create adds a channel. New channels get warning-and-above alerts of
// every category until routing says otherwise.
func (c *Channels) Create(ctx context.Context, in ChannelInput) (*Channel, error) {
	if in.Type == TypeDesktop {
		return nil, invalid("there is only one desktop channel")
	}
	name, err := checkName(in.Name)
	if err != nil {
		return nil, err
	}
	sec := keepSecrets(in.Type, applySecrets(Secrets{}, in.Secrets))
	cfg, err := normalizeConfig(in.Type, in.Config, sec)
	if err != nil {
		return nil, err
	}
	enabled := in.Enabled == nil || *in.Enabled
	cfgJSON, _ := json.Marshal(cfg)
	tx, err := c.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := store.Now()
	res, err := tx.ExecContext(ctx, `INSERT INTO notify_channels (type, name, enabled, config, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		in.Type, name, boolInt(enabled), string(cfgJSON), now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	sealed, err := c.seal(ctx, id, sec)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE notify_channels SET secrets = ? WHERE id = ?`, sealed, id); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO notify_routes (category, channel_id, min_severity) VALUES ('*', ?, 'warning')`, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return c.Get(ctx, id)
}

// Update changes a channel's name, enabled state, settings and secrets.
// The type can't change.
func (c *Channels) Update(ctx context.Context, id int64, in ChannelInput) (*Channel, error) {
	cur, err := c.get(ctx, id, true)
	if err != nil {
		return nil, err
	}
	if in.Type != "" && in.Type != cur.Type {
		return nil, invalid("a channel's type can't change; add a new channel instead")
	}
	name := cur.Name
	if in.Name != "" {
		if name, err = checkName(in.Name); err != nil {
			return nil, err
		}
	}
	enabled := cur.Enabled
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	if cur.Type == TypeDesktop {
		_, err := c.DB.ExecContext(ctx, `UPDATE notify_channels SET name = ?, enabled = ?, updated_at = ? WHERE id = ?`, name, boolInt(enabled), store.Now(), id)
		if err != nil {
			return nil, err
		}
		return c.Get(ctx, id)
	}
	sec := keepSecrets(cur.Type, applySecrets(cur.secrets, in.Secrets))
	cfg, err := normalizeConfig(cur.Type, in.Config, sec)
	if err != nil {
		return nil, err
	}
	// A saved password or key only ever goes where it was entered for: a
	// new destination needs it typed again.
	if DestinationChanged(cur.Type, cur.Config, cfg) {
		switch {
		case cur.Type == TypeSMTP && cur.secrets.Password != "" && (in.Secrets == nil || in.Secrets.Password == nil):
			return nil, invalid("the mail server or user changed: enter the password again")
		case cur.Type == TypeSES && (in.Secrets == nil || in.Secrets.SecretAccessKey == nil):
			return nil, invalid("the region or access key changed: enter the secret access key again")
		}
	}
	sealed, err := c.seal(ctx, id, sec)
	if err != nil {
		return nil, err
	}
	cfgJSON, _ := json.Marshal(cfg)
	if _, err := c.DB.ExecContext(ctx, `UPDATE notify_channels SET name = ?, enabled = ?, config = ?, secrets = ?, updated_at = ?, last_error = '' WHERE id = ?`,
		name, boolInt(enabled), string(cfgJSON), sealed, store.Now(), id); err != nil {
		return nil, err
	}
	return c.Get(ctx, id)
}

// DestinationChanged reports whether a channel's settings now send its
// stored secret somewhere else (another mail server, port, encryption or
// user; another SES region or key).
func DestinationChanged(typ string, old, cur ChannelConfig) bool {
	switch typ {
	case TypeSMTP:
		return old.Host != cur.Host || old.Port != cur.Port || old.Security != cur.Security || old.Username != cur.Username || old.AllowAnyPort != cur.AllowAnyPort
	case TypeSES:
		return old.Region != cur.Region || old.AccessKeyID != cur.AccessKeyID
	}
	return false
}

// Delete removes a channel (not the desktop).
func (c *Channels) Delete(ctx context.Context, id int64) error {
	cur, err := c.get(ctx, id, false)
	if err != nil {
		return err
	}
	if cur.Type == TypeDesktop {
		return invalid("the desktop channel can't be removed; turn it off instead")
	}
	_, err = c.DB.ExecContext(ctx, `DELETE FROM notify_channels WHERE id = ?`, id)
	return err
}

func (c *Channels) recordResult(ctx context.Context, id int64, sendErr error) {
	msg := ""
	if sendErr != nil {
		msg = clip(sendErr.Error(), 500)
	}
	_, _ = c.DB.ExecContext(ctx, `UPDATE notify_channels SET last_at = ?, last_ok = ?, last_error = ? WHERE id = ?`,
		store.Now(), boolInt(sendErr == nil), msg, id)
}

// RouteOff as a route's MinSeverity: the channel gets nothing of that
// category (overriding "*").
const RouteOff = "off"

// Route is the lowest severity one channel gets for one category.
type Route struct {
	Category    string `json:"category"`
	ChannelID   int64  `json:"channelId"`
	MinSeverity string `json:"minSeverity"`
}

// Routes returns every routing rule.
func (c *Channels) Routes(ctx context.Context) ([]Route, error) {
	rows, err := c.DB.QueryContext(ctx, `SELECT category, channel_id, min_severity FROM notify_routes ORDER BY category, channel_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Route{}
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.Category, &r.ChannelID, &r.MinSeverity); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

var categoryRE = regexp.MustCompile(`^(\*|[a-z][a-z0-9_-]{0,31})$`)

// SetRoutes replaces every routing rule. A channel without a rule for an
// event's category (nor "*") doesn't get it.
func (c *Channels) SetRoutes(ctx context.Context, routes []Route) error {
	if len(routes) > 1000 {
		return invalid("too many routing rules")
	}
	chans, err := c.List(ctx)
	if err != nil {
		return err
	}
	known := map[int64]bool{}
	for _, ch := range chans {
		known[ch.ID] = true
	}
	seen := map[string]bool{}
	for _, r := range routes {
		if !categoryRE.MatchString(r.Category) {
			return invalid("invalid category %q", r.Category)
		}
		if !known[r.ChannelID] {
			return invalid("no channel %d", r.ChannelID)
		}
		if !ValidSeverity(r.MinSeverity) && r.MinSeverity != RouteOff {
			return invalid("minSeverity must be info, warning, critical or off")
		}
		k := r.Category + "\x00" + strconv.FormatInt(r.ChannelID, 10)
		if seen[k] {
			return invalid("two rules for %s on channel %d", r.Category, r.ChannelID)
		}
		seen[k] = true
	}
	tx, err := c.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM notify_routes`); err != nil {
		return err
	}
	for _, r := range routes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO notify_routes (category, channel_id, min_severity) VALUES (?, ?, ?)`,
			r.Category, r.ChannelID, r.MinSeverity); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// targets returns the enabled channels an event of this kind and severity
// goes to: a rule for its category wins over "*".
func (c *Channels) targets(ctx context.Context, kind, severity string) ([]*channelRow, error) {
	routes, err := c.Routes(ctx)
	if err != nil {
		return nil, err
	}
	cat := Category(kind)
	min := map[int64]string{}
	for _, r := range routes {
		if r.Category == "*" {
			if _, ok := min[r.ChannelID]; !ok {
				min[r.ChannelID] = r.MinSeverity
			}
		}
	}
	for _, r := range routes {
		if r.Category == cat {
			min[r.ChannelID] = r.MinSeverity
		}
	}
	ids := make([]int64, 0, len(min))
	for id := range min {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	var out []*channelRow
	for _, id := range ids {
		if m := min[id]; m == RouteOff || SeverityRank(severity) < SeverityRank(m) {
			continue
		}
		r, err := c.get(ctx, id, true)
		if err != nil || !r.Enabled {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
