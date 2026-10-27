// Package publish puts the HardyOS desktop and its apps on the internet
// (or only on the NetBird network) through NetBird's reverse proxy: the
// publishing settings, the services HardyOS keeps in NetBird (and only
// those), the setup check, and the sync that creates, changes and removes
// them.
//
// Every service points at this server's NetBird peer, at the HardyOS app
// gateway (api/appgateway.go) on the NetBird interface, over HTTPS with
// the desktop's self-signed certificate (the target skips verifying it;
// the hop runs inside WireGuard), with the original Host passed through
// and a shared secret header the gateway requires.
package publish

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/netbird"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Modes and sign-ins.
const (
	ModeOff     = "off"
	ModeNetBird = "netbird"
	ModePublic  = "public"

	AuthSSO      = "sso"
	AuthPassword = "password"
	AuthPIN      = "pin"
	AuthNone     = "none"
)

// DesktopKey is the desktop's row in remote_services; apps are "app:<id>".
const DesktopKey = "desktop"

// SSOKey is HardyOS's own sign-in provider (OIDC) at sso.<base>: always
// public with nothing in front, since NetBird's server and every browser
// signing in must reach it. hardyd routes that host to the provider.
const SSOKey = "sso"

// SSOLabel is the provider's name under the base domain.
const SSOLabel = "sso"

// FilesKey is files.<base>: share link pages (/s/...) for people without
// NetBird, and nothing else. Public with nothing in front (each link has
// its own token, password and limits); published while a share link is
// active or public share links are switched on.
const FilesKey = "files"

// FilesLabel is its name under the base domain.
const FilesLabel = "files"

// AppKey is an app's row key.
func AppKey(id string) string { return "app:" + id }

// Setting keys.
const (
	settingPublish = "remote.publish"
	settingToken   = "remote.token"  // sealed
	settingSecret  = "remote.secret" // sealed: the gateway header's value
)

// GatewayHeader carries the shared secret from NetBird's proxy to the
// gateway (a target's custom header).
const GatewayHeader = "X-Hardyos-Gateway"

// DefaultGatewayPort is the gateway's port on the NetBird address.
const DefaultGatewayPort = 44200

// Settings are the publishing settings.
type Settings struct {
	// Enabled: HardyOS keeps its services in NetBird. Off removes them.
	Enabled bool `json:"enabled"`
	// BaseDomain: apps are <app id>.<base>, the desktop <desktop>.<base>.
	BaseDomain string `json:"baseDomain"`
	// APIURL is NetBird's management API (default: the management URL the
	// server joined with).
	APIURL string `json:"apiUrl"`
	// Cluster is the proxy cluster the base domain is served by (from
	// NetBird's domain list; used when HardyOS registers the domain).
	Cluster string `json:"cluster"`
	// DesktopName is the desktop's name under the base domain.
	DesktopName string `json:"desktopName"`
	// DefaultMode is how apps without their own choice are published:
	// netbird, public or off.
	DefaultMode string `json:"defaultMode"`
	// PublicShareLinks keeps files.<base> published even while no share
	// link is active.
	PublicShareLinks bool `json:"publicShareLinks"`
	// Instance tags this server's services ("hardyos-<instance>-..."), so
	// two servers on one NetBird account never touch each other's.
	Instance string `json:"instance"`
}

// ServiceConfig is how one thing (the desktop or an app) is published.
type ServiceConfig struct {
	Mode   string   `json:"mode"`
	Auth   string   `json:"auth"`
	Groups []string `json:"groups"`
	// HardyOSSignIn: the gateway asks for a HardyOS sign-in before the
	// app (apps only; the desktop has its own sign-in page).
	HardyOSSignIn bool `json:"hardyosSignIn"`
	// HasSecret: a password or PIN is saved (never returned).
	HasSecret bool `json:"hasSecret"`
	// Default: the app follows the default mode (no choice of its own).
	Default bool `json:"default"`
}

// Record is what the last sync saw for one service.
type Record struct {
	Key       string `json:"key"`
	ServiceID string `json:"serviceId,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Status    string `json:"status,omitempty"`
	Error     string `json:"error,omitempty"`
	SyncedAt  string `json:"syncedAt,omitempty"`
	applied   string
}

// Store keeps publishing state in hardyd's database.
type Store struct {
	DB     *store.DB
	Sealer *Sealer
}

// ErrNoDB: no database (tests without one).
var ErrNoDB = errors.New("no database")

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Defaults fills in what an unset setting means.
func (s *Settings) Defaults() {
	if s.DesktopName == "" {
		s.DesktopName = "nas"
	}
	if s.DefaultMode == "" {
		s.DefaultMode = ModeNetBird
	}
}

// Validate checks settings an administrator saves.
func (s Settings) Validate() error {
	if s.BaseDomain != "" && !netbird.ValidDomain(s.BaseDomain) {
		return fmt.Errorf("%q isn't a domain like home.example.net", s.BaseDomain)
	}
	if s.Enabled && s.BaseDomain == "" {
		return errors.New("choose the base domain first")
	}
	if !netbird.ValidDNSLabel(s.DesktopName) {
		return errors.New("the desktop's name is letters, digits and dashes (like nas)")
	}
	if s.DesktopName == SSOLabel || s.DesktopName == FilesLabel {
		return errors.New(s.DesktopName + " is HardyOS's own name under the base domain: choose another for the desktop")
	}
	if s.APIURL != "" {
		if _, err := netbird.NormalizeBaseURL(s.APIURL); err != nil {
			return err
		}
	}
	switch s.DefaultMode {
	case ModeOff, ModeNetBird, ModePublic:
	default:
		return fmt.Errorf("unknown default %q", s.DefaultMode)
	}
	return nil
}

// Load reads the settings (defaults when none are saved).
func (st *Store) Load(ctx context.Context) (Settings, error) {
	var s Settings
	if st.DB == nil {
		return s, ErrNoDB
	}
	v, err := st.DB.GetSetting(ctx, settingPublish)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return s, err
	}
	if v != "" {
		if err := json.Unmarshal([]byte(v), &s); err != nil {
			return s, fmt.Errorf("publishing settings: %w", err)
		}
	}
	s.Defaults()
	return s, nil
}

// Save stores the settings, giving the server its instance tag the first
// time.
func (st *Store) Save(ctx context.Context, s Settings) (Settings, error) {
	if st.DB == nil {
		return s, ErrNoDB
	}
	s.Defaults()
	if err := s.Validate(); err != nil {
		return s, err
	}
	if s.Instance == "" {
		old, _ := st.Load(ctx)
		s.Instance = old.Instance
	}
	if s.Instance == "" {
		s.Instance = randomHex(3)
	}
	b, _ := json.Marshal(s)
	if err := st.DB.SetSetting(ctx, settingPublish, string(b)); err != nil {
		return s, err
	}
	// The names HardyOS's sign-in provider builds its issuer from
	// (https://sso.<base>), read by internal/oidc: only while published.
	base := ""
	if s.Enabled {
		base = s.BaseDomain
	}
	if err := st.DB.SetSetting(ctx, SettingBaseDomain, base); err != nil {
		return s, err
	}
	return s, st.DB.SetSetting(ctx, SettingDesktopName, s.DesktopName)
}

// Settings the sign-in provider (internal/oidc, part B) reads for its
// issuer: the base domain while publishing is on, and the desktop's name.
const (
	SettingBaseDomain  = "remote.base_domain"
	SettingDesktopName = "remote.desktop_name"
)

func (st *Store) sealed(ctx context.Context, key string) (string, error) {
	if st.DB == nil {
		return "", ErrNoDB
	}
	v, err := st.DB.GetSetting(ctx, key)
	if errors.Is(err, store.ErrNotFound) || v == "" {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return st.Sealer.Open(key, v)
}

func (st *Store) setSealed(ctx context.Context, key, value string) error {
	if st.DB == nil {
		return ErrNoDB
	}
	v, err := st.Sealer.Seal(key, value)
	if err != nil {
		return err
	}
	return st.DB.SetSetting(ctx, key, v)
}

// SealedSetting reads a sealed setting ("" when unset).
func (st *Store) SealedSetting(ctx context.Context, key string) (string, error) {
	return st.sealed(ctx, key)
}

// SetSealedSetting saves a setting sealed.
func (st *Store) SetSealedSetting(ctx context.Context, key, value string) error {
	return st.setSealed(ctx, key, value)
}

// Token is the NetBird access token ("" when none is saved).
func (st *Store) Token(ctx context.Context) (string, error) { return st.sealed(ctx, settingToken) }

// HasToken reports whether a token is saved (readable or not).
func (st *Store) HasToken(ctx context.Context) bool {
	if st.DB == nil {
		return false
	}
	v, err := st.DB.GetSetting(ctx, settingToken)
	return err == nil && v != ""
}

// SetToken saves (or, with "", forgets) the access token.
func (st *Store) SetToken(ctx context.Context, token string) error {
	return st.setSealed(ctx, settingToken, token)
}

// GatewaySecret is the shared secret NetBird's proxy sends the gateway,
// made on first use.
func (st *Store) GatewaySecret(ctx context.Context) (string, error) {
	v, err := st.sealed(ctx, settingSecret)
	if errors.Is(err, ErrSealed) {
		v = "" // restored from another server: make a new one (the sync updates every service)
	} else if err != nil {
		return "", err
	}
	if v != "" {
		return v, nil
	}
	v = randomHex(32)
	return v, st.setSealed(ctx, settingSecret, v)
}

type row struct {
	cfg    ServiceConfig
	rec    Record
	secret string // sealed
	set    bool   // the row exists
	mode   string // as stored ('' = default)
}

func (st *Store) rows(ctx context.Context) (map[string]*row, error) {
	if st.DB == nil {
		return nil, ErrNoDB
	}
	rs, err := st.DB.QueryContext(ctx, `SELECT key, mode, auth, groups, hardyos_signin, secret, service_id, domain, status, error, applied, synced_at FROM remote_services`)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	out := map[string]*row{}
	for rs.Next() {
		r := &row{set: true}
		var groups string
		var signin int
		if err := rs.Scan(&r.rec.Key, &r.mode, &r.cfg.Auth, &groups, &signin, &r.secret, &r.rec.ServiceID, &r.rec.Domain,
			&r.rec.Status, &r.rec.Error, &r.rec.applied, &r.rec.SyncedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(groups), &r.cfg.Groups)
		r.cfg.HardyOSSignIn = signin != 0
		r.cfg.HasSecret = r.secret != ""
		out[r.rec.Key] = r
	}
	return out, rs.Err()
}

// resolve fills in what an unset choice means for key.
func resolve(key string, r *row, s Settings) ServiceConfig {
	if key == SSOKey || key == FilesKey {
		return ServiceConfig{Mode: ModePublic, Auth: AuthNone, Groups: []string{}, Default: true}
	}
	c := ServiceConfig{HardyOSSignIn: true}
	if r != nil {
		c = r.cfg
	}
	if r == nil || r.mode == "" {
		c.Default = true
		if key == DesktopKey {
			// The desktop has administration in it: NetBird devices only
			// unless an administrator chooses otherwise.
			c.Mode = ModeNetBird
		} else {
			c.Mode = s.DefaultMode
		}
	} else {
		c.Mode = r.mode
	}
	if c.Auth == "" {
		if key == DesktopKey {
			c.Auth = AuthNone // the desktop has its own sign-in page
		} else {
			c.Auth = AuthSSO
		}
	}
	if c.Groups == nil {
		c.Groups = []string{}
	}
	if key == DesktopKey {
		c.HardyOSSignIn = false
	}
	return c
}

// Config is how key is published (its own choice or the default).
func (st *Store) Config(ctx context.Context, key string) (ServiceConfig, error) {
	s, err := st.Load(ctx)
	if err != nil {
		return ServiceConfig{}, err
	}
	rows, err := st.rows(ctx)
	if err != nil {
		return ServiceConfig{}, err
	}
	return resolve(key, rows[key], s), nil
}

// ValidateConfig checks a choice an administrator saves.
func ValidateConfig(c ServiceConfig, secret *string) error {
	switch c.Mode {
	case "", ModeOff, ModeNetBird, ModePublic:
	default:
		return fmt.Errorf("unknown mode %q", c.Mode)
	}
	switch c.Auth {
	case "", AuthSSO, AuthNone:
	case AuthPassword:
		if secret != nil && len(*secret) < 8 {
			return errors.New("use a password of at least 8 characters")
		}
	case AuthPIN:
		if secret != nil && (len(*secret) < 4 || len(*secret) > 12 || strings.Trim(*secret, "0123456789") != "") {
			return errors.New("a PIN is 4 to 12 digits")
		}
	default:
		return fmt.Errorf("unknown sign-in %q", c.Auth)
	}
	if len(c.Groups) > 50 {
		return errors.New("too many groups")
	}
	for _, g := range c.Groups {
		if g == "" || len(g) > 64 || strings.ContainsAny(g, " /\\\"'") {
			return fmt.Errorf("%q isn't a NetBird group id", g)
		}
	}
	return nil
}

// SetConfig saves how key is published. secret (password or PIN) is kept
// when nil, cleared when "". Mode "" goes back to the default.
func (st *Store) SetConfig(ctx context.Context, key string, c ServiceConfig, secret *string) error {
	if st.DB == nil {
		return ErrNoDB
	}
	if err := ValidateConfig(c, secret); err != nil {
		return err
	}
	if c.Mode == ModePublic && (c.Auth == AuthPassword || c.Auth == AuthPIN) && secret == nil {
		cur, err := st.rows(ctx)
		if err != nil {
			return err
		}
		if r := cur[key]; r == nil || r.secret == "" || r.cfg.Auth != c.Auth {
			return fmt.Errorf("enter the %s", map[string]string{AuthPassword: "password", AuthPIN: "PIN"}[c.Auth])
		}
	}
	groups, _ := json.Marshal(nonNil(c.Groups))
	signin := 0
	if c.HardyOSSignIn {
		signin = 1
	}
	_, err := st.DB.ExecContext(ctx, `INSERT INTO remote_services (key, mode, auth, groups, hardyos_signin) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET mode = excluded.mode, auth = excluded.auth, groups = excluded.groups, hardyos_signin = excluded.hardyos_signin`,
		key, c.Mode, c.Auth, string(groups), signin)
	if err != nil || secret == nil {
		return err
	}
	sealed, err := st.Sealer.Seal("remote_services/"+key, *secret)
	if err != nil {
		return err
	}
	_, err = st.DB.ExecContext(ctx, `UPDATE remote_services SET secret = ? WHERE key = ?`, sealed, key)
	return err
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Forget removes key's row (an app was removed: its choice goes too).
func (st *Store) Forget(ctx context.Context, key string) error {
	if st.DB == nil {
		return ErrNoDB
	}
	_, err := st.DB.ExecContext(ctx, `DELETE FROM remote_services WHERE key = ?`, key)
	return err
}

// Records returns what the last sync saw, by key.
func (st *Store) Records(ctx context.Context) (map[string]Record, error) {
	rows, err := st.rows(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]Record{}
	for k, r := range rows {
		out[k] = r.rec
	}
	return out, nil
}

func (st *Store) secretOf(r *row) (string, error) {
	if r == nil || r.secret == "" {
		return "", nil
	}
	return st.Sealer.Open("remote_services/"+r.rec.Key, r.secret)
}

func (st *Store) saveRecord(ctx context.Context, rec Record) error {
	_, err := st.DB.ExecContext(ctx, `INSERT INTO remote_services (key, service_id, domain, status, error, applied, synced_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET service_id = excluded.service_id, domain = excluded.domain, status = excluded.status,
		error = excluded.error, applied = excluded.applied, synced_at = excluded.synced_at`,
		rec.Key, rec.ServiceID, rec.Domain, rec.Status, rec.Error, rec.applied, rec.SyncedAt)
	return err
}

// rowsExist is used by tests.
func (st *Store) exists(ctx context.Context, key string) bool {
	var k string
	err := st.DB.QueryRowContext(ctx, `SELECT key FROM remote_services WHERE key = ?`, key).Scan(&k)
	return !errors.Is(err, sql.ErrNoRows) && err == nil
}
