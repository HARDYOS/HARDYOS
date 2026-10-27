package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Client kinds.
const (
	// KindConfidential clients authenticate with a secret (a server: NetBird's
	// management, its embedded identity provider).
	KindConfidential = "confidential"
	// KindPublic clients can't keep a secret (a browser app, a CLI) and must
	// use PKCE.
	KindPublic = "public"
)

// Client is an app allowed to sign people in through HardyOS.
type Client struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	Kind                   string   `json:"kind"`
	RedirectURIs           []string `json:"redirectUris"`
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris"`
	// AllowedGroups limits sign-in to members of these domain groups
	// (NETBIOS\group); empty lets every account in.
	AllowedGroups []string `json:"allowedGroups"`
	// FirstParty clients (set up by an administrator for this server's own
	// use, such as NetBird) skip the consent screen.
	FirstParty bool   `json:"firstParty"`
	Preset     string `json:"preset"`
	// ManagedBy is set for clients another part of HardyOS keeps (Remote
	// Access); administrators see them but change them there.
	ManagedBy string `json:"managedBy"`
	Disabled  bool   `json:"disabled"`
	HasSecret bool   `json:"hasSecret"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`

	secretHash string
}

// ClientSpec is what an administrator (or Ensure) sets on a client.
type ClientSpec struct {
	Name                   string   `json:"name"`
	Kind                   string   `json:"kind"`
	RedirectURIs           []string `json:"redirectUris"`
	PostLogoutRedirectURIs []string `json:"postLogoutRedirectUris"`
	AllowedGroups          []string `json:"allowedGroups"`
	FirstParty             bool     `json:"firstParty"`
	Preset                 string   `json:"preset"`
	Disabled               bool     `json:"disabled"`
}

// Errors from the client store.
var (
	ErrNotFound = errors.New("no such sign-in client")
	ErrManaged  = errors.New("this client is kept by Remote Access; change it there")
)

// ValidationError lists every problem with a ClientSpec.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string { return strings.Join(e.Problems, "; ") }

// Clients reads and writes sign-in clients.
type Clients struct {
	DB *store.DB
	// OnChange runs after every change (the provider drops cached state).
	OnChange func()
}

const clientCols = `id, name, kind, secret_hash, redirect_uris, post_logout_uris, allowed_groups, first_party, preset, managed_by, disabled, created_at, updated_at`

func scanClient(row interface{ Scan(...any) error }) (*Client, error) {
	var c Client
	var redirects, logouts, groups string
	var fp, dis int
	if err := row.Scan(&c.ID, &c.Name, &c.Kind, &c.secretHash, &redirects, &logouts, &groups, &fp, &c.Preset, &c.ManagedBy, &dis, &c.CreatedAt, &c.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	c.FirstParty, c.Disabled = fp != 0, dis != 0
	c.HasSecret = c.secretHash != ""
	c.RedirectURIs = jsonList(redirects)
	c.PostLogoutRedirectURIs = jsonList(logouts)
	c.AllowedGroups = jsonList(groups)
	return &c, nil
}

func jsonList(s string) []string {
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	if out == nil {
		out = []string{}
	}
	return out
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// List returns every client, by name.
func (c *Clients) List(ctx context.Context) ([]*Client, error) {
	rows, err := c.DB.QueryContext(ctx, `SELECT `+clientCols+` FROM oidc_clients ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Client{}
	for rows.Next() {
		cl, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cl)
	}
	return out, rows.Err()
}

// Get returns one client.
func (c *Clients) Get(ctx context.Context, id string) (*Client, error) {
	return scanClient(c.DB.QueryRowContext(ctx, `SELECT `+clientCols+` FROM oidc_clients WHERE id = ?`, id))
}

// Create adds a client. For a confidential client the secret is returned:
// this is the only time it exists outside the caller (only a hash is kept).
func (c *Clients) Create(ctx context.Context, spec ClientSpec) (*Client, string, error) {
	return c.create(ctx, spec, "")
}

func (c *Clients) create(ctx context.Context, spec ClientSpec, managedBy string) (*Client, string, error) {
	spec, err := normalize(spec)
	if err != nil {
		return nil, "", err
	}
	id := newClientID()
	secret, hash := "", ""
	if spec.Kind == KindConfidential {
		secret, hash = newSecret()
	}
	now := store.Now()
	_, err = c.DB.ExecContext(ctx, `INSERT INTO oidc_clients (`+clientCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, spec.Name, spec.Kind, hash, jsonString(spec.RedirectURIs), jsonString(spec.PostLogoutRedirectURIs),
		jsonString(spec.AllowedGroups), boolInt(spec.FirstParty), spec.Preset, managedBy, boolInt(spec.Disabled), now, now)
	if err != nil {
		return nil, "", err
	}
	c.changed()
	cl, err := c.Get(ctx, id)
	return cl, secret, err
}

// Update replaces a client's settings. A client that changes from public to
// confidential gets a secret (returned); one that becomes public loses it.
func (c *Clients) Update(ctx context.Context, id string, spec ClientSpec) (*Client, string, error) {
	cur, err := c.Get(ctx, id)
	if err != nil {
		return nil, "", err
	}
	if cur.ManagedBy != "" {
		return nil, "", ErrManaged
	}
	return c.update(ctx, cur, spec)
}

func (c *Clients) update(ctx context.Context, cur *Client, spec ClientSpec) (*Client, string, error) {
	spec, err := normalize(spec)
	if err != nil {
		return nil, "", err
	}
	secret, hash := "", cur.secretHash
	switch {
	case spec.Kind == KindPublic:
		hash = ""
	case hash == "":
		secret, hash = newSecret()
	}
	_, err = c.DB.ExecContext(ctx, `UPDATE oidc_clients SET name = ?, kind = ?, secret_hash = ?, redirect_uris = ?, post_logout_uris = ?,
		allowed_groups = ?, first_party = ?, preset = ?, disabled = ?, updated_at = ? WHERE id = ?`,
		spec.Name, spec.Kind, hash, jsonString(spec.RedirectURIs), jsonString(spec.PostLogoutRedirectURIs),
		jsonString(spec.AllowedGroups), boolInt(spec.FirstParty), spec.Preset, boolInt(spec.Disabled), store.Now(), cur.ID)
	if err != nil {
		return nil, "", err
	}
	if spec.Disabled && !cur.Disabled {
		if err := revokeClientGrants(ctx, c.DB, cur.ID); err != nil {
			return nil, "", err
		}
	}
	c.changed()
	cl, err := c.Get(ctx, cur.ID)
	return cl, secret, err
}

// NewSecret replaces a confidential client's secret and returns the new one.
func (c *Clients) NewSecret(ctx context.Context, id string) (string, error) {
	cur, err := c.Get(ctx, id)
	if err != nil {
		return "", err
	}
	if cur.Kind != KindConfidential {
		return "", &ValidationError{Problems: []string{"public clients have no secret"}}
	}
	secret, hash := newSecret()
	if _, err := c.DB.ExecContext(ctx, `UPDATE oidc_clients SET secret_hash = ?, updated_at = ? WHERE id = ?`, hash, store.Now(), id); err != nil {
		return "", err
	}
	c.changed()
	return secret, nil
}

// Delete removes a client, its grants, tokens and consents.
func (c *Clients) Delete(ctx context.Context, id string) error {
	cur, err := c.Get(ctx, id)
	if err != nil {
		return err
	}
	if cur.ManagedBy != "" {
		return ErrManaged
	}
	return c.delete(ctx, id)
}

func (c *Clients) delete(ctx context.Context, id string) error {
	res, err := c.DB.ExecContext(ctx, `DELETE FROM oidc_clients WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	c.changed()
	return nil
}

// Ensure keeps a client for another part of HardyOS (Remote Access asks for
// one per use, "public app sign-in" for example), keyed by key: it's
// created the first time, with a secret that is returned only then, and
// its name, redirect URIs and allowed groups are brought up to date on
// later calls (secret unchanged, "" returned). Ensured clients are
// confidential and first-party; administrators see them in Control Panel
// but can't change or delete them (ErrManaged).
func (c *Clients) Ensure(ctx context.Context, key, name string, redirectURIs, groups []string) (clientID, secret string, err error) {
	if key == "" || len(key) > 64 {
		return "", "", errors.New("oidc: Ensure needs a key of 1-64 characters")
	}
	spec := ClientSpec{Name: name, Kind: KindConfidential, RedirectURIs: redirectURIs, AllowedGroups: groups, FirstParty: true, Preset: "managed"}
	cur, err := scanClient(c.DB.QueryRowContext(ctx, `SELECT `+clientCols+` FROM oidc_clients WHERE managed_by = ?`, key))
	switch {
	case errors.Is(err, ErrNotFound):
		cl, secret, err := c.create(ctx, spec, key)
		if err != nil {
			return "", "", err
		}
		return cl.ID, secret, nil
	case err != nil:
		return "", "", err
	}
	spec.Disabled = cur.Disabled
	if _, _, err := c.update(ctx, cur, spec); err != nil {
		return "", "", err
	}
	return cur.ID, "", nil
}

// EnsuredSecret gives a client kept with Ensure a new secret (for when the
// caller lost the first one).
func (c *Clients) EnsuredSecret(ctx context.Context, key string) (clientID, secret string, err error) {
	var id string
	if err := c.DB.QueryRowContext(ctx, `SELECT id FROM oidc_clients WHERE managed_by = ?`, key).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrNotFound
		}
		return "", "", err
	}
	s, err := c.NewSecret(ctx, id)
	return id, s, err
}

// Forget removes a client kept with Ensure (nothing happens when there's none).
func (c *Clients) Forget(ctx context.Context, key string) error {
	var id string
	err := c.DB.QueryRowContext(ctx, `SELECT id FROM oidc_clients WHERE managed_by = ?`, key).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return c.delete(ctx, id)
}

// checkSecret compares a presented secret with the stored hash in constant
// time.
func (cl *Client) checkSecret(secret string) bool {
	if cl.secretHash == "" || secret == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashHex(secret)), []byte(cl.secretHash)) == 1
}

func (c *Clients) changed() {
	if c.OnChange != nil {
		c.OnChange()
	}
}

func newClientID() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return "hos-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

// newSecret is 256 random bits. A hash this strong can't be brute-forced,
// so SHA-256 is enough (no slow password hash needed).
func newSecret() (secret, hash string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	secret = base64.RawURLEncoding.EncodeToString(b)
	return secret, hashHex(secret)
}

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

var groupRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,14}\\[^\\/:*?"<>|\x00-\x1f]{1,64}$`)

// normalize checks a spec and returns it cleaned up.
func normalize(s ClientSpec) (ClientSpec, error) {
	var problems []string
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" || utf8.RuneCountInString(s.Name) > 64 {
		problems = append(problems, "give the client a name of 1-64 characters")
	}
	if s.Kind == "" {
		s.Kind = KindConfidential
	}
	if s.Kind != KindConfidential && s.Kind != KindPublic {
		problems = append(problems, "kind must be confidential or public")
	}
	s.RedirectURIs, problems = cleanURIs(s.RedirectURIs, "redirect URI", s.Kind, problems)
	if len(s.RedirectURIs) == 0 {
		problems = append(problems, "add at least one redirect URI")
	}
	s.PostLogoutRedirectURIs, problems = cleanURIs(s.PostLogoutRedirectURIs, "sign-out redirect URI", s.Kind, problems)
	groups := []string{}
	for _, g := range s.AllowedGroups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if !groupRE.MatchString(g) {
			problems = append(problems, fmt.Sprintf("%q isn't a domain group: write it as DOMAIN\\group", g))
			continue
		}
		if !slices.ContainsFunc(groups, func(x string) bool { return strings.EqualFold(x, g) }) {
			groups = append(groups, g)
		}
	}
	if len(groups) > 50 {
		problems = append(problems, "at most 50 groups")
	}
	s.AllowedGroups = groups
	if len(s.Preset) > 32 {
		problems = append(problems, "preset name too long")
	}
	if len(problems) > 0 {
		return s, &ValidationError{Problems: problems}
	}
	return s, nil
}

// cleanURIs validates redirect URIs: absolute, no fragment, no user info,
// HTTPS (plain HTTP only to this computer, for CLIs), at most 20, at most
// 1000 characters. They're stored exactly as written and matched exactly.
func cleanURIs(in []string, what, kind string, problems []string) ([]string, []string) {
	out := []string{}
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if p := checkRedirectURI(raw, kind); p != "" {
			problems = append(problems, fmt.Sprintf("%s %q: %s", what, raw, p))
			continue
		}
		if !slices.Contains(out, raw) {
			out = append(out, raw)
		}
	}
	if len(out) > 20 {
		problems = append(problems, fmt.Sprintf("at most 20 of each kind of %s", what))
	}
	return out, problems
}

func checkRedirectURI(raw, kind string) string {
	if len(raw) > 1000 {
		return "too long"
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return "must be a full address such as https://vpn.example.net/callback"
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return "can't have a #fragment"
	}
	if u.User != nil {
		return "can't contain a user name or password"
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return "must use https (plain http only for localhost, for command-line tools)"
		}
		if kind == KindConfidential {
			// A server that keeps a secret doesn't sign in through a
			// browser on this computer.
			return "plain http is only for public clients (command-line tools)"
		}
	default:
		return "must use https"
	}
	if strings.ContainsAny(u.Host, "*") {
		return "wildcards aren't allowed: list every address"
	}
	return ""
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
