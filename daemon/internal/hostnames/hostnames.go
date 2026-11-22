// Package hostnames gives the desktop, the sign-in provider, the office
// editor, Photos, webmail and every app with a web page its own name under
// the base domain (decisions 450-459), with a Let's Encrypt wildcard
// certificate for *.<base> got through the DNS-01 challenge in Cloudflare.
//
// The Cloudflare token is hardyd-priv's (priv.OpDNS*): this package asks
// root to publish and remove challenge records and never sees the token.
// The certificate's key is hardyd's: hardyd terminates TLS.
package hostnames

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cfdns"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/tlscert"
)

// HardyOS's own names under the base (an app with one of these ids is
// reached by its id only through NetBird publishing, never here).
const (
	SSOLabel    = "sso"
	FilesLabel  = "files"
	OfficeLabel = "office"
	PhotosLabel = "photos"
	MailLabel   = "mail"
)

// Reserved reports whether label is one of HardyOS's own names (the
// desktop's is reserved too, by the caller).
func Reserved(label string) bool {
	switch label {
	case SSOLabel, FilesLabel, OfficeLabel, PhotosLabel, MailLabel:
		return true
	}
	return false
}

// RenewBefore is how long before expiry the certificate is renewed.
const RenewBefore = 30 * 24 * time.Hour

// RetryAfter is how long a failed issuance waits before trying again by
// itself (Let's Encrypt limits failed validations).
const RetryAfter = 6 * time.Hour

// DNS is root's DNS operations as hardyd uses them.
type DNS interface {
	Status(ctx context.Context) (*priv.DNSStatus, error)
	Present(ctx context.Context, name, value string) (id string, err error)
	Cleanup(ctx context.Context, id string) error
}

// PrivDNS is DNS through hardyd-priv.
type PrivDNS struct{ Priv *priv.Client }

// Status implements DNS.
func (p PrivDNS) Status(ctx context.Context) (*priv.DNSStatus, error) {
	var st priv.DNSStatus
	if err := p.Priv.Call(ctx, priv.OpDNSStatus, struct{}{}, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Present implements DNS.
func (p PrivDNS) Present(ctx context.Context, name, value string) (string, error) {
	var r priv.DNSACMEPresentResult
	if err := p.Priv.Call(ctx, priv.OpDNSACMEPresent, priv.DNSACMEPresentArgs{Name: name, Value: value}, &r); err != nil {
		return "", err
	}
	return r.ID, nil
}

// Cleanup implements DNS.
func (p PrivDNS) Cleanup(ctx context.Context, id string) error {
	return p.Priv.Call(ctx, priv.OpDNSACMECleanup, priv.DNSACMECleanupArgs{ID: id}, nil)
}

// Settings are Control Panel › Hostnames' choices.
type Settings struct {
	// Enabled: serve the hostnames once the certificate is there (and keep
	// it renewed). Off: everything as before (ports, self-signed).
	Enabled bool `json:"enabled"`
	// Email is Let's Encrypt's contact for expiry warnings ("" = none).
	Email string `json:"email"`
	// Staging uses Let's Encrypt's staging server (untrusted certificates,
	// for trying the setup out without hitting rate limits).
	Staging bool `json:"staging"`
}

// Validate checks the settings.
func (s Settings) Validate() error {
	if s.Email != "" {
		a, err := mail.ParseAddress(s.Email)
		if err != nil || a.Address != s.Email || len(s.Email) > 254 {
			return errors.New("the contact address isn't an email address")
		}
	}
	return nil
}

const (
	settingKey     = "hostnames.settings"
	settingAccount = "hostnames.acme_account"
	sealPurpose    = "hostnames"
)

// Cert is one issuance (or failed attempt).
type Cert struct {
	Names     string    `json:"names"`
	Serial    string    `json:"serial,omitempty"`
	NotBefore time.Time `json:"notBefore,omitzero"`
	NotAfter  time.Time `json:"notAfter,omitzero"`
	Issuer    string    `json:"issuer,omitempty"`
	Error     string    `json:"error,omitempty"`
	At        time.Time `json:"at"`
}

// Store keeps the settings, the sealed ACME account key and the issuance
// history in hardyd's database.
type Store struct {
	DB   *store.DB
	Keys secretbox.Source
}

// Load returns the settings.
func (st *Store) Load(ctx context.Context) (Settings, error) {
	var s Settings
	v, err := st.DB.GetSetting(ctx, settingKey)
	if errors.Is(err, store.ErrNotFound) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal([]byte(v), &s)
}

// Save stores the settings.
func (st *Store) Save(ctx context.Context, s Settings) error {
	b, _ := json.Marshal(s)
	return st.DB.SetSetting(ctx, settingKey, string(b))
}

// AccountKey returns the ACME account key, making (and sealing) one the
// first time.
func (st *Store) AccountKey(ctx context.Context) (crypto.Signer, error) {
	key, err := st.Keys.Key(ctx, sealPurpose)
	if err != nil {
		return nil, err
	}
	aad := []byte(settingAccount)
	if v, err := st.DB.GetSetting(ctx, settingAccount); err == nil {
		raw, err := hex.DecodeString(v)
		if err == nil {
			if plain, err := secretbox.Open(key, raw, aad); err == nil {
				if k, err := x509.ParseECPrivateKey(plain); err == nil {
					return k, nil
				}
			}
		}
		// Can't be opened (a restore without keys): a new account.
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	k, err := NewKey()
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	sealed, err := secretbox.Seal(key, der, aad)
	if err != nil {
		return nil, err
	}
	return k, st.DB.SetSetting(ctx, settingAccount, hex.EncodeToString(sealed))
}

// Record adds an issuance (or failure) to the history (the newest 50 are
// kept).
func (st *Store) Record(ctx context.Context, c Cert) error {
	nb, na := "", ""
	if !c.NotBefore.IsZero() {
		nb = c.NotBefore.UTC().Format(time.RFC3339)
	}
	if !c.NotAfter.IsZero() {
		na = c.NotAfter.UTC().Format(time.RFC3339)
	}
	if _, err := st.DB.ExecContext(ctx, `INSERT INTO hostname_certs (names, serial, not_before, not_after, issuer, error, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, c.Names, c.Serial, nb, na, c.Issuer, clip(c.Error, 500), store.Now()); err != nil {
		return err
	}
	_, err := st.DB.ExecContext(ctx, `DELETE FROM hostname_certs WHERE id NOT IN (SELECT id FROM hostname_certs ORDER BY id DESC LIMIT 50)`)
	return err
}

// Last returns the newest issuance and the newest failure after it (each
// nil when there is none).
func (st *Store) Last(ctx context.Context) (ok, failed *Cert, err error) {
	rows, err := st.DB.QueryContext(ctx, `SELECT names, serial, not_before, not_after, issuer, error, created_at FROM hostname_certs ORDER BY id DESC LIMIT 50`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c Cert
		var nb, na, at string
		if err := rows.Scan(&c.Names, &c.Serial, &nb, &na, &c.Issuer, &c.Error, &at); err != nil {
			return nil, nil, err
		}
		c.NotBefore, _ = time.Parse(time.RFC3339, nb)
		c.NotAfter, _ = time.Parse(time.RFC3339, na)
		c.At, _ = time.Parse(time.RFC3339Nano, at)
		if c.At.IsZero() {
			c.At, _ = time.Parse(time.RFC3339, at)
		}
		if c.Error != "" {
			if ok == nil && failed == nil {
				cc := c
				failed = &cc
			}
			continue
		}
		cc := c
		ok = &cc
		break
	}
	if err := rows.Err(); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, err
	}
	return ok, failed, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Manager issues, installs and renews the wildcard certificate.
type Manager struct {
	Store *Store
	DNS   DNS
	// Certs serves the certificate; Dir is where it is kept (next to the
	// self-signed one).
	Certs *tlscert.Store
	Dir   string
	// Directory replaces Let's Encrypt's (tests: a fake ACME server).
	Directory string
	// Resolver checks public DNS for the challenge (nil: Let's Encrypt is
	// asked straight away; production passes public resolvers).
	Resolver TXTResolver
	// Settle is the issuer's wait after the record shows (tests: tiny).
	Settle time.Duration
	Now    func() time.Time

	mu sync.Mutex
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Names is what the certificate is for.
func Names(base string) []string { return []string{"*." + base} }

// LoadInstalled puts the certificate kept on disk in service (at start).
func (m *Manager) LoadInstalled(ctx context.Context) error {
	st, err := m.DNS.Status(ctx)
	if err != nil {
		return err
	}
	if !st.Set || st.Base == "" {
		return m.Certs.SetWildcard("", nil)
	}
	c, err := tlscert.LoadWildcard(m.Dir, st.Base, m.now())
	if err != nil {
		_ = m.Certs.SetWildcard("", nil)
		return err
	}
	return m.Certs.SetWildcard(st.Base, c)
}

// Due reports whether a certificate for base should be got now: none, one
// for another base, or one expiring within RenewBefore.
func (m *Manager) Due(base string) bool {
	b, leaf := m.Certs.Wildcard()
	return leaf == nil || b != base || m.now().Add(RenewBefore).After(leaf.NotAfter)
}

// Issue gets a certificate for the base root's token is for, installs it and
// records it. It is the job's work (hostnames.issue).
func (m *Manager) Issue(ctx context.Context, progress func(float64, string)) (*Cert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if progress == nil {
		progress = func(float64, string) {}
	}
	set, err := m.Store.Load(ctx)
	if err != nil {
		return nil, err
	}
	st, err := m.DNS.Status(ctx)
	if err != nil {
		return nil, err
	}
	if !st.Set || !cfdns.ValidDomain(st.Base) {
		return nil, errors.New("no Cloudflare token is set (Control Panel › Hostnames)")
	}
	base := st.Base
	names := Names(base)
	fail := func(err error) (*Cert, error) {
		_ = m.Store.Record(ctx, Cert{Names: strings.Join(names, " "), Error: err.Error(), At: m.now().UTC()})
		return nil, err
	}
	acct, err := m.Store.AccountKey(ctx)
	if err != nil {
		return fail(fmt.Errorf("ACME account key: %w", err))
	}
	key, err := NewKey()
	if err != nil {
		return fail(err)
	}
	csr, err := CSR(key, names)
	if err != nil {
		return fail(err)
	}
	dir := m.Directory
	if dir == "" {
		dir = LetsEncrypt
		if set.Staging {
			dir = LetsEncryptStaging
		}
	}
	iss := &Issuer{Directory: dir, AccountKey: acct, Email: set.Email, DNS: m.DNS, Resolver: m.Resolver, Settle: m.Settle, Progress: progress}
	chain, err := iss.Issue(ctx, names, csr)
	if err != nil {
		return fail(err)
	}
	keyPEM, err := tlscert.MarshalKey(key)
	if err != nil {
		return fail(err)
	}
	c, err := tlscert.ParseChain(base, chain, keyPEM, m.now())
	if err != nil {
		return fail(fmt.Errorf("the certificate Let's Encrypt sent isn't usable: %w", err))
	}
	progress(90, "Installing the certificate")
	if err := tlscert.SaveWildcard(m.Dir, chain, keyPEM); err != nil {
		return fail(err)
	}
	if err := m.Certs.SetWildcard(base, c); err != nil {
		return fail(err)
	}
	leaf := c.Leaf
	rec := Cert{Names: strings.Join(leaf.DNSNames, " "), Serial: leaf.SerialNumber.Text(16), NotBefore: leaf.NotBefore,
		NotAfter: leaf.NotAfter, Issuer: leaf.Issuer.CommonName, At: m.now().UTC()}
	_ = m.Store.Record(ctx, rec)
	return &rec, nil
}

// Remove takes the certificate out of service and deletes it (the token was
// cleared).
func (m *Manager) Remove() {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.Certs.SetWildcard("", nil)
	tlscert.RemoveWildcard(m.Dir)
}

// Fingerprint is a certificate's SHA-256, for the settings page.
func Fingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

// ChainPEM is the served chain (tests).
func ChainPEM(c *tls.Certificate) []byte {
	var b strings.Builder
	for _, d := range c.Certificate {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}))
	}
	return []byte(b.String())
}
