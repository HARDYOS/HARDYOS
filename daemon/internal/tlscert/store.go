package tlscert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// The wildcard certificate (decision 455): Let's Encrypt's *.<base>, served
// for names one label under the base while the hostnames are active; the
// self-signed certificate for everything else (the desktop by address or
// local name). Key and chain are one file, replaced in one rename.
const WildcardFile = "wildcard.pem"

// Older names (removed when a new certificate is saved).
const (
	oldWildcardCert = "wildcard.crt"
	oldWildcardKey  = "wildcard.key"
)

// Store picks the certificate for each TLS handshake.
type Store struct {
	mu       sync.RWMutex
	fallback *tls.Certificate
	wild     *tls.Certificate
	leaf     *x509.Certificate
	base     string
	active   bool
	now      func() time.Time
}

// SetActive says whether the hostnames are being served: only then does a
// handshake for a name under the base get the wildcard (decision 450).
func (s *Store) SetActive(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = on
}

// NewStore serves fallback until a wildcard certificate is set.
func NewStore(fallback tls.Certificate) *Store {
	return &Store{fallback: &fallback, now: time.Now}
}

// SetWildcard installs (or with nil removes) the certificate for *.<base>.
func (s *Store) SetWildcard(base string, c *tls.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c == nil {
		s.wild, s.leaf, s.base = nil, nil, ""
		return nil
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return err
	}
	if err := leaf.VerifyHostname("x." + base); err != nil {
		return fmt.Errorf("the certificate isn't for *.%s", base)
	}
	c.Leaf = leaf
	s.wild, s.leaf, s.base = c, leaf, base
	return nil
}

// Wildcard reports the installed wildcard certificate: its base and leaf
// ("" and nil when there is none or it has expired).
func (s *Store) Wildcard() (string, *x509.Certificate) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.leaf == nil || s.now().After(s.leaf.NotAfter) {
		return "", nil
	}
	return s.base, s.leaf
}

// Covers reports whether name is one label under the wildcard's base.
func Covers(base, name string) bool {
	if base == "" {
		return false
	}
	label, ok := strings.CutSuffix(strings.ToLower(strings.TrimSuffix(name, ".")), "."+base)
	return ok && label != "" && !strings.Contains(label, ".")
}

// GetCertificate implements tls.Config.GetCertificate.
func (s *Store) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active && s.wild != nil && Covers(s.base, hello.ServerName) && s.now().Before(s.leaf.NotAfter) {
		return s.wild, nil
	}
	return s.fallback, nil
}

// TLSConfig is a server configuration using the store.
func (s *Store) TLSConfig() *tls.Config {
	return &tls.Config{GetCertificate: s.GetCertificate, MinVersion: tls.VersionTLS12}
}

// ParseChain checks a PEM chain and key belong together, name *.<base> and
// are valid now, and returns them as a tls.Certificate.
func ParseChain(base string, chainPEM, keyPEM []byte, now time.Time) (*tls.Certificate, error) {
	c, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, err
	}
	if err := leaf.VerifyHostname("x." + base); err != nil {
		return nil, fmt.Errorf("the certificate isn't for *.%s", base)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("the certificate isn't valid now")
	}
	c.Leaf = leaf
	return &c, nil
}

// LoadWildcard reads the wildcard certificate kept in dir.
func LoadWildcard(dir, base string, now time.Time) (*tls.Certificate, error) {
	b, err := os.ReadFile(filepath.Join(dir, WildcardFile))
	if err != nil {
		return nil, err
	}
	return ParseChain(base, b, b, now)
}

// SaveWildcard keeps a checked chain and its key in dir as one 0600 file
// (key first), written to a temporary file, synced and renamed over the
// old one: a reader sees the old pair or the new one, never a mix.
func SaveWildcard(dir string, chainPEM, keyPEM []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".wildcard-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(append(append([]byte{}, keyPEM...), chainPEM...)); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, WildcardFile)); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(dir, oldWildcardCert))
	_ = os.Remove(filepath.Join(dir, oldWildcardKey))
	return nil
}

// RemoveWildcard deletes the wildcard certificate file.
func RemoveWildcard(dir string) {
	_ = os.Remove(filepath.Join(dir, WildcardFile))
	_ = os.Remove(filepath.Join(dir, oldWildcardCert))
	_ = os.Remove(filepath.Join(dir, oldWildcardKey))
}

// MarshalKey PEM-encodes an ECDSA key.
func MarshalKey(k crypto.Signer) ([]byte, error) {
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("only ECDSA keys")
	}
	der, err := x509.MarshalECPrivateKey(ek)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}
