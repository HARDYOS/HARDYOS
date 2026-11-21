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
// for names one label under the base; the self-signed certificate for
// everything else (the desktop by address or local name).
const (
	WildcardCert = "wildcard.crt"
	WildcardKey  = "wildcard.key"
)

// Store picks the certificate for each TLS handshake.
type Store struct {
	mu       sync.RWMutex
	fallback *tls.Certificate
	wild     *tls.Certificate
	leaf     *x509.Certificate
	base     string
	now      func() time.Time
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
	if s.wild != nil && Covers(s.base, hello.ServerName) && s.now().Before(s.leaf.NotAfter) {
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
	chain, err := os.ReadFile(filepath.Join(dir, WildcardCert))
	if err != nil {
		return nil, err
	}
	key, err := os.ReadFile(filepath.Join(dir, WildcardKey))
	if err != nil {
		return nil, err
	}
	return ParseChain(base, chain, key, now)
}

// SaveWildcard keeps a checked chain and its key in dir (key 0600), each
// written to a temporary file and renamed so a reader never sees half.
func SaveWildcard(dir string, chainPEM, keyPEM []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	write := func(name string, b []byte, mode os.FileMode) error {
		tmp := filepath.Join(dir, "."+name+".tmp")
		_ = os.Remove(tmp)
		if err := os.WriteFile(tmp, b, mode); err != nil {
			return err
		}
		return os.Rename(tmp, filepath.Join(dir, name))
	}
	if err := write(WildcardKey, keyPEM, 0o600); err != nil {
		return err
	}
	return write(WildcardCert, chainPEM, 0o644)
}

// RemoveWildcard deletes the wildcard certificate files.
func RemoveWildcard(dir string) {
	_ = os.Remove(filepath.Join(dir, WildcardCert))
	_ = os.Remove(filepath.Join(dir, WildcardKey))
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
