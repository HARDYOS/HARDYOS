package replication

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// SecretsPurpose is the secretbox purpose for replication's sealed values
// (this server's private key, pinned keys, the pairing code).
const SecretsPurpose = "replication"

const keyIdentity = "replication.identity"

// Sealer seals replication's secrets with a key from hardyd-priv.
type Sealer struct {
	Source secretbox.Source

	once     sync.Once
	fallback secretbox.Source
}

func (s *Sealer) source() secretbox.Source {
	if s != nil && s.Source != nil {
		return s.Source
	}
	s.once.Do(func() { s.fallback = secretbox.NewStaticSource() })
	return s.fallback
}

// Seal encrypts plain, bound to aad (where it's stored).
func (s *Sealer) Seal(ctx context.Context, plain []byte, aad string) ([]byte, error) {
	k, err := s.source().Key(ctx, SecretsPurpose)
	if err != nil {
		return nil, err
	}
	return secretbox.Seal(k, plain, []byte(aad))
}

// Open decrypts what Seal made.
func (s *Sealer) Open(ctx context.Context, sealed []byte, aad string) ([]byte, error) {
	k, err := s.source().Key(ctx, SecretsPurpose)
	if err != nil {
		return nil, err
	}
	return secretbox.Open(k, sealed, []byte(aad))
}

// Identity is this server's replication key pair: a self-signed
// certificate whose public key other servers pin when they pair.
type Identity struct {
	Cert tls.Certificate
	// Pin is the SHA-256 of the public key (hex).
	Pin string
}

// PinOf is the SHA-256 (hex) of a certificate's public key.
func PinOf(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

type storedIdentity struct {
	Key  []byte `json:"key"`  // PKCS #8
	Cert []byte `json:"cert"` // DER
}

// loadIdentity reads this server's identity, making one the first time.
// The private key is sealed in the settings table.
func loadIdentity(ctx context.Context, db *store.DB, sealer *Sealer, hostname string) (*Identity, error) {
	if v, err := db.GetSetting(ctx, keyIdentity); err == nil {
		raw, err := hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("replication identity: %w", err)
		}
		plain, err := sealer.Open(ctx, raw, keyIdentity)
		if err != nil {
			return nil, fmt.Errorf("replication identity: %w (pair the servers again)", err)
		}
		var si storedIdentity
		if err := json.Unmarshal(plain, &si); err != nil {
			return nil, err
		}
		return identityFrom(si)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	si, err := newIdentity(hostname)
	if err != nil {
		return nil, err
	}
	plain, _ := json.Marshal(si)
	sealed, err := sealer.Seal(ctx, plain, keyIdentity)
	if err != nil {
		return nil, err
	}
	if err := db.SetSetting(ctx, keyIdentity, hex.EncodeToString(sealed)); err != nil {
		return nil, err
	}
	return identityFrom(si)
}

func newIdentity(hostname string) (storedIdentity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return storedIdentity{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "HardyOS replication " + hostname},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(30, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return storedIdentity{}, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return storedIdentity{}, err
	}
	return storedIdentity{Key: pk, Cert: der}, nil
}

func identityFrom(si storedIdentity) (*Identity, error) {
	k, err := x509.ParsePKCS8PrivateKey(si.Key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(si.Cert)
	if err != nil {
		return nil, err
	}
	return &Identity{Cert: tls.Certificate{Certificate: [][]byte{si.Cert}, PrivateKey: k, Leaf: c}, Pin: PinOf(c)}, nil
}

// ---- pairing codes ---------------------------------------------------------

// A pairing code is 128 random bits, shown as 26 base32 letters and
// digits in groups. It never leaves the two administrators' screens: the
// servers prove to each other that they know it (HMAC over both pinned
// keys), so someone in the middle can't learn it or swap a key.
var codeEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewCode makes a pairing code (raw bytes and how it's shown).
func NewCode() ([]byte, string) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b, FormatCode(b)
}

// FormatCode shows a code as XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX.
func FormatCode(b []byte) string {
	s := codeEnc.EncodeToString(b)
	var parts []string
	for i := 0; i < len(s); i += 5 {
		j := min(i+5, len(s))
		if len(s)-j < 5 && len(s)-j > 0 {
			j = len(s)
		}
		parts = append(parts, s[i:j])
		if j == len(s) {
			break
		}
	}
	return strings.Join(parts, "-")
}

// ParseCode reads a code as typed or pasted (case, spaces and dashes
// don't matter).
func ParseCode(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "").Replace(strings.TrimSpace(s)))
	b, err := codeEnc.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil, errors.New("that isn't a pairing code: copy it from the other server's Control Panel › Replication")
	}
	return b, nil
}

// Proofs: each side's HMAC under the code over both servers' pins.
func sourceProof(code []byte, sourcePin, receiverPin string) []byte {
	m := hmac.New(sha256.New, code)
	m.Write([]byte("hardyos-pair-v1 source\x00" + sourcePin + "\x00" + receiverPin))
	return m.Sum(nil)
}

func receiverProof(code []byte, sourcePin, receiverPin, sourceID string) []byte {
	m := hmac.New(sha256.New, code)
	m.Write([]byte("hardyos-pair-v1 receiver\x00" + sourcePin + "\x00" + receiverPin + "\x00" + sourceID))
	return m.Sum(nil)
}
