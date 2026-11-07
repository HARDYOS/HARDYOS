package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"time"
)

// Identity is a member's (or the witness's) cluster key pair: ECDSA P-256
// in a self-signed certificate. Its pin (SHA-256 of the public key) is in
// the replicated state; it signs log entries and assertions and
// authenticates the node's TLS connections. It is separate from the
// replication identity (decision 330).
type Identity struct {
	Key  *ecdsa.PrivateKey
	Cert tls.Certificate
	// PublicKey is the SubjectPublicKeyInfo (DER) and Pin its SHA-256.
	PublicKey []byte
	Pin       string
}

type storedIdentity struct {
	Key  []byte `json:"key"`  // PKCS #8
	Cert []byte `json:"cert"` // DER
}

// NewIdentity makes a key pair for a node.
func NewIdentity(name string) (*Identity, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "HardyOS cluster " + name},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(30, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return identityFrom(storedIdentity{Key: pk, Cert: der})
}

// MarshalIdentity encodes an identity for sealing or a 0600 file.
func MarshalIdentity(id *Identity) ([]byte, error) {
	pk, err := x509.MarshalPKCS8PrivateKey(id.Key)
	if err != nil {
		return nil, err
	}
	return json.Marshal(storedIdentity{Key: pk, Cert: id.Cert.Certificate[0]})
}

// UnmarshalIdentity reads what MarshalIdentity wrote.
func UnmarshalIdentity(b []byte) (*Identity, error) {
	var si storedIdentity
	if err := json.Unmarshal(b, &si); err != nil {
		return nil, fmt.Errorf("cluster identity: %w", err)
	}
	return identityFrom(si)
}

func identityFrom(si storedIdentity) (*Identity, error) {
	k, err := x509.ParsePKCS8PrivateKey(si.Key)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("cluster identity: not a P-256 key")
	}
	c, err := x509.ParseCertificate(si.Cert)
	if err != nil {
		return nil, err
	}
	if !ek.PublicKey.Equal(c.PublicKey) {
		return nil, errors.New("cluster identity: key and certificate don't match")
	}
	return &Identity{Key: ek, Cert: tls.Certificate{Certificate: [][]byte{si.Cert}, PrivateKey: ek, Leaf: c},
		PublicKey: c.RawSubjectPublicKeyInfo, Pin: PinOfKey(c.RawSubjectPublicKeyInfo)}, nil
}

// PinOfKey is the SHA-256 (hex) of a SubjectPublicKeyInfo.
func PinOfKey(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// PinOfCert is a certificate's key pin.
func PinOfCert(c *x509.Certificate) string { return PinOfKey(c.RawSubjectPublicKeyInfo) }

// ParsePublicKey reads a P-256 SubjectPublicKeyInfo.
func ParsePublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("unreadable key: %v", err)
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("the key isn't ECDSA P-256")
	}
	return ek, nil
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewClusterID makes a cluster id: 128 random bits, base32 lowercase.
func NewClusterID() ClusterID {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return ClusterID(strings.ToLower(b32.EncodeToString(b)))
}

// SignCommand encodes c canonically (encoding/json of the struct, Body
// compacted) and signs it with the identity's key (ES256, ASN.1).
func SignCommand(id *Identity, c Command) (*SignedCommand, error) {
	if len(c.Body) == 0 {
		c.Body = json.RawMessage("{}")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	sig, err := ecdsa.SignASN1(rand.Reader, id.Key, sum[:])
	if err != nil {
		return nil, err
	}
	return &SignedCommand{Command: raw, Signature: sig}, nil
}
