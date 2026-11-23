package cluster

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// Assertions (decision 324, docs/plans/cluster.md section 4): the entry
// node's signed statement of who the person is, sent with every request it
// forwards to another member. A compact JWS, ES256 only, with the claims of
// Assertion. The target checks the mTLS peer is the issuer, the signature
// with the issuer's key from the state, the audience (itself), freshness
// (at most AssertionTTL, small clock skew allowed), that the nonce wasn't
// seen within NonceWindow, and the request hash.

// AssertionTTL is the most an assertion may live; NonceWindow how long a
// nonce is remembered (longer than the TTL plus skew).
const (
	AssertionTTL  = 60 * time.Second
	AssertionSkew = 5 * time.Second
	NonceWindow   = 2 * time.Minute
)

var assertionHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"hardyos-assertion"}`))

// RequestHash binds an assertion to one request: SHA-256 (hex) over the
// method, path, raw query and the body's SHA-256.
func RequestHash(method, path, rawQuery string, body []byte) string {
	b := sha256.Sum256(body)
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%x", method, path, rawQuery, b)
	return hex.EncodeToString(h.Sum(nil))
}

// RequestHashDigest is RequestHash for a body whose SHA-256 is known.
func RequestHashDigest(method, path, rawQuery string, bodySum []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%x", method, path, rawQuery, bodySum)
	return hex.EncodeToString(h.Sum(nil))
}

// NewNonce is a random assertion id.
func NewNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// SignAssertion makes the compact JWS of a.
func SignAssertion(id *Identity, a Assertion) (string, error) {
	if a.ExpiresAt-a.IssuedAt > int64(AssertionTTL/time.Second) || a.ExpiresAt <= a.IssuedAt {
		return "", errors.New("assertion lifetime must be 1-60 s")
	}
	payload, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	signing := assertionHeader + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, id.Key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ParseAssertion reads a JWS's claims without checking it (to find the
// issuer whose key checks it).
func ParseAssertion(jws string) (*Assertion, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 || len(jws) > 8192 {
		return nil, errors.New("malformed assertion")
	}
	if parts[0] != assertionHeader {
		return nil, errors.New("unsupported assertion header")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed assertion")
	}
	var a Assertion
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, errors.New("malformed assertion claims")
	}
	return &a, nil
}

// AssertionCheck is what the target expects of an assertion.
type AssertionCheck struct {
	// IssuerKey is the issuer's public key (SPKI) from the state; the
	// caller has already matched the mTLS peer's pin to the issuer.
	Issuer    NodeID
	IssuerKey []byte
	Audience  NodeID
	Request   string
	Now       time.Time
	Nonces    *NonceCache
}

// Errors of VerifyAssertion.
var (
	ErrAssertionInvalid = errors.New("invalid cluster assertion")
	ErrAssertionReplay  = errors.New("cluster assertion replayed")
)

// VerifyAssertion checks a JWS and returns its claims.
func VerifyAssertion(jws string, c AssertionCheck) (*Assertion, error) {
	a, err := ParseAssertion(jws)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAssertionInvalid, err)
	}
	k, err := ParsePublicKey(c.IssuerKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAssertionInvalid, err)
	}
	i := strings.LastIndexByte(jws, '.')
	sig, err := base64.RawURLEncoding.DecodeString(jws[i+1:])
	if err != nil || len(sig) != 64 {
		return nil, fmt.Errorf("%w: bad signature encoding", ErrAssertionInvalid)
	}
	sum := sha256.Sum256([]byte(jws[:i]))
	if !ecdsa.Verify(k, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, fmt.Errorf("%w: bad signature", ErrAssertionInvalid)
	}
	switch {
	case a.Issuer != c.Issuer:
		return nil, fmt.Errorf("%w: issued by %s, sent by %s", ErrAssertionInvalid, a.Issuer, c.Issuer)
	case a.Audience != c.Audience:
		return nil, fmt.Errorf("%w: meant for %s", ErrAssertionInvalid, a.Audience)
	case a.ExpiresAt-a.IssuedAt > int64(AssertionTTL/time.Second) || a.ExpiresAt <= a.IssuedAt:
		return nil, fmt.Errorf("%w: lifetime", ErrAssertionInvalid)
	case c.Now.Unix() < a.IssuedAt-int64(AssertionSkew/time.Second) || c.Now.Unix() > a.ExpiresAt+int64(AssertionSkew/time.Second):
		return nil, fmt.Errorf("%w: expired or not yet valid", ErrAssertionInvalid)
	case len(a.Nonce) < 16 || len(a.Nonce) > 64:
		return nil, fmt.Errorf("%w: nonce", ErrAssertionInvalid)
	case a.Request != c.Request:
		return nil, fmt.Errorf("%w: made for another request", ErrAssertionInvalid)
	case a.Subject.Name == "" || (a.Subject.Kind != "local" && a.Subject.Kind != "domain"):
		return nil, fmt.Errorf("%w: subject", ErrAssertionInvalid)
	case a.Subject.Kind == "domain" && a.Subject.SID == "":
		return nil, fmt.Errorf("%w: a domain subject needs its SID", ErrAssertionInvalid)
	}
	if c.Nonces == nil || !c.Nonces.Use(string(a.Issuer)+"/"+a.Nonce, c.Now) {
		return nil, ErrAssertionReplay
	}
	return a, nil
}

// NonceCache remembers nonces for NonceWindow (bounded: when full, the
// oldest go first; a nonce that falls out early can only be replayed
// within its 60 s lifetime if more than Max assertions arrived meanwhile).
type NonceCache struct {
	Max int

	mu   sync.Mutex
	seen map[string]time.Time
	fifo []string
}

// Use records a nonce and reports whether it was new.
func (n *NonceCache) Use(nonce string, now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.seen == nil {
		n.seen = map[string]time.Time{}
	}
	max := n.Max
	if max <= 0 {
		max = 200_000
	}
	for len(n.fifo) > 0 {
		t, ok := n.seen[n.fifo[0]]
		if ok && now.Sub(t) < NonceWindow && len(n.fifo) < max {
			break
		}
		delete(n.seen, n.fifo[0])
		n.fifo = n.fifo[1:]
	}
	if _, ok := n.seen[nonce]; ok {
		return false
	}
	n.seen[nonce] = now
	n.fifo = append(n.fifo, nonce)
	return true
}
