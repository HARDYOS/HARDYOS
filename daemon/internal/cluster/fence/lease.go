package fence

// Leader-signed lease statements (decision 389). Root (hardyd-priv) must
// not take hardyd's word for how long the node is quorate: a hung or buggy
// hardyd that keeps saying "valid" would keep the watchdog quiet. So every
// pet carries the leader's signed answer to this node's heartbeat, and
// root verifies it against voter keys it pinned itself and derives the
// deadline on its own clock.
//
// Part A produces the statements (the leader signs each heartbeat answer);
// this file defines the format and the check root makes. Until part A
// sends them, a node runs in the legacy mode (no keys pinned in root): the
// deadline is hardyd's, as before.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// LeaseStatement is what the leader signs when it answers a node's
// heartbeat after confirming it still leads.
type LeaseStatement struct {
	Cluster string `json:"cluster"`
	// Leader signed it; Node is the heartbeat's sender (this server).
	Leader string `json:"leader"`
	Node   string `json:"node"`
	Term   uint64 `json:"term"`
	// IssuedMs is the leader's wall clock (Unix ms) when it answered.
	IssuedMs int64 `json:"issuedMs"`
	// ValidMs is the quorum lease it grants from IssuedMs (Q).
	ValidMs int64 `json:"validMs"`
}

// SignedLease is a statement and the leader's ES256 signature (ASN.1) over
// the statement's exact bytes.
type SignedLease struct {
	Statement json.RawMessage `json:"statement"`
	Signature []byte          `json:"signature"`
}

// LeaseKeys are what root pins to check statements: this node's id, the
// cluster's, and the voters' public keys (SubjectPublicKeyInfo, DER).
type LeaseKeys struct {
	Cluster string            `json:"cluster"`
	Node    string            `json:"node"`
	Voters  map[string][]byte `json:"voters"` // node id -> key
}

// LeaseVerifier checks a signed statement and says for how long from now
// root may keep petting.
type LeaseVerifier interface {
	Verify(raw []byte, keys *LeaseKeys, now time.Time) (time.Duration, error)
}

// MaxLeaseSkew is how far the leader's clock may be from root's.
const MaxLeaseSkew = 5 * time.Second

// ES256Leases is the LeaseVerifier for part A's statements. It refuses a
// statement older than the last one it accepted (a replay).
type ES256Leases struct {
	last int64
}

// Verify implements LeaseVerifier.
func (v *ES256Leases) Verify(raw []byte, keys *LeaseKeys, now time.Time) (time.Duration, error) {
	if keys == nil || len(keys.Voters) == 0 {
		return 0, errors.New("no voter keys are pinned")
	}
	var sl SignedLease
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sl); err != nil {
		return 0, fmt.Errorf("the lease statement: %w", err)
	}
	var st LeaseStatement
	dec = json.NewDecoder(bytes.NewReader(sl.Statement))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return 0, fmt.Errorf("the lease statement: %w", err)
	}
	der, ok := keys.Voters[st.Leader]
	if !ok {
		return 0, fmt.Errorf("%s isn't a voter root knows", st.Leader)
	}
	pk, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return 0, err
	}
	ec, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		return 0, errors.New("a voter key isn't ECDSA")
	}
	sum := sha256.Sum256(sl.Statement)
	if !ecdsa.VerifyASN1(ec, sum[:], sl.Signature) {
		return 0, errors.New("the lease statement's signature doesn't verify")
	}
	if st.Cluster != keys.Cluster || st.Node != keys.Node {
		return 0, errors.New("the lease statement is for another server")
	}
	issued := time.UnixMilli(st.IssuedMs)
	age := now.Sub(issued)
	if age > MaxLeaseSkew || age < -MaxLeaseSkew {
		return 0, fmt.Errorf("the lease statement is %s old", age.Round(time.Millisecond))
	}
	if st.IssuedMs < v.last {
		return 0, errors.New("an older lease statement than the last one")
	}
	if st.ValidMs <= 0 {
		return 0, errors.New("the lease statement grants nothing")
	}
	valid := time.Duration(st.ValidMs) * time.Millisecond
	if age > 0 {
		valid -= age
	}
	if valid <= 0 {
		return 0, errors.New("the lease statement has run out")
	}
	v.last = st.IssuedMs
	return valid, nil
}

// LeaseSource is what part A's Membership offers once the leader signs
// its heartbeat answers: the latest statement for this node.
type LeaseSource interface {
	LeaseStatement() (signed []byte, ok bool)
}

// LeaseWatchdog is a Watchdog that carries statements to root and pins
// the keys root checks them with (runtime.PrivWatchdog).
type LeaseWatchdog interface {
	PetWithLease(ctx context.Context, validFor time.Duration, statement []byte) error
	PinLeaseKeys(ctx context.Context, keys LeaseKeys) error
}

// StatusWatchdog reports root's view of the watchdog (the agent
// reconciles with it when it starts and notices a restarted hardyd-priv).
type StatusWatchdog interface {
	Status(ctx context.Context) (Status, error)
}
