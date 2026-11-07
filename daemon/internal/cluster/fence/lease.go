package fence

// Leader-signed lease statements (decision 389). Root (hardyd-priv) must
// not take hardyd's word for how long the node is quorate: a hung or buggy
// hardyd that keeps saying "valid" would keep the watchdog quiet. So every
// pet carries the leader's signed answer to this node's heartbeat (part
// A's cluster.LeaderStatement, the very statement that extends the node's
// quorum lease), and root verifies it against keys it pinned itself and
// derives the deadline on its own clock: the statement echoes the node's
// own send time, so root measures the lease from a time of this machine.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// LeaseStatement is part A's heartbeat statement: the leader leads, heard
// Node's heartbeat sent at Sent (the node's clock), and grants LeaseMs.
type LeaseStatement = cluster.LeaderStatement

// SignedLease is a statement and the leader's ES256 signature over
// cluster.StatementDomain + the statement's exact bytes.
type SignedLease = cluster.SignedStatement

// LeaseKeys are what root pins to check statements: this node's id, the
// cluster's, and the keys of the members that may lead
// (cluster.LeaseKeySet: node id -> SubjectPublicKeyInfo, DER).
type LeaseKeys struct {
	Cluster string            `json:"cluster"`
	Node    string            `json:"node"`
	Voters  map[string][]byte `json:"voters"`
	// Lease vouches for a new key set while the watchdog is armed: a
	// statement signed by a key root already pinned whose Keys is this
	// set's cluster.KeySetHash (a member joined or left while HA workloads
	// ran here).
	Lease json.RawMessage `json:"lease,omitempty"`
}

// Hash is the key set's cluster.KeySetHash.
func (k LeaseKeys) Hash() string { return cluster.KeySetHash(k.Voters) }

// LeaseVerifier checks a signed statement and says for how long from now
// root may keep petting.
type LeaseVerifier interface {
	Verify(raw []byte, keys *LeaseKeys, now time.Time) (time.Duration, error)
}

// MaxLeaseSkew is how far in the future a statement's send time may be
// (the node's own clock: only a clock step makes it so).
const MaxLeaseSkew = 5 * time.Second

// ES256Leases is the LeaseVerifier for part A's statements. It refuses a
// statement older than the last one it accepted (a replay).
type ES256Leases struct {
	last int64
}

// Verify implements LeaseVerifier.
func (v *ES256Leases) Verify(raw []byte, keys *LeaseKeys, now time.Time) (time.Duration, error) {
	st, valid, err := CheckLease(raw, keys, now)
	if err != nil {
		return 0, err
	}
	if st.Sent < v.last {
		return 0, errors.New("an older lease statement than the last one")
	}
	v.last = st.Sent
	return valid, nil
}

// CheckLease verifies a SignedLease against the pinned keys: signed by a
// pinned key for this cluster and this node, sent no later than now (give
// or take MaxLeaseSkew) and still within the lease it grants. It returns
// the statement and how long from now the lease lasts.
func CheckLease(raw []byte, keys *LeaseKeys, now time.Time) (*LeaseStatement, time.Duration, error) {
	if keys == nil || len(keys.Voters) == 0 {
		return nil, 0, errors.New("no leader keys are pinned")
	}
	var sl SignedLease
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sl); err != nil {
		return nil, 0, fmt.Errorf("the lease statement: %w", err)
	}
	var head struct {
		Leader string `json:"leader"`
	}
	if err := json.Unmarshal(sl.Statement, &head); err != nil {
		return nil, 0, fmt.Errorf("the lease statement: %w", err)
	}
	der, ok := keys.Voters[head.Leader]
	if !ok {
		return nil, 0, fmt.Errorf("%s isn't a server root knows may lead", head.Leader)
	}
	st, err := cluster.VerifyStatement(der, sl.Statement, sl.Signature)
	if err != nil {
		return nil, 0, fmt.Errorf("the lease statement: %w", err)
	}
	if string(st.Cluster) != keys.Cluster || string(st.Node) != keys.Node || string(st.Leader) != head.Leader {
		return nil, 0, errors.New("the lease statement is for another server")
	}
	lease := time.Duration(st.LeaseMs) * time.Millisecond
	if lease <= 0 || lease > cluster.MaxStatementLease {
		return nil, 0, fmt.Errorf("the lease statement grants %s", lease)
	}
	age := now.Sub(time.Unix(0, st.Sent))
	if age < -MaxLeaseSkew {
		return nil, 0, fmt.Errorf("the lease statement is from %s in the future", (-age).Round(time.Millisecond))
	}
	valid := lease
	if age > 0 {
		valid -= age
	}
	if valid <= 0 {
		return nil, 0, errors.New("the lease statement has run out")
	}
	return st, valid, nil
}

// LeaseSource is what part A's Membership offers: the latest
// leader-signed statement for this node (SignedLease JSON).
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
