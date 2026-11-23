package cluster

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

// Leader-signed heartbeat statements as a quorum lease (decisions 367 and
// 389). One format serves both ends: a member counts itself quorate only
// with the leader's signed answer to its heartbeat (part A), and the
// member's root (hardyd-priv) keeps its watchdog quiet only for as long as
// the same statement grants, checked against keys root pinned itself and
// measured on root's own clock (part C's fence.Feeder). The statement
// echoes the member's own send time, so on the member it is a time of the
// member's own clock: no skew between the leader and root matters.

// SignedStatement is a LeaderStatement (its exact JSON) and the leader's
// ES256 signature (ASN.1) over StatementDomain + Statement. It is what
// Core.LeaseStatement hands the fence agent and what root verifies.
type SignedStatement struct {
	Statement json.RawMessage `json:"statement"`
	Signature []byte          `json:"signature"`
}

// StatementDomain separates heartbeat signatures from every other use of
// the cluster key.
const StatementDomain = "hardyos-heartbeat/1\n"

// MaxStatementLease bounds the lease a statement may grant (the largest
// quorum lease the timings allow).
const MaxStatementLease = 2 * time.Minute

// VerifyStatement checks a statement's signature with the signer's
// SubjectPublicKeyInfo and decodes it.
func VerifyStatement(spki []byte, statement json.RawMessage, sig []byte) (*LeaderStatement, error) {
	k, err := ParsePublicKey(spki)
	if err != nil {
		return nil, err
	}
	if len(statement) == 0 || len(statement) > 4096 || len(sig) == 0 || len(sig) > 128 {
		return nil, errors.New("no leader statement")
	}
	sum := sha256.Sum256(append([]byte(StatementDomain), statement...))
	if !ecdsa.VerifyASN1(k, sum[:], sig) {
		return nil, errors.New("bad leader signature")
	}
	var st LeaderStatement
	if err := json.Unmarshal(statement, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// LeaseKeySet is the keys root pins to check statements with: every
// member that may ever lead (compute and storage servers that aren't
// removed; never the witness), node id -> SPKI. It changes only when a
// server joins, leaves or gets a new key, not when one is fenced or in
// maintenance.
func LeaseKeySet(s *Snapshot) map[string][]byte {
	out := map[string][]byte{}
	if s == nil {
		return out
	}
	for id, n := range s.Nodes {
		if n == nil || len(n.PublicKey) == 0 || n.State == NodeRemoved {
			continue
		}
		if n.Role == RoleCompute || n.Role == RoleStorage {
			out[string(id)] = n.PublicKey
		}
	}
	return out
}

// KeySetHash is the SHA-256 (hex) of a key set: the sorted node ids with
// their keys' pins. A leader's statement carries the hash of its own
// LeaseKeySet, so root can accept a new key set while its watchdog is
// armed only when a key it already trusts vouches for it.
func KeySetHash(keys map[string][]byte) string {
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	h := sha256.New()
	for _, id := range ids {
		pin := sha256.Sum256(keys[id])
		h.Write([]byte(id + "\n" + hex.EncodeToString(pin[:]) + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}
