package san

// Root's own pins (security review H3, M1, M2; decisions 375-378): what
// root on the storage node checks every request from hardyd against, so a
// compromised or buggy hardyd on the storage node can't quietly point
// storage at another address, re-admit a fenced node or replay old state.
//
//   - Pins: each compute node's storage address and cluster key (SPKI),
//     taken the first time root sees the node (trust on first use, at the
//     storage node's setup and when a node joins) and never changed by
//     hardyd afterwards. A different address or key for a pinned node
//     disables that node's target (nothing else) until an administrator
//     resets the pin as root on the storage node (hardyctl).
//   - The storage subnet, pinned the same way.
//   - Fences keyed by node id and the node's key pin, with a per-node epoch
//     high-water mark that survives unfencing (an old fence can't be
//     replayed and an old unfence can't be reused).
//   - Unfencing needs the fenced node's own signed rejoin statement for
//     that epoch, verified with its pinned key.
//   - Index high-water marks per kind (LIO, exports, firewall) that may
//     not move backwards, nor jump further ahead than entries could have
//     been committed since the last accepted change.
//
// What root can't check without verifying the Raft log itself (that a
// node really joined, that a grant is really in the log) is pending the
// owner's decision on member isolation (docs/plans/cluster.md 8.1).

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Pin is root's record of one compute node.
type Pin struct {
	Address netip.Addr `json:"address"`
	// Key is the node's cluster key (SPKI); KeyPin its SHA-256 (hex).
	Key    []byte    `json:"key"`
	KeyPin string    `json:"keyPin"`
	Pinned time.Time `json:"pinned"`
}

// FenceRecord is one fence root holds: the epoch and the key pin of the
// node it was put on ("" when root had no pin for it).
type FenceRecord struct {
	Epoch  uint64 `json:"epoch"`
	KeyPin string `json:"keyPin,omitempty"`
}

// UnmarshalJSON also reads the earlier format (just the epoch).
func (f *FenceRecord) UnmarshalJSON(b []byte) error {
	var n uint64
	if err := json.Unmarshal(b, &n); err == nil {
		*f = FenceRecord{Epoch: n}
		return nil
	}
	type plain FenceRecord
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*f = FenceRecord(p)
	return nil
}

// Index limits: a change may carry an index at most indexJumpBase ahead
// of the last accepted one, plus indexJumpPerSecond for every second
// since then (far more entries than a cluster commits; a hardyd that
// sends a huge index can't lock root out of every later change).
const (
	indexJumpBase      = 10000
	indexJumpPerSecond = 1000
)

// IndexMark is one kind's high-water mark.
type IndexMark struct {
	Index uint64    `json:"index"`
	At    time.Time `json:"at"`
}

// check accepts idx when it isn't older than the mark and isn't too far
// ahead of it. now is root's clock.
func (m IndexMark) check(kind string, idx uint64, now time.Time) error {
	if idx < m.Index {
		return &ValidationError{fmt.Errorf("%s from index %d is older than the applied one (%d)", kind, idx, m.Index)}
	}
	if m.Index == 0 && m.At.IsZero() {
		return nil
	}
	el := now.Sub(m.At)
	if el < 0 {
		el = 0
	}
	max := uint64(indexJumpBase) + uint64(indexJumpPerSecond)*uint64(el/time.Second)
	if idx-m.Index > max {
		return &ValidationError{fmt.Errorf("%s from index %d is %d entries ahead of the applied one (%d); at most %d are possible since %s",
			kind, idx, idx-m.Index, m.Index, max, m.At.Format(time.RFC3339))}
	}
	return nil
}

func (m *IndexMark) advance(idx uint64, now time.Time) {
	if idx > m.Index || m.At.IsZero() {
		m.Index, m.At = idx, now
	}
}

// pinProblem says why a node's target is disabled by root's pins, or "".
func (st *rootState) pinNode(n cluster.NodeID, addr netip.Addr, key []byte, own []netip.Addr, now time.Time) string {
	p := st.Pins[n]
	if p == nil {
		switch {
		case !addr.IsValid():
			return "it has no storage address yet"
		case len(key) == 0:
			return "its cluster key wasn't given"
		}
		if err := st.addressAllowed(n, addr, own); err != nil {
			return err.Error()
		}
		if _, err := cluster.ParsePublicKey(key); err != nil {
			return "its cluster key isn't valid: " + err.Error()
		}
		if st.Pins == nil {
			st.Pins = map[cluster.NodeID]*Pin{}
		}
		st.Pins[n] = &Pin{Address: addr, Key: append([]byte(nil), key...), KeyPin: cluster.PinOfKey(key), Pinned: now}
		return ""
	}
	if addr != p.Address {
		return fmt.Sprintf("its storage address changed from %s to %s; an administrator confirms that on the storage server with: hardyctl cluster-storage repin %s", p.Address, addr, n)
	}
	if cluster.PinOfKey(key) != p.KeyPin {
		return fmt.Sprintf("its cluster key changed; an administrator confirms that on the storage server with: hardyctl cluster-storage repin %s", n)
	}
	return ""
}

// addressAllowed checks a new pin's address (M1): in the pinned storage
// subnet, not one of the storage node's own addresses, and not pinned to
// another node.
func (st *rootState) addressAllowed(n cluster.NodeID, a netip.Addr, own []netip.Addr) error {
	if !a.Is4() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() {
		return fmt.Errorf("storage address %s isn't usable", a)
	}
	if st.Subnet.IsValid() && (!st.Subnet.Contains(a) || a == st.Subnet.Addr() || isBroadcast(st.Subnet, a)) {
		return fmt.Errorf("storage address %s isn't a host address of the storage network %s", a, st.Subnet)
	}
	for _, o := range own {
		if o == a {
			return fmt.Errorf("storage address %s is the storage server's own", a)
		}
	}
	for o, p := range st.Pins {
		if o != n && p.Address == a {
			return fmt.Errorf("storage address %s already belongs to %s", a, o)
		}
	}
	return nil
}

func isBroadcast(p netip.Prefix, a netip.Addr) bool {
	if !a.Is4() || p.Bits() >= 31 {
		return false
	}
	b := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= (1 << host) - 1
	x := a.As4()
	return uint32(x[0])<<24|uint32(x[1])<<16|uint32(x[2])<<8|uint32(x[3]) == v
}

// pinnedAddr is a node's pinned storage address.
func (st *rootState) pinnedAddr(n cluster.NodeID) (netip.Addr, bool) {
	if p := st.Pins[n]; p != nil {
		return p.Address, true
	}
	return netip.Addr{}, false
}

// nodeOfAddr finds the pinned node of an address.
func (st *rootState) nodeOfAddr(a netip.Addr) (cluster.NodeID, bool) {
	for n, p := range st.Pins {
		if p.Address == a {
			return n, true
		}
	}
	return "", false
}

// ---- rejoin statements ---------------------------------------------------------

// RejoinStatement is a fenced compute node's own signed request to be let
// back in at one fence epoch (H3). The node's hardyd signs it with its
// cluster key once node.rejoin is applied for it; root verifies it with
// the key it pinned for the node before it lifts the fence. Its digest
// has its own prefix, so it can never be mistaken for a log entry or an
// assertion.
type RejoinStatement struct {
	Cluster   cluster.ClusterID `json:"cluster"`
	Node      cluster.NodeID    `json:"node"`
	Epoch     uint64            `json:"epoch"`
	BootID    string            `json:"bootId,omitempty"`
	Signature []byte            `json:"signature"`
}

// validBoot: the statement's boot id is the one the log recorded for the
// node (cluster.ValidBootID), or none.
func validBoot(id string) bool { return id == "" || cluster.ValidBootID(id) == nil }

func (s RejoinStatement) digest() []byte {
	sum := sha256.Sum256([]byte("hardyos-storage-unfence/1\n" + string(s.Cluster) + "\n" + string(s.Node) + "\n" +
		strconv.FormatUint(s.Epoch, 10) + "\n" + s.BootID))
	return sum[:]
}

// SignRejoin signs a statement with a node's cluster key.
func SignRejoin(key *ecdsa.PrivateKey, s RejoinStatement) (RejoinStatement, error) {
	if key == nil {
		return s, errors.New("no cluster key")
	}
	if !validBoot(s.BootID) {
		return s, errors.New("boot id isn't valid")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, s.digest())
	if err != nil {
		return s, err
	}
	s.Signature = sig
	return s, nil
}

// Verify checks the signature with an SPKI.
func (s RejoinStatement) Verify(spki []byte) error {
	k, err := cluster.ParsePublicKey(spki)
	if err != nil {
		return err
	}
	if !validBoot(s.BootID) || len(s.Signature) == 0 || len(s.Signature) > 128 {
		return errors.New("malformed rejoin statement")
	}
	if !ecdsa.VerifyASN1(k, s.digest(), s.Signature) {
		return errors.New("the rejoin statement's signature doesn't verify with the node's pinned key")
	}
	return nil
}
