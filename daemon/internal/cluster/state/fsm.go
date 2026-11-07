// Package state is the cluster's replicated state machine: the pure,
// deterministic part every member and the witness run on the same log
// entries (docs/plans/cluster.md section 2.3).
//
// The FSM checks every entry before an applier sees it:
//
//  1. the signature against the proposer's key in the current state
//     (cluster.create carries its creator's key and must come first);
//  2. the proposer's role is one the applier allows for the type;
//  3. the proposer's sequence number is greater than the last one applied
//     for it (a leader can't replay old signed entries);
//  4. the applier's own preconditions.
//
// A refused entry changes nothing but the proposer's sequence (so it can't
// be replayed once its preconditions hold) and the applied index, on every
// node alike. An entry of a type no applier knows stops the FSM: the node
// would diverge from the others (Halted).
//
// Nothing here reads the clock, the network or the disk. Parts B and C add
// their appliers in their own files of this package (register in an init
// function); the witness then applies their entries too.
package state

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// ErrRefused wraps every reason an entry was refused before or by its
// applier.
var ErrRefused = errors.New("refused")

// ErrHalted: the FSM stopped at an entry it can't apply (an unknown type).
var ErrHalted = errors.New("the cluster state machine stopped")

var (
	regMu    sync.Mutex
	registry []cluster.Applier
)

// register adds an applier every new FSM gets (called from init functions
// of this package's files: members.go, witness.go, and parts B and C).
func register(a cluster.Applier) {
	regMu.Lock()
	defer regMu.Unlock()
	registry = append(registry, a)
}

// Result is what applying one entry did.
type Result = cluster.ApplyResult

var _ cluster.StateMachine = (*FSM)(nil)

// FSM is the replicated state with its appliers. Safe for concurrent use:
// Apply and Restore are called by Raft, readers take copies.
type FSM struct {
	mu       sync.RWMutex
	s        *cluster.Snapshot
	appliers map[cluster.CommandType]cluster.Applier
	halted   error
}

// New returns an empty FSM with the built-in appliers (members, witness
// and whatever parts B and C registered).
func New() *FSM {
	f := &FSM{s: Empty(), appliers: map[cluster.CommandType]cluster.Applier{}}
	regMu.Lock()
	l := slices.Clone(registry)
	regMu.Unlock()
	for _, a := range l {
		f.Register(a)
	}
	return f
}

// Empty is the state before cluster.create.
func Empty() *cluster.Snapshot {
	return &cluster.Snapshot{
		Nodes:      map[cluster.NodeID]*cluster.Node{},
		Placements: map[cluster.WorkloadRef]*cluster.Placement{},
		Grants:     map[cluster.WorkloadRef]*cluster.Grant{},
		Fences:     map[cluster.NodeID]*cluster.Fence{},
		Seq:        map[cluster.NodeID]uint64{},
		AppUIDs:    map[string]int{},
	}
}

// Register adds an applier for its types (replacing an earlier one for the
// same type). Call before the log is replayed.
func (f *FSM) Register(a cluster.Applier) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range a.Types() {
		f.appliers[t] = a
	}
}

// Known reports whether an applier handles t.
func (f *FSM) Known(t cluster.CommandType) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.appliers[t] != nil
}

// Halted is why the FSM stopped, or nil.
func (f *FSM) Halted() error {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.halted
}

func refused(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, a...))
}

// Apply applies the log entry at index (a cluster.SignedCommand as JSON).
func (f *FSM) Apply(index uint64, entry []byte) Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	res := Result{Index: index}
	if f.halted != nil {
		res.Err = f.halted
		return res
	}
	if index <= f.s.Index && f.s.Index != 0 {
		// Raft never hands an entry twice; a restored snapshot already has it.
		res.Err = refused("entry %d was already applied", index)
		return res
	}
	defer func() { f.s.Index = index }()

	var sc cluster.SignedCommand
	if err := json.Unmarshal(entry, &sc); err != nil {
		res.Err = refused("not a signed command")
		return res
	}
	c, err := DecodeCommand(sc.Command)
	if err != nil {
		res.Err = refused("%v", err)
		return res
	}
	res.Command = c

	// 1. Signature: against the proposer's key in the current state, or the
	// creator's key for the first entry.
	var proposer *cluster.Node
	if c.Type == cluster.CmdClusterCreate {
		if f.s.Cluster != "" {
			res.Err = refused("the cluster exists already")
			return res
		}
		var b CreateBody
		if err := json.Unmarshal(c.Body, &b); err != nil {
			res.Err = refused("cluster.create: %v", err)
			return res
		}
		if b.Node.ID != c.Proposer || b.Cluster != c.Cluster {
			res.Err = refused("cluster.create must be proposed by the node it creates the cluster with")
			return res
		}
		n := b.Node
		proposer = &n
	} else {
		if f.s.Cluster == "" {
			res.Err = refused("no cluster yet")
			return res
		}
		if c.Cluster != f.s.Cluster {
			res.Err = refused("entry for another cluster")
			return res
		}
		proposer = f.s.Nodes[c.Proposer]
		if proposer == nil || proposer.State == cluster.NodeRemoved {
			res.Err = refused("%s isn't a member", c.Proposer)
			return res
		}
	}
	if err := VerifyNodeKey(proposer); err != nil {
		res.Err = refused("%v", err)
		return res
	}
	if err := Verify(&sc, proposer.PublicKey); err != nil {
		res.Err = refused("bad signature from %s", c.Proposer)
		return res
	}

	// The type must be known before anything else is decided: an unknown
	// type means this node can't follow the log any more.
	a := f.appliers[c.Type]
	if a == nil {
		f.halted = fmt.Errorf("%w at entry %d: unknown command type %q (update this server)", ErrHalted, index, c.Type)
		res.Err = f.halted
		return res
	}

	// 3. Replay guard. A validly signed entry uses its sequence number up
	// even when refused below, so it can't be replayed once its
	// preconditions would hold.
	if c.Seq <= f.s.Seq[c.Proposer] {
		res.Err = refused("replayed or out-of-order entry from %s (seq %d, last %d)", c.Proposer, c.Seq, f.s.Seq[c.Proposer])
		return res
	}
	consume := func() { f.s.Seq[c.Proposer] = c.Seq }

	// 2. Signer role.
	if !slices.Contains(a.Signers(c.Type), proposer.Role) {
		consume()
		res.Err = refused("a %s node may not propose %s", proposer.Role, c.Type)
		return res
	}

	// 4. The applier works on a copy; a refusal leaves the state as it was.
	next := Clone(f.s)
	if err := a.Apply(next, *c); err != nil {
		consume()
		res.Err = fmt.Errorf("%w: %s", ErrRefused, err.Error())
		return res
	}
	next.Seq[c.Proposer] = c.Seq
	f.s = next
	return res
}

// DecodeCommand reads a command's canonical JSON strictly.
func DecodeCommand(raw []byte) (*cluster.Command, error) {
	var c cluster.Command
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("unreadable command: %v", err)
	}
	if c.Type == "" || c.Proposer == "" || c.Seq == 0 {
		return nil, errors.New("command without type, proposer or sequence")
	}
	return &c, nil
}

// VerifyNodeKey checks that a node's key parses as P-256 and matches its
// pin.
func VerifyNodeKey(n *cluster.Node) error {
	if n == nil || len(n.PublicKey) == 0 {
		return errors.New("no key")
	}
	if PinOfKey(n.PublicKey) != n.Pin {
		return fmt.Errorf("%s's key doesn't match its pin", n.ID)
	}
	_, err := ParseKey(n.PublicKey)
	return err
}

// PinOfKey is the SHA-256 (hex) of a SubjectPublicKeyInfo.
func PinOfKey(spki []byte) string {
	sum := sha256.Sum256(spki)
	return hex.EncodeToString(sum[:])
}

// ParseKey reads a P-256 SubjectPublicKeyInfo.
func ParseKey(spki []byte) (*ecdsa.PublicKey, error) {
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("unreadable key: %v", err)
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve.Params().Name != "P-256" {
		return nil, errors.New("the key isn't ECDSA P-256")
	}
	return ek, nil
}

// Verify checks an ES256 signature (ASN.1) over the command's bytes.
func Verify(sc *cluster.SignedCommand, spki []byte) error {
	k, err := ParseKey(spki)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(sc.Command)
	if !ecdsa.VerifyASN1(k, sum[:], sc.Signature) {
		return errors.New("bad signature")
	}
	return nil
}

// ---- reading ---------------------------------------------------------------

// Snapshot returns a deep copy of the state (cluster.State).
func (f *FSM) Snapshot() *cluster.Snapshot {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return Clone(f.s)
}

// Node returns a copy of a member's record.
func (f *FSM) Node(id cluster.NodeID) (*cluster.Node, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	n := f.s.Nodes[id]
	if n == nil {
		return nil, false
	}
	c := cloneNode(n)
	return c, true
}

// Placement returns a copy of a workload's placement.
func (f *FSM) Placement(w cluster.WorkloadRef) (*cluster.Placement, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	p := f.s.Placements[w]
	if p == nil {
		return nil, false
	}
	var c cluster.Placement
	b, _ := json.Marshal(p)
	_ = json.Unmarshal(b, &c)
	return &c, true
}

// Grant returns a copy of a workload's grant.
func (f *FSM) Grant(w cluster.WorkloadRef) (*cluster.Grant, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	g := f.s.Grants[w]
	if g == nil {
		return nil, false
	}
	c := *g
	c.Nodes = slices.Clone(g.Nodes)
	return &c, true
}

// Index is the last applied index.
func (f *FSM) Index() uint64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.s.Index
}

// PinIndex maps every member's pin to its record (removed members are
// gone from the state, so their pins aren't in it).
func (f *FSM) PinIndex() map[string]cluster.Node {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make(map[string]cluster.Node, len(f.s.Nodes))
	for _, n := range f.s.Nodes {
		out[n.Pin] = *cloneNode(n)
	}
	return out
}

func cloneNode(n *cluster.Node) *cluster.Node {
	var c cluster.Node
	b, _ := json.Marshal(n)
	_ = json.Unmarshal(b, &c)
	return &c
}

// ---- snapshots and the codec -----------------------------------------------

// Encode is the state as JSON (Placements and Grants as sorted lists).
func (f *FSM) Encode() ([]byte, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return Encode(f.s)
}

// Restore replaces the state with an encoded one (a Raft snapshot).
func (f *FSM) Restore(data []byte) error {
	s, err := Decode(data)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s = s
	f.halted = nil
	return nil
}

type snapshotAlias cluster.Snapshot

type wireSnapshot struct {
	*snapshotAlias
	Placements []*cluster.Placement `json:"placements"`
	Grants     []*cluster.Grant     `json:"grants"`
}

func refLess(a, b cluster.WorkloadRef) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.ID < b.ID
}

// Encode writes a snapshot as JSON with its maps' lists sorted, so equal
// states encode equally.
func Encode(s *cluster.Snapshot) ([]byte, error) {
	w := wireSnapshot{snapshotAlias: (*snapshotAlias)(s), Placements: []*cluster.Placement{}, Grants: []*cluster.Grant{}}
	for _, p := range s.Placements {
		w.Placements = append(w.Placements, p)
	}
	for _, g := range s.Grants {
		w.Grants = append(w.Grants, g)
	}
	sort.Slice(w.Placements, func(i, j int) bool { return refLess(w.Placements[i].Workload, w.Placements[j].Workload) })
	sort.Slice(w.Grants, func(i, j int) bool { return refLess(w.Grants[i].Workload, w.Grants[j].Workload) })
	return json.Marshal(w)
}

// Decode reads what Encode wrote.
func Decode(data []byte) (*cluster.Snapshot, error) {
	s := Empty()
	w := wireSnapshot{snapshotAlias: (*snapshotAlias)(s)}
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("cluster state: %w", err)
	}
	for _, p := range w.Placements {
		if p != nil {
			s.Placements[p.Workload] = p
		}
	}
	for _, g := range w.Grants {
		if g != nil {
			s.Grants[g.Workload] = g
		}
	}
	if s.Nodes == nil {
		s.Nodes = map[cluster.NodeID]*cluster.Node{}
	}
	if s.Fences == nil {
		s.Fences = map[cluster.NodeID]*cluster.Fence{}
	}
	if s.Seq == nil {
		s.Seq = map[cluster.NodeID]uint64{}
	}
	if s.AppUIDs == nil {
		s.AppUIDs = map[string]int{}
	}
	return s, nil
}

// Clone deep-copies a snapshot.
func Clone(s *cluster.Snapshot) *cluster.Snapshot {
	b, err := Encode(s)
	if err != nil {
		panic(err) // the state is always encodable
	}
	c, err := Decode(b)
	if err != nil {
		panic(err)
	}
	return c
}
