package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Part A's appliers: the cluster itself and its members.

func init() { register(membersApplier{}) }

// FeatureLevel is the feature level this build supports at most; members
// announce "cluster/<n>" for every level they support.
const FeatureLevel = 1

// FeatureName is the feature string a member announces for level n.
func FeatureName(n int) string { return "cluster/" + strconv.Itoa(n) }

// Features is what this build announces.
func Features() []string {
	out := []string{}
	for i := 1; i <= FeatureLevel; i++ {
		out = append(out, FeatureName(i))
	}
	return out
}

var nodeIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ValidNodeID checks a node id (contract: lowercase letters, digits and
// '-', 1-32 characters, starting with a letter).
func ValidNodeID(id cluster.NodeID) error {
	if !nodeIDRE.MatchString(string(id)) || strings.HasSuffix(string(id), "-") {
		return fmt.Errorf("%q isn't a valid server name: 1-32 lowercase letters, digits and '-', starting with a letter", id)
	}
	return nil
}

var clusterIDRE = regexp.MustCompile(`^[a-z2-7]{26}$`)

// ValidClusterID checks a cluster id (128 bits, base32 lowercase, no
// padding).
func ValidClusterID(id cluster.ClusterID) error {
	if !clusterIDRE.MatchString(string(id)) {
		return errors.New("invalid cluster id")
	}
	return nil
}

// CreateBody is cluster.create's body.
type CreateBody struct {
	Cluster       cluster.ClusterID `json:"cluster"`
	Name          string            `json:"name"`
	Node          cluster.Node      `json:"node"`
	StorageSubnet netip.Prefix      `json:"storageSubnet"`
}

// MemberAddBody is member.add's body.
type MemberAddBody struct {
	Node cluster.Node `json:"node"`
}

// MemberReadyBody is member.ready's body (the proposer is the node).
type MemberReadyBody struct{}

// MemberUpdateBody is member.update's body: the proposer's own record.
type MemberUpdateBody struct {
	Addresses *cluster.Addresses   `json:"addresses,omitempty"`
	Version   string               `json:"version,omitempty"`
	Features  []string             `json:"features,omitempty"`
	BootID    string               `json:"bootId,omitempty"`
	Compute   *cluster.ComputeInfo `json:"compute,omitempty"`
}

// MemberRemoveBody is member.remove's body.
type MemberRemoveBody struct {
	Node cluster.NodeID `json:"node"`
}

// MaintenanceBody is node.maintenance's body.
type MaintenanceBody struct {
	Node  cluster.NodeID `json:"node"`
	Enter bool           `json:"enter"`
}

// FeatureLevelBody is cluster.featurelevel's body.
type FeatureLevelBody struct {
	Level int `json:"level"`
}

// WitnessHelloBody is witness.hello's body: the witness's own record.
type WitnessHelloBody struct {
	Addresses cluster.Addresses `json:"addresses"`
	Version   string            `json:"version"`
	Features  []string          `json:"features,omitempty"`
	BootID    string            `json:"bootId,omitempty"`
}

var hardy = []cluster.Role{cluster.RoleCompute, cluster.RoleStorage}

type membersApplier struct{}

func (membersApplier) Types() []cluster.CommandType {
	return []cluster.CommandType{cluster.CmdClusterCreate, cluster.CmdMemberAdd, cluster.CmdMemberReady,
		cluster.CmdMemberUpdate, cluster.CmdMemberRemove, cluster.CmdMaintenance, cluster.CmdFeatureLevel,
		cluster.CmdTimings, cluster.CmdWitnessHello}
}

func (membersApplier) Signers(t cluster.CommandType) []cluster.Role {
	if t == cluster.CmdWitnessHello {
		return []cluster.Role{cluster.RoleWitness}
	}
	return hardy
}

func decodeBody(c cluster.Command, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(c.Body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: unreadable body: %v", c.Type, err)
	}
	return nil
}

func (m membersApplier) Apply(s *cluster.Snapshot, c cluster.Command) error {
	switch c.Type {
	case cluster.CmdClusterCreate:
		return applyCreate(s, c)
	case cluster.CmdMemberAdd:
		return applyAdd(s, c)
	case cluster.CmdMemberReady:
		return applyReady(s, c)
	case cluster.CmdMemberUpdate:
		return applyUpdate(s, c)
	case cluster.CmdMemberRemove:
		return applyRemove(s, c)
	case cluster.CmdMaintenance:
		return applyMaintenance(s, c)
	case cluster.CmdFeatureLevel:
		return applyFeatureLevel(s, c)
	case cluster.CmdTimings:
		return applyTimings(s, c)
	case cluster.CmdWitnessHello:
		return applyWitnessHello(s, c)
	}
	return fmt.Errorf("%s isn't a membership command", c.Type)
}

// checkNewNode validates a node record about to be added.
func checkNewNode(s *cluster.Snapshot, n *cluster.Node) error {
	if err := ValidNodeID(n.ID); err != nil {
		return err
	}
	switch n.Role {
	case cluster.RoleCompute, cluster.RoleStorage, cluster.RoleWitness:
	default:
		return fmt.Errorf("unknown role %q", n.Role)
	}
	if err := VerifyNodeKey(n); err != nil {
		return err
	}
	if len(n.Name) == 0 || len(n.Name) > 64 {
		return errors.New("a server name is 1-64 characters")
	}
	if err := validAddresses(s, n.ID, &n.Addresses, n.Role); err != nil {
		return err
	}
	for _, o := range s.Nodes {
		switch {
		case o.ID == n.ID:
			return fmt.Errorf("a member is already called %s", n.ID)
		case strings.EqualFold(o.Name, n.Name):
			return fmt.Errorf("a member already has the hostname %s", n.Name)
		case o.Pin == n.Pin:
			return errors.New("that key already belongs to a member")
		case n.Role == cluster.RoleStorage && o.Role == cluster.RoleStorage:
			return fmt.Errorf("the cluster already has a storage node (%s)", o.ID)
		case n.Role == cluster.RoleWitness && o.Role == cluster.RoleWitness:
			return fmt.Errorf("the cluster already has a witness (%s)", o.ID)
		}
	}
	return nil
}

func applyCreate(s *cluster.Snapshot, c cluster.Command) error {
	var b CreateBody
	if err := decodeBody(c, &b); err != nil {
		return err
	}
	if err := ValidClusterID(b.Cluster); err != nil {
		return err
	}
	if b.Name == "" || len(b.Name) > 64 {
		return errors.New("a cluster name is 1-64 characters")
	}
	if b.Node.Role == cluster.RoleWitness {
		return errors.New("the witness can't create a cluster")
	}
	if b.StorageSubnet.IsValid() && (!b.StorageSubnet.Addr().Is4() || b.StorageSubnet.Bits() < 8 || b.StorageSubnet.Bits() > 30) {
		return errors.New("the storage network is an IPv4 prefix between /8 and /30")
	}
	s.StorageSubnet = b.StorageSubnet.Masked()
	n := b.Node
	if err := checkNewNode(s, &n); err != nil {
		s.StorageSubnet = netip.Prefix{}
		return err
	}
	s.Cluster, s.Name, s.FeatureLevel = b.Cluster, b.Name, 1
	s.Timings = cluster.DefaultTimings
	n.State, n.Suffrage, n.Joined, n.FenceEpoch = cluster.NodeActive, cluster.Voter, c.Time, 0
	s.Nodes[n.ID] = &n
	return nil
}

func activeHardy(n *cluster.Node) bool {
	return n != nil && n.Role != cluster.RoleWitness && n.State == cluster.NodeActive
}

func applyAdd(s *cluster.Snapshot, c cluster.Command) error {
	if !activeHardy(s.Nodes[c.Proposer]) {
		return errors.New("only an active server can add members")
	}
	var b MemberAddBody
	if err := decodeBody(c, &b); err != nil {
		return err
	}
	n := b.Node
	if err := checkNewNode(s, &n); err != nil {
		return err
	}
	n.State, n.Suffrage, n.Joined, n.FenceEpoch, n.BootID = cluster.NodeJoining, cluster.NonVoter, c.Time, 0, ""
	s.Nodes[n.ID] = &n
	return nil
}

func applyReady(s *cluster.Snapshot, c cluster.Command) error {
	var b MemberReadyBody
	if err := decodeBody(c, &b); err != nil {
		return err
	}
	n := s.Nodes[c.Proposer]
	if n.State != cluster.NodeJoining {
		return fmt.Errorf("%s isn't joining", n.ID)
	}
	n.State, n.Suffrage = cluster.NodeActive, cluster.Voter
	return nil
}

// validAddresses checks a member's addresses (decision 374): the witness
// has a NetBird address only (it may not claim a LAN or storage address,
// which the storage node's firewall would trust); a server has a LAN
// address, and a storage address only inside the cluster's storage network
// (without one, a storage address isn't recorded); only the storage node
// has portals, on its storage address; and no address may be one another
// member already uses.
func validAddresses(s *cluster.Snapshot, self cluster.NodeID, a *cluster.Addresses, role cluster.Role) error {
	if role == cluster.RoleWitness {
		if !a.NetBird.IsValid() {
			return errors.New("the witness needs a NetBird address")
		}
		if a.LAN.IsValid() || a.Storage.IsValid() || len(a.Portals) > 0 {
			return errors.New("the witness has a NetBird address only")
		}
	} else if !a.LAN.IsValid() {
		return errors.New("a server needs a LAN address")
	}
	if a.Storage.IsValid() {
		if !s.StorageSubnet.IsValid() {
			a.Storage = netip.Addr{}
		} else if !s.StorageSubnet.Contains(a.Storage) || a.Storage == s.StorageSubnet.Masked().Addr() {
			return fmt.Errorf("the storage address %s isn't on the storage network %s", a.Storage, s.StorageSubnet)
		}
	}
	if len(a.Portals) > 4 {
		return errors.New("at most four portals")
	}
	if len(a.Portals) > 0 && role != cluster.RoleStorage {
		return errors.New("only the storage node has iSCSI portals")
	}
	for _, p := range a.Portals {
		if !p.IsValid() || p.Addr() != a.Storage {
			return errors.New("the iSCSI portals are on the storage node's storage address")
		}
	}
	mine := []netip.Addr{a.LAN, a.Storage, a.NetBird}
	for i, x := range mine {
		if !x.IsValid() {
			continue
		}
		if x.IsUnspecified() || x.IsMulticast() || x.IsLoopback() {
			return fmt.Errorf("%s isn't a usable address", x)
		}
		for _, y := range mine[i+1:] {
			if x == y {
				return fmt.Errorf("%s is given for two paths", x)
			}
		}
	}
	for id, o := range s.Nodes {
		if id == self {
			continue
		}
		for _, y := range []netip.Addr{o.Addresses.LAN, o.Addresses.Storage, o.Addresses.NetBird} {
			for _, x := range mine {
				if x.IsValid() && x == y {
					return fmt.Errorf("%s is %s's address", x, id)
				}
			}
		}
	}
	return nil
}

func validFeatures(f []string) error {
	if len(f) > 64 {
		return errors.New("too many features")
	}
	for _, x := range f {
		if len(x) == 0 || len(x) > 64 {
			return errors.New("invalid feature name")
		}
	}
	return nil
}

func applyUpdate(s *cluster.Snapshot, c cluster.Command) error {
	var b MemberUpdateBody
	if err := decodeBody(c, &b); err != nil {
		return err
	}
	n := s.Nodes[c.Proposer]
	if b.Addresses != nil {
		a := *b.Addresses
		if err := validAddresses(s, n.ID, &a, n.Role); err != nil {
			return err
		}
		n.Addresses = a
	}

	if b.Version != "" {
		if len(b.Version) > 64 {
			return errors.New("invalid version")
		}
		n.Version = b.Version
	}
	if b.Features != nil {
		if err := validFeatures(b.Features); err != nil {
			return err
		}
		n.Features = slices.Clone(b.Features)
	}
	if b.BootID != "" {
		if err := cluster.ValidBootID(b.BootID); err != nil {
			return err
		}
		n.BootID = b.BootID
	}
	if b.Compute != nil {
		if n.Role != cluster.RoleCompute {
			return errors.New("only compute nodes have compute details")
		}
		ci := *b.Compute
		n.Compute = &ci
	}
	return nil
}

func applyRemove(s *cluster.Snapshot, c cluster.Command) error {
	var b MemberRemoveBody
	if err := decodeBody(c, &b); err != nil {
		return err
	}
	p := s.Nodes[c.Proposer]
	if b.Node != c.Proposer && !activeHardy(p) {
		return errors.New("only an active server can remove another member")
	}
	n := s.Nodes[b.Node]
	if n == nil {
		return fmt.Errorf("%s isn't a member", b.Node)
	}
	others := 0
	compute := 0
	for _, o := range s.Nodes {
		if o.ID != n.ID && o.Role != cluster.RoleWitness {
			others++
			if o.Role == cluster.RoleCompute {
				compute++
			}
		}
	}
	if n.Role != cluster.RoleWitness && others == 0 {
		return errors.New("the last server can't be removed: dissolve the cluster instead")
	}
	if n.Role == cluster.RoleStorage && compute > 0 {
		return errors.New("the storage node leaves last: remove the compute servers first")
	}
	for _, pl := range s.Placements {
		if pl.Owner == n.ID || pl.Target == n.ID {
			return fmt.Errorf("%s still has cluster workloads (%s): move them first", n.ID, pl.Workload.ID)
		}
	}
	for _, g := range s.Grants {
		if slices.Contains(g.Nodes, n.ID) {
			return fmt.Errorf("%s still holds storage of %s", n.ID, g.Workload.ID)
		}
	}
	// The record goes: its pin is refused from now on, and a new install
	// joins with a new key. Its sequence number stays (harmless: a new key
	// can't sign the old entries).
	delete(s.Nodes, n.ID)
	delete(s.Fences, n.ID)
	return nil
}

func applyMaintenance(s *cluster.Snapshot, c cluster.Command) error {
	if !activeHardy(s.Nodes[c.Proposer]) && s.Nodes[c.Proposer].State != cluster.NodeMaintenance {
		return errors.New("only an active server can change maintenance")
	}
	var b MaintenanceBody
	if err := decodeBody(c, &b); err != nil {
		return err
	}
	n := s.Nodes[b.Node]
	if n == nil || n.Role == cluster.RoleWitness {
		return fmt.Errorf("%s isn't a server of the cluster", b.Node)
	}
	switch {
	case b.Enter && n.State == cluster.NodeActive:
		n.State, n.Suffrage = cluster.NodeMaintenance, cluster.NonVoter
	case !b.Enter && n.State == cluster.NodeMaintenance:
		n.State, n.Suffrage = cluster.NodeActive, cluster.Voter
	default:
		return fmt.Errorf("%s is %s", n.ID, n.State)
	}
	return nil
}

func applyFeatureLevel(s *cluster.Snapshot, c cluster.Command) error {
	var b FeatureLevelBody
	if err := decodeBody(c, &b); err != nil {
		return err
	}
	if b.Level <= s.FeatureLevel {
		return fmt.Errorf("the feature level is %d already", s.FeatureLevel)
	}
	want := FeatureName(b.Level)
	ids := make([]string, 0, len(s.Nodes))
	for id := range s.Nodes {
		ids = append(ids, string(id))
	}
	slices.Sort(ids)
	for _, id := range ids {
		n := s.Nodes[cluster.NodeID(id)]
		if !slices.Contains(n.Features, want) {
			return fmt.Errorf("%s doesn't support feature level %d yet: update it first", n.ID, b.Level)
		}
	}
	s.FeatureLevel = b.Level
	return nil
}

// CheckTimings checks the fencing invariant (docs/plans/cluster.md 7.1).
func CheckTimings(t cluster.Timings) error {
	for _, d := range []struct {
		name string
		v    int64
	}{{"heartbeat", int64(t.Heartbeat)}, {"suspect", int64(t.Suspect)}, {"quorum lease", int64(t.QuorumLease)},
		{"self-stop", int64(t.SelfStop)}, {"watchdog", int64(t.Watchdog)}, {"dead", int64(t.Dead)},
		{"storage isolation", int64(t.StorageIsolated)}, {"LAN isolation", int64(t.LANIsolated)}, {"fence acknowledgement", int64(t.FenceAck)}} {
		if d.v <= 0 {
			return fmt.Errorf("the %s time must be positive", d.name)
		}
	}
	const tenSeconds = int64(10_000_000_000)
	if int64(t.Dead) < int64(t.QuorumLease)+int64(t.Watchdog)+tenSeconds {
		return errors.New("dead must be at least quorum lease + watchdog + 10 s")
	}
	if t.SelfStop >= t.Watchdog {
		return errors.New("self-stop must be shorter than the watchdog")
	}
	if t.Heartbeat >= t.Suspect || t.Heartbeat*3 > t.QuorumLease {
		return errors.New("the heartbeat must be well inside the suspect time and the quorum lease")
	}
	// Part C's bounds (decision 353): every node refuses what the API
	// refuses, so an unsafe value can't reach the state through another
	// member.
	return ValidateTimings(t)
}

func applyTimings(s *cluster.Snapshot, c cluster.Command) error {
	var t cluster.Timings
	if err := decodeBody(c, &t); err != nil {
		return err
	}
	if err := CheckTimings(t); err != nil {
		return err
	}
	s.Timings = t
	return nil
}
