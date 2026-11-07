package state

// Part C's node fencing appliers (docs/plans/cluster.md section 7.3):
// node.dead, node.isolated, node.rejoin and the per-node watchdog override,
// plus the timing bounds part A's cluster.timings applier checks.
//
// The storage node's side (storage.fenced, storage.unfenced) is part B's
// applier: it sets the Fence's Confirmed flag and moves the node to fenced
// (and back to active after a rejoin). Recovery waits for Confirmed.

import (
	"errors"
	"fmt"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// NodeDeadBody declares a node dead (the HA coordinator on the leader).
// Epoch must be the node's FenceEpoch + 1.
type NodeDeadBody struct {
	Node  cluster.NodeID `json:"node"`
	Epoch uint64         `json:"epoch"`
	// Reason: "dead" (not heard for F), "removed" (Remove node), or
	// "isolated" (node.isolated uses it).
	Reason string `json:"reason"`
}

// NodeRejoinBody is a fenced node coming back.
type NodeRejoinBody struct {
	Node   cluster.NodeID `json:"node"`
	Epoch  uint64         `json:"epoch"`
	BootID string         `json:"bootId"`
	// Clean: the node stopped and detached every cluster workload itself
	// (an isolated node whose self-fence finished without a reset). Only
	// then may it rejoin without a new boot.
	Clean bool `json:"clean,omitempty"`
}

// WatchdogOverrideBody allows (or stops allowing) HA workloads on a node
// without a hardware watchdog. Confirm must be the node's id.
type WatchdogOverrideBody struct {
	Node    cluster.NodeID `json:"node"`
	Allow   bool           `json:"allow"`
	Confirm string         `json:"confirm"`
}

// Fences is part C's applier for node fencing.
type Fences struct{}

var _ cluster.Applier = Fences{}

// Every FSM (members and the witness) applies the fencing commands.
func init() { register(Fences{}) }

// Types implements cluster.Applier.
func (Fences) Types() []cluster.CommandType {
	return []cluster.CommandType{cluster.CmdNodeDead, cluster.CmdNodeIsolated, cluster.CmdNodeRejoin, cluster.CmdHAWatchdog}
}

// Signers implements cluster.Applier.
func (Fences) Signers(t cluster.CommandType) []cluster.Role {
	if t == cluster.CmdNodeRejoin {
		// Only the node itself (checked in Apply).
		return []cluster.Role{cluster.RoleCompute}
	}
	return hardyOSMembers
}

// Apply implements cluster.Applier.
func (Fences) Apply(s *cluster.Snapshot, c cluster.Command) error {
	ensure(s)
	switch c.Type {
	case cluster.CmdNodeDead, cluster.CmdNodeIsolated:
		var b NodeDeadBody
		if err := decode(c, &b); err != nil {
			return err
		}
		reason := b.Reason
		if c.Type == cluster.CmdNodeIsolated {
			reason = "isolated"
		} else if reason != "dead" && reason != "removed" {
			return fmt.Errorf("node.dead's reason is dead or removed, not %q", reason)
		}
		return applyDead(s, c, b, reason)
	case cluster.CmdNodeRejoin:
		var b NodeRejoinBody
		if err := decode(c, &b); err != nil {
			return err
		}
		return applyRejoin(s, c, b)
	case cluster.CmdHAWatchdog:
		var b WatchdogOverrideBody
		if err := decode(c, &b); err != nil {
			return err
		}
		node, ok := s.Nodes[b.Node]
		if !ok || node.Role != cluster.RoleCompute {
			return fmt.Errorf("%s isn't a compute server", b.Node)
		}
		if b.Confirm != string(b.Node) {
			return fmt.Errorf("type the server's name (%s) to confirm", b.Node)
		}
		if !b.Allow {
			for _, p := range s.Placements {
				if p.Owner == b.Node && p.HA.Enabled && (node.Compute == nil || node.Compute.Watchdog != "hardware") {
					return fmt.Errorf("%s still runs HA workloads (%s); move them or turn HA off for them first", b.Node, p.Name)
				}
			}
			delete(s.HAOverrides, b.Node)
			return nil
		}
		kind := ""
		if node.Compute != nil {
			kind = node.Compute.Watchdog
		}
		if kind == "hardware" {
			return fmt.Errorf("%s has a hardware watchdog; nothing to allow", b.Node)
		}
		if kind == "" {
			// Without any watchdog nothing resets a hung server: only
			// softdog may be allowed (decision 391).
			return fmt.Errorf("%s has no watchdog at all; load its watchdog driver (or softdog) first", b.Node)
		}
		s.HAOverrides[b.Node] = &cluster.WatchdogOverride{Node: b.Node, Kind: kind, Actor: c.Actor, At: c.Time}
		return nil
	}
	return fmt.Errorf("fences: unexpected command %s", c.Type)
}

func applyDead(s *cluster.Snapshot, c cluster.Command, b NodeDeadBody, reason string) error {
	node, ok := s.Nodes[b.Node]
	if !ok {
		return fmt.Errorf("%s isn't a member", b.Node)
	}
	if node.Role != cluster.RoleCompute {
		// The storage node never self-fences and is never fenced: nothing
		// could run without it anyway (section 7.2).
		return fmt.Errorf("only compute servers are fenced, not %s (%s)", b.Node, node.Role)
	}
	switch node.State {
	case cluster.NodeActive, cluster.NodeMaintenance, cluster.NodeRejoining, cluster.NodeJoining:
	default:
		return fmt.Errorf("%s is already %s", b.Node, node.State)
	}
	if b.Epoch != node.FenceEpoch+1 {
		return fmt.Errorf("%w: %s's next fence epoch is %d", cluster.ErrStaleGeneration, b.Node, node.FenceEpoch+1)
	}
	node.State = cluster.NodeDead
	node.FenceEpoch = b.Epoch
	// The boot the node had when it was declared dead: a rejoin must come
	// from another one (member.update records the boot id at every start).
	s.Fences[b.Node] = &cluster.Fence{Node: b.Node, Epoch: b.Epoch, Reason: reason, Requested: c.Time, BootID: node.BootID}
	for _, p := range s.Placements {
		g := s.Grants[p.Workload]
		switch {
		case p.Owner == b.Node && g != nil && g.Mode == cluster.GrantMigration:
			// The source of a live migration died: the destination may or
			// may not have the VM. The two-node grant (and Target) stay;
			// the coordinator collapses it once the fence holds.
			p.State = recoverOrOrphan(p)
		case p.Owner == b.Node:
			p.Target = ""
			p.State = recoverOrOrphan(p)
		case p.Target == b.Node:
			// The destination of a move died: the move is over; a live
			// migration's grant stays two-node until the fence holds and
			// the coordinator collapses it to the source.
			if g == nil || g.Mode != cluster.GrantMigration {
				p.Target = ""
			}
		default:
			continue
		}
		p.Changed = c.Time
	}
	return nil
}

// recoverOrOrphan is a dead owner's workload's state: HA workloads wait
// for the fence and recovery; others are orphaned until someone starts
// them elsewhere (they keep their last state so the UI can say what it was).
func recoverOrOrphan(p *cluster.Placement) cluster.PlacementState {
	if p.HA.Enabled && p.Requested == cluster.RequestRunning {
		p.Problem = "its server is down; waiting for the storage server to cut it off"
		return cluster.PlacementRecovering
	}
	p.Problem = "its server is down (orphaned): start it on another server"
	return cluster.PlacementStopped
}

func applyRejoin(s *cluster.Snapshot, c cluster.Command, b NodeRejoinBody) error {
	if c.Proposer != b.Node {
		return errors.New("only the node itself rejoins")
	}
	node, ok := s.Nodes[b.Node]
	if !ok {
		return fmt.Errorf("%s isn't a member", b.Node)
	}
	f := s.Fences[b.Node]
	if node.State != cluster.NodeFenced || f == nil || !f.Confirmed {
		return fmt.Errorf("%s isn't fenced (it is %s)", b.Node, node.State)
	}
	if b.Epoch != node.FenceEpoch {
		return fmt.Errorf("%w: %s's fence epoch is %d", cluster.ErrStaleGeneration, b.Node, node.FenceEpoch)
	}
	if b.BootID == "" {
		return errors.New("a rejoin carries the node's boot id")
	}
	fencedBoot := f.BootID
	if fencedBoot == "" {
		fencedBoot = node.BootID
	}
	if b.BootID == fencedBoot && !(f.Reason == "isolated" && b.Clean) {
		return fmt.Errorf("%s must restart before it rejoins (it was fenced as %s)", b.Node, f.Reason)
	}
	node.BootID = b.BootID
	node.State = cluster.NodeRejoining
	// Whatever still names the node is stale: a new generation (with a
	// grant the storage node applies afresh), stopped until the node
	// reconciles. Its old processes can't match the new generation, so the
	// node stops them before anything starts.
	for _, p := range s.Placements {
		if p.Owner != b.Node {
			continue
		}
		p.Generation++
		p.State = cluster.PlacementStopped
		p.Target = ""
		p.Changed = c.Time
		s.Grants[p.Workload] = &cluster.Grant{Workload: p.Workload, Nodes: []cluster.NodeID{b.Node}, Mode: cluster.GrantExclusive, Generation: p.Generation}
	}
	return nil
}

// ---- timings -----------------------------------------------------------------

// Bounds on the configurable timings (decision 353). The invariant
// Dead >= QuorumLease + Watchdog + 10s and SelfStop < Watchdog always
// holds; the bounds keep each value in a range where the design works.
var (
	MinHeartbeat, MaxHeartbeat             = 500 * time.Millisecond, 5 * time.Second
	MinQuorumLease, MaxQuorumLease         = 5 * time.Second, 120 * time.Second
	MinWatchdog, MaxWatchdog               = 5 * time.Second, 60 * time.Second
	MinSelfStop                            = 2 * time.Second
	MaxDead                                = 10 * time.Minute
	DeadMargin                             = 10 * time.Second
	MinStorageIsolated                     = 5 * time.Second
	MinLANIsolated                         = 30 * time.Second
	MinFenceAck, MaxFenceAck               = 10 * time.Second, 5 * time.Minute
	heartbeatsPerLease             float64 = 5
)

// ValidateTimings checks timings against the safety invariant and the
// bounds. Part A's cluster.timings applier calls it, so an unsafe value is
// refused by every node, not only by the API.
func ValidateTimings(t cluster.Timings) error {
	var p []string
	chk := func(ok bool, msg string, args ...any) {
		if !ok {
			p = append(p, fmt.Sprintf(msg, args...))
		}
	}
	chk(t.Heartbeat >= MinHeartbeat && t.Heartbeat <= MaxHeartbeat, "the heartbeat is %s-%s", MinHeartbeat, MaxHeartbeat)
	chk(t.QuorumLease >= MinQuorumLease && t.QuorumLease <= MaxQuorumLease, "the quorum lease is %s-%s", MinQuorumLease, MaxQuorumLease)
	chk(float64(t.QuorumLease) >= heartbeatsPerLease*float64(t.Heartbeat), "the quorum lease is at least 5 heartbeats")
	chk(t.Watchdog >= MinWatchdog && t.Watchdog <= MaxWatchdog, "the watchdog timeout is %s-%s", MinWatchdog, MaxWatchdog)
	chk(t.SelfStop >= MinSelfStop && t.SelfStop < t.Watchdog, "the self-stop time is at least %s and shorter than the watchdog timeout", MinSelfStop)
	chk(t.Dead >= t.QuorumLease+t.Watchdog+DeadMargin, "a server is declared dead no sooner than quorum lease + watchdog + %s (%s)", DeadMargin, t.QuorumLease+t.Watchdog+DeadMargin)
	chk(t.Dead <= MaxDead, "a server is declared dead within %s", MaxDead)
	chk(t.Suspect >= 2*t.Heartbeat && t.Suspect < t.Dead, "suspect comes after two heartbeats and before dead")
	chk(t.StorageIsolated >= MinStorageIsolated, "storage isolation takes at least %s", MinStorageIsolated)
	chk(t.LANIsolated >= MinLANIsolated, "LAN isolation takes at least %s", MinLANIsolated)
	chk(t.FenceAck >= MinFenceAck && t.FenceAck <= MaxFenceAck, "the fence acknowledgement wait is %s-%s", MinFenceAck, MaxFenceAck)
	if len(p) > 0 {
		return &TimingsError{Problems: p}
	}
	return nil
}

// TimingsError lists every problem with proposed timings.
type TimingsError struct{ Problems []string }

func (e *TimingsError) Error() string {
	out := "unsafe cluster timings: "
	for i, x := range e.Problems {
		if i > 0 {
			out += "; "
		}
		out += x
	}
	return out
}
