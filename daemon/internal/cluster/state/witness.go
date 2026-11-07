package state

import (
	"errors"
	"slices"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// witness.hello is the only command the witness may sign: its own
// addresses, version and features. The first one after member.add makes it
// active (it is then counted for the voter set: docs/plans/cluster.md 2.2).
// It is sent when the witness starts and when something in it changes, not
// as a heartbeat (heartbeats go over the peer API, not the log).
func applyWitnessHello(s *cluster.Snapshot, c cluster.Command) error {
	var b WitnessHelloBody
	if err := decodeBody(c, &b); err != nil {
		return err
	}
	n := s.Nodes[c.Proposer]
	if n.Role != cluster.RoleWitness {
		return errors.New("only the witness says hello")
	}
	if err := validAddresses(s, n.ID, &b.Addresses, cluster.RoleWitness); err != nil {
		return err
	}
	if err := validFeatures(b.Features); err != nil {
		return err
	}
	if len(b.Version) > 64 || len(b.BootID) > 64 {
		return errors.New("invalid version or boot id")
	}
	if n.State != cluster.NodeJoining && n.Addresses.NetBird == b.Addresses.NetBird && n.Version == b.Version &&
		n.BootID == b.BootID && slices.Equal(n.Features, b.Features) {
		// Nothing changed: not worth a log entry (decision 372).
		return errors.New("the witness's hello changes nothing")
	}
	n.Addresses = b.Addresses
	n.Version = b.Version
	n.Features = slices.Clone(b.Features)
	n.BootID = b.BootID
	if n.State == cluster.NodeJoining {
		n.State = cluster.NodeActive
	}
	return nil
}

// WitnessVotes reports whether the witness should vote given the state:
// only when the number of HardyOS voters is even (decision 322).
func WitnessVotes(s *cluster.Snapshot) bool {
	n := len(HardyVoters(s))
	return n > 0 && n%2 == 0
}

// HardyVoters lists the HardyOS members that vote: every server that isn't
// joining, in maintenance or removed (a dead or fenced voter stays a voter
// until an administrator removes it; nothing is shrunk automatically).
func HardyVoters(s *cluster.Snapshot) []cluster.NodeID {
	var out []cluster.NodeID
	for id, n := range s.Nodes {
		if n.Role == cluster.RoleWitness {
			continue
		}
		switch n.State {
		case cluster.NodeJoining, cluster.NodeMaintenance, cluster.NodeRemoved:
			continue
		}
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// DesiredSuffrage is each member's suffrage as the state wants it (the
// core's rule, cluster.DesiredSuffrage).
func DesiredSuffrage(s *cluster.Snapshot) map[cluster.NodeID]cluster.Suffrage {
	return cluster.DesiredSuffrage(s)
}
