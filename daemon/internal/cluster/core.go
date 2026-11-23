package cluster

// Part A's additions next to the contract: the interfaces between the
// cluster core (this package) and the pure state machine
// (internal/cluster/state), which can't import each other both ways.

// ApplyResult is what the state machine did with one log entry.
type ApplyResult struct {
	Index uint64
	// Command is the decoded entry (nil when it couldn't be decoded).
	Command *Command
	// Err is why the entry was refused (state.ErrRefused) or that the
	// machine stopped (state.ErrHalted).
	Err error
}

// StateMachine is the replicated state as the core drives it
// (state.FSM implements it).
type StateMachine interface {
	State
	Apply(index uint64, entry []byte) ApplyResult
	Encode() ([]byte, error)
	Restore(data []byte) error
	Register(a Applier)
	// Halted is why the machine stopped (an entry it can't apply), or nil.
	Halted() error
	// PinIndex maps every member's pin to its record.
	PinIndex() map[string]Node
	// Admit is the leader's check before it appends an entry: a member's
	// valid signature, a type this build knows at a level the cluster has
	// enabled, and a role allowed to propose it (decision 366). The FSM
	// checks all of it again when the entry applies.
	Admit(sc *SignedCommand) error
	// Reset empties the state before Raft replays the log (never from the
	// network: a snapshot that would empty it is refused).
	Reset()
	// SetRestoreCheck installs the check every restored snapshot must pass
	// against the current state (decision 365).
	SetRestoreCheck(func(cur, next *Snapshot) error)
}

// commandLevels is the feature level each command type needs; types not
// listed need level 1. A new type always gets a level above every earlier
// build's FeatureLevel, so a node that doesn't know a type at a level it
// supports knows the type is bogus (decision 366).
var commandLevels = map[CommandType]int{}

// LevelOf is the feature level a command type needs.
func LevelOf(t CommandType) int {
	if l, ok := commandLevels[t]; ok {
		return l
	}
	return 1
}

// MayLead reports whether a member may act as the cluster's leader: send
// Raft's AppendEntries, InstallSnapshot, TimeoutNow and vote requests, and
// sign heartbeat answers. Only HardyOS servers that are active (or
// rejoining after a fence, or in maintenance and handing over); never the
// witness, a joining server, a dead or fenced one (decision 365).
func MayLead(n Node) bool {
	if n.Role != RoleCompute && n.Role != RoleStorage {
		return false
	}
	switch n.State {
	case NodeActive, NodeRejoining, NodeMaintenance:
		return true
	}
	return false
}

// Part A implements the contract's interfaces with these.
var (
	_ Membership = (*Core)(nil)
	_ PeerClient = (*peerClient)(nil)
	_ PeerMux    = (*peerMux)(nil)
	_ PeerBook   = (*Core)(nil)
)
