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
}

// Part A implements the contract's interfaces with these.
var (
	_ Membership = (*Core)(nil)
	_ PeerClient = (*peerClient)(nil)
	_ PeerMux    = (*peerMux)(nil)
	_ PeerBook   = (*Core)(nil)
)
