package fence

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Cluster is what the agent reads from part A's Membership.
type Cluster interface {
	Self() (cluster.Node, error)
	State() cluster.State
	// Quorate: whether this node's quorum lease is valid, and until when
	// (monotonic).
	Quorate() (bool, time.Time)
}

// SelfFencer stops HA workloads by force and detaches their storage
// (cluster.selffence through hardyd-priv, then the attacher). It returns
// nil only when all of them are stopped.
type SelfFencer interface {
	SelfFence(ctx context.Context, epoch uint64, ws []cluster.WorkloadRef) error
}

// LocalRunning lists the cluster workloads running on this node now.
type LocalRunning func(ctx context.Context) ([]cluster.WorkloadStatus, error)

// AgentStatus is the agent's view, for the Cluster app.
type AgentStatus struct {
	State   cluster.FenceState `json:"state"`
	Kind    string             `json:"kind"`
	Problem string             `json:"problem,omitempty"`
	// HAHere are the HA workloads placed on (or running on) this node.
	HAHere       []cluster.WorkloadRef `json:"haHere"`
	LastFence    time.Time             `json:"lastFence,omitzero"`
	FenceReason  string                `json:"fenceReason,omitempty"`
	CleanStopped bool                  `json:"cleanStopped"`
}

// Agent is the node-local self-fencing state machine (cluster.FenceAgent):
//
//	DISARMED --(an HA workload is placed or runs here)--> ARMED: the
//	  watchdog is open and root pets it while the quorum lease is valid
//	ARMED --(lease lost, or the state says this node is dead/isolated)-->
//	  SELF-FENCING: root stops petting; HA workloads are killed and
//	  detached; done within S -> disarm -> DISARMED; not done -> the
//	  watchdog resets the server within W
//	ARMED --(no HA workload here any more, quorate)--> DISARMED
type Agent struct {
	Cluster  Cluster
	Watchdog cluster.Watchdog
	Fencer   SelfFencer
	Running  LocalRunning
	Log      *slog.Logger
	// Now is the clock (monotonic; tests fake it).
	Now func() time.Time
	// OnChange is called after every state change (events, alerts).
	OnChange func(AgentStatus)

	mu         sync.Mutex
	state      cluster.FenceState
	kind       string
	problem    string
	fencing    bool      // a self-fence is running
	fenceStart time.Time // when the current self-fence began
	fenceDone  bool      // it finished with everything stopped
	fenceErr   error
	lastFence  time.Time
	reason     string
	clean      bool
	haHere     []cluster.WorkloadRef
}

var _ cluster.FenceAgent = (*Agent)(nil)

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Agent) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

// State implements cluster.FenceAgent.
func (a *Agent) State() cluster.FenceState {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state == "" {
		return cluster.FenceDisarmed
	}
	return a.state
}

// Status reports the agent's view.
func (a *Agent) Status() AgentStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.statusLocked()
}

func (a *Agent) statusLocked() AgentStatus {
	st := a.state
	if st == "" {
		st = cluster.FenceDisarmed
	}
	return AgentStatus{State: st, Kind: a.kind, Problem: a.problem, HAHere: slices.Clone(a.haHere),
		LastFence: a.lastFence, FenceReason: a.reason, CleanStopped: a.clean}
}

// Run implements cluster.FenceAgent: Step every half heartbeat.
func (a *Agent) Run(ctx context.Context) error {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		a.Step(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// ownFence reports whether the applied state orders this node to fence
// itself: it was declared dead or isolated (or is fenced and hasn't
// rejoined).
func ownFence(s *cluster.Snapshot, self cluster.NodeID) (bool, string) {
	n, ok := s.Nodes[self]
	if !ok {
		return false, ""
	}
	switch n.State {
	case cluster.NodeDead, cluster.NodeFenced, cluster.NodeRemoved:
		reason := string(n.State)
		if f := s.Fences[self]; f != nil && f.Epoch == n.FenceEpoch {
			reason = f.Reason
		}
		return true, reason
	}
	return false, ""
}

// haWorkloads are the HA workloads that run here, and, while the node is
// quorate and not ordered to fence, those placed here (as owner or
// migration target) about to run: the watchdog is armed before they start.
func haWorkloads(s *cluster.Snapshot, self cluster.NodeID, running []cluster.WorkloadStatus, placed bool) []cluster.WorkloadRef {
	set := map[cluster.WorkloadRef]bool{}
	for w, p := range s.Placements {
		if !p.HA.Enabled || !placed {
			continue
		}
		if p.Owner == self || p.Target == self {
			switch p.State {
			case cluster.PlacementRunning, cluster.PlacementStarting, cluster.PlacementMigrating, cluster.PlacementStopping, cluster.PlacementMoving:
				set[w] = true
			}
		}
	}
	for _, r := range running {
		if !r.Running && !r.Paused {
			continue
		}
		p, ok := s.Placements[r.Workload]
		if !ok || p.HA.Enabled {
			// A cluster workload running here that the state doesn't know
			// (or knows as HA) is protected like an HA one.
			set[r.Workload] = true
		}
	}
	out := make([]cluster.WorkloadRef, 0, len(set))
	for w := range set {
		out = append(out, w)
	}
	slices.SortFunc(out, func(x, y cluster.WorkloadRef) int {
		if x.Kind != y.Kind {
			if x.Kind < y.Kind {
				return -1
			}
			return 1
		}
		if x.ID < y.ID {
			return -1
		}
		if x.ID > y.ID {
			return 1
		}
		return 0
	})
	return out
}

// Step runs one round of the state machine.
func (a *Agent) Step(ctx context.Context) {
	self, err := a.Cluster.Self()
	if err != nil {
		// Not in a cluster: nothing to protect. A leftover arm is let go.
		a.mu.Lock()
		armed := a.state == cluster.FenceArmed
		a.mu.Unlock()
		if armed {
			a.disarm(ctx, "left the cluster")
		}
		return
	}
	s := a.Cluster.State().Snapshot()
	t := s.Timings
	if t.Watchdog == 0 {
		t = cluster.DefaultTimings
	}
	var running []cluster.WorkloadStatus
	known := true
	if a.Running != nil {
		running, err = a.Running(ctx)
		if err != nil {
			// Unknown is treated as "everything placed here may run": the
			// agent never disarms on a list it couldn't read.
			known = false
			a.log().Warn("fence: listing local workloads", "err", err)
		}
	}
	quorate, until := a.Cluster.Quorate()
	ordered, why := ownFence(s, self.ID)
	ha := haWorkloads(s, self.ID, running, (quorate && !ordered) || !known)
	now := a.now()

	a.mu.Lock()
	a.haHere = ha
	state := a.state
	if state == "" {
		state = cluster.FenceDisarmed
	}
	fencing, done := a.fencing, a.fenceDone
	a.mu.Unlock()

	switch state {
	case cluster.FenceDisarmed:
		if len(ha) == 0 {
			return
		}
		// HA workloads here: arm first, whatever happens next, so a stuck
		// stop still ends in a reset.
		kind, err := a.Watchdog.Arm(ctx, t.Watchdog)
		a.mu.Lock()
		a.kind = kind
		a.mu.Unlock()
		if err != nil {
			a.startSelfFence(ctx, self, ha, "no-watchdog", t, now)
			a.setProblem("the watchdog couldn't be armed: " + err.Error() + "; HA workloads here are stopped")
			return
		}
		if ordered || !quorate {
			reason := why
			if !quorate {
				reason = "no-quorum"
			}
			_ = a.Watchdog.Expire(ctx)
			a.startSelfFence(ctx, self, ha, reason, t, now)
			return
		}
		a.setState(cluster.FenceArmed, "")
		a.pet(ctx, until, now, t)
	case cluster.FenceArmed:
		switch {
		case ordered:
			_ = a.Watchdog.Expire(ctx)
			a.startSelfFence(ctx, self, ha, why, t, now)
		case !quorate:
			// The lease already ran out, so root has stopped petting.
			_ = a.Watchdog.Expire(ctx)
			a.startSelfFence(ctx, self, ha, "no-quorum", t, now)
		case len(ha) == 0 && known:
			a.disarm(ctx, "")
		default:
			a.pet(ctx, until, now, t)
		}
	case cluster.FenceSelfFencing:
		if fencing {
			return // still stopping; no pets in any case
		}
		if done {
			// Everything stopped in time: nothing HA runs here, so the
			// watchdog can go. (Not petting meanwhile was safe: S < W.)
			a.mu.Lock()
			a.clean = true
			a.mu.Unlock()
			a.disarm(ctx, "")
			return
		}
		// Not everything stopped: never pet again; the watchdog resets
		// the server.
		a.setProblem("HA workloads didn't stop within the self-stop time; the watchdog resets this server")
	}
}

func (a *Agent) pet(ctx context.Context, until, now time.Time, t cluster.Timings) {
	valid := until.Sub(now)
	if valid <= 0 {
		return
	}
	if valid > t.QuorumLease {
		valid = t.QuorumLease
	}
	if err := a.Watchdog.Pet(ctx, valid); err != nil {
		a.setProblem("petting the watchdog: " + err.Error())
		return
	}
	a.setProblem("")
}

func (a *Agent) disarm(ctx context.Context, problem string) {
	if err := a.Watchdog.Disarm(ctx); err != nil {
		a.setProblem("disarming the watchdog: " + err.Error())
		return
	}
	a.mu.Lock()
	a.fenceDone, a.fenceErr = false, nil
	a.mu.Unlock()
	a.setState(cluster.FenceDisarmed, problem)
}

// startSelfFence stops ws by force within S, in the background.
func (a *Agent) startSelfFence(ctx context.Context, self cluster.Node, ws []cluster.WorkloadRef, reason string, t cluster.Timings, now time.Time) {
	a.mu.Lock()
	if a.fencing {
		a.mu.Unlock()
		return
	}
	a.fencing, a.fenceDone, a.fenceErr = true, false, nil
	a.fenceStart, a.lastFence, a.reason, a.clean = now, now, reason, false
	a.mu.Unlock()
	a.setState(cluster.FenceSelfFencing, "")
	a.log().Warn("fence: self-fencing", "reason", reason, "workloads", len(ws))
	go func() {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), t.SelfStop)
		defer cancel()
		err := a.Fencer.SelfFence(fctx, self.FenceEpoch, ws)
		if err == nil && fctx.Err() != nil {
			err = errors.New("the self-stop time ran out")
		}
		a.mu.Lock()
		a.fencing = false
		a.fenceDone = err == nil
		a.fenceErr = err
		a.mu.Unlock()
		if err != nil {
			a.log().Error("fence: HA workloads didn't stop; the watchdog will reset this server", "err", err)
		}
		a.notify()
	}()
}

// SelfFenceDone is for tests: whether the last self-fence finished and how.
func (a *Agent) SelfFenceDone() (running bool, ok bool, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.fencing, a.fenceDone, a.fenceErr
}

func (a *Agent) setState(s cluster.FenceState, problem string) {
	a.mu.Lock()
	changed := a.state != s || a.problem != problem
	a.state, a.problem = s, problem
	a.mu.Unlock()
	if changed {
		a.notify()
	}
}

func (a *Agent) setProblem(p string) {
	a.mu.Lock()
	changed := a.problem != p
	a.problem = p
	a.mu.Unlock()
	if changed {
		a.notify()
	}
}

func (a *Agent) notify() {
	if a.OnChange == nil {
		return
	}
	a.mu.Lock()
	st := a.statusLocked()
	a.mu.Unlock()
	a.OnChange(st)
}

// ---- power fencing (later) --------------------------------------------------------

// ErrNoPowerFencing: no out-of-band power control is configured for the
// node (IPMI/Redfish are a follow-up; decision 327).
var ErrNoPowerFencing = errors.New("no power fencing (IPMI/Redfish) is configured for this server")

// NoPower is the PowerFencer every node has until IPMI/Redfish land. The
// HA coordinator uses a power fencer only in addition to the storage fence.
type NoPower struct{}

var _ cluster.PowerFencer = NoPower{}

// PowerOff implements cluster.PowerFencer.
func (NoPower) PowerOff(context.Context, cluster.NodeID) error { return ErrNoPowerFencing }

// PowerState implements cluster.PowerFencer.
func (NoPower) PowerState(context.Context, cluster.NodeID) (bool, error) {
	return true, ErrNoPowerFencing
}
