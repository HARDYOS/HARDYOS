package fence

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
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
	// Idle: armed with no HA workload here (a nowayout device, or root
	// refused to disarm while other cluster workloads run).
	Idle bool `json:"idle,omitempty"`
	// RootRestarted: hardyd-priv restarted while the watchdog was armed.
	RootRestarted bool `json:"rootRestarted,omitempty"`
}

// Agent is the node-local self-fencing state machine (cluster.FenceAgent):
//
//	DISARMED --(an HA workload is placed or runs here)--> ARMED: the
//	  watchdog is open and root pets it while the quorum lease is valid
//	ARMED --(lease lost, or the state says this node is dead/isolated)-->
//	  SELF-FENCING: root stops petting; HA workloads are killed and
//	  detached; done within S -> disarm -> DISARMED; not done -> the
//	  watchdog resets the server within W
//	ARMED --(no HA workload here any more, quorate)--> DISARMED (unless
//	  the device is nowayout or root still sees cluster workloads: then
//	  it stays armed, petted while quorate)
//
// Until it has been quorate once, or the lease time Q has passed since it
// started, a lost lease isn't acted on (a restarted hardyd hasn't heard
// the leader yet; root keeps the deadline it last had). HA workloads start
// only once it is ARMED (Ready).
type Agent struct {
	Cluster  Cluster
	Watchdog cluster.Watchdog
	Fencer   SelfFencer
	Running  LocalRunning
	Log      *slog.Logger
	// Now is the clock (monotonic; tests fake it).
	Now func() time.Time
	// Boot and Mono are CLOCK_BOOTTIME and CLOCK_MONOTONIC (defaults
	// BootNow, MonoNow; tests fake them): when they drift apart the server
	// was suspended and the lease counts as lost (decision 392).
	Boot, Mono func() time.Time
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
	started    time.Time // first Step
	everQ      bool      // quorate at least once since started
	armedW     time.Duration
	nowayout   bool
	idle       bool
	instance   string // hardyd-priv's instance at the last status
	rootGone   bool
	keysPinned bool
	keySet     string // the cluster.KeySetHash root has pinned
	// suspend detection
	lastBoot, lastMono time.Time
	voidBefore         time.Time // a lease ending before voidBefore+Q is void
	cleanEpoch         uint64    // a fence of this epoch was obeyed cleanly here
	fenceEpoch         uint64    // the epoch the running self-fence obeys (0: lease loss)
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

// Ready reports whether HA workloads may start here: the watchdog is
// armed and no self-fence is running.
func (a *Agent) Ready() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state == cluster.FenceArmed && !a.fencing && !a.rootGone
}

// CleanFence reports whether this hardyd obeyed the node's fence of epoch
// itself: its self-fence finished with everything stopped, or nothing HA
// ran here when the order came. Only then may an isolated node rejoin on
// the same boot (node.rejoin's Clean).
func (a *Agent) CleanFence(epoch uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return epoch > 0 && a.cleanEpoch == epoch
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
		LastFence: a.lastFence, FenceReason: a.reason, CleanStopped: a.clean, Idle: a.idle, RootRestarted: a.rootGone}
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

// suspended notices a suspend since the last step: the boot clock ran on
// while the monotonic one stood still.
func (a *Agent) suspended() bool {
	boot, mono := a.Boot, a.Mono
	if boot == nil || mono == nil {
		if a.Now != nil {
			return false // a faked clock: no suspends
		}
		boot, mono = BootNow, MonoNow
	}
	b, m := boot(), mono()
	a.mu.Lock()
	defer a.mu.Unlock()
	defer func() { a.lastBoot, a.lastMono = b, m }()
	if a.lastBoot.IsZero() {
		return false
	}
	return b.Sub(a.lastBoot)-m.Sub(a.lastMono) > time.Second
}

// rootStatus reads root's view (when the watchdog can say) and reconciles:
// an arm root still holds after hardyd restarted is adopted; a restarted
// hardyd-priv (whose crash closed the device without the magic character)
// is reported and the watchdog armed again at once.
func (a *Agent) rootStatus(ctx context.Context) (*Status, bool) {
	sw, ok := a.Watchdog.(StatusWatchdog)
	if !ok {
		return nil, false
	}
	st, err := sw.Status(ctx)
	if err != nil {
		return nil, false
	}
	a.mu.Lock()
	prev := a.instance
	a.instance = st.Instance
	a.nowayout = st.NoWayOut
	state := a.state
	restarted := prev != "" && st.Instance != "" && prev != st.Instance
	if state == "" || state == cluster.FenceDisarmed {
		if st.Armed && prev == "" {
			// hardyd restarted; root kept the watchdog armed.
			a.state, a.kind, a.armedW = cluster.FenceArmed, st.Kind, time.Duration(st.TimeoutSec)*time.Second
			a.keysPinned = st.Leases
		}
	}
	if st.Leases {
		a.keySet = st.KeySet
	} else {
		a.keysPinned, a.keySet = false, ""
	}
	if restarted && (state == cluster.FenceArmed || state == cluster.FenceSelfFencing) {
		a.rootGone = !st.Armed
	}
	if st.Armed {
		a.rootGone = false
	}
	a.mu.Unlock()
	if restarted && (state == cluster.FenceArmed || state == cluster.FenceSelfFencing) {
		a.log().Error("fence: hardyd-priv restarted while the watchdog was armed; the hardware resets this server unless it is armed again in time")
		a.setProblem("hardyd-priv restarted while HA workloads were protected here; the watchdog was armed again")
	}
	return &st, true
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
	now := a.now()
	a.mu.Lock()
	if a.started.IsZero() {
		a.started = now
	}
	started := a.started
	a.mu.Unlock()
	root, haveRoot := a.rootStatus(ctx)

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
	if a.suspended() {
		// The lease was measured on a clock that stood still while the
		// server slept: it is lost, whatever it says.
		a.mu.Lock()
		a.voidBefore = until
		a.mu.Unlock()
		a.log().Warn("fence: this server was suspended; its quorum lease counts as lost")
	}
	a.mu.Lock()
	if !a.voidBefore.IsZero() {
		if until.After(a.voidBefore) {
			a.voidBefore = time.Time{} // a lease from a heartbeat after the resume
		} else {
			quorate = false
		}
	}
	if quorate {
		a.everQ = true
	}
	grace := !a.everQ && now.Sub(started) < t.QuorumLease
	a.mu.Unlock()
	ordered, why := ownFence(s, self.ID)
	ha := haWorkloads(s, self.ID, running, (quorate && !ordered) || !known)

	a.mu.Lock()
	a.haHere = ha
	state := a.state
	if state == "" {
		state = cluster.FenceDisarmed
	}
	fencing, done := a.fencing, a.fenceDone
	rootGone := a.rootGone
	a.mu.Unlock()

	if grace && !quorate && !ordered {
		// Just started and not heard the leader yet: neither self-fence
		// nor arm on a lease that may simply not have arrived.
		return
	}
	if ordered && state == cluster.FenceDisarmed && known && len(ha) == 0 {
		// The order came and nothing HA runs here: obeyed as it stands
		// (the reconciler stops the rest).
		a.mu.Lock()
		a.cleanEpoch = self.FenceEpoch
		a.mu.Unlock()
	}

	switch state {
	case cluster.FenceDisarmed:
		if len(ha) == 0 {
			return
		}
		// HA workloads here: arm first, whatever happens next, so a stuck
		// stop still ends in a reset.
		a.pinKeys(ctx, s, self)
		kind, err := a.Watchdog.Arm(ctx, t.Watchdog)
		a.mu.Lock()
		a.kind = kind
		if err == nil {
			a.armedW = t.Watchdog
		}
		a.mu.Unlock()
		if err != nil {
			a.startSelfFence(ctx, self, ha, "no-watchdog", t, now, ordered)
			a.setProblem("the watchdog couldn't be armed: " + err.Error() + "; HA workloads here are stopped")
			return
		}
		if ordered || !quorate {
			reason := why
			if !quorate {
				reason = "no-quorum"
			}
			_ = a.Watchdog.Expire(ctx)
			a.startSelfFence(ctx, self, ha, reason, t, now, ordered)
			return
		}
		a.setState(cluster.FenceArmed, "")
		a.pet(ctx, until, now, t)
	case cluster.FenceArmed:
		if rootGone || (haveRoot && !root.Armed) {
			// Root lost the device (hardyd-priv restarted): arm again now.
			if _, err := a.Watchdog.Arm(ctx, t.Watchdog); err == nil {
				a.mu.Lock()
				a.rootGone, a.armedW = false, t.Watchdog
				a.mu.Unlock()
			}
		} else if a.keysStale(s) {
			// A server that may lead joined or left: root takes the new
			// keys only on the leader's word (the current statement).
			a.pinKeys(ctx, s, self)
		} else if a.armedTimeout() != t.Watchdog {
			// The cluster's watchdog timeout changed: the device follows.
			if _, err := a.Watchdog.Arm(ctx, t.Watchdog); err != nil {
				a.setProblem("changing the watchdog timeout: " + err.Error())
			} else {
				a.mu.Lock()
				a.armedW = t.Watchdog
				a.mu.Unlock()
			}
		}
		switch {
		case ordered:
			_ = a.Watchdog.Expire(ctx)
			a.startSelfFence(ctx, self, ha, why, t, now, true)
		case !quorate && len(ha) == 0 && known && a.isIdle():
			// Armed only because it can't be disarmed and nothing HA runs:
			// nothing to protect, so the lease doesn't matter.
			a.petIdle(ctx, t)
		case !quorate:
			// The lease already ran out, so root has stopped petting.
			_ = a.Watchdog.Expire(ctx)
			a.startSelfFence(ctx, self, ha, "no-quorum", t, now, false)
		case len(ha) == 0 && known:
			if a.disarmOrIdle(ctx) {
				return
			}
			a.pet(ctx, until, now, t)
		default:
			a.setIdle(false)
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
			if !a.disarmOrIdle(ctx) {
				// It can't go (nowayout, or other cluster workloads still
				// run): armed and idle, petted only with quorum.
				a.setState(cluster.FenceArmed, "")
			}
			return
		}
		// Not everything stopped: never pet again; the watchdog resets
		// the server.
		a.setProblem("HA workloads didn't stop within the self-stop time; the watchdog resets this server")
	}
}

func (a *Agent) armedTimeout() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.armedW
}

func (a *Agent) isIdle() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.idle
}

func (a *Agent) setIdle(on bool) {
	a.mu.Lock()
	a.idle = on
	a.mu.Unlock()
}

// disarmOrIdle disarms; a nowayout device, or root still seeing cluster
// workloads, keeps it armed and idle (it reports false then).
func (a *Agent) disarmOrIdle(ctx context.Context) bool {
	a.mu.Lock()
	nowayout := a.nowayout
	a.mu.Unlock()
	if nowayout {
		a.setIdle(true)
		return false
	}
	err := a.Watchdog.Disarm(ctx)
	if err == nil {
		a.mu.Lock()
		a.fenceDone, a.fenceErr, a.idle, a.armedW = false, nil, false, 0
		a.mu.Unlock()
		a.setState(cluster.FenceDisarmed, "")
		return true
	}
	msg := err.Error()
	if strings.Contains(msg, "still run") || strings.Contains(msg, "nowayout") {
		a.setIdle(true)
		a.setProblem("")
		return false
	}
	a.setProblem("disarming the watchdog: " + msg)
	return false
}

// petIdle keeps an idle (nothing HA here) armed watchdog quiet for one
// lease time.
func (a *Agent) petIdle(ctx context.Context, t cluster.Timings) {
	if err := a.Watchdog.Pet(ctx, t.QuorumLease); err != nil {
		a.setProblem("petting the watchdog: " + err.Error())
	}
}

// pinKeys hands root the keys of the servers that may lead
// (cluster.LeaseKeySet) before it arms, and again when they change while
// armed, with the leader's current statement vouching for them (when both
// sides support leader-signed lease statements).
func (a *Agent) pinKeys(ctx context.Context, s *cluster.Snapshot, self cluster.Node) {
	lw, ok := a.Watchdog.(LeaseWatchdog)
	if !ok {
		return
	}
	src, ok := a.Cluster.(LeaseSource)
	if !ok {
		return
	}
	k := LeaseKeys{Cluster: string(s.Cluster), Node: string(self.ID), Voters: cluster.LeaseKeySet(s)}
	if len(k.Voters) == 0 {
		return
	}
	if stmt, ok := src.LeaseStatement(); ok {
		k.Lease = stmt
	}
	if err := lw.PinLeaseKeys(ctx, k); err != nil {
		a.log().Warn("fence: pinning the lease keys in root", "err", err)
		return
	}
	a.mu.Lock()
	a.keysPinned, a.keySet = true, k.Hash()
	a.mu.Unlock()
}

// keysStale: root checks statements with keys that are no longer the
// cluster's set of servers that may lead.
func (a *Agent) keysStale(s *cluster.Snapshot) bool {
	if _, ok := a.Watchdog.(LeaseWatchdog); !ok {
		return false
	}
	if _, ok := a.Cluster.(LeaseSource); !ok {
		return false
	}
	a.mu.Lock()
	pinned, set := a.keysPinned, a.keySet
	a.mu.Unlock()
	return pinned && set != cluster.KeySetHash(cluster.LeaseKeySet(s))
}

func (a *Agent) pet(ctx context.Context, until, now time.Time, t cluster.Timings) {
	valid := until.Sub(now)
	if valid <= 0 {
		return
	}
	if valid > t.QuorumLease {
		valid = t.QuorumLease
	}
	var err error
	lw, okW := a.Watchdog.(LeaseWatchdog)
	src, okS := a.Cluster.(LeaseSource)
	if okW && okS {
		if stmt, ok := src.LeaseStatement(); ok {
			err = lw.PetWithLease(ctx, valid, stmt)
		} else {
			err = a.Watchdog.Pet(ctx, valid)
		}
	} else {
		err = a.Watchdog.Pet(ctx, valid)
	}
	if err != nil {
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
	a.fenceDone, a.fenceErr, a.idle, a.armedW = false, nil, false, 0
	a.mu.Unlock()
	a.setState(cluster.FenceDisarmed, problem)
}

// startSelfFence stops ws by force within S, in the background. ordered:
// the cluster declared this node dead or isolated (a clean finish lets an
// isolated node rejoin on the same boot).
func (a *Agent) startSelfFence(ctx context.Context, self cluster.Node, ws []cluster.WorkloadRef, reason string, t cluster.Timings, now time.Time, ordered bool) {
	a.mu.Lock()
	if a.fencing {
		a.mu.Unlock()
		return
	}
	a.fencing, a.fenceDone, a.fenceErr = true, false, nil
	a.fenceStart, a.lastFence, a.reason, a.clean = now, now, reason, false
	a.fenceEpoch = 0
	if ordered {
		a.fenceEpoch = self.FenceEpoch
	}
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
		if err == nil && a.fenceEpoch > 0 {
			a.cleanEpoch = a.fenceEpoch
		}
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
