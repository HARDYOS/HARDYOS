// Package state holds the cluster's pure state machine appliers
// (docs/plans/cluster.md section 2.3). Each part owns its own file; this one
// is part C's placements: workloads, owners, generations, grants, moves and
// HA policies. Appliers are deterministic: no clock, no I/O, no randomness.
//
// The rules that keep a disk from ever having two runners live here, in
// the one linear history every node and the storage node apply (decisions
// 326 and 350):
//
//   - every change of owner or grant raises the placement's Generation and
//     replaces the Grant with a not-yet-applied one for that generation;
//   - an exclusive grant names one node; a migration grant names the two
//     nodes of a live migration and is only ever made from a running
//     placement by its owner's move.begin;
//   - the owner of a workload changes only when the old owner reported it
//     stopped for the current generation, the old owner's fence is
//     confirmed by the storage node, or a live migration's grant collapses
//     to one of its two nodes.
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// ---- command bodies (part C) -------------------------------------------------

// WorkloadAdd registers a cluster workload whose storage the storage node
// has provisioned (part B). It starts at generation 1 with an exclusive
// grant for Owner.
type WorkloadAdd struct {
	Workload  cluster.WorkloadRef     `json:"workload"`
	Name      string                  `json:"name"`
	Owner     cluster.NodeID          `json:"owner"`
	Requested cluster.Requested       `json:"requested"`
	HA        cluster.HAPolicy        `json:"ha"`
	Pinned    bool                    `json:"pinned,omitempty"`
	Storage   cluster.WorkloadStorage `json:"storage"`
	// SpecHash is root's hash of the settings the administrator approved
	// (vms.cluster.hash / apps.cluster.hash on the proposer, which holds
	// the workload's storage). Required: a node starts the workload only
	// when its own root computes the same hash (decision 386).
	SpecHash string `json:"specHash"`
}

// WorkloadSpecSet records the hash of a workload's newly approved settings
// (its owner, after an administrator changed them).
type WorkloadSpecSet struct {
	Workload   cluster.WorkloadRef `json:"workload"`
	Generation uint64              `json:"generation"`
	SpecHash   string              `json:"specHash"`
}

// WorkloadRemove forgets a workload (its storage is destroyed by part B
// afterwards). It must be stopped, or its owner fenced.
type WorkloadRemove struct {
	Workload   cluster.WorkloadRef `json:"workload"`
	Generation uint64              `json:"generation"`
}

// PlacementSet changes a workload's owner and grant: an offline move's
// hand-over, a recovery after a fence, the end of a live migration (Mode
// exclusive with Owner one of the two), or "no node fits" (Owner empty,
// State pending).
type PlacementSet struct {
	Workload cluster.WorkloadRef `json:"workload"`
	// Expected is the generation the proposer saw.
	Expected uint64         `json:"expected"`
	Owner    cluster.NodeID `json:"owner,omitempty"`
	// State the placement is in afterwards (stopped, starting, pending,
	// running for the end of a live migration).
	State   cluster.PlacementState `json:"state"`
	Problem string                 `json:"problem,omitempty"`
	// Reason is shown in the history: "move", "recover", "migrated",
	// "migration-failed", "pending", "start-elsewhere".
	Reason string `json:"reason"`
}

// RequestedSet records what the person asked for (start or stop).
type RequestedSet struct {
	Workload   cluster.WorkloadRef `json:"workload"`
	Generation uint64              `json:"generation"`
	Requested  cluster.Requested   `json:"requested"`
}

// WorkloadStateReport is the owner's report of its workload.
type WorkloadStateReport struct {
	Workload   cluster.WorkloadRef    `json:"workload"`
	Generation uint64                 `json:"generation"`
	State      cluster.PlacementState `json:"state"`
	Problem    string                 `json:"problem,omitempty"`
}

// MoveBegin starts an offline move or a live migration.
type MoveBegin struct {
	Workload   cluster.WorkloadRef `json:"workload"`
	Generation uint64              `json:"generation"`
	To         cluster.NodeID      `json:"to"`
	Mode       cluster.MoveMode    `json:"mode"`
}

// MoveEnd closes a move (successful or not).
type MoveEnd struct {
	Workload   cluster.WorkloadRef `json:"workload"`
	Generation uint64              `json:"generation"`
	OK         bool                `json:"ok"`
	Problem    string              `json:"problem,omitempty"`
}

// HAPolicySet changes a workload's HA policy.
type HAPolicySet struct {
	Workload cluster.WorkloadRef `json:"workload"`
	Policy   cluster.HAPolicy    `json:"policy"`
}

// CPUBaselineSet records the cluster's CPU baseline model ("" = none: VMs
// use host-passthrough and only migrate between identical CPUs).
type CPUBaselineSet struct {
	Model string `json:"model"`
}

// ---- applier -----------------------------------------------------------------

// Placements is part C's applier for workloads and placements.
type Placements struct{}

var _ cluster.Applier = Placements{}

// Every FSM (members and the witness) applies the placement commands.
func init() { register(Placements{}) }

// Types implements cluster.Applier.
func (Placements) Types() []cluster.CommandType {
	return []cluster.CommandType{
		cluster.CmdWorkloadAdd, cluster.CmdWorkloadRemove, cluster.CmdPlacementSet, cluster.CmdRequested,
		cluster.CmdWorkloadState, cluster.CmdMoveBegin, cluster.CmdMoveEnd, cluster.CmdHAPolicy, cluster.CmdCPUBaseline,
		cluster.CmdWorkloadSpec,
	}
}

// hardyOSMembers may sign every part C command (never the witness).
var hardyOSMembers = []cluster.Role{cluster.RoleCompute, cluster.RoleStorage}

// Signers implements cluster.Applier.
func (Placements) Signers(t cluster.CommandType) []cluster.Role {
	if t == cluster.CmdWorkloadState || t == cluster.CmdWorkloadSpec {
		// The owner's report: the applier checks it is the owner.
		return []cluster.Role{cluster.RoleCompute}
	}
	return hardyOSMembers
}

// Apply implements cluster.Applier.
func (Placements) Apply(s *cluster.Snapshot, c cluster.Command) error {
	ensure(s)
	switch c.Type {
	case cluster.CmdWorkloadAdd:
		var b WorkloadAdd
		if err := decode(c, &b); err != nil {
			return err
		}
		return applyWorkloadAdd(s, c, b)
	case cluster.CmdWorkloadRemove:
		var b WorkloadRemove
		if err := decode(c, &b); err != nil {
			return err
		}
		return applyWorkloadRemove(s, b)
	case cluster.CmdPlacementSet:
		var b PlacementSet
		if err := decode(c, &b); err != nil {
			return err
		}
		return applyPlacementSet(s, c, b)
	case cluster.CmdRequested:
		var b RequestedSet
		if err := decode(c, &b); err != nil {
			return err
		}
		p, err := current(s, b.Workload, b.Generation)
		if err != nil {
			return err
		}
		if b.Requested != cluster.RequestRunning && b.Requested != cluster.RequestStopped {
			return fmt.Errorf("requested must be running or stopped")
		}
		p.Requested = b.Requested
		if p.State == cluster.PlacementError && b.Requested == cluster.RequestRunning {
			// Starting it again by hand clears the error.
			p.State, p.Problem = cluster.PlacementStopped, ""
		}
		p.Changed = c.Time
		return nil
	case cluster.CmdWorkloadState:
		var b WorkloadStateReport
		if err := decode(c, &b); err != nil {
			return err
		}
		return applyStateReport(s, c, b)
	case cluster.CmdMoveBegin:
		var b MoveBegin
		if err := decode(c, &b); err != nil {
			return err
		}
		return applyMoveBegin(s, c, b)
	case cluster.CmdMoveEnd:
		var b MoveEnd
		if err := decode(c, &b); err != nil {
			return err
		}
		p, err := current(s, b.Workload, b.Generation)
		if err != nil {
			return err
		}
		if p.Target == "" {
			return errors.New("no move is in progress")
		}
		if g := s.Grants[p.Workload]; g != nil && g.Mode == cluster.GrantMigration {
			return errors.New("a live migration ends with placement.set, not move.end")
		}
		// The member that began the move ends it (or one of its two nodes).
		if c.Proposer != p.MoveBy && c.Proposer != p.Owner && c.Proposer != p.Target {
			return fmt.Errorf("%s didn't begin this move (%s did)", c.Proposer, p.MoveBy)
		}
		p.Target = ""
		p.MoveBy = ""
		if !b.OK {
			p.Problem = b.Problem
		}
		p.Changed = c.Time
		return nil
	case cluster.CmdWorkloadSpec:
		var b WorkloadSpecSet
		if err := decode(c, &b); err != nil {
			return err
		}
		p, err := current(s, b.Workload, b.Generation)
		if err != nil {
			return err
		}
		if c.Proposer != p.Owner {
			return fmt.Errorf("only %s's owner records its approved settings", ref(b.Workload))
		}
		if p.Target != "" {
			return errors.New("finish the move first")
		}
		if err := ValidSpecHash(b.SpecHash); err != nil {
			return err
		}
		p.SpecHash = b.SpecHash
		p.Changed = c.Time
		return nil
	case cluster.CmdHAPolicy:
		var b HAPolicySet
		if err := decode(c, &b); err != nil {
			return err
		}
		p, ok := s.Placements[b.Workload]
		if !ok {
			return fmt.Errorf("no workload %s", ref(b.Workload))
		}
		pol := NormalizePolicy(b.Policy)
		if err := ValidatePolicy(s, p, pol); err != nil {
			return err
		}
		p.HA = pol
		p.Changed = c.Time
		return nil
	case cluster.CmdCPUBaseline:
		var b CPUBaselineSet
		if err := decode(c, &b); err != nil {
			return err
		}
		if b.Model != "" && !cpuModelRE.MatchString(b.Model) {
			return fmt.Errorf("%q isn't a CPU model name", b.Model)
		}
		s.CPUBaseline = b.Model
		return nil
	}
	return fmt.Errorf("placements: unexpected command %s", c.Type)
}

var cpuModelRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$`)

// ValidCPUModel reports whether name may be a cluster CPU baseline.
func ValidCPUModel(name string) bool { return cpuModelRE.MatchString(name) }

var workloadIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

var specHashRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidSpecHash checks a workload's approved-settings hash.
func ValidSpecHash(h string) error {
	if !specHashRE.MatchString(h) {
		return errors.New("a workload needs the hash of its approved settings (sha256:<hex>)")
	}
	return nil
}

func validRef(w cluster.WorkloadRef) error {
	if w.Kind != cluster.KindVM && w.Kind != cluster.KindApp {
		return fmt.Errorf("unknown workload kind %q", w.Kind)
	}
	if !workloadIDRE.MatchString(w.ID) {
		return fmt.Errorf("%q isn't a workload id", w.ID)
	}
	return nil
}

func applyWorkloadAdd(s *cluster.Snapshot, c cluster.Command, b WorkloadAdd) error {
	if err := validRef(b.Workload); err != nil {
		return err
	}
	if _, dup := s.Placements[b.Workload]; dup {
		return fmt.Errorf("%s is already a cluster workload", ref(b.Workload))
	}
	if err := runnableOn(s, b.Owner); err != nil {
		return err
	}
	if err := ValidSpecHash(b.SpecHash); err != nil {
		return err
	}
	if b.Requested == "" {
		b.Requested = cluster.RequestStopped
	}
	p := &cluster.Placement{
		Workload: b.Workload, Name: b.Name, Owner: b.Owner, Generation: 1,
		Requested: b.Requested, State: cluster.PlacementStopped,
		Pinned: b.Pinned, Storage: b.Storage, Changed: c.Time, SpecHash: b.SpecHash,
	}
	pol := NormalizePolicy(b.HA)
	if err := ValidatePolicy(s, p, pol); err != nil {
		return err
	}
	p.HA = pol
	s.Placements[b.Workload] = p
	s.Grants[b.Workload] = &cluster.Grant{Workload: b.Workload, Nodes: []cluster.NodeID{b.Owner}, Mode: cluster.GrantExclusive, Generation: 1}
	return nil
}

func applyWorkloadRemove(s *cluster.Snapshot, b WorkloadRemove) error {
	p, err := current(s, b.Workload, b.Generation)
	if err != nil {
		return err
	}
	if p.Target != "" {
		return errors.New("finish or cancel the move first")
	}
	stopped := p.State == cluster.PlacementStopped || p.State == cluster.PlacementPending || p.State == cluster.PlacementError
	if !stopped && !ownerFenced(s, p.Owner) {
		return errors.New("stop it first")
	}
	delete(s.Placements, b.Workload)
	delete(s.Grants, b.Workload)
	return nil
}

func applyPlacementSet(s *cluster.Snapshot, c cluster.Command, b PlacementSet) error {
	p, err := current(s, b.Workload, b.Expected)
	if err != nil {
		return err
	}
	g := s.Grants[b.Workload]
	if g == nil {
		return fmt.Errorf("%s has no grant", ref(b.Workload))
	}
	switch b.State {
	case cluster.PlacementStopped, cluster.PlacementStarting, cluster.PlacementPending, cluster.PlacementRunning, cluster.PlacementRecovering:
	default:
		return fmt.Errorf("placement.set can't leave a workload %s", b.State)
	}
	// A move in progress is ended by the member that began it, unless one
	// of its nodes is fenced (the HA coordinator collapses or recovers
	// it). Outside a move any member may propose (pending, decision 394).
	if (p.Target != "" || g.Mode == cluster.GrantMigration) && c.Proposer != p.MoveBy &&
		!ownerFenced(s, p.Owner) && (p.Target == "" || !ownerFenced(s, p.Target)) &&
		!(g.Mode == cluster.GrantMigration && b.Reason == "migration-timeout" && c.Time.Sub(p.Changed) >= MigrationGrantTimeout) {
		return fmt.Errorf("%s is being moved by %s; only it can hand it over", p.Name, p.MoveBy)
	}
	// End of a live migration: the grant collapses to one of its two
	// nodes (libvirt stops the source when a migration succeeds and keeps
	// it when it fails). Anywhere else only once both are fenced.
	if g.Mode == cluster.GrantMigration {
		if !slices.Contains(g.Nodes, b.Owner) {
			for _, n := range g.Nodes {
				if !ownerFenced(s, n) {
					return fmt.Errorf("a live migration ends on its source or its destination while %s is up", n)
				}
			}
		}
		if b.State == cluster.PlacementRunning && !slices.Contains(g.Nodes, b.Owner) {
			return errors.New("only a migration's own node keeps the VM running")
		}
		if b.Owner != "" {
			if err := runnableOn(s, b.Owner); err != nil {
				return err
			}
		}
		return setOwner(s, p, b, c)
	}
	if b.State == cluster.PlacementPending {
		if b.Owner != "" {
			return errors.New("a pending workload has no owner")
		}
		if !ownerReleased(s, p) {
			return fmt.Errorf("%s still has %s running it", ref(b.Workload), p.Owner)
		}
		return setOwner(s, p, b, c)
	}
	if b.Owner == "" {
		return errors.New("placement.set needs an owner")
	}
	if b.State == cluster.PlacementRunning {
		return errors.New("only a live migration hands over a running workload")
	}
	if err := runnableOn(s, b.Owner); err != nil {
		return err
	}
	if b.Owner != p.Owner && !ownerReleased(s, p) {
		// The one rule that keeps two nodes off one disk in the log.
		return fmt.Errorf("%s is still placed on %s: it must be reported stopped there, or %s fenced, before it can move", p.Name, p.Owner, p.Owner)
	}
	if p.HA.Enabled && b.Owner != p.Owner {
		if ok, why := HAEligible(s, b.Owner); !ok {
			return fmt.Errorf("%s can't run HA workloads: %s", b.Owner, why)
		}
	}
	if p.Pinned && b.Owner != p.Owner && b.Reason != "start-elsewhere" && b.Reason != "move-confirmed" {
		return fmt.Errorf("%s is pinned to %s", p.Name, p.Owner)
	}
	return setOwner(s, p, b, c)
}

// MigrationGrantTimeout is how long a live migration's two-node grant may
// stand before the HA coordinator (on the leader) ends it after asking
// both nodes what runs (the source's send limit, 10 minutes, and a
// margin; decision 388).
const MigrationGrantTimeout = 12 * time.Minute

// ownerReleased: the current owner can't be running the workload: it
// reported it stopped (or in error, which the owner reports after
// stopping) for this generation, it has no owner, or its owner's fence is
// confirmed.
func ownerReleased(s *cluster.Snapshot, p *cluster.Placement) bool {
	if p.Owner == "" {
		return true
	}
	switch p.State {
	case cluster.PlacementStopped, cluster.PlacementError, cluster.PlacementPending:
		return true
	}
	return ownerFenced(s, p.Owner)
}

// ownerFenced: the storage node confirmed the node's latest fence.
func ownerFenced(s *cluster.Snapshot, n cluster.NodeID) bool {
	node, ok := s.Nodes[n]
	if !ok || node.State == cluster.NodeRemoved {
		return true
	}
	f := s.Fences[n]
	return f != nil && f.Confirmed && f.Epoch == node.FenceEpoch && f.Epoch > 0 &&
		(node.State == cluster.NodeFenced || node.State == cluster.NodeRejoining || node.State == cluster.NodeDead)
}

func setOwner(s *cluster.Snapshot, p *cluster.Placement, b PlacementSet, c cluster.Command) error {
	p.Generation++
	p.Owner = b.Owner
	p.Target = ""
	if c.Proposer != p.MoveBy || (b.Reason != "move" && b.Reason != "move-confirmed" && b.Reason != "migrated") {
		// The mover keeps driving the new owner's start step after its own
		// hand-over; anyone else's change ends its say.
		p.MoveBy = ""
	}
	if b.Reason == "relocate" {
		keep := []time.Time{}
		for _, t := range p.Relocated {
			if c.Time.Sub(t) < time.Hour {
				keep = append(keep, t)
			}
		}
		if len(keep) >= 20 {
			keep = keep[len(keep)-19:]
		}
		p.Relocated = append(keep, c.Time)
	}
	p.State = b.State
	p.Problem = b.Problem
	p.Changed = c.Time
	nodes := []cluster.NodeID{}
	if b.Owner != "" {
		nodes = []cluster.NodeID{b.Owner}
	}
	s.Grants[p.Workload] = &cluster.Grant{Workload: p.Workload, Nodes: nodes, Mode: cluster.GrantExclusive, Generation: p.Generation}
	return nil
}

func applyStateReport(s *cluster.Snapshot, c cluster.Command, b WorkloadStateReport) error {
	p, err := current(s, b.Workload, b.Generation)
	if err != nil {
		return err
	}
	g := s.Grants[b.Workload]
	reporter := c.Proposer
	migrating := g != nil && g.Mode == cluster.GrantMigration
	if reporter != p.Owner && !(migrating && slices.Contains(g.Nodes, reporter)) {
		return fmt.Errorf("%s isn't %s's owner", reporter, ref(b.Workload))
	}
	switch b.State {
	case cluster.PlacementRunning, cluster.PlacementStarting, cluster.PlacementStopping:
		if migrating {
			return nil // the migration's own state stands
		}
		if g == nil || !g.Applied || !slices.Contains(g.Nodes, reporter) {
			return fmt.Errorf("%s reported %s running without an applied grant", reporter, ref(b.Workload))
		}
	case cluster.PlacementStopped, cluster.PlacementError:
		if migrating {
			return errors.New("a migrating VM is reported through the migration")
		}
	default:
		return fmt.Errorf("an owner can't report %s", b.State)
	}
	p.State = b.State
	p.Problem = b.Problem
	p.Changed = c.Time
	return nil
}

func applyMoveBegin(s *cluster.Snapshot, c cluster.Command, b MoveBegin) error {
	p, err := current(s, b.Workload, b.Generation)
	if err != nil {
		return err
	}
	if p.Target != "" {
		return fmt.Errorf("%s is already moving to %s", p.Name, p.Target)
	}
	if b.To == p.Owner || b.To == "" {
		return errors.New("choose another server")
	}
	if err := runnableOn(s, b.To); err != nil {
		return err
	}
	if p.Owner == "" || ownerFenced(s, p.Owner) {
		return errors.New("its server is down: start it elsewhere instead")
	}
	if p.HA.Enabled {
		if ok, why := HAEligible(s, b.To); !ok {
			return fmt.Errorf("%s can't run HA workloads: %s", b.To, why)
		}
	}
	switch b.Mode {
	case cluster.MoveOffline:
		p.State = cluster.PlacementMoving
		p.Target = b.To
		p.MoveBy = c.Proposer
		p.Changed = c.Time
		return nil
	case cluster.MoveLive:
		if b.Workload.Kind != cluster.KindVM {
			return errors.New("only VMs move live")
		}
		if p.Pinned {
			return fmt.Errorf("%s is pinned to %s (passthrough devices)", p.Name, p.Owner)
		}
		if p.State != cluster.PlacementRunning {
			return errors.New("only a running VM migrates live")
		}
		if g := s.Grants[b.Workload]; g == nil || !g.Applied {
			return errors.New("the VM's storage grant isn't applied yet")
		}
		p.Generation++
		p.State = cluster.PlacementMigrating
		p.Target = b.To
		p.MoveBy = c.Proposer
		p.Changed = c.Time
		s.Grants[b.Workload] = &cluster.Grant{Workload: b.Workload, Nodes: []cluster.NodeID{p.Owner, b.To},
			Mode: cluster.GrantMigration, Generation: p.Generation}
		return nil
	}
	return fmt.Errorf("unknown move mode %q", b.Mode)
}

// runnableOn: n is an active compute node that isn't fenced.
func runnableOn(s *cluster.Snapshot, n cluster.NodeID) error {
	node, ok := s.Nodes[n]
	if !ok {
		return fmt.Errorf("%s isn't a member", n)
	}
	if node.Role != cluster.RoleCompute {
		return fmt.Errorf("%s isn't a compute server", n)
	}
	if node.State != cluster.NodeActive {
		return fmt.Errorf("%s is %s", n, node.State)
	}
	return nil
}

// ---- HA policy ---------------------------------------------------------------

// NormalizePolicy fills in defaults.
func NormalizePolicy(p cluster.HAPolicy) cluster.HAPolicy {
	if p.Priority == 0 {
		p.Priority = 50
	}
	if p.MaxRestarts == 0 {
		p.MaxRestarts = 3
	}
	if p.MaxRelocations == 0 {
		p.MaxRelocations = 2
	}
	if p.Preferred == nil {
		p.Preferred = nil
	}
	return p
}

var groupRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ValidatePolicy checks a policy for a placement (pure; also used by the
// API before proposing).
func ValidatePolicy(s *cluster.Snapshot, p *cluster.Placement, pol cluster.HAPolicy) error {
	if pol.Priority < 1 || pol.Priority > 100 {
		return errors.New("priority is 1-100")
	}
	if pol.MaxRestarts < 0 || pol.MaxRestarts > 20 {
		return errors.New("restarts per hour are 0-20")
	}
	if pol.MaxRelocations < 0 || pol.MaxRelocations > 10 {
		return errors.New("moves per hour are 0-10")
	}
	if pol.AntiAffinity != "" && !groupRE.MatchString(pol.AntiAffinity) {
		return errors.New("the anti-affinity group is lowercase letters, digits and -")
	}
	if len(pol.Preferred) > 16 {
		return errors.New("at most 16 preferred servers")
	}
	seen := map[cluster.NodeID]bool{}
	for _, n := range pol.Preferred {
		node, ok := s.Nodes[n]
		if !ok || node.Role != cluster.RoleCompute {
			return fmt.Errorf("%s isn't a compute server", n)
		}
		if seen[n] {
			return fmt.Errorf("%s is listed twice", n)
		}
		seen[n] = true
	}
	if pol.Restricted && len(pol.Preferred) == 0 {
		return errors.New("restricting to preferred servers needs at least one")
	}
	if !pol.Enabled {
		return nil
	}
	if p.Pinned {
		return fmt.Errorf("%s is pinned to %s (passthrough devices) and can't be highly available", p.Name, p.Owner)
	}
	if p.Owner != "" {
		if ok, why := HAEligible(s, p.Owner); !ok {
			return fmt.Errorf("%s can't run HA workloads: %s", p.Owner, why)
		}
	}
	return nil
}

// HAEligible says whether node n may host HA workloads: a compute node
// with a hardware watchdog, or one an administrator allowed without one
// for the watchdog it has now (decision 352).
func HAEligible(s *cluster.Snapshot, n cluster.NodeID) (bool, string) {
	node, ok := s.Nodes[n]
	if !ok || node.Role != cluster.RoleCompute {
		return false, "it isn't a compute server"
	}
	kind := ""
	if node.Compute != nil {
		kind = node.Compute.Watchdog
	}
	if kind == "hardware" {
		return true, ""
	}
	if o := s.HAOverrides[n]; o != nil && o.Kind == kind && kind != "" {
		return true, ""
	}
	if kind == "softdog" {
		return false, "it has only the software watchdog (softdog), which doesn't survive a kernel hang; an administrator can allow it in Cluster › HA"
	}
	return false, "it has no watchdog; an administrator can allow it in Cluster › HA"
}

// ---- helpers -----------------------------------------------------------------

func ensure(s *cluster.Snapshot) {
	if s.Placements == nil {
		s.Placements = map[cluster.WorkloadRef]*cluster.Placement{}
	}
	if s.Grants == nil {
		s.Grants = map[cluster.WorkloadRef]*cluster.Grant{}
	}
	if s.Fences == nil {
		s.Fences = map[cluster.NodeID]*cluster.Fence{}
	}
	if s.Nodes == nil {
		s.Nodes = map[cluster.NodeID]*cluster.Node{}
	}
	if s.HAOverrides == nil {
		s.HAOverrides = map[cluster.NodeID]*cluster.WatchdogOverride{}
	}
}

func current(s *cluster.Snapshot, w cluster.WorkloadRef, gen uint64) (*cluster.Placement, error) {
	p, ok := s.Placements[w]
	if !ok {
		return nil, fmt.Errorf("no workload %s", ref(w))
	}
	if p.Generation != gen {
		return nil, fmt.Errorf("%w (%s is at generation %d, not %d)", cluster.ErrStaleGeneration, ref(w), p.Generation, gen)
	}
	return p, nil
}

func ref(w cluster.WorkloadRef) string { return string(w.Kind) + ":" + w.ID }

// decode reads a command body strictly.
func decode(c cluster.Command, v any) error {
	dec := json.NewDecoder(bytes.NewReader(c.Body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", c.Type, err)
	}
	return nil
}

// SortedPlacements returns the placements in a stable order (kind, id).
func SortedPlacements(s *cluster.Snapshot) []*cluster.Placement {
	out := make([]*cluster.Placement, 0, len(s.Placements))
	for _, p := range s.Placements {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Workload.Kind != out[j].Workload.Kind {
			return out[i].Workload.Kind < out[j].Workload.Kind
		}
		return out[i].Workload.ID < out[j].Workload.ID
	})
	return out
}

// Intent is what a node wants to do with a workload (MayRunFor).
type Intent int

const (
	// IntentKeep: keep a running workload running (the owner, or either
	// node of a live migration).
	IntentKeep Intent = iota
	// IntentStart: start it from cold. Only the owner, with an exclusive
	// grant: a live migration's destination never starts the VM itself.
	IntentStart
	// IntentReceive: take part in a live migration as its destination
	// (attach, admit the incoming VM).
	IntentReceive
)

// MayRun is MayRunFor with IntentKeep.
func MayRun(s *cluster.Snapshot, n cluster.NodeID, w cluster.WorkloadRef, gen uint64) error {
	return MayRunFor(s, n, w, gen, IntentKeep)
}

// MayRunFor is the check every node makes before it starts, receives or
// keeps running a workload: the applied placement names it as owner (or as
// a node of a live migration, for keeping and receiving only) with gen,
// and the storage grant for gen is applied and names it (decisions 326
// and 387).
func MayRunFor(s *cluster.Snapshot, n cluster.NodeID, w cluster.WorkloadRef, gen uint64, intent Intent) error {
	if err := mayRun(s, n, w, gen); err != nil {
		return err
	}
	p, g := s.Placements[w], s.Grants[w]
	switch intent {
	case IntentStart:
		if p.Owner != n || g.Mode != cluster.GrantExclusive || len(g.Nodes) != 1 {
			return cluster.ErrNotOwner
		}
	case IntentReceive:
		if g.Mode != cluster.GrantMigration || p.Target != n || p.Owner == n {
			return cluster.ErrNotOwner
		}
	}
	return nil
}

func mayRun(s *cluster.Snapshot, n cluster.NodeID, w cluster.WorkloadRef, gen uint64) error {
	node, ok := s.Nodes[n]
	if !ok {
		return cluster.ErrNotMember
	}
	switch node.State {
	case cluster.NodeDead, cluster.NodeFenced, cluster.NodeRejoining, cluster.NodeRemoved:
		return cluster.ErrFenced
	}
	if f := s.Fences[n]; f != nil && f.Epoch == node.FenceEpoch && f.Epoch > 0 && node.State != cluster.NodeActive && node.State != cluster.NodeMaintenance {
		return cluster.ErrFenced
	}
	p, ok := s.Placements[w]
	if !ok {
		return cluster.ErrNotOwner
	}
	g := s.Grants[w]
	if p.Generation != gen || g == nil || g.Generation != gen {
		return cluster.ErrStaleGeneration
	}
	if !slices.Contains(g.Nodes, n) {
		return cluster.ErrNotOwner
	}
	if p.Owner != n && !(g.Mode == cluster.GrantMigration && p.Target == n) {
		return cluster.ErrNotOwner
	}
	if !g.Applied {
		return cluster.ErrStorageUnavailable
	}
	return nil
}
