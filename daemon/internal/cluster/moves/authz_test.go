package moves_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/moves"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

// as calls a node's move step as member from.
func (e *env) as(from cluster.NodeID) *peers {
	p := e.mover.Peers.(*peers)
	return &peers{from: from, servers: p.servers}
}

func step(t *testing.T, p *peers, node cluster.NodeID, path string, in any) error {
	t.Helper()
	var res moves.StepResult
	if err := p.Call(context.Background(), node, http.MethodPost, cluster.PeerPathPrefix+path, in, &res); err != nil {
		return err
	}
	if !res.OK {
		return &cluster.PeerError{Node: node, Message: res.Message}
	}
	return nil
}

// A member that isn't moving a workload (nor the leader) can't drive any
// of its steps: stop it, start it, hold it, take its storage away, abort
// or admit a migration, or read an app's publishing (decision 387).
func TestMisbehavingPeerCantDriveMoveSteps(t *testing.T) {
	e := newEnv(t)
	vm := e.w.AddVM("web", "c1", true, 50)
	e.w.Run(2 * time.Second)
	onlyOn(t, e.w, vm, "c1")
	evil := e.as("c2")
	cases := map[string]struct {
		node cluster.NodeID
		path string
		in   any
	}{
		"stop":    {"c1", moves.PathStop, moves.StepRequest{Workload: vm, Generation: 1}},
		"start":   {"c2", moves.PathStart, moves.StepRequest{Workload: vm, Generation: 1, Start: true}},
		"hold":    {"c1", moves.PathHold, moves.HoldRequest{Workload: vm, Seconds: 3600}},
		"detach":  {"c1", moves.PathDetach, moves.StepRequest{Workload: vm, Generation: 1, Force: true}},
		"attach":  {"c2", moves.PathAttach, moves.StepRequest{Workload: vm, Generation: 1, Migration: true}},
		"abort":   {"c1", moves.PathAbort, moves.AbortRequest{VM: "web", Generation: 1}},
		"accept":  {"c2", moves.PathAccept, moves.AcceptRequest{VM: "web", From: "c1", Token: strings.Repeat("ab", 16), Generation: 1}},
		"send":    {"c1", moves.PathSend, moves.SendRequest{VM: "web", To: "c2", Token: strings.Repeat("ab", 16), Generation: 1, MigrateURI: "tcp://10.77.0.22"}},
		"prepare": {"c2", moves.PathPrepare, moves.PrepareRequest{Workload: vm, Mode: cluster.MoveOffline}},
		"state":   {"c1", moves.PathState, moves.StateRequest{VM: "web"}},
	}
	for name, c := range cases {
		if err := step(t, evil, c.node, c.path, c.in); err == nil {
			t.Errorf("%s from a bystander was accepted", name)
		}
	}
	// A move begun by c3 (the mover) doesn't give c1 or c2 a say.
	if err := e.w.Propose("c3", cluster.CmdMoveBegin, state.MoveBegin{Workload: vm, Generation: 1, To: "c2", Mode: cluster.MoveOffline}); err != nil {
		t.Fatal(err)
	}
	if err := step(t, e.as("c2"), "c1", moves.PathStop, moves.StepRequest{Workload: vm, Generation: 1}); err == nil {
		t.Fatal("the destination stopped the workload on the source")
	}
	if err := e.w.Propose("c1", cluster.CmdPlacementSet, state.PlacementSet{Workload: vm, Expected: 1, Owner: "c2", State: cluster.PlacementStarting, Reason: "move"}); err == nil {
		t.Fatal("a member other than the mover handed the workload over")
	}
	e.w.Run(3 * time.Second)
	onlyOn(t, e.w, vm, "c1")
	if len(e.w.Violations) > 0 {
		t.Fatal(e.w.Violations)
	}
}

func TestPublishOnlyToTheMovesDestination(t *testing.T) {
	e := newEnv(t)
	app := cluster.WorkloadRef{Kind: cluster.KindApp, ID: "notes"}
	if err := e.w.Propose("c1", cluster.CmdWorkloadAdd, state.WorkloadAdd{SpecHash: "sha256:" + strings.Repeat("a", 64), Workload: app, Name: "notes", Owner: "c1", Requested: cluster.RequestRunning}); err != nil {
		t.Fatal(err)
	}
	e.w.Run(2 * time.Second)
	get := func(as cluster.NodeID) error {
		var pc moves.PublishConfig
		return e.as(as).Call(context.Background(), "c1", http.MethodGet, cluster.PeerPathPrefix+moves.PathPublishExport+"?app="+url.QueryEscape("notes"), nil, &pc)
	}
	var res moves.StepResult
	_ = e.as("c2").Call(context.Background(), "c1", http.MethodGet, cluster.PeerPathPrefix+moves.PathPublishExport+"?app=notes", nil, &res)
	if res.OK || res.Message == "" {
		t.Fatalf("c2 read the app's publishing without a move: %+v", res)
	}
	if err := e.w.Propose("c3", cluster.CmdMoveBegin, state.MoveBegin{Workload: app, Generation: 1, To: "c2", Mode: cluster.MoveOffline}); err != nil {
		t.Fatal(err)
	}
	res = moves.StepResult{}
	_ = e.as("c3").Call(context.Background(), "c1", http.MethodGet, cluster.PeerPathPrefix+moves.PathPublishExport+"?app=notes", nil, &res)
	if res.Message == "" {
		t.Fatal("the mover itself read the app's publishing (only the destination may)")
	}
	if err := get("c2"); err != nil {
		t.Fatalf("the destination couldn't read it: %v", err)
	}
}

func TestMigrationTargetCantColdStart(t *testing.T) {
	e := newEnv(t)
	vm := e.w.AddVM("web", "c1", false, 0)
	e.w.Run(2 * time.Second)
	if err := e.w.Propose("c3", cluster.CmdMoveBegin, state.MoveBegin{Workload: vm, Generation: 1, To: "c2", Mode: cluster.MoveLive}); err != nil {
		t.Fatal(err)
	}
	e.w.Run(time.Second) // the storage node applies the two-node grant
	if err := step(t, e.as("c3"), "c2", moves.PathStart, moves.StepRequest{Workload: vm, Generation: 2, Start: true}); err == nil {
		t.Fatal("the destination of a live migration started the VM from cold")
	}
	if _, ok := e.w.Nodes["c2"].RunningGen(vm); ok {
		t.Fatal("two runners")
	}
}

// The migration arrived but send reported a failure: the destination has
// the only copy and keeps it; the source doesn't start it again.
func TestFailedSendThatLandedStaysOnTheDestination(t *testing.T) {
	e := newEnv(t)
	vm := e.w.AddVM("web", "c1", true, 50)
	e.w.Run(2 * time.Second)
	e.privs["c1"].failSend = true
	e.privs["c1"].sendLands = true
	if _, err := e.mover.Move(context.Background(), cluster.MoveRequest{Workload: vm, To: "c2", Mode: cluster.MoveLive}, actor); err == nil {
		t.Fatal("the failed send was reported as a success")
	}
	p := e.w.Snapshot().Placements[vm]
	if p.Owner != "c2" || p.State != cluster.PlacementRunning || p.Target != "" {
		t.Fatalf("%+v", p)
	}
	for i := 0; i < 10; i++ {
		e.w.Run(time.Second)
		onlyOn(t, e.w, vm, "c2")
	}
	if len(e.w.Violations) > 0 {
		t.Fatal(e.w.Violations)
	}
}

// A copy left on the destination is destroyed by its root before the
// migration collapses onto the source.
func TestFailedMigrationDestroysTheDestinationCopy(t *testing.T) {
	e := newEnv(t)
	vm := e.w.AddVM("web", "c1", true, 50)
	e.w.Run(2 * time.Second)
	e.privs["c1"].failSend = true
	e.privs["c1"].leaveCopy = true
	if _, err := e.mover.Move(context.Background(), cluster.MoveRequest{Workload: vm, To: "c2", Mode: cluster.MoveLive}, actor); err == nil {
		t.Fatal("reported success")
	}
	if d := e.privs["c2"].destroyed; len(d) != 1 || d[0] != "web" {
		t.Fatalf("destroyed on c2: %v", d)
	}
	p := e.w.Snapshot().Placements[vm]
	if p.Owner != "c1" || p.State != cluster.PlacementRunning {
		t.Fatalf("%+v", p)
	}
	e.w.Run(5 * time.Second)
	onlyOn(t, e.w, vm, "c1")
	if g, _ := e.w.Nodes["c1"].RunningGen(vm); g != 1 {
		t.Fatalf("the source restarted the VM (generation %d)", g)
	}
}
