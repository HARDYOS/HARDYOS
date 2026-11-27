package netcheck

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

type fakeState struct{ s *cluster.Snapshot }

func (f fakeState) Snapshot() *cluster.Snapshot { return f.s }
func (f fakeState) Node(id cluster.NodeID) (*cluster.Node, bool) {
	n, ok := f.s.Nodes[id]
	return n, ok
}
func (f fakeState) Placement(cluster.WorkloadRef) (*cluster.Placement, bool) { return nil, false }
func (f fakeState) Grant(cluster.WorkloadRef) (*cluster.Grant, bool)         { return nil, false }
func (f fakeState) Index() uint64                                            { return 1 }

type fakeLocal struct {
	self cluster.Node
	snap *cluster.Snapshot
}

func (f *fakeLocal) Self() (cluster.Node, error) { return f.self, nil }
func (f *fakeLocal) State() cluster.State        { return fakeState{f.snap} }
func (f *fakeLocal) Identity() *cluster.Identity { return nil }
func (f *fakeLocal) DialPeer(context.Context, string, cluster.Node) (net.Conn, error) {
	return nil, cluster.ErrUnreachable
}

type fakePeers struct {
	mu   sync.Mutex
	reps map[cluster.NodeID]*Report
}

func (f *fakePeers) Call(_ context.Context, node cluster.NodeID, _, path string, _, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.reps[node]
	if r == nil {
		return cluster.ErrUnreachable
	}
	b, _ := json.Marshal(r)
	return json.Unmarshal(b, out)
}

func (f *fakePeers) Do(context.Context, cluster.NodeID, *http.Request) (*http.Response, error) {
	return nil, cluster.ErrUnreachable
}

func TestMonitorNotifiesOwnChangesAfterTwoRounds(t *testing.T) {
	c := newTCluster(t)
	good := c.reports(t)
	self := c.nodes["c1"].node
	peers := &fakePeers{reps: good}
	var notes []bool
	m := &Monitor{Local: &fakeLocal{self: self, snap: c.snap}, Peers: peers, OnChange: func(_ context.Context, mine MemberResult, _ Result) {
		notes = append(notes, mine.OK)
	}}
	set := func(r *Report) {
		cp := *r
		cp.Checked = time.Now()
		m.mu.Lock()
		m.report = &cp
		m.mu.Unlock()
	}
	set(good["c1"])
	m.observe(context.Background())
	m.observe(context.Background())
	if len(notes) != 0 {
		t.Fatalf("a good first state notified: %v", notes)
	}
	bad := *good["c1"]
	bad.Paths = append([]PathResult(nil), bad.Paths...)
	bad.Paths[0].Answered = false
	set(&bad)
	m.observe(context.Background())
	if len(notes) != 0 {
		t.Fatalf("one bad round notified: %v", notes)
	}
	m.observe(context.Background())
	if len(notes) != 1 || notes[0] {
		t.Fatalf("two bad rounds: %v", notes)
	}
	m.observe(context.Background())
	if len(notes) != 1 {
		t.Fatalf("notified again: %v", notes)
	}
	set(good["c1"])
	m.observe(context.Background())
	m.observe(context.Background())
	if len(notes) != 2 || !notes[1] {
		t.Fatalf("back to good: %v", notes)
	}
	// Another server's problem isn't this server's notification, but it
	// is in the cluster's result.
	peers.mu.Lock()
	delete(peers.reps, "c2")
	peers.mu.Unlock()
	m.observe(context.Background())
	m.observe(context.Background())
	if len(notes) != 2 {
		t.Fatalf("notified for c2: %v", notes)
	}
	m.mu.Lock()
	m.fetched = nil
	m.mu.Unlock()
	if r := m.Status(context.Background()); r.OK {
		t.Fatalf("c2's missing report: %+v", r)
	}
}
