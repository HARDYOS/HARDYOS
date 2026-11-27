package netcheck

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Only the pairs that matter (decision 496): a server in maintenance or out
// of reach fails only the decisions that involve it.
func TestNetcheckScopedPairs(t *testing.T) {
	c := newTCluster(t)
	// c2 lost its storage port: the cluster card fails, a move between c1
	// and nas doesn't care.
	c2 := c.nodes["c2"].node.Addresses.Storage
	c.net.Isolate(c2, c.nodes["nas"].node.Addresses.Storage, c.nodes["c1"].node.Addresses.Storage)
	reps := c.reports(t)
	if res := Evaluate(c.snap, reps, nil, time.Now()); res.OK {
		t.Fatalf("cluster-wide: %+v", res)
	}
	res := EvaluateFor(c.snap, reps, nil, time.Now(), "c1")
	if !res.OK || len(res.PerMember) != 2 {
		t.Fatalf("c1 and the storage server: %+v", res)
	}
	for _, m := range res.PerMember {
		for _, p := range m.Paths {
			if p.Peer == "c2" {
				t.Fatalf("judged a pair with c2: %+v", p)
			}
		}
	}
	if res := EvaluateFor(c.snap, reps, nil, time.Now(), "c1", "c2"); res.OK || !strings.Contains(res.Reason, "storage network") {
		t.Fatalf("c1 and c2: %+v", res)
	}
	// c2 unreachable altogether (no report): the same.
	delete(reps, "c2")
	if res := EvaluateFor(c.snap, reps, map[cluster.NodeID]error{"c2": cluster.ErrUnreachable}, time.Now(), "c1"); !res.OK {
		t.Fatalf("an unreachable c2 failed c1's move: %+v", res)
	}
	// In maintenance: skipped in the card, refused when named.
	c.snap.Nodes["c2"].State = cluster.NodeMaintenance
	c.net.Rejoin(c2, c.nodes["nas"].node.Addresses.Storage, c.nodes["c1"].node.Addresses.Storage)
	reps = c.reports(t)
	if res := Evaluate(c.snap, reps, nil, time.Now()); !res.OK {
		t.Fatalf("maintenance failed the card: %+v", res)
	}
	if res := EvaluateFor(c.snap, reps, nil, time.Now(), "c1", "c2"); res.OK || !strings.Contains(res.Reason, "c2 is maintenance") {
		t.Fatalf("named while in maintenance: %+v", res)
	}
	if res := EvaluateFor(c.snap, reps, nil, time.Now(), "nope"); res.OK || !strings.Contains(res.Reason, "isn't a compute or storage server") {
		t.Fatalf("unknown member: %+v", res)
	}
	// StatusFor over a Source fetches only what it judges.
	src := &staticSource{snap: c.snap, reps: reps}
	if res := StatusFor(context.Background(), src, "c1"); !res.OK {
		t.Fatalf("StatusFor: %+v", res)
	}
	if !slices.Equal(src.asked, []cluster.NodeID{"c1", "nas"}) {
		t.Fatalf("fetched %v, want only c1 and nas", src.asked)
	}
}

func TestNetcheckFutureReport(t *testing.T) {
	c := newTCluster(t)
	reps := c.reports(t)
	reps["c1"].Checked = time.Now().Add(time.Minute)
	if res := Evaluate(c.snap, reps, nil, time.Now()); res.OK || !strings.Contains(res.Reason, "in the future") {
		t.Fatalf("%+v", res)
	}
}

type staticSource struct {
	snap  *cluster.Snapshot
	reps  map[cluster.NodeID]*Report
	asked []cluster.NodeID
}

func (s *staticSource) Snapshot() *cluster.Snapshot { return s.snap }

func (s *staticSource) Reports(_ context.Context, ids []cluster.NodeID) (map[cluster.NodeID]*Report, map[cluster.NodeID]error) {
	s.asked = ids
	out := map[cluster.NodeID]*Report{}
	for _, id := range ids {
		if r := s.reps[id]; r != nil {
			out[id] = r
		}
	}
	return out, nil
}
