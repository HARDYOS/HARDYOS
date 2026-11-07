package runtime_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/cluster/runtime"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

type source struct{ imgs map[string][]string }

func (s *source) Images(_ context.Context, _ cluster.NodeID, app string) ([]string, error) {
	if l, ok := s.imgs[app]; ok {
		return slices.Clone(l), nil
	}
	return nil, errors.New("owner unreachable")
}

type store struct {
	have   []string
	pulls  [][]string
	broken string
}

func (s *store) Have(_ context.Context, imgs []string) ([]string, error) {
	var out []string
	for _, i := range imgs {
		if slices.Contains(s.have, i) {
			out = append(out, i)
		}
	}
	return out, nil
}
func (s *store) Pull(_ context.Context, imgs []string) (map[string]string, error) {
	s.pulls = append(s.pulls, slices.Clone(imgs))
	failed := map[string]string{}
	for _, i := range imgs {
		if i == s.broken {
			failed[i] = "registry unreachable"
			continue
		}
		s.have = append(s.have, i)
	}
	return failed, nil
}

func TestPrepullKeepsHAAppImagesEverywhere(t *testing.T) {
	w := clustertest.New(t, "c1", "c2")
	app := cluster.WorkloadRef{Kind: cluster.KindApp, ID: "wiki"}
	plain := cluster.WorkloadRef{Kind: cluster.KindApp, ID: "notes"}
	_ = w.Propose("c1", cluster.CmdWorkloadAdd, state.WorkloadAdd{SpecHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Workload: app, Name: "wiki", Owner: "c1", HA: cluster.HAPolicy{Enabled: true}})
	_ = w.Propose("c1", cluster.CmdWorkloadAdd, state.WorkloadAdd{SpecHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Workload: plain, Name: "notes", Owner: "c1"})
	src := &source{imgs: map[string][]string{"wiki": {"ghcr.io/x/wiki:1.0", "postgres:16"}, "notes": {"notes:1"}}}
	st := &store{have: []string{"postgres:16"}}
	p := &runtime.Prepuller{Cluster: w.Nodes["c2"], Source: src, Images: st, Now: w.Clock.Now}
	ctx := context.Background()
	p.Step(ctx, false)
	if len(st.pulls) != 1 || !slices.Equal(st.pulls[0], []string{"ghcr.io/x/wiki:1.0"}) {
		t.Fatalf("pulled %v (only the missing image of the HA app)", st.pulls)
	}
	p.Step(ctx, false)
	if len(st.pulls) != 1 {
		t.Fatal("pulled again without a change")
	}
	// An update changes the image list: refreshed at once.
	src.imgs["wiki"] = []string{"ghcr.io/x/wiki:1.1", "postgres:16"}
	st.broken = "ghcr.io/x/wiki:1.1"
	p.Step(ctx, false)
	s := p.Status()
	if len(s) != 1 || s[0].App != "wiki" || !slices.Equal(s[0].Missing, []string{"ghcr.io/x/wiki:1.1"}) || s[0].Failed["ghcr.io/x/wiki:1.1"] == "" {
		t.Fatalf("%+v", s)
	}
	// The owner is unreachable: the last known list is used.
	delete(src.imgs, "wiki")
	st.broken = ""
	p.Step(ctx, true)
	if s := p.Status(); len(s[0].Missing) != 0 {
		t.Fatalf("%+v", s)
	}
	// A node that can't host HA keeps nothing.
	w.SetCompute("c2", func(ci *cluster.ComputeInfo) { ci.Watchdog = "softdog" })
	p.Step(ctx, true)
	if len(p.Status()) != 0 {
		t.Fatal("a node that can't run HA workloads pre-pulls")
	}
	_ = time.Second
}
