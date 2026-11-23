package publish

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/netbird"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func TestClusterServiceNames(t *testing.T) {
	if got := clusterServiceName("abcdefghijklmnop", AppKey("wiki")); got != "hardyos-c-abcdefgh-app-wiki" {
		t.Fatalf("got %s", got)
	}
	if validClusterID("../x") || !validClusterID("abcdefgh234567") {
		t.Fatal("cluster id check")
	}
}

// TestClusterAppFollowsItsOwner: a cluster app published by c1 moves to
// c2; c2's sync points the same service at itself, c1 leaves it alone, and
// the publishing choice (with its password) moves along.
func TestClusterAppFollowsItsOwner(t *testing.T) {
	e := newEnv(t) // c1 (peer-nas, 100.83.40.2)
	const cid = "abcdefghijklmnop"
	e.in.ClusterID = cid
	e.in.ClusterApps = []string{"wiki"}
	e.in.Apps = append(e.in.Apps, App{ID: "wiki", Name: "Wiki", Cluster: true})
	pw := "family-secret-1"
	if err := e.st.SetConfig(e.ctx, AppKey("wiki"), ServiceConfig{Mode: ModePublic, Auth: AuthPassword}, &pw); err != nil {
		t.Fatal(err)
	}
	e.sync(t)
	svc := byDomain(e.nb, "wiki.home.example.net")
	if svc == nil || svc.Name != "hardyos-c-abcdefgh-app-wiki" || svc.Targets[0].TargetID != "peer-nas" {
		t.Fatalf("on c1: %+v", svc)
	}

	// c2: another server on the same NetBird account.
	e.nb.Lock()
	e.nb.Peers = append(e.nb.Peers, netbird.Peer{ID: "peer-c2", Name: "c2", IP: "100.83.40.3", Connected: true, Hostname: "c2"})
	e.nb.Unlock()
	ctx := context.Background()
	db2, err := store.Open(ctx, filepath.Join(t.TempDir(), "c2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	st2 := &Store{DB: db2, Sealer: &Sealer{KeyFile: filepath.Join(t.TempDir(), "k", "hardyd.key")}}
	_ = st2.SetToken(ctx, "nbp_token123")
	if _, err := st2.Save(ctx, Settings{Enabled: true, BaseDomain: "home.example.net", DefaultMode: ModeOff, DesktopName: "c2"}); err != nil {
		t.Fatal(err)
	}
	pub2 := &Publisher{Store: st2}
	in2 := Inputs{NetBirdIP: "100.83.40.3", ManagementURL: e.nb.URL, Known: true, ClusterID: cid, ClusterApps: []string{"wiki"}}

	// Before the move c2 doesn't touch c1's app.
	if _, err := pub2.Sync(ctx, in2); err != nil {
		t.Fatal(err)
	}
	if v := byDomain(e.nb, "wiki.home.example.net"); v == nil || v.Targets[0].TargetID != "peer-nas" {
		t.Fatalf("c2 touched c1's app: %+v", v)
	}

	// The move: the choice travels, c2 owns the app now.
	raw, err := Handoff{Store: e.st}.Export(ctx, "wiki")
	if err != nil {
		t.Fatal(err)
	}
	if err := (Handoff{Store: st2}).Import(ctx, "wiki", raw); err != nil {
		t.Fatal(err)
	}
	in2.Apps = []App{{ID: "wiki", Name: "Wiki", Cluster: true}}
	if _, err := pub2.Sync(ctx, in2); err != nil {
		t.Fatal(err)
	}
	e.in.Apps = e.in.Apps[:len(e.in.Apps)-1]
	e.sync(t)
	v := byDomain(e.nb, "wiki.home.example.net")
	if v == nil || v.Targets[0].TargetID != "peer-c2" || v.Name != "hardyos-c-abcdefgh-app-wiki" || v.Auth.PasswordAuth == nil {
		t.Fatalf("after the move: %+v", v)
	}
	n := 0
	for _, s := range e.nb.ServiceList() {
		if s.Domain == "wiki.home.example.net" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d services for wiki", n)
	}

	// The app leaves the cluster: whoever syncs removes its service.
	in2.Apps, in2.ClusterApps = nil, []string{}
	if _, err := pub2.Sync(ctx, in2); err != nil {
		t.Fatal(err)
	}
	if byDomain(e.nb, "wiki.home.example.net") != nil {
		t.Fatal("a removed cluster app stayed published")
	}
}
