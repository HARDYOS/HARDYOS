package convert

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
	"github.com/hardyos/hardyos/daemon/internal/cluster/storagesvc"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

var appNotes = cluster.WorkloadRef{Kind: cluster.KindApp, ID: "notes"}

// failedAppConversion records a conversion of the app notes that stopped
// after the app was held (hardyd crashed at the final copy).
func failedAppConversion(t *testing.T, r *rig, wasRunning bool) *Record {
	t.Helper()
	rec := &Record{ID: "abandon01", Direction: DirHA, Kind: cluster.KindApp, Workload: "notes", Name: "Notes", StoragePool: "nas", LocalPool: "tank",
		Phase: PhaseFinal, State: StateFailed, WasRunning: wasRunning, Options: Options{Attempt: 1}, Actor: "alice", Started: r.w.Clock.Now()}
	if err := r.c.save(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	return rec
}

// An app whose conversion crashed after it was held: Abandon ends the
// hold and starts it again when the hold recorded that it ran before
// (decision 504), even when the record didn't keep that; never otherwise.
func TestAbandonStartsAnAppThatRan(t *testing.T) {
	for _, ran := range []bool{true, false} {
		r := newRig(t)
		r.priv.running = false
		r.priv.appHold = &apps.HAHoldResult{Held: true, WasRunning: ran}
		rec := failedAppConversion(t, r, false)
		j, err := r.c.StartAbandon(context.Background(), AbandonParams{Conv: rec.ID, Actor: cluster.Actor{Kind: "local", Name: "alice"}}, "Notes", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := r.wait(j); got.State != jobs.Succeeded {
			t.Fatalf("abandon: %s", got.Error)
		}
		ev := r.logged()
		rel, start := slices.Index(ev, "release app"), slices.Index(ev, "start app")
		if rel < 0 || (ran && start < rel) || (!ran && start >= 0) {
			t.Fatalf("ran before %v: %v", ran, ev)
		}
		if got, _ := r.c.Get(context.Background(), rec.ID); got.State != StateAbandoned {
			t.Fatalf("record %+v", got)
		}
	}
}

// The hold records the state the app was in (WasRunning passed along)
// and a conversion that gives up before the park starts it from that.
func TestRestartLocalUsesTheHold(t *testing.T) {
	r := newRig(t)
	r.priv.running = false
	r.priv.appHold = &apps.HAHoldResult{Held: true, WasRunning: true}
	rec := &Record{ID: "restart01", Kind: cluster.KindApp, Workload: "notes"}
	if !r.c.restartLocal(rec) || !rec.WasRunning || !slices.Contains(r.logged(), "start app") {
		t.Fatalf("not started again: %v", r.logged())
	}
}

type fakePeers struct {
	answers map[cluster.NodeID][]hacopy.Parked
	calls   []string
}

func (f *fakePeers) Call(_ context.Context, node cluster.NodeID, method, path string, _, out any) error {
	f.calls = append(f.calls, string(node)+" "+method+" "+path)
	l, ok := f.answers[node]
	if !ok {
		return errors.New("no answer")
	}
	if p, ok := out.(*[]hacopy.Parked); ok {
		*p = l
	}
	return nil
}

func (f *fakePeers) Do(context.Context, cluster.NodeID, *http.Request) (*http.Response, error) {
	return nil, errors.New("not here")
}

// Kept copies of every member (decision 505): this server's, the storage
// server's through its storage API, every other member's over the peer
// API, which also deletes them (DeleteOn); a member that doesn't answer
// is left out, the witness never asked.
func TestKeptFromEveryMember(t *testing.T) {
	r := newRig(t)
	peers := &fakePeers{answers: map[cluster.NodeID][]hacopy.Parked{
		"c2": {{Pool: "tank", Name: "app-notes-1764240000", Kind: cluster.KindApp, ID: "notes", Side: hacopy.SideLocal}},
	}}
	r.c.Peers = peers
	l, err := r.c.Kept(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 1 || l[0].Node != "c2" || l[0].DeleteOn != "c2" || l[0].ID != "notes" {
		t.Fatalf("kept %+v", l)
	}
	for _, c := range peers.calls {
		if strings.HasPrefix(c, "nas ") || strings.HasPrefix(c, "c1 ") || !strings.HasSuffix(c, cluster.PeerPathPrefix+PathKept) {
			t.Fatalf("asked %s", c)
		}
	}
	delete(peers.answers, "c2")
	if l, _ := r.c.Kept(context.Background()); len(l) != 0 {
		t.Fatalf("a silent member's list %+v", l)
	}
}

// Why an app's shared folders can't move (decision 502): used by another
// app here, in a backup task here, the VMs' ISO library, a name or id the
// storage server has, permissions naming domain accounts the storage
// server can't resolve; notes for what changes for people.
func TestShareProblems(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	people := []shares.Rule{{Kind: shares.KindGroup, Name: `HOME\Family`, Level: shares.LevelWrite}}
	r.priv.realm = "HOME.LAN"
	r.priv.shareList = []shares.Share{
		{ID: "media", Name: "Media", Pool: "tank", Mounted: true, UsedBytes: 10 << 30, Access: people, Services: shares.DefaultServices(),
			Apps: []shares.AppGrant{{App: "notes", UID: 30001, Level: shares.LevelWrite}, {App: "plex", UID: 30002, Level: shares.LevelRead}}},
		{ID: "photos", Name: "Photos", Pool: "tank", Mounted: true},
		{ID: "isos", Name: "ISOs", Pool: "tank", Mounted: true},
		{ID: "docs", Name: "Docs", Pool: "tank", Mounted: false},
	}
	r.stor.sharesInfo = &storagesvc.HASharesInfo{Joined: true, Realm: "OTHER.LAN", Shares: []storagesvc.HAShareName{{ID: "x", Name: "photos", Pool: "nas"}}}
	if _, err := r.c.DB.ExecContext(ctx, `INSERT INTO backup_tasks (id, name, target, items, created_at, updated_at) VALUES ('b1', 'Nightly', 't', '[{"kind":"share","id":"docs"}]', ?, ?)`,
		store.Now(), store.Now()); err != nil {
		t.Fatal(err)
	}
	li := &localInfo{name: "Notes", shares: []apps.HAShare{{ID: "media", Write: true}, {ID: "photos"}, {ID: "isos"}, {ID: "docs"}}}
	probs, notes, ready := r.c.shareProblems(ctx, appNotes, li)
	all := strings.Join(probs, "\n")
	for _, want := range []string{"also used by plex", "Media's permissions name accounts of HOME.LAN", "called photos already", "ISO library",
		"Docs isn't mounted", `backup task "Nightly"`} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in\n%s", want, all)
		}
	}
	if len(ready) != 4 || ready[0].Name != "Media" || !ready[0].Write {
		t.Fatalf("ready %+v", ready)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "Media is shared on the network from the storage server") {
		t.Fatalf("notes %v", notes)
	}
	// Same domain and nothing else in the way: no problem.
	r.stor.sharesInfo = &storagesvc.HASharesInfo{Joined: true, Realm: "home.lan", Shares: []storagesvc.HAShareName{}}
	r.priv.shareList = r.priv.shareList[:1]
	r.priv.shareList[0].Apps = r.priv.shareList[0].Apps[:1]
	li.shares = li.shares[:1]
	if probs, _, _ := r.c.shareProblems(ctx, appNotes, li); len(probs) != 0 {
		t.Fatalf("problems %v", probs)
	}
}

// The storage server's copy of a shared folder is let go of (and used in
// the cluster) only once this server's copy is recorded as put aside:
// never two copies anyone can write.
func TestShareIntoClusterNeedsTheLocalCopyParked(t *testing.T) {
	r := newRig(t)
	rec := &Record{ID: "conv0001", Kind: cluster.KindApp, Workload: "notes", StoragePool: "nas",
		Options: Options{Shares: []ShareMove{{ID: "media", Name: "Media", Pool: "tank", Conv: "conv0001s0", Adopted: true}}}}
	if err := r.c.shareIntoCluster(context.Background(), rec, cluster.Actor{}); err == nil || !strings.Contains(err.Error(), "isn't recorded as put aside") {
		t.Fatalf("let go of before this server's copy was parked: %v", err)
	}
	if rec.Options.Shares[0].Released || rec.Options.Shares[0].InCluster {
		t.Fatal("marked shared")
	}
}

// Putting a storage server's shared folder copy aside: one it never let
// go of goes for an hour when this server's copy is there; one it shared
// (it may have been written there) is kept until an administrator deletes
// it, never given a grace period.
func TestAsideShares(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.priv.shareList = []shares.Share{{ID: "media", Name: "Media", Pool: "tank"}}
	r.stor.adopted, r.stor.adoptedBy = true, "conv0001s0"
	rec := &Record{ID: "conv0001", Kind: cluster.KindApp, Workload: "notes", StoragePool: "nas",
		Options: Options{Attempt: 1, Shares: []ShareMove{{ID: "media", Name: "Media", Pool: "tank", Conv: "conv0001s0", Adopted: true}}}}
	if err := r.c.asideShares(ctx, rec, cluster.Actor{}, false); err != nil {
		t.Fatal(err)
	}
	last := r.stor.parks[len(r.stor.parks)-1]
	if last.Expect != "conv0001s0" || last.KeepUntil == 0 || last.Workload.Kind != hacopy.KindShare || rec.Options.Shares[0].UntilDeleted {
		t.Fatalf("aside %+v %+v", last, rec.Options.Shares[0])
	}
	r.stor.adopted, r.stor.adoptedBy = true, "conv0001s0"
	rec.Options.Shares[0] = ShareMove{ID: "media", Name: "Media", Pool: "tank", Conv: "conv0001s0", Adopted: true, Released: true}
	if err := r.c.asideShares(ctx, rec, cluster.Actor{}, false); err != nil {
		t.Fatal(err)
	}
	last = r.stor.parks[len(r.stor.parks)-1]
	if last.KeepUntil != 0 || !rec.Options.Shares[0].UntilDeleted || rec.Options.Shares[0].ParkedName == "" {
		t.Fatalf("a shared copy got an expiry: %+v %+v", last, rec.Options.Shares[0])
	}
	// keepShares never gives that one a grace period.
	n := len(r.stor.keeps)
	r.c.keepShares(ctx, rec, cluster.Actor{})
	if len(r.stor.keeps) != n {
		t.Fatal("a copy kept until deleted got a grace period")
	}
}
