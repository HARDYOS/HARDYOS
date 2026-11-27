package convert

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// Undo checks first that this server's copies of the shared folders can
// come back (decision 508): with one missing, nothing changes, the storage
// server's copies included.
func TestUndoNeedsTheLocalSharesThere(t *testing.T) {
	r := newRig(t)
	rec := &Record{ID: "undoshare1", Direction: DirHA, Kind: cluster.KindApp, Workload: "notes", Name: "Notes", StoragePool: "nas", LocalPool: "tank",
		Phase: PhaseRegister, State: StateFailed, Actor: "alice", Started: r.w.Clock.Now(),
		Options: Options{Attempt: 1, Shares: []ShareMove{{ID: "media", Name: "Media", Pool: "tank", Conv: "undoshare1s0", ParkedPool: "tank",
			ParkedName: "share-media-1", ParkedSide: "local", Adopted: true, Released: true, InCluster: true}}}}
	if err := r.c.save(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
	j, err := r.c.StartUndo(context.Background(), UndoParams{Conv: rec.ID}, "Notes", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := r.wait(j)
	if got.State != jobs.Failed || !strings.Contains(got.Error, "isn't here") || !strings.Contains(got.Error, "nothing was changed") {
		t.Fatalf("undo: %s %s", got.State, got.Error)
	}
	if len(r.stor.parks) != 0 {
		t.Fatalf("the storage server's copies were touched: %+v", r.stor.parks)
	}
}

// Abandon is refused while a shared folder is parked on this server
// (never parked on both servers, decision 508).
func TestAbandonRefusedWhileASharedFolderIsParkedHere(t *testing.T) {
	r := newRig(t)
	rec := failedAppConversion(t, r, true)
	rec.Options.Shares = []ShareMove{{ID: "media", Name: "Media", Pool: "tank", Conv: rec.ID + "s0", ParkedPool: "tank", ParkedName: "share-media-1", ParkedSide: "local"}}
	_ = r.c.save(context.Background(), rec)
	if _, err := r.c.StartAbandon(context.Background(), AbandonParams{Conv: rec.ID}, "Notes", nil); err == nil || !strings.Contains(err.Error(), "put aside on this server") {
		t.Fatalf("abandon: %v", err)
	}
}

// The checks that may have changed during a long copy run again just
// before the hold (decision 508).
func TestHoldSharesChecksAgain(t *testing.T) {
	r := newRig(t)
	rec := &Record{ID: "holdagain1", Kind: cluster.KindApp, Workload: "notes", Options: Options{Shares: []ShareMove{{ID: "media", Name: "Media", Pool: "tank", Conv: "holdagain1s0"}}}}
	r.priv.shareList = []shares.Share{{ID: "media", Name: "Media", Pool: "tank", Mounted: true,
		Apps: []shares.AppGrant{{App: "notes", UID: 30001, Level: shares.LevelRead}, {App: "plex", UID: 30002, Level: shares.LevelRead}}}}
	if err := r.c.holdShares(context.Background(), rec); err == nil || !strings.Contains(err.Error(), "plex") {
		t.Fatalf("held though another app uses it now: %v", err)
	}
	if slices.ContainsFunc(r.logged(), func(e string) bool { return strings.HasPrefix(e, "hold share") }) {
		t.Fatal("held")
	}
	r.priv.shareList[0].Apps = r.priv.shareList[0].Apps[:1]
	if err := r.c.holdShares(context.Background(), rec); err != nil || !slices.Contains(r.logged(), "hold share media") {
		t.Fatalf("hold: %v %v", err, r.logged())
	}
}
