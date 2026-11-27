package storagesvc

import (
	"net/http"
	"slices"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// The storage server's side of a shared folder that moves with an app
// (decisions 500-502): letting go of one adopted held needs an
// administrator's signed request and names a shared folder; one is
// adopted only with its settings; one still used in the cluster is never
// put aside; and none is put back from another server.
func TestHAShareRules(t *testing.T) {
	s, ids := storageWithKeys(t)
	m := &fakeMembership{self: "nas", s: s}
	pv := &fakePriv{}
	svc := &Service{M: m, Priv: pv, Audit: (&auditLog{}).record, Network: netStatus("10.77.0.10", "enp2s0")}
	mux := newFakeMux()
	svc.RegisterPeer(mux)
	mux.caller = *s.Nodes["c1"]
	alice := cluster.Principal{Kind: "local", Name: "alice", Admin: true}
	c1 := &signer{id: ids["c1"], node: "c1"}
	media := cluster.WorkloadRef{Kind: hacopy.KindShare, ID: "media"}

	rel := HARequest{Workload: media, Conv: "abcdefgh12s0"}
	if w := post(t, mux, "storage/ha/share/release", rel, nil, cluster.Principal{}); w.Code != http.StatusForbidden {
		t.Fatalf("released without an administrator: %d %s", w.Code, w.Body)
	}
	if w := post(t, mux, "storage/ha/share/release", HARequest{Workload: web, Conv: "abcdefgh12"}, c1, alice); w.Code != http.StatusForbidden {
		t.Fatalf("a VM let go of as a shared folder: %d", w.Code)
	}
	if slices.Contains(pv.ops(), "shares.ha.hold") {
		t.Fatal("a refused request reached root")
	}
	if w := post(t, mux, "storage/ha/share/release", rel, c1, alice); w.Code != http.StatusOK {
		t.Fatalf("release: %d %s", w.Code, w.Body)
	}
	var got shares.HAHoldArgs
	for _, c := range pv.calls {
		if c.op == "shares.ha.hold" {
			got = c.args.(shares.HAHoldArgs)
		}
	}
	if got.ID != "media" || got.Conv != "abcdefgh12s0" || !got.Release {
		t.Fatalf("root was asked %+v", got)
	}
	if w := post(t, mux, "storage/ha/adopt", HARequest{Workload: media, Pool: "tank", Conv: "abcdefgh12s0"}, c1, alice); w.Code != http.StatusForbidden {
		t.Fatalf("adopted without its settings: %d %s", w.Code, w.Body)
	}
	s.ClusterShares = map[string]*cluster.ClusterShare{"media": {ID: "media", Pool: "tank", Dataset: "tank/shares/media"}}
	if w := post(t, mux, "storage/ha/park", HARequest{Workload: media, Pool: "tank", Confirm: "media", Conv: "abcdefgh12s0x1", Expect: "abcdefgh12s0"}, c1, alice); w.Code != http.StatusForbidden {
		t.Fatalf("parked while used in the cluster: %d %s", w.Code, w.Body)
	}
	if w := post(t, mux, "storage/ha/unpark", HARequest{Workload: media, Pool: "tank", Name: "share-media-1"}, c1, alice); w.Code != http.StatusForbidden {
		t.Fatalf("put back from another server: %d %s", w.Code, w.Body)
	}
}
