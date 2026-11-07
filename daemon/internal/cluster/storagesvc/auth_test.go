package storagesvc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/sanclient"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// fakeMux serves the registered handlers with a chosen caller.
type fakeMux struct {
	mux    *http.ServeMux
	caller cluster.Node
	fenced []string
}

func newFakeMux() *fakeMux { return &fakeMux{mux: http.NewServeMux()} }

func (m *fakeMux) Handle(p string, h http.Handler) { m.mux.Handle(p, h) }
func (m *fakeMux) AllowFenced(p string, h http.Handler) {
	m.fenced = append(m.fenced, p)
	m.mux.Handle(p, h)
}
func (m *fakeMux) Caller(*http.Request) (cluster.Node, bool) { return m.caller, m.caller.ID != "" }

// signer signs like a node's core.
type signer struct {
	id   *cluster.Identity
	node cluster.NodeID
}

func (s signer) Identity() *cluster.Identity { return s.id }
func (s signer) AssertFor(f *cluster.Forward, sum []byte) (string, error) {
	now := time.Now()
	return cluster.SignAssertion(s.id, cluster.Assertion{Issuer: s.node, Audience: f.Node, Subject: f.Principal, IssuedAt: now.Unix(),
		ExpiresAt: now.Add(cluster.AssertionTTL).Unix(), Nonce: cluster.NewNonce(), Request: cluster.RequestHashDigest(f.Method, f.Path, f.RawQuery, sum)})
}

// auditLog records audit entries.
type auditLog struct {
	mu      sync.Mutex
	entries []string
}

func (a *auditLog) record(_ context.Context, actor cluster.Actor, action, target string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, actor.Kind+":"+actor.Name+" via "+string(actor.Via)+" "+action+" "+target)
}

// storageWithKeys is the test state with keys for c1 and c2.
func storageWithKeys(t *testing.T) (*cluster.Snapshot, map[cluster.NodeID]*cluster.Identity) {
	t.Helper()
	s := testSnapshot()
	ids := map[cluster.NodeID]*cluster.Identity{}
	for _, n := range []cluster.NodeID{"c1", "c2"} {
		id, err := cluster.NewIdentity(string(n))
		if err != nil {
			t.Fatal(err)
		}
		ids[n] = id
		s.Nodes[n].PublicKey = id.PublicKey
	}
	return s, ids
}

func post(t *testing.T, m *fakeMux, path string, body any, sig *signer, principal cluster.Principal) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	full := cluster.PeerPathPrefix + path
	r := httptest.NewRequest(http.MethodPost, full, bytes.NewReader(b))
	if sig != nil {
		sum := sha256.Sum256(b)
		jws, err := sig.AssertFor(&cluster.Forward{Node: "nas", Principal: principal, Method: http.MethodPost, Path: full}, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set(cluster.AssertionHeader, jws)
	}
	w := httptest.NewRecorder()
	m.mux.ServeHTTP(w, r)
	return w
}

func TestPeerRequestsTakeThePersonFromTheAssertion(t *testing.T) {
	s, ids := storageWithKeys(t)
	m := &fakeMembership{self: "nas", s: s}
	al := &auditLog{}
	pv := &fakePriv{}
	svc := &Service{M: m, Priv: pv, Audit: al.record, Network: netStatus("10.77.0.10", "enp2s0")}
	mux := newFakeMux()
	svc.RegisterPeer(mux)
	mux.caller = *s.Nodes["c1"]
	alice := cluster.Principal{Kind: "local", Name: "alice", Admin: true}
	c1 := &signer{id: ids["c1"], node: "c1"}

	// A bare node call can't destroy, roll back, delete snapshots, resize,
	// switch a mode or share a folder, whatever actor its body names (H1).
	for path, body := range map[string]any{
		"storage/destroy":         destroyReq{Workload: web, Confirm: "web", Actor: cluster.Actor{Kind: "local", Name: "admin"}},
		"storage/rollback":        snapReq{Workload: web, Name: "s1", Confirm: "s1", Actor: cluster.Actor{Kind: "local", Name: "admin"}},
		"storage/snapshot/delete": snapReq{Workload: web, Name: "s1", Confirm: "s1"},
		"storage/resize":          resizeReq{Workload: web, Disk: "disk0", SizeGB: 99},
		"storage/mode":            ModeRequest{App: "notes", To: cluster.StorageBlock, Confirm: "notes"},
		"storage/share":           ShareRequest{Pool: "tank", ID: "media", In: true},
	} {
		if w := post(t, mux, path, body, nil, cluster.Principal{}); w.Code != http.StatusForbidden {
			t.Errorf("%s without an assertion: %d %s", path, w.Code, w.Body)
		}
	}
	if len(pv.calls) != 0 {
		t.Fatalf("a refused request reached root: %v", pv.ops())
	}
	// An assertion signed with another node's key is refused.
	forged := &signer{id: ids["c2"], node: "c1"}
	if w := post(t, mux, "storage/snapshot/delete", snapReq{Workload: web, Name: "s1", Confirm: "s1"}, forged, alice); w.Code != http.StatusForbidden {
		t.Fatalf("forged assertion: %d %s", w.Code, w.Body)
	}
	// A non-admin person can't either.
	if w := post(t, mux, "storage/snapshot/delete", snapReq{Workload: web, Name: "s1", Confirm: "s1"}, c1, cluster.Principal{Kind: "local", Name: "bob"}); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin assertion: %d %s", w.Code, w.Body)
	}
	// An administrator's: done, audited as that person via c1, whatever
	// the body says.
	body := snapReq{Workload: web, Name: "s1", Confirm: "s1", Actor: cluster.Actor{Kind: "local", Name: "mallory"}}
	if w := post(t, mux, "storage/snapshot/delete", body, c1, alice); w.Code != http.StatusOK {
		t.Fatalf("admin delete: %d %s", w.Code, w.Body)
	}
	if !slices.Contains(al.entries, "local:alice via c1 cluster.storage.snapshot.delete vm web@s1") {
		t.Fatalf("audit %v", al.entries)
	}
	// The same assertion can't be used twice.
	b, _ := json.Marshal(snapReq{Workload: web, Name: "s2", Confirm: "s2"})
	full := cluster.PeerPathPrefix + "storage/snapshot/delete"
	sum := sha256.Sum256(b)
	jws, _ := c1.AssertFor(&cluster.Forward{Node: "nas", Principal: alice, Method: http.MethodPost, Path: full}, sum[:])
	for i, want := range []int{http.StatusOK, http.StatusForbidden} {
		r := httptest.NewRequest(http.MethodPost, full, bytes.NewReader(b))
		r.Header.Set(cluster.AssertionHeader, jws)
		w := httptest.NewRecorder()
		mux.mux.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("use %d of one assertion: %d %s", i+1, w.Code, w.Body)
		}
	}
}

func TestOwnersSnapshotOnlyTheirOwnWorkloads(t *testing.T) {
	s, _ := storageWithKeys(t)
	m := &fakeMembership{self: "nas", s: s}
	pv := &fakePriv{reply: map[string]any{san.OpSnapshotCreate: san.SnapshotInfo{Name: "x"}}}
	svc := &Service{M: m, Priv: pv, Peers: &fakePeers{}, Network: netStatus("10.77.0.10", "enp2s0")}
	mux := newFakeMux()
	svc.RegisterPeer(mux)
	mux.caller = *s.Nodes["c2"]
	if w := post(t, mux, "storage/snapshot", snapReq{Workload: web, Name: "x"}, nil, cluster.Principal{}); w.Code != http.StatusForbidden {
		t.Fatalf("c2 snapshotted c1's VM: %d %s", w.Code, w.Body)
	}
	mux.caller = *s.Nodes["c1"]
	if w := post(t, mux, "storage/snapshot", snapReq{Workload: web, Name: "x"}, nil, cluster.Principal{}); w.Code != http.StatusOK {
		t.Fatalf("the owner's snapshot: %d %s", w.Code, w.Body)
	}
	if w := post(t, mux, "storage/snapshot", snapReq{Workload: web, Name: "y"}, nil, cluster.Principal{}); w.Code != http.StatusForbidden {
		t.Fatalf("a second owner snapshot within a minute: %d %s", w.Code, w.Body)
	}
}

func TestCallStorageSignsForPeople(t *testing.T) {
	s, ids := storageWithKeys(t)
	s.Nodes["nas"].PublicKey = nil
	m := &fakeMembership{self: "c1", s: s}
	var got *http.Request
	var body []byte
	peers := &recordPeers{do: func(r *http.Request) (*http.Response, error) {
		got = r
		body, _ = io.ReadAll(r.Body)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
	}}
	svc := &Service{M: m, Peers: peers, Signer: func() Signer { return signer{id: ids["c1"], node: "c1"} }}
	if err := svc.Rollback(context.Background(), web, "s1", "s1", cluster.Actor{Kind: "local", Name: "alice", Via: "c1"}); err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Header.Get(cluster.AssertionHeader) == "" {
		t.Fatal("a person's request went unsigned")
	}
	a, err := cluster.VerifyAssertion(got.Header.Get(cluster.AssertionHeader), cluster.AssertionCheck{Issuer: "c1", IssuerKey: ids["c1"].PublicKey,
		Audience: "nas", Request: cluster.RequestHash(http.MethodPost, got.URL.Path, got.URL.RawQuery, body), Now: time.Now(), Nonces: &cluster.NonceCache{}})
	if err != nil || a.Subject.Name != "alice" || !a.Subject.Admin {
		t.Fatalf("assertion %+v: %v", a, err)
	}
	// HardyOS's own requests are plain node calls.
	if err := svc.callStorage(context.Background(), "nas", "storage/health", struct{}{}, nil, systemActor("c1")); err != nil {
		t.Fatal(err)
	}
	if len(peers.calls) != 1 {
		t.Fatalf("calls %v", peers.calls)
	}
}

type recordPeers struct {
	calls []string
	do    func(*http.Request) (*http.Response, error)
}

func (p *recordPeers) Call(ctx context.Context, node cluster.NodeID, method, path string, in, out any) error {
	p.calls = append(p.calls, path)
	return nil
}
func (p *recordPeers) Do(ctx context.Context, node cluster.NodeID, r *http.Request) (*http.Response, error) {
	return p.do(r)
}

func TestRejoinStatementGoesToRootWithTheUnfence(t *testing.T) {
	s, ids := storageWithKeys(t)
	s.Nodes["c1"].State, s.Nodes["c1"].BootID = cluster.NodeRejoining, "boot2"
	s.Fences["c1"] = &cluster.Fence{Node: "c1", Epoch: 3, Confirmed: true}
	// The compute side signs and sends its statement.
	mc := &fakeMembership{self: "c1", s: s}
	peers := &capturePeers{}
	compute := &Service{M: mc, Priv: &fakePriv{}, Peers: peers, Signer: func() Signer { return signer{id: ids["c1"], node: "c1"} }}
	if err := compute.sendRejoin(context.Background(), *s.Nodes["c1"], s); err != nil {
		t.Fatal(err)
	}
	stmt, ok := peers.sent["storage/rejoin"].(san.RejoinStatement)
	if !ok || stmt.Epoch != 3 || stmt.Node != "c1" || stmt.Verify(ids["c1"].PublicKey) != nil {
		t.Fatalf("statement %+v", peers.sent)
	}
	// The storage node takes it from c1 only, and passes it to root.
	ms := &fakeMembership{self: "nas", s: s}
	pv := &fakePriv{}
	storage := &Service{M: ms, Priv: pv}
	mux := newFakeMux()
	storage.RegisterPeer(mux)
	if !slices.Contains(mux.fenced, peerPattern("rejoin")) {
		t.Fatal("a fenced node can't send its rejoin")
	}
	mux.caller = *s.Nodes["c2"]
	if w := post(t, mux, "storage/rejoin", stmt, nil, cluster.Principal{}); w.Code != http.StatusForbidden {
		t.Fatalf("c2 sent c1's statement: %d", w.Code)
	}
	mux.caller = *s.Nodes["c1"]
	if w := post(t, mux, "storage/rejoin", stmt, nil, cluster.Principal{}); w.Code != http.StatusOK {
		t.Fatalf("c1's statement: %d %s", w.Code, w.Body)
	}
	if err := storage.UnfenceNode(context.Background(), "c1", 3); err != nil {
		t.Fatal(err)
	}
	ua := pv.calls[len(pv.calls)-1].args.(san.UnfenceArgs)
	if ua.Statement == nil || ua.Statement.Verify(ids["c1"].PublicKey) != nil {
		t.Fatalf("unfence args %+v", ua)
	}
}

type capturePeers struct{ sent map[string]any }

func (p *capturePeers) Call(ctx context.Context, node cluster.NodeID, method, path string, in, out any) error {
	if p.sent == nil {
		p.sent = map[string]any{}
	}
	p.sent[path] = in
	return nil
}
func (p *capturePeers) Do(context.Context, cluster.NodeID, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestBuildDesiredUsesOnlySoundStorageAddresses(t *testing.T) {
	s, _ := storageWithKeys(t)
	s.Nodes["c2"].Addresses.Storage = addr("10.77.0.10")                                                                                                     // the storage node's
	s.Nodes["c4"] = &cluster.Node{ID: "c4", Role: cluster.RoleCompute, State: cluster.NodeActive, Addresses: cluster.Addresses{Storage: addr("10.88.0.4")}}  // outside
	s.Nodes["c5"] = &cluster.Node{ID: "c5", Role: cluster.RoleCompute, State: cluster.NodeActive, Addresses: cluster.Addresses{Storage: addr("10.77.0.21")}} // c1's
	p := BuildDesired(s, "nas")
	for _, n := range []cluster.NodeID{"c1", "c2", "c4", "c5"} {
		if _, ok := p.Addresses[n]; ok {
			t.Errorf("%s's storage address %s was used", n, p.Addresses[n])
		}
	}
	if len(p.Keys["c1"]) == 0 || p.Subnet != s.StorageSubnet {
		t.Fatalf("keys %v subnet %s", p.Keys, p.Subnet)
	}
}

func TestLANStorageNetworkDropsOwnerExports(t *testing.T) {
	m := &fakeMembership{self: "nas", s: testSnapshot()}
	m.s.Nodes["c3"].State = cluster.NodeActive
	delete(m.s.Fences, "c3")
	pv := &fakePriv{}
	svc := &Service{M: m, Priv: pv, Network: netStatus("10.77.0.10", "eno1"), Store: lanStore(t)}
	err := NewAgent(svc).Reconcile(context.Background())
	if err == nil || !strings.Contains(err.Error(), "the LAN itself") {
		t.Fatalf("no problem reported: %v", err)
	}
	for _, c := range pv.calls {
		if a, ok := c.args.(san.NFSApplyArgs); ok {
			for _, e := range a.Exports {
				if e.Kind != nfs.KindShare {
					t.Fatalf("owner export on the LAN: %+v", e)
				}
			}
			if a.Index != m.s.Index {
				t.Fatalf("exports without the index: %+v", a)
			}
		}
	}
	if slices.Contains(m.proposed, cluster.CmdStorageApplied) {
		t.Fatal("grants acknowledged whose data isn't exported")
	}
}

func TestMigrationHookResolvesTheSource(t *testing.T) {
	m := &fakeMembership{self: "c2", s: testSnapshot()}
	pv := &fakePriv{}
	svc := &Service{M: m, Priv: pv}
	if err := svc.AllowMigration(context.Background(), "c1", 49160, 90*time.Second); err != nil {
		t.Fatal(err)
	}
	a := pv.calls[0].args.(san.MigrationArgs)
	if a.Source != addr("10.77.0.21") || a.Port != 49160 || a.Seconds != 90 || a.Revoke {
		t.Fatalf("args %+v", a)
	}
	if err := svc.RevokeMigration(context.Background(), "c1"); err != nil || !pv.calls[1].args.(san.MigrationArgs).Revoke {
		t.Fatalf("revoke: %v", err)
	}
	if err := svc.AllowMigration(context.Background(), "nas", 0, 0); err == nil {
		t.Fatal("the storage node isn't a migration source")
	}
}

func TestWritersOnlyForTheHolder(t *testing.T) {
	s := testSnapshot()
	m := &fakeMembership{self: "nas", s: s}
	name := san.BackstoreName(web, "disk0")
	pv := &fakePriv{reply: map[string]any{san.OpStatus: san.Status{Holders: map[string]*san.Holders{name: {Nodes: []cluster.NodeID{"c1"}, Prev: []cluster.NodeID{"c2"}, Seq: 4}}}}}
	svc := &Service{M: m, Priv: pv}
	if _, err := svc.writers(context.Background(), "c2", web); err == nil {
		t.Fatal("a node the volume isn't granted to asked")
	}
	w, err := svc.writers(context.Background(), "c1", web)
	wwn := s.Placements[web].Storage.Volumes[0].WWN
	if err != nil || w[wwn] != (sanclient.WriterInfo{Known: true, OthersWrote: true, Seq: 4}) {
		t.Fatalf("%v %+v", err, w)
	}
}

// lanStore is a store whose saved storage network is the LAN itself.
func lanStore(t *testing.T) *Store {
	t.Helper()
	st := newTestStore(t)
	if err := st.SaveStorageNet(context.Background(), network.StoragePlan{Kind: network.StorageShared, Interface: "eno1", Address: "192.168.1.5/24"}); err != nil {
		t.Fatal(err)
	}
	return st
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "hardyd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Store{DB: db}
}

var _ = netip.Addr{}
