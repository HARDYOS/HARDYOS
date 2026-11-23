package storagesvc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/sanclient"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
)

const cid = cluster.ClusterID("abcdefghijklmnopqrstuvwxyz")

var (
	web   = cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}
	notes = cluster.WorkloadRef{Kind: cluster.KindApp, ID: "notes"}
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func testSnapshot() *cluster.Snapshot {
	node := func(id cluster.NodeID, role cluster.Role, st cluster.NodeState, a string) *cluster.Node {
		return &cluster.Node{ID: id, Role: role, State: st, Addresses: cluster.Addresses{Storage: addr(a)}}
	}
	return &cluster.Snapshot{
		Cluster: cid, Index: 10, StorageSubnet: netip.MustParsePrefix("10.77.0.0/24"),
		Nodes: map[cluster.NodeID]*cluster.Node{
			"nas": node("nas", cluster.RoleStorage, cluster.NodeActive, "10.77.0.10"),
			"c1":  node("c1", cluster.RoleCompute, cluster.NodeActive, "10.77.0.21"),
			"c2":  node("c2", cluster.RoleCompute, cluster.NodeActive, "10.77.0.22"),
			"c3":  node("c3", cluster.RoleCompute, cluster.NodeDead, "10.77.0.23"),
			"w":   {ID: "w", Role: cluster.RoleWitness, State: cluster.NodeActive},
		},
		Placements: map[cluster.WorkloadRef]*cluster.Placement{
			web: {Workload: web, Owner: "c1", Generation: 5, State: cluster.PlacementRunning, Requested: cluster.RequestRunning,
				Storage: cluster.WorkloadStorage{Pool: "tank",
					Volumes: []cluster.Volume{{Dataset: "tank/vms/web/disk0", Disk: "disk0", WWN: san.WWN(san.Serial(cid, "1"))}},
					Exports: []cluster.Export{{Kind: cluster.ExportVMState, Dataset: "tank/vms/web", Path: "/mnt/tank/vms/web", FSID: "11"}}}},
			notes: {Workload: notes, Owner: "c3", Generation: 2, State: cluster.PlacementRecovering, Requested: cluster.RequestRunning,
				Storage: cluster.WorkloadStorage{Pool: "tank", Mode: cluster.StorageNFS,
					Exports: []cluster.Export{{Kind: cluster.ExportAppData, Dataset: "tank/apps/notes", Path: "/mnt/tank/apps/notes", FSID: "12"}}}},
		},
		Grants: map[cluster.WorkloadRef]*cluster.Grant{
			web:   {Workload: web, Nodes: []cluster.NodeID{"c1"}, Mode: cluster.GrantExclusive, Generation: 5},
			notes: {Workload: notes, Nodes: []cluster.NodeID{"c3"}, Mode: cluster.GrantExclusive, Generation: 2},
		},
		Fences: map[cluster.NodeID]*cluster.Fence{"c3": {Node: "c3", Epoch: 4, Reason: "dead"}},
		ClusterShares: map[string]*cluster.ClusterShare{"media": {ID: "media", Pool: "tank", Dataset: "tank/shares/media",
			Path: "/mnt/tank/shares/media", MountPath: "/mnt/hc/tank/shares/media", FSID: "13"}},
	}
}

func TestBuildDesired(t *testing.T) {
	s := testSnapshot()
	p := BuildDesired(s, "nas")
	if err := p.SAN.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(p.SAN.Portals) != 1 || p.SAN.Portals[0] != netip.MustParseAddrPort("10.77.0.10:3260") {
		t.Fatalf("portals %v", p.SAN.Portals)
	}
	byNode := map[cluster.NodeID]san.Target{}
	for _, tg := range p.SAN.Targets {
		byNode[tg.Node] = tg
	}
	if len(byNode) != 3 {
		t.Fatalf("targets for compute nodes only: %+v", p.SAN.Targets)
	}
	if !slices.Equal(byNode["c1"].LUNs, []string{san.BackstoreName(web, "disk0")}) || len(byNode["c2"].LUNs) != 0 {
		t.Fatalf("mappings %+v", byNode)
	}
	if byNode["c3"].Enabled || len(byNode["c3"].LUNs) != 0 || byNode["c3"].FenceEpoch != 4 {
		t.Fatalf("the dead node kept access: %+v", byNode["c3"])
	}
	if len(p.Fences) != 1 || p.Fences[0].Node != "c3" {
		t.Fatalf("fences %+v", p.Fences)
	}
	// Exports: the VM's state to c1 only; nothing for the dead owner's app;
	// the share to active compute nodes only.
	ex := map[string][]netip.Addr{}
	for _, e := range p.Exports {
		ex[e.Dataset] = e.Clients
	}
	if !slices.Equal(ex["tank/vms/web"], []netip.Addr{addr("10.77.0.21")}) || ex["tank/apps/notes"] != nil {
		t.Fatalf("exports %v", ex)
	}
	if !slices.Equal(ex["tank/shares/media"], []netip.Addr{addr("10.77.0.21"), addr("10.77.0.22")}) {
		t.Fatalf("share clients %v", ex["tank/shares/media"])
	}
	if !slices.Contains(p.Fenced, addr("10.77.0.23")) || slices.Contains(p.Members, addr("10.77.0.23")) {
		t.Fatalf("firewall members %v fenced %v", p.Members, p.Fenced)
	}
	if len(p.Acks) != 1 || p.Acks[0].Workload != web {
		t.Fatalf("acks %+v", p.Acks)
	}
	// An exclusive grant naming two nodes maps only one; a migration grant
	// maps both.
	s.Grants[web].Nodes = []cluster.NodeID{"c1", "c2"}
	p = BuildDesired(s, "nas")
	if n := len(p.SAN.Mapped(san.BackstoreName(web, "disk0"))); n != 1 {
		t.Fatalf("exclusive grant mapped to %d nodes", n)
	}
	s.Grants[web].Mode = cluster.GrantMigration
	p = BuildDesired(s, "nas")
	if err := p.SAN.Validate(); err != nil {
		t.Fatal(err)
	}
	if n := len(p.SAN.Mapped(san.BackstoreName(web, "disk0"))); n != 2 {
		t.Fatalf("migration grant mapped to %d nodes", n)
	}
	// A placement whose storage names another workload's dataset is
	// skipped entirely.
	s.Placements[web].Storage.Volumes[0].Dataset = "tank/vms/db/disk0"
	p = BuildDesired(s, "nas")
	if len(p.SAN.Backstores) != 0 {
		t.Fatalf("mapped a foreign dataset: %+v", p.SAN.Backstores)
	}
	// Hold.
	s = testSnapshot()
	p = BuildDesired(s, "nas")
	p.Hold(web)
	if len(p.SAN.Backstores) != 0 || len(p.Acks) != 0 || slices.ContainsFunc(p.Exports, func(e nfs.ClusterExport) bool { return e.Dataset == "tank/vms/web" }) {
		t.Fatalf("hold left %+v", p)
	}
}

func TestCheckGrant(t *testing.T) {
	s := testSnapshot()
	g := cluster.Grant{Workload: web, Generation: 5}
	if err := CheckGrant(s, "c1", g); !errors.Is(err, cluster.ErrStorageUnavailable) {
		t.Fatalf("unapplied grant: %v", err)
	}
	s.Grants[web].Applied = true
	if err := CheckGrant(s, "c1", g); err != nil {
		t.Fatal(err)
	}
	if err := CheckGrant(s, "c2", g); !errors.Is(err, cluster.ErrStorageUnavailable) {
		t.Fatalf("another node: %v", err)
	}
	if err := CheckGrant(s, "c1", cluster.Grant{Workload: web, Generation: 4}); !errors.Is(err, cluster.ErrStaleGeneration) {
		t.Fatalf("stale: %v", err)
	}
	s.Grants[notes].Applied = true
	if err := CheckGrant(s, "c3", cluster.Grant{Workload: notes, Generation: 2}); !errors.Is(err, cluster.ErrFenced) {
		t.Fatalf("fenced node: %v", err)
	}
}

// ---- fakes -----------------------------------------------------------------------

type fakeState struct{ s *cluster.Snapshot }

func (f fakeState) Snapshot() *cluster.Snapshot {
	b, _ := json.Marshal(f.s)
	var c cluster.Snapshot
	_ = json.Unmarshal(b, &c)
	c.Placements, c.Grants = map[cluster.WorkloadRef]*cluster.Placement{}, map[cluster.WorkloadRef]*cluster.Grant{}
	for k, v := range f.s.Placements {
		x := *v
		c.Placements[k] = &x
	}
	for k, v := range f.s.Grants {
		x := *v
		x.Nodes = slices.Clone(v.Nodes)
		c.Grants[k] = &x
	}
	return &c
}
func (f fakeState) Node(id cluster.NodeID) (*cluster.Node, bool) {
	n, ok := f.s.Nodes[id]
	return n, ok
}
func (f fakeState) Placement(w cluster.WorkloadRef) (*cluster.Placement, bool) {
	p, ok := f.s.Placements[w]
	return p, ok
}
func (f fakeState) Grant(w cluster.WorkloadRef) (*cluster.Grant, bool) {
	g, ok := f.s.Grants[w]
	return g, ok
}
func (f fakeState) Index() uint64 { return f.s.Index }

// fakeMembership applies proposals with the real storage applier.
type fakeMembership struct {
	mu       sync.Mutex
	self     cluster.NodeID
	s        *cluster.Snapshot
	proposed []cluster.CommandType
}

func (m *fakeMembership) Self() (cluster.Node, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return *m.s.Nodes[m.self], nil
}
func (m *fakeMembership) State() cluster.State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fakeState{fakeState{m.s}.Snapshot()}
}
func (m *fakeMembership) Leader() (cluster.NodeID, bool)                   { return "nas", true }
func (m *fakeMembership) Quorate() (bool, time.Time)                       { return true, time.Now().Add(time.Minute) }
func (m *fakeMembership) Health(context.Context) ([]cluster.Health, error) { return nil, nil }
func (m *fakeMembership) Propose(ctx context.Context, t cluster.CommandType, body any, a cluster.Actor) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, _ := json.Marshal(body)
	m.proposed = append(m.proposed, t)
	if err := (state.Storage{}).Apply(m.s, cluster.Command{Type: t, Body: b, Time: time.Now()}); err != nil {
		return 0, err
	}
	m.s.Index++
	return m.s.Index, nil
}
func (m *fakeMembership) WaitApplied(context.Context, uint64) error { return nil }
func (m *fakeMembership) Subscribe(context.Context) <-chan cluster.Event {
	return make(chan cluster.Event)
}
func (m *fakeMembership) Register(cluster.Applier) {}

type privCall struct {
	op   string
	args any
}

type fakePriv struct {
	mu    sync.Mutex
	calls []privCall
	fail  map[string]error
	reply map[string]any
}

func (p *fakePriv) Call(ctx context.Context, op string, args, out any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, privCall{op, args})
	if err := p.fail[op]; err != nil {
		return err
	}
	if r, ok := p.reply[op]; ok && out != nil {
		b, _ := json.Marshal(r)
		return json.Unmarshal(b, out)
	}
	return nil
}

func (p *fakePriv) ops() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for _, c := range p.calls {
		out = append(out, c.op)
	}
	return out
}

func netStatus(a string, iface string) func(context.Context) (*network.Status, error) {
	return func(context.Context) (*network.Status, error) {
		return &network.Status{Live: []network.LiveInterface{{Name: iface, Kind: "port", Addresses: []string{a + "/24"}}}}, nil
	}
}

func TestAgentFencesFirstThenAcks(t *testing.T) {
	m := &fakeMembership{self: "nas", s: testSnapshot()}
	pv := &fakePriv{}
	svc := &Service{M: m, Priv: pv, Network: netStatus("10.77.0.10", "enp2s0")}
	a := NewAgent(svc)
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	ops := pv.ops()
	if len(ops) < 4 || ops[0] != san.OpFence || ops[1] != san.OpApply || ops[2] != san.OpNFSClusterSet || ops[3] != san.OpFirewallApply {
		t.Fatalf("order %v", ops)
	}
	if fa := pv.calls[0].args.(san.FenceArgs); fa.Node != "c3" || fa.Epoch != 4 || fa.Confirm != "c3" {
		t.Fatalf("fence args %+v", fa)
	}
	if !slices.Equal(m.proposed, []cluster.CommandType{cluster.CmdStorageFenced, cluster.CmdStorageApplied}) {
		t.Fatalf("proposed %v", m.proposed)
	}
	if !m.s.Fences["c3"].Confirmed || m.s.Nodes["c3"].State != cluster.NodeFenced || !m.s.Grants[web].Applied {
		t.Fatal("state after the pass")
	}
	// A fence that fails is never confirmed, and nothing is acknowledged
	// from a failed apply.
	m2 := &fakeMembership{self: "nas", s: testSnapshot()}
	pv2 := &fakePriv{fail: map[string]error{san.OpFence: errors.New("configfs busy"), san.OpApply: errors.New("boom")}}
	svc2 := &Service{M: m2, Priv: pv2, Network: netStatus("10.77.0.10", "enp2s0")}
	if err := NewAgent(svc2).Reconcile(context.Background()); err == nil {
		t.Fatal("errors not reported")
	}
	if len(m2.proposed) != 0 {
		t.Fatalf("proposed %v after failures", m2.proposed)
	}
}

func TestAttachChecksGrantAndUsesCommittedStorage(t *testing.T) {
	m := &fakeMembership{self: "c1", s: testSnapshot()}
	sec, _ := san.NewSecrets("c1")
	pv := &fakePriv{reply: map[string]any{sanclient.OpAttach: sanclient.Record{Attachment: cluster.Attachment{Workload: web, Generation: 5}}}}
	peers := &fakePeers{answers: map[string]any{"storage/chap": sec}}
	svc := &Service{M: m, Priv: pv, Peers: peers, Network: netStatus("10.77.0.21", "enp2s0")}
	ctx := context.Background()
	if _, err := svc.Attach(ctx, cluster.WorkloadStorage{}, cluster.Grant{Workload: web, Generation: 5}); !errors.Is(err, cluster.ErrStorageUnavailable) {
		t.Fatalf("attached before the storage node applied the grant: %v", err)
	}
	m.s.Grants[web].Applied = true
	// The caller's storage is ignored: what the state has is attached.
	evil := cluster.WorkloadStorage{Pool: "tank", Volumes: []cluster.Volume{{Dataset: "tank/vms/db/disk0", Disk: "disk0"}}}
	if _, err := svc.Attach(ctx, evil, cluster.Grant{Workload: web, Generation: 5}); err != nil {
		t.Fatal(err)
	}
	var att sanclient.AttachArgs
	var login sanclient.LoginArgs
	for _, c := range pv.calls {
		switch c.op {
		case sanclient.OpAttach:
			att = c.args.(sanclient.AttachArgs)
		case sanclient.OpLogin:
			login = c.args.(sanclient.LoginArgs)
		}
	}
	if att.Storage.Volumes[0].Dataset != "tank/vms/web/disk0" || att.Server != addr("10.77.0.10") || att.Interface != "enp2s0" {
		t.Fatalf("attach args %+v", att)
	}
	if login.CHAP.Password != sec.Password || login.Node != "c1" || login.Portals[0] != netip.MustParseAddrPort("10.77.0.10:3260") {
		t.Fatalf("login %+v", login)
	}
	if !slices.Contains(pv.ops(), sanclient.OpRescan) {
		t.Fatal("no rescan after login")
	}
}

type fakePeers struct {
	answers map[string]any
	calls   []string
}

func (f *fakePeers) Call(ctx context.Context, node cluster.NodeID, method, path string, in, out any) error {
	f.calls = append(f.calls, string(node)+" "+path)
	if a, ok := f.answers[path]; ok && out != nil {
		b, _ := json.Marshal(a)
		return json.Unmarshal(b, out)
	}
	return nil
}
func (f *fakePeers) Do(ctx context.Context, node cluster.NodeID, r *http.Request) (*http.Response, error) {
	return nil, errors.New("not here")
}

func TestSwitchModeHoldsAndCommits(t *testing.T) {
	s := testSnapshot()
	s.Nodes["c3"].State = cluster.NodeActive
	delete(s.Fences, "c3")
	p := s.Placements[notes]
	p.State, p.Requested = cluster.PlacementStopped, cluster.RequestStopped
	m := &fakeMembership{self: "nas", s: s}
	wwn := san.WWN(san.Serial(cid, "9"))
	pv := &fakePriv{reply: map[string]any{
		san.OpVolumeCreate: san.VolumeInfo{Dataset: "tank/apps/notes/block", GUID: "9", WWN: wwn, SizeGB: 64},
		san.OpAppMigrate:   san.MigrateResult{To: cluster.StorageBlock, Snapshot: "hc-before-block-x"},
	}}
	peers := &fakePeers{}
	svc := &Service{M: m, Priv: pv, Peers: peers, Network: netStatus("10.77.0.10", "enp2s0")}
	NewAgent(svc)
	ctx := context.Background()
	if _, err := svc.SwitchAppMode(ctx, ModeRequest{App: "notes", To: cluster.StorageBlock, Confirm: "wrong"}); err == nil {
		t.Fatal("no confirmation needed")
	}
	res, err := svc.SwitchAppMode(ctx, ModeRequest{App: "notes", To: cluster.StorageBlock, Confirm: "notes"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != cluster.StorageBlock || m.s.Placements[notes].Storage.Mode != cluster.StorageBlock || m.s.Placements[notes].Generation != 3 {
		t.Fatalf("result %+v placement %+v", res, m.s.Placements[notes])
	}
	if !slices.Contains(peers.calls, "c3 storage/detach") {
		t.Fatalf("the owner wasn't asked to detach: %v", peers.calls)
	}
	// While migrating, an apply without the app's export happened before the copy.
	ops := pv.ops()
	migrate := slices.Index(ops, san.OpAppMigrate)
	held := false
	for i, c := range pv.calls[:migrate] {
		if c.op == san.OpNFSClusterSet {
			ex := c.args.(san.NFSApplyArgs).Exports
			held = !slices.ContainsFunc(ex, func(e nfs.ClusterExport) bool { return strings.HasSuffix(e.Dataset, "/notes") })
			_ = i
		}
	}
	if !held {
		t.Fatalf("the app's data was still exported during the move: %v", ops)
	}
	running := testSnapshot()
	m.s = running
	if _, err := svc.SwitchAppMode(ctx, ModeRequest{App: "web", To: cluster.StorageBlock, Confirm: "web"}); err == nil {
		t.Fatal("a VM's mode switched")
	}
}
