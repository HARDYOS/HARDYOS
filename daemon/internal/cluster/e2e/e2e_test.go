// Package e2e_test runs parts A, B and C of the cluster together in one
// process (docs/plans/cluster.md section 10, "in-process cluster"): real
// cluster cores (Raft, the signed log, mutual TLS on an in-memory network,
// heartbeats and quorum leases) behind part A's membership service and its
// live view, part B's storage service and agent with its real root code
// for LIO and NFS on the storage node (on a fake configfs and a fake zfs),
// and part C's placement, reconciler, fence agent, mover and HA coordinator,
// over real hardyd-priv sockets whose compute-side operations are fakes.
//
// One storage node, three compute nodes and the witness: join, storage
// grants, a VM and an app placed and started, an offline move, then a
// compute node cut off from everything: it fences itself, the leader
// declares it dead, the storage node revokes its access and confirms in
// the log, and only then is its HA VM restarted elsewhere. Never two
// runners, never a LUN in two targets, never a start while another node
// can still reach the disk.
package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
	"github.com/hardyos/hardyos/daemon/internal/cluster/member"
	"github.com/hardyos/hardyos/daemon/internal/cluster/moves"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/cluster/storagesvc"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

var admin = cluster.Actor{Kind: "local", Name: "admin"}

// testTimings are the shortest the safety bounds allow (decision 353):
// dead after 20 s, quorum lease 5 s, watchdog 5 s.
var testTimings = cluster.Timings{Heartbeat: 500 * time.Millisecond, Suspect: 2 * time.Second, QuorumLease: 5 * time.Second,
	SelfStop: 2 * time.Second, Watchdog: 5 * time.Second, Dead: 20 * time.Second, StorageIsolated: 5 * time.Second,
	LANIsolated: 30 * time.Second, FenceAck: 10 * time.Second}

var fastRaft = cluster.RaftTimings{Heartbeat: 300 * time.Millisecond, Election: 300 * time.Millisecond, LeaderLease: 150 * time.Millisecond,
	Commit: 5 * time.Millisecond, SnapshotThreshold: 256, TrailingLogs: 512, SnapshotInterval: 5 * time.Second}

// fastPaths probe often but tolerate a loaded test machine: a path
// switch drops the connections on the old path, in-flight calls with them.
var fastPaths = cluster.PathTimings{Interval: 250 * time.Millisecond, Timeout: 2 * time.Second, DownAfter: 3, UpAfter: 10}

func addr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	return netip.MustParseAddr(s)
}

// hnode is one HardyOS server: hardyd's cluster parts on a priv socket.
type hnode struct {
	id      cluster.NodeID
	role    cluster.Role
	addrs   cluster.Addresses
	svc     *member.Service
	live    *member.Live
	storage *storagesvc.Service
	ha      *ha.Service
	root    *computeRoot // compute nodes
	cancel  context.CancelFunc
	// part C's loops run under their own context (a hardyd restart).
	haCancel context.CancelFunc
	haDone   chan struct{}
	pc       *priv.Client
	// boot is this server's boot id as part C sees it.
	bootMu sync.Mutex
	boot   string
}

func (n *hnode) bootID() string {
	n.bootMu.Lock()
	defer n.bootMu.Unlock()
	return n.boot
}

// reboot gives the server a new boot id (what a reset does, as far as
// rejoining is concerned).
func (n *hnode) reboot() {
	n.bootMu.Lock()
	n.boot += "+"
	n.bootMu.Unlock()
}

type harness struct {
	t     *testing.T
	w     *world
	net   *clustertest.Net
	log   *slog.Logger
	nodes map[cluster.NodeID]*hnode
	wit   *cluster.Core
	witA  cluster.Addresses
	// storageLive is the storage node's view (read by the LIO watcher).
	storageLive atomic.Pointer[member.Live]
}

func newHarness(t *testing.T) *harness {
	lvl := slog.LevelError + 4
	if os.Getenv("CLUSTER_DEBUG") != "" {
		lvl = slog.LevelDebug
	}
	h := &harness{t: t, w: newWorld(t), net: clustertest.NewNet(), nodes: map[cluster.NodeID]*hnode{},
		log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))}
	h.w.cid = func() cluster.ClusterID {
		if l := h.storageLive.Load(); l != nil {
			return l.State().Snapshot().Cluster
		}
		return ""
	}
	h.w.snap = func() *cluster.Snapshot {
		if l := h.storageLive.Load(); l != nil {
			return l.State().Snapshot()
		}
		return nil
	}
	return h
}

func (h *harness) add(id string, role cluster.Role, lan, stor, nb string) *hnode {
	t := h.t
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	n := &hnode{id: cluster.NodeID(id), role: role, cancel: cancel, boot: "boot-" + id,
		addrs: cluster.Addresses{LAN: addr(lan), Storage: addr(stor), NetBird: addr(nb)}}
	h.nodes[n.id] = n
	h.w.addrOf[n.addrs.Storage] = n.id
	log := h.log.With("node", id)

	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "hardyd.db"))
	if err != nil {
		t.Fatal(err)
	}
	var ps *priv.Server
	if role == cluster.RoleStorage {
		ps = storageRoot(t, ctx, h.w)
	} else {
		ps, n.root = computeServer(h.w, n.id)
	}
	ps.Logger = quiet
	pc := priv.NewClient(servePriv(t, ctx, ps))
	n.pc = pc

	// Part A: the membership service and its live view.
	n.svc = &member.Service{DB: db, Version: "1.0.0", Dir: t.TempDir(), Log: log,
		Net:      h.net.Host(n.addrs.LAN, n.addrs.Storage, n.addrs.NetBird),
		Addrs:    func(netip.Prefix) cluster.Addresses { return n.addrs },
		Hostname: func() string { return id },
		Raft:     fastRaft, Paths: fastPaths}
	n.live = n.svc.Live()
	if role == cluster.RoleStorage {
		h.storageLive.Store(n.live)
	}

	// Part B: storage service, attacher and agent.
	storageIf := network.Status{Live: []network.LiveInterface{{Name: "enp2s0", Kind: "port", Up: true, Carrier: true, SpeedMbps: 10000,
		Addresses: []string{n.addrs.Storage.String() + "/24"}}}}
	n.storage = &storagesvc.Service{M: n.live, Peers: n.live, Priv: pc, Log: log, Store: &storagesvc.Store{DB: db},
		Network: func(context.Context) (*network.Status, error) { return &storageIf, nil }}
	agent := storagesvc.NewAgent(n.storage)
	agent.Interval = time.Second
	n.storage.RegisterPeer(n.live)

	// Part C: placement, reconciler, fence agent, mover, coordinator.
	n.ha = &ha.Service{Priv: pc, DB: db, Log: log, BootID: n.bootID, Parts: ha.Parts{Membership: n.live, Peers: n.live, Mux: n.live,
		Attacher: n.storage, Stream: moves.ALPNStream{Dial: n.live.DialMigrate}}}
	n.ha.Init()
	n.live.SetMigrate(n.ha.Node.ServeMigrateConn)
	n.ha.Announcer.Interval = time.Second
	n.ha.Reconciler.Log = log
	health := &ha.HealthReporter{Cluster: n.live, Storage: n.storage.Healthy, Service: n.ha, Interval: 250 * time.Millisecond}
	n.svc.Health = health.Get

	if err := n.svc.Init(ctx); err != nil {
		t.Fatal(err)
	}
	go n.svc.Run(ctx)
	go agent.Run(ctx)
	hctx, hcancel := context.WithCancel(ctx)
	n.haCancel, n.haDone = hcancel, make(chan struct{})
	go func() { n.ha.Start(hctx); close(n.haDone) }()
	go health.Run(ctx)
	t.Cleanup(func() {
		cancel()
		if c := n.svc.Core(); c != nil {
			c.Stop()
		}
		db.Close()
	})
	return n
}

func (h *harness) addWitness(nb string) {
	t := h.t
	ident, err := cluster.NewIdentity("witness")
	if err != nil {
		t.Fatal(err)
	}
	h.witA = cluster.Addresses{NetBird: addr(nb)}
	core, err := cluster.New(context.Background(), cluster.Config{
		Identity: ident, Store: &clustertest.MemStore{}, Machine: state.New(), Net: h.net.Host(h.witA.NetBird),
		Dir: t.TempDir(), Version: "1.0.0", Features: state.Features(), BootID: "boot-witness",
		Addresses: func() cluster.Addresses { return h.witA }, Raft: fastRaft, Paths: fastPaths, Log: h.log.With("node", "witness"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(core.Stop)
	h.wit = core
	nas := h.nodes["nas"]
	ctx := tctx(t, 30*time.Second)
	off, err := nas.svc.Core().OpenJoinCode(ctx, cluster.RoleWitness, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.Join(ctx, cluster.JoinParams{Address: nas.addrs.NetBird.String(), Code: off.Code, Node: "witness", Name: "witness", Role: cluster.RoleWitness}); err != nil {
		t.Fatalf("witness join: %v", err)
	}
	if err := core.FinishJoin(ctx, state.WitnessHelloBody{Addresses: h.witA, Version: "1.0.0", Features: state.Features()}); err != nil {
		t.Fatalf("witness hello: %v", err)
	}
}

func tctx(t *testing.T, d time.Duration) context.Context {
	c, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return c
}

func (h *harness) eventually(what string, d time.Duration, f func() error) {
	h.t.Helper()
	deadline := time.Now().Add(d)
	var err error
	for time.Now().Before(deadline) {
		if err = f(); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.w.dump()
	h.t.Fatalf("%s: %v", what, err)
}

func (h *harness) snap() *cluster.Snapshot { return h.nodes["nas"].live.State().Snapshot() }

func (h *harness) propose(n *hnode, t cluster.CommandType, body any) {
	h.t.Helper()
	ctx := tctx(h.t, 20*time.Second)
	idx, err := n.live.Propose(ctx, t, body, admin)
	if err != nil {
		h.t.Fatalf("%s from %s: %v", t, n.id, err)
	}
	if err := n.live.WaitApplied(ctx, idx); err != nil {
		h.t.Fatal(err)
	}
}

// cut takes a node off every network (LAN, storage, NetBird).
func (h *harness) cut(n *hnode) {
	mine := []netip.Addr{n.addrs.LAN, n.addrs.Storage, n.addrs.NetBird}
	var others []netip.Addr
	for _, o := range h.nodes {
		if o != n {
			others = append(others, o.addrs.LAN, o.addrs.Storage, o.addrs.NetBird)
		}
	}
	others = append(others, h.witA.NetBird)
	for _, a := range mine {
		h.net.Isolate(a, others...)
	}
}

func placed(s *cluster.Snapshot, w cluster.WorkloadRef) (*cluster.Placement, *cluster.Grant) {
	return s.Placements[w], s.Grants[w]
}

// running checks that w runs on exactly node, under the placement's
// generation, with an applied grant, and that the placement says so.
func (h *harness) running(w cluster.WorkloadRef, node cluster.NodeID) error {
	s := h.snap()
	p, g := placed(s, w)
	if p == nil || g == nil {
		return fmt.Errorf("%s isn't placed", wname(w))
	}
	if p.Owner != node || p.State != cluster.PlacementRunning || !g.Applied || g.Generation != p.Generation {
		return fmt.Errorf("%s: owner %s state %s generation %d grant %+v", wname(w), p.Owner, p.State, p.Generation, *g)
	}
	r := h.w.runners(w)
	if len(r) != 1 {
		return fmt.Errorf("%s runs on %v (want %s at %d)", wname(w), r, node, p.Generation)
	}
	if g, ok := r[node]; !ok || g != p.Generation {
		// A VM migrated live keeps the process it started under an earlier
		// generation; its attachment carries the current one.
		rec, _, attached := h.nodes[node].root.record(w)
		if !ok || !attached || rec.Generation != p.Generation {
			return fmt.Errorf("%s runs on %v (want %s at %d)", wname(w), r, node, p.Generation)
		}
	}
	return nil
}

func TestClusterEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("the end-to-end cluster takes about a minute")
	}
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.w.watchLIO(ctx)
	t.Cleanup(func() {
		if t.Failed() {
			h.w.dump()
		}
	})

	nas := h.add("nas", cluster.RoleStorage, "192.168.1.105", "10.77.0.10", "100.64.0.105")
	c1 := h.add("c1", cluster.RoleCompute, "192.168.1.21", "10.77.0.21", "100.64.0.21")
	c2 := h.add("c2", cluster.RoleCompute, "192.168.1.22", "10.77.0.22", "100.64.0.22")
	c3 := h.add("c3", cluster.RoleCompute, "192.168.1.23", "10.77.0.23", "100.64.0.23")

	// ---- create, join, the witness --------------------------------------------------
	if _, err := nas.svc.Create(tctx(t, 30*time.Second), member.CreateParams{Name: "home", Role: cluster.RoleStorage,
		StorageSubnet: "10.77.0.0/24", Actor: admin}); err != nil {
		t.Fatalf("create: %v", err)
	}
	h.propose(nas, cluster.CmdTimings, testTimings)
	for _, c := range []*hnode{c1, c2, c3} {
		off, err := nas.svc.Core().OpenJoinCode(tctx(t, 30*time.Second), cluster.RoleCompute, "admin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.svc.Join(tctx(t, 60*time.Second), nas.addrs.LAN.String(), off.Code, cluster.RoleCompute); err != nil {
			t.Fatalf("%s joins: %v", c.id, err)
		}
	}
	h.addWitness("100.64.0.9")
	h.eventually("every member active, compute hardware announced, targets made", 30*time.Second, func() error {
		s := h.snap()
		if len(s.Nodes) != 5 {
			return fmt.Errorf("%d members", len(s.Nodes))
		}
		for id, n := range s.Nodes {
			if n.State != cluster.NodeActive {
				return fmt.Errorf("%s is %s", id, n.State)
			}
			if n.Role == cluster.RoleCompute {
				if n.Compute == nil || n.Compute.Watchdog != "hardware" || n.Compute.MemoryMB != 65536 {
					return fmt.Errorf("%s's hardware: %+v", id, n.Compute)
				}
				if ok, why := state.HAEligible(s, id); !ok {
					return fmt.Errorf("%s isn't HA-eligible: %s", id, why)
				}
			}
		}
		if s.Timings != testTimings {
			return fmt.Errorf("timings %+v", s.Timings)
		}
		cur := san.Current(h.w.storageFS, s.Cluster)
		for _, c := range []cluster.NodeID{"c1", "c2", "c3"} {
			if tg, ok := cur[c]; !ok || !tg.Enabled {
				return fmt.Errorf("no enabled target for %s: %+v", c, cur)
			}
		}
		// The leader hears every compute node, quorate with its storage paths.
		hs, err := nas.live.Health(context.Background())
		if err != nil {
			return err
		}
		ready := 0
		for _, x := range hs {
			if s.Nodes[x.Node] != nil && s.Nodes[x.Node].Role == cluster.RoleCompute && x.Quorate && x.StorageOK {
				ready++
			}
		}
		if ready != 3 {
			return fmt.Errorf("health %+v", hs)
		}
		// Every member applied the same log, the witness too.
		idx := h.wit.Machine().Index()
		for _, n := range h.nodes {
			if n.live.State().Index() != idx {
				return fmt.Errorf("%s at %d, the witness at %d", n.id, n.live.State().Index(), idx)
			}
		}
		return nil
	})
	if hl := h.wit.Halted(); hl != nil {
		t.Fatalf("the witness stopped following the log: %v", hl)
	}

	// ---- a VM on c1 and an app on c2, storage provisioned by the storage node ------------
	web := cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}
	notes := cluster.WorkloadRef{Kind: cluster.KindApp, ID: "notes"}
	pctx := tctx(t, 60*time.Second)
	vmStorage, err := c1.storage.ProvisionVM(pctx, cluster.VMStorageRequest{VM: "web", Pool: "tank", Disks: []cluster.DiskRequest{{Name: "disk0", SizeGB: 32}}}, admin)
	if err != nil {
		t.Fatalf("provision the VM's storage through c1: %v", err)
	}
	if len(vmStorage.Volumes) != 1 || vmStorage.Volumes[0].WWN == "" || len(vmStorage.Exports) != 1 {
		t.Fatalf("VM storage %+v", vmStorage)
	}
	uid := state.FreeAppUID(h.snap())
	h.propose(c2, cluster.CmdAppUID, state.AppUIDBody{App: "notes", UID: uid})
	appStorage, err := c2.storage.ProvisionApp(pctx, cluster.AppStorageRequest{App: "notes", Pool: "tank", UID: uid}, admin)
	if err != nil {
		t.Fatalf("provision the app's storage through c2: %v", err)
	}
	if appStorage.Mode != cluster.StorageNFS || len(appStorage.Exports) != 1 {
		t.Fatalf("app storage %+v", appStorage)
	}
	haOn := cluster.HAPolicy{Enabled: true, Priority: 80, MaxRestarts: 3, MaxRelocations: 2}
	h.propose(c1, cluster.CmdWorkloadAdd, state.WorkloadAdd{SpecHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Workload: web, Name: "Web server", Owner: "c1", Requested: cluster.RequestRunning,
		HA: haOn, Storage: *vmStorage})
	h.propose(c2, cluster.CmdWorkloadAdd, state.WorkloadAdd{SpecHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Workload: notes, Name: "Notes", Owner: "c2", Requested: cluster.RequestRunning,
		HA: haOn, Storage: *appStorage})
	h.eventually("the storage node grants them and their owners start them", 30*time.Second, func() error {
		if err := h.running(web, "c1"); err != nil {
			return err
		}
		return h.running(notes, "c2")
	})
	// The grant is real on the storage node: the LUN is in c1's target only,
	// the app's folder is exported to c2 only.
	if r := h.w.reach(*vmStorage, web); len(r) != 1 || r[0] != "c1" {
		t.Fatalf("the VM's storage reaches %v", r)
	}
	if r := h.w.reach(*appStorage, notes); len(r) != 1 || r[0] != "c2" {
		t.Fatalf("the app's storage reaches %v", r)
	}
	h.eventually("the fence agents armed the watchdogs of c1 and c2", 10*time.Second, func() error {
		for _, n := range []*hnode{c1, c2} {
			n.root.mu.Lock()
			armed := n.root.armed
			n.root.mu.Unlock()
			if !armed {
				return fmt.Errorf("%s's watchdog isn't armed", n.id)
			}
		}
		return nil
	})

	// ---- an offline move of the app, c2 -> c3, started on c1 (a third server) ----------
	p, _ := placed(h.snap(), notes)
	gen := p.Generation
	res, err := c1.ha.Mover.Move(tctx(t, 90*time.Second), cluster.MoveRequest{Workload: notes, To: "c3", Mode: cluster.MoveOffline, Generation: gen}, admin)
	if err != nil {
		t.Fatalf("offline move: %v", err)
	}
	if res.From != "c2" || res.To != "c3" || res.Generation <= gen {
		t.Fatalf("move result %+v", res)
	}
	h.eventually("the app runs on c3 only", 30*time.Second, func() error { return h.running(notes, "c3") })
	if r := h.w.reach(*appStorage, notes); len(r) != 1 || r[0] != "c3" {
		t.Fatalf("after the move the app's storage reaches %v", r)
	}

	// ---- a member that isn't moving a workload can't drive its steps -------------------
	var refused moves.StepResult
	if err := c3.live.Call(tctx(t, 10*time.Second), "c1", http.MethodPost, cluster.PeerPathPrefix+moves.PathStop,
		moves.StepRequest{Workload: web, Generation: h.snap().Placements[web].Generation}, &refused); err != nil {
		t.Fatalf("calling c1's stop step: %v", err)
	}
	if refused.OK || !strings.Contains(refused.Message, "isn't the one moving") {
		t.Fatalf("c3 stopped c1's VM without moving it: %+v", refused)
	}
	if err := h.running(web, "c1"); err != nil {
		t.Fatal(err)
	}

	// ---- live migration c1 -> c2 and back, with both nodes on the LUN -------------------
	for _, hop := range [][2]*hnode{{c1, c2}, {c2, c1}} {
		src, dst := hop[0], hop[1]
		p, _ := placed(h.snap(), web)
		res, err := c3.ha.Mover.Move(tctx(t, 90*time.Second), cluster.MoveRequest{Workload: web, To: dst.id, Mode: cluster.MoveLive, Generation: p.Generation}, admin)
		if err != nil {
			t.Fatalf("live migration %s -> %s: %v", src.id, dst.id, err)
		}
		if res.Mode != cluster.MoveLive || res.To != dst.id || res.Generation != p.Generation+2 {
			t.Fatalf("live migration result %+v", res)
		}
		h.eventually("web runs on "+string(dst.id)+" only", 30*time.Second, func() error {
			s := h.snap()
			q, g := placed(s, web)
			if q.Owner != dst.id || q.State != cluster.PlacementRunning || g.Mode != cluster.GrantExclusive || !g.Applied {
				return fmt.Errorf("placement %+v grant %+v", q, g)
			}
			r := h.w.runners(web)
			if g, ok := r[dst.id]; len(r) != 1 || !ok || g < p.Generation+1 {
				return fmt.Errorf("web runs on %v", r)
			}
			return nil
		})
		dst.root.mu.Lock()
		relayed := slices.Clone(dst.root.relayed)
		dst.root.mu.Unlock()
		if !slices.Contains(relayed, "migrate web") {
			t.Fatalf("%s's libvirt didn't get the source's connection through the cluster port: %v", dst.id, relayed)
		}
	}
	h.eventually("the storage node maps web to c1 alone again", 20*time.Second, func() error {
		if r := h.w.reach(*vmStorage, web); len(r) != 1 || r[0] != "c1" {
			return fmt.Errorf("web's storage reaches %v", r)
		}
		return nil
	})

	// ---- hardyd restarts on c1 (part C's loops start afresh) ---------------------------
	fencesBefore := c1.root.fences
	c1.haCancel()
	<-c1.haDone
	again := &ha.Service{Priv: c1.pc, DB: nil, Log: h.log.With("node", "c1", "hardyd", 2), BootID: c1.bootID,
		Parts: ha.Parts{Membership: c1.live, Peers: c1.live, Attacher: c1.storage, Stream: moves.ALPNStream{Dial: c1.live.DialMigrate}}}
	again.Init()
	hctx, hcancel := context.WithCancel(context.Background())
	t.Cleanup(hcancel)
	c1.haCancel, c1.haDone = hcancel, make(chan struct{})
	go func() { again.Start(hctx); close(c1.haDone) }()
	time.Sleep(testTimings.QuorumLease + 2*time.Second)
	if c1.root.fences != fencesBefore {
		t.Fatal("a hardyd restart self-fenced c1")
	}
	if err := h.running(web, "c1"); err != nil {
		t.Fatalf("after the hardyd restart: %v", err)
	}
	if st := again.Agent.State(); st != cluster.FenceArmed {
		t.Fatalf("the restarted fence agent is %s", st)
	}

	// ---- c1 dies (cut off from everything, still powered) ----------------------------
	h.w.notef("cutting c1 off")
	before, _ := placed(h.snap(), web)
	h.cut(c1)
	cutAt := time.Now()
	h.eventually("c1 fences itself: its HA VM stops there", testTimings.QuorumLease+testTimings.SelfStop+5*time.Second, func() error {
		if _, runs := h.w.runners(web)["c1"]; runs {
			return errors.New("web still runs on c1")
		}
		return nil
	})
	selfFenced := time.Since(cutAt)
	h.eventually("the leader declares c1 dead, the storage node fences it, web restarts elsewhere", 90*time.Second, func() error {
		s := h.snap()
		f := s.Fences["c1"]
		if f == nil || !f.Confirmed {
			return fmt.Errorf("c1's fence %+v (c1 is %s)", f, s.Nodes["c1"].State)
		}
		p, _ := placed(s, web)
		if p.Owner == "c1" || p.Owner == "" {
			return fmt.Errorf("web: owner %q state %s", p.Owner, p.State)
		}
		return h.running(web, p.Owner)
	})
	recovered := time.Since(cutAt)
	s := h.snap()
	p, g := placed(s, web)
	f := s.Fences["c1"]
	if s.Nodes["c1"].State != cluster.NodeFenced || f.Reason != "dead" {
		t.Fatalf("c1 is %s, fence %+v", s.Nodes["c1"].State, f)
	}
	if p.Generation <= before.Generation || g.Mode != cluster.GrantExclusive || len(g.Nodes) != 1 || g.Nodes[0] != p.Owner {
		t.Fatalf("web after recovery: placement %+v grant %+v", p, g)
	}
	if !f.ConfirmedAt.After(cutAt) || p.Changed.Before(f.ConfirmedAt) {
		t.Fatalf("recovery (%s) before the storage fence was confirmed (%s)", p.Changed, f.ConfirmedAt)
	}
	// The storage node really cut c1 off: its target is disabled and empty,
	// and nothing is exported to it.
	if tg := san.Current(h.w.storageFS, s.Cluster)["c1"]; tg.Enabled || len(tg.LUNs) != 0 {
		t.Fatalf("c1's target after the fence: %+v", tg)
	}
	for _, ws := range []cluster.WorkloadStorage{*vmStorage, *appStorage} {
		for _, e := range ws.Exports {
			for _, n := range h.w.exportClients(e.Path) {
				if n == "c1" {
					t.Fatalf("%s is still exported to c1", e.Path)
				}
			}
		}
	}
	// The app on c3 never moved.
	if err := h.running(notes, "c3"); err != nil {
		t.Fatal(err)
	}
	t.Logf("c1 stopped its HA VM %.1fs after the cut; the VM ran again on %s after %.1fs (dead after %s)",
		selfFenced.Seconds(), p.Owner, recovered.Seconds(), testTimings.Dead)

	// ---- c1 comes back on the same boot: it starts nothing ----------------------------
	for _, o := range h.nodes {
		if o != c1 {
			for _, a := range []netip.Addr{c1.addrs.LAN, c1.addrs.Storage, c1.addrs.NetBird} {
				h.net.Rejoin(a, o.addrs.LAN, o.addrs.Storage, o.addrs.NetBird, h.witA.NetBird)
			}
		}
	}
	h.eventually("c1 catches up with the log", 30*time.Second, func() error {
		if c1.live.State().Index() < s.Index {
			return fmt.Errorf("c1 at %d", c1.live.State().Index())
		}
		return nil
	})
	time.Sleep(3 * time.Second)
	if len(h.w.runsOn("c1")) != 0 {
		t.Fatalf("c1 runs %v after coming back fenced", h.w.runsOn("c1"))
	}
	if st := h.snap().Nodes["c1"].State; st != cluster.NodeFenced {
		t.Fatalf("c1 is %s after coming back on the same boot (a dead node needs a new boot to rejoin)", st)
	}
	if fb := h.snap().Fences["c1"].BootID; fb != c1.bootID() {
		t.Fatalf("the fence remembers boot %q, c1 runs %q", fb, c1.bootID())
	}

	// ---- c1 reboots: a new boot id rejoins (through the leader, while fenced) ----------
	c1.reboot()
	h.eventually("c1 rejoins after its reboot and is active again", 90*time.Second, func() error {
		s := h.snap()
		if st := s.Nodes["c1"].State; st != cluster.NodeActive {
			return fmt.Errorf("c1 is %s", st)
		}
		if s.Nodes["c1"].BootID != c1.bootID() {
			return fmt.Errorf("c1's boot %q", s.Nodes["c1"].BootID)
		}
		return nil
	})
	if err := h.running(web, p.Owner); err != nil {
		t.Fatalf("web after c1 rejoined: %v", err)
	}

	h.w.mu.Lock()
	v := append([]string(nil), h.w.violations...)
	h.w.mu.Unlock()
	if len(v) > 0 {
		h.w.dump()
		t.Fatalf("safety violations: %v", v)
	}
	if testing.Verbose() {
		h.w.dump()
	}
}
