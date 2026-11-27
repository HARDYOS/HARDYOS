package convert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/cluster/storagesvc"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

func tree(ds ...hacopy.TreeDataset) *hacopy.Tree { return &hacopy.Tree{Exists: true, Datasets: ds} }

func snaps(names ...string) []hacopy.Snap {
	var out []hacopy.Snap
	for i, n := range names {
		out = append(out, hacopy.Snap{Name: n, GUID: "1" + n, TXG: uint64(i + 1)})
	}
	return out
}

// plan sends every snapshot (the oldest in full, then increments), from
// the newest one both copies have, and refuses copies that diverged.
func TestPlan(t *testing.T) {
	src := tree(hacopy.TreeDataset{Child: "", Snaps: snaps("a", "b", "c")}, hacopy.TreeDataset{Child: "disk0", Snaps: snaps("a", "b", "c")})
	got, err := plan(src, &hacopy.Tree{})
	if err != nil {
		t.Fatal(err)
	}
	want := []step{{"", "", "a", ""}, {"", "a", "b", ""}, {"", "b", "c", ""}, {"disk0", "", "a", ""}, {"disk0", "a", "b", ""}, {"disk0", "b", "c", ""}}
	if !slices.Equal(got, want) {
		t.Fatalf("plan %+v", got)
	}
	dst := tree(hacopy.TreeDataset{Child: "", Snaps: snaps("a", "b", "c")}, hacopy.TreeDataset{Child: "disk0", Snaps: snaps("a")})
	got, _ = plan(src, dst)
	if !slices.Equal(got, []step{{"disk0", "a", "b", ""}, {"disk0", "b", "c", ""}}) {
		t.Fatalf("resumed plan %+v", got)
	}
	// A copy with a snapshot the source doesn't have is never built on.
	bad := tree(hacopy.TreeDataset{Child: "", Snaps: []hacopy.Snap{{Name: "x", GUID: "9"}}})
	if _, err := plan(src, bad); err == nil {
		t.Fatal("a diverged copy was built on")
	}
	// Nothing to send from a dataset without snapshots.
	if _, err := plan(tree(hacopy.TreeDataset{Child: ""}), nil); err == nil {
		t.Fatal("planned from no snapshot")
	}
}

// ---- fakes ---------------------------------------------------------------------------

// rig is one compute server (c1) of a fake cluster with a fake root and a
// fake storage server.
type rig struct {
	t      *testing.T
	w      *clustertest.World
	c      *Converter
	jobs   *jobs.Manager
	priv   *fakePriv
	stor   *fakeStorage
	cancel context.CancelFunc
	mu     sync.Mutex
	events []string
}

func (r *rig) log(e string) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *rig) logged() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.events)
}

func newRig(t *testing.T) *rig {
	t.Helper()
	w := clustertest.New(t, "c1", "c2")
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "hardyd.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	m := &jobs.Manager{DB: db, Workers: 2}
	r := &rig{t: t, w: w, jobs: m, cancel: cancel}
	r.priv = &fakePriv{r: r, running: true, local: map[string][]string{"": {"s1"}, "disk0": {"s1"}}}
	r.priv.incoming = map[string][]string{}
	r.stor = &fakeStorage{r: r, incoming: map[string][]string{}, cluster: map[string][]string{"": {"s1"}, "disk0": {"s1"}}}
	n := w.Nodes["c1"]
	r.c = &Converter{Cluster: n, Storage: r.stor, Priv: r.priv, Specs: fakeSpecs{n: n}, DB: db, Jobs: m, Now: w.Clock.Now, Poll: time.Millisecond}
	r.c.RegisterJobs(m)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// The cluster runs on its own: reconcilers, the storage agent.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			w.Tick(time.Second)
			time.Sleep(time.Millisecond)
		}
	}()
	t.Cleanup(func() { cancel(); <-done; m.Wait() })
	return r
}

func (r *rig) wait(j *jobs.Job) *jobs.Job {
	r.t.Helper()
	for i := 0; i < 5000; i++ {
		got, err := r.jobs.Get(context.Background(), j.ID)
		if err == nil && (got.State == jobs.Succeeded || got.State == jobs.Failed) {
			return got
		}
		time.Sleep(2 * time.Millisecond)
	}
	r.t.Fatal("the job never finished")
	return nil
}

var vmWeb = cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}

type fakeSpecs struct{ n *clustertest.Node }

func (f fakeSpecs) ApproveSpec(context.Context, cluster.WorkloadRef, cluster.Actor) error { return nil }
func (f fakeSpecs) Hold(w cluster.WorkloadRef) func()                                     { return f.n.Rec.Hold(w) }

type fakePriv struct {
	r       *rig
	mu      sync.Mutex
	running bool
	parked  bool
	local   map[string][]string // child -> snapshots
	sends   int
	adoptOK int // OpVMsClusterAdopt fails while < 0
	// incoming is what "make local" received here (child -> labels).
	incoming map[string][]string
	recvs    sync.WaitGroup
}

func (p *fakePriv) Call(_ context.Context, op string, args, out any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, _ := json.Marshal(args)
	set := func(v any) error {
		if out == nil {
			return nil
		}
		raw, _ := json.Marshal(v)
		return json.Unmarshal(raw, out)
	}
	switch op {
	case priv.OpVMsHACheck:
		if p.parked {
			return &priv.Error{Code: priv.CodeNotFound, Message: "no such VM"}
		}
		st := "stopped"
		if p.running {
			st = "running"
		}
		return set(vms.HACheckResult{ID: "web", Name: "Web", LocalPool: "tank", State: st, MemoryMB: 2048, VCPUs: 2,
			Hash: "sha256:" + strings.Repeat("c", 64), Problems: []string{}})
	case hacopy.OpTree:
		var a hacopy.TreeArgs
		_ = json.Unmarshal(b, &a)
		if a.Conv != "" {
			t := hacopy.Tree{}
			for _, c := range []string{"", "disk0"} {
				if l := p.incoming[c]; len(l) > 0 {
					t.Exists = true
					t.Datasets = append(t.Datasets, hacopy.TreeDataset{Child: c, Snaps: snaps(l...)})
				}
			}
			return set(t)
		}
		if p.parked {
			return errors.New("tank/vms/web doesn't exist")
		}
		t := hacopy.Tree{Exists: true}
		for _, c := range []string{"", "disk0"} {
			t.Datasets = append(t.Datasets, hacopy.TreeDataset{Child: c, Snaps: snaps(p.local[c]...), Used: 1 << 20})
		}
		return set(t)
	case hacopy.OpSnapshot:
		var a hacopy.SnapArgs
		_ = json.Unmarshal(b, &a)
		p.r.log("snapshot " + a.Name)
		for c := range p.local {
			p.local[c] = append(p.local[c], a.Name)
		}
		return nil
	case priv.OpVMsGet:
		st := "stopped"
		if p.running {
			st = "running"
		}
		if p.parked {
			return &priv.Error{Code: priv.CodeNotFound, Message: "no such VM"}
		}
		return set(vms.VM{Spec: vms.Spec{ID: "web"}, State: st})
	case priv.OpVMsStop:
		p.r.log("stop local")
		p.running = false
		return nil
	case priv.OpVMsStart:
		p.r.log("start local")
		p.running = true
		return nil
	case hacopy.OpPark:
		if p.running {
			return errors.New("parking a running VM")
		}
		p.r.log("park local")
		p.parked = true
		return set(hacopy.ParkResult{Pool: "tank", Name: "vm-web-1"})
	case priv.OpVMsClusterAdopt:
		if p.adoptOK < 0 {
			p.adoptOK++
			return errors.New("the attached state folder didn't answer")
		}
		p.r.log("adopt spec")
		return set(priv.SpecHashResult{Hash: "sha256:" + strings.Repeat("c", 64)})
	case hacopy.OpParkedKeep:
		var a hacopy.ParkedKeepArgs
		_ = json.Unmarshal(b, &a)
		if a.KeepUntil > 0 {
			p.r.log("keep local for a while")
		}
		return nil
	case hacopy.OpAdopt:
		p.r.log("adopt local")
		p.parked = false
		return set(hacopy.AdoptResult{Dataset: "tank/vms/web"})
	case hacopy.OpStream:
		if strings.Contains(string(b), "recv") {
			p.mu.Unlock()
			p.recvs.Wait()
			p.mu.Lock()
		}
		return set(hacopy.StreamState{Done: true, OK: true})
	case hacopy.OpCancel:
		return nil
	}
	return errors.New("fake priv: " + op)
}

func (p *fakePriv) CallFile(_ context.Context, op string, args, out any) (*os.File, error) {
	if op == hacopy.OpRecv {
		var a hacopy.RecvArgs
		b, _ := json.Marshal(args)
		_ = json.Unmarshal(b, &a)
		pr, pw, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		p.recvs.Add(1)
		go func() {
			defer p.recvs.Done()
			got, _ := io.ReadAll(pr)
			pr.Close()
			if string(got) == "zfs stream" {
				p.mu.Lock()
				p.incoming[a.Child] = append(p.incoming[a.Child], a.Label)
				p.mu.Unlock()
			}
		}()
		raw, _ := json.Marshal(hacopy.StreamStart{Stream: "recv"})
		_ = json.Unmarshal(raw, out)
		return pw, nil
	}
	if op != hacopy.OpSend {
		return nil, errors.New("fake priv file: " + op)
	}
	p.mu.Lock()
	p.sends++
	p.mu.Unlock()
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	go func() { _, _ = pw.Write([]byte("zfs stream")); pw.Close() }()
	raw, _ := json.Marshal(hacopy.StreamStart{Stream: "s"})
	_ = json.Unmarshal(raw, out)
	return pr, nil
}

type fakeStorage struct {
	r        *rig
	mu       sync.Mutex
	incoming map[string][]string
	adoptErr error
	pending  map[string]string // token -> child@label
	// cluster are the cluster copy's snapshots (make local).
	cluster map[string][]string
}

func (s *fakeStorage) HAPool(context.Context) (string, error) { return "nas", nil }
func (s *fakeStorage) HAOpenRecv(_ context.Context, r storagesvc.HAStreamRequest) (*storagesvc.HAStreamOpened, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = map[string]string{}
	}
	tok := r.Child + "@" + r.Label
	s.pending[tok] = tok
	return &storagesvc.HAStreamOpened{Token: tok, Stream: "rs"}, nil
}
func (s *fakeStorage) HAOpenSend(_ context.Context, r storagesvc.HAStreamRequest) (*storagesvc.HAStreamOpened, error) {
	p := s.r.w.Snapshot().Placements[r.Workload]
	if p == nil || p.State != cluster.PlacementStopped || p.Requested != cluster.RequestStopped {
		return nil, errors.New("must be a stopped cluster workload")
	}
	return &storagesvc.HAStreamOpened{Token: "send", Stream: "ss"}, nil
}
func (s *fakeStorage) HAStream(context.Context, string) (*hacopy.StreamState, error) {
	return &hacopy.StreamState{Done: true, OK: true}, nil
}
func (s *fakeStorage) HATree(_ context.Context, r storagesvc.HARequest) (*hacopy.Tree, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := &hacopy.Tree{}
	src := s.incoming
	if r.Conv == "" {
		src = s.cluster
	}
	for _, c := range []string{"", "disk0"} {
		if l := src[c]; len(l) > 0 {
			t.Exists = true
			t.Datasets = append(t.Datasets, hacopy.TreeDataset{Child: c, Snaps: snaps(l...), Used: 1 << 20})
		}
	}
	return t, nil
}
func (s *fakeStorage) HAAdopt(context.Context, storagesvc.HARequest) (*cluster.WorkloadStorage, error) {
	if s.adoptErr != nil {
		return nil, s.adoptErr
	}
	s.r.log("adopt storage")
	return &cluster.WorkloadStorage{Pool: "nas", Volumes: []cluster.Volume{{Dataset: "nas/vms/web/disk0", Disk: "disk0", SizeGB: 10, WWN: "6001405aabbccdd0"}}}, nil
}
func (s *fakeStorage) HAAbort(context.Context, storagesvc.HARequest) error { return nil }
func (s *fakeStorage) HASnapshot(_ context.Context, r storagesvc.HARequest) error {
	s.r.log("snapshot storage")
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.cluster {
		s.cluster[c] = append(s.cluster[c], r.Name)
	}
	return nil
}
func (s *fakeStorage) HAUnpark(context.Context, storagesvc.HARequest) error     { return nil }
func (s *fakeStorage) HAParkedKeep(context.Context, storagesvc.HARequest) error { return nil }
func (s *fakeStorage) HAPark(context.Context, storagesvc.HARequest) (*hacopy.ParkResult, error) {
	s.r.log("park storage")
	return &hacopy.ParkResult{Pool: "nas", Name: "vm-web-2"}, nil
}
func (s *fakeStorage) HAParked(context.Context) ([]hacopy.Parked, error) { return nil, nil }
func (s *fakeStorage) HAParkedDestroy(context.Context, storagesvc.HAParkedDestroy) error {
	return nil
}
func (s *fakeStorage) SwitchAppMode(context.Context, storagesvc.ModeRequest) (*storagesvc.ModeResult, error) {
	return nil, errors.New("not here")
}
func (s *fakeStorage) Attach(ctx context.Context, ws cluster.WorkloadStorage, g cluster.Grant) (*cluster.Attachment, error) {
	s.r.log("attach")
	return s.r.w.Nodes["c1"].Rec.Attacher.Attach(ctx, ws, g)
}
func (s *fakeStorage) Detach(ctx context.Context, w cluster.WorkloadRef, force bool) error {
	return s.r.w.Nodes["c1"].Rec.Attacher.Detach(ctx, w, force)
}
func (s *fakeStorage) CopyConn(_ context.Context, token string) (Conn, error) {
	return &fakeConn{s: s, token: token}, nil
}

type fakeConn struct {
	s     *fakeStorage
	token string
	buf   bytes.Buffer
	sent  bool
}

func (c *fakeConn) Read(p []byte) (int, error) {
	if c.token != "send" || c.sent {
		return 0, io.EOF
	}
	c.sent = true
	return copy(p, "zfs stream"), nil
}
func (c *fakeConn) Write(p []byte) (int, error) { return c.buf.Write(p) }
func (c *fakeConn) Close() error                { return nil }
func (c *fakeConn) CloseWrite() error           { return nil }
func (c *fakeConn) Verdict() error {
	if c.buf.String() != "zfs stream" {
		return errors.New("a broken stream")
	}
	child, label, _ := strings.Cut(c.token, "@")
	c.s.mu.Lock()
	c.s.incoming[child] = append(c.s.incoming[child], label)
	c.s.mu.Unlock()
	return nil
}

// ---- flows ---------------------------------------------------------------------------

// A running VM: copied while it runs, stopped, its changes copied, the
// storage server adopts it, the local copy is parked before the cluster
// workload exists, which starts on this server; the kept copy gets its
// grace period once it runs.
func TestToHA(t *testing.T) {
	r := newRig(t)
	j, err := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb, Priority: 70, Actor: cluster.Actor{Kind: "local", Name: "alice"}}, "Web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.wait(j); got.State != jobs.Succeeded {
		t.Fatalf("the conversion: %s", got.Error)
	}
	recs, _ := r.c.List(context.Background(), 10)
	if len(recs) != 1 || recs[0].State != StateDone || recs[0].Phase != PhaseDone {
		t.Fatalf("records %+v", recs)
	}
	conv := recs[0].ID
	ev := r.logged()
	steps := []string{"snapshot " + snapName(conv, "pre", 1), "stop local", "snapshot " + snapName(conv, "final", 1), "adopt storage", "park local",
		"attach", "adopt spec", "keep local for a while"}
	last := -1
	for _, s := range steps {
		i := slices.Index(ev, s)
		if i <= last {
			t.Fatalf("%q out of order: %v", s, ev)
		}
		last = i
	}
	if slices.Contains(ev, "start local") {
		t.Fatalf("the local copy started again: %v", ev)
	}
	p := r.w.Snapshot().Placements[vmWeb]
	if p == nil || p.Owner != "c1" || !p.HA.Enabled || p.HA.Priority != 70 || !slices.Equal(p.HA.Preferred, []cluster.NodeID{"c1"}) || p.HA.FailBack {
		t.Fatalf("placement %+v", p)
	}
	if p.State != cluster.PlacementRunning || p.SpecHash != "sha256:"+strings.Repeat("c", 64) {
		t.Fatalf("placement state %s hash %s", p.State, p.SpecHash)
	}
	if g, ok := r.w.Nodes["c1"].RunningGen(vmWeb); !ok || g != p.Generation {
		t.Fatalf("c1 doesn't run it under its generation: %d %v", g, ok)
	}
	// Every snapshot arrived (s1, pre and final for both datasets).
	if got := r.stor.incoming["disk0"]; len(got) != 3 {
		t.Fatalf("disk0's snapshots on cluster storage: %v", got)
	}
}

// A conversion that fails before the local copy is parked leaves the VM
// as it was (started again); nothing is registered.
func TestToHAFailureBeforeParkStartsItAgain(t *testing.T) {
	r := newRig(t)
	r.stor.adoptErr = errors.New("the storage server's pool is full")
	j, err := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.wait(j); got.State != jobs.Failed || !strings.Contains(got.Error, "pool is full") {
		t.Fatalf("the conversion: %s %s", got.State, got.Error)
	}
	ev := r.logged()
	if !slices.Contains(ev, "start local") || slices.Contains(ev, "park local") {
		t.Fatalf("events %v", ev)
	}
	if r.w.Snapshot().Placements[vmWeb] != nil {
		t.Fatal("a failed conversion registered the workload")
	}
	recs, _ := r.c.List(context.Background(), 10)
	if recs[0].State != StateFailed || recs[0].Phase != PhaseAdopt {
		t.Fatalf("record %+v", recs[0])
	}
	// What was copied stays for a retry, which copies only what's new.
	sent := r.priv.sends
	r.stor.adoptErr = nil
	j, err = r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.wait(j); got.State != jobs.Succeeded {
		t.Fatalf("the retry: %s", got.Error)
	}
	if r.priv.sends-sent != 4 {
		t.Fatalf("the retry sent %d streams; only the two new snapshots of each dataset were new", r.priv.sends-sent)
	}
}

// A conversion that fails after the local copy was parked never puts it
// back by itself; resuming carries on without copying again.
func TestToHAResumesAfterPark(t *testing.T) {
	r := newRig(t)
	r.priv.adoptOK = -1
	j, err := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.wait(j); got.State != jobs.Failed {
		t.Fatalf("the conversion: %s", got.State)
	}
	if slices.Contains(r.logged(), "start local") {
		t.Fatal("the parked local copy was started after the cluster workload existed")
	}
	p := r.w.Snapshot().Placements[vmWeb]
	if p == nil || p.Requested != cluster.RequestStopped {
		t.Fatalf("placement %+v", p)
	}
	if _, err := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "", nil); !errors.Is(err, errTyped) {
		t.Fatalf("resumed without the name typed: %v", err)
	}
	sent := r.priv.sends
	j, err = r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.wait(j); got.State != jobs.Succeeded {
		t.Fatalf("resuming: %s", got.Error)
	}
	if r.priv.sends != sent {
		t.Fatal("resuming after the park copied again")
	}
	if p := r.w.Snapshot().Placements[vmWeb]; p.State != cluster.PlacementRunning {
		t.Fatalf("after resuming: %s", p.State)
	}
}

// The LAN check refuses "Make highly available" (decision 487).
func TestToHARefusedByNetCheck(t *testing.T) {
	r := newRig(t)
	r.c.Net = netDown{}
	rd, err := r.c.Check(context.Background(), vmWeb, CPUBaseline)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(rd.Problems, func(p string) bool { return strings.Contains(p, "switch is down") }) {
		t.Fatalf("problems %v", rd.Problems)
	}
	if _, err := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil); err == nil {
		t.Fatal("started with the LAN check failing")
	}
}

type netDown struct{}

func (netDown) LocalNetworkOK(context.Context) (bool, string) { return false, "the switch is down" }

// "Make local again": the cluster workload stops, a final snapshot is
// copied here, the cluster forgets it before this server's copy is
// adopted, and it runs here; the cluster copy is kept for a while.
func TestToLocal(t *testing.T) {
	r := newRig(t)
	r.priv.parked, r.priv.running = true, false // no local VM called web here
	if err := r.w.Propose("c1", cluster.CmdWorkloadAdd, state.WorkloadAdd{SpecHash: "sha256:" + strings.Repeat("a", 64), Workload: vmWeb, Name: "Web",
		Owner: "c1", Requested: cluster.RequestRunning, HA: cluster.HAPolicy{Enabled: true}, Storage: cluster.WorkloadStorage{Pool: "nas"}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2000 && r.w.Snapshot().Placements[vmWeb].State != cluster.PlacementRunning; i++ {
		time.Sleep(time.Millisecond)
	}
	if _, err := r.c.StartToLocal(context.Background(), ToLocalParams{Workload: vmWeb, Pool: "tank"}, "nope", nil); !errors.Is(err, errTyped) {
		t.Fatalf("without the name typed: %v", err)
	}
	j, err := r.c.StartToLocal(context.Background(), ToLocalParams{Workload: vmWeb, Pool: "tank", Actor: cluster.Actor{Kind: "local", Name: "alice"}}, "Web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.wait(j); got.State != jobs.Succeeded {
		t.Fatalf("make local: %s", got.Error)
	}
	if r.w.Snapshot().Placements[vmWeb] != nil {
		t.Fatal("it is still a cluster workload")
	}
	ev := r.logged()
	last := -1
	for _, s := range []string{"snapshot storage", "park storage", "adopt local", "start local"} {
		i := slices.Index(ev, s)
		if i <= last {
			t.Fatalf("%q out of order: %v", s, ev)
		}
		last = i
	}
	if got := r.priv.incoming["disk0"]; len(got) != 2 {
		t.Fatalf("disk0's snapshots that came back: %v", got)
	}
	if n, ok := r.w.Nodes["c1"].RunningGen(vmWeb); ok {
		t.Fatalf("the cluster copy still runs (generation %d)", n)
	}
}
