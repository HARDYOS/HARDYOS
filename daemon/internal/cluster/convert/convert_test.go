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
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
	"github.com/hardyos/hardyos/daemon/internal/cluster/netcheck"
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
	// parkFail: OpPark fails (nothing parked) while > 0; parkLost: OpPark
	// parks but its answer is lost while > 0.
	parkFail, parkLost int
	parkConv           string // the conversion that parked it
	parkCalls          []hacopy.ParkArgs
	// changed: written after the final snapshot (RefuseChanged refuses).
	changed bool
	// onSnap hears every snapshot taken here.
	onSnap func(name string)
	// listFail: ha.parked.list fails.
	listFail bool
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
		if p.onSnap != nil {
			p.onSnap(a.Name)
		}
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
		var a hacopy.ParkArgs
		_ = json.Unmarshal(b, &a)
		p.parkCalls = append(p.parkCalls, a)
		if p.parked && a.Conv != "" && a.Conv == p.parkConv {
			// Root's idempotent answer: the copy this conversion parked.
			return set(hacopy.ParkResult{Pool: "tank", Name: "vm-web-1", Existing: true})
		}
		if p.parked {
			return errors.New("tank/vms/web doesn't exist")
		}
		if p.running {
			return errors.New("parking a running VM")
		}
		if a.RefuseChanged && p.changed {
			return &priv.Error{Code: priv.CodeBadArgs, Message: "it changed after the conversion's final snapshot"}
		}
		if p.parkFail > 0 {
			p.parkFail--
			p.r.log("park local failed")
			return errors.New("zfs rename: dataset is busy")
		}
		p.r.log("park local")
		p.parked, p.parkConv = true, a.Conv
		if p.parkLost > 0 {
			p.parkLost--
			return errors.New("the connection to root broke")
		}
		return set(hacopy.ParkResult{Pool: "tank", Name: "vm-web-1"})
	case hacopy.OpParkedList:
		if p.listFail {
			return errors.New("root didn't answer")
		}
		l := []hacopy.Parked{}
		if p.parked && p.parkConv != "" {
			l = append(l, hacopy.Parked{Pool: "tank", Name: "vm-web-1", Kind: cluster.KindVM, ID: "web", Side: hacopy.SideLocal, Conv: p.parkConv})
		}
		return set(map[string]any{"parked": l})
	case hacopy.OpUnpark:
		if !p.parked {
			return errors.New("nothing parked")
		}
		p.r.log("unpark local")
		p.parked, p.parkConv = false, ""
		return nil
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
	// adopted: the cluster copy is at its live dataset (by adoptedBy).
	adopted   bool
	adoptedBy string
	// parkFail: HAPark fails while > 0; parks are its requests;
	// clusterChanged: the cluster copy was written after its snapshot.
	parkFail       int
	parks          []storagesvc.HARequest
	clusterChanged bool
	keeps          []storagesvc.HARequest
	cancels        int
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
func (s *fakeStorage) HAAdopt(_ context.Context, r storagesvc.HARequest) (*cluster.WorkloadStorage, error) {
	if s.adoptErr != nil {
		return nil, s.adoptErr
	}
	s.mu.Lock()
	if s.adopted {
		s.mu.Unlock()
		return nil, errors.New("nas/vms/web exists already; it isn't replaced")
	}
	s.adopted, s.adoptedBy = true, r.Conv
	s.mu.Unlock()
	s.r.log("adopt storage")
	return &cluster.WorkloadStorage{Pool: "nas", Volumes: []cluster.Volume{{Dataset: "nas/vms/web/disk0", Disk: "disk0", SizeGB: 10, WWN: "6001405aabbccdd0"}}}, nil
}
func (s *fakeStorage) HACancel(context.Context, string, cluster.Actor) error {
	s.mu.Lock()
	s.cancels++
	s.mu.Unlock()
	return nil
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
func (s *fakeStorage) HAUnpark(context.Context, storagesvc.HARequest) error { return nil }
func (s *fakeStorage) HAParkedKeep(_ context.Context, r storagesvc.HARequest) error {
	s.mu.Lock()
	s.keeps = append(s.keeps, r)
	s.mu.Unlock()
	if r.KeepUntil > 0 {
		s.r.log("keep storage for a while")
	}
	return nil
}
func (s *fakeStorage) HAPark(_ context.Context, r storagesvc.HARequest) (*hacopy.ParkResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.parks = append(s.parks, r)
	if s.parkFail > 0 {
		s.parkFail--
		s.r.log("park storage failed")
		return nil, errors.New("the storage server didn't answer")
	}
	if r.Expect != "" && (!s.adopted || s.adoptedBy != r.Expect) {
		return nil, errors.New("isn't what this conversion set up")
	}
	// Make local parks the cluster workload's copy (registered with
	// workload.add in its test, never adopted here).
	s.adopted = false
	s.r.log("park storage")
	return &hacopy.ParkResult{Pool: "nas", Name: "vm-web-2", Changed: s.clusterChanged}, nil
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

// The reviewer's scenario (H1): parking the local copy fails, and so does
// putting the adopted cluster copy aside. The conversion goes back before
// the park (the local VM runs again, nothing is registered); resuming puts
// the stale cluster copy aside first, copies afresh, and never has the
// cluster workload and the local VM both there.
func TestToHAParkFailureNeverRegisters(t *testing.T) {
	r := newRig(t)
	r.priv.parkFail, r.stor.parkFail = 1, 1
	j, err := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.wait(j); got.State != jobs.Failed || !strings.Contains(got.Error, "putting this server's copy aside") {
		t.Fatalf("the conversion: %s %s", got.State, got.Error)
	}
	if r.w.Snapshot().Placements[vmWeb] != nil {
		t.Fatal("registered although this server's copy wasn't put aside")
	}
	recs, _ := r.c.List(context.Background(), 10)
	rec := recs[0]
	if rec.Phase != PhaseAdopt || rec.Options.Storage == nil || rec.Options.ParkedName != "" {
		t.Fatalf("record after the failed park: phase %s storage %v parked %q", rec.Phase, rec.Options.Storage != nil, rec.Options.ParkedName)
	}
	if !r.priv.running || r.priv.parked {
		t.Fatal("the local VM isn't running as it was")
	}
	// Resume: the earlier attempt's cluster copy goes aside (an hour, under
	// its attempt's own mark), everything new is copied, then the park.
	j, err = r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.wait(j); got.State != jobs.Succeeded {
		t.Fatalf("resuming: %s", got.Error)
	}
	ev := r.logged()
	last := -1
	for _, s := range []string{"park local failed", "start local", "park storage", "adopt storage", "park local", "attach"} {
		i := slices.Index(ev[last+1:], s)
		if i < 0 {
			t.Fatalf("%q missing or out of order: %v", s, ev)
		}
		last += i + 1
	}
	aside := r.stor.parks[len(r.stor.parks)-1]
	if aside.KeepUntil == 0 || aside.Conv == rec.ID || !strings.HasPrefix(aside.Conv, rec.ID) {
		t.Fatalf("the stale cluster copy was put aside as %+v", aside)
	}
	p := r.w.Snapshot().Placements[vmWeb]
	if p == nil || p.State != cluster.PlacementRunning || r.priv.running {
		t.Fatalf("after resuming: placement %+v, local running %v", p, r.priv.running)
	}
	for _, a := range r.priv.parkCalls {
		if a.Conv != rec.ID || !a.RefuseChanged || a.Since == "" {
			t.Fatalf("a park without the conversion's mark or the change check: %+v", a)
		}
	}
}

// hardyd going away around the park (H1): root parked the copy but its
// answer was lost; asking again names the copy this conversion parked,
// and the conversion goes on without a second park.
func TestToHAParkAnswerLost(t *testing.T) {
	r := newRig(t)
	r.priv.parkLost = 1
	j, err := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.wait(j); got.State != jobs.Succeeded {
		t.Fatalf("the conversion: %s", got.Error)
	}
	recs, _ := r.c.List(context.Background(), 10)
	if recs[0].Options.ParkedName != "vm-web-1" {
		t.Fatalf("the parked copy wasn't recorded: %+v", recs[0].Options)
	}
	if n := strings.Count(strings.Join(r.logged(), "\n"), "park local"); n != 1 {
		t.Fatalf("parked %d times", n)
	}
}

// hardyd restarted after saving the park phase (H1): the resume parks
// this server's copy (or finds it parked) before anything is registered,
// and refuses to register without a recorded parked copy.
func TestToHAResumeAtParkPhase(t *testing.T) {
	for _, parkedAlready := range []bool{false, true} {
		r := newRig(t)
		r.stor.adoptErr = errors.New("cut short")
		j, _ := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil)
		r.wait(j)
		r.stor.adoptErr = nil
		recs, _ := r.c.List(context.Background(), 10)
		rec := recs[0]
		// As a restart leaves it: the park phase saved, the cluster copy
		// adopted, the local copy stopped (or parked by root already).
		rec.Phase, rec.State = PhasePark, StateFailed
		rec.Options.Storage = &cluster.WorkloadStorage{Pool: "nas", Volumes: []cluster.Volume{{Dataset: "nas/vms/web/disk0", Disk: "disk0", SizeGB: 10, WWN: "6001405aabbccdd0"}}}
		r.stor.adopted, r.stor.adoptedBy = true, rec.ID
		r.priv.running = false
		if parkedAlready {
			r.priv.parked, r.priv.parkConv = true, rec.ID
		}
		if err := r.c.save(context.Background(), &rec); err != nil {
			t.Fatal(err)
		}
		r.mu.Lock()
		r.events = nil
		r.mu.Unlock()
		j, err := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := r.wait(j); got.State != jobs.Succeeded {
			t.Fatalf("parked already %v: resuming: %s", parkedAlready, got.Error)
		}
		ev := r.logged()
		if parkedAlready == slices.Contains(ev, "park local") {
			t.Fatalf("parked already %v: events %v", parkedAlready, ev)
		}
		if i, k := slices.Index(ev, "attach"), slices.Index(ev, "park local"); !parkedAlready && (k < 0 || k > i) {
			t.Fatalf("registered before the park: %v", ev)
		}
	}
}

// register refuses without a recorded parked local copy.
func TestRegisterNeedsParkedCopy(t *testing.T) {
	r := newRig(t)
	self, _ := r.w.Nodes["c1"].Self()
	rec := &Record{ID: "abcdefghij", Direction: DirHA, Kind: cluster.KindVM, Workload: "web", Phase: PhaseRegister,
		Options: Options{Storage: &cluster.WorkloadStorage{Pool: "nas"}}}
	if err := r.c.register(nil, self, rec, ToHAParams{}); err == nil || !strings.Contains(err.Error(), "isn't recorded as put aside") {
		t.Fatalf("registered without a parked copy: %v", err)
	}
	if r.w.Snapshot().Placements[vmWeb] != nil {
		t.Fatal("it was registered")
	}
}

// Undo (H2, M1): this server's copy comes back first; the cluster copy is
// put aside with no expiry, and its grace period starts only once this
// server's copy runs again and only if the cluster copy didn't change.
func TestUndo(t *testing.T) {
	for _, changed := range []bool{false, true} {
		r := newRig(t)
		r.priv.adoptOK = -1
		r.stor.clusterChanged = changed
		j, _ := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil)
		if got := r.wait(j); got.State != jobs.Failed {
			t.Fatalf("the conversion: %s", got.State)
		}
		recs, _ := r.c.List(context.Background(), 10)
		if _, err := r.c.StartUndo(context.Background(), UndoParams{Conv: recs[0].ID}, "nope", nil); !errors.Is(err, errTyped) {
			t.Fatalf("undone without the name typed: %v", err)
		}
		j, err := r.c.StartUndo(context.Background(), UndoParams{Conv: recs[0].ID}, "Web", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := r.wait(j); got.State != jobs.Succeeded {
			t.Fatalf("undo: %s", got.Error)
		}
		ev := r.logged()
		u, p := slices.Index(ev, "unpark local"), slices.Index(ev, "park storage")
		if u < 0 || p < 0 || u > p {
			t.Fatalf("the cluster copy went aside before this server's copy was back: %v", ev)
		}
		park := r.stor.parks[len(r.stor.parks)-1]
		if park.KeepUntil != 0 || park.Conv != recs[0].ID || park.Since == "" {
			t.Fatalf("the cluster copy was put aside as %+v", park)
		}
		if !r.priv.running || r.w.Snapshot().Placements[vmWeb] != nil {
			t.Fatal("not back as it was")
		}
		kept := slices.Contains(ev, "keep storage for a while")
		if kept == changed {
			t.Fatalf("changed %v: the cluster copy's grace period started: %v", changed, kept)
		}
		got, _ := r.c.Get(context.Background(), recs[0].ID)
		if got.State != StateUndone || got.Options.ClusterChanged != changed || got.Options.ParkedSide != string(hacopy.SideCluster) {
			t.Fatalf("record %+v", got.Options)
		}
	}
}

// L-A: when this server's copy can't be seen as the workload after a
// failed park (parked, the answer lost, the lookup failing too), the
// cluster copy put aside gets no expiry: it may be the only copy left.
func TestAsideCopyKeptWhenLocalCopyIsntSeen(t *testing.T) {
	r := newRig(t)
	r.priv.parkLost = 1
	r.priv.listFail = true
	j, _ := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil)
	if got := r.wait(j); got.State != jobs.Failed {
		t.Fatalf("the conversion: %s", got.State)
	}
	aside := r.stor.parks[len(r.stor.parks)-1]
	if aside.KeepUntil != 0 || aside.Expect == "" {
		t.Fatalf("the cluster copy was put aside as %+v with this server's copy gone", aside)
	}
	if r.w.Snapshot().Placements[vmWeb] != nil {
		t.Fatal("registered")
	}
}

// Undo (M-D): once this server's copy is back and the cluster forgot the
// workload, it runs again here, even when the cluster copy can't be put
// aside (that is left for a retry of the undo).
func TestUndoStartsLocalWhenClusterParkFails(t *testing.T) {
	r := newRig(t)
	r.priv.adoptOK = -1
	j, _ := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil)
	if got := r.wait(j); got.State != jobs.Failed {
		t.Fatalf("the conversion: %s", got.State)
	}
	recs, _ := r.c.List(context.Background(), 10)
	r.stor.mu.Lock()
	r.stor.parkFail = 1 << 30
	r.stor.mu.Unlock()
	j, err := r.c.StartUndo(context.Background(), UndoParams{Conv: recs[0].ID}, "Web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.wait(j); got.State != jobs.Failed {
		t.Fatalf("undo with the storage server refusing: %s", got.State)
	}
	if !r.priv.running || r.priv.parked || r.w.Snapshot().Placements[vmWeb] != nil {
		t.Fatalf("this server's copy isn't running again: running %v parked %v", r.priv.running, r.priv.parked)
	}
}

// Abandon puts a copy the conversion adopted aside (an hour) instead of
// leaving it in the way of the next conversion.
func TestAbandonPutsAdoptedCopyAside(t *testing.T) {
	r := newRig(t)
	r.priv.parkFail, r.stor.parkFail = 1, 1
	j, _ := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil)
	r.wait(j)
	recs, _ := r.c.List(context.Background(), 10)
	j, err := r.c.StartAbandon(context.Background(), AbandonParams{Conv: recs[0].ID}, "Web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.wait(j); got.State != jobs.Succeeded {
		t.Fatalf("abandon: %s", got.Error)
	}
	park := r.stor.parks[len(r.stor.parks)-1]
	if park.Expect != recs[0].ID || park.Conv != recs[0].ID || park.KeepUntil == 0 || r.stor.adopted {
		t.Fatalf("the adopted copy: %+v (still there %v)", park, r.stor.adopted)
	}
}

// A copy into the storage server that fails on this side gives up the
// storage server's stream too (M4).
func TestFailedCopyCancelsRemoteStream(t *testing.T) {
	r := newRig(t)
	r.stor.mu.Lock()
	r.stor.cancels = 0
	r.stor.mu.Unlock()
	rec := &Record{ID: "abcdefghij", Direction: DirHA, Kind: cluster.KindVM, Workload: "web", StoragePool: "nas"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = r.c.pushStep(ctx, rec, hacopy.Ref{Kind: cluster.KindVM, ID: "web", Pool: "tank", Side: hacopy.SideLocal}, step{To: "s1"}, cluster.Actor{}, func(int64) {})
	r.stor.mu.Lock()
	defer r.stor.mu.Unlock()
	if r.stor.cancels == 0 {
		t.Fatal("the storage server's stream wasn't cancelled")
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
	if _, err := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil); !errors.Is(err, ErrNetwork) {
		t.Fatalf("started with the LAN check failing: %v", err)
	}
}

type netDown struct{}

func (netDown) LocalNetworkOK(context.Context) (bool, string) { return false, "the switch is down" }

// PairCheck judges this server (the monitor adds the storage servers).
func TestPairCheck(t *testing.T) {
	var asked []cluster.NodeID
	p := PairCheck{Self: func() (cluster.Node, error) { return cluster.Node{ID: "c1"}, nil },
		Status: func(_ context.Context, m ...cluster.NodeID) netcheck.Result {
			asked = m
			return netcheck.Result{OK: false, Reason: "c1 and nas: the storage network doesn't answer"}
		}}
	ok, why := p.LocalNetworkOK(context.Background())
	if ok || !strings.Contains(why, "storage network") || !slices.Equal(asked, []cluster.NodeID{"c1"}) {
		t.Fatalf("pair check: %v %q, asked about %v", ok, why, asked)
	}
}

// netFlip fails once down is set.
type netFlip struct{ down *atomic.Bool }

func (n netFlip) LocalNetworkOK(context.Context) (bool, string) {
	if n.down.Load() {
		return false, "the storage network stopped answering"
	}
	return true, ""
}

// haDown is turning HA on's check refusing (ha.Service.CheckHA).
type haDown struct {
	asked *atomic.Int32
	pol   *atomic.Value
}

var errHANetwork = errors.New("the servers don't share a local network yet, so high availability can't be turned on: c2 can't reach nas")

func (h haDown) CheckHA(_ context.Context, w cluster.WorkloadRef, pol cluster.HAPolicy) error {
	h.asked.Add(1)
	h.pol.Store(pol)
	return errHANetwork
}

// The conversion asks turning HA on's own check (every server it could
// fail over to), since its workload.add doesn't pass through it; a refusal
// is the API's "network" refusal and nothing happens to the VM.
func TestToHARefusedByHACheck(t *testing.T) {
	r := newRig(t)
	h := haDown{asked: &atomic.Int32{}, pol: &atomic.Value{}}
	r.c.HA = h
	if _, err := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb, Priority: 70}, "Web", nil); !errors.Is(err, errHANetwork) {
		t.Fatalf("started with turning HA on refused: %v", err)
	}
	pol, _ := h.pol.Load().(cluster.HAPolicy)
	if !pol.Enabled || pol.Priority != 70 || !slices.Equal(pol.Preferred, []cluster.NodeID{"c1"}) {
		t.Fatalf("checked the policy %+v, not the one it registers", pol)
	}
	if slices.Contains(r.logged(), "stop local") || r.w.Snapshot().Placements[vmWeb] != nil {
		t.Fatal("something happened to the VM")
	}
}

// A network check failing while it copies stops the conversion before the
// VM goes down: it keeps running from this server, nothing is registered.
func TestToHANetworkFailsBeforeTheStop(t *testing.T) {
	r := newRig(t)
	down := &atomic.Bool{}
	r.c.Net = netFlip{down: down}
	r.priv.onSnap = func(name string) {
		if strings.Contains(name, "-pre") {
			down.Store(true) // during the copy while it runs
		}
	}
	j, err := r.c.StartToHA(context.Background(), ToHAParams{Workload: vmWeb}, "Web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.wait(j); got.State != jobs.Failed || !strings.Contains(got.Error, "storage network stopped answering") {
		t.Fatalf("the conversion: %s %s", got.State, got.Error)
	}
	if slices.Contains(r.logged(), "stop local") || !r.priv.running || r.priv.parked {
		t.Fatalf("the VM went down: %v", r.logged())
	}
	if r.w.Snapshot().Placements[vmWeb] != nil {
		t.Fatal("registered with the network check failing")
	}
}

// lateRemove makes the first workload.remove answer with an error and
// commit a moment later (a proposal whose outcome wasn't known in time).
type lateRemove struct {
	Cluster
	once sync.Once
	done chan struct{}
}

func (l *lateRemove) Propose(ctx context.Context, t cluster.CommandType, body any, actor cluster.Actor) (uint64, error) {
	if t != cluster.CmdWorkloadRemove {
		return l.Cluster.Propose(ctx, t, body, actor)
	}
	late := false
	l.once.Do(func() { late = true })
	if !late {
		return l.Cluster.Propose(ctx, t, body, actor)
	}
	go func() {
		defer close(l.done)
		time.Sleep(20 * time.Millisecond)
		_, _ = l.Cluster.Propose(context.Background(), t, body, actor)
	}()
	return 0, errors.New("timed out waiting for the log")
}

// "Make local again" whose removal's outcome wasn't known (M-C): the
// record keeps the removal as its own, so the resume after it committed
// goes on instead of refusing a workload "removed by someone else".
func TestToLocalRemovalOutcomeUnknown(t *testing.T) {
	r := newRig(t)
	r.priv.parked, r.priv.running = true, false
	if err := r.w.Propose("c1", cluster.CmdWorkloadAdd, state.WorkloadAdd{SpecHash: "sha256:" + strings.Repeat("a", 64), Workload: vmWeb, Name: "Web",
		Owner: "c1", Requested: cluster.RequestRunning, HA: cluster.HAPolicy{Enabled: true}, Storage: cluster.WorkloadStorage{Pool: "nas"}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2000 && r.w.Snapshot().Placements[vmWeb].State != cluster.PlacementRunning; i++ {
		time.Sleep(time.Millisecond)
	}
	late := &lateRemove{Cluster: r.c.Cluster, done: make(chan struct{})}
	r.c.Cluster = late
	j, err := r.c.StartToLocal(context.Background(), ToLocalParams{Workload: vmWeb, Pool: "tank"}, "Web", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.wait(j); got.State != jobs.Failed || !strings.Contains(got.Error, "timed out") {
		t.Fatalf("make local: %s %s", got.State, got.Error)
	}
	<-late.done
	for i := 0; i < 2000 && r.w.Snapshot().Placements[vmWeb] != nil; i++ {
		time.Sleep(time.Millisecond)
	}
	if r.w.Snapshot().Placements[vmWeb] != nil {
		t.Fatal("the late removal didn't commit")
	}
	j, err = r.c.StartToLocal(context.Background(), ToLocalParams{Workload: vmWeb, Pool: "tank"}, "Web", nil)
	if err != nil {
		t.Fatalf("resuming: %v", err)
	}
	if got := r.wait(j); got.State != jobs.Succeeded {
		t.Fatalf("resuming after its own removal committed: %s", got.Error)
	}
	if !slices.Contains(r.logged(), "adopt local") {
		t.Fatalf("not adopted here: %v", r.logged())
	}
}

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
