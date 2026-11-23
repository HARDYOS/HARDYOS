package fence

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// fakeDevice is a watchdog device: it records keepalives and fires when
// none came within its timeout (checked by the test).
type fakeDevice struct {
	mu       sync.Mutex
	timeout  int
	pets     []time.Time
	closed   bool
	magic    bool
	clampTo  int
	failPets bool
}

func (d *fakeDevice) SetTimeout(s int) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.clampTo > 0 {
		s = d.clampTo
	}
	d.timeout = s
	return s, nil
}

type clk struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clk) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clk) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var devClock *clk

func (d *fakeDevice) Keepalive() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failPets {
		return errors.New("io")
	}
	d.pets = append(d.pets, devClock.now())
	return nil
}
func (d *fakeDevice) Close(magic bool) error {
	d.mu.Lock()
	d.closed, d.magic = true, magic
	d.mu.Unlock()
	return nil
}

// fired reports whether the device would have reset the server at now.
func (d *fakeDevice) fired(now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed && d.magic {
		return false
	}
	if len(d.pets) == 0 {
		return true
	}
	return now.Sub(d.pets[len(d.pets)-1]) >= time.Duration(d.timeout)*time.Second
}

func newFeeder(dev *fakeDevice) (*Feeder, *clk) {
	c := &clk{t: time.Unix(1000, 0)}
	devClock = c
	return &Feeder{Open: func() (Device, string, error) { return dev, KindHardware, nil }, Now: c.now, Interval: time.Hour}, c
}

func TestFeederPetsOnlyWithinTheDeadline(t *testing.T) {
	dev := &fakeDevice{}
	f, c := newFeeder(dev)
	defer f.Disarm()
	if _, err := f.Arm(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := f.Pet(15 * time.Second); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 14; i++ {
		c.add(time.Second)
		f.Tick()
	}
	if dev.fired(c.now()) {
		t.Fatal("fired while hardyd's deadline was valid")
	}
	// hardyd stops renewing (hung, or the lease ran out): root stops too.
	for i := 0; i < 11; i++ {
		c.add(time.Second)
		f.Tick()
	}
	if !dev.fired(c.now()) {
		t.Fatal("root kept petting past hardyd's deadline")
	}
	if st := f.Status(); st.PettingForMs != 0 || !st.Armed {
		t.Fatalf("%+v", st)
	}
}

func TestFeederExpireAndDisarm(t *testing.T) {
	dev := &fakeDevice{}
	f, c := newFeeder(dev)
	if _, err := f.Arm(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	_ = f.Pet(time.Minute)
	f.Expire()
	for i := 0; i < 10; i++ {
		c.add(time.Second)
		f.Tick()
	}
	if !dev.fired(c.now()) {
		t.Fatal("expire didn't stop the petting")
	}
	if err := f.Disarm(); err != nil {
		t.Fatal(err)
	}
	if !dev.closed || !dev.magic {
		t.Fatal("disarm didn't write the magic close")
	}
	if err := f.Pet(time.Second); err == nil {
		t.Fatal("pet after disarm")
	}
}

func TestFeederBounds(t *testing.T) {
	dev := &fakeDevice{}
	f, _ := newFeeder(dev)
	defer f.Disarm()
	if _, err := f.Arm(2 * time.Second); err == nil {
		t.Fatal("a 2 s timeout was accepted")
	}
	if _, err := f.Arm(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := f.Pet(time.Hour); err != nil {
		t.Fatal(err)
	}
	if st := f.Status(); st.PettingForMs > (2 * time.Minute).Milliseconds() {
		t.Fatalf("a pet was valid for %d ms", st.PettingForMs)
	}
	dev2 := &fakeDevice{clampTo: 30}
	f2, _ := newFeeder(dev2)
	defer f2.Disarm()
	if _, err := f2.Arm(10 * time.Second); err == nil {
		t.Fatal("a device that rounds the timeout up was accepted (it breaks F >= Q+W+10)")
	}
}

func TestDetectKind(t *testing.T) {
	cases := map[string]string{"iTCO_wdt": KindHardware, "Software Watchdog": KindSoftdog, "": KindNone}
	for id, want := range cases {
		fs := fstest.MapFS{}
		if id != "" {
			fs["sys/class/watchdog/watchdog0/identity"] = &fstest.MapFile{Data: []byte(id + "\n")}
		}
		if got := DetectKind(fs); got != want {
			t.Errorf("%q: got %q", id, got)
		}
	}
}

// ---- the agent --------------------------------------------------------------------

type fakeCluster struct {
	mu      sync.Mutex
	s       *cluster.Snapshot
	quorate bool
	until   time.Time
}

func (c *fakeCluster) Self() (cluster.Node, error) { return *c.s.Nodes["c1"], nil }
func (c *fakeCluster) State() cluster.State        { return view{c.s} }
func (c *fakeCluster) Quorate() (bool, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.quorate, c.until
}

type view struct{ s *cluster.Snapshot }

func (v view) Snapshot() *cluster.Snapshot                              { return v.s }
func (v view) Node(cluster.NodeID) (*cluster.Node, bool)                { return nil, false }
func (v view) Placement(cluster.WorkloadRef) (*cluster.Placement, bool) { return nil, false }
func (v view) Grant(cluster.WorkloadRef) (*cluster.Grant, bool)         { return nil, false }
func (v view) Index() uint64                                            { return 0 }

type wd struct {
	mu                       sync.Mutex
	armed                    bool
	pets                     []time.Duration
	expired, disarmed, fails int
	kind                     string
}

func (w *wd) Arm(context.Context, time.Duration) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.kind == "" {
		return "", ErrNoWatchdog
	}
	w.armed = true
	return w.kind, nil
}
func (w *wd) Pet(_ context.Context, d time.Duration) error {
	w.mu.Lock()
	w.pets = append(w.pets, d)
	w.mu.Unlock()
	return nil
}
func (w *wd) Disarm(context.Context) error {
	w.mu.Lock()
	w.armed = false
	w.disarmed++
	w.mu.Unlock()
	return nil
}
func (w *wd) Expire(context.Context) error {
	w.mu.Lock()
	w.expired++
	w.mu.Unlock()
	return nil
}

type fencer struct {
	mu    sync.Mutex
	calls [][]cluster.WorkloadRef
	err   error
}

func (f *fencer) SelfFence(_ context.Context, _ uint64, ws []cluster.WorkloadRef) error {
	f.mu.Lock()
	f.calls = append(f.calls, ws)
	f.mu.Unlock()
	return f.err
}

var vm = cluster.WorkloadRef{Kind: cluster.KindVM, ID: "web"}

func agentWorld(ha bool) (*Agent, *fakeCluster, *wd, *fencer, *[]cluster.WorkloadStatus) {
	s := &cluster.Snapshot{Timings: cluster.DefaultTimings, Nodes: map[cluster.NodeID]*cluster.Node{
		"c1": {ID: "c1", Role: cluster.RoleCompute, State: cluster.NodeActive}}, Placements: map[cluster.WorkloadRef]*cluster.Placement{},
		Fences: map[cluster.NodeID]*cluster.Fence{}}
	s.Placements[vm] = &cluster.Placement{Workload: vm, Owner: "c1", State: cluster.PlacementRunning, HA: cluster.HAPolicy{Enabled: ha}}
	now := time.Unix(5000, 0)
	c := &fakeCluster{s: s, quorate: true, until: now.Add(15 * time.Second)}
	w := &wd{kind: KindHardware}
	f := &fencer{}
	running := []cluster.WorkloadStatus{{Workload: vm, Running: true, Generation: 1}}
	a := &Agent{Cluster: c, Watchdog: w, Fencer: f, Now: func() time.Time { return now },
		Running: func(context.Context) ([]cluster.WorkloadStatus, error) { return running, nil }}
	return a, c, w, f, &running
}

func wait(a *Agent) {
	for i := 0; i < 1000; i++ {
		if r, _, _ := a.SelfFenceDone(); !r {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAgentArmsOnlyForHA(t *testing.T) {
	a, _, w, _, _ := agentWorld(false)
	a.Step(context.Background())
	if w.armed || a.State() != cluster.FenceDisarmed {
		t.Fatal("armed without HA workloads")
	}
	a, _, w, _, _ = agentWorld(true)
	a.Step(context.Background())
	if !w.armed || a.State() != cluster.FenceArmed || len(w.pets) != 1 || w.pets[0] != 15*time.Second {
		t.Fatalf("state %s pets %v", a.State(), w.pets)
	}
}

func TestAgentSelfFencesOnLeaseLoss(t *testing.T) {
	a, c, w, f, running := agentWorld(true)
	ctx := context.Background()
	a.Step(ctx)
	c.quorate = false
	a.Step(ctx)
	wait(a)
	if a.State() != cluster.FenceSelfFencing || w.expired != 1 || len(f.calls) != 1 || f.calls[0][0] != vm {
		t.Fatalf("state %s expired %d calls %v", a.State(), w.expired, f.calls)
	}
	*running = nil
	a.Step(ctx)
	if a.State() != cluster.FenceDisarmed || w.armed || w.disarmed != 1 {
		t.Fatalf("after a clean self-fence: %s armed %v", a.State(), w.armed)
	}
	// Without quorum it doesn't re-arm for workloads placed here.
	a.Step(ctx)
	if w.armed {
		t.Fatal("re-armed without quorum for placed workloads")
	}
}

func TestAgentStuckSelfFenceNeverPetsAgain(t *testing.T) {
	a, c, w, f, _ := agentWorld(true)
	ctx := context.Background()
	f.err = errors.New("stuck")
	a.Step(ctx)
	pets := len(w.pets)
	c.quorate = false
	a.Step(ctx)
	wait(a)
	c.quorate = true // quorum comes back: still no pets, the reset comes
	for i := 0; i < 5; i++ {
		a.Step(ctx)
	}
	if len(w.pets) != pets || w.disarmed != 0 || a.State() != cluster.FenceSelfFencing {
		t.Fatalf("pets %d->%d disarmed %d state %s", pets, len(w.pets), w.disarmed, a.State())
	}
}

func TestAgentObeysNodeIsolated(t *testing.T) {
	a, c, w, f, _ := agentWorld(true)
	ctx := context.Background()
	a.Step(ctx)
	c.s.Nodes["c1"].State = cluster.NodeDead
	c.s.Nodes["c1"].FenceEpoch = 1
	c.s.Fences["c1"] = &cluster.Fence{Node: "c1", Epoch: 1, Reason: "isolated"}
	a.Step(ctx)
	wait(a)
	if w.expired != 1 || len(f.calls) != 1 || a.Status().FenceReason != "isolated" {
		t.Fatalf("expired %d calls %v status %+v", w.expired, f.calls, a.Status())
	}
}

func TestAgentWithoutWatchdogStopsHA(t *testing.T) {
	a, _, w, f, _ := agentWorld(true)
	w.kind = ""
	a.Step(context.Background())
	wait(a)
	if len(f.calls) != 1 || a.Status().Problem == "" {
		t.Fatalf("HA workloads on a node whose watchdog can't be armed: calls %v status %+v", f.calls, a.Status())
	}
}

func TestAgentUnknownLocalListKeepsArmed(t *testing.T) {
	a, c, w, _, _ := agentWorld(true)
	ctx := context.Background()
	a.Step(ctx)
	a.Running = func(context.Context) ([]cluster.WorkloadStatus, error) { return nil, errors.New("hardyd-priv hung") }
	c.s.Placements[vm].Owner = "c2" // even if the state says it moved
	a.Step(ctx)
	if !w.armed || w.disarmed != 0 {
		t.Fatal("disarmed on a local list it couldn't read")
	}
}

func TestNoPower(t *testing.T) {
	if err := (NoPower{}).PowerOff(context.Background(), "c1"); !errors.Is(err, ErrNoPowerFencing) {
		t.Fatal(err)
	}
}
