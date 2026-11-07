package fence

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// ---- root (the feeder) ----------------------------------------------------------

func TestFeederRefusesDisarmWhileWorkloadsRun(t *testing.T) {
	dev := &fakeDevice{}
	f, c := newFeeder(dev)
	running := true
	f.Running = func(context.Context) (bool, error) { return running, nil }
	if _, err := f.Arm(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := f.DisarmChecked(context.Background()); !errors.Is(err, ErrStillRunning) {
		t.Fatalf("disarmed with cluster workloads running: %v", err)
	}
	f.Running = func(context.Context) (bool, error) { return true, errors.New("libvirt hung") }
	if err := f.DisarmChecked(context.Background()); err == nil {
		t.Fatal("disarmed without knowing what runs")
	}
	// Right after root's own self-fence the non-HA ones may stay.
	f.Running = func(context.Context) (bool, error) { return running, nil }
	f.SelfFenced()
	c.add(time.Minute)
	if err := f.DisarmChecked(context.Background()); err != nil {
		t.Fatalf("after a self-fence: %v", err)
	}
	if !dev.closed || !dev.magic {
		t.Fatal("not closed with the magic character")
	}
	// Long after it, the check holds again.
	dev2 := &fakeDevice{}
	f2, c2 := newFeeder(dev2)
	f2.Running = func(context.Context) (bool, error) { return true, nil }
	_, _ = f2.Arm(10 * time.Second)
	f2.SelfFenced()
	c2.add(10 * time.Minute)
	if err := f2.DisarmChecked(context.Background()); !errors.Is(err, ErrStillRunning) {
		t.Fatalf("an old self-fence still allowed a disarm: %v", err)
	}
}

func TestFeederNeverDisarmsNoWayOut(t *testing.T) {
	dev := &fakeDevice{}
	f, _ := newFeeder(dev)
	f.NoWayOut = func() bool { return true }
	if _, err := f.Arm(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	if !f.Status().NoWayOut {
		t.Fatal("status doesn't say nowayout")
	}
	if err := f.DisarmChecked(context.Background()); !errors.Is(err, ErrNoWayOut) {
		t.Fatalf("%v", err)
	}
	if dev.closed {
		t.Fatal("a nowayout device was closed (it would reset the server)")
	}
	fs := fstest.MapFS{"sys/class/watchdog/watchdog0/nowayout": &fstest.MapFile{Data: []byte("1\n")}}
	if !DetectNoWayOut(fs) || DetectNoWayOut(fstest.MapFS{}) {
		t.Fatal("DetectNoWayOut")
	}
}

func TestFeederStopsPettingAfterASuspend(t *testing.T) {
	dev := &fakeDevice{}
	f, c := newFeeder(dev)
	mono := time.Unix(77, 0)
	f.Mono = func() time.Time { return mono }
	if _, err := f.Arm(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := f.Pet(time.Minute); err != nil {
		t.Fatal(err)
	}
	c.add(time.Second)
	mono = mono.Add(time.Second)
	f.Tick()
	pets := len(dev.pets)
	// Suspended for 30 s: the boot clock ran, the monotonic one didn't.
	c.add(30 * time.Second)
	f.Tick()
	c.add(time.Second)
	mono = mono.Add(time.Second)
	f.Tick()
	if len(dev.pets) != pets {
		t.Fatal("root kept petting on a deadline from before a suspend")
	}
	if st := f.Status(); st.PettingForMs != 0 || !strings.Contains(st.Problem, "suspended") {
		t.Fatalf("%+v", st)
	}
}

func TestFeederInstanceChangesPerStart(t *testing.T) {
	a, _ := newFeeder(&fakeDevice{})
	b, _ := newFeeder(&fakeDevice{})
	if a.Status().Instance == "" || a.Status().Instance == b.Status().Instance || a.Status().Instance != a.Status().Instance {
		t.Fatal("instance ids")
	}
}

// ---- lease statements ----------------------------------------------------------

type leader struct {
	key *ecdsa.PrivateKey
	der []byte
}

func newLeader(t *testing.T) leader {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return leader{k, der}
}

func (l leader) sign(t *testing.T, st LeaseStatement) []byte {
	b, _ := json.Marshal(st)
	sum := sha256.Sum256(b)
	sig, err := ecdsa.SignASN1(rand.Reader, l.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(SignedLease{Statement: b, Signature: sig})
	return out
}

func TestLeaseStatementsPinnedInRoot(t *testing.T) {
	l, other := newLeader(t), newLeader(t)
	keys := LeaseKeys{Cluster: "abc", Node: "c1", Voters: map[string][]byte{"c2": l.der}}
	now := time.Now()
	st := LeaseStatement{Cluster: "abc", Leader: "c2", Node: "c1", Term: 3, IssuedMs: now.UnixMilli(), ValidMs: 15000}
	v := &ES256Leases{}
	d, err := v.Verify(l.sign(t, st), &keys, now.Add(time.Second))
	if err != nil || d > 14*time.Second || d < 13*time.Second {
		t.Fatalf("%s %v", d, err)
	}
	bad := map[string][]byte{
		"another key":     other.sign(t, st),
		"another node":    l.sign(t, LeaseStatement{Cluster: "abc", Leader: "c2", Node: "c3", IssuedMs: now.UnixMilli(), ValidMs: 15000}),
		"another cluster": l.sign(t, LeaseStatement{Cluster: "xyz", Leader: "c2", Node: "c1", IssuedMs: now.UnixMilli(), ValidMs: 15000}),
		"not a voter":     l.sign(t, LeaseStatement{Cluster: "abc", Leader: "c9", Node: "c1", IssuedMs: now.UnixMilli(), ValidMs: 15000}),
		"stale":           l.sign(t, LeaseStatement{Cluster: "abc", Leader: "c2", Node: "c1", IssuedMs: now.Add(-time.Minute).UnixMilli(), ValidMs: 15000}),
		"older replay":    l.sign(t, LeaseStatement{Cluster: "abc", Leader: "c2", Node: "c1", IssuedMs: now.Add(-2 * time.Second).UnixMilli(), ValidMs: 15000}),
		"garbage":         []byte(`{"statement":"x"}`),
	}
	for name, raw := range bad {
		if _, err := v.Verify(raw, &keys, now.Add(time.Second)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// In root: with keys pinned and workloads running, an unsigned pet is
	// refused; the statement's validity bounds the deadline.
	dev := &fakeDevice{}
	f, _ := newFeeder(dev)
	f.Running = func(context.Context) (bool, error) { return true, nil }
	if err := f.PinKeys(keys); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Arm(10 * time.Second); err != nil {
		t.Fatal(err)
	}
	if err := f.PinKeys(LeaseKeys{Cluster: "abc", Node: "c1", Voters: map[string][]byte{"c9": other.der}}); err == nil {
		t.Fatal("keys were swapped while armed")
	}
	if err := f.PetLease(context.Background(), time.Minute, nil); !errors.Is(err, ErrLeaseNeeded) {
		t.Fatalf("an unsigned pet with workloads running: %v", err)
	}
	st.IssuedMs = time.Now().UnixMilli()
	st.ValidMs = 5000
	if err := f.PetLease(context.Background(), time.Minute, l.sign(t, st)); err != nil {
		t.Fatal(err)
	}
	if ms := f.Status().PettingForMs; ms > 5000 || ms < 3000 {
		t.Fatalf("root pets for %d ms, the statement granted 5000", ms)
	}
	if err := f.PetLease(context.Background(), time.Minute, other.sign(t, st)); err == nil {
		t.Fatal("a statement signed by an unknown key was accepted")
	}
	// Nothing runs: unsigned pets are fine (an idle armed watchdog).
	f.Running = func(context.Context) (bool, error) { return false, nil }
	if err := f.PetLease(context.Background(), time.Minute, nil); err != nil {
		t.Fatal(err)
	}
}

// ---- the agent -------------------------------------------------------------------

// rootWD is a watchdog whose root view can be read (instance, nowayout)
// and whose disarm root may refuse.
type rootWD struct {
	wd
	instance  string
	nowayout  bool
	refuse    error
	timeouts  []time.Duration
	rootArmed bool
}

func (r *rootWD) Arm(ctx context.Context, d time.Duration) (string, error) {
	r.mu.Lock()
	r.timeouts = append(r.timeouts, d)
	r.rootArmed = true
	r.mu.Unlock()
	return r.wd.Arm(ctx, d)
}

func (r *rootWD) Disarm(ctx context.Context) error {
	if r.refuse != nil {
		return r.refuse
	}
	r.mu.Lock()
	r.rootArmed = false
	r.mu.Unlock()
	return r.wd.Disarm(ctx)
}

func (r *rootWD) Status(context.Context) (Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return Status{Armed: r.rootArmed, Kind: KindHardware, Instance: r.instance, NoWayOut: r.nowayout, TimeoutSec: 10}, nil
}

func TestAgentStartupGrace(t *testing.T) {
	a, c, w, f, _ := agentWorld(true)
	now := time.Unix(5000, 0)
	a.Now = func() time.Time { return now }
	c.quorate = false // hardyd just started: no lease yet
	a.Step(context.Background())
	if len(f.calls) != 0 || w.expired != 0 {
		t.Fatal("self-fenced before the first heartbeat could be answered")
	}
	now = now.Add(cluster.DefaultTimings.QuorumLease)
	a.Step(context.Background())
	wait(a)
	if len(f.calls) != 1 {
		t.Fatal("never self-fenced after the grace")
	}
}

func TestAgentAdoptsRootsArmAndReArmsAfterARootRestart(t *testing.T) {
	a, _, _, _, _ := agentWorld(true)
	r := &rootWD{wd: wd{kind: KindHardware}, instance: "one", rootArmed: true}
	a.Watchdog = r
	var seen []AgentStatus
	a.OnChange = func(st AgentStatus) { seen = append(seen, st) }
	a.Step(context.Background())
	if a.State() != cluster.FenceArmed || !a.Ready() {
		t.Fatalf("didn't adopt root's arm: %s", a.State())
	}
	// hardyd-priv restarted: a new instance, the device closed.
	r.mu.Lock()
	r.instance, r.rootArmed = "two", false
	r.mu.Unlock()
	a.Step(context.Background())
	if !r.rootArmed {
		t.Fatal("not armed again after hardyd-priv restarted")
	}
	alerted := false
	for _, st := range seen {
		alerted = alerted || strings.Contains(st.Problem, "hardyd-priv restarted")
	}
	if !alerted {
		t.Fatalf("no alert: %+v", seen)
	}
}

func TestAgentReArmsWhenTheWatchdogTimeoutChanges(t *testing.T) {
	a, c, _, _, _ := agentWorld(true)
	r := &rootWD{wd: wd{kind: KindHardware}, instance: "one"}
	a.Watchdog = r
	a.Step(context.Background())
	c.s.Timings.Watchdog = 20 * time.Second
	c.s.Timings.Dead = 60 * time.Second
	a.Step(context.Background())
	if len(r.timeouts) != 2 || r.timeouts[1] != 20*time.Second {
		t.Fatalf("arms: %v", r.timeouts)
	}
}

func TestAgentStaysArmedWhenItCantDisarm(t *testing.T) {
	for name, set := range map[string]func(*rootWD){
		"nowayout": func(r *rootWD) { r.nowayout = true },
		"root refuses": func(r *rootWD) {
			r.refuse = errors.New("cluster workloads still run on this server: the watchdog stays armed")
		},
	} {
		a, c, _, _, running := agentWorld(true)
		r := &rootWD{wd: wd{kind: KindHardware}, instance: "one"}
		set(r)
		a.Watchdog = r
		a.Step(context.Background())
		// The HA workload moved away.
		c.s.Placements[vm].Owner = "c2"
		*running = nil
		a.Step(context.Background())
		st := a.Status()
		if a.State() != cluster.FenceArmed || !st.Idle || r.disarmed != 0 {
			t.Fatalf("%s: state %s %+v", name, a.State(), st)
		}
		pets := len(r.pets)
		a.Step(context.Background())
		if len(r.pets) <= pets {
			t.Fatalf("%s: an idle armed watchdog isn't petted", name)
		}
		// Quorum lost with nothing HA here: nothing to fence, still petted.
		c.quorate = false
		pets = len(r.pets)
		a.Step(context.Background())
		if len(r.pets) <= pets || a.State() != cluster.FenceArmed {
			t.Fatalf("%s: idle without quorum: %s", name, a.State())
		}
	}
}

func TestAgentTreatsASuspendAsLeaseLoss(t *testing.T) {
	a, _, w, f, _ := agentWorld(true)
	boot, mono := time.Unix(100, 0), time.Unix(50, 0)
	a.Boot = func() time.Time { return boot }
	a.Mono = func() time.Time { return mono }
	a.Step(context.Background())
	if a.State() != cluster.FenceArmed {
		t.Fatal(a.State())
	}
	// Slept for a minute: the lease (monotonic) still looks valid.
	boot = boot.Add(time.Minute)
	a.Step(context.Background())
	wait(a)
	if len(f.calls) != 1 || w.expired == 0 {
		t.Fatalf("a suspend didn't count as a lost lease: calls %v", f.calls)
	}
}

func TestAgentRecordsAnObeyedFence(t *testing.T) {
	a, c, _, _, running := agentWorld(true)
	ctx := context.Background()
	a.Step(ctx)
	c.s.Nodes["c1"].State = cluster.NodeDead
	c.s.Nodes["c1"].FenceEpoch = 4
	c.s.Fences["c1"] = &cluster.Fence{Node: "c1", Epoch: 4, Reason: "isolated"}
	a.Step(ctx)
	wait(a)
	*running = nil
	a.Step(ctx)
	if !a.CleanFence(4) || a.CleanFence(3) {
		t.Fatal("the obeyed fence wasn't recorded")
	}
	// A lease loss alone isn't a fence obeyed.
	b, c2, _, _, _ := agentWorld(true)
	b.Step(ctx)
	c2.quorate = false
	b.Step(ctx)
	wait(b)
	if b.CleanFence(0) || b.CleanFence(1) {
		t.Fatal("a lease loss counted as an obeyed fence")
	}
}
