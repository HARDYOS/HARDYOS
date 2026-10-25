package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// fakePriv answers root-helper calls from handler funcs and records them.
type fakePriv struct {
	mu       sync.Mutex
	handlers map[string]func(args json.RawMessage) (any, error)
	calls    []string
}

func (f *fakePriv) on(op string, fn func(args json.RawMessage) (any, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.handlers == nil {
		f.handlers = map[string]func(json.RawMessage) (any, error){}
	}
	f.handlers[op] = fn
}

func (f *fakePriv) Call(ctx context.Context, op string, args any, out any) error {
	raw, _ := json.Marshal(args)
	f.mu.Lock()
	f.calls = append(f.calls, op+" "+string(raw))
	fn := f.handlers[op]
	f.mu.Unlock()
	if fn == nil {
		return fmt.Errorf("fakePriv: unexpected op %s", op)
	}
	res, err := fn(raw)
	if err != nil {
		return err
	}
	if out != nil {
		b, _ := json.Marshal(res)
		return json.Unmarshal(b, out)
	}
	return nil
}

func (f *fakePriv) called(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

func newService(t *testing.T) (*Service, *fakePriv, *notify.Center) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	fp := &fakePriv{}
	nc := &notify.Center{DB: db, Events: events.NewBroker()}
	return &Service{Priv: fp, DB: db, Notify: nc, Monitor: time.Millisecond}, fp, nc
}

func ok(v any) func(json.RawMessage) (any, error) {
	return func(json.RawMessage) (any, error) { return v, nil }
}

func TestCreatePoolJob(t *testing.T) {
	svc, fp, nc := newService(t)
	fp.on(priv.OpPoolCreate, ok(zfs.Status{Name: "tank", State: "ONLINE"}))
	fp.on(priv.OpDatasetCreate, ok([]zfs.Dataset{}))
	fp.on(priv.OpHWSystem, ok(hw.System{Memory: hw.Memory{TotalBytes: 128 * hw.GiB}, CPU: hw.CPU{Virtualization: "vt-x"}}))
	fp.on(priv.OpHWDisks, ok([]hw.Disk{}))
	fp.on(priv.OpARCSet, ok(map[string]any{}))

	m := &jobs.Manager{DB: svc.DB}
	svc.RegisterJobs(m)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); m.Wait() }()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	spec := zfs.PoolSpec{Name: "tank", Data: []zfs.VdevSpec{{Type: zfs.Mirror, Disks: []string{"/dev/disk/by-id/ata-a", "/dev/disk/by-id/ata-b"}}}}
	j, err := m.Submit(ctx, KindPoolCreate, "Create tank", CreatePoolParams{Spec: spec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var done *jobs.Job
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if done, _ = m.Get(ctx, j.ID); done.State.Done() {
			break
		}
	}
	if done.State != jobs.Succeeded {
		t.Fatalf("job = %+v", done)
	}
	if !strings.Contains(fp.called(priv.OpPoolCreate)[0], `"confirmWipe":true`) {
		t.Error("create must pass confirmWipe")
	}
	if n := len(fp.called(priv.OpDatasetCreate)); n != len(StandardDatasets) {
		t.Errorf("created %d datasets, want %d", n, len(StandardDatasets))
	}
	if len(fp.called(priv.OpARCSet)) != 1 {
		t.Error("ARC limit not applied on first pool")
	}
	pols, _ := svc.ListSnapshotPolicies(ctx)
	scrubs, _ := svc.ListScrubPolicies(ctx)
	if len(pols) != 4 || len(scrubs) != 1 || scrubs[0].IntervalDays != 30 {
		t.Errorf("default policies: %d snapshot, %+v scrub", len(pols), scrubs)
	}
	list, _ := nc.List(ctx, true, 10)
	if len(list) != 1 || !strings.Contains(list[0].Title, "tank is ready") {
		t.Errorf("notifications = %+v", list)
	}
}

func TestSnapshotScheduleAndRetention(t *testing.T) {
	svc, fp, _ := newService(t)
	ctx := context.Background()
	if _, err := svc.SaveSnapshotPolicy(ctx, SnapshotPolicy{Dataset: "tank/users", Frequency: "daily", Keep: 2, Recursive: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	var existing []zfs.Snapshot
	for _, day := range []string{"20261020", "20261021", "20261022"} {
		for _, ds := range []string{"tank/users", "tank/users/cade"} {
			existing = append(existing, zfs.Snapshot{Name: ds + "@auto-daily-" + day + "-0000", Dataset: ds, Label: "auto-daily-" + day + "-0000"})
		}
	}
	existing = append(existing, zfs.Snapshot{Name: "tank/users@before-upgrade", Dataset: "tank/users", Label: "before-upgrade"})
	fp.on(priv.OpSnapshotCreate, func(raw json.RawMessage) (any, error) {
		var a priv.SnapshotCreateArgs
		_ = json.Unmarshal(raw, &a)
		for _, ds := range []string{"tank/users", "tank/users/cade"} {
			existing = append(existing, zfs.Snapshot{Name: ds + "@" + a.Label, Dataset: ds, Label: a.Label})
		}
		return nil, nil
	})
	fp.on(priv.OpSnapshots, func(json.RawMessage) (any, error) { return existing, nil })
	fp.on(priv.OpSnapshotDestroy, ok(nil))
	fp.on(priv.OpPools, ok([]zfs.Pool{}))
	fp.on(priv.OpHWDisks, ok([]hw.Disk{}))

	now := time.Date(2026, 10, 23, 0, 0, 30, 0, time.UTC)
	svc.Tick(ctx, now)

	destroyed := fp.called(priv.OpSnapshotDestroy)
	if len(destroyed) != 4 {
		t.Fatalf("destroyed %d snapshots, want 4 (2 oldest per dataset): %v", len(destroyed), destroyed)
	}
	all := strings.Join(destroyed, "\n")
	if !strings.Contains(all, "20261020") || !strings.Contains(all, "20261021") || strings.Contains(all, "before-upgrade") || strings.Contains(all, "20261022") {
		t.Errorf("wrong snapshots destroyed:\n%s", all)
	}
	if !strings.Contains(fp.called(priv.OpSnapshotCreate)[0], "auto-daily-20261023-0000") {
		t.Errorf("label = %v", fp.called(priv.OpSnapshotCreate))
	}

	// Not due again an hour later.
	svc.Tick(ctx, now.Add(time.Hour))
	if n := len(fp.called(priv.OpSnapshotCreate)); n != 1 {
		t.Fatalf("snapshot taken again too soon (%d)", n)
	}
	svc.Tick(ctx, now.Add(24*time.Hour))
	if n := len(fp.called(priv.OpSnapshotCreate)); n != 2 {
		t.Fatalf("daily snapshot not taken next day (%d)", n)
	}
}

func TestScrubSchedule(t *testing.T) {
	svc, fp, _ := newService(t)
	ctx := context.Background()
	if _, err := svc.SaveScrubPolicy(ctx, ScrubPolicy{Pool: "tank", IntervalDays: 30, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	finished := time.Date(2026, 10, 1, 5, 0, 0, 0, time.UTC)
	fp.on(priv.OpPoolStatus, ok(zfs.Status{Name: "tank", Scan: zfs.Scan{Kind: "scrub", State: "finished", FinishedAt: &finished}}))
	fp.on(priv.OpPoolScrub, ok(nil))
	fp.on(priv.OpPools, ok([]zfs.Pool{}))
	fp.on(priv.OpHWDisks, ok([]hw.Disk{}))

	svc.Tick(ctx, finished.Add(10*24*time.Hour))
	if len(fp.called(priv.OpPoolScrub)) != 0 {
		t.Fatal("scrubbed 10 days after the last one")
	}
	svc.Tick(ctx, finished.Add(31*24*time.Hour))
	if len(fp.called(priv.OpPoolScrub)) != 1 {
		t.Fatal("no scrub after 31 days")
	}
}

func TestPoolHealthAndSMARTNotifications(t *testing.T) {
	svc, fp, nc := newService(t)
	ctx := context.Background()
	health := "ONLINE"
	fp.on(priv.OpPools, func(json.RawMessage) (any, error) { return []zfs.Pool{{Name: "tank", Health: health}}, nil })
	fp.on(priv.OpHWDisks, ok([]hw.Disk{{Name: "sda", ByID: "/dev/disk/by-id/ata-A", Model: "WD", Serial: "1"}, {Name: "sdx", ByID: "/dev/sdx", Removable: true}}))
	smartHealth := hw.HealthGood
	fp.on(priv.OpHWSmart, func(json.RawMessage) (any, error) {
		return hw.SMART{Health: smartHealth, Reasons: []string{"8 reallocated sectors"}}, nil
	})

	now := time.Now()
	svc.Tick(ctx, now) // first sight: healthy pool, good disk -> no notifications
	if list, _ := nc.List(ctx, true, 10); len(list) != 0 {
		t.Fatalf("unexpected notifications: %+v", list)
	}
	health, smartHealth = "DEGRADED", hw.HealthWarning
	svc.Tick(ctx, now.Add(SMARTInterval+time.Minute))
	list, _ := nc.List(ctx, true, 10)
	titles := []string{}
	for _, n := range list {
		titles = append(titles, n.Title)
	}
	joined := strings.Join(titles, " | ")
	if !strings.Contains(joined, "tank is degraded") || !strings.Contains(joined, "sda health: warning") {
		t.Fatalf("notifications = %s", joined)
	}
	for _, c := range fp.called(priv.OpHWSmart) {
		if strings.Contains(c, "sdx") {
			t.Fatal("removable disk was SMART-checked")
		}
	}
	h, _ := svc.DiskHealthAll(ctx)
	if len(h) != 1 || h[0].Health != hw.HealthWarning {
		t.Fatalf("disk health = %+v", h)
	}
}

func TestPolicyValidation(t *testing.T) {
	svc, _, _ := newService(t)
	ctx := context.Background()
	bad := []SnapshotPolicy{
		{Dataset: "tank/../x", Frequency: "daily", Keep: 1},
		{Dataset: "tank/users", Frequency: "yearly", Keep: 1},
		{Dataset: "tank/users", Frequency: "daily", Keep: 0},
	}
	for _, p := range bad {
		if _, err := svc.SaveSnapshotPolicy(ctx, p); err == nil {
			t.Errorf("accepted %+v", p)
		}
	}
	if _, err := svc.SaveSnapshotPolicy(ctx, SnapshotPolicy{Dataset: "tank/users", Frequency: "daily", Keep: 7, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SaveSnapshotPolicy(ctx, SnapshotPolicy{Dataset: "tank/users", Frequency: "daily", Keep: 7}); err == nil {
		t.Error("duplicate policy accepted")
	}
	if _, err := svc.SaveScrubPolicy(ctx, ScrubPolicy{Pool: "tank", IntervalDays: 0}); err == nil {
		t.Error("zero interval accepted")
	}
}
