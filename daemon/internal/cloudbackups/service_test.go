package cloudbackups

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cloudbackup"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

type env struct {
	svc    *Service
	jobs   *jobs.Manager
	mu     sync.Mutex
	now    time.Time
	events []Event
	ops    []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{now: time.Date(2026, 10, 27, 1, 0, 0, 0, time.Local)}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	ps.Handle(priv.OpCloudTargets, func(context.Context, json.RawMessage) (any, error) {
		return priv.CloudTargetsResult{Targets: []cloudbackup.Target{{ID: "off", Name: "Offsite", Kind: "b2", Bucket: "bucket-1"}}}, nil
	})
	done := func(op string) priv.HandlerFunc {
		return func(context.Context, json.RawMessage) (any, error) {
			e.mu.Lock()
			e.ops = append(e.ops, op)
			e.mu.Unlock()
			return cloudbackup.Task{ID: op, Done: true, Error: map[bool]string{true: "repository damaged"}[op == "check"]}, nil
		}
	}
	ps.Handle(priv.OpCloudBackup, done("backup"))
	ps.Handle(priv.OpCloudPrune, done("prune"))
	ps.Handle(priv.OpCloudCheck, done("check"))
	ps.Handle(priv.OpCloudTask, func(_ context.Context, raw json.RawMessage) (any, error) {
		var a priv.CloudTaskRef
		_ = json.Unmarshal(raw, &a)
		return cloudbackup.Task{ID: a.ID, Done: true, Error: map[bool]string{true: "repository damaged"}[a.ID == "check"]}, nil
	})
	go func() { _ = ps.Serve(ctx, ln) }()
	m := &jobs.Manager{DB: db}
	e.jobs = m
	e.svc = &Service{DB: db, Priv: priv.NewClient(sock), Jobs: m, Poll: 5 * time.Millisecond, Dir: t.TempDir(),
		Now:      func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now },
		Notifier: NotifierFunc(func(_ context.Context, ev Event) { e.mu.Lock(); e.events = append(e.events, ev); e.mu.Unlock() })}
	e.svc.RegisterJobs(m)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); m.Wait(); db.Close() })
	return e
}

func (e *env) set(t time.Time) { e.mu.Lock(); e.now = t; e.mu.Unlock() }

func (e *env) jobCount(t *testing.T, kind string) int {
	l, err := e.jobs.List(context.Background(), nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, j := range l {
		if j.Kind == kind {
			n++
		}
	}
	return n
}

func (e *env) waitJobs(t *testing.T) {
	for i := 0; i < 200; i++ {
		l, _ := e.jobs.List(context.Background(), nil, 100)
		busy := false
		for _, j := range l {
			busy = busy || !j.State.Done()
		}
		if !busy {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("jobs didn't finish")
}

func TestScheduleRunsMissesAndUpkeep(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	task, err := e.svc.CreateTask(ctx, TaskInput{Name: "Nightly", Target: "off", Items: []cloudbackup.Item{{Kind: "share", ID: "media"}}})
	if err != nil {
		t.Fatal(err)
	}
	day := func(d, h, m int) time.Time { return time.Date(2026, 10, d, h, m, 0, 0, time.Local) }

	// Not due yet; the maintenance slot is seen for the first time.
	e.svc.Tick(ctx, day(27, 1, 0))
	if n := e.jobCount(t, JobRun); n != 0 {
		t.Fatalf("%d runs before the slot", n)
	}
	// Due: one run, then nothing more in the same slot.
	e.set(day(27, 1, 30))
	e.svc.Tick(ctx, day(27, 1, 30))
	e.waitJobs(t)
	e.svc.Tick(ctx, day(27, 1, 31))
	e.waitJobs(t)
	if n := e.jobCount(t, JobRun); n != 1 {
		t.Fatalf("%d runs in one slot", n)
	}
	runs, _ := e.svc.Runs(ctx, task.ID, 10)
	if len(runs) != 1 || runs[0].State != RunSucceeded || runs[0].Trigger != "schedule" {
		t.Fatalf("runs: %+v", runs)
	}
	// The server was off over the next two slots: one missed report for
	// the newest, no catch-up run.
	e.set(day(29, 9, 0))
	e.svc.Tick(ctx, day(29, 9, 0))
	e.waitJobs(t)
	if n := e.jobCount(t, JobRun); n != 1 {
		t.Fatalf("a missed slot was run late (%d runs)", n)
	}
	runs, _ = e.svc.Runs(ctx, task.ID, 10)
	if len(runs) != 2 || runs[0].State != RunMissed {
		t.Fatalf("no missed run: %+v", runs)
	}
	kinds := map[string]int{}
	for _, ev := range e.events {
		kinds[ev.Kind]++
	}
	if kinds[EventBackupSucceeded] != 1 || kinds[EventBackupMissed] != 1 {
		t.Fatalf("events: %+v", e.events)
	}
	// Sunday 04:30: prune, then a check that fails and says so.
	sunday := time.Date(2026, 11, 1, 4, 30, 0, 0, time.Local)
	e.set(sunday)
	e.svc.Tick(ctx, sunday)
	e.waitJobs(t)
	if e.jobCount(t, JobPrune) != 1 || e.jobCount(t, JobCheck) != 1 {
		t.Fatalf("upkeep jobs: prune %d check %d", e.jobCount(t, JobPrune), e.jobCount(t, JobCheck))
	}
	found := false
	for _, ev := range e.events {
		found = found || (ev.Kind == EventCheckFailed && ev.Severity == SeverityCritical)
	}
	if !found {
		t.Fatalf("no check-failed event: %+v", e.events)
	}
	// A disabled task isn't scheduled.
	off := false
	if _, err := e.svc.UpdateTask(ctx, task.ID, TaskInput{Name: "Nightly", Target: "off", Items: task.Items, Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	e.set(day(30, 1, 30))
	e.svc.Tick(ctx, time.Date(2026, 11, 2, 1, 30, 0, 0, time.Local))
	e.waitJobs(t)
	if n := e.jobCount(t, JobRun); n != 1 {
		t.Fatalf("a disabled task ran (%d)", n)
	}
	// Runs left running by a crashed hardyd are failed at start.
	_, _ = e.svc.DB.ExecContext(ctx, `INSERT INTO backup_runs (id, task_id, kind, target, state, started_at) VALUES ('zz', ?, 'backup', 'off', 'running', ?)`, task.ID, store.Now())
	e.svc.Recover(ctx)
	all, _ := e.svc.Runs(ctx, task.ID, 100)
	recovered := false
	for _, r := range all {
		recovered = recovered || (r.ID == "zz" && r.State == RunFailed)
	}
	if !recovered {
		t.Fatalf("recover: %+v", all)
	}
}

func TestTaskValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, in := range []TaskInput{
		{Name: "", Target: "off", Items: []cloudbackup.Item{{Kind: "system"}}},
		{Name: "x", Target: "nope", Items: []cloudbackup.Item{{Kind: "system"}}},
		{Name: "x", Target: "off"},
		{Name: "x", Target: "off", Items: []cloudbackup.Item{{Kind: "system"}, {Kind: "system"}}},
		{Name: "x", Target: "off", Items: []cloudbackup.Item{{Kind: "disk", ID: "sda"}}},
		{Name: "x", Target: "off", Items: []cloudbackup.Item{{Kind: "system"}}, Retention: &cloudbackup.Retention{}},
		{Name: "x", Target: "off", Items: []cloudbackup.Item{{Kind: "system"}}, Schedule: &Schedule{Frequency: "hourly", Time: "00:00", EveryHours: 7}},
		{Name: "x\nnewline", Target: "off", Items: []cloudbackup.Item{{Kind: "system"}}},
	} {
		if _, err := e.svc.CreateTask(ctx, in); err == nil {
			t.Errorf("accepted %+v", in)
		}
	}
}
