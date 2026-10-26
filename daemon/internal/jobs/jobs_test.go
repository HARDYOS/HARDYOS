package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func newManager(t *testing.T) (*Manager, func() error) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "j.db"))
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{DB: db, Events: events.NewBroker(), Workers: 2}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		m.Wait()
		db.Close()
	})
	return m, func() error { return m.Start(ctx) }
}

func waitDone(t *testing.T, m *Manager, id string) *Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		j, err := m.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if j.State.Done() {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s did not finish", id)
	return nil
}

func TestJobSucceedsWithResultAndProgress(t *testing.T) {
	m, start := newManager(t)
	m.Register(Kind{Name: "test.add", Run: func(jc *Context) (any, error) {
		var p struct{ A, B int }
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(50, "adding")
		return map[string]int{"sum": p.A + p.B}, nil
	}})
	sub := m.Events.Subscribe(1, true, 32)
	if err := start(); err != nil {
		t.Fatal(err)
	}

	j, err := m.Submit(context.Background(), "test.add", "Add numbers", map[string]int{"A": 2, "B": 3}, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := waitDone(t, m, j.ID)
	if done.State != Succeeded || done.Progress != 100 {
		t.Fatalf("job = %+v", done)
	}
	var res map[string]int
	_ = json.Unmarshal(done.Result, &res)
	if res["sum"] != 5 {
		t.Fatalf("result = %s", done.Result)
	}
	if len(sub.C) < 3 {
		t.Fatalf("expected queued/running/progress/succeeded events, got %d", len(sub.C))
	}
}

func TestJobFailureAndPanic(t *testing.T) {
	m, start := newManager(t)
	m.Register(Kind{Name: "test.fail", Run: func(jc *Context) (any, error) { return nil, errors.New("disk on fire") }})
	m.Register(Kind{Name: "test.panic", Run: func(jc *Context) (any, error) { panic("boom") }})
	_ = start()

	a, _ := m.Submit(context.Background(), "test.fail", "fail", nil, nil)
	b, _ := m.Submit(context.Background(), "test.panic", "panic", nil, nil)
	if j := waitDone(t, m, a.ID); j.State != Failed || j.Error != "disk on fire" {
		t.Fatalf("fail job = %+v", j)
	}
	if j := waitDone(t, m, b.ID); j.State != Failed {
		t.Fatalf("panic job = %+v", j)
	}
}

func TestCancelRunningJob(t *testing.T) {
	m, start := newManager(t)
	started := make(chan struct{})
	m.Register(Kind{Name: "test.slow", Run: func(jc *Context) (any, error) {
		close(started)
		<-jc.Done()
		return nil, jc.Err()
	}})
	_ = start()
	j, _ := m.Submit(context.Background(), "test.slow", "slow", nil, nil)
	<-started
	if err := m.Cancel(context.Background(), j.ID); err != nil {
		t.Fatal(err)
	}
	if done := waitDone(t, m, j.ID); done.State != Cancelled {
		t.Fatalf("state = %s", done.State)
	}
}

func TestLockKeySerializes(t *testing.T) {
	m, start := newManager(t)
	var running, maxRunning atomic.Int32
	m.Register(Kind{
		Name:    "test.pool",
		LockKey: func(json.RawMessage) string { return "pool:tank" },
		Run: func(jc *Context) (any, error) {
			n := running.Add(1)
			for {
				old := maxRunning.Load()
				if n <= old || maxRunning.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(30 * time.Millisecond)
			running.Add(-1)
			return nil, nil
		},
	})
	_ = start()
	a, _ := m.Submit(context.Background(), "test.pool", "a", nil, nil)
	b, _ := m.Submit(context.Background(), "test.pool", "b", nil, nil)
	waitDone(t, m, a.ID)
	waitDone(t, m, b.ID)
	if maxRunning.Load() != 1 {
		t.Fatalf("jobs with the same lock overlapped (max %d)", maxRunning.Load())
	}
}

func TestStartFailsInterruptedJobs(t *testing.T) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "j.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO jobs (id, kind, title, state, created_at) VALUES ('job_old', 'x', 'old', 'running', ?)`, store.Now()); err != nil {
		t.Fatal(err)
	}
	m := &Manager{DB: db}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); m.Wait() }()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	j, _ := m.Get(context.Background(), "job_old")
	if j.State != Failed {
		t.Fatalf("leftover job state = %s, want failed", j.State)
	}
}

func TestUnknownKind(t *testing.T) {
	m, start := newManager(t)
	_ = start()
	if _, err := m.Submit(context.Background(), "nope", "x", nil, nil); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("err = %v", err)
	}
}

func TestFailedJobKeepsAResult(t *testing.T) {
	m, start := newManager(t)
	m.Register(Kind{Name: "test.partial", Run: func(jc *Context) (any, error) {
		return nil, &FailedWith{Err: errors.New("step 2 broke"), Result: map[string]string{"snapshot": "s1"}}
	}})
	if err := start(); err != nil {
		t.Fatal(err)
	}
	j, err := m.Submit(context.Background(), "test.partial", "Partial", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	j = waitDone(t, m, j.ID)
	var res map[string]string
	_ = json.Unmarshal(j.Result, &res)
	if j.State != Failed || j.Error != "step 2 broke" || res["snapshot"] != "s1" {
		t.Fatalf("job: %+v %s", j, j.Result)
	}
}
