package cloudbackup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Backups, restores, prunes and checks take far longer than one priv
// operation may: they run as tasks inside hardyd-priv, which hardyd's job
// follows (cloudbackup.task) and cancels (cloudbackup.cancel). Cancelling
// interrupts restic's whole process group.

// Task kinds.
const (
	TaskBackup  = "backup"
	TaskRestore = "restore"
	TaskPrune   = "prune"
	TaskCheck   = "check"
	TaskRebuild = "rebuild"
)

// Task is work running in hardyd-priv.
type Task struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	Target   string          `json:"target"`
	Progress float64         `json:"progress"`
	Message  string          `json:"message"`
	Done     bool            `json:"done"`
	Error    string          `json:"error"`
	Result   json.RawMessage `json:"result,omitempty"`
	Started  time.Time       `json:"started"`
	Finished time.Time       `json:"finished"`
}

// MaxTasks bounds tasks running at once.
const MaxTasks = 4

type taskTable struct {
	mu      sync.Mutex
	m       map[string]*Task
	cancels map[string]context.CancelFunc
}

type taskCtx struct {
	t  *taskTable
	id string
}

func (c taskCtx) progress(pct float64, msg string) {
	c.t.mu.Lock()
	defer c.t.mu.Unlock()
	if x := c.t.m[c.id]; x != nil {
		if pct < 0 {
			pct = 0
		}
		if pct > 100 {
			pct = 100
		}
		x.Progress, x.Message = pct, msg
	}
}

// start runs fn in the background. One task per target at a time.
func (t *taskTable) start(kind, target string, fn func(ctx context.Context, tc taskCtx) (any, error)) (*Task, error) {
	t.mu.Lock()
	if t.m == nil {
		t.m = map[string]*Task{}
		t.cancels = map[string]context.CancelFunc{}
	}
	active := 0
	for id, x := range t.m {
		if x.Done && time.Since(x.Finished) > time.Hour {
			delete(t.m, id)
			continue
		}
		if !x.Done {
			active++
			if x.Target == target && target != "" {
				t.mu.Unlock()
				return nil, problemf("another backup task is running on this destination; wait for it to finish")
			}
		}
	}
	if active >= MaxTasks {
		t.mu.Unlock()
		return nil, problemf("%d backup tasks are already running; wait for one to finish", MaxTasks)
	}
	x := &Task{ID: randomID(12), Kind: kind, Target: target, Started: time.Now().UTC(), Message: "Starting"}
	ctx, cancel := context.WithCancel(context.Background())
	t.m[x.ID] = x
	t.cancels[x.ID] = cancel
	cp := *x
	t.mu.Unlock()
	go func() {
		defer cancel()
		res, err := safeTask(fn, ctx, taskCtx{t: t, id: x.ID})
		t.mu.Lock()
		defer t.mu.Unlock()
		x.Done, x.Finished = true, time.Now().UTC()
		delete(t.cancels, x.ID)
		if res != nil {
			if b, merr := json.Marshal(res); merr == nil {
				x.Result = b
			}
		}
		switch {
		case err == nil:
			x.Progress, x.Message = 100, "Done"
		case errors.Is(err, context.Canceled):
			x.Error = "cancelled"
		default:
			x.Error = err.Error()
		}
	}()
	return &cp, nil
}

func safeTask(fn func(ctx context.Context, tc taskCtx) (any, error), ctx context.Context, tc taskCtx) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("the task failed: %v", r)
		}
	}()
	return fn(ctx, tc)
}

func (t *taskTable) get(id string) (*Task, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	x, ok := t.m[id]
	if !ok {
		return nil, false
	}
	cp := *x
	return &cp, true
}

func (t *taskTable) cancel(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.cancels[id]
	if ok {
		c()
	}
	return ok
}

func (t *taskTable) list() []Task {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := []Task{}
	for _, x := range t.m {
		out = append(out, *x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.After(out[j].Started) })
	return out
}

// TaskStatus reports a task.
func (r *Root) TaskStatus(id string) (*Task, error) {
	x, ok := r.tasks.get(id)
	if !ok {
		return nil, problemf("there's no such backup task (hardyd-priv may have restarted)")
	}
	return x, nil
}

// CancelTask stops a task.
func (r *Root) CancelTask(id string) bool { return r.tasks.cancel(id) }

// Tasks lists recent tasks.
func (r *Root) Tasks() []Task { return r.tasks.list() }
