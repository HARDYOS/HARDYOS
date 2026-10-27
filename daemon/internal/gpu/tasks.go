package gpu

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Task is a background driver job (apt and DKMS builds take longer than a
// privileged call may). hardyd's job polls it.
type Task struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	State    string    `json:"state"` // running, succeeded, failed
	Step     string    `json:"step"`
	Progress int       `json:"progress"`
	Log      string    `json:"log"` // the last MaxLogBytes
	Error    string    `json:"error,omitempty"`
	Result   any       `json:"result,omitempty"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitzero"`
}

// Task kinds.
const (
	TaskNvidiaPrepare = "nvidia.prepare"
	TaskNvidiaInstall = "nvidia.install"
	TaskNvidiaRemove  = "nvidia.remove"
	TaskVGPUInstall   = "vgpu.install"
	TaskVGPURemove    = "vgpu.remove"
)

// Task states.
const (
	TaskRunning   = "running"
	TaskSucceeded = "succeeded"
	TaskFailed    = "failed"
)

// MaxLogBytes is how much of a task's log is kept.
const MaxLogBytes = 64 << 10

// ErrBusy means another driver task is running.
var ErrBusy = errors.New("another graphics driver task is running; wait for it to finish")

type task struct {
	mu sync.Mutex
	t  Task
}

// tc is what a task's work function uses.
type tc struct {
	m  *Manager
	tk *task
}

func (c *tc) step(pct int, msg string) {
	c.tk.mu.Lock()
	c.tk.t.Step, c.tk.t.Progress = msg, pct
	c.tk.mu.Unlock()
	c.logf("== %s", msg)
}

func (c *tc) logf(format string, args ...any) {
	c.tk.mu.Lock()
	defer c.tk.mu.Unlock()
	l := c.tk.t.Log + fmt.Sprintf(format, args...) + "\n"
	if len(l) > MaxLogBytes {
		l = l[len(l)-MaxLogBytes:]
	}
	c.tk.t.Log = l
}

// run runs a command, logging it and its output; a failure carries the
// end of the output.
func (c *tc) run(ctx context.Context, env []string, name string, args ...string) (string, error) {
	c.logf("$ %s %s", name, strings.Join(args, " "))
	var res sysexec.Result
	var err error
	if len(env) > 0 {
		res, err = sysexec.RunEnv(ctx, c.m.Runner, env, nil, name, args...)
	} else {
		res, err = c.m.Runner.Run(ctx, nil, name, args...)
	}
	out := strings.TrimSpace(string(res.Stdout) + "\n" + string(res.Stderr))
	if out != "" {
		c.logf("%s", out)
	}
	if err != nil {
		return out, fmt.Errorf("%s: %w", name, err)
	}
	if res.ExitCode != 0 {
		tail := out
		if len(tail) > 600 {
			tail = "…" + tail[len(tail)-600:]
		}
		return out, fmt.Errorf("%s exited %d: %s", name, res.ExitCode, tail)
	}
	return out, nil
}

// start runs fn in the background as a new task. Only one runs at a time.
func (m *Manager) start(kind string, fn func(ctx context.Context, c *tc) (any, error)) (*Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.task != nil {
		m.task.mu.Lock()
		running := m.task.t.State == TaskRunning
		m.task.mu.Unlock()
		if running {
			return nil, ErrBusy
		}
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	tk := &task{t: Task{ID: hex.EncodeToString(b), Kind: kind, State: TaskRunning, Started: time.Now().UTC()}}
	m.task = tk
	m.saveTask(tk.t)
	timeout := m.TaskTimeout
	if timeout == 0 {
		timeout = 90 * time.Minute
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		c := &tc{m: m, tk: tk}
		res, err := fn(ctx, c)
		tk.mu.Lock()
		tk.t.Finished = time.Now().UTC()
		if err != nil {
			tk.t.State, tk.t.Error = TaskFailed, err.Error()
		} else {
			tk.t.State, tk.t.Result, tk.t.Progress = TaskSucceeded, res, 100
		}
		snapshot := tk.t
		tk.mu.Unlock()
		c.saveLog(snapshot)
		m.saveTask(snapshot)
		m.log().Info("gpu driver task finished", "kind", kind, "ok", err == nil, "err", err)
	}()
	snap := tk.snapshot()
	return &snap, nil
}

func (t *task) snapshot() Task {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.t
}

// Task returns the running or last task (nil if none since start).
func (m *Manager) Task() *Task {
	m.mu.Lock()
	tk := m.task
	m.mu.Unlock()
	if tk == nil {
		// The last task before hardyd-priv restarted.
		var t Task
		b, err := os.ReadFile(m.path(filepath.Join(Dir, "logs", "task.json")))
		if err != nil || json.Unmarshal(b, &t) != nil {
			return nil
		}
		if t.State == TaskRunning {
			t.State, t.Error = TaskFailed, "interrupted: the server or its root helper restarted while this ran. Start it again; it picks up where the package manager stopped."
		}
		return &t
	}
	s := tk.snapshot()
	return &s
}

func (m *Manager) saveTask(t Task) {
	d, err := m.ensureDir("logs")
	if err != nil {
		return
	}
	t.Log = ""
	b, _ := json.Marshal(t)
	_ = os.WriteFile(filepath.Join(d, "task.json"), b, 0o600)
}

// Wait blocks until the current task finishes (tests).
func (m *Manager) Wait(ctx context.Context) *Task {
	for {
		t := m.Task()
		if t == nil || t.State != TaskRunning {
			return t
		}
		select {
		case <-ctx.Done():
			return t
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// saveLog keeps the last log in Dir for later reading.
func (c *tc) saveLog(t Task) {
	d, err := c.m.ensureDir("logs")
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(d, t.Kind+".log"), []byte(t.Log), 0o600)
}

// ownedByRoot refuses a directory root doesn't own or others can write.
func ownedByRoot(fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must be root's and writable by root only", Dir)
	}
	return nil
}
