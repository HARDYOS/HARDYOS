package replica

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Proc is a started command.
type Proc interface {
	Wait() error
	// Kill ends the command and everything it started (its process group).
	Kill()
}

// Starter starts a long-running command with its standard streams (zfs
// send and receive run for as long as the data takes, so they don't go
// through sysexec.Runner, which buffers output).
type Starter interface {
	Start(name string, args []string, stdin io.Reader, stdout, stderr io.Writer) (Proc, error)
}

// ExecStarter is the real Starter: no shell, a fixed PATH, its own
// process group.
type ExecStarter struct{}

type execProc struct{ cmd *exec.Cmd }

func (p execProc) Wait() error { return p.cmd.Wait() }

func (p execProc) Kill() {
	if p.cmd.Process == nil {
		return
	}
	if err := syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL); err != nil {
		_ = p.cmd.Process.Kill()
	}
}

// Start implements Starter.
func (ExecStarter) Start(name string, args []string, stdin io.Reader, stdout, stderr io.Writer) (Proc, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	sysexec.OwnGroup(cmd)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return execProc{cmd}, nil
}

// StreamState is what hardyd asks about a running send or receive.
type StreamState struct {
	ID    string `json:"id"`
	Done  bool   `json:"done"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Bytes is what went into zfs receive so far (receives only).
	Bytes int64 `json:"bytes"`
}

// MaxStreamTime bounds one send or receive; a stream that takes longer is
// killed (a resumable receive keeps what it got).
const MaxStreamTime = 72 * time.Hour

// keepFinished is how long a finished stream's outcome stays for hardyd
// to read.
const keepFinished = 15 * time.Minute

type stream struct {
	id      string
	target  string // the dataset a receive writes (one receive per target)
	started time.Time
	bytes   atomic.Int64

	mu       sync.Mutex
	proc     Proc
	closer   io.Closer // the pipe end root holds; closed on cancel
	done     bool
	err      error
	finished time.Time
	killed   bool
	timer    *time.Timer
}

func (s *stream) state() StreamState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := StreamState{ID: s.id, Done: s.done, Bytes: s.bytes.Load()}
	if s.done {
		st.OK = s.err == nil
		if s.err != nil {
			st.Error = s.err.Error()
		}
	}
	return st
}

func (s *stream) cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return
	}
	s.killed = true
	if s.proc != nil {
		s.proc.Kill()
	}
	if s.closer != nil {
		_ = s.closer.Close()
	}
}

// streams tracks running sends and receives by id.
type streams struct {
	mu      sync.Mutex
	byID    map[string]*stream
	targets map[string]string // dataset -> receiving stream id
}

// ErrBusy means a receive into the same dataset is already running.
var ErrBusy = errors.New("a transfer into that replica is already running")

// ErrNoStream means the id isn't known (finished long ago, or never was).
var ErrNoStream = errors.New("no such transfer")

func newStreamID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (r *streams) add(target string) (*stream, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byID == nil {
		r.byID, r.targets = map[string]*stream{}, map[string]string{}
	}
	r.gc()
	if target != "" {
		if id, ok := r.targets[target]; ok {
			if s := r.byID[id]; s != nil && !s.state().Done {
				return nil, ErrBusy
			}
		}
	}
	s := &stream{id: newStreamID(), target: target, started: time.Now()}
	r.byID[s.id] = s
	if target != "" {
		r.targets[target] = s.id
	}
	s.timer = time.AfterFunc(MaxStreamTime, s.cancel)
	return s, nil
}

// gc forgets streams that finished a while ago; r.mu is held.
func (r *streams) gc() {
	now := time.Now()
	for id, s := range r.byID {
		s.mu.Lock()
		old := s.done && now.Sub(s.finished) > keepFinished
		s.mu.Unlock()
		if old {
			delete(r.byID, id)
			if r.targets[s.target] == id {
				delete(r.targets, s.target)
			}
		}
	}
}

func (r *streams) get(id string) (*stream, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.byID[id]
	if s == nil {
		return nil, ErrNoStream
	}
	return s, nil
}

// running reports whether a receive into target (or below it) runs.
func (r *streams) running(prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for t, id := range r.targets {
		if t == prefix || strings.HasPrefix(t, prefix+"/") {
			if s := r.byID[id]; s != nil && !s.state().Done {
				return true
			}
		}
	}
	return false
}

// finish records a stream's outcome.
func (s *stream) finish(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.killed {
		err = errors.New("cancelled")
	}
	s.done, s.err, s.finished = true, err, time.Now()
	if s.timer != nil {
		s.timer.Stop()
	}
}

// tail keeps the last bytes a command wrote to stderr, for its error.
type tail struct {
	mu  sync.Mutex
	buf []byte
}

const tailMax = 4096

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > tailMax {
		t.buf = t.buf[len(t.buf)-tailMax:]
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.TrimSpace(string(t.buf))
}

// countingReader counts what passes through.
type countingReader struct {
	r io.Reader
	n *atomic.Int64
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}
