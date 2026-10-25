// Package jobs runs long operations (pool creation, resilvers, installs,
// updates) in the background, persists their state, and streams progress.
package jobs

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// State of a job.
type State string

const (
	Queued    State = "queued"
	Running   State = "running"
	Succeeded State = "succeeded"
	Failed    State = "failed"
	Cancelled State = "cancelled"
)

// Done reports whether the job has finished.
func (s State) Done() bool { return s == Succeeded || s == Failed || s == Cancelled }

// Job is the public view of a job.
type Job struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Title      string          `json:"title"`
	State      State           `json:"state"`
	Progress   float64         `json:"progress"`
	Message    string          `json:"message"`
	Error      string          `json:"error"`
	Params     json.RawMessage `json:"params"`
	Result     json.RawMessage `json:"result"`
	CreatedBy  *int64          `json:"createdBy"`
	CreatedAt  time.Time       `json:"createdAt"`
	StartedAt  *time.Time      `json:"startedAt"`
	FinishedAt *time.Time      `json:"finishedAt"`
}

// Context is handed to a running job.
type Context struct {
	context.Context
	job *Job
	m   *Manager

	mu        sync.Mutex
	lastWrite time.Time
}

// Params decodes the job's parameters into v.
func (c *Context) Params(v any) error { return json.Unmarshal(c.job.Params, v) }

// ID returns the job's ID.
func (c *Context) ID() string { return c.job.ID }

// Progress reports completion (0-100) and a short status message.
// Updates are published immediately and persisted at most once a second.
func (c *Context) Progress(pct float64, msg string) {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	c.mu.Lock()
	c.job.Progress, c.job.Message = pct, msg
	persist := time.Since(c.lastWrite) >= time.Second
	if persist {
		c.lastWrite = time.Now()
	}
	snapshot := *c.job
	c.mu.Unlock()
	if persist {
		c.m.save(context.Background(), &snapshot)
	}
	c.m.publish(&snapshot)
}

// RunFunc does the work of a job kind. Return a JSON-encodable result or an error.
type RunFunc func(jc *Context) (any, error)

// Kind describes a job type.
type Kind struct {
	Name string
	Run  RunFunc
	// LockKey, if set, returns a key; jobs with the same key run one at a time
	// (e.g. "pool:tank" so two operations on one pool never overlap).
	LockKey func(params json.RawMessage) string
	// AdminOnly events are only streamed to admins.
	AdminOnly bool
}

// Manager queues and runs jobs.
type Manager struct {
	DB      *store.DB
	Events  *events.Broker
	Logger  *slog.Logger
	Workers int

	mu      sync.Mutex
	kinds   map[string]Kind
	cancels map[string]context.CancelFunc
	locks   map[string]*sync.Mutex
	queue   chan string
	wg      sync.WaitGroup
	started bool
}

// ErrUnknownKind is returned when submitting an unregistered job kind.
var ErrUnknownKind = errors.New("unknown job kind")

// Register adds a job kind. Call before Start.
func (m *Manager) Register(k Kind) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.kinds == nil {
		m.kinds = map[string]Kind{}
	}
	m.kinds[k.Name] = k
}

func (m *Manager) log() *slog.Logger {
	if m.Logger != nil {
		return m.Logger
	}
	return slog.Default()
}

// Start marks jobs left over from a previous run as failed and starts workers.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return errors.New("jobs: already started")
	}
	m.started = true
	if m.Workers <= 0 {
		m.Workers = 2
	}
	m.cancels = map[string]context.CancelFunc{}
	m.locks = map[string]*sync.Mutex{}
	m.queue = make(chan string, 1024)
	m.mu.Unlock()

	if _, err := m.DB.ExecContext(ctx, `UPDATE jobs SET state = 'failed', error = 'interrupted: hardyd restarted', finished_at = ?
		WHERE state IN ('queued', 'running')`, store.Now()); err != nil {
		return err
	}
	for i := 0; i < m.Workers; i++ {
		m.wg.Add(1)
		go m.worker(ctx)
	}
	return nil
}

// Wait blocks until all workers exit (after the Start context is cancelled).
func (m *Manager) Wait() { m.wg.Wait() }

// Submit queues a job and returns it.
func (m *Manager) Submit(ctx context.Context, kind, title string, params any, userID *int64) (*Job, error) {
	m.mu.Lock()
	_, ok := m.kinds[kind]
	started := m.started
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKind, kind)
	}
	if !started {
		return nil, errors.New("jobs: manager not started")
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("encode params: %w", err)
	}
	if params == nil {
		raw = []byte("{}")
	}
	j := &Job{
		ID: newID(), Kind: kind, Title: title, State: Queued,
		Params: raw, Result: json.RawMessage("{}"), CreatedBy: userID, CreatedAt: time.Now().UTC(),
	}
	if _, err := m.DB.ExecContext(ctx, `INSERT INTO jobs (id, kind, title, state, params, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, j.ID, j.Kind, j.Title, j.State, string(j.Params), j.CreatedBy, store.FormatTime(j.CreatedAt)); err != nil {
		return nil, err
	}
	m.publish(j)
	select {
	case m.queue <- j.ID:
	default:
		return nil, errors.New("jobs: queue full")
	}
	return j, nil
}

// Cancel asks a queued or running job to stop.
func (m *Manager) Cancel(ctx context.Context, id string) error {
	j, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if j.State.Done() {
		return fmt.Errorf("job already %s", j.State)
	}
	m.mu.Lock()
	cancel := m.cancels[id]
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		return nil
	}
	// Still queued: mark cancelled; the worker skips it.
	now := time.Now().UTC()
	j.State, j.FinishedAt = Cancelled, &now
	m.save(ctx, j)
	m.publish(j)
	return nil
}

func (m *Manager) worker(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-m.queue:
			m.run(ctx, id)
		}
	}
}

func (m *Manager) run(parent context.Context, id string) {
	j, err := m.Get(parent, id)
	if err != nil || j.State != Queued {
		return
	}
	m.mu.Lock()
	kind := m.kinds[j.Kind]
	m.mu.Unlock()

	if kind.LockKey != nil {
		if key := kind.LockKey(j.Params); key != "" {
			m.mu.Lock()
			l := m.locks[key]
			if l == nil {
				l = &sync.Mutex{}
				m.locks[key] = l
			}
			m.mu.Unlock()
			l.Lock()
			defer l.Unlock()
			// It may have been cancelled while waiting for the lock.
			if j, err = m.Get(parent, id); err != nil || j.State != Queued {
				return
			}
		}
	}

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	m.mu.Lock()
	m.cancels[id] = cancel
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.cancels, id)
		m.mu.Unlock()
	}()

	now := time.Now().UTC()
	j.State, j.StartedAt = Running, &now
	m.save(parent, j)
	m.publish(j)

	jc := &Context{Context: ctx, job: j, m: m}
	result, runErr := safeRun(kind.Run, jc)

	jc.mu.Lock()
	defer jc.mu.Unlock()
	fin := time.Now().UTC()
	j.FinishedAt = &fin
	switch {
	case runErr == nil:
		j.State, j.Progress = Succeeded, 100
		if result != nil {
			if raw, err := json.Marshal(result); err == nil {
				j.Result = raw
			}
		}
	case errors.Is(runErr, context.Canceled) || ctx.Err() != nil && parent.Err() == nil:
		j.State, j.Error = Cancelled, "cancelled"
	default:
		j.State, j.Error = Failed, runErr.Error()
	}
	m.save(context.Background(), j)
	m.publish(j)
	m.log().Info("job finished", "id", j.ID, "kind", j.Kind, "state", j.State, "duration", fin.Sub(now).String())
}

func safeRun(fn RunFunc, jc *Context) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("job panicked: %v", r)
		}
	}()
	return fn(jc)
}

func (m *Manager) save(ctx context.Context, j *Job) {
	_, err := m.DB.ExecContext(ctx, `UPDATE jobs SET state = ?, progress = ?, message = ?, error = ?, result = ?,
		started_at = ?, finished_at = ? WHERE id = ?`,
		j.State, j.Progress, j.Message, j.Error, string(j.Result), timePtr(j.StartedAt), timePtr(j.FinishedAt), j.ID)
	if err != nil {
		m.log().Error("save job", "id", j.ID, "err", err)
	}
}

func (m *Manager) publish(j *Job) {
	if m.Events == nil {
		return
	}
	m.mu.Lock()
	admin := m.kinds[j.Kind].AdminOnly
	m.mu.Unlock()
	var user int64
	if j.CreatedBy != nil {
		user = *j.CreatedBy
	}
	m.Events.PublishJSON(events.TypeJobUpdated, j, admin, user)
}

const jobCols = `id, kind, title, state, progress, message, error, params, result, created_by, created_at, started_at, finished_at`

func scanJob(row interface{ Scan(...any) error }) (*Job, error) {
	var j Job
	var params, result, created string
	var started, finished sql.NullString
	if err := row.Scan(&j.ID, &j.Kind, &j.Title, &j.State, &j.Progress, &j.Message, &j.Error,
		&params, &result, &j.CreatedBy, &created, &started, &finished); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	j.Params, j.Result = json.RawMessage(params), json.RawMessage(result)
	j.CreatedAt = store.ParseTime(created)
	if started.Valid {
		t := store.ParseTime(started.String)
		j.StartedAt = &t
	}
	if finished.Valid {
		t := store.ParseTime(finished.String)
		j.FinishedAt = &t
	}
	return &j, nil
}

// Get returns one job.
func (m *Manager) Get(ctx context.Context, id string) (*Job, error) {
	return scanJob(m.DB.QueryRowContext(ctx, `SELECT `+jobCols+` FROM jobs WHERE id = ?`, id))
}

// List returns recent jobs, newest first. If userID is non-nil, only that user's jobs.
func (m *Manager) List(ctx context.Context, userID *int64, limit int) ([]*Job, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	q := `SELECT ` + jobCols + ` FROM jobs`
	var args []any
	if userID != nil {
		q += ` WHERE created_by = ?`
		args = append(args, *userID)
	}
	q += ` ORDER BY created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := m.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func timePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return store.FormatTime(*t)
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "job_" + hex.EncodeToString(b)
}
