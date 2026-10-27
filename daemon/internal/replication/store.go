package replication

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/replica"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Target is a server this one sends replicas to.
type Target struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	SourceID  string    `json:"sourceId"`
	Pin       string    `json:"pin"` // the receiver's key, pinned at pairing
	CreatedAt time.Time `json:"createdAt"`
}

// Task replicates chosen items to a target on a schedule.
type Task struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	TargetID        string         `json:"targetId"`
	Items           []replica.Item `json:"items"`
	IntervalMinutes int            `json:"intervalMinutes"`
	BandwidthKBps   int            `json:"bandwidthKBps"` // 0: unlimited
	KeepLocal       int            `json:"keepLocal"`
	KeepRemote      int            `json:"keepRemote"`
	Enabled         bool           `json:"enabled"`
	LastRunAt       *time.Time     `json:"lastRunAt"`
	LastSuccessAt   *time.Time     `json:"lastSuccessAt"`
	LastError       string         `json:"lastError"`
	LastBytes       int64          `json:"lastBytes"`
	Alert           string         `json:"alert"` // '', failed, stale
	CreatedAt       time.Time      `json:"createdAt"`
	UpdatedAt       time.Time      `json:"updatedAt"`
}

// Run is one replication or restore in a task's history.
type Run struct {
	ID         int64      `json:"id"`
	TaskID     string     `json:"taskId"`
	JobID      string     `json:"jobId"`
	Kind       string     `json:"kind"` // replicate, restore
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt"`
	State      string     `json:"state"` // running, succeeded, failed, cancelled
	Bytes      int64      `json:"bytes"`
	Message    string     `json:"message"`
}

// SourceRules are the receiving administrator's rules for a source.
type SourceRules struct {
	QuotaBytes         uint64 `json:"quotaBytes"`
	MinKeep            int    `json:"minKeep"`
	MinAgeDays         int    `json:"minAgeDays"`
	MinIntervalMinutes int    `json:"minIntervalMinutes"`
	MaxDatasets        int    `json:"maxDatasets"`
	MaxSnapshots       int    `json:"maxSnapshots"`
	AllowBrowse        bool   `json:"allowBrowse"`
}

// DefaultRules are a new source's rules besides its quota.
var DefaultRules = SourceRules{MinKeep: 3, MinAgeDays: 7, MaxDatasets: replica.DefaultMaxDatasets, MaxSnapshots: replica.DefaultMaxSnapshots}

// Check validates rules.
func (r *SourceRules) Check() error {
	switch {
	case r.QuotaBytes == 0:
		return errors.New("set a space limit for the server's replicas")
	case r.MinKeep < 1 || r.MinKeep > MaxKeep:
		return fmt.Errorf("keep between 1 and %d snapshots", MaxKeep)
	case r.MinAgeDays < 0 || r.MinAgeDays > 3650:
		return errors.New("keep snapshots between 0 and 3650 days")
	case r.MinIntervalMinutes < 0 || r.MinIntervalMinutes > 7*24*60:
		return errors.New("the minimum interval is at most 7 days")
	case r.MaxDatasets < 1 || r.MaxDatasets > 100000 || r.MaxSnapshots < 1 || r.MaxSnapshots > 1000000:
		return errors.New("the dataset and snapshot limits aren't valid")
	}
	return nil
}

// Limits are the rules as root applies them.
func (r SourceRules) Limits() replica.Limits {
	return replica.Limits{QuotaBytes: r.QuotaBytes, MinAgeDays: r.MinAgeDays, MinIntervalMinutes: r.MinIntervalMinutes,
		MaxDatasets: r.MaxDatasets, MaxSnapshots: r.MaxSnapshots}
}

// Source is a server allowed to send replicas to this one.
type Source struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Pin  string `json:"-"`
	Pool string `json:"pool"`
	SourceRules
	CreatedAt  time.Time    `json:"createdAt"`
	LastSeenAt *time.Time   `json:"lastSeenAt"`
	Items      []SourceItem `json:"items"`
}

// SourceItem is what a source said about one of its items.
type SourceItem struct {
	Kind      string    `json:"kind"`
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Pool      string    `json:"pool"`
	TaskID    string    `json:"taskId"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Pairing is the receiving server's open pairing code (without the code).
type Pairing struct {
	Pool       string    `json:"pool"`
	QuotaBytes uint64    `json:"quotaBytes"`
	MinKeep    int       `json:"minKeep"`
	MinAgeDays int       `json:"minAgeDays"`
	ExpiresAt  time.Time `json:"expiresAt"`
	code       []byte
	failures   int
}

// Store keeps replication's records in hardyd's database.
type Store struct {
	DB     *store.DB
	Sealer *Sealer

	// Unsealed sources, kept until a source changes (every request on
	// the receiving port looks its caller up).
	cacheMu sync.Mutex
	cache   []Source
}

func (s *Store) invalidate() {
	s.cacheMu.Lock()
	s.cache = nil
	s.cacheMu.Unlock()
}

func newID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func timeOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return store.FormatTime(*t)
}

func parseNull(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t := store.ParseTime(s.String)
	return &t
}

func (s *Store) sealPin(ctx context.Context, pin, aad string) ([]byte, error) {
	return s.Sealer.Seal(ctx, []byte(pin), aad)
}

func (s *Store) openPin(ctx context.Context, sealed []byte, aad string) (string, error) {
	b, err := s.Sealer.Open(ctx, sealed, aad)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---- targets -----------------------------------------------------------------

// AddTarget records a paired receiving server.
func (s *Store) AddTarget(ctx context.Context, t *Target) error {
	if t.ID == "" {
		t.ID = newID(6)
	}
	t.CreatedAt = time.Now().UTC()
	sealed, err := s.sealPin(ctx, t.Pin, "repl-target:"+t.ID)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO repl_targets (id, name, address, pin_sealed, source_id, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.Address, sealed, t.SourceID, store.FormatTime(t.CreatedAt))
	return err
}

// Targets lists paired receiving servers. A target whose pin can't be
// opened (a database restored onto another server) has Pin "".
func (s *Store) Targets(ctx context.Context) ([]Target, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, name, address, pin_sealed, source_id, created_at FROM repl_targets ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Target{}
	for rows.Next() {
		var t Target
		var sealed []byte
		var created string
		if err := rows.Scan(&t.ID, &t.Name, &t.Address, &sealed, &t.SourceID, &created); err != nil {
			return nil, err
		}
		t.CreatedAt = store.ParseTime(created)
		t.Pin, _ = s.openPin(ctx, sealed, "repl-target:"+t.ID)
		out = append(out, t)
	}
	return out, rows.Err()
}

// Target returns one target.
func (s *Store) Target(ctx context.Context, id string) (*Target, error) {
	l, err := s.Targets(ctx)
	if err != nil {
		return nil, err
	}
	for i := range l {
		if l[i].ID == id {
			return &l[i], nil
		}
	}
	return nil, store.ErrNotFound
}

// UpdateTargetAddress changes where a target is reached.
func (s *Store) UpdateTargetAddress(ctx context.Context, id, address string) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE repl_targets SET address = ? WHERE id = ?`, address, id)
	return oneRow(res, err)
}

// DeleteTarget forgets a target (its tasks must be gone).
func (s *Store) DeleteTarget(ctx context.Context, id string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM repl_targets WHERE id = ?`, id)
	return oneRow(res, err)
}

func oneRow(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ---- tasks -------------------------------------------------------------------

const taskCols = `id, name, target_id, items, interval_minutes, bwlimit_kbps, keep_local, keep_remote, enabled,
	last_run_at, last_success_at, last_error, last_bytes, alert, created_at, updated_at`

func scanTask(row interface{ Scan(...any) error }) (*Task, error) {
	var t Task
	var items, created, updated string
	var enabled int
	var lastRun, lastOK sql.NullString
	if err := row.Scan(&t.ID, &t.Name, &t.TargetID, &items, &t.IntervalMinutes, &t.BandwidthKBps, &t.KeepLocal, &t.KeepRemote, &enabled,
		&lastRun, &lastOK, &t.LastError, &t.LastBytes, &t.Alert, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, err
	}
	if err := json.Unmarshal([]byte(items), &t.Items); err != nil || t.Items == nil {
		t.Items = []replica.Item{}
	}
	t.Enabled = enabled != 0
	t.LastRunAt, t.LastSuccessAt = parseNull(lastRun), parseNull(lastOK)
	t.CreatedAt, t.UpdatedAt = store.ParseTime(created), store.ParseTime(updated)
	return &t, nil
}

// Tasks lists replication tasks.
func (s *Store) Tasks(ctx context.Context) ([]Task, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+taskCols+` FROM repl_tasks ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Task{}
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// Task returns one task.
func (s *Store) Task(ctx context.Context, id string) (*Task, error) {
	return scanTask(s.DB.QueryRowContext(ctx, `SELECT `+taskCols+` FROM repl_tasks WHERE id = ?`, id))
}

// SaveTask inserts or updates a task's settings (not its run state).
func (s *Store) SaveTask(ctx context.Context, t *Task) error {
	items, _ := json.Marshal(t.Items)
	now := time.Now().UTC()
	t.UpdatedAt = now
	if t.ID == "" {
		t.ID = newID(5)
		t.CreatedAt = now
		_, err := s.DB.ExecContext(ctx, `INSERT INTO repl_tasks (id, name, target_id, items, interval_minutes, bwlimit_kbps, keep_local, keep_remote, enabled, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, t.ID, t.Name, t.TargetID, string(items), t.IntervalMinutes, t.BandwidthKBps, t.KeepLocal, t.KeepRemote, boolInt(t.Enabled),
			store.FormatTime(now), store.FormatTime(now))
		return err
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE repl_tasks SET name = ?, items = ?, interval_minutes = ?, bwlimit_kbps = ?, keep_local = ?, keep_remote = ?, enabled = ?, updated_at = ? WHERE id = ?`,
		t.Name, string(items), t.IntervalMinutes, t.BandwidthKBps, t.KeepLocal, t.KeepRemote, boolInt(t.Enabled), store.FormatTime(now), t.ID)
	return oneRow(res, err)
}

// DeleteTask removes a task and its history.
func (s *Store) DeleteTask(ctx context.Context, id string) error {
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM repl_runs WHERE task_id = ?`, id); err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, `DELETE FROM repl_tasks WHERE id = ?`, id)
	return oneRow(res, err)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// recordStart marks a task as started and opens its history entry.
func (s *Store) recordStart(ctx context.Context, taskID, jobID, kind string, at time.Time) (int64, error) {
	if kind == "replicate" {
		if _, err := s.DB.ExecContext(ctx, `UPDATE repl_tasks SET last_run_at = ? WHERE id = ?`, store.FormatTime(at), taskID); err != nil {
			return 0, err
		}
	}
	res, err := s.DB.ExecContext(ctx, `INSERT INTO repl_runs (task_id, job_id, kind, started_at, state) VALUES (?, ?, ?, ?, 'running')`,
		taskID, jobID, kind, store.FormatTime(at))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// recordEnd closes a history entry and, for replications, the task's
// last result.
func (s *Store) recordEnd(ctx context.Context, runID int64, taskID, kind, state string, bytes int64, msg string, at time.Time) error {
	if _, err := s.DB.ExecContext(ctx, `UPDATE repl_runs SET finished_at = ?, state = ?, bytes = ?, message = ? WHERE id = ?`,
		store.FormatTime(at), state, bytes, msg, runID); err != nil {
		return err
	}
	if kind != "replicate" {
		return nil
	}
	if state == "succeeded" {
		_, err := s.DB.ExecContext(ctx, `UPDATE repl_tasks SET last_success_at = ?, last_error = '', last_bytes = ? WHERE id = ?`,
			store.FormatTime(at), bytes, taskID)
		return err
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE repl_tasks SET last_error = ? WHERE id = ?`, msg, taskID)
	return err
}

// setAlert records what was last notified about a task.
func (s *Store) setAlert(ctx context.Context, taskID, alert string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE repl_tasks SET alert = ? WHERE id = ?`, alert, taskID)
	return err
}

// MaxHistory is how many runs each task keeps.
const MaxHistory = 200

// Runs lists a task's history, newest first.
func (s *Store) Runs(ctx context.Context, taskID string, limit int) ([]Run, error) {
	if limit <= 0 || limit > MaxHistory {
		limit = 50
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT id, task_id, job_id, kind, started_at, finished_at, state, bytes, message FROM repl_runs
		WHERE task_id = ? ORDER BY id DESC LIMIT ?`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		var r Run
		var started string
		var finished sql.NullString
		if err := rows.Scan(&r.ID, &r.TaskID, &r.JobID, &r.Kind, &started, &finished, &r.State, &r.Bytes, &r.Message); err != nil {
			return nil, err
		}
		r.StartedAt, r.FinishedAt = store.ParseTime(started), parseNull(finished)
		out = append(out, r)
	}
	return out, rows.Err()
}

// trimRuns keeps the newest MaxHistory runs of a task, and marks runs
// left running by a restart as failed.
func (s *Store) trimRuns(ctx context.Context, taskID string) {
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM repl_runs WHERE task_id = ? AND id NOT IN (SELECT id FROM repl_runs WHERE task_id = ? ORDER BY id DESC LIMIT ?)`,
		taskID, taskID, MaxHistory)
}

func (s *Store) failInterrupted(ctx context.Context) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE repl_runs SET state = 'failed', message = 'interrupted: hardyd restarted', finished_at = ? WHERE state = 'running'`, store.Now())
}

// ---- sources (receiving side) -------------------------------------------------

// AddSource records a server allowed to send replicas here.
func (s *Store) AddSource(ctx context.Context, src *Source) error {
	src.CreatedAt = time.Now().UTC()
	sealed, err := s.sealPin(ctx, src.Pin, "repl-source:"+src.ID)
	if err != nil {
		return err
	}
	defer s.invalidate()
	_, err = s.DB.ExecContext(ctx, `INSERT INTO repl_sources (id, name, pin_sealed, pool, quota_bytes, min_keep, min_age_days, min_interval_minutes,
		max_datasets, max_snapshots, allow_browse, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		src.ID, src.Name, sealed, src.Pool, int64(src.QuotaBytes), src.MinKeep, src.MinAgeDays, src.MinIntervalMinutes,
		src.MaxDatasets, src.MaxSnapshots, boolInt(src.AllowBrowse), store.FormatTime(src.CreatedAt))
	return err
}

// pinned returns the sources with their pins (cached).
func (s *Store) pinned(ctx context.Context) ([]Source, error) {
	s.cacheMu.Lock()
	c := s.cache
	s.cacheMu.Unlock()
	if c != nil {
		return c, nil
	}
	l, err := s.Sources(ctx)
	if err != nil {
		return nil, err
	}
	s.cacheMu.Lock()
	s.cache = l
	s.cacheMu.Unlock()
	return l, nil
}

// Sources lists the servers allowed to send here, with their items.
func (s *Store) Sources(ctx context.Context) ([]Source, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, name, pin_sealed, pool, quota_bytes, min_keep, min_age_days, min_interval_minutes,
		max_datasets, max_snapshots, allow_browse, created_at, last_seen_at FROM repl_sources ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	out := []Source{}
	for rows.Next() {
		var src Source
		var sealed []byte
		var created string
		var seen sql.NullString
		var quota int64
		var browse int
		if err := rows.Scan(&src.ID, &src.Name, &sealed, &src.Pool, &quota, &src.MinKeep, &src.MinAgeDays, &src.MinIntervalMinutes,
			&src.MaxDatasets, &src.MaxSnapshots, &browse, &created, &seen); err != nil {
			rows.Close()
			return nil, err
		}
		src.QuotaBytes = uint64(max(quota, 0))
		src.AllowBrowse = browse != 0
		src.CreatedAt, src.LastSeenAt = store.ParseTime(created), parseNull(seen)
		src.Pin, _ = s.openPin(ctx, sealed, "repl-source:"+src.ID)
		src.Items = []SourceItem{}
		out = append(out, src)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	irows, err := s.DB.QueryContext(ctx, `SELECT source_id, kind, item_id, name, pool, task_id, updated_at FROM repl_source_items ORDER BY kind, item_id`)
	if err != nil {
		return nil, err
	}
	defer irows.Close()
	idx := map[string]int{}
	for i := range out {
		idx[out[i].ID] = i
	}
	for irows.Next() {
		var src, updated string
		var it SourceItem
		if err := irows.Scan(&src, &it.Kind, &it.ID, &it.Name, &it.Pool, &it.TaskID, &updated); err != nil {
			return nil, err
		}
		it.UpdatedAt = store.ParseTime(updated)
		if i, ok := idx[src]; ok {
			out[i].Items = append(out[i].Items, it)
		}
	}
	return out, irows.Err()
}

// Source returns one source.
func (s *Store) Source(ctx context.Context, id string) (*Source, error) {
	l, err := s.Sources(ctx)
	if err != nil {
		return nil, err
	}
	for i := range l {
		if l[i].ID == id {
			return &l[i], nil
		}
	}
	return nil, store.ErrNotFound
}

// UpdateSource changes a source's rules.
func (s *Store) UpdateSource(ctx context.Context, id string, r SourceRules) error {
	defer s.invalidate()
	res, err := s.DB.ExecContext(ctx, `UPDATE repl_sources SET quota_bytes = ?, min_keep = ?, min_age_days = ?, min_interval_minutes = ?,
		max_datasets = ?, max_snapshots = ?, allow_browse = ? WHERE id = ?`,
		int64(r.QuotaBytes), r.MinKeep, r.MinAgeDays, r.MinIntervalMinutes, r.MaxDatasets, r.MaxSnapshots, boolInt(r.AllowBrowse), id)
	return oneRow(res, err)
}

// DeleteSource forgets a source (and what it said about its items).
func (s *Store) DeleteSource(ctx context.Context, id string) error {
	defer s.invalidate()
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM repl_source_items WHERE source_id = ?`, id); err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, `DELETE FROM repl_sources WHERE id = ?`, id)
	return oneRow(res, err)
}

func (s *Store) touchSource(ctx context.Context, id string) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE repl_sources SET last_seen_at = ? WHERE id = ?`, store.Now(), id)
}

// MaxSourceItems bounds what one source can record here.
const MaxSourceItems = 500

func (s *Store) putSourceItem(ctx context.Context, sourceID string, it SourceItem) error {
	var n int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM repl_source_items WHERE source_id = ?`, sourceID).Scan(&n); err != nil {
		return err
	}
	if n >= MaxSourceItems {
		var exists int
		_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM repl_source_items WHERE source_id = ? AND kind = ? AND item_id = ?`, sourceID, it.Kind, it.ID).Scan(&exists)
		if exists == 0 {
			return fmt.Errorf("too many items from one server (at most %d)", MaxSourceItems)
		}
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO repl_source_items (source_id, kind, item_id, name, pool, task_id, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source_id, kind, item_id) DO UPDATE SET name = excluded.name, pool = excluded.pool, task_id = excluded.task_id, updated_at = excluded.updated_at`,
		sourceID, it.Kind, it.ID, it.Name, it.Pool, it.TaskID, store.Now())
	return err
}

// ---- pairing (receiving side) -----------------------------------------------

// SetPairing replaces the open pairing code.
func (s *Store) SetPairing(ctx context.Context, code []byte, p Pairing) error {
	sealed, err := s.Sealer.Seal(ctx, code, "repl-pairing")
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO repl_pairing (id, code_sealed, pool, quota_bytes, min_keep, min_age_days, failures, expires_at, created_at) VALUES (1, ?, ?, ?, ?, ?, 0, ?, ?)
		ON CONFLICT(id) DO UPDATE SET code_sealed = excluded.code_sealed, pool = excluded.pool, quota_bytes = excluded.quota_bytes,
		min_keep = excluded.min_keep, min_age_days = excluded.min_age_days, failures = 0, expires_at = excluded.expires_at, created_at = excluded.created_at`,
		sealed, p.Pool, int64(p.QuotaBytes), p.MinKeep, p.MinAgeDays, store.FormatTime(p.ExpiresAt), store.Now())
	return err
}

// Pairing returns the open pairing code (nil when there's none or it
// expired).
func (s *Store) Pairing(ctx context.Context, now time.Time) (*Pairing, error) {
	var p Pairing
	var sealed []byte
	var exp string
	var quota int64
	err := s.DB.QueryRowContext(ctx, `SELECT code_sealed, pool, quota_bytes, min_keep, min_age_days, failures, expires_at FROM repl_pairing WHERE id = 1`).
		Scan(&sealed, &p.Pool, &quota, &p.MinKeep, &p.MinAgeDays, &p.failures, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.QuotaBytes = uint64(max(quota, 0))
	p.ExpiresAt = store.ParseTime(exp)
	if !now.Before(p.ExpiresAt) || p.failures >= MaxPairFailures {
		return nil, nil
	}
	code, err := s.Sealer.Open(ctx, sealed, "repl-pairing")
	if err != nil {
		return nil, nil
	}
	p.code = code
	return &p, nil
}

// ClearPairing removes the open pairing code.
func (s *Store) ClearPairing(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM repl_pairing`)
	return err
}

func (s *Store) pairingFailed(ctx context.Context) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE repl_pairing SET failures = failures + 1 WHERE id = 1`)
}
