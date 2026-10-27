// Package cloudbackups is hardyd's side of versioned cloud backups: backup
// tasks (what, where, when, how long to keep), their runs as jobs that
// follow hardyd-priv's backup tasks, restores, destination upkeep (prune
// and check) and the schedule. hardyd-priv (internal/cloudbackup) does
// all the work with restic and keeps every credential; hardyd only knows
// destinations by id. See docs/backup.md.
package cloudbackups

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardyos/hardyos/daemon/internal/backup"
	"github.com/hardyos/hardyos/daemon/internal/cloudbackup"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Job kinds.
const (
	JobRun     = "backup.cloud.run"
	JobRestore = "backup.cloud.restore"
	JobPrune   = "backup.cloud.prune"
	JobCheck   = "backup.cloud.check"
	JobRebuild = "backup.cloud.rebuild"
)

// Service runs cloud backups from hardyd.
type Service struct {
	DB       *store.DB
	Priv     *priv.Client
	Jobs     *jobs.Manager
	Notifier Notifier
	Log      *slog.Logger
	// Version is the running HardyOS version (recorded with the settings).
	Version string
	// Dir is hardyd's work directory, where the database copy for a backup
	// waits for hardyd-priv (default /var/lib/hardyos/backups).
	Dir      string
	Hostname func() string
	Now      func() time.Time
	// Poll is how often a job asks hardyd-priv how its task is going.
	Poll time.Duration
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) notifier() Notifier {
	if s.Notifier != nil {
		return s.Notifier
	}
	return NopNotifier{}
}

func (s *Service) dir() string {
	if s.Dir != "" {
		return s.Dir
	}
	return "/" + backup.WorkDir
}

func (s *Service) poll() time.Duration {
	if s.Poll > 0 {
		return s.Poll
	}
	return 2 * time.Second
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Problem is the caller's mistake.
type Problem struct{ Msg string }

func (p *Problem) Error() string { return p.Msg }

func problemf(format string, a ...any) error { return &Problem{Msg: fmt.Sprintf(format, a...)} }

// ErrNotFound means there's no such task.
var ErrNotFound = errors.New("there's no backup task with that id")

// ---- tasks ----------------------------------------------------------------------

// Task is a backup task.
type Task struct {
	ID        string                `json:"id"`
	Name      string                `json:"name"`
	Target    string                `json:"target"`
	Items     []cloudbackup.Item    `json:"items"`
	Schedule  Schedule              `json:"schedule"`
	Retention cloudbackup.Retention `json:"retention"`
	Enabled   bool                  `json:"enabled"`
	CreatedAt time.Time             `json:"createdAt"`
	UpdatedAt time.Time             `json:"updatedAt"`
	LastRun   *Run                  `json:"lastRun"`
	NextRun   *time.Time            `json:"nextRun"`
	Running   bool                  `json:"running"`
}

// TaskInput creates or changes a task.
type TaskInput struct {
	Name      string                 `json:"name"`
	Target    string                 `json:"target"`
	Items     []cloudbackup.Item     `json:"items"`
	Schedule  *Schedule              `json:"schedule,omitempty"`
	Retention *cloudbackup.Retention `json:"retention,omitempty"`
	Enabled   *bool                  `json:"enabled,omitempty"`
}

var nameRE = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,64}$`)

func (s *Service) checkInput(ctx context.Context, in *TaskInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if !nameRE.MatchString(in.Name) || utf8.RuneCountInString(in.Name) > 64 {
		return problemf("give the task a name of at most 64 characters")
	}
	if len(in.Items) == 0 {
		return problemf("choose what to back up")
	}
	if len(in.Items) > 256 {
		return problemf("a task backs up at most 256 things")
	}
	seen := map[string]bool{}
	for _, it := range in.Items {
		if err := it.Check(); err != nil {
			return &Problem{Msg: err.Error()}
		}
		if seen[it.Key()] {
			return problemf("%s is chosen twice", it.Key())
		}
		seen[it.Key()] = true
	}
	if in.Schedule != nil {
		if err := in.Schedule.Check(); err != nil {
			return &Problem{Msg: err.Error()}
		}
	}
	if in.Retention != nil {
		if err := in.Retention.Check(); err != nil {
			return &Problem{Msg: err.Error()}
		}
	}
	targets, err := s.Targets(ctx)
	if err != nil {
		return err
	}
	for _, t := range targets {
		if t.ID == in.Target {
			return nil
		}
	}
	return problemf("choose where the backups go")
}

const taskCols = `id, name, target, items, schedule, retention, enabled, last_slot, created_at, updated_at`

func scanTask(row interface{ Scan(...any) error }) (*Task, string, error) {
	var t Task
	var items, sched, ret, created, updated, slot string
	var enabled int
	if err := row.Scan(&t.ID, &t.Name, &t.Target, &items, &sched, &ret, &enabled, &slot, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", ErrNotFound
		}
		return nil, "", err
	}
	_ = json.Unmarshal([]byte(items), &t.Items)
	if json.Unmarshal([]byte(sched), &t.Schedule) != nil || t.Schedule.Check() != nil {
		t.Schedule = Schedule{Frequency: Manual}
	}
	if json.Unmarshal([]byte(ret), &t.Retention) != nil || t.Retention.Check() != nil {
		t.Retention = cloudbackup.DefaultRetention
	}
	if t.Items == nil {
		t.Items = []cloudbackup.Item{}
	}
	t.Enabled = enabled != 0
	t.CreatedAt, t.UpdatedAt = store.ParseTime(created), store.ParseTime(updated)
	return &t, slot, nil
}

// Tasks lists the backup tasks with their last run and next time.
func (s *Service) Tasks(ctx context.Context) ([]Task, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+taskCols+` FROM backup_tasks ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var out []Task
	for rows.Next() {
		t, _, err := scanTask(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, *t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		s.decorate(ctx, &out[i])
	}
	if out == nil {
		out = []Task{}
	}
	return out, nil
}

func (s *Service) decorate(ctx context.Context, t *Task) {
	if r, err := s.lastRun(ctx, t.ID); err == nil {
		t.LastRun = r
		t.Running = r != nil && r.State == RunRunning
	}
	if t.Enabled {
		if n := t.Schedule.NextSlot(s.now()); !n.IsZero() {
			t.NextRun = &n
		}
	}
}

// Task returns one task.
func (s *Service) Task(ctx context.Context, id string) (*Task, error) {
	t, _, err := scanTask(s.DB.QueryRowContext(ctx, `SELECT `+taskCols+` FROM backup_tasks WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	s.decorate(ctx, t)
	return t, nil
}

// CreateTask makes a task.
func (s *Service) CreateTask(ctx context.Context, in TaskInput) (*Task, error) {
	if in.Schedule == nil {
		d := DefaultSchedule
		in.Schedule = &d
	}
	if in.Retention == nil {
		d := cloudbackup.DefaultRetention
		in.Retention = &d
	}
	if err := s.checkInput(ctx, &in); err != nil {
		return nil, err
	}
	id := "t" + randHex(6)
	items, _ := json.Marshal(in.Items)
	sched, _ := json.Marshal(in.Schedule)
	ret, _ := json.Marshal(in.Retention)
	enabled := in.Enabled == nil || *in.Enabled
	now := store.Now()
	// The slot just passed counts as handled: a new task never reports a
	// missed backup for a time before it existed.
	slot := ""
	if ls := in.Schedule.LastSlot(s.now()); !ls.IsZero() {
		slot = store.FormatTime(ls)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO backup_tasks (id, name, target, items, schedule, retention, enabled, last_slot, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, in.Name, in.Target, string(items), string(sched), string(ret), boolInt(enabled), slot, now, now); err != nil {
		return nil, err
	}
	return s.Task(ctx, id)
}

// UpdateTask changes a task (nil schedule, retention or enabled keep theirs).
func (s *Service) UpdateTask(ctx context.Context, id string, in TaskInput) (*Task, error) {
	cur, err := s.Task(ctx, id)
	if err != nil {
		return nil, err
	}
	if in.Schedule == nil {
		in.Schedule = &cur.Schedule
	}
	if in.Retention == nil {
		in.Retention = &cur.Retention
	}
	if err := s.checkInput(ctx, &in); err != nil {
		return nil, err
	}
	enabled := cur.Enabled
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	items, _ := json.Marshal(in.Items)
	sched, _ := json.Marshal(in.Schedule)
	ret, _ := json.Marshal(in.Retention)
	slot := ""
	if ls := in.Schedule.LastSlot(s.now()); !ls.IsZero() {
		slot = store.FormatTime(ls)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE backup_tasks SET name = ?, target = ?, items = ?, schedule = ?, retention = ?, enabled = ?,
		last_slot = CASE WHEN schedule = ? THEN last_slot ELSE ? END, updated_at = ? WHERE id = ?`,
		in.Name, in.Target, string(items), string(sched), string(ret), boolInt(enabled), string(sched), slot, store.Now(), id); err != nil {
		return nil, err
	}
	return s.Task(ctx, id)
}

// DeleteTask removes a task. Its versions stay in the repository (until
// removed by hand from the destination).
func (s *Service) DeleteTask(ctx context.Context, id string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM backup_tasks WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---- destinations -----------------------------------------------------------------

// Target is a destination as the API shows it.
type Target struct {
	cloudbackup.Target
	Maintenance     Maintenance `json:"maintenance"`
	KitDownloadedAt *time.Time  `json:"kitDownloadedAt"`
	LastCheck       *Run        `json:"lastCheck"`
}

// Targets lists the destinations (from hardyd-priv) with their upkeep.
func (s *Service) Targets(ctx context.Context) ([]Target, error) {
	var res priv.CloudTargetsResult
	if err := s.Priv.Call(ctx, priv.OpCloudTargets, nil, &res); err != nil {
		return nil, err
	}
	out := []Target{}
	for _, t := range res.Targets {
		tg := Target{Target: t, Maintenance: DefaultMaintenance}
		var maint string
		var kit sql.NullString
		if err := s.DB.QueryRowContext(ctx, `SELECT maintenance, kit_downloaded_at FROM backup_target_settings WHERE target = ?`, t.ID).Scan(&maint, &kit); err == nil {
			var m Maintenance
			if json.Unmarshal([]byte(maint), &m) == nil && m.Check() == nil {
				tg.Maintenance = m
			}
			if kit.Valid {
				k := store.ParseTime(kit.String)
				tg.KitDownloadedAt = &k
			}
		}
		if r, err := s.lastOfKind(ctx, t.ID, "check"); err == nil {
			tg.LastCheck = r
		}
		out = append(out, tg)
	}
	return out, nil
}

// SetMaintenance changes a destination's upkeep.
func (s *Service) SetMaintenance(ctx context.Context, target string, m Maintenance) error {
	if err := m.Check(); err != nil {
		return &Problem{Msg: err.Error()}
	}
	b, _ := json.Marshal(m)
	slot := ""
	if ls := m.schedule().LastSlot(s.now()); !ls.IsZero() {
		slot = store.FormatTime(ls)
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO backup_target_settings (target, maintenance, last_slot) VALUES (?, ?, ?)
		ON CONFLICT(target) DO UPDATE SET maintenance = excluded.maintenance, last_slot = excluded.last_slot`, target, string(b), slot)
	return err
}

// KitDownloaded records that a destination's recovery kit was downloaded.
func (s *Service) KitDownloaded(ctx context.Context, target string) error {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO backup_target_settings (target, kit_downloaded_at) VALUES (?, ?)
		ON CONFLICT(target) DO UPDATE SET kit_downloaded_at = excluded.kit_downloaded_at`, target, store.Now())
	return err
}

// ForgetTarget removes hardyd's settings of a destination removed from
// hardyd-priv.
func (s *Service) ForgetTarget(ctx context.Context, target string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM backup_target_settings WHERE target = ?`, target)
	return err
}

// TasksUsing lists the tasks that back up to a destination.
func (s *Service) TasksUsing(ctx context.Context, target string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT name FROM backup_tasks WHERE target = ? ORDER BY name`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ---- runs --------------------------------------------------------------------------

// Run states.
const (
	RunRunning   = "running"
	RunSucceeded = "succeeded"
	RunPartial   = "partial"
	RunFailed    = "failed"
	RunCancelled = "cancelled"
	RunMissed    = "missed"
)

// Run is one run of a task, a restore or an upkeep job.
type Run struct {
	ID         string          `json:"id"`
	TaskID     string          `json:"taskId"`
	Kind       string          `json:"kind"`
	Target     string          `json:"target"`
	JobID      string          `json:"jobId"`
	Trigger    string          `json:"trigger"`
	State      string          `json:"state"`
	StartedAt  time.Time       `json:"startedAt"`
	FinishedAt *time.Time      `json:"finishedAt"`
	Files      int64           `json:"files"`
	Bytes      int64           `json:"bytes"`
	Added      int64           `json:"added"`
	Detail     json.RawMessage `json:"detail"`
	Error      string          `json:"error"`
}

const runCols = `id, task_id, kind, target, job_id, trigger, state, started_at, finished_at, files, bytes, added, detail, error`

func scanRun(row interface{ Scan(...any) error }) (*Run, error) {
	var r Run
	var started, detail string
	var finished sql.NullString
	if err := row.Scan(&r.ID, &r.TaskID, &r.Kind, &r.Target, &r.JobID, &r.Trigger, &r.State, &started, &finished,
		&r.Files, &r.Bytes, &r.Added, &detail, &r.Error); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	r.StartedAt = store.ParseTime(started)
	if finished.Valid {
		t := store.ParseTime(finished.String)
		r.FinishedAt = &t
	}
	if detail == "" || !json.Valid([]byte(detail)) {
		detail = "{}"
	}
	r.Detail = json.RawMessage(detail)
	return &r, nil
}

func (s *Service) lastRun(ctx context.Context, task string) (*Run, error) {
	return scanRun(s.DB.QueryRowContext(ctx, `SELECT `+runCols+` FROM backup_runs WHERE task_id = ? AND kind = 'backup' ORDER BY started_at DESC LIMIT 1`, task))
}

func (s *Service) lastOfKind(ctx context.Context, target, kind string) (*Run, error) {
	return scanRun(s.DB.QueryRowContext(ctx, `SELECT `+runCols+` FROM backup_runs WHERE target = ? AND kind = ? ORDER BY started_at DESC LIMIT 1`, target, kind))
}

// Runs lists recent runs, newest first (task "" = all).
func (s *Service) Runs(ctx context.Context, task string, limit int) ([]Run, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT ` + runCols + ` FROM backup_runs`
	args := []any{}
	if task != "" {
		q += ` WHERE task_id = ?`
		args = append(args, task)
	}
	q += ` ORDER BY started_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func (s *Service) startRun(ctx context.Context, r *Run) error {
	r.StartedAt = s.now().UTC()
	if r.State == "" {
		r.State = RunRunning
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO backup_runs (id, task_id, kind, target, job_id, trigger, state, started_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.TaskID, r.Kind, r.Target, r.JobID, r.Trigger, r.State, store.FormatTime(r.StartedAt))
	return err
}

func (s *Service) finishRun(r *Run, state string, detail any, runErr error) {
	now := s.now().UTC()
	r.State, r.FinishedAt = state, &now
	if runErr != nil {
		r.Error = runErr.Error()
		if len(r.Error) > 2000 {
			r.Error = r.Error[:2000]
		}
	}
	b := []byte("{}")
	if detail != nil {
		if d, err := json.Marshal(detail); err == nil {
			b = d
		}
	}
	r.Detail = b
	if _, err := s.DB.ExecContext(context.Background(), `UPDATE backup_runs SET state = ?, finished_at = ?, files = ?, bytes = ?, added = ?, detail = ?, error = ? WHERE id = ?`,
		r.State, store.FormatTime(now), r.Files, r.Bytes, r.Added, string(b), r.Error, r.ID); err != nil {
		s.log().Error("cloud backup: recording a run", "run", r.ID, "err", err)
	}
}

// ---- following hardyd-priv's tasks ---------------------------------------------------

// follow waits for a hardyd-priv task, reporting its progress between
// from and to; cancelling the job cancels the task (restic's process
// group is interrupted).
func (s *Service) follow(jc *jobs.Context, t *cloudbackup.Task, from, to float64) (*cloudbackup.Task, error) {
	cancelled := false
	for {
		var cur cloudbackup.Task
		ctx, cancel := context.WithTimeout(context.WithoutCancel(jc), 30*time.Second)
		err := s.Priv.Call(ctx, priv.OpCloudTask, priv.CloudTaskRef{ID: t.ID}, &cur)
		cancel()
		if err != nil {
			return nil, err
		}
		jc.Progress(from+cur.Progress*(to-from)/100, cur.Message)
		if cur.Done {
			if cancelled || cur.Error == "cancelled" {
				return &cur, context.Canceled
			}
			if cur.Error != "" {
				return &cur, errors.New(cur.Error)
			}
			return &cur, nil
		}
		select {
		case <-jc.Done():
			if !cancelled {
				cancelled = true
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				_ = s.Priv.Call(ctx, priv.OpCloudCancel, priv.CloudTaskRef{ID: t.ID}, nil)
				cancel()
			}
			time.Sleep(s.poll())
		case <-time.After(s.poll()):
		}
	}
}

// ---- jobs ------------------------------------------------------------------------------

// RunParams starts a task's run.
type RunParams struct {
	Task    string `json:"task"`
	Run     string `json:"run"`
	Trigger string `json:"trigger"`
}

// RestoreParams is a restore job (cloudbackup.RestoreArgs as hardyd sends
// it: Who is the person, for restores of their own files).
type RestoreParams struct {
	cloudbackup.RestoreArgs
}

// TargetParams names a destination.
type TargetParams struct {
	Target string `json:"target"`
}

// NewRunID makes a run id: the time and a random part.
func (s *Service) NewRunID() string {
	return strings.ToLower(s.now().UTC().Format("20060102-150405")) + "-" + randHex(3)
}

func lockTarget(target string) string { return "cloud-backup:" + target }

// RegisterJobs adds the job kinds.
func (s *Service) RegisterJobs(m *jobs.Manager) {
	m.Register(jobs.Kind{Name: JobRun, AdminOnly: true, LockKey: func(raw json.RawMessage) string {
		var p RunParams
		_ = json.Unmarshal(raw, &p)
		if t, err := s.Task(context.Background(), p.Task); err == nil {
			return lockTarget(t.Target)
		}
		return "cloud-backup"
	}, Run: s.runJob})
	m.Register(jobs.Kind{Name: JobRestore, LockKey: func(raw json.RawMessage) string {
		var p RestoreParams
		_ = json.Unmarshal(raw, &p)
		return lockTarget(p.Target)
	}, Run: s.restoreJob})
	m.Register(jobs.Kind{Name: JobPrune, AdminOnly: true, LockKey: targetLock, Run: func(jc *jobs.Context) (any, error) {
		return s.upkeepJob(jc, "prune")
	}})
	m.Register(jobs.Kind{Name: JobCheck, AdminOnly: true, LockKey: targetLock, Run: func(jc *jobs.Context) (any, error) {
		return s.upkeepJob(jc, "check")
	}})
	m.Register(jobs.Kind{Name: JobRebuild, AdminOnly: true, LockKey: func(raw json.RawMessage) string {
		var p cloudbackup.RebuildArgs
		_ = json.Unmarshal(raw, &p)
		return lockTarget(p.Target)
	}, Run: s.rebuildJob})
}

func targetLock(raw json.RawMessage) string {
	var p TargetParams
	_ = json.Unmarshal(raw, &p)
	return lockTarget(p.Target)
}

// SubmitRun queues a task's run.
func (s *Service) SubmitRun(ctx context.Context, task *Task, trigger string, user *int64) (*jobs.Job, error) {
	return s.Jobs.Submit(ctx, JobRun, "Back up: "+task.Name, RunParams{Task: task.ID, Run: s.NewRunID(), Trigger: trigger}, user)
}

func (s *Service) hostname() string {
	if s.Hostname != nil {
		return s.Hostname()
	}
	h, _ := os.Hostname()
	return h
}

// systemDB copies hardyd's database for the settings item.
func (s *Service) systemDB(ctx context.Context) (string, cloudbackup.SystemMeta, error) {
	meta := cloudbackup.SystemMeta{Version: s.Version, Hostname: s.hostname()}
	if err := os.MkdirAll(s.dir(), 0o750); err != nil {
		return "", meta, err
	}
	path := filepath.Join(s.dir(), "cloud-"+randHex(8)+".db")
	if err := s.DB.Snapshot(ctx, path); err != nil {
		return "", meta, fmt.Errorf("copying the database: %w", err)
	}
	// hardyd-priv (root) reads it; nobody else needs to.
	_ = os.Chmod(path, 0o600)
	info, err := store.Inspect(ctx, path)
	if err != nil {
		os.Remove(path)
		return "", meta, err
	}
	meta.Schema, meta.Users = info.Schema, info.Users
	return path, meta, nil
}

func (s *Service) runJob(jc *jobs.Context) (any, error) {
	var p RunParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	task, err := s.Task(jc, p.Task)
	if err != nil {
		return nil, err
	}
	if cloudbackup.ValidRunID(p.Run) != nil {
		p.Run = s.NewRunID()
	}
	run := &Run{ID: p.Run, TaskID: task.ID, Kind: "backup", Target: task.Target, JobID: jc.ID(), Trigger: p.Trigger}
	if err := s.startRun(jc, run); err != nil {
		return nil, err
	}
	args := cloudbackup.BackupArgs{Target: task.Target, Task: task.ID, Run: p.Run, Items: task.Items, Retention: task.Retention}
	for _, it := range task.Items {
		if it.Kind == cloudbackup.ItemSystem {
			jc.Progress(1, "Copying the settings database")
			path, meta, err := s.systemDB(jc)
			if err != nil {
				s.finishRun(run, RunFailed, nil, err)
				s.notifyRun(jc, task, run, err)
				return nil, err
			}
			defer os.Remove(path)
			args.SystemDB, args.System = path, meta
		}
	}
	if args.System.Hostname == "" {
		args.System = cloudbackup.SystemMeta{Version: s.Version, Hostname: s.hostname()}
	}
	var started cloudbackup.Task
	if err := s.Priv.Call(jc, priv.OpCloudBackup, args, &started); err != nil {
		s.finishRun(run, RunFailed, nil, err)
		s.notifyRun(jc, task, run, err)
		return nil, err
	}
	done, ferr := s.follow(jc, &started, 2, 100)
	var res cloudbackup.RunResult
	if done != nil && len(done.Result) > 0 {
		_ = json.Unmarshal(done.Result, &res)
	}
	for _, it := range res.Items {
		run.Files += it.Files
		run.Bytes += it.Bytes
		run.Added += it.Added
	}
	state := RunSucceeded
	switch {
	case errors.Is(ferr, context.Canceled):
		state = RunCancelled
	case ferr != nil && res.Failed > 0 && res.Failed < len(res.Items):
		state = RunPartial
	case ferr != nil:
		state = RunFailed
	}
	s.finishRun(run, state, res, ferr)
	if state != RunCancelled {
		s.notifyRun(jc, task, run, ferr)
	}
	if ferr != nil {
		return nil, &jobs.FailedWith{Err: ferr, Result: res}
	}
	return res, nil
}

func (s *Service) notifyRun(ctx context.Context, t *Task, r *Run, err error) {
	e := Event{Time: s.now().UTC(), Link: "backup://tasks/" + t.ID}
	if err == nil {
		e.Kind, e.Severity, e.Title = EventBackupSucceeded, SeverityInfo, "Backup finished: "+t.Name
		e.Body = fmt.Sprintf("%d files, %s new data sent.", r.Files, humanBytes(r.Added))
	} else {
		e.Kind, e.Severity, e.Title = EventBackupFailed, SeverityCritical, "Backup failed: "+t.Name
		if r.State == RunPartial {
			e.Severity, e.Title = SeverityWarning, "Backup incomplete: "+t.Name
		}
		e.Body = err.Error()
	}
	s.notifier().Notify(context.WithoutCancel(ctx), e)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func (s *Service) restoreJob(jc *jobs.Context) (any, error) {
	var p RestoreParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	p.MaxSchema = store.SchemaVersion()
	run := &Run{ID: "x" + randHex(8), Kind: "restore", Target: p.Target, JobID: jc.ID(), Trigger: "manual"}
	if err := s.startRun(jc, run); err != nil {
		return nil, err
	}
	var started cloudbackup.Task
	if err := s.Priv.Call(jc, priv.OpCloudRestore, p.RestoreArgs, &started); err != nil {
		s.finishRun(run, RunFailed, nil, err)
		return nil, err
	}
	done, ferr := s.follow(jc, &started, 0, 100)
	var res cloudbackup.RestoreResult
	if done != nil && len(done.Result) > 0 {
		_ = json.Unmarshal(done.Result, &res)
	}
	run.Files, run.Bytes = int64(res.Files), res.Bytes
	state := RunSucceeded
	switch {
	case errors.Is(ferr, context.Canceled):
		state = RunCancelled
	case ferr != nil:
		state = RunFailed
	}
	s.finishRun(run, state, res, ferr)
	if ferr != nil {
		return nil, &jobs.FailedWith{Err: ferr, Result: res}
	}
	return res, nil
}

func (s *Service) upkeepJob(jc *jobs.Context, kind string) (any, error) {
	var p TargetParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	run := &Run{ID: "m" + randHex(8), Kind: kind, Target: p.Target, JobID: jc.ID(), Trigger: "schedule"}
	if err := s.startRun(jc, run); err != nil {
		return nil, err
	}
	var started cloudbackup.Task
	var err error
	if kind == "prune" {
		err = s.Priv.Call(jc, priv.OpCloudPrune, priv.CloudTargetRef{ID: p.Target}, &started)
	} else {
		pct := DefaultMaintenance.CheckPercent
		if l, terr := s.Targets(jc); terr == nil {
			for _, t := range l {
				if t.ID == p.Target {
					pct = t.Maintenance.CheckPercent
				}
			}
		}
		err = s.Priv.Call(jc, priv.OpCloudCheck, priv.CloudCheckArgs{Target: p.Target, Percent: pct}, &started)
	}
	if err != nil {
		s.finishRun(run, RunFailed, nil, err)
		if kind == "check" {
			s.notifyCheck(jc, p.Target, err)
		}
		return nil, err
	}
	_, ferr := s.follow(jc, &started, 0, 100)
	state := RunSucceeded
	switch {
	case errors.Is(ferr, context.Canceled):
		state = RunCancelled
	case ferr != nil:
		state = RunFailed
	}
	s.finishRun(run, state, nil, ferr)
	if kind == "check" && state == RunFailed {
		s.notifyCheck(jc, p.Target, ferr)
	}
	return map[string]string{"state": state}, ferr
}

func (s *Service) notifyCheck(ctx context.Context, target string, err error) {
	s.notifier().Notify(context.WithoutCancel(ctx), Event{Kind: EventCheckFailed, Severity: SeverityCritical,
		Title: "Backup check failed", Body: fmt.Sprintf("The backups at %s didn't pass their check: %v", target, err),
		Link: "backup://targets/" + target, Time: s.now().UTC()})
}

func (s *Service) rebuildJob(jc *jobs.Context) (any, error) {
	var p cloudbackup.RebuildArgs
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	run := &Run{ID: "b" + randHex(8), Kind: "rebuild", Target: p.Target, JobID: jc.ID(), Trigger: "manual"}
	if err := s.startRun(jc, run); err != nil {
		return nil, err
	}
	var started cloudbackup.Task
	if err := s.Priv.Call(jc, priv.OpCloudRebuild, p, &started); err != nil {
		s.finishRun(run, RunFailed, nil, err)
		return nil, err
	}
	done, ferr := s.follow(jc, &started, 0, 100)
	var res cloudbackup.RebuildResult
	if done != nil && len(done.Result) > 0 {
		_ = json.Unmarshal(done.Result, &res)
	}
	state := RunSucceeded
	switch {
	case errors.Is(ferr, context.Canceled):
		state = RunCancelled
	case ferr != nil:
		state = RunFailed
	case len(res.Failed) > 0:
		state = RunPartial
		ferr = fmt.Errorf("%d items couldn't be brought back", len(res.Failed))
	}
	s.finishRun(run, state, res, ferr)
	if ferr != nil {
		return nil, &jobs.FailedWith{Err: ferr, Result: res}
	}
	return res, nil
}

// ---- schedule ------------------------------------------------------------------------

// Recover marks runs left running by a previous hardyd as failed (their
// jobs were; hardyd-priv's task may have finished on its own).
func (s *Service) Recover(ctx context.Context) {
	if _, err := s.DB.ExecContext(ctx, `UPDATE backup_runs SET state = 'failed', error = 'interrupted: hardyd restarted', finished_at = ?
		WHERE state = 'running'`, store.Now()); err != nil {
		s.log().Warn("cloud backup: recovering runs", "err", err)
	}
}

// Run runs the schedule until ctx ends.
func (s *Service) Run(ctx context.Context) {
	s.Recover(ctx)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.Tick(ctx, now)
		}
	}
}

// MissedAfter is how late a slot may be started; later, it's reported as
// missed (the server was off or busy) and the next slot is waited for.
const MissedAfter = 30 * time.Minute

// Tick starts what's due at now and reports missed slots.
func (s *Service) Tick(ctx context.Context, now time.Time) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+taskCols+` FROM backup_tasks WHERE enabled = 1`)
	if err != nil {
		s.log().Warn("cloud backup schedule", "err", err)
		return
	}
	type due struct {
		t    *Task
		slot string
	}
	var tasks []due
	for rows.Next() {
		t, slot, err := scanTask(rows)
		if err == nil {
			tasks = append(tasks, due{t, slot})
		}
	}
	rows.Close()
	for _, d := range tasks {
		slot := d.t.Schedule.LastSlot(now)
		if slot.IsZero() {
			continue
		}
		key := store.FormatTime(slot)
		if key <= d.slot && d.slot != "" {
			continue
		}
		if _, err := s.DB.ExecContext(ctx, `UPDATE backup_tasks SET last_slot = ? WHERE id = ?`, key, d.t.ID); err != nil {
			continue
		}
		running := false
		if r, err := s.lastRun(ctx, d.t.ID); err == nil && r != nil && r.State == RunRunning {
			running = true
		}
		if d.slot == "" {
			// First tick for this task: start counting from here.
			if now.Sub(slot) > MissedAfter {
				continue
			}
		}
		if now.Sub(slot) > MissedAfter || running {
			why := "the server was off or busy at that time"
			if running {
				why = "the previous backup was still running"
			}
			s.missed(ctx, d.t, slot, why)
			continue
		}
		if _, err := s.SubmitRun(ctx, d.t, "schedule", nil); err != nil {
			s.log().Warn("cloud backup: starting a scheduled backup", "task", d.t.ID, "err", err)
		}
	}
	s.tickMaintenance(ctx, now)
}

func (s *Service) missed(ctx context.Context, t *Task, slot time.Time, why string) {
	r := &Run{ID: "s" + randHex(8), TaskID: t.ID, Kind: "backup", Target: t.Target, Trigger: "schedule", State: RunMissed}
	if err := s.startRun(ctx, r); err == nil {
		s.finishRun(r, RunMissed, map[string]string{"slot": slot.UTC().Format(time.RFC3339)}, errors.New(why))
	}
	s.notifier().Notify(ctx, Event{Kind: EventBackupMissed, Severity: SeverityWarning, Title: "Backup missed: " + t.Name,
		Body: fmt.Sprintf("The backup due %s didn't run: %s.", slot.Format("Jan 2 15:04"), why), Link: "backup://tasks/" + t.ID, Time: s.now().UTC()})
}

func (s *Service) tickMaintenance(ctx context.Context, now time.Time) {
	targets, err := s.Targets(ctx)
	if err != nil {
		return
	}
	for _, t := range targets {
		var last string
		_ = s.DB.QueryRowContext(ctx, `SELECT last_slot FROM backup_target_settings WHERE target = ?`, t.ID).Scan(&last)
		slot := t.Maintenance.schedule().LastSlot(now)
		if slot.IsZero() {
			continue
		}
		key := store.FormatTime(slot)
		if key <= last && last != "" {
			continue
		}
		mb, _ := json.Marshal(t.Maintenance)
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO backup_target_settings (target, maintenance, last_slot) VALUES (?, ?, ?)
			ON CONFLICT(target) DO UPDATE SET last_slot = excluded.last_slot`, t.ID, string(mb), key); err != nil {
			continue
		}
		if last == "" || now.Sub(slot) > 6*time.Hour {
			continue // first sight, or long past: wait for the next one
		}
		title := t.Name
		if _, err := s.Jobs.Submit(ctx, JobPrune, "Free space: "+title, TargetParams{Target: t.ID}, nil); err != nil {
			s.log().Warn("cloud backup: prune", "target", t.ID, "err", err)
		}
		if _, err := s.Jobs.Submit(ctx, JobCheck, "Check backups: "+title, TargetParams{Target: t.ID}, nil); err != nil {
			s.log().Warn("cloud backup: check", "target", t.ID, "err", err)
		}
	}
}
