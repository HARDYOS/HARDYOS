// Package convert is "Make highly available" and "Make local again"
// (docs/plans/make-ha.md, decisions 480-489): the jobs that copy a VM's or
// an app's datasets between a compute server's own pool and the storage
// server's cluster pool, register it as a cluster workload (or remove it
// from the cluster), and keep the copy it came from for a grace period.
//
// A conversion runs on the compute server that holds the workload (or,
// for "Make local again", the one it goes to). Its progress is kept in
// cluster_conversions, so a failed or interrupted conversion resumes from
// where it got to, and is undone or abandoned only by an administrator.
// The rules that keep a workload from running twice: the local copy is
// parked (no longer a VM or app) before the cluster workload exists, the
// cluster workload is removed before the local copy is adopted, and
// nothing is rolled back by itself once a copy may have run.
package convert

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
	"github.com/hardyos/hardyos/daemon/internal/cluster/storagesvc"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Job kinds.
const (
	JobToHA       = "cluster.ha.convert"
	JobToLocal    = "cluster.ha.local"
	JobUndo       = "cluster.ha.undo"
	JobAbandon    = "cluster.ha.abandon"
	JobParkedDrop = "cluster.ha.parked.delete"
)

// Directions.
const (
	DirHA    = "ha"
	DirLocal = "local"
)

// Conversion states.
const (
	StateRunning   = "running"
	StateDone      = "done"
	StateFailed    = "failed"
	StateUndone    = "undone"
	StateAbandoned = "abandoned"
)

// DefaultGrace is how long a parked copy is kept after the workload ran
// from its new storage (the owner's choice: a day).
const DefaultGrace = 24 * time.Hour

// Priv is the part of priv.Client conversions use.
type Priv interface {
	Call(ctx context.Context, op string, args, out any) error
	CallFile(ctx context.Context, op string, args, out any) (*os.File, error)
}

// Cluster is the part of the membership conversions use.
type Cluster interface {
	Self() (cluster.Node, error)
	State() cluster.State
	Quorate() (bool, time.Time)
	Propose(ctx context.Context, t cluster.CommandType, body any, actor cluster.Actor) (uint64, error)
	WaitApplied(ctx context.Context, index uint64) error
}

// Storage is what conversions use of part B's service (the storage
// server's side over the peer API, and attaching here).
type Storage interface {
	HAPool(ctx context.Context) (string, error)
	HAOpenRecv(ctx context.Context, r storagesvc.HAStreamRequest) (*storagesvc.HAStreamOpened, error)
	HAOpenSend(ctx context.Context, r storagesvc.HAStreamRequest) (*storagesvc.HAStreamOpened, error)
	HAStream(ctx context.Context, stream string) (*hacopy.StreamState, error)
	HATree(ctx context.Context, r storagesvc.HARequest) (*hacopy.Tree, error)
	HAAdopt(ctx context.Context, r storagesvc.HARequest) (*cluster.WorkloadStorage, error)
	HAAbort(ctx context.Context, r storagesvc.HARequest) error
	HASnapshot(ctx context.Context, r storagesvc.HARequest) error
	HAPark(ctx context.Context, r storagesvc.HARequest) (*hacopy.ParkResult, error)
	HAUnpark(ctx context.Context, r storagesvc.HARequest) error
	HAParked(ctx context.Context) ([]hacopy.Parked, error)
	HAParkedKeep(ctx context.Context, r storagesvc.HARequest) error
	HAParkedDestroy(ctx context.Context, r storagesvc.HAParkedDestroy) error
	// CopyConn opens the copy connection for an opened stream.
	CopyConn(ctx context.Context, token string) (Conn, error)
	SwitchAppMode(ctx context.Context, r storagesvc.ModeRequest) (*storagesvc.ModeResult, error)
	Attach(ctx context.Context, ws cluster.WorkloadStorage, g cluster.Grant) (*cluster.Attachment, error)
	Detach(ctx context.Context, w cluster.WorkloadRef, force bool) error
}

// Specs is what conversions use of part C's service.
type Specs interface {
	// ApproveSpec records a workload's settings as they are on its
	// storage now (its owner; workload.spec).
	ApproveSpec(ctx context.Context, w cluster.WorkloadRef, actor cluster.Actor) error
	// Hold keeps the reconciler off a workload until the release.
	Hold(w cluster.WorkloadRef) func()
}

// NetCheck reports whether this server's local network is fit for HA
// (decision 487): "Make highly available" and live moves are refused when
// it isn't. The cluster's netcheck package implements it; AlwaysOK is the
// default until it is wired (cmd/hardyd/cluster_c.go).
type NetCheck interface {
	LocalNetworkOK(ctx context.Context) (bool, string)
}

// AlwaysOK is the NetCheck that never refuses.
type AlwaysOK struct{}

// LocalNetworkOK implements NetCheck.
func (AlwaysOK) LocalNetworkOK(context.Context) (bool, string) { return true, "" }

// Converter runs conversions on this server.
type Converter struct {
	Cluster Cluster
	Storage Storage
	Priv    Priv
	Specs   Specs
	DB      *store.DB
	Jobs    *jobs.Manager
	Audit   *audit.Log
	Notify  notify.Notifier
	Net     NetCheck
	Log     *slog.Logger
	// Grace is how long parked copies are kept (DefaultGrace).
	Grace time.Duration
	// Now and Poll are for tests.
	Now  func() time.Time
	Poll time.Duration
}

func (c *Converter) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

func (c *Converter) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Converter) poll() time.Duration {
	if c.Poll > 0 {
		return c.Poll
	}
	return 2 * time.Second
}

func (c *Converter) grace() time.Duration {
	if c.Grace > 0 {
		return c.Grace
	}
	return DefaultGrace
}

func (c *Converter) net() NetCheck {
	if c.Net != nil {
		return c.Net
	}
	return AlwaysOK{}
}

// ErrNotMember: this server isn't in a cluster.
var ErrNotMember = cluster.ErrNotMember

// Member reports whether this server is in a cluster.
func (c *Converter) Member() bool {
	if c == nil || c.Cluster == nil {
		return false
	}
	_, err := c.Cluster.Self()
	return err == nil
}

// NetworkOK is the LAN check (decision 487).
func (c *Converter) NetworkOK(ctx context.Context) (bool, string) { return c.net().LocalNetworkOK(ctx) }

// ---- records ------------------------------------------------------------------------

// Options are a conversion's choices and what it learnt along the way.
type Options struct {
	// Priority is the HA priority (1-100).
	Priority int `json:"priority,omitempty"`
	// CPU: "baseline" (the cluster's CPU model) or "host" (keep the VM's).
	CPU      string `json:"cpu,omitempty"`
	CPUModel string `json:"cpuModel,omitempty"`
	SetCPU   bool   `json:"setCPU,omitempty"`
	// Hash is the approved settings' hash registered with workload.add.
	Hash string `json:"hash,omitempty"`
	// Dir is an app's folder before it moved (its compose file names it).
	Dir string `json:"dir,omitempty"`
	// Mode is an app's data mode on cluster storage.
	Mode string `json:"mode,omitempty"`
	UID  int    `json:"uid,omitempty"`
	// Storage is what the storage server adopted.
	Storage *cluster.WorkloadStorage `json:"storage,omitempty"`
	// ParkedPool and ParkedName name the copy kept on the other side;
	// ParkedSide is where (local or cluster).
	ParkedPool string `json:"parkedPool,omitempty"`
	ParkedName string `json:"parkedName,omitempty"`
	ParkedSide string `json:"parkedSide,omitempty"`
	// Generation is the cluster workload's generation the conversion
	// registered (to HA) or took its final snapshot at (to local), with
	// the placement's change time then.
	Generation uint64    `json:"generation,omitempty"`
	Changed    time.Time `json:"changed,omitzero"`
	// AwaitStart: the workload wasn't running, so the kept copy's grace
	// period starts once it first runs from its new storage.
	AwaitStart bool `json:"awaitStart,omitempty"`
	// Attempt counts the runs that took snapshots (their names carry it).
	Attempt int `json:"attempt,omitempty"`
}

// Record is one conversion.
type Record struct {
	ID          string               `json:"id"`
	Direction   string               `json:"direction"`
	Kind        cluster.WorkloadKind `json:"kind"`
	Workload    string               `json:"workload"`
	Name        string               `json:"name"`
	StoragePool string               `json:"storagePool"`
	LocalPool   string               `json:"localPool"`
	Phase       string               `json:"phase"`
	State       string               `json:"state"`
	Problem     string               `json:"problem,omitempty"`
	JobID       string               `json:"jobId"`
	WasRunning  bool                 `json:"wasRunning"`
	Options     Options              `json:"options"`
	BytesDone   int64                `json:"bytesDone"`
	BytesTotal  int64                `json:"bytesTotal"`
	Actor       string               `json:"actor"`
	Started     time.Time            `json:"started"`
	Updated     time.Time            `json:"updated"`
	Finished    time.Time            `json:"finished,omitzero"`
}

// Ref is the record's workload.
func (r *Record) Ref() cluster.WorkloadRef { return cluster.WorkloadRef{Kind: r.Kind, ID: r.Workload} }

func newID() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	const alpha = "abcdefghijklmnopqrstuvwxyz234567"
	out := make([]byte, len(b))
	for i, x := range b {
		out[i] = alpha[int(x)%len(alpha)]
	}
	return string(out)
}

const recordCols = `id, direction, kind, workload, name, storage_pool, local_pool, phase, state, problem, job_id, was_running, options,
	bytes_done, bytes_total, actor, started_at, updated_at, finished_at`

func scanRecord(sc interface{ Scan(...any) error }) (*Record, error) {
	var r Record
	var opts, st, up, fi string
	var was int
	if err := sc.Scan(&r.ID, &r.Direction, &r.Kind, &r.Workload, &r.Name, &r.StoragePool, &r.LocalPool, &r.Phase, &r.State, &r.Problem,
		&r.JobID, &was, &opts, &r.BytesDone, &r.BytesTotal, &r.Actor, &st, &up, &fi); err != nil {
		return nil, err
	}
	r.WasRunning = was != 0
	_ = json.Unmarshal([]byte(opts), &r.Options)
	r.Started, r.Updated = store.ParseTime(st), store.ParseTime(up)
	if fi != "" {
		r.Finished = store.ParseTime(fi)
	}
	return &r, nil
}

func (c *Converter) save(ctx context.Context, r *Record) error {
	if c.DB == nil {
		return nil
	}
	r.Updated = c.now().UTC()
	opts, _ := json.Marshal(r.Options)
	fi := ""
	if !r.Finished.IsZero() {
		fi = store.FormatTime(r.Finished)
	}
	_, err := c.DB.ExecContext(context.WithoutCancel(ctx), `INSERT INTO cluster_conversions (`+recordCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name = excluded.name, storage_pool = excluded.storage_pool, local_pool = excluded.local_pool,
			phase = excluded.phase, state = excluded.state, problem = excluded.problem, job_id = excluded.job_id,
			was_running = excluded.was_running, options = excluded.options, bytes_done = excluded.bytes_done,
			bytes_total = excluded.bytes_total, updated_at = excluded.updated_at, finished_at = excluded.finished_at`,
		r.ID, r.Direction, string(r.Kind), r.Workload, r.Name, r.StoragePool, r.LocalPool, r.Phase, r.State, r.Problem, r.JobID,
		boolInt(r.WasRunning), string(opts), r.BytesDone, r.BytesTotal, r.Actor, store.FormatTime(r.Started), store.FormatTime(r.Updated), fi)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Get reads a conversion.
func (c *Converter) Get(ctx context.Context, id string) (*Record, error) {
	if c.DB == nil {
		return nil, sql.ErrNoRows
	}
	return scanRecord(c.DB.QueryRowContext(ctx, `SELECT `+recordCols+` FROM cluster_conversions WHERE id = ?`, id))
}

// List returns the latest conversions run here.
func (c *Converter) List(ctx context.Context, limit int) ([]Record, error) {
	out := []Record{}
	if c.DB == nil {
		return out, nil
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := c.DB.QueryContext(ctx, `SELECT `+recordCols+` FROM cluster_conversions ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// open finds an unfinished conversion of a workload in one direction.
func (c *Converter) open(ctx context.Context, w cluster.WorkloadRef) (*Record, error) {
	if c.DB == nil {
		return nil, nil
	}
	r, err := scanRecord(c.DB.QueryRowContext(ctx, `SELECT `+recordCols+` FROM cluster_conversions
		WHERE kind = ? AND workload = ? AND state IN ('running', 'failed') ORDER BY started_at DESC LIMIT 1`, string(w.Kind), w.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// Open is the unfinished conversion of a workload, if any.
func (c *Converter) Open(ctx context.Context, w cluster.WorkloadRef) (*Record, error) {
	return c.open(ctx, w)
}

// OnStart marks conversions a hardyd restart interrupted as failed (their
// job was failed with it); they resume when started again.
func (c *Converter) OnStart(ctx context.Context) {
	if c.DB == nil {
		return
	}
	if _, err := c.DB.ExecContext(ctx, `UPDATE cluster_conversions SET state = 'failed', problem = 'interrupted: hardyd restarted', updated_at = ?
		WHERE state = 'running'`, store.FormatTime(c.now())); err != nil {
		c.log().Warn("convert: marking interrupted conversions", "err", err)
	}
}

// ---- helpers -------------------------------------------------------------------------

func (c *Converter) audit(actor cluster.Actor, action, target, detail string, err error) {
	if c.Audit == nil {
		return
	}
	out := audit.Success
	if err != nil {
		out = audit.Failure
		if detail != "" {
			detail += ": "
		}
		detail += err.Error()
	}
	name := actor.Name
	if actor.Via != "" {
		name += " (via " + string(actor.Via) + ")"
	}
	_ = c.Audit.Record(context.Background(), audit.Entry{Actor: name, Action: action, Target: target, Outcome: out, Detail: detail})
}

func (c *Converter) alert(kind, sev, title, body string) {
	if c.Notify == nil {
		return
	}
	c.Notify.Notify(context.Background(), notify.Event{Kind: kind, Severity: sev, Title: title, Body: body, Link: "cluster", Time: c.now()})
}

func (c *Converter) propose(ctx context.Context, t cluster.CommandType, body any, actor cluster.Actor) error {
	idx, err := c.Cluster.Propose(ctx, t, body, actor)
	if err != nil {
		return err
	}
	return c.Cluster.WaitApplied(ctx, idx)
}

func (c *Converter) snapshot() *cluster.Snapshot { return c.Cluster.State().Snapshot() }

// waitFor polls cond until it says done, an error, or the time is up.
func (c *Converter) waitFor(ctx context.Context, d time.Duration, what string, cond func(*cluster.Snapshot) (bool, error)) error {
	deadline := c.now().Add(d)
	for {
		done, err := cond(c.snapshot())
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if c.now().After(deadline) {
			return fmt.Errorf("%s took longer than %s", what, d)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.poll()):
		}
	}
}

func refString(w cluster.WorkloadRef) string { return string(w.Kind) + ":" + w.ID }

// localLock is the lock key of a workload's own jobs (the VMs' and apps'
// start, stop and settings).
func localLock(w cluster.WorkloadRef) string {
	if w.Kind == cluster.KindApp {
		return "app:" + w.ID
	}
	return "vm:" + w.ID
}

// ClusterLock is the lock key of a cluster workload's jobs (moves,
// requests, policies): conversions take it too.
func ClusterLock(w cluster.WorkloadRef) string { return "cluster:" + string(w.Kind) + ":" + w.ID }

// snapName is a conversion snapshot's name. Each attempt takes its own:
// a workload that ran again after a failed attempt has changed since the
// earlier attempt's snapshots, so a retry must not take those for its
// final state.
func snapName(conv, what string, attempt int) string {
	return fmt.Sprintf("hardyos-ha-%s-%s%d", conv, what, attempt)
}

// fail records a failed phase; the job fails with err.
func (c *Converter) fail(ctx context.Context, r *Record, err error) error {
	r.State, r.Problem = StateFailed, err.Error()
	if errors.Is(err, context.Canceled) {
		r.Problem = "cancelled"
	}
	_ = c.save(ctx, r)
	return err
}

// phase records progress through the phases.
func (c *Converter) phase(ctx context.Context, jc progress, r *Record, phase string, pct float64, msg string) {
	r.Phase = phase
	_ = c.save(ctx, r)
	if jc != nil {
		jc.Progress(pct, msg)
	}
}

type progress interface {
	Progress(pct float64, msg string)
}

// hostCheck: this server is an active compute member with quorum.
func (c *Converter) hostCheck() (cluster.Node, *cluster.Snapshot, error) {
	self, err := c.Cluster.Self()
	if err != nil {
		return cluster.Node{}, nil, ErrNotMember
	}
	if self.Role != cluster.RoleCompute {
		return self, nil, errors.New("only a compute server runs cluster workloads")
	}
	snap := c.snapshot()
	n := snap.Nodes[self.ID]
	if n == nil || n.State != cluster.NodeActive {
		return self, nil, errors.New("this server isn't an active member of the cluster")
	}
	if q, _ := c.Cluster.Quorate(); !q {
		return self, nil, cluster.ErrNoQuorum
	}
	return self, snap, nil
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

var errTyped = errors.New("type the name to confirm")

func confirmed(confirm string, names ...string) bool {
	confirm = strings.TrimSpace(confirm)
	for _, n := range names {
		if n != "" && confirm == n {
			return true
		}
	}
	return false
}
