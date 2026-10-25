// Package audit records every state-changing action: who, what, when, and
// whether it worked.
package audit

import (
	"context"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Outcome of an audited action.
type Outcome string

const (
	Success Outcome = "success"
	Failure Outcome = "failure"
	Denied  Outcome = "denied"
)

// Entry is one audit record.
type Entry struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	ActorID *int64    `json:"actorId"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
	Outcome Outcome   `json:"outcome"`
	Detail  string    `json:"detail"`
	IP      string    `json:"ip"`
}

// Log writes and reads the audit trail.
type Log struct {
	DB     *store.DB
	Events *events.Broker
}

// Record appends an entry. Failures to write are returned but callers
// generally log and continue rather than failing the user's action.
func (l *Log) Record(ctx context.Context, e Entry) error {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	if len(e.Detail) > 2000 {
		e.Detail = e.Detail[:2000]
	}
	res, err := l.DB.ExecContext(ctx, `INSERT INTO audit_log (at, actor_id, actor, action, target, outcome, detail, ip)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		store.FormatTime(e.At), e.ActorID, e.Actor, e.Action, e.Target, e.Outcome, e.Detail, e.IP)
	if err != nil {
		return err
	}
	e.ID, _ = res.LastInsertId()
	if l.Events != nil {
		l.Events.PublishJSON(events.TypeAudit, e, true, 0)
	}
	return nil
}

// Query filters for List.
type Query struct {
	ActorID *int64
	Action  string // prefix match, e.g. "user." or "storage.pool.create"
	Limit   int
	Before  int64 // return entries with id < Before (for paging); 0 = newest
}

// List returns entries newest first.
func (l *Log) List(ctx context.Context, q Query) ([]Entry, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 100
	}
	sql := `SELECT id, at, actor_id, actor, action, target, outcome, detail, ip FROM audit_log WHERE 1=1`
	var args []any
	if q.ActorID != nil {
		sql += ` AND actor_id = ?`
		args = append(args, *q.ActorID)
	}
	if q.Action != "" {
		sql += ` AND action LIKE ? ESCAPE '\'`
		args = append(args, escapeLike(q.Action)+"%")
	}
	if q.Before > 0 {
		sql += ` AND id < ?`
		args = append(args, q.Before)
	}
	sql += ` ORDER BY id DESC LIMIT ?`
	args = append(args, q.Limit)

	rows, err := l.DB.QueryContext(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		var at string
		if err := rows.Scan(&e.ID, &at, &e.ActorID, &e.Actor, &e.Action, &e.Target, &e.Outcome, &e.Detail, &e.IP); err != nil {
			return nil, err
		}
		e.At = store.ParseTime(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

func escapeLike(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '%' || r == '_' || r == '\\' {
			out = append(out, '\\')
		}
		out = append(out, r)
	}
	return string(out)
}
