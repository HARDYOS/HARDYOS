package monitor

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Condition is something the monitor currently sees wrong: a degraded
// pool, a hot disk, an app that keeps restarting. It's raised once (an
// alert), updated quietly while it lasts, raised again only if it gets
// worse (or eases to a lower severity), and cleared once (a "resolved"
// notice). Conditions survive restarts, so a restart doesn't repeat them.
type Condition struct {
	Key      string    `json:"key"` // "pool.health:tank", "disk.smart:<by-id>"
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Title    string    `json:"title"`
	Body     string    `json:"body"`
	Link     string    `json:"link"`
	Since    time.Time `json:"since"`
}

type conditions struct {
	db     *store.DB
	notify notify.Notifier
	now    func() time.Time
	mu     sync.Mutex
}

func (c *conditions) get(ctx context.Context, key string) (*Condition, bool) {
	var x Condition
	var since string
	err := c.db.QueryRowContext(ctx, `SELECT key, kind, severity, title, body, link, since FROM monitor_conditions WHERE key = ?`, key).
		Scan(&x.Key, &x.Kind, &x.Severity, &x.Title, &x.Body, &x.Link, &since)
	if err != nil {
		return nil, false
	}
	x.Since = store.ParseTime(since)
	return &x, true
}

// Set raises or updates a condition.
func (c *conditions) Set(ctx context.Context, x Condition) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	prev, had := c.get(ctx, x.Key)
	since := now
	if had {
		since = prev.Since
	}
	_, _ = c.db.ExecContext(ctx, `INSERT INTO monitor_conditions (key, kind, severity, title, body, link, since, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET kind = excluded.kind, severity = excluded.severity, title = excluded.title, body = excluded.body,
		link = excluded.link, updated_at = excluded.updated_at`,
		x.Key, x.Kind, x.Severity, x.Title, x.Body, x.Link, store.FormatTime(since), store.FormatTime(now))
	if had && prev.Severity == x.Severity {
		return
	}
	c.notify.Notify(ctx, notify.Event{Kind: x.Kind, Severity: x.Severity, Title: x.Title, Body: x.Body, Link: x.Link, Time: now})
}

// Clear ends a condition, with a notice saying it's resolved.
func (c *conditions) Clear(ctx context.Context, key, title, body string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev, had := c.get(ctx, key)
	if !had {
		return
	}
	_, _ = c.db.ExecContext(ctx, `DELETE FROM monitor_conditions WHERE key = ?`, key)
	if title == "" {
		return
	}
	c.notify.Notify(ctx, notify.Event{Kind: prev.Kind, Severity: notify.SeverityInfo, Title: title, Body: body, Link: prev.Link, Time: c.now()})
}

// Has reports whether a condition is raised.
func (c *conditions) Has(ctx context.Context, key string) bool {
	_, ok := c.get(ctx, key)
	return ok
}

// Keys lists raised conditions whose key starts with prefix.
func (c *conditions) Keys(ctx context.Context, prefix string) []string {
	rows, err := c.db.QueryContext(ctx, `SELECT key FROM monitor_conditions WHERE key LIKE ? ESCAPE '\'`, escapeLike(prefix)+"%")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if rows.Scan(&k) == nil {
			out = append(out, k)
		}
	}
	return out
}

// Drop silently forgets conditions under prefix that aren't in keep (the
// pool, disk, app or VM is gone).
func (c *conditions) Drop(ctx context.Context, prefix string, keep map[string]bool) {
	for _, k := range c.Keys(ctx, prefix) {
		if !keep[k] {
			c.Clear(ctx, k, "", "")
		}
	}
}

// List returns every raised condition, most severe first.
func (c *conditions) List(ctx context.Context) ([]Condition, error) {
	rows, err := c.db.QueryContext(ctx, `SELECT key, kind, severity, title, body, link, since FROM monitor_conditions
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, since`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Condition{}
	for rows.Next() {
		var x Condition
		var since string
		if err := rows.Scan(&x.Key, &x.Kind, &x.Severity, &x.Title, &x.Body, &x.Link, &since); err != nil {
			return nil, err
		}
		x.Since = store.ParseTime(since)
		out = append(out, x)
	}
	return out, rows.Err()
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
