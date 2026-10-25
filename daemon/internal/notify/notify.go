// Package notify stores notifications for the desktop's notification center
// and pushes them live over the event stream.
package notify

import (
	"context"
	"database/sql"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Level of a notification.
type Level string

const (
	Info    Level = "info"
	Success Level = "success"
	Warning Level = "warning"
	Error   Level = "error"
)

// Notification is one entry in the notification center.
type Notification struct {
	ID        int64      `json:"id"`
	At        time.Time  `json:"at"`
	Level     Level      `json:"level"`
	Title     string     `json:"title"`
	Body      string     `json:"body"`
	Source    string     `json:"source"`
	AdminOnly bool       `json:"adminOnly"`
	ReadAt    *time.Time `json:"readAt"`
}

// Center records notifications.
type Center struct {
	DB     *store.DB
	Events *events.Broker
}

// Send stores a notification and publishes it.
func (c *Center) Send(ctx context.Context, n Notification) error {
	if n.At.IsZero() {
		n.At = time.Now().UTC()
	}
	res, err := c.DB.ExecContext(ctx, `INSERT INTO notifications (at, level, title, body, source, admin_only) VALUES (?, ?, ?, ?, ?, ?)`,
		store.FormatTime(n.At), n.Level, n.Title, n.Body, n.Source, boolInt(n.AdminOnly))
	if err != nil {
		return err
	}
	n.ID, _ = res.LastInsertId()
	if c.Events != nil {
		c.Events.PublishJSON(events.TypeNotification, n, n.AdminOnly, 0)
	}
	return nil
}

// List returns recent notifications visible to the user, newest first.
func (c *Center) List(ctx context.Context, admin bool, limit int) ([]Notification, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `SELECT id, at, level, title, body, source, admin_only, read_at FROM notifications`
	if !admin {
		q += ` WHERE admin_only = 0`
	}
	q += ` ORDER BY id DESC LIMIT ?`
	rows, err := c.DB.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Notification{}
	for rows.Next() {
		var n Notification
		var at string
		var adminOnly int
		var readAt sql.NullString
		if err := rows.Scan(&n.ID, &at, &n.Level, &n.Title, &n.Body, &n.Source, &adminOnly, &readAt); err != nil {
			return nil, err
		}
		n.At, n.AdminOnly = store.ParseTime(at), adminOnly != 0
		if readAt.Valid {
			t := store.ParseTime(readAt.String)
			n.ReadAt = &t
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// MarkRead marks one notification (id > 0) or all visible ones (id == 0) read.
func (c *Center) MarkRead(ctx context.Context, id int64, admin bool) error {
	q := `UPDATE notifications SET read_at = ? WHERE read_at IS NULL`
	args := []any{store.Now()}
	if id > 0 {
		q += ` AND id = ?`
		args = append(args, id)
	}
	if !admin {
		q += ` AND admin_only = 0`
	}
	_, err := c.DB.ExecContext(ctx, q, args...)
	return err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
