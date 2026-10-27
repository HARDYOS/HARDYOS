// Package notify is HardyOS's notification system: the desktop's
// notification center (Center), and the dispatcher (Dispatcher) that takes
// every Event, routes it by kind and severity to the desktop and to
// channels (Discord, Slack, Teams, webhooks, email over SMTP, Amazon SES),
// and holds back duplicates, floods and quiet-hours noise.
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
	// Kind is the event kind ("disk.smart"); Link where it points in the
	// desktop ("storage/disks"). Both empty for older entries.
	Kind string `json:"kind"`
	Link string `json:"link"`
}

// Center records notifications.
type Center struct {
	DB     *store.DB
	Events *events.Broker
	// Forward, when set, receives what Send is given instead of storing it
	// directly: the dispatcher then routes it (desktop and channels) like
	// any event. Store is what the dispatcher calls for the desktop.
	Forward func(ctx context.Context, n Notification)
}

// Send stores a notification and publishes it (or hands it to Forward).
// Packages that predate events (storage jobs, updates, settings backups)
// call it.
func (c *Center) Send(ctx context.Context, n Notification) error {
	if c.Forward != nil {
		c.Forward(ctx, n)
		return nil
	}
	return c.Store(ctx, n)
}

// Store writes a notification to the desktop's center and publishes it,
// without routing.
func (c *Center) Store(ctx context.Context, n Notification) error {
	if n.At.IsZero() {
		n.At = time.Now().UTC()
	}
	res, err := c.DB.ExecContext(ctx, `INSERT INTO notifications (at, level, title, body, source, admin_only, kind, link) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		store.FormatTime(n.At), n.Level, n.Title, n.Body, n.Source, boolInt(n.AdminOnly), n.Kind, n.Link)
	if err != nil {
		return err
	}
	n.ID, _ = res.LastInsertId()
	if c.Events != nil {
		c.Events.PublishJSON(events.TypeNotification, n, n.AdminOnly, 0)
	}
	// Keep the center to its newest entries.
	_, _ = c.DB.ExecContext(ctx, `DELETE FROM notifications WHERE id <= ? - 2000`, n.ID)
	return nil
}

// visible is the WHERE clause for what a user may see.
func visible(admin bool) string {
	if admin {
		return "1=1"
	}
	return "n.admin_only = 0"
}

// List returns recent notifications, newest first, without anyone's read
// state (see ListFor).
func (c *Center) List(ctx context.Context, admin bool, limit int) ([]Notification, error) {
	return c.ListFor(ctx, 0, admin, limit)
}

// ListFor returns recent notifications visible to the user, newest first,
// with ReadAt as that user read them.
func (c *Center) ListFor(ctx context.Context, userID int64, admin bool, limit int) ([]Notification, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := c.DB.QueryContext(ctx, `SELECT n.id, n.at, n.level, n.title, n.body, n.source, n.admin_only, n.kind, n.link,
		COALESCE(r.read_at, n.read_at)
		FROM notifications n LEFT JOIN notification_reads r ON r.notification_id = n.id AND r.user_id = ?
		WHERE `+visible(admin)+` ORDER BY n.id DESC LIMIT ?`, userID, limit)
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
		if err := rows.Scan(&n.ID, &at, &n.Level, &n.Title, &n.Body, &n.Source, &adminOnly, &n.Kind, &n.Link, &readAt); err != nil {
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

// Unread counts the notifications the user hasn't read.
func (c *Center) Unread(ctx context.Context, userID int64, admin bool) (int, error) {
	var n int
	err := c.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM notifications n
		LEFT JOIN notification_reads r ON r.notification_id = n.id AND r.user_id = ?
		WHERE `+visible(admin)+` AND r.read_at IS NULL AND n.read_at IS NULL`, userID).Scan(&n)
	return n, err
}

// MarkRead marks one notification (id > 0) or all visible ones (id == 0)
// read for one user. Each person has their own read state.
func (c *Center) MarkRead(ctx context.Context, userID, id int64, admin bool) error {
	if userID <= 0 {
		return nil
	}
	q := `INSERT OR IGNORE INTO notification_reads (notification_id, user_id, read_at)
		SELECT n.id, ?, ? FROM notifications n WHERE ` + visible(admin)
	args := []any{userID, store.Now()}
	if id > 0 {
		q += ` AND n.id = ?`
		args = append(args, id)
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
