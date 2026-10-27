package cloudbackups

import (
	"context"
	"time"
)

// Notifications go through a small local interface; hardyd plugs in the
// alert dispatcher (internal/notify), so routing, channels and quiet hours
// apply. Event has exactly the fields of notify.Event, and every kind
// starts with "backup." (the routing category).

// Severities.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Event kinds this package emits.
const (
	EventBackupSucceeded = "backup.succeeded"
	EventBackupFailed    = "backup.failed"
	EventBackupMissed    = "backup.missed"
	EventCheckFailed     = "backup.check_failed"
)

// Event is something worth telling an administrator.
type Event struct {
	Kind     string
	Severity string
	Title    string
	Body     string
	Link     string
	Time     time.Time
}

// Notifier delivers events.
type Notifier interface {
	Notify(ctx context.Context, e Event)
}

// NopNotifier drops every event.
type NopNotifier struct{}

// Notify implements Notifier.
func (NopNotifier) Notify(context.Context, Event) {}

// NotifierFunc adapts a function (tests, integration).
type NotifierFunc func(ctx context.Context, e Event)

// Notify implements Notifier.
func (f NotifierFunc) Notify(ctx context.Context, e Event) { f(ctx, e) }
