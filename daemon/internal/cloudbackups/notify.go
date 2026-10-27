package cloudbackups

import (
	"context"
	"time"
)

// Notifications go through a small local interface: internal/notify's
// event delivery (email, push, ...) is being built separately and plugs
// in here; until then hardyd wires NopNotifier. Event has exactly the
// fields of notify.Event.

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
