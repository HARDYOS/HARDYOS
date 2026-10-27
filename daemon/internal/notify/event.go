package notify

import (
	"context"
	"strings"
	"time"
)

// Event is one alert or notice from anywhere in HardyOS: a check in
// internal/monitor, a backup or replication run, a disk test. Other
// packages emit it through a local interface with the method
// Notify(ctx, Event); this shape is shared and kept stable.
//
//   - Kind names what happened, "<category>.<what>", e.g. "disk.smart",
//     "pool.capacity", "ups.power", "backup.failed". Routing uses the
//     category (the part before the first dot).
//   - Severity is SeverityInfo, SeverityWarning or SeverityCritical.
//   - Link points into the desktop ("storage/disks", "ups", "apps/<id>");
//     empty when there's nowhere to go.
//   - Time is when it happened (zero: now).
type Event struct {
	Kind, Severity, Title, Body, Link string
	Time                              time.Time
}

// Severities, lowest first.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Notifier is anything events can be handed to. *Dispatcher is the real
// one; Discard drops them.
type Notifier interface {
	Notify(ctx context.Context, e Event)
}

// NotifierFunc adapts a function to Notifier.
type NotifierFunc func(ctx context.Context, e Event)

// Notify implements Notifier.
func (f NotifierFunc) Notify(ctx context.Context, e Event) { f(ctx, e) }

// Discard is a Notifier that drops every event.
var Discard Notifier = NotifierFunc(func(context.Context, Event) {})

// SeverityRank orders severities: info 0, warning 1, critical 2. Unknown
// severities count as info.
func SeverityRank(s string) int {
	switch s {
	case SeverityWarning:
		return 1
	case SeverityCritical:
		return 2
	}
	return 0
}

// ValidSeverity reports whether s is one of the three severities.
func ValidSeverity(s string) bool {
	return s == SeverityInfo || s == SeverityWarning || s == SeverityCritical
}

// Category is the routing category of a kind: the part before the first
// dot ("disk.smart" -> "disk"); a kind without a dot is its own category.
func Category(kind string) string {
	c, _, _ := strings.Cut(kind, ".")
	return c
}

// levelFor maps a severity to the desktop notification level.
func levelFor(sev string) Level {
	switch sev {
	case SeverityCritical:
		return Error
	case SeverityWarning:
		return Warning
	}
	return Info
}

// severityFor maps a desktop level to a severity (success is info).
func severityFor(l Level) string {
	switch l {
	case Error:
		return SeverityCritical
	case Warning:
		return SeverityWarning
	}
	return SeverityInfo
}

// normalize fills defaults and bounds the text an event may carry.
func (e Event) normalize() Event {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Time = e.Time.UTC()
	if !ValidSeverity(e.Severity) {
		e.Severity = SeverityInfo
	}
	e.Kind = clip(strings.TrimSpace(e.Kind), 80)
	if e.Kind == "" {
		e.Kind = "system.notice"
	}
	e.Title = clip(oneLine(e.Title), 200)
	if e.Title == "" {
		e.Title = e.Kind
	}
	e.Body = clip(e.Body, 4000)
	e.Link = clip(oneLine(e.Link), 300)
	return e
}

func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Don't cut a UTF-8 sequence in half.
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "…"
}
