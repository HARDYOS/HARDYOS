// Package snapshots takes, prunes and manages the automatic snapshots of
// shared folders. It runs inside hardyd-priv. See docs/plans/file-sharing.md
// (section 2) and docs/shares.md.
//
// Names are fixed by the contract because Samba's shadow_copy2 (Windows
// Previous Versions) and the File Manager read them:
//
//	<pool>/shares/<id>@hardyos-auto-<kind>_<YYYY-MM-DD-HHMM>
//
// in UTC, where the time is the schedule slot the snapshot stands for
// (hourly at :00, daily at 00:00, weekly on Monday 00:00, monthly on the 1st
// at 00:00).
package snapshots

import (
	"regexp"
	"strings"
	"time"
)

// Kind is a kind of automatic snapshot.
type Kind string

// Kinds of automatic snapshots.
const (
	Hourly  Kind = "hourly"
	Daily   Kind = "daily"
	Weekly  Kind = "weekly"
	Monthly Kind = "monthly"
)

// Kinds lists every kind, shortest period first.
var Kinds = []Kind{Hourly, Daily, Weekly, Monthly}

// AutoPrefix starts every automatic snapshot's name. Manual snapshots may
// not use it.
const AutoPrefix = "hardyos-auto-"

// timeFormat is the slot time in a name (shadow:format = _%Y-%m-%d-%H%M).
const timeFormat = "2006-01-02-1504"

var autoRE = regexp.MustCompile(`^hardyos-auto-(hourly|daily|weekly|monthly)_([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4})$`)

// Name is the snapshot label for kind's slot at t (taken in UTC).
func Name(k Kind, t time.Time) string {
	return AutoPrefix + string(k) + "_" + t.UTC().Format(timeFormat)
}

// Parse reads an automatic snapshot's label. ok is false for anything that
// isn't exactly one: other snapshots are never touched by the scheduler.
func Parse(label string) (k Kind, slot time.Time, ok bool) {
	m := autoRE.FindStringSubmatch(label)
	if m == nil {
		return "", time.Time{}, false
	}
	t, err := time.ParseInLocation(timeFormat, m[2], time.UTC)
	if err != nil {
		return "", time.Time{}, false
	}
	// A name that doesn't round-trip (2026-02-30 normalised by nobody, a
	// minute past the slot) wasn't made by the scheduler.
	if Name(Kind(m[1]), t) != label || !Slot(Kind(m[1]), t).Equal(t) {
		return "", time.Time{}, false
	}
	return Kind(m[1]), t, true
}

// Slot is the newest scheduled time of kind at or before now, in UTC.
func Slot(k Kind, now time.Time) time.Time {
	now = now.UTC()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	switch k {
	case Hourly:
		return now.Truncate(time.Hour)
	case Daily:
		return day
	case Weekly:
		// time.Monday is 1, Sunday 0: days since the last Monday.
		back := (int(day.Weekday()) + 6) % 7
		return day.AddDate(0, 0, -back)
	case Monthly:
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	return time.Time{}
}

// Keep is how many snapshots of kind the settings keep.
func Keep(k Kind, hourly, daily, weekly, monthly int) int {
	switch k {
	case Hourly:
		return hourly
	case Daily:
		return daily
	case Weekly:
		return weekly
	case Monthly:
		return monthly
	}
	return 0
}

// KindOf tells what made a snapshot: an automatic kind, "manual" (taken
// from the Control Panel; marked with PropMade) or "other" (anything else:
// made by hand, by apps or by another tool).
func KindOf(label, made string) string {
	if k, _, ok := Parse(label); ok {
		return string(k)
	}
	if made == MadeManual {
		return "manual"
	}
	return "other"
}

// PropMade marks snapshots HardyOS took on request (value MadeManual).
const (
	PropMade   = "org.hardyos:snapshot"
	MadeManual = "manual"
)

// reservedLabel reports whether a label is kept for the scheduler.
func reservedLabel(label string) bool {
	return strings.HasPrefix(strings.ToLower(label), AutoPrefix)
}
