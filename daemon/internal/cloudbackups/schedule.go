package cloudbackups

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Schedule says when a task runs, in the server's local time.
type Schedule struct {
	// Frequency: manual (only when asked), hourly (every EveryHours from
	// midnight, at Time's minute), daily (at Time), weekly (at Time on
	// Weekdays, 0 = Sunday).
	Frequency  string `json:"frequency"`
	Time       string `json:"time"`
	EveryHours int    `json:"everyHours,omitempty"`
	Weekdays   []int  `json:"weekdays,omitempty"`
}

// Frequencies.
const (
	Manual = "manual"
	Hourly = "hourly"
	Daily  = "daily"
	Weekly = "weekly"
)

// DefaultSchedule is daily at 01:30.
var DefaultSchedule = Schedule{Frequency: Daily, Time: "01:30"}

func parseHM(s string) (int, int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil || t.Format("15:04") != s {
		return 0, 0, errors.New("times look like 01:30")
	}
	return t.Hour(), t.Minute(), nil
}

// Check validates and normalizes a schedule.
func (s *Schedule) Check() error {
	switch s.Frequency {
	case Manual:
		s.Time, s.EveryHours, s.Weekdays = "", 0, nil
		return nil
	case Hourly:
		if s.EveryHours < 1 || s.EveryHours > 12 || 24%s.EveryHours != 0 {
			return errors.New("run every 1, 2, 3, 4, 6, 8 or 12 hours")
		}
		s.Weekdays = nil
	case Daily:
		s.EveryHours, s.Weekdays = 0, nil
	case Weekly:
		s.EveryHours = 0
		if len(s.Weekdays) == 0 {
			return errors.New("choose at least one day")
		}
		seen := map[int]bool{}
		out := []int{}
		for _, d := range s.Weekdays {
			if d < 0 || d > 6 {
				return errors.New("days are 0 (Sunday) to 6 (Saturday)")
			}
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
		sort.Ints(out)
		s.Weekdays = out
	default:
		return fmt.Errorf("unknown frequency %q", s.Frequency)
	}
	if _, _, err := parseHM(s.Time); err != nil {
		return err
	}
	return nil
}

// LastSlot is the newest scheduled time at or before now (zero for manual).
func (s Schedule) LastSlot(now time.Time) time.Time {
	if s.Frequency == Manual {
		return time.Time{}
	}
	h, m, err := parseHM(s.Time)
	if err != nil {
		return time.Time{}
	}
	now = now.Truncate(time.Minute)
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	switch s.Frequency {
	case Hourly:
		hour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
		for i := 0; i < 48; i++ {
			t := hour.Add(-time.Duration(i) * time.Hour).Add(time.Duration(m) * time.Minute)
			if t.Hour()%s.EveryHours == h%s.EveryHours && !t.After(now) {
				return t
			}
		}
	case Daily:
		for d := 0; d < 2; d++ {
			base := day.AddDate(0, 0, -d)
			t := time.Date(base.Year(), base.Month(), base.Day(), h, m, 0, 0, now.Location())
			if !t.After(now) {
				return t
			}
		}
	case Weekly:
		want := map[int]bool{}
		for _, w := range s.Weekdays {
			want[w] = true
		}
		for d := 0; d < 8; d++ {
			base := day.AddDate(0, 0, -d)
			if !want[int(base.Weekday())] {
				continue
			}
			t := time.Date(base.Year(), base.Month(), base.Day(), h, m, 0, 0, now.Location())
			if !t.After(now) {
				return t
			}
		}
	}
	return time.Time{}
}

// NextSlot is the first scheduled time after now (zero for manual).
func (s Schedule) NextSlot(now time.Time) time.Time {
	if s.Frequency == Manual {
		return time.Time{}
	}
	// Step forward a minute at a time would be slow; slots are at most a
	// week apart, so look for the last slot before each candidate day end.
	for d := 0; d <= 8; d++ {
		end := now.Truncate(time.Minute).AddDate(0, 0, d).Add(24 * time.Hour)
		cand := s.LastSlot(end)
		if cand.After(now) {
			// The earliest slot after now: walk back while still after now.
			for {
				prev := s.LastSlot(cand.Add(-time.Minute))
				if prev.IsZero() || !prev.After(now) {
					return cand
				}
				cand = prev
			}
		}
	}
	return time.Time{}
}

// Maintenance is a destination's weekly upkeep: forgotten data is pruned
// and then CheckPercent of the repository's data is read back.
type Maintenance struct {
	Weekday      int    `json:"weekday"`
	Time         string `json:"time"`
	CheckPercent int    `json:"checkPercent"`
}

// DefaultMaintenance is Sundays at 04:30, reading back 5%.
var DefaultMaintenance = Maintenance{Weekday: 0, Time: "04:30", CheckPercent: 5}

// Check validates maintenance settings.
func (m *Maintenance) Check() error {
	if m.Weekday < 0 || m.Weekday > 6 {
		return errors.New("days are 0 (Sunday) to 6 (Saturday)")
	}
	if _, _, err := parseHM(m.Time); err != nil {
		return err
	}
	if m.CheckPercent < 0 || m.CheckPercent > 100 {
		return errors.New("read back 0-100% of the data")
	}
	return nil
}

func (m Maintenance) schedule() Schedule {
	return Schedule{Frequency: Weekly, Time: m.Time, Weekdays: []int{m.Weekday}}
}
