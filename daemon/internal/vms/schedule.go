package vms

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/snapshots"
)

// Scheduled VM snapshots (decision 415). A VM's schedule lives in its
// vm.json, changed only with SetSchedule (a job in hardyd, audited) and
// kept by every other update. hardyd-priv looks every minute: each kind
// with a count gets a snapshot for its current slot (hourly at :00, daily
// at midnight UTC, weekly on Mondays, monthly on the 1st), taken like a
// manual one (frozen through the guest agent when it runs, otherwise
// crash-consistent and marked so), and keeps that many of its kind.
// Snapshots taken by hand are never pruned. A kind set to 0 while the
// schedule is on loses its automatic snapshots; turning the whole schedule
// off keeps them.

// Schedule is how many automatic snapshots of each kind a VM keeps.
type Schedule struct {
	Hourly  int `json:"hourly"`
	Daily   int `json:"daily"`
	Weekly  int `json:"weekly"`
	Monthly int `json:"monthly"`
}

// Most automatic snapshots of each kind.
const (
	MaxHourly  = 48
	MaxDaily   = 62
	MaxWeekly  = 52
	MaxMonthly = 36
)

func (sc *Schedule) problems() []string {
	var p []string
	check := func(name string, n, most int) {
		if n < 0 || n > most {
			p = append(p, fmt.Sprintf("keep 0 to %d %s snapshots", most, name))
		}
	}
	check("hourly", sc.Hourly, MaxHourly)
	check("daily", sc.Daily, MaxDaily)
	check("weekly", sc.Weekly, MaxWeekly)
	check("monthly", sc.Monthly, MaxMonthly)
	return p
}

func (sc *Schedule) keep(k snapshots.Kind) int {
	return snapshots.Keep(k, sc.Hourly, sc.Daily, sc.Weekly, sc.Monthly)
}

// Off reports a schedule that takes nothing.
func (sc *Schedule) Off() bool {
	return sc == nil || sc.Hourly+sc.Daily+sc.Weekly+sc.Monthly == 0
}

var autoSnapRE = regexp.MustCompile(`^vm-auto-(hourly|daily|weekly|monthly)-([0-9]{8}-[0-9]{4})$`)

const autoTimeFormat = "20060102-1504"

// AutoSnapName is the automatic snapshot of kind for the slot at t.
func AutoSnapName(k snapshots.Kind, t time.Time) string {
	return "vm-auto-" + string(k) + "-" + snapshots.Slot(k, t).Format(autoTimeFormat)
}

// autoKind tells an automatic snapshot's kind and slot; ok is false for
// anything else (a manual snapshot, a name that doesn't round-trip).
func autoKind(name string) (snapshots.Kind, time.Time, bool) {
	mt := autoSnapRE.FindStringSubmatch(name)
	if mt == nil {
		return "", time.Time{}, false
	}
	t, err := time.ParseInLocation(autoTimeFormat, mt[2], time.UTC)
	k := snapshots.Kind(mt[1])
	if err != nil || AutoSnapName(k, t) != name {
		return "", time.Time{}, false
	}
	return k, t, true
}

// SetScheduleArgs changes a VM's snapshot schedule (nil or all zero: off).
type SetScheduleArgs struct {
	ID       string    `json:"id"`
	Schedule *Schedule `json:"schedule"`
}

// SetSchedule saves a VM's snapshot schedule.
func (m *Manager) SetSchedule(ctx context.Context, a SetScheduleArgs) (*VM, error) {
	unlock, err := m.lockValid(a.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := m.find(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	sc := a.Schedule
	if sc.Off() {
		sc = nil
	} else if p := sc.problems(); len(p) > 0 {
		return nil, Problems(p)
	}
	st.spec.Schedule = sc
	if err := m.saveSpec(st); err != nil {
		return nil, err
	}
	m.log().Info("vms: snapshot schedule", "id", a.ID, "schedule", sc)
	return m.Get(ctx, a.ID)
}

// RunSchedules takes and prunes scheduled snapshots every minute until ctx
// ends.
func (m *Manager) RunSchedules(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		m.TickSchedules(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// TickSchedules does one round for every VM with a schedule.
func (m *Manager) TickSchedules(ctx context.Context) {
	l, err := m.all(ctx)
	if err != nil {
		m.log().Warn("vms: listing VMs for scheduled snapshots", "err", err)
		return
	}
	now := m.now().UTC()
	for _, st := range l {
		if st.spec.Schedule.Off() {
			continue
		}
		if err := m.tickSchedule(ctx, st.spec.ID, now); err != nil {
			m.log().Warn("vms: scheduled snapshot", "id", st.spec.ID, "err", err)
		}
	}
}

func (m *Manager) tickSchedule(ctx context.Context, id string, now time.Time) error {
	unlock, err := m.lockValid(id)
	if err != nil {
		return err
	}
	defer unlock()
	st, err := m.find(ctx, id) // fresh, under the lock
	if err != nil {
		return err
	}
	sc := st.spec.Schedule
	if sc.Off() {
		return nil
	}
	existing, err := m.snapshots(ctx, st)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, s := range existing {
		have[s.Name] = true
	}
	for _, k := range snapshots.Kinds {
		if sc.keep(k) <= 0 {
			continue
		}
		name := AutoSnapName(k, now)
		if have[name] {
			continue
		}
		sn, err := m.takeSnapshot(ctx, st, name, "Automatic ("+string(k)+")")
		if err != nil {
			return err
		}
		existing = append(existing, *sn)
		have[name] = true
	}
	for _, name := range pruneAuto(existing, sc) {
		if _, err := m.zfs(ctx, "destroy", "-r", st.dataset+"@"+name); err != nil {
			return fmt.Errorf("removing the old automatic snapshot %s: %w", name, err)
		}
		m.log().Info("vms: pruned an automatic snapshot", "id", id, "snapshot", name)
	}
	return nil
}

// pruneAuto lists the automatic snapshots past each kind's count, oldest
// first.
func pruneAuto(l []Snapshot, sc *Schedule) []string {
	byKind := map[snapshots.Kind][]time.Time{}
	names := map[time.Time]map[snapshots.Kind]string{}
	for _, s := range l {
		k, t, ok := autoKind(s.Name)
		if !ok {
			continue
		}
		byKind[k] = append(byKind[k], t)
		if names[t] == nil {
			names[t] = map[snapshots.Kind]string{}
		}
		names[t][k] = s.Name
	}
	var out []string
	for _, k := range snapshots.Kinds {
		ts := byKind[k]
		sort.Slice(ts, func(i, j int) bool { return ts[i].After(ts[j]) })
		keep := max(sc.keep(k), 0)
		for i := len(ts) - 1; i >= keep; i-- {
			out = append(out, names[ts[i]][k])
		}
	}
	return out
}
