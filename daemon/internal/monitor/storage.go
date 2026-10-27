package monitor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// ---- pools ----------------------------------------------------------------

// leafErrors lists the devices of a pool with read, write or checksum
// errors.
func leafErrors(v *zfs.Vdev, out *[]string, total *uint64) {
	if v == nil {
		return
	}
	if len(v.Children) == 0 && (v.Read+v.Write+v.Checksum) > 0 {
		name := v.Disk
		if name == "" {
			name = v.Name
		}
		*out = append(*out, fmt.Sprintf("%s: %d read, %d write, %d checksum errors", strings.TrimPrefix(name, "/dev/disk/by-id/"), v.Read, v.Write, v.Checksum))
		*total += v.Read + v.Write + v.Checksum
	}
	for _, c := range v.Children {
		leafErrors(c, out, total)
	}
}

func (s *Service) checkPools(ctx context.Context, now time.Time) {
	var pools []zfs.Pool
	if err := s.Priv.Call(ctx, priv.OpPools, nil, &pools); err != nil {
		s.log().Debug("pool check", "err", err)
		return
	}
	set := s.Settings(ctx)
	keep := map[string]bool{}
	var pts []Point
	scrubs := map[string]bool{}
	for _, p := range pools {
		link := "storage/pool/" + p.Name
		hk := "pool.health:" + p.Name
		keep[hk] = true
		switch p.Health {
		case "ONLINE":
			s.conds.Clear(ctx, hk, "Pool "+p.Name+" is healthy again", "")
		case "DEGRADED":
			s.conds.Set(ctx, Condition{Key: hk, Kind: "pool.health", Severity: notify.SeverityWarning, Link: link,
				Title: "Pool " + p.Name + " is degraded", Body: "A disk has failed or gone missing. The data is still there; replace the disk soon in Storage Manager."})
		default:
			s.conds.Set(ctx, Condition{Key: hk, Kind: "pool.health", Severity: notify.SeverityCritical, Link: link,
				Title: "Pool " + p.Name + " is " + strings.ToLower(p.Health), Body: "The pool needs attention now: open Storage Manager."})
		}

		ck := "pool.capacity:" + p.Name
		keep[ck] = true
		pct := p.CapacityPct
		switch {
		case pct >= set.PoolCritPct:
			s.conds.Set(ctx, Condition{Key: ck, Kind: "pool.capacity", Severity: notify.SeverityCritical, Link: link,
				Title: fmt.Sprintf("Pool %s is %d%% full", p.Name, pct), Body: "ZFS slows down and can stop writing when a pool is nearly full. Delete old snapshots or files, or add disks."})
		case pct >= set.PoolWarnPct:
			s.conds.Set(ctx, Condition{Key: ck, Kind: "pool.capacity", Severity: notify.SeverityWarning, Link: link,
				Title: fmt.Sprintf("Pool %s is %d%% full", p.Name, pct), Body: "Plan for more space: ZFS works best below 80%."})
		case pct < set.PoolWarnPct-2: // a little hysteresis
			s.conds.Clear(ctx, ck, fmt.Sprintf("Pool %s is back to %d%% full", p.Name, pct), "")
		}
		pts = append(pts,
			Point{Series: "pool.used:" + p.Name, Label: p.Name, Unit: UnitBytes, Value: float64(p.AllocBytes)},
			Point{Series: "pool.size:" + p.Name, Label: p.Name, Unit: UnitBytes, Value: float64(p.SizeBytes)},
			Point{Series: "pool.pct:" + p.Name, Label: p.Name, Unit: UnitPercent, Value: float64(pct)})

		var st zfs.Status
		if err := s.Priv.Call(ctx, priv.OpPoolStatus, priv.PoolArgs{Pool: p.Name}, &st); err != nil {
			continue
		}
		scrubs[p.Name] = st.Scan.Kind == "scrub" && st.Scan.State == "running"
		var lines []string
		var total uint64
		leafErrors(st.Root, &lines, &total)
		for _, g := range st.Groups {
			if g.Class != zfs.ClassData {
				leafErrors(g, &lines, &total)
			}
		}
		ek := "pool.errors:" + p.Name
		keep[ek] = true
		if total > 0 {
			sort.Strings(lines)
			s.conds.Set(ctx, Condition{Key: ek, Kind: "pool.errors", Severity: notify.SeverityWarning, Link: link,
				Title: "Disk errors in pool " + p.Name, Body: strings.Join(lines, "\n") + "\nZFS repaired what it could. If the counts keep growing, replace the disk; clear them in Storage Manager once dealt with."})
		} else {
			s.conds.Clear(ctx, ek, "No more disk errors in pool "+p.Name, "")
		}
		dk := "pool.data:" + p.Name
		keep[dk] = true
		if st.Errors != "" && !strings.HasPrefix(st.Errors, "No known data errors") {
			s.conds.Set(ctx, Condition{Key: dk, Kind: "pool.data", Severity: notify.SeverityCritical, Link: link,
				Title: "Pool " + p.Name + " has damaged files", Body: st.Errors + "\nZFS couldn't repair them: restore those files from a backup or snapshot."})
		} else {
			s.conds.Clear(ctx, dk, "Pool "+p.Name+" has no damaged files any more", "")
		}
		sk := "pool.scrub:" + p.Name
		keep[sk] = true
		if st.Scan.Kind == "scrub" && st.Scan.State == "finished" && st.Scan.Errors != nil {
			if *st.Scan.Errors > 0 {
				s.conds.Set(ctx, Condition{Key: sk, Kind: "pool.scrub", Severity: notify.SeverityCritical, Link: link,
					Title: fmt.Sprintf("Scrub of %s found %d errors", p.Name, *st.Scan.Errors), Body: st.Scan.Text})
			} else {
				s.conds.Clear(ctx, sk, "The last scrub of "+p.Name+" found no errors", "")
			}
		}
	}
	s.mu.Lock()
	s.scrubs = scrubs
	s.mu.Unlock()
	s.conds.Drop(ctx, "pool.", keep) // pools that were exported or destroyed
	s.record(ctx, now, pts)
}

// ---- disks ----------------------------------------------------------------

// isHDD: a spinning disk (temperature limits differ).
func isHDD(d hw.Disk, sm *hw.SMART) bool {
	if sm != nil && sm.RotationRPM > 0 {
		return true
	}
	return d.Kind == hw.KindHDD
}

func diskTitle(d hw.Disk) string {
	if d.Model != "" {
		return d.Name + " (" + d.Model + ")"
	}
	return d.Name
}

// counters kept to notice a disk getting worse between readings.
type smartCounters struct {
	Reallocated, Pending, Uncorrectable, MediaErrors, GrownDefects int64
}

func countersOf(sm *hw.SMART) smartCounters {
	v := func(p *int64) int64 {
		if p == nil {
			return 0
		}
		return *p
	}
	return smartCounters{v(sm.Reallocated), v(sm.Pending), v(sm.Uncorrectable), v(sm.MediaErrors), v(sm.GrownDefects)}
}

const countersKey = "monitor.smart_counters"

func (s *Service) loadCounters(ctx context.Context) map[string]smartCounters {
	m := map[string]smartCounters{}
	if raw, err := s.DB.GetSetting(ctx, countersKey); err == nil {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	return m
}

func worse(a, b smartCounters) []string {
	var out []string
	add := func(name string, x, y int64) {
		if y > x {
			out = append(out, fmt.Sprintf("%s %d → %d", name, x, y))
		}
	}
	add("reallocated sectors", a.Reallocated, b.Reallocated)
	add("pending sectors", a.Pending, b.Pending)
	add("uncorrectable sectors", a.Uncorrectable, b.Uncorrectable)
	add("media errors", a.MediaErrors, b.MediaErrors)
	add("grown defects", a.GrownDefects, b.GrownDefects)
	return out
}

func (s *Service) listDisks(ctx context.Context) ([]hw.Disk, error) {
	var disks []hw.Disk
	if err := s.Priv.Call(ctx, priv.OpHWDisks, nil, &disks); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.disks = disks
	s.mu.Unlock()
	return disks, nil
}

// checkSMART reads every fixed disk's SMART data without waking sleeping
// disks: health, temperature, counters getting worse, self-test results.
func (s *Service) checkSMART(ctx context.Context, now time.Time) {
	disks, err := s.listDisks(ctx)
	if err != nil {
		s.log().Debug("SMART check", "err", err)
		return
	}
	set := s.Settings(ctx)
	counters := s.loadCounters(ctx)
	keep := map[string]bool{}
	var pts []Point
	for _, d := range disks {
		if d.Removable {
			continue
		}
		hk, tk := "disk.smart:"+d.ByID, "disk.temperature:"+d.ByID
		keep[hk], keep[tk] = true, true
		var sm hw.SMART
		if err := s.Priv.Call(ctx, priv.OpHWSmart, priv.DeviceArgs{Device: d.ByID, NoWake: true}, &sm); err != nil {
			s.log().Debug("SMART read failed", "disk", d.ByID, "err", err)
			continue
		}
		if sm.Standby {
			continue // asleep: keep the last reading
		}
		s.mu.Lock()
		s.smart[d.ByID], s.smartAt[d.ByID] = &sm, now
		s.mu.Unlock()
		reasons, _ := json.Marshal(sm.Reasons)
		_, _ = s.DB.ExecContext(ctx, `INSERT INTO disk_health (by_id, health, reasons, temperature, checked_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(by_id) DO UPDATE SET health = excluded.health, reasons = excluded.reasons,
			temperature = excluded.temperature, checked_at = excluded.checked_at`,
			d.ByID, sm.Health, string(reasons), sm.TemperatureC, store.FormatTime(now))
		link := "storage/disks/" + d.Name
		switch sm.Health {
		case hw.HealthFailing:
			s.conds.Set(ctx, Condition{Key: hk, Kind: "disk.smart", Severity: notify.SeverityCritical, Link: link,
				Title: "Disk " + diskTitle(d) + " is failing", Body: strings.Join(sm.Reasons, "; ") + "\nSerial " + d.Serial + ". Replace it soon and make sure your backups are current."})
		case hw.HealthWarning:
			s.conds.Set(ctx, Condition{Key: hk, Kind: "disk.smart", Severity: notify.SeverityWarning, Link: link,
				Title: "Disk " + diskTitle(d) + " shows wear", Body: strings.Join(sm.Reasons, "; ") + "\nSerial " + d.Serial + "."})
		case hw.HealthGood:
			s.conds.Clear(ctx, hk, "Disk "+diskTitle(d)+" is healthy again", "")
		}
		cur := countersOf(&sm)
		if prev, ok := counters[d.ByID]; ok {
			if w := worse(prev, cur); len(w) > 0 {
				s.Notify.Notify(ctx, notify.Event{Kind: "disk.smart", Severity: notify.SeverityWarning, Link: link,
					Title: "Disk " + diskTitle(d) + " is getting worse", Body: strings.Join(w, "; ") + ". A disk whose counts keep rising is likely to fail."})
			}
		}
		counters[d.ByID] = cur

		if sm.TemperatureC != nil {
			t := *sm.TemperatureC
			pts = append(pts, Point{Series: "disk.temp:" + d.Name, Label: d.Name, Unit: UnitCelsius, Value: float64(t)})
			warn, crit := set.SSDWarnC, set.SSDCritC
			if isHDD(d, &sm) {
				warn, crit = set.HDDWarnC, set.HDDCritC
			}
			switch {
			case t >= crit:
				s.conds.Set(ctx, Condition{Key: tk, Kind: "disk.temperature", Severity: notify.SeverityCritical, Link: link,
					Title: fmt.Sprintf("Disk %s is at %d °C", diskTitle(d), t), Body: fmt.Sprintf("Above the %d °C limit: check the fans and airflow now; heat shortens a disk's life.", crit)})
			case t >= warn:
				s.conds.Set(ctx, Condition{Key: tk, Kind: "disk.temperature", Severity: notify.SeverityWarning, Link: link,
					Title: fmt.Sprintf("Disk %s is running warm at %d °C", diskTitle(d), t), Body: fmt.Sprintf("The warning level is %d °C. Check the fans and airflow.", warn)})
			case t <= warn-3:
				s.conds.Clear(ctx, tk, fmt.Sprintf("Disk %s is back to %d °C", diskTitle(d), t), "")
			}
		}
		s.selfTestResult(ctx, d, &sm, now)
	}
	if b, err := json.Marshal(counters); err == nil {
		_ = s.DB.SetSetting(ctx, countersKey, string(b))
	}
	s.conds.Drop(ctx, "disk.", keep)
	s.record(ctx, now, pts)
}

// ---- self-tests -------------------------------------------------------------

// TestState is a disk's self-test schedule and last result.
type TestState struct {
	ByID         string     `json:"byId"`
	NextShortAt  time.Time  `json:"nextShortAt"`
	NextLongAt   time.Time  `json:"nextLongAt"`
	LastShortAt  *time.Time `json:"lastShortAt"`
	LastLongAt   *time.Time `json:"lastLongAt"`
	Running      string     `json:"running"` // "", short, long
	RunningSince *time.Time `json:"runningSince"`
	LastType     string     `json:"lastType"`
	LastResult   string     `json:"lastResult"`
	LastPassed   *bool      `json:"lastPassed"`
	LastDoneAt   *time.Time `json:"lastDoneAt"`
	Excluded     bool       `json:"excluded"`
}

func nullTime(n sql.NullString) *time.Time {
	if !n.Valid || n.String == "" {
		return nil
	}
	t := store.ParseTime(n.String)
	return &t
}

func (s *Service) testState(ctx context.Context, byID string) (*TestState, bool) {
	var t TestState
	var next1, next2 string
	var l1, l2, since, done sql.NullString
	var passed sql.NullInt64
	var manual int
	err := s.DB.QueryRowContext(ctx, `SELECT by_id, next_short_at, next_long_at, last_short_at, last_long_at, running, running_since, manual,
		last_type, last_result, last_passed, last_done_at FROM smart_tests WHERE by_id = ?`, byID).
		Scan(&t.ByID, &next1, &next2, &l1, &l2, &t.Running, &since, &manual, &t.LastType, &t.LastResult, &passed, &done)
	if err != nil {
		return nil, false
	}
	t.NextShortAt, t.NextLongAt = store.ParseTime(next1), store.ParseTime(next2)
	t.LastShortAt, t.LastLongAt, t.RunningSince, t.LastDoneAt = nullTime(l1), nullTime(l2), nullTime(since), nullTime(done)
	if passed.Valid {
		p := passed.Int64 != 0
		t.LastPassed = &p
	}
	return &t, true
}

// seedTests gives disks without a schedule first due dates spread over
// the interval, so they take turns.
func (s *Service) seedTests(ctx context.Context, disks []hw.Disk, set Settings, now time.Time) {
	var fresh []hw.Disk
	for _, d := range disks {
		if _, ok := s.testState(ctx, d.ByID); !ok && !d.Removable {
			fresh = append(fresh, d)
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].ByID < fresh[j].ByID })
	n := len(fresh)
	for i, d := range fresh {
		short := now.Add(time.Duration(i+1) * time.Duration(set.SMART.ShortDays) * 24 * time.Hour / time.Duration(n+1))
		long := now.Add(time.Duration(i+1) * time.Duration(set.SMART.LongDays) * 24 * time.Hour / time.Duration(n+1))
		_, _ = s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO smart_tests (by_id, next_short_at, next_long_at) VALUES (?, ?, ?)`,
			d.ByID, store.FormatTime(short), store.FormatTime(long))
	}
}

// scheduleSelfTests starts due self-tests inside the maintenance window:
// one start per minute, one long test at a time, never on a pool that's
// scrubbing.
func (s *Service) scheduleSelfTests(ctx context.Context, now time.Time) {
	set := s.Settings(ctx)
	s.mu.Lock()
	disks := append([]hw.Disk(nil), s.disks...)
	scrubs := map[string]bool{}
	for k, v := range s.scrubs {
		scrubs[k] = v
	}
	s.mu.Unlock()
	if len(disks) == 0 {
		return
	}
	s.seedTests(ctx, disks, set, now)
	if !set.SMART.Enabled || !set.SMART.InWindow(now.Local()) {
		return
	}
	var running int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM smart_tests WHERE running = 'long'`).Scan(&running)
	sort.Slice(disks, func(i, j int) bool { return disks[i].ByID < disks[j].ByID })
	for _, d := range disks {
		if d.Removable || slices.Contains(set.SMART.Excluded, d.ByID) || (d.Pool != "" && scrubs[d.Pool]) {
			continue
		}
		s.mu.Lock()
		sm := s.smart[d.ByID]
		s.mu.Unlock()
		if sm == nil || (sm.Passed == nil && sm.CriticalWarning == nil) || sm.SelfTest.Running {
			continue // never read, no SMART, or busy
		}
		ts, ok := s.testState(ctx, d.ByID)
		if !ok || ts.Running != "" {
			continue
		}
		kind := ""
		switch {
		case !now.Before(ts.NextLongAt) && running == 0:
			kind = hw.TestLong
		case !now.Before(ts.NextShortAt):
			kind = hw.TestShort
		}
		if kind == "" {
			continue
		}
		if err := s.StartTest(ctx, d.ByID, kind, false); err != nil {
			s.log().Warn("scheduled self-test didn't start", "disk", d.ByID, "test", kind, "err", err)
			// Try again next window rather than every minute.
			_, _ = s.DB.ExecContext(ctx, `UPDATE smart_tests SET next_`+kind+`_at = ? WHERE by_id = ?`, store.FormatTime(now.Add(20*time.Hour)), d.ByID)
		}
		return // one start per minute
	}
}

// ErrTestRunning: the disk is already testing.
var ErrTestRunning = errors.New("a self-test is already running on this disk")

// StartTest starts a self-test now (manual from the UI, or scheduled) and
// moves the disk's schedule on.
func (s *Service) StartTest(ctx context.Context, byID, kind string, manual bool) error {
	s.init()
	if kind != hw.TestShort && kind != hw.TestLong {
		return fmt.Errorf("test must be short or long")
	}
	set := s.Settings(ctx)
	now := s.now()
	if ts, ok := s.testState(ctx, byID); ok && ts.Running != "" {
		return ErrTestRunning
	}
	if err := s.Priv.Call(ctx, priv.OpHWSmartTest, priv.SmartTestArgs{Device: byID, Test: kind}, nil); err != nil {
		return err
	}
	nextShort := now.Add(time.Duration(set.SMART.ShortDays) * 24 * time.Hour)
	_, _ = s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO smart_tests (by_id, next_short_at, next_long_at) VALUES (?, ?, ?)`,
		byID, store.FormatTime(nextShort), store.FormatTime(now.Add(time.Duration(set.SMART.LongDays)*24*time.Hour)))
	if kind == hw.TestLong {
		_, _ = s.DB.ExecContext(ctx, `UPDATE smart_tests SET running = 'long', running_since = ?, manual = ?, last_long_at = ?,
			next_long_at = ?, next_short_at = ? WHERE by_id = ?`, store.FormatTime(now), b2i(manual), store.FormatTime(now),
			store.FormatTime(now.Add(time.Duration(set.SMART.LongDays)*24*time.Hour)), store.FormatTime(nextShort), byID)
	} else {
		_, _ = s.DB.ExecContext(ctx, `UPDATE smart_tests SET running = 'short', running_since = ?, manual = ?, last_short_at = ?,
			next_short_at = ? WHERE by_id = ?`, store.FormatTime(now), b2i(manual), store.FormatTime(now), store.FormatTime(nextShort), byID)
	}
	// Read the disk again in a few minutes to follow the test.
	s.mu.Lock()
	delete(s.last, "smart")
	s.last["smart"] = now.Add(-10*time.Minute + 3*time.Minute)
	s.mu.Unlock()
	return nil
}

// selfTestResult records how a running test ended.
func (s *Service) selfTestResult(ctx context.Context, d hw.Disk, sm *hw.SMART, now time.Time) {
	ts, ok := s.testState(ctx, d.ByID)
	if !ok || ts.Running == "" {
		return
	}
	if sm.SelfTest.Running {
		// Follow it closely while it runs.
		s.mu.Lock()
		s.last["smart"] = now.Add(-10*time.Minute + 5*time.Minute)
		s.mu.Unlock()
		return
	}
	if ts.RunningSince != nil && now.Sub(*ts.RunningSince) < 2*time.Minute {
		return // the drive may not have started it yet
	}
	var manual int
	_ = s.DB.QueryRowContext(ctx, `SELECT manual FROM smart_tests WHERE by_id = ?`, d.ByID).Scan(&manual)
	result, passed := "no result in the drive's log", (*bool)(nil)
	if len(sm.SelfTests) > 0 {
		result, passed = sm.SelfTests[0].Status, sm.SelfTests[0].Passed
	}
	var p any
	if passed != nil {
		p = b2i(*passed)
	}
	_, _ = s.DB.ExecContext(ctx, `UPDATE smart_tests SET running = '', running_since = NULL, manual = 0, last_type = ?, last_result = ?,
		last_passed = ?, last_done_at = ? WHERE by_id = ?`, ts.Running, result, p, store.FormatTime(now), d.ByID)
	link := "storage/disks/" + d.Name
	what := map[string]string{"short": "Short", "long": "Long"}[ts.Running]
	switch {
	case passed != nil && !*passed && !strings.Contains(strings.ToLower(result), "abort") && !strings.Contains(strings.ToLower(result), "interrupt"):
		s.Notify.Notify(ctx, notify.Event{Kind: "disk.selftest", Severity: notify.SeverityCritical, Link: link,
			Title: what + " self-test failed on disk " + diskTitle(d), Body: result + "\nSerial " + d.Serial + ". The disk can't read part of itself: replace it and check your backups."})
	case manual != 0:
		s.Notify.Notify(ctx, notify.Event{Kind: "disk.selftest", Severity: notify.SeverityInfo, Link: link,
			Title: what + " self-test finished on disk " + diskTitle(d), Body: result})
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// DiskInfo is one disk as the Storage Manager's health view shows it.
type DiskInfo struct {
	Disk      hw.Disk    `json:"disk"`
	SMART     *hw.SMART  `json:"smart"`  // last reading (nil until read; not refreshed while asleep)
	ReadAt    *time.Time `json:"readAt"` //
	Tests     *TestState `json:"tests"`  // nil before the first schedule
	Asleep    bool       `json:"asleep"` // in standby at the last check
	Supported bool       `json:"supported"`
}

// Disks returns every disk with its last SMART reading and test schedule.
func (s *Service) Disks(ctx context.Context) ([]DiskInfo, error) {
	s.init()
	disks, err := s.listDisks(ctx)
	if err != nil {
		return nil, err
	}
	set := s.Settings(ctx)
	out := []DiskInfo{}
	for _, d := range disks {
		di := DiskInfo{Disk: d}
		s.mu.Lock()
		if sm := s.smart[d.ByID]; sm != nil {
			di.SMART = sm
			t := s.smartAt[d.ByID]
			di.ReadAt = &t
			di.Supported = sm.Passed != nil || sm.CriticalWarning != nil
		}
		s.mu.Unlock()
		if ts, ok := s.testState(ctx, d.ByID); ok {
			ts.Excluded = slices.Contains(set.SMART.Excluded, d.ByID)
			di.Tests = ts
		}
		out = append(out, di)
	}
	return out, nil
}

// Refresh reads one disk's SMART data now (waking it) and keeps it.
func (s *Service) Refresh(ctx context.Context, byID string) (*hw.SMART, error) {
	s.init()
	var sm hw.SMART
	if err := s.Priv.Call(ctx, priv.OpHWSmart, priv.DeviceArgs{Device: byID}, &sm); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.smart[byID], s.smartAt[byID] = &sm, s.now()
	s.mu.Unlock()
	return &sm, nil
}
