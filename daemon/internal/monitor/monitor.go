// Package monitor watches the server and raises alerts: disks (SMART
// health, temperature, self-tests on a schedule) and pools (health, device
// errors, scrub errors, capacity), the UPS, apps, VMs, the domain
// controller's replication, NetBird and publishing, and hardyd-priv; and it
// keeps resource history (CPU, memory, network, disk I/O, temperatures,
// pool use, per app and per VM) for the Resource Monitor. Alerts go out as
// notify.Events through the dispatcher.
package monitor

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Caller is the root helper client (faked in tests).
type Caller interface {
	Call(ctx context.Context, op string, args any, out any) error
}

// Settings are the thresholds and schedules administrators can change.
type Settings struct {
	PoolWarnPct int `json:"poolWarnPct"` // pool capacity warning (80)
	PoolCritPct int `json:"poolCritPct"` // and critical (90)
	HDDWarnC    int `json:"hddWarnC"`    // hard disk temperature warning (50)
	HDDCritC    int `json:"hddCritC"`    // and critical (55)
	SSDWarnC    int `json:"ssdWarnC"`    // SSD / NVMe (70)
	SSDCritC    int `json:"ssdCritC"`    // (80)
	// CPU and other sensors use the chip's own max/crit when it reports
	// them, these otherwise.
	SensorWarnC int `json:"sensorWarnC"` // 85
	SensorCritC int `json:"sensorCritC"` // 95

	SMART Schedule `json:"smart"`
}

// Schedule is when disks test themselves and pools are scrubbed.
type Schedule struct {
	Enabled   bool `json:"enabled"`
	ShortDays int  `json:"shortDays"` // a short self-test every … days (7)
	LongDays  int  `json:"longDays"`  // a long (extended) self-test every … days (30)
	// Tests (and scrubs, with ScrubInWindow) start only between these
	// hours, server time (01:00-06:00); the end may be before the start
	// (over midnight).
	WindowStart   int  `json:"windowStart"`
	WindowEnd     int  `json:"windowEnd"`
	ScrubInWindow bool `json:"scrubInWindow"`
	// Excluded disks (by-id) get no automatic tests.
	Excluded []string `json:"excluded"`
}

// DefaultSettings are the defaults (docs/monitoring.md).
func DefaultSettings() Settings {
	return Settings{PoolWarnPct: 80, PoolCritPct: 90, HDDWarnC: 50, HDDCritC: 55, SSDWarnC: 70, SSDCritC: 80, SensorWarnC: 85, SensorCritC: 95,
		SMART: Schedule{Enabled: true, ShortDays: 7, LongDays: 30, WindowStart: 1, WindowEnd: 6, ScrubInWindow: true, Excluded: []string{}}}
}

// ValidationError is a bad setting.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// Validate checks settings.
func (s Settings) Validate() error {
	bad := func(m string) error { return &ValidationError{Msg: m} }
	switch {
	case s.PoolWarnPct < 50 || s.PoolWarnPct > 99 || s.PoolCritPct <= s.PoolWarnPct || s.PoolCritPct > 100:
		return bad("pool warnings: warning between 50 and 99%, critical above it")
	case s.HDDWarnC < 30 || s.HDDCritC <= s.HDDWarnC || s.HDDCritC > 90:
		return bad("hard disk temperatures: warning from 30 °C, critical above it, at most 90 °C")
	case s.SSDWarnC < 30 || s.SSDCritC <= s.SSDWarnC || s.SSDCritC > 100:
		return bad("SSD temperatures: warning from 30 °C, critical above it, at most 100 °C")
	case s.SensorWarnC < 40 || s.SensorCritC <= s.SensorWarnC || s.SensorCritC > 120:
		return bad("sensor temperatures: warning from 40 °C, critical above it, at most 120 °C")
	case s.SMART.ShortDays < 1 || s.SMART.ShortDays > 90 || s.SMART.LongDays < 7 || s.SMART.LongDays > 365:
		return bad("short tests every 1-90 days, long tests every 7-365 days")
	case s.SMART.WindowStart < 0 || s.SMART.WindowStart > 23 || s.SMART.WindowEnd < 0 || s.SMART.WindowEnd > 23 || s.SMART.WindowStart == s.SMART.WindowEnd:
		return bad("the maintenance window is two different hours, 0-23")
	case len(s.SMART.Excluded) > 256:
		return bad("too many excluded disks")
	}
	for _, d := range s.SMART.Excluded {
		if !hw.ValidDevicePath(d) {
			return bad("excluded disks are listed by their /dev/disk/by-id path")
		}
	}
	return nil
}

// InWindow reports whether t's hour is in the maintenance window.
func (s Schedule) InWindow(t time.Time) bool {
	h := t.Hour()
	if s.WindowStart < s.WindowEnd {
		return h >= s.WindowStart && h < s.WindowEnd
	}
	return h >= s.WindowStart || h < s.WindowEnd
}

const settingsKey = "monitor.settings"

// Service is the monitor.
type Service struct {
	DB      *store.DB
	Priv    Caller
	Notify  notify.Notifier
	History *History
	Log     *slog.Logger
	Root    fs.FS // "/" (sysfs, procfs)
	UPS     *UPSService
	// PublishErrors returns publishing's failing services (key -> error);
	// nil when publishing isn't set up on this server.
	PublishErrors func(ctx context.Context) (map[string]string, error)
	// Now is the clock (tests).
	Now func() time.Time

	once     sync.Once
	sources  []Source
	conds    *conditions
	mu       sync.Mutex
	last     map[string]time.Time // when each check last ran
	smart    map[string]*hw.SMART // by-id -> last full reading
	smartAt  map[string]time.Time
	disks    []hw.Disk
	scrubs   map[string]bool // pool -> scrub running
	apps     map[string]string
	vms      map[string]string
	appBase  bool
	vmBase   bool
	privErr  int
	nbBad    int
	hot      map[string]int // sensor -> consecutive checks over a limit
	restarts map[string]int // app -> consecutive checks seen restarting
	appNames map[string]string
}

// AppNames maps app ids to names, from the last apps check (labels for
// per-app history).
func (s *Service) AppNames() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.appNames))
	for k, v := range s.appNames {
		out[k] = v
	}
	return out
}

func (s *Service) init() {
	s.once.Do(func() {
		if s.Notify == nil {
			s.Notify = notify.Discard
		}
		if s.Root == nil {
			s.Root = os.DirFS("/")
		}
		s.conds = &conditions{db: s.DB, notify: s.Notify, now: s.now}
		s.last, s.smart, s.smartAt, s.scrubs = map[string]time.Time{}, map[string]*hw.SMART{}, map[string]time.Time{}, map[string]bool{}
		s.apps, s.vms, s.hot, s.restarts = map[string]string{}, map[string]string{}, map[string]int{}, map[string]int{}
		s.appNames = map[string]string{}
	})
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// AddSource adds a history source (call before Run).
func (s *Service) AddSource(src Source) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sources = append(s.sources, src)
}

// Settings returns the current settings.
func (s *Service) Settings(ctx context.Context) Settings {
	st := DefaultSettings()
	if raw, err := s.DB.GetSetting(ctx, settingsKey); err == nil {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	if st.SMART.Excluded == nil {
		st.SMART.Excluded = []string{}
	}
	return st
}

// SaveSettings validates and stores settings.
func (s *Service) SaveSettings(ctx context.Context, st Settings) (Settings, error) {
	if st.SMART.Excluded == nil {
		st.SMART.Excluded = []string{}
	}
	if err := st.Validate(); err != nil {
		return st, err
	}
	b, _ := json.Marshal(st)
	return st, s.DB.SetSetting(ctx, settingsKey, string(b))
}

// Conditions lists what's wrong right now.
func (s *Service) Conditions(ctx context.Context) ([]Condition, error) {
	s.init()
	return s.conds.List(ctx)
}

// due reports whether a check named name should run now, and marks it.
func (s *Service) due(name string, every time.Duration, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.last[name]; ok && now.Sub(t) < every-time.Second {
		return false
	}
	s.last[name] = now
	return true
}

// Tick does everything due at now: history collection (every 10 s) and
// the checks on their own intervals.
func (s *Service) Tick(ctx context.Context, now time.Time) {
	s.init()
	s.collect(ctx, now)
	checks := []struct {
		name  string
		every time.Duration
		fn    func(context.Context, time.Time)
	}{
		{"pools", time.Minute, s.checkPools},
		{"smart", 10 * time.Minute, s.checkSMART},
		{"selftests", time.Minute, s.scheduleSelfTests},
		{"apps", 30 * time.Second, s.checkApps},
		{"vms", 30 * time.Second, s.checkVMs},
		{"priv", time.Minute, s.checkPriv},
		{"netbird", time.Minute, s.checkNetBird},
		{"domain", 10 * time.Minute, s.checkReplication},
		{"publish", 5 * time.Minute, s.checkPublish},
		{"sensors", time.Minute, s.checkSensors},
	}
	for _, c := range checks {
		if s.due(c.name, c.every, now) {
			c.fn(ctx, now)
		}
	}
	if s.History != nil && s.due("history.flush", time.Minute, now) {
		if err := s.History.Flush(ctx); err != nil {
			s.log().Warn("history flush", "err", err)
		}
		if err := s.History.Rollup(ctx, now); err != nil {
			s.log().Warn("history rollup", "err", err)
		}
	}
	if s.History != nil && s.due("history.prune", time.Hour, now) {
		if err := s.History.Prune(ctx, now); err != nil {
			s.log().Warn("history prune", "err", err)
		}
	}
}

// collect runs the sources that are due and records their points.
func (s *Service) collect(ctx context.Context, now time.Time) {
	if s.History == nil {
		return
	}
	s.mu.Lock()
	srcs := append([]Source(nil), s.sources...)
	s.mu.Unlock()
	for _, src := range srcs {
		if !s.due("src."+src.Name(), src.Interval(), now) {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		pts, err := src.Collect(cctx, now)
		cancel()
		if err != nil {
			s.log().Debug("history source failed", "source", src.Name(), "err", err)
		}
		s.record(ctx, now, pts)
	}
}

func (s *Service) record(ctx context.Context, now time.Time, pts []Point) {
	if s.History == nil {
		return
	}
	for _, p := range pts {
		if err := s.History.Record(ctx, SeriesInfo{Name: p.Series, Label: p.Label, Unit: p.Unit}, now, p.Value); err != nil {
			s.log().Debug("history record", "series", p.Series, "err", err)
		}
	}
}

// Run ticks every 10 seconds until ctx is done.
func (s *Service) Run(ctx context.Context) {
	s.init()
	if s.UPS != nil {
		s.UPS.Notify = s.Notify
		go s.UPS.Run(ctx)
	}
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if s.History != nil {
				_ = s.History.Flush(context.Background())
			}
			return
		case now := <-t.C:
			s.Tick(ctx, now)
		}
	}
}

// ScrubAllowed is storage's hook for starting scheduled scrubs: inside the
// maintenance window (when set to), and not while another pool scrubs or a
// disk of the pool runs a long self-test.
func (s *Service) ScrubAllowed(ctx context.Context, pool string, now time.Time) bool {
	s.init()
	set := s.Settings(ctx)
	if set.SMART.ScrubInWindow && !set.SMART.InWindow(now.Local()) {
		return false
	}
	s.mu.Lock()
	for p, running := range s.scrubs {
		if running && p != pool {
			s.mu.Unlock()
			return false
		}
	}
	disks := append([]hw.Disk(nil), s.disks...)
	s.mu.Unlock()
	for _, d := range disks {
		if d.Pool != pool {
			continue
		}
		var running string
		_ = s.DB.QueryRowContext(ctx, `SELECT running FROM smart_tests WHERE by_id = ?`, d.ByID).Scan(&running)
		if running == "long" {
			return false
		}
	}
	return true
}
