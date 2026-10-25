package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// SnapshotPolicy takes automatic snapshots of a dataset and keeps the newest Keep.
type SnapshotPolicy struct {
	ID        int64      `json:"id"`
	Dataset   string     `json:"dataset"`
	Frequency string     `json:"frequency"` // hourly, daily, weekly, monthly
	Keep      int        `json:"keep"`
	Recursive bool       `json:"recursive"`
	Enabled   bool       `json:"enabled"`
	LastRunAt *time.Time `json:"lastRunAt"`
	LastError string     `json:"lastError"`
}

// ScrubPolicy scrubs a pool every IntervalDays.
type ScrubPolicy struct {
	Pool          string     `json:"pool"`
	IntervalDays  int        `json:"intervalDays"`
	Enabled       bool       `json:"enabled"`
	LastStartedAt *time.Time `json:"lastStartedAt"`
	LastError     string     `json:"lastError"`
}

var periods = map[string]time.Duration{
	"hourly":  time.Hour,
	"daily":   24 * time.Hour,
	"weekly":  7 * 24 * time.Hour,
	"monthly": 30 * 24 * time.Hour,
}

// ValidFrequency reports whether f is a known snapshot frequency.
func ValidFrequency(f string) bool { _, ok := periods[f]; return ok }

// autoPrefix is the label prefix for a policy's snapshots.
func autoPrefix(freq string) string { return "auto-" + freq + "-" }

// SMARTInterval is how often every disk's SMART health is checked.
const SMARTInterval = 6 * time.Hour

// Run calls Tick every minute until ctx is cancelled.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	s.Tick(ctx, time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.Tick(ctx, now)
		}
	}
}

// Tick runs everything that is due at now. Errors are logged and recorded on
// the policy, never fatal.
func (s *Service) Tick(ctx context.Context, now time.Time) {
	if err := s.runSnapshots(ctx, now); err != nil {
		s.log().Warn("snapshot schedule", "err", err)
	}
	if err := s.runScrubs(ctx, now); err != nil {
		s.log().Warn("scrub schedule", "err", err)
	}
	if err := s.checkPools(ctx); err != nil {
		s.log().Warn("pool health check", "err", err)
	}
	last, _ := s.DB.GetSetting(ctx, "smart.last_check")
	if t := store.ParseTime(last); now.Sub(t) >= SMARTInterval {
		if err := s.CheckSMART(ctx); err != nil {
			s.log().Warn("SMART check", "err", err)
		}
		_ = s.DB.SetSetting(ctx, "smart.last_check", store.FormatTime(now))
	}
}

// ListSnapshotPolicies returns all snapshot policies.
func (s *Service) ListSnapshotPolicies(ctx context.Context) ([]SnapshotPolicy, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, dataset, frequency, keep, recursive, enabled, last_run_at, last_error
		FROM snapshot_policies ORDER BY dataset, frequency`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SnapshotPolicy{}
	for rows.Next() {
		var p SnapshotPolicy
		var rec, en int
		var last sql.NullString
		if err := rows.Scan(&p.ID, &p.Dataset, &p.Frequency, &p.Keep, &rec, &en, &last, &p.LastError); err != nil {
			return nil, err
		}
		p.Recursive, p.Enabled = rec != 0, en != 0
		if last.Valid {
			t := store.ParseTime(last.String)
			p.LastRunAt = &t
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SaveSnapshotPolicy creates (ID 0) or updates a policy.
func (s *Service) SaveSnapshotPolicy(ctx context.Context, p SnapshotPolicy) (*SnapshotPolicy, error) {
	if err := zfs.ValidDatasetName(p.Dataset); err != nil {
		return nil, err
	}
	if !ValidFrequency(p.Frequency) {
		return nil, fmt.Errorf("frequency must be hourly, daily, weekly or monthly")
	}
	if p.Keep < 1 || p.Keep > 1000 {
		return nil, fmt.Errorf("keep must be between 1 and 1000")
	}
	if p.ID == 0 {
		res, err := s.DB.ExecContext(ctx, `INSERT INTO snapshot_policies (dataset, frequency, keep, recursive, enabled, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`, p.Dataset, p.Frequency, p.Keep, b2i(p.Recursive), b2i(p.Enabled), store.Now())
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return nil, fmt.Errorf("%s already has a %s policy", p.Dataset, p.Frequency)
			}
			return nil, err
		}
		p.ID, _ = res.LastInsertId()
	} else {
		res, err := s.DB.ExecContext(ctx, `UPDATE snapshot_policies SET keep = ?, recursive = ?, enabled = ? WHERE id = ?`,
			p.Keep, b2i(p.Recursive), b2i(p.Enabled), p.ID)
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil, store.ErrNotFound
		}
	}
	return &p, nil
}

// DeleteSnapshotPolicy removes a policy (its snapshots stay).
func (s *Service) DeleteSnapshotPolicy(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM snapshot_policies WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ListScrubPolicies returns all scrub policies.
func (s *Service) ListScrubPolicies(ctx context.Context) ([]ScrubPolicy, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT pool, interval_days, enabled, last_started_at, last_error FROM scrub_policies ORDER BY pool`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ScrubPolicy{}
	for rows.Next() {
		var p ScrubPolicy
		var en int
		var last sql.NullString
		if err := rows.Scan(&p.Pool, &p.IntervalDays, &en, &last, &p.LastError); err != nil {
			return nil, err
		}
		p.Enabled = en != 0
		if last.Valid {
			t := store.ParseTime(last.String)
			p.LastStartedAt = &t
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SaveScrubPolicy creates or updates a pool's scrub schedule.
func (s *Service) SaveScrubPolicy(ctx context.Context, p ScrubPolicy) (*ScrubPolicy, error) {
	if err := zfs.ValidPoolName(p.Pool); err != nil {
		return nil, err
	}
	if p.IntervalDays < 1 || p.IntervalDays > 365 {
		return nil, fmt.Errorf("intervalDays must be between 1 and 365")
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO scrub_policies (pool, interval_days, enabled) VALUES (?, ?, ?)
		ON CONFLICT(pool) DO UPDATE SET interval_days = excluded.interval_days, enabled = excluded.enabled`,
		p.Pool, p.IntervalDays, b2i(p.Enabled))
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Service) runSnapshots(ctx context.Context, now time.Time) error {
	policies, err := s.ListSnapshotPolicies(ctx)
	if err != nil {
		return err
	}
	for _, p := range policies {
		if !p.Enabled || (p.LastRunAt != nil && now.Sub(*p.LastRunAt) < periods[p.Frequency]-time.Minute) {
			continue
		}
		runErr := s.snapshotOnce(ctx, p, now)
		msg := ""
		if runErr != nil {
			msg = runErr.Error()
			s.send(ctx, notify.Warning, "Automatic snapshot failed", fmt.Sprintf("%s (%s): %s", p.Dataset, p.Frequency, msg))
		}
		if _, err := s.DB.ExecContext(ctx, `UPDATE snapshot_policies SET last_run_at = ?, last_error = ? WHERE id = ?`,
			store.FormatTime(now), msg, p.ID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) snapshotOnce(ctx context.Context, p SnapshotPolicy, now time.Time) error {
	label := autoPrefix(p.Frequency) + now.UTC().Format("20060102-1504")
	if err := s.Priv.Call(ctx, priv.OpSnapshotCreate, priv.SnapshotCreateArgs{Dataset: p.Dataset, Label: label, Recursive: p.Recursive}, nil); err != nil {
		return err
	}
	var snaps []zfs.Snapshot
	if err := s.Priv.Call(ctx, priv.OpSnapshots, priv.DatasetListArgs{Root: p.Dataset}, &snaps); err != nil {
		return err
	}
	byDataset := map[string][]zfs.Snapshot{}
	for _, sn := range snaps {
		if !strings.HasPrefix(sn.Label, autoPrefix(p.Frequency)) {
			continue
		}
		if sn.Dataset != p.Dataset && !p.Recursive {
			continue
		}
		byDataset[sn.Dataset] = append(byDataset[sn.Dataset], sn)
	}
	var errs []error
	for _, list := range byDataset {
		sort.Slice(list, func(i, j int) bool { return list[i].Label > list[j].Label }) // newest first (labels sort by time)
		for _, old := range list[min(p.Keep, len(list)):] {
			if err := s.Priv.Call(ctx, priv.OpSnapshotDestroy, priv.SnapshotArgs{Name: old.Name}, nil); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (s *Service) runScrubs(ctx context.Context, now time.Time) error {
	policies, err := s.ListScrubPolicies(ctx)
	if err != nil {
		return err
	}
	for _, p := range policies {
		if !p.Enabled {
			continue
		}
		var st zfs.Status
		if err := s.Priv.Call(ctx, priv.OpPoolStatus, priv.PoolArgs{Pool: p.Pool}, &st); err != nil {
			continue // pool exported or missing; nothing to do
		}
		if st.Scan.State == "running" || st.Scan.State == "paused" {
			continue
		}
		last := p.LastStartedAt
		if st.Scan.Kind == "scrub" && st.Scan.FinishedAt != nil && (last == nil || st.Scan.FinishedAt.After(*last)) {
			last = st.Scan.FinishedAt
		}
		if last != nil && now.Sub(*last) < time.Duration(p.IntervalDays)*24*time.Hour {
			continue
		}
		msg := ""
		if err := s.Priv.Call(ctx, priv.OpPoolScrub, priv.PoolScrubArgs{Pool: p.Pool, Action: "start"}, nil); err != nil {
			msg = err.Error()
		}
		if _, err := s.DB.ExecContext(ctx, `UPDATE scrub_policies SET last_started_at = ?, last_error = ? WHERE pool = ?`,
			store.FormatTime(now), msg, p.Pool); err != nil {
			return err
		}
	}
	return nil
}

// checkPools notifies when a pool's health changes from what was last seen.
func (s *Service) checkPools(ctx context.Context) error {
	var pools []zfs.Pool
	if err := s.Priv.Call(ctx, priv.OpPools, nil, &pools); err != nil {
		return err
	}
	for _, p := range pools {
		key := "pool.health." + p.Name
		prev, err := s.DB.GetSetting(ctx, key)
		if err == nil && prev == p.Health {
			continue
		}
		_ = s.DB.SetSetting(ctx, key, p.Health)
		if errors.Is(err, store.ErrNotFound) && p.Health == "ONLINE" {
			continue // first sighting of a healthy pool
		}
		switch p.Health {
		case "ONLINE":
			s.send(ctx, notify.Success, "Pool "+p.Name+" is healthy again", "")
		case "DEGRADED":
			s.send(ctx, notify.Warning, "Pool "+p.Name+" is degraded", "A disk has failed or gone missing. Your data is still safe; replace the disk soon in Storage Manager.")
		default:
			s.send(ctx, notify.Error, "Pool "+p.Name+" is "+strings.ToLower(p.Health), "The pool needs attention now. Open Storage Manager for details.")
		}
	}
	return nil
}

// DiskHealth is the stored SMART verdict for a disk.
type DiskHealth struct {
	ByID         string    `json:"byId"`
	Health       hw.Health `json:"health"`
	Reasons      []string  `json:"reasons"`
	TemperatureC *int      `json:"temperatureC"`
	CheckedAt    time.Time `json:"checkedAt"`
}

var healthRank = map[hw.Health]int{hw.HealthGood: 0, hw.HealthUnknown: 0, hw.HealthWarning: 1, hw.HealthFailing: 2}

// CheckSMART reads every fixed disk's SMART data and notifies when one gets worse.
func (s *Service) CheckSMART(ctx context.Context) error {
	var disks []hw.Disk
	if err := s.Priv.Call(ctx, priv.OpHWDisks, nil, &disks); err != nil {
		return err
	}
	for _, d := range disks {
		if d.Removable {
			continue
		}
		dev := d.ByID
		if !hw.ValidDevicePath(dev) {
			dev = d.Path
		}
		var sm hw.SMART
		if err := s.Priv.Call(ctx, priv.OpHWSmart, priv.DeviceArgs{Device: dev}, &sm); err != nil {
			s.log().Debug("SMART read failed", "disk", dev, "err", err)
			continue
		}
		var prev string
		_ = s.DB.QueryRowContext(ctx, `SELECT health FROM disk_health WHERE by_id = ?`, d.ByID).Scan(&prev)
		reasons, _ := json.Marshal(sm.Reasons)
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO disk_health (by_id, health, reasons, temperature, checked_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(by_id) DO UPDATE SET health = excluded.health, reasons = excluded.reasons,
			temperature = excluded.temperature, checked_at = excluded.checked_at`,
			d.ByID, sm.Health, string(reasons), sm.TemperatureC, store.Now()); err != nil {
			return err
		}
		if healthRank[sm.Health] > healthRank[hw.Health(prev)] {
			level := notify.Warning
			if sm.Health == hw.HealthFailing {
				level = notify.Error
			}
			s.send(ctx, level, fmt.Sprintf("Disk %s health: %s", d.Name, sm.Health),
				fmt.Sprintf("%s (%s): %s", d.Model, d.Serial, strings.Join(sm.Reasons, "; ")))
		}
	}
	return nil
}

// DiskHealthAll returns the stored SMART verdict for every disk checked so far.
func (s *Service) DiskHealthAll(ctx context.Context) ([]DiskHealth, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT by_id, health, reasons, temperature, checked_at FROM disk_health ORDER BY by_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DiskHealth{}
	for rows.Next() {
		var h DiskHealth
		var reasons, checked string
		var temp sql.NullInt64
		if err := rows.Scan(&h.ByID, &h.Health, &reasons, &temp, &checked); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(reasons), &h.Reasons)
		if temp.Valid {
			t := int(temp.Int64)
			h.TemperatureC = &t
		}
		h.CheckedAt = store.ParseTime(checked)
		out = append(out, h)
	}
	return out, rows.Err()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
