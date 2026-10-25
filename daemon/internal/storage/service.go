package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Caller is the part of the root helper client the service uses (faked in tests).
type Caller interface {
	Call(ctx context.Context, op string, args any, out any) error
}

// Service is hardyd's storage layer.
type Service struct {
	Priv    Caller
	Jobs    *jobs.Manager
	DB      *store.DB
	Notify  *notify.Center
	Log     *slog.Logger
	Monitor time.Duration // how often long jobs poll pool status; default 15s
}

// Job kinds.
const (
	KindPoolCreate  = "storage.pool.create"
	KindPoolAdd     = "storage.pool.add"
	KindPoolAttach  = "storage.pool.attach"
	KindPoolReplace = "storage.pool.replace"
)

// StandardDatasets are created on every new pool (see docs/architecture.md).
var StandardDatasets = []struct{ Name, Role string }{
	{"system", "system"}, {"apps", "apps"}, {"users", "users"}, {"shares", "shares"}, {"vms", "vms"},
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// Hardware is the full hardware picture shown in the UI.
type Hardware struct {
	System       hw.System       `json:"system"`
	Disks        []hw.Disk       `json:"disks"`
	Capabilities hw.Capabilities `json:"capabilities"`
}

// Hardware reads the system, disks and capability profile from the root helper.
func (s *Service) Hardware(ctx context.Context) (*Hardware, error) {
	var h Hardware
	if err := s.Priv.Call(ctx, priv.OpHWSystem, nil, &h.System); err != nil {
		return nil, err
	}
	if err := s.Priv.Call(ctx, priv.OpHWDisks, nil, &h.Disks); err != nil {
		return nil, err
	}
	if h.Disks == nil {
		h.Disks = []hw.Disk{}
	}
	h.Capabilities = hw.Profile(h.System, h.Disks)
	return &h, nil
}

// Recommend proposes a layout for a new pool from the currently unused disks.
func (s *Service) Recommend(ctx context.Context, name string) (*Recommendation, error) {
	if err := zfs.ValidPoolName(name); err != nil {
		return nil, err
	}
	h, err := s.Hardware(ctx)
	if err != nil {
		return nil, err
	}
	return Recommend(name, h.Disks, h.System.Memory.TotalBytes)
}

// lockPool serializes jobs on one pool.
func lockPool(field string) func(json.RawMessage) string {
	return func(raw json.RawMessage) string {
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			return ""
		}
		var name string
		if v, ok := m[field]; ok {
			_ = json.Unmarshal(v, &name)
		}
		if name == "" {
			if spec, ok := m["spec"]; ok {
				var ps zfs.PoolSpec
				_ = json.Unmarshal(spec, &ps)
				name = ps.Name
			}
		}
		if name == "" {
			return ""
		}
		return "pool:" + name
	}
}

// CreatePoolParams are the job parameters for KindPoolCreate.
type CreatePoolParams struct {
	Spec zfs.PoolSpec `json:"spec"`
}

// AddParams are the job parameters for KindPoolAdd.
type AddParams struct {
	Pool string       `json:"pool"`
	Spec zfs.PoolSpec `json:"spec"`
}

// AttachParams are the job parameters for KindPoolAttach.
type AttachParams struct {
	Pool   string `json:"pool"`
	Target string `json:"target"`
	Disk   string `json:"disk"`
}

// ReplaceParams are the job parameters for KindPoolReplace.
type ReplaceParams struct {
	Pool string `json:"pool"`
	Old  string `json:"old"`
	Disk string `json:"disk"`
}

// RegisterJobs adds the storage job kinds to the manager.
func (s *Service) RegisterJobs(m *jobs.Manager) {
	m.Register(jobs.Kind{Name: KindPoolCreate, AdminOnly: true, LockKey: lockPool("pool"), Run: s.runCreate})
	m.Register(jobs.Kind{Name: KindPoolAdd, AdminOnly: true, LockKey: lockPool("pool"), Run: func(jc *jobs.Context) (any, error) {
		var p AddParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(10, "Preparing disks")
		var st zfs.Status
		if err := s.Priv.Call(jc, priv.OpPoolAdd, priv.PoolAddArgs{Pool: p.Pool, Spec: p.Spec, ConfirmWipe: true}, &st); err != nil {
			return nil, err
		}
		s.send(jc, notify.Success, "Disks added to "+p.Pool, fmt.Sprintf("%d disk(s) were added.", len(p.Spec.Disks())))
		return st, nil
	}})
	m.Register(jobs.Kind{Name: KindPoolAttach, AdminOnly: true, LockKey: lockPool("pool"), Run: func(jc *jobs.Context) (any, error) {
		var p AttachParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(2, "Attaching disk")
		if err := s.Priv.Call(jc, priv.OpPoolAttach, priv.PoolAttachArgs{Pool: p.Pool, Target: p.Target, Disk: p.Disk, ConfirmWipe: true}, nil); err != nil {
			return nil, err
		}
		st, err := s.monitor(jc, p.Pool, "expand")
		if err == nil {
			s.send(jc, notify.Success, "Pool "+p.Pool+" expanded", "The new disk is part of "+p.Target+".")
		}
		return st, err
	}})
	m.Register(jobs.Kind{Name: KindPoolReplace, AdminOnly: true, LockKey: lockPool("pool"), Run: func(jc *jobs.Context) (any, error) {
		var p ReplaceParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(2, "Starting replacement")
		if err := s.Priv.Call(jc, priv.OpPoolReplace, priv.PoolReplaceArgs{Pool: p.Pool, Old: p.Old, Disk: p.Disk, ConfirmWipe: true}, nil); err != nil {
			return nil, err
		}
		st, err := s.monitor(jc, p.Pool, "resilver")
		if err == nil {
			s.send(jc, notify.Success, "Disk replaced in "+p.Pool, "Resilvering finished; the pool is fully redundant again.")
		}
		return st, err
	}})
}

func (s *Service) runCreate(jc *jobs.Context) (any, error) {
	var p CreatePoolParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	name := p.Spec.Name
	jc.Progress(5, "Erasing disks and creating the pool")
	var st zfs.Status
	if err := s.Priv.Call(jc, priv.OpPoolCreate, priv.PoolCreateArgs{Spec: p.Spec, ConfirmWipe: true}, &st); err != nil {
		return nil, err
	}
	jc.Progress(70, "Creating standard datasets")
	for _, d := range StandardDatasets {
		args := priv.DatasetCreateArgs{Name: name + "/" + d.Name, Props: map[string]string{"hardyos:role": d.Role}}
		if err := s.Priv.Call(jc, priv.OpDatasetCreate, args, nil); err != nil {
			return nil, fmt.Errorf("create dataset %s: %w", args.Name, err)
		}
	}
	jc.Progress(85, "Setting up schedules")
	if err := s.defaultPolicies(jc, name); err != nil {
		s.log().Warn("default policies", "pool", name, "err", err)
	}
	s.applyARC(jc)
	s.send(jc, notify.Success, "Pool "+name+" is ready", "Standard folders, monthly scrubs and daily snapshots of users and shares are set up.")
	return st, nil
}

// defaultPolicies: monthly scrub; daily (14) and weekly (8) snapshots of users and shares.
func (s *Service) defaultPolicies(ctx context.Context, pool string) error {
	if _, err := s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO scrub_policies (pool, interval_days, enabled) VALUES (?, 30, 1)`, pool); err != nil {
		return err
	}
	for _, ds := range []string{pool + "/users", pool + "/shares"} {
		for _, p := range []struct {
			freq string
			keep int
		}{{"daily", 14}, {"weekly", 8}} {
			if _, err := s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO snapshot_policies (dataset, frequency, keep, recursive, enabled, created_at)
				VALUES (?, ?, ?, 1, 1, ?)`, ds, p.freq, p.keep, store.Now()); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyARC sets the suggested ARC limit once, the first time a pool is created.
func (s *Service) applyARC(ctx context.Context) {
	if _, err := s.DB.GetSetting(ctx, "zfs.arc_max"); err == nil {
		return
	}
	h, err := s.Hardware(ctx)
	if err != nil || h.Capabilities.ARCMaxBytes == 0 {
		return
	}
	if err := s.Priv.Call(ctx, priv.OpARCSet, priv.ARCSetArgs{MaxBytes: h.Capabilities.ARCMaxBytes}, nil); err != nil {
		s.log().Warn("set ARC limit", "err", err)
		return
	}
	_ = s.DB.SetSetting(ctx, "zfs.arc_max", fmt.Sprint(h.Capabilities.ARCMaxBytes))
}

// monitor polls pool status until the given scan kind ("resilver" or "expand") is done.
func (s *Service) monitor(jc *jobs.Context, pool, kind string) (*zfs.Status, error) {
	interval := s.Monitor
	if interval == 0 {
		interval = 15 * time.Second
	}
	label := map[string]string{"resilver": "Resilvering", "expand": "Expanding"}[kind]
	for {
		var st zfs.Status
		if err := s.Priv.Call(jc, priv.OpPoolStatus, priv.PoolArgs{Pool: pool}, &st); err != nil {
			return nil, err
		}
		scan := st.Scan
		if kind == "expand" {
			if st.Expand == nil {
				return &st, nil
			}
			scan = *st.Expand
		}
		if scan.Kind != kind || scan.State != "running" {
			return &st, nil
		}
		pct := 0.0
		if scan.Percent != nil {
			pct = *scan.Percent
		}
		msg := label
		if scan.Remaining != "" {
			msg += ", " + scan.Remaining + " to go"
		}
		jc.Progress(pct, msg)
		select {
		case <-jc.Done():
			return nil, errors.New("stopped watching; the operation continues in the background")
		case <-time.After(interval):
		}
	}
}

func (s *Service) send(ctx context.Context, level notify.Level, title, body string) {
	if s.Notify == nil {
		return
	}
	if err := s.Notify.Send(ctx, notify.Notification{Level: level, Title: title, Body: body, Source: "storage", AdminOnly: true}); err != nil {
		s.log().Warn("notification failed", "err", err)
	}
}
