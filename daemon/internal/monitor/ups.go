package monitor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/ups"
)

// UPSSecretsInput changes UPS passwords: nil keeps, "" clears.
type UPSSecretsInput struct {
	ClientPassword *string `json:"clientPassword,omitempty"`
	RemotePassword *string `json:"remotePassword,omitempty"`
}

// UPSView is what the UPS page shows.
type UPSView struct {
	Config     ups.Config      `json:"config"`
	SecretsSet map[string]bool `json:"secretsSet"`
	Status     *ups.Status     `json:"status"`
	Error      string          `json:"error"`
	CheckedAt  *time.Time      `json:"checkedAt"`
}

const (
	upsConfigKey  = "ups.config"
	upsSecretsKey = "ups.secrets"
	upsPurpose    = "ups"
)

// UPSService keeps the UPS setup in hardyd's database and watches the UPS.
type UPSService struct {
	DB     *store.DB
	Keys   secretbox.Source // nil: a key for this process only (tests)
	Notify notify.Notifier
	Log    *slog.Logger
	// Interval between reads (default 10 s).
	Interval time.Duration
	// Query reads a UPS (default ups.Query); tests replace it.
	Query func(ctx context.Context, addr, name string) (*ups.Status, error)

	mu        sync.Mutex
	last      *ups.Status
	lastErr   string
	checked   time.Time
	failures  int
	baseline  bool
	commAlert bool
}

func (s *UPSService) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *UPSService) key(ctx context.Context) ([]byte, error) {
	if s.Keys == nil {
		s.Keys = secretbox.NewStaticSource()
	}
	return s.Keys.Key(ctx, upsPurpose)
}

// Config returns the stored setup and its passwords.
func (s *UPSService) Config(ctx context.Context) (ups.Config, ups.Secrets, error) {
	c := ups.Config{Mode: ups.ModeOff}
	var sec ups.Secrets
	if raw, err := s.DB.GetSetting(ctx, upsConfigKey); err == nil {
		_ = json.Unmarshal([]byte(raw), &c)
	}
	raw, err := s.DB.GetSetting(ctx, upsSecretsKey)
	if err != nil || raw == "" {
		return c, sec, nil
	}
	sealed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return c, sec, nil
	}
	k, err := s.key(ctx)
	if err != nil {
		return c, sec, err
	}
	plain, err := secretbox.Open(k, sealed, []byte("settings:"+upsSecretsKey))
	if err != nil {
		return c, sec, fmt.Errorf("the UPS passwords can't be read on this server; enter them again: %w", err)
	}
	_ = json.Unmarshal(plain, &sec)
	return c, sec, nil
}

// Save validates and stores a setup; it returns what hardyd-priv should
// apply. Applying it is a job (internal/api).
func (s *UPSService) Save(ctx context.Context, c ups.Config, in *UPSSecretsInput) (ups.Config, ups.Secrets, error) {
	_, sec, _ := s.Config(ctx)
	if in != nil {
		if in.ClientPassword != nil {
			sec.ClientPassword = *in.ClientPassword
		}
		if in.RemotePassword != nil {
			sec.RemotePassword = *in.RemotePassword
		}
	}
	norm, err := c.Normalize(sec)
	if err != nil {
		return c, sec, err
	}
	switch norm.Mode {
	case ups.ModeLocal:
		if !norm.ServeNetwork {
			sec.ClientPassword = ""
		}
		sec.RemotePassword = ""
	case ups.ModeNetClient:
		sec.ClientPassword = ""
	default:
		sec = ups.Secrets{}
	}
	b, _ := json.Marshal(norm)
	if err := s.DB.SetSetting(ctx, upsConfigKey, string(b)); err != nil {
		return norm, sec, err
	}
	sealed := ""
	if sec != (ups.Secrets{}) {
		k, err := s.key(ctx)
		if err != nil {
			return norm, sec, err
		}
		plain, _ := json.Marshal(sec)
		box, err := secretbox.Seal(k, plain, []byte("settings:"+upsSecretsKey))
		if err != nil {
			return norm, sec, err
		}
		sealed = base64.StdEncoding.EncodeToString(box)
	}
	if err := s.DB.SetSetting(ctx, upsSecretsKey, sealed); err != nil {
		return norm, sec, err
	}
	s.mu.Lock()
	s.last, s.lastErr, s.baseline, s.failures, s.commAlert = nil, "", false, 0, false
	s.mu.Unlock()
	return norm, sec, nil
}

// View returns the setup (without passwords) and the last reading.
func (s *UPSService) View(ctx context.Context) (*UPSView, error) {
	c, sec, err := s.Config(ctx)
	v := &UPSView{Config: c, SecretsSet: map[string]bool{"clientPassword": sec.ClientPassword != "", "remotePassword": sec.RemotePassword != ""}}
	if err != nil {
		v.Error = err.Error()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v.Status = s.last
	if v.Error == "" {
		v.Error = s.lastErr
	}
	if !s.checked.IsZero() {
		t := s.checked
		v.CheckedAt = &t
	}
	return v, nil
}

// Latest is the last good reading (nil if none, or if the last read failed).
func (s *UPSService) Latest() *ups.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastErr != "" {
		return nil
	}
	return s.last
}

// Run reads the UPS every Interval until ctx is done.
func (s *UPSService) Run(ctx context.Context) {
	iv := s.Interval
	if iv == 0 {
		iv = 10 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		s.Poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *UPSService) notify(ctx context.Context, kind, sev, title, body string) {
	if s.Notify != nil {
		s.Notify.Notify(ctx, notify.Event{Kind: kind, Severity: sev, Title: title, Body: body, Link: "ups"})
	}
}

func describe(st *ups.Status) string {
	var parts []string
	if st.ChargePct != nil {
		parts = append(parts, fmt.Sprintf("battery %.0f%%", *st.ChargePct))
	}
	if st.RuntimeSecs != nil {
		parts = append(parts, fmt.Sprintf("about %d minutes left", int(math.Round(*st.RuntimeSecs/60))))
	}
	if st.LoadPct != nil {
		parts = append(parts, fmt.Sprintf("load %.0f%%", *st.LoadPct))
	}
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += ", " + p
	}
	return "Now: " + out + "."
}

// UPSSource records the UPS's charge, runtime, load and input voltage.
func UPSSource(u *UPSService) Source {
	return FuncSource{ID: "ups", Every: 10 * time.Second, Fn: func(context.Context, time.Time) ([]Point, error) {
		st := u.Latest()
		if st == nil {
			return nil, nil
		}
		var pts []Point
		add := func(series, unit string, v *float64) {
			if v != nil {
				pts = append(pts, Point{Series: series + ":" + st.UPS, Label: st.UPS, Unit: unit, Value: *v})
			}
		}
		add("ups.charge", UnitPercent, st.ChargePct)
		add("ups.runtime", UnitSeconds, st.RuntimeSecs)
		add("ups.load", UnitPercent, st.LoadPct)
		add("ups.input", UnitVolts, st.InputVolts)
		return pts, nil
	}}
}

// commFailures is how many reads in a row must fail before an alert.
const commFailures = 3

// Poll reads the UPS once and raises alerts for what changed.
func (s *UPSService) Poll(ctx context.Context) {
	c, _, err := s.Config(ctx)
	if err != nil || c.Mode == ups.ModeOff || c.Mode == "" {
		s.mu.Lock()
		s.last, s.lastErr, s.checked = nil, "", time.Time{}
		s.mu.Unlock()
		return
	}
	addr, name := c.Target()
	q := s.Query
	if q == nil {
		q = ups.Query
	}
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	st, err := q(qctx, addr, name)
	cancel()
	where := "this server's UPS"
	if c.Mode == ups.ModeNetClient {
		where = "the UPS on " + c.RemoteHost
	}

	s.mu.Lock()
	prev, wasBase := s.last, s.baseline
	s.checked = time.Now().UTC()
	if err != nil {
		s.failures++
		s.lastErr = err.Error()
		if errors.Is(err, ups.ErrStale) {
			s.lastErr = ups.ErrStale.Error()
		}
		raise := s.failures == commFailures && !s.commAlert
		if raise {
			s.commAlert = true
		}
		s.mu.Unlock()
		if raise {
			s.notify(ctx, "ups.comm", notify.SeverityWarning, "Lost contact with "+where,
				"HardyOS can't read the UPS ("+err.Error()+"). If the power fails now, this server may not shut down cleanly. Check the USB cable or the UPS server.")
		}
		return
	}
	recovered := s.commAlert
	s.failures, s.lastErr, s.commAlert, s.last, s.baseline = 0, "", false, st, true
	s.mu.Unlock()

	if recovered {
		s.notify(ctx, "ups.comm", notify.SeverityInfo, "Contact with "+where+" is back", describe(st))
	}
	if !wasBase || prev == nil {
		// First reading since start (or a new setup): only report what
		// needs attention now.
		if st.OnBattery {
			s.notify(ctx, "ups.power", notify.SeverityWarning, "UPS on battery", "The power is out. "+describe(st))
		}
		if st.ReplaceBattery {
			s.notify(ctx, "ups.battery", notify.SeverityWarning, "Replace the UPS battery", "The UPS says its battery needs replacing.")
		}
		return
	}
	switch {
	case st.OnBattery && !prev.OnBattery:
		s.notify(ctx, "ups.power", notify.SeverityWarning, "UPS on battery", "The power went out. "+describe(st)+
			" HardyOS shuts down cleanly when the battery runs low.")
	case st.OnLine && prev.OnBattery:
		s.notify(ctx, "ups.power", notify.SeverityInfo, "Power is back", "The UPS is on mains power again. "+describe(st))
	}
	if st.LowBattery && !prev.LowBattery {
		s.notify(ctx, "ups.battery", notify.SeverityCritical, "UPS battery low: shutting down",
			"The battery is nearly empty. Servers using this UPS are shutting down now. "+describe(st))
	}
	if st.ForcedShutdown && !prev.ForcedShutdown {
		s.notify(ctx, "ups.power", notify.SeverityCritical, "UPS shutdown in progress", "The UPS server asked every server on this UPS to shut down.")
	}
	if st.ReplaceBattery && !prev.ReplaceBattery {
		s.notify(ctx, "ups.battery", notify.SeverityWarning, "Replace the UPS battery", "The UPS says its battery needs replacing.")
	}
	if st.Overload && !prev.Overload {
		s.notify(ctx, "ups.load", notify.SeverityWarning, "UPS overloaded", "More is plugged into the UPS than it can carry. "+describe(st))
	}
}
