package monitor

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
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
	// Addresses are this server's addresses, for the one upsd listens on.
	Addresses []string `json:"addresses"`
}

// serverAddrs lists this server's unicast addresses (not loopback or
// link-local), for choosing where upsd listens.
func serverAddrs() []string {
	out := []string{}
	as, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range as {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := p.Addr().Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		out = append(out, ip.String())
	}
	return out
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
//
// The setup before is kept until RestorePrevious or ForgetPrevious (the
// apply job calls one of them), so a setup that fails to apply is rolled
// back. moved reports that the remote UPS server, port or user changed.
func (s *UPSService) Save(ctx context.Context, c ups.Config, in *UPSSecretsInput) (norm ups.Config, sec ups.Secrets, moved bool, err error) {
	old, sec, _ := s.Config(ctx)
	if in != nil {
		if in.ClientPassword != nil {
			sec.ClientPassword = *in.ClientPassword
		}
		if in.RemotePassword != nil {
			sec.RemotePassword = *in.RemotePassword
		}
	}
	norm, err = c.Normalize(sec)
	if err != nil {
		return c, sec, false, err
	}
	// The remote password only goes to the server it was entered for.
	if old.Mode == ups.ModeNetClient && norm.Mode == ups.ModeNetClient &&
		(old.RemoteHost != norm.RemoteHost || old.RemotePort != norm.RemotePort || old.RemoteUser != norm.RemoteUser) {
		moved = true
		if in == nil || in.RemotePassword == nil {
			return c, sec, true, &ups.ValidationError{Msg: "the UPS server, port or user changed: enter the password again"}
		}
	}
	prevCfg, _ := s.DB.GetSetting(ctx, upsConfigKey)
	prevSec, _ := s.DB.GetSetting(ctx, upsSecretsKey)
	if err := s.DB.SetSetting(ctx, upsConfigKey+".prev", prevCfg); err != nil {
		return norm, sec, moved, err
	}
	if err := s.DB.SetSetting(ctx, upsSecretsKey+".prev", prevSec); err != nil {
		return norm, sec, moved, err
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
		return norm, sec, moved, err
	}
	sealed := ""
	if sec != (ups.Secrets{}) {
		k, err := s.key(ctx)
		if err != nil {
			return norm, sec, moved, err
		}
		plain, _ := json.Marshal(sec)
		box, err := secretbox.Seal(k, plain, []byte("settings:"+upsSecretsKey))
		if err != nil {
			return norm, sec, moved, err
		}
		sealed = base64.StdEncoding.EncodeToString(box)
	}
	if err := s.DB.SetSetting(ctx, upsSecretsKey, sealed); err != nil {
		return norm, sec, moved, err
	}
	s.reset()
	return norm, sec, moved, nil
}

func (s *UPSService) reset() {
	s.mu.Lock()
	s.last, s.lastErr, s.baseline, s.failures, s.commAlert = nil, "", false, 0, false
	s.mu.Unlock()
}

// RestorePrevious puts back the setup from before the last Save (its
// apply failed).
func (s *UPSService) RestorePrevious(ctx context.Context) error {
	cfg, err := s.DB.GetSetting(ctx, upsConfigKey+".prev")
	if err != nil {
		return nil // nothing kept
	}
	sec, _ := s.DB.GetSetting(ctx, upsSecretsKey+".prev")
	if cfg == "" {
		cfg = `{"mode":"off"}`
	}
	if err := s.DB.SetSetting(ctx, upsConfigKey, cfg); err != nil {
		return err
	}
	if err := s.DB.SetSetting(ctx, upsSecretsKey, sec); err != nil {
		return err
	}
	s.reset()
	return s.ForgetPrevious(ctx)
}

// ForgetPrevious drops the kept setup (the new one is applied).
func (s *UPSService) ForgetPrevious(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM settings WHERE key IN (?, ?)`, upsConfigKey+".prev", upsSecretsKey+".prev")
	return err
}

// View returns the setup (without passwords) and the last reading.
func (s *UPSService) View(ctx context.Context) (*UPSView, error) {
	c, sec, err := s.Config(ctx)
	v := &UPSView{Config: c, SecretsSet: map[string]bool{"clientPassword": sec.ClientPassword != "", "remotePassword": sec.RemotePassword != ""}, Addresses: serverAddrs()}
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
		if c.Mode == ups.ModeNetClient && c.RemoteTLS {
			tc := &tls.Config{ServerName: c.RemoteHost, MinVersion: tls.VersionTLS12, InsecureSkipVerify: !c.RemoteVerify} //nolint:gosec // encryption without verification is the administrator's choice
			q = func(ctx context.Context, addr, name string) (*ups.Status, error) {
				return ups.QueryTLS(ctx, addr, name, tc)
			}
		}
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
