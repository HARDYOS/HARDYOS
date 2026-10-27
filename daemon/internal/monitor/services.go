package monitor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/netbird"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// intentWindow: a stop within this long of an administrator's stop,
// restart, update or removal (audit log or job) is expected.
const intentWindow = 10 * time.Minute

// intended reports whether someone recently did one of the actions to the
// target (audit entries whose target starts with the id, or jobs of the
// kinds whose params name it).
func (s *Service) intended(ctx context.Context, id string, actions, kinds []string, now time.Time) bool {
	since := store.FormatTime(now.Add(-intentWindow))
	for _, a := range actions {
		var n int
		_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE action = ? AND at >= ? AND (target = ? OR target LIKE ? ESCAPE '\')`,
			a, since, id, escapeLike(id)+" %").Scan(&n)
		if n > 0 {
			return true
		}
	}
	for _, k := range kinds {
		var n int
		_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE kind = ? AND created_at >= ? AND json_extract(params, '$.id') = ?`,
			k, since, id).Scan(&n)
		if n > 0 {
			return true
		}
	}
	return false
}

// ---- apps -------------------------------------------------------------------

// appsOverview is the part of apps.status (internal/apps.Overview) the
// monitor reads.
type appsOverview struct {
	Available     bool   `json:"available"`
	Configured    bool   `json:"configured"`
	EngineRunning bool   `json:"engineRunning"`
	Problem       string `json:"problem"`
	Apps          []struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		State      string `json:"state"`
		Blocked    string `json:"blocked"`
		Containers []struct {
			Service string `json:"service"`
			State   string `json:"state"`
			Health  string `json:"health"`
			Status  string `json:"status"`
		} `json:"containers"`
	} `json:"apps"`
}

var appIntentActions = []string{"apps.stop", "apps.restart", "apps.remove", "apps.update", "apps.reconfigure", "apps.rollback", "apps.install"}
var appIntentKinds = []string{"apps.remove", "apps.update", "apps.reconfigure", "apps.rollback", "apps.install"}

func (s *Service) checkApps(ctx context.Context, now time.Time) {
	var o appsOverview
	if err := s.Priv.Call(ctx, priv.OpAppsStatus, nil, &o); err != nil {
		return
	}
	if !o.Available || !o.Configured {
		s.conds.Drop(ctx, "app.", nil)
		return
	}
	keep := map[string]bool{"app.engine": true}
	if !o.EngineRunning {
		s.conds.Set(ctx, Condition{Key: "app.engine", Kind: "app.engine", Severity: notify.SeverityCritical, Link: "apps",
			Title: "The app engine (Docker) isn't running", Body: strings.TrimSpace("None of the apps can run. " + o.Problem)})
		return
	}
	s.conds.Clear(ctx, "app.engine", "The app engine (Docker) is running again", "")
	s.mu.Lock()
	base, prev := s.appBase, s.apps
	s.apps, s.appBase = map[string]string{}, true
	s.mu.Unlock()
	for _, a := range o.Apps {
		name := a.Name
		if name == "" {
			name = a.ID
		}
		link := "apps/" + a.ID
		s.mu.Lock()
		s.apps[a.ID], s.appNames[a.ID] = a.State, name
		s.mu.Unlock()
		dk, rk, hk := "app.down:"+a.ID, "app.restart:"+a.ID, "app.health:"+a.ID
		keep[dk], keep[rk], keep[hk] = true, true, true
		var restarting, unhealthy, exited []string
		for _, c := range a.Containers {
			switch {
			case c.State == "restarting" || strings.HasPrefix(c.Status, "Restarting"):
				restarting = append(restarting, c.Service+": "+c.Status)
			case c.State == "exited" || c.State == "dead":
				exited = append(exited, c.Service+": "+c.Status)
			}
			if c.Health == "unhealthy" {
				unhealthy = append(unhealthy, c.Service)
			}
		}
		// A restart loop: seen twice in a row (30 s apart).
		s.mu.Lock()
		if len(restarting) > 0 {
			s.restarts[a.ID]++
		} else {
			delete(s.restarts, a.ID)
		}
		loops := s.restarts[a.ID]
		s.mu.Unlock()
		if loops >= 2 {
			s.conds.Set(ctx, Condition{Key: rk, Kind: "app.restart", Severity: notify.SeverityWarning, Link: link,
				Title: name + " keeps restarting", Body: strings.Join(restarting, "\n") + "\nIts log in the App Store says why."})
		} else if len(restarting) == 0 {
			s.conds.Clear(ctx, rk, name+" stopped restarting", "")
		}
		if len(unhealthy) > 0 {
			s.conds.Set(ctx, Condition{Key: hk, Kind: "app.health", Severity: notify.SeverityWarning, Link: link,
				Title: name + " is unhealthy", Body: "Its health check fails: " + strings.Join(unhealthy, ", ") + "."})
		} else {
			s.conds.Clear(ctx, hk, name+" is healthy again", "")
		}
		switch a.State {
		case "running", "starting", "unhealthy":
			s.conds.Clear(ctx, dk, name+" is running again", "")
		case "stopped", "partial":
			was := prev[a.ID]
			if base && (was == "running" || was == "unhealthy") && !s.intended(ctx, a.ID, appIntentActions, appIntentKinds, now) {
				sev, title := notify.SeverityWarning, name+" stopped unexpectedly"
				if a.State == "partial" {
					title = "Part of " + name + " stopped"
				}
				s.conds.Set(ctx, Condition{Key: dk, Kind: "app.crashed", Severity: sev, Link: link, Title: title,
					Body: strings.Join(exited, "\n") + "\nStart it again from the App Store; its log says why it stopped."})
			}
		}
	}
	s.conds.Drop(ctx, "app.", keep)
}

// ---- VMs ----------------------------------------------------------------------

type vmsOverview struct {
	VMs []struct {
		ID           string  `json:"id"`
		Name         string  `json:"name"`
		State        string  `json:"state"`
		CPUPercent   float64 `json:"cpuPercent"`
		MemoryUsedMB int     `json:"memoryUsedMB"`
	} `json:"vms"`
}

var vmIntentKinds = []string{"vms.stop", "vms.force-stop", "vms.restart", "vms.reset", "vms.delete", "vms.update", "vms.rollback", "vms.snapshot"}

func (s *Service) checkVMs(ctx context.Context, now time.Time) {
	var o vmsOverview
	if err := s.Priv.Call(ctx, priv.OpVMsList, nil, &o); err != nil {
		return
	}
	s.mu.Lock()
	base, prev := s.vmBase, s.vms
	s.vms, s.vmBase = map[string]string{}, true
	s.mu.Unlock()
	keep := map[string]bool{}
	var pts []Point
	for _, v := range o.VMs {
		name := v.Name
		if name == "" {
			name = v.ID
		}
		s.mu.Lock()
		s.vms[v.ID] = v.State
		s.mu.Unlock()
		k := "vm.down:" + v.ID
		keep[k] = true
		link := "vms/" + v.ID
		switch v.State {
		case "crashed":
			s.conds.Set(ctx, Condition{Key: k, Kind: "vm.crashed", Severity: notify.SeverityCritical, Link: link,
				Title: "VM " + name + " crashed", Body: "Its log in Virtual Machines may say why. Start it again from there."})
		case "running":
			s.conds.Clear(ctx, k, "VM "+name+" is running again", "")
			pts = append(pts,
				Point{Series: "vm.cpu:" + v.ID, Label: name, Unit: UnitPercent, Value: v.CPUPercent},
				Point{Series: "vm.mem:" + v.ID, Label: name, Unit: UnitBytes, Value: float64(v.MemoryUsedMB) * 1024 * 1024})
		case "stopped":
			if base && prev[v.ID] == "running" && !s.intended(ctx, v.ID, nil, vmIntentKinds, now) {
				s.conds.Set(ctx, Condition{Key: k, Kind: "vm.stopped", Severity: notify.SeverityWarning, Link: link,
					Title: "VM " + name + " stopped unexpectedly", Body: "It wasn't stopped from HardyOS. If someone shut it down from inside, start it again or ignore this."})
			}
		}
	}
	s.conds.Drop(ctx, "vm.", keep)
	s.record(ctx, now, pts)
}

// ---- hardyd-priv --------------------------------------------------------------

const privStartedKey = "monitor.priv_started"

// bootTime is when the system started (from /proc/uptime).
func (s *Service) bootTime(now time.Time) time.Time {
	b, err := fs.ReadFile(s.Root, "proc/uptime")
	if err != nil {
		return time.Time{}
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return time.Time{}
	}
	secs, _ := strconv.ParseFloat(f[0], 64)
	return now.Add(-time.Duration(secs * float64(time.Second)))
}

func (s *Service) checkPriv(ctx context.Context, now time.Time) {
	var p priv.PingResult
	if err := s.Priv.Call(ctx, priv.OpPing, nil, &p); err != nil {
		s.mu.Lock()
		s.privErr++
		n := s.privErr
		s.mu.Unlock()
		if n >= 2 {
			s.conds.Set(ctx, Condition{Key: "system.priv", Kind: "system.priv", Severity: notify.SeverityCritical, Link: "logs",
				Title: "The root helper (hardyd-priv) isn't answering", Body: "Storage, apps, VMs and settings can't change until it's back: " + err.Error()})
		}
		return
	}
	s.mu.Lock()
	s.privErr = 0
	s.mu.Unlock()
	s.conds.Clear(ctx, "system.priv", "The root helper (hardyd-priv) is answering again", "")
	if p.Started.IsZero() {
		return
	}
	prev, _ := s.DB.GetSetting(ctx, privStartedKey)
	cur := store.FormatTime(p.Started)
	if prev == cur {
		return
	}
	_ = s.DB.SetSetting(ctx, privStartedKey, cur)
	// A start shortly after boot is the system starting, not a restart.
	if prev != "" {
		if boot := s.bootTime(now); boot.IsZero() || p.Started.Sub(boot) > 3*time.Minute {
			s.Notify.Notify(ctx, notify.Event{Kind: "system.priv", Severity: notify.SeverityWarning, Link: "logs",
				Title: "The root helper (hardyd-priv) restarted", Body: "It started again at " + p.Started.Local().Format("15:04:05") +
					". If it keeps happening, Log Center shows why (journalctl -u hardyd-priv)."})
		}
	}
}

// ---- NetBird --------------------------------------------------------------------

func (s *Service) checkNetBird(ctx context.Context, now time.Time) {
	var st netbird.ClientStatus
	if err := s.Priv.Call(ctx, priv.OpNetBirdStatus, nil, &st); err != nil {
		return
	}
	if !st.Joined {
		s.conds.Clear(ctx, "remote.netbird", "", "")
		return
	}
	if st.Connected {
		s.mu.Lock()
		s.nbBad = 0
		s.mu.Unlock()
		s.conds.Clear(ctx, "remote.netbird", "NetBird is connected again", "")
		return
	}
	s.mu.Lock()
	s.nbBad++
	n := s.nbBad
	s.mu.Unlock()
	if n >= 3 { // three minutes
		body := "Remote access and published apps don't work until it reconnects."
		if st.Problem != "" {
			body = st.Problem + " " + body
		}
		s.conds.Set(ctx, Condition{Key: "remote.netbird", Kind: "remote.netbird", Severity: notify.SeverityWarning, Link: "control/remote",
			Title: "NetBird is disconnected (" + strings.ReplaceAll(st.State, "_", " ") + ")", Body: body})
	}
}

// ---- domain controller replication -------------------------------------------

func (s *Service) checkReplication(ctx context.Context, now time.Time) {
	var r domain.Replication
	if err := s.Priv.Call(ctx, priv.OpDomainReplication, nil, &r); err != nil {
		var pe *priv.Error
		if errors.As(err, &pe) && pe.Code == priv.CodeUnknownOp {
			return
		}
		s.log().Debug("replication check", "err", err)
		return
	}
	if !r.Checked || len(r.Failing) == 0 {
		s.conds.Clear(ctx, "domain.replication", "Domain controllers are replicating again", "")
		return
	}
	s.conds.Set(ctx, Condition{Key: "domain.replication", Kind: "domain.replication", Severity: notify.SeverityWarning, Link: "control/domain",
		Title: "Domain controller replication is failing", Body: strings.Join(r.Failing, "\n") +
			"\nChanges made on one domain controller don't reach the other. Check that both are running and can reach each other."})
}

// ---- publishing ------------------------------------------------------------------

func (s *Service) checkPublish(ctx context.Context, now time.Time) {
	if s.PublishErrors == nil {
		return
	}
	errs, err := s.PublishErrors(ctx)
	if err != nil {
		return
	}
	keep := map[string]bool{}
	keys := make([]string, 0, len(errs))
	for k := range errs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ck := "remote.publish:" + k
		keep[ck] = true
		s.conds.Set(ctx, Condition{Key: ck, Kind: "remote.publish", Severity: notify.SeverityWarning, Link: "control/remote",
			Title: "Publishing " + strings.TrimPrefix(k, "app:") + " failed", Body: errs[k] + "\nRemote Access shows each published service; its certificate comes from NetBird's proxy."})
	}
	for _, k := range s.conds.Keys(ctx, "remote.publish:") {
		if !keep[k] {
			s.conds.Clear(ctx, k, "Publishing "+strings.TrimPrefix(strings.TrimPrefix(k, "remote.publish:"), "app:")+" works again", "")
		}
	}
}

// ---- temperatures (hwmon) --------------------------------------------------------

func (s *Service) checkSensors(ctx context.Context, now time.Time) {
	set := s.Settings(ctx)
	keep := map[string]bool{}
	for _, sn := range ReadSensors(s.Root) {
		if sn.Chip == "nvme" || sn.Chip == "drivetemp" {
			continue // disks are judged from SMART with their own limits
		}
		warn, crit := float64(set.SensorWarnC), float64(set.SensorCritC)
		if sn.MaxC != nil && *sn.MaxC > 40 {
			warn = *sn.MaxC
		}
		if sn.CritC != nil && *sn.CritC > warn {
			crit = *sn.CritC
		}
		k := "system.temperature:" + sn.Key
		keep[k] = true
		s.mu.Lock()
		if sn.TempC >= warn {
			s.hot[k]++
		} else {
			s.hot[k] = 0
		}
		sustained := s.hot[k] >= 2 // two checks a minute apart
		s.mu.Unlock()
		switch {
		case sustained && sn.TempC >= crit:
			s.conds.Set(ctx, Condition{Key: k, Kind: "system.temperature", Severity: notify.SeverityCritical, Link: "monitor",
				Title: fmt.Sprintf("%s is at %.0f °C", sn.Label, sn.TempC), Body: fmt.Sprintf("Its critical limit is %.0f °C. Check the fans and airflow now.", crit)})
		case sustained:
			s.conds.Set(ctx, Condition{Key: k, Kind: "system.temperature", Severity: notify.SeverityWarning, Link: "monitor",
				Title: fmt.Sprintf("%s is hot at %.0f °C", sn.Label, sn.TempC), Body: fmt.Sprintf("Its limit is %.0f °C.", warn)})
		case sn.TempC <= warn-3:
			s.conds.Clear(ctx, k, fmt.Sprintf("%s is back to %.0f °C", sn.Label, sn.TempC), "")
		}
	}
	s.conds.Drop(ctx, "system.temperature:", keep)
}
