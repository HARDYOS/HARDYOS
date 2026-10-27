package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/netbird"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// fakePriv answers root-helper calls from handler funcs and records them.
type fakePriv struct {
	mu       sync.Mutex
	handlers map[string]func(args json.RawMessage) (any, error)
	calls    []string
}

func (f *fakePriv) on(op string, fn func(args json.RawMessage) (any, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.handlers == nil {
		f.handlers = map[string]func(json.RawMessage) (any, error){}
	}
	f.handlers[op] = fn
}

func (f *fakePriv) Call(ctx context.Context, op string, args any, out any) error {
	raw, _ := json.Marshal(args)
	f.mu.Lock()
	f.calls = append(f.calls, op+" "+string(raw))
	fn := f.handlers[op]
	f.mu.Unlock()
	if fn == nil {
		return &priv.Error{Code: priv.CodeUnknownOp, Message: op}
	}
	res, err := fn(raw)
	if err != nil {
		return err
	}
	if out != nil {
		b, _ := json.Marshal(res)
		return json.Unmarshal(b, out)
	}
	return nil
}

func (f *fakePriv) called(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

type recorder struct {
	mu  sync.Mutex
	got []notify.Event
}

func (r *recorder) Notify(_ context.Context, e notify.Event) {
	r.mu.Lock()
	r.got = append(r.got, e)
	r.mu.Unlock()
}

func (r *recorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, e := range r.got {
		out = append(out, e.Severity+":"+e.Title)
	}
	r.got = nil
	return out
}

func newMonitor(t *testing.T) (*Service, *fakePriv, *recorder, *time.Time) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h, err := OpenHistory(context.Background(), filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	now := time.Date(2026, 10, 27, 3, 0, 0, 0, time.Local)
	fp, rec := &fakePriv{}, &recorder{}
	s := &Service{DB: db, Priv: fp, Notify: rec, History: h, Root: fstest.MapFS{}, Now: func() time.Time { return now }}
	s.init()
	return s, fp, rec, &now
}

func status(t *testing.T, name string) *zfs.Status {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	st, err := zfs.ParseStatus(b)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestPoolChecks(t *testing.T) {
	s, fp, rec, now := newMonitor(t)
	ctx := context.Background()
	pool := zfs.Pool{Name: "tank", Health: "DEGRADED", CapacityPct: 83, SizeBytes: 12e12, AllocBytes: 10e12}
	st := status(t, "zpool-degraded.txt")
	fp.on(priv.OpPools, func(json.RawMessage) (any, error) { return []zfs.Pool{pool}, nil })
	fp.on(priv.OpPoolStatus, func(json.RawMessage) (any, error) { return st, nil })

	s.checkPools(ctx, *now)
	got := rec.take()
	want := []string{"warning:Pool tank is degraded", "warning:Pool tank is 83% full", "warning:Disk errors in pool tank",
		"critical:Pool tank has damaged files", "critical:Scrub of tank found 3 errors"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("events\n got %v\nwant %v", got, want)
	}
	conds, _ := s.Conditions(ctx)
	var body string
	for _, c := range conds {
		if c.Key == "pool.errors:tank" {
			body = c.Body
		}
	}
	if !strings.Contains(body, "ata-ST4000VN008-2DR166_ZDH1BBBB: 12 read, 0 write, 41 checksum errors") ||
		!strings.Contains(body, "nvme-INTEL_SSDPE21D280GA_PHM1: 1 read") || strings.Count(body, "ZDH1BBBB") != 1 {
		t.Errorf("error body %q", body)
	}
	if conds[0].Severity != notify.SeverityCritical {
		t.Errorf("critical conditions should sort first: %+v", conds[0])
	}

	// The same again: nothing new. Then worse: capacity critical.
	s.checkPools(ctx, *now)
	if got := rec.take(); len(got) != 0 {
		t.Errorf("repeat raised %v", got)
	}
	pool.CapacityPct = 91
	s.checkPools(ctx, *now)
	if got := rec.take(); len(got) != 1 || got[0] != "critical:Pool tank is 91% full" {
		t.Errorf("escalation %v", got)
	}
	// Fixed: everything clears once.
	pool = zfs.Pool{Name: "tank", Health: "ONLINE", CapacityPct: 70}
	st = status(t, "zpool-online.txt")
	s.checkPools(ctx, *now)
	got = rec.take()
	if len(got) != 5 {
		t.Errorf("resolved %v", got)
	}
	for _, g := range got {
		if !strings.HasPrefix(g, "info:") {
			t.Errorf("resolution not info: %s", g)
		}
	}
	if conds, _ := s.Conditions(ctx); len(conds) != 0 {
		t.Errorf("left over %+v", conds)
	}
	// History has the pool's use.
	_ = s.History.Flush(ctx)
	r, err := s.History.Query(ctx, []string{"pool.pct:tank"}, now.Add(-time.Minute), now.Add(time.Minute), *now, 100)
	if err != nil || len(r.Series) != 1 {
		t.Fatalf("history %v %v", r, err)
	}
}

func TestCapacityHysteresis(t *testing.T) {
	s, fp, rec, now := newMonitor(t)
	pct := 81
	fp.on(priv.OpPools, func(json.RawMessage) (any, error) {
		return []zfs.Pool{{Name: "tank", Health: "ONLINE", CapacityPct: pct}}, nil
	})
	fp.on(priv.OpPoolStatus, func(json.RawMessage) (any, error) { return status(t, "zpool-online.txt"), nil })
	for _, p := range []int{81, 79, 80, 79, 77} {
		pct = p
		s.checkPools(context.Background(), *now)
	}
	if got := rec.take(); strings.Join(got, "|") != "warning:Pool tank is 81% full|info:Pool tank is back to 77% full" {
		t.Errorf("flapping around 80%%: %v", got)
	}
}

func smartSample(t *testing.T, name string) *hw.SMART {
	b, err := os.ReadFile(filepath.Join("..", "hw", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	sm, err := hw.ParseSMART(b)
	if err != nil {
		t.Fatal(err)
	}
	return sm
}

func diskSet() []hw.Disk {
	return []hw.Disk{
		{Name: "sda", ByID: "/dev/disk/by-id/ata-A", Model: "WDC WD120EFBX", Serial: "5QG0AAAA", Kind: hw.KindHDD, Pool: "tank"},
		{Name: "sdb", ByID: "/dev/disk/by-id/ata-B", Model: "ST4000VN008", Serial: "ZDH1BBBB", Kind: hw.KindHDD, Pool: "tank"},
		{Name: "nvme0n1", ByID: "/dev/disk/by-id/nvme-C", Model: "WD Red SN700", Kind: hw.KindNVMe},
		{Name: "sdz", ByID: "/dev/disk/by-id/usb-Stick", Removable: true},
	}
}

func TestSMARTChecks(t *testing.T) {
	s, fp, rec, now := newMonitor(t)
	ctx := context.Background()
	samples := map[string]*hw.SMART{
		"/dev/disk/by-id/ata-A":  smartSample(t, "smart-sata-hdd.json"),
		"/dev/disk/by-id/ata-B":  smartSample(t, "smart-sata-failing.json"),
		"/dev/disk/by-id/nvme-C": smartSample(t, "smart-nvme.json"),
	}
	fp.on(priv.OpHWDisks, func(json.RawMessage) (any, error) { return diskSet(), nil })
	fp.on(priv.OpHWSmart, func(raw json.RawMessage) (any, error) {
		var a priv.DeviceArgs
		_ = json.Unmarshal(raw, &a)
		if !a.NoWake {
			t.Errorf("periodic SMART read may wake disks: %s", raw)
		}
		return samples[a.Device], nil
	})
	s.checkSMART(ctx, *now)
	got := rec.take()
	if len(got) != 1 || !strings.HasPrefix(got[0], "critical:Disk sdb (ST4000VN008) is failing") {
		t.Fatalf("events %v", got)
	}
	if len(fp.called(priv.OpHWSmart+` {"device":"/dev/disk/by-id/usb-Stick"`)) != 0 {
		t.Error("read SMART of a removable disk")
	}
	// Hot, and getting worse.
	hot := *samples["/dev/disk/by-id/ata-A"]
	temp := 53
	hot.TemperatureC = &temp
	samples["/dev/disk/by-id/ata-A"] = &hot
	worse := *samples["/dev/disk/by-id/ata-B"]
	more := int64(1700)
	worse.Reallocated = &more
	samples["/dev/disk/by-id/ata-B"] = &worse
	s.checkSMART(ctx, *now)
	got = rec.take()
	if len(got) != 2 || !strings.Contains(strings.Join(got, "|"), "warning:Disk sdb (ST4000VN008) is getting worse") ||
		!strings.Contains(strings.Join(got, "|"), "warning:Disk sda (WDC WD120EFBX) is running warm at 53 °C") {
		t.Errorf("events %v", got)
	}
	// Asleep: nothing changes, the condition stays.
	samples["/dev/disk/by-id/ata-A"] = &hw.SMART{Standby: true, Health: hw.HealthUnknown}
	s.checkSMART(ctx, *now)
	if got := rec.take(); len(got) != 0 {
		t.Errorf("standby raised %v", got)
	}
	if !s.conds.Has(ctx, "disk.temperature:/dev/disk/by-id/ata-A") {
		t.Error("standby cleared the temperature condition")
	}
	// The disk table the old API reads is kept up to date.
	var n int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM disk_health`).Scan(&n)
	if n != 3 {
		t.Errorf("disk_health rows %d", n)
	}
	// A disk that went away drops its conditions quietly.
	fp.on(priv.OpHWDisks, func(json.RawMessage) (any, error) { return diskSet()[2:], nil })
	s.checkSMART(ctx, *now)
	if got := rec.take(); len(got) != 0 {
		t.Errorf("removal raised %v", got)
	}
	if conds, _ := s.Conditions(ctx); len(conds) != 0 {
		t.Errorf("conditions left %+v", conds)
	}
}

func TestSelfTestSchedule(t *testing.T) {
	s, fp, rec, now := newMonitor(t)
	ctx := context.Background()
	disks := diskSet()[:3]
	s.disks = disks
	for _, d := range disks {
		s.smart[d.ByID] = smartSample(t, "smart-sata-hdd.json")
	}
	var started []string
	fp.on(priv.OpHWSmartTest, func(raw json.RawMessage) (any, error) {
		var a priv.SmartTestArgs
		_ = json.Unmarshal(raw, &a)
		started = append(started, a.Test+" "+a.Device)
		return map[string]string{}, nil
	})
	*now = time.Date(2026, 10, 27, 12, 0, 0, 0, time.Local) // outside the window: only seeding
	s.scheduleSelfTests(ctx, *now)
	var dues []time.Time
	for _, d := range disks {
		ts, ok := s.testState(ctx, d.ByID)
		if !ok {
			t.Fatalf("no schedule for %s", d.ByID)
		}
		dues = append(dues, ts.NextLongAt)
	}
	// Staggered: a quarter of a month apart.
	if gap := dues[1].Sub(dues[0]); gap < 7*24*time.Hour || gap > 8*24*time.Hour {
		t.Errorf("long tests %v apart", gap)
	}
	if len(started) != 0 {
		t.Fatalf("started outside the window: %v", started)
	}
	// Ten days later at 2 am: the first disk's short and long are due; long wins, one start per tick.
	*now = time.Date(2026, 11, 6, 2, 0, 0, 0, time.Local)
	s.scheduleSelfTests(ctx, *now)
	if len(started) != 1 || started[0] != "long /dev/disk/by-id/ata-A" {
		t.Fatalf("started %v", started)
	}
	// Another tick: no second long test while one runs; a short one instead.
	*now = now.Add(time.Minute)
	s.scheduleSelfTests(ctx, *now)
	if len(started) != 2 || !strings.HasPrefix(started[1], "short ") {
		t.Fatalf("started %v", started)
	}
	// A pool that scrubs gets no tests.
	s.scrubs["tank"] = true
	*now = now.Add(time.Minute)
	before := len(started)
	s.scheduleSelfTests(ctx, *now)
	for _, x := range started[before:] {
		if strings.Contains(x, "ata-") {
			t.Errorf("tested a disk of a scrubbing pool: %s", x)
		}
	}
	// The long test finishes with a read failure: a critical alert.
	failing := smartSample(t, "smart-sata-failing.json")
	fp.on(priv.OpHWDisks, func(json.RawMessage) (any, error) { return disks, nil })
	fp.on(priv.OpHWSmart, func(raw json.RawMessage) (any, error) {
		if strings.Contains(string(raw), "ata-A") {
			return failing, nil
		}
		return smartSample(t, "smart-sata-hdd.json"), nil
	})
	*now = now.Add(3 * time.Hour)
	s.checkSMART(ctx, *now)
	got := strings.Join(rec.take(), "|")
	if !strings.Contains(got, "critical:Long self-test failed on disk sda (WDC WD120EFBX)") {
		t.Errorf("events %s", got)
	}
	ts, _ := s.testState(ctx, "/dev/disk/by-id/ata-A")
	if ts.Running != "" || ts.LastPassed == nil || *ts.LastPassed || ts.LastType != "long" || ts.LastResult != "Completed: read failure" {
		t.Errorf("state %+v", ts)
	}
	// Manual tests can't overlap.
	_, _ = s.DB.Exec(`UPDATE smart_tests SET running = 'short' WHERE by_id = ?`, "/dev/disk/by-id/nvme-C")
	if err := s.StartTest(ctx, "/dev/disk/by-id/nvme-C", "long", true); err != ErrTestRunning {
		t.Errorf("overlapping test: %v", err)
	}
}

func TestScrubAllowed(t *testing.T) {
	s, _, _, now := newMonitor(t)
	ctx := context.Background()
	s.disks = diskSet()
	if s.ScrubAllowed(ctx, "tank", time.Date(2026, 10, 27, 14, 0, 0, 0, time.Local)) {
		t.Error("scrub allowed outside the window")
	}
	if !s.ScrubAllowed(ctx, "tank", *now) {
		t.Error("scrub refused in the window")
	}
	s.scrubs["media"] = true
	if s.ScrubAllowed(ctx, "tank", *now) {
		t.Error("two pools scrubbing at once")
	}
	s.scrubs["media"] = false
	_, _ = s.DB.Exec(`INSERT INTO smart_tests (by_id, next_short_at, next_long_at, running) VALUES ('/dev/disk/by-id/ata-B', 'x', 'x', 'long')`)
	if s.ScrubAllowed(ctx, "tank", *now) {
		t.Error("scrub during a long self-test of one of the pool's disks")
	}
}

func TestAppChecks(t *testing.T) {
	s, fp, rec, now := newMonitor(t)
	ctx := context.Background()
	state, cstate, cstatus := "running", "running", "Up 3 hours"
	fp.on(priv.OpAppsStatus, func(json.RawMessage) (any, error) {
		return map[string]any{"available": true, "configured": true, "engineRunning": true, "apps": []any{
			map[string]any{"id": "immich", "name": "Immich", "state": state, "containers": []any{
				map[string]any{"service": "server", "state": cstate, "status": cstatus}}}}}, nil
	})
	s.checkApps(ctx, *now) // baseline
	state, cstate, cstatus = "stopped", "exited", "Exited (137) 5 seconds ago"
	s.checkApps(ctx, *now)
	if got := rec.take(); len(got) != 1 || got[0] != "warning:Immich stopped unexpectedly" {
		t.Fatalf("crash: %v", got)
	}
	state, cstate, cstatus = "running", "running", "Up 1 second"
	s.checkApps(ctx, *now)
	if got := rec.take(); len(got) != 1 || got[0] != "info:Immich is running again" {
		t.Fatalf("recovery: %v", got)
	}
	// Stopped by an administrator: expected.
	_, _ = s.DB.Exec(`INSERT INTO audit_log (at, actor, action, target, outcome, detail, ip) VALUES (?, 'cade', 'apps.stop', 'immich', 'success', '', '')`, store.FormatTime(*now))
	state, cstate, cstatus = "stopped", "exited", "Exited (0) 1 second ago"
	s.checkApps(ctx, *now)
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("intended stop raised %v", got)
	}
	// A restart loop, seen twice.
	state, cstate, cstatus = "restarting", "restarting", "Restarting (1) 4 seconds ago"
	s.checkApps(ctx, *now)
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("one sighting raised %v", got)
	}
	s.checkApps(ctx, *now)
	if got := rec.take(); len(got) != 1 || got[0] != "warning:Immich keeps restarting" {
		t.Fatalf("loop: %v", got)
	}
}

func TestVMChecks(t *testing.T) {
	s, fp, rec, now := newMonitor(t)
	ctx := context.Background()
	st := "running"
	fp.on(priv.OpVMsList, func(json.RawMessage) (any, error) {
		return map[string]any{"vms": []any{map[string]any{"id": "haos", "name": "Home Assistant", "state": st, "cpuPercent": 12.5, "memoryUsedMB": 2048}}}, nil
	})
	s.checkVMs(ctx, *now)
	st = "stopped"
	s.checkVMs(ctx, *now)
	if got := rec.take(); len(got) != 1 || got[0] != "warning:VM Home Assistant stopped unexpectedly" {
		t.Fatalf("%v", got)
	}
	st = "crashed"
	s.checkVMs(ctx, *now)
	if got := rec.take(); len(got) != 1 || got[0] != "critical:VM Home Assistant crashed" {
		t.Fatalf("%v", got)
	}
	st = "running"
	s.checkVMs(ctx, *now)
	rec.take()
	// Stopped through HardyOS: expected.
	_, _ = s.DB.Exec(`INSERT INTO jobs (id, kind, title, state, params, created_at) VALUES ('j1', 'vms.stop', 'Stop', 'succeeded', '{"id":"haos"}', ?)`, store.FormatTime(*now))
	st = "stopped"
	s.checkVMs(ctx, *now)
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("intended stop raised %v", got)
	}
}

func TestServiceChecks(t *testing.T) {
	s, fp, rec, now := newMonitor(t)
	ctx := context.Background()
	s.Root = fstest.MapFS{"proc/uptime": {Data: []byte("86400.00 1000.00\n")}}
	started := now.Add(-time.Hour)
	fp.on(priv.OpPing, func(json.RawMessage) (any, error) { return priv.PingResult{Started: started}, nil })
	s.checkPriv(ctx, *now)
	started = now.Add(-time.Minute)
	s.checkPriv(ctx, *now)
	if got := rec.take(); len(got) != 1 || got[0] != "warning:The root helper (hardyd-priv) restarted" {
		t.Fatalf("priv restart %v", got)
	}
	fp.on(priv.OpPing, func(json.RawMessage) (any, error) { return nil, fmt.Errorf("connection refused") })
	s.checkPriv(ctx, *now)
	s.checkPriv(ctx, *now)
	if got := rec.take(); len(got) != 1 || !strings.HasPrefix(got[0], "critical:The root helper") {
		t.Fatalf("priv down %v", got)
	}

	nb := netbird.ClientStatus{Joined: true, State: "connecting"}
	fp.on(priv.OpNetBirdStatus, func(json.RawMessage) (any, error) { return nb, nil })
	for range 3 {
		s.checkNetBird(ctx, *now)
	}
	nb.Connected, nb.State = true, "connected"
	s.checkNetBird(ctx, *now)
	if got := rec.take(); strings.Join(got, "|") != "warning:NetBird is disconnected (connecting)|info:NetBird is connected again" {
		t.Fatalf("netbird %v", got)
	}

	s.checkReplication(ctx, *now) // no samba op: nothing
	fp.on(priv.OpDomainReplication, func(json.RawMessage) (any, error) {
		return domain.Replication{Checked: true, Failing: []string{"DC2: 7 failed attempts"}}, nil
	})
	s.checkReplication(ctx, *now)
	if got := rec.take(); len(got) != 1 || got[0] != "warning:Domain controller replication is failing" {
		t.Fatalf("replication %v", got)
	}

	errs := map[string]string{"app:immich": "certificate not issued yet: DNS doesn't point to the proxy"}
	s.PublishErrors = func(context.Context) (map[string]string, error) { return errs, nil }
	s.checkPublish(ctx, *now)
	errs = map[string]string{}
	s.checkPublish(ctx, *now)
	if got := rec.take(); strings.Join(got, "|") != "warning:Publishing immich failed|info:Publishing immich works again" {
		t.Fatalf("publish %v", got)
	}
}

func hwmonFS() fstest.MapFS {
	return fstest.MapFS{
		"sys/class/hwmon/hwmon0/name":        {Data: []byte("coretemp\n")},
		"sys/class/hwmon/hwmon0/temp1_input": {Data: []byte("91000\n")},
		"sys/class/hwmon/hwmon0/temp1_label": {Data: []byte("Package id 0\n")},
		"sys/class/hwmon/hwmon0/temp1_max":   {Data: []byte("90000\n")},
		"sys/class/hwmon/hwmon0/temp1_crit":  {Data: []byte("100000\n")},
		"sys/class/hwmon/hwmon1/name":        {Data: []byte("nvme\n")},
		"sys/class/hwmon/hwmon1/temp1_input": {Data: []byte("99000\n")},
		"sys/class/hwmon/hwmon2/name":        {Data: []byte("acpitz\n")},
		"sys/class/hwmon/hwmon2/temp1_input": {Data: []byte("27800\n")},
	}
}

func TestSensors(t *testing.T) {
	s, _, rec, now := newMonitor(t)
	s.Root = hwmonFS()
	sensors := ReadSensors(s.Root)
	if len(sensors) != 3 || sensors[0].Label != "coretemp Package id 0" || *sensors[0].MaxC != 90 || *sensors[0].CritC != 100 {
		t.Fatalf("sensors %+v", sensors)
	}
	s.checkSensors(context.Background(), *now)
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("one hot reading raised %v", got)
	}
	s.checkSensors(context.Background(), *now)
	if got := rec.take(); len(got) != 1 || got[0] != "warning:coretemp Package id 0 is hot at 91 °C" {
		t.Fatalf("%v (nvme sensors are judged by SMART)", got)
	}
}

func TestSources(t *testing.T) {
	root := fstest.MapFS{
		"proc/diskstats": {Data: []byte("   8       0 sda 100 0 2000 0 50 0 4000 0 0 100 0 0 0 0 0\n   8       1 sda1 1 0 1 0 1 0 1 0 0 1 0\n 259 0 nvme0n1 10 0 80 0 5 0 40 0 0 10 0 0 0 0 0\n   7 0 loop0 1 0 1 0 1 0 1 0 0 1 0\n")},
	}
	d := &DiskIOSource{Root: root}
	t0 := time.Unix(1_800_000_000, 0)
	if pts, _ := d.Collect(context.Background(), t0); len(pts) != 0 {
		t.Fatalf("first collection has no rates: %v", pts)
	}
	root["proc/diskstats"] = &fstest.MapFile{Data: []byte("   8       0 sda 100 0 4048 0 50 0 4000 0 0 600 0 0 0 0 0\n 259 0 nvme0n1 10 0 80 0 5 0 40 0 0 10 0 0 0 0 0\n")}
	pts, _ := d.Collect(context.Background(), t0.Add(10*time.Second))
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Series] = p.Value
	}
	if got["disk.read:sda"] != 2048*512/10.0 || got["disk.busy:sda"] != 5 || got["disk.write:nvme0n1"] != 0 || len(pts) != 6 {
		t.Errorf("disk io %v", got)
	}

	apps := fstest.MapFS{
		AppSlicesDir + `/hardyos-app-apex\x2drmm.slice/cpu.stat`:       {Data: []byte("usage_usec 1000000\nuser_usec 1\n")},
		AppSlicesDir + `/hardyos-app-apex\x2drmm.slice/memory.current`: {Data: []byte("524288000\n")},
		AppSlicesDir + `/hardyos-app-apex\x2drmm.slice/io.stat`:        {Data: []byte("8:0 rbytes=1000 wbytes=2000 rios=1 wios=1\n")},
	}
	a := &AppsSource{Root: apps, CPUs: func() int { return 4 }, Names: func() map[string]string { return map[string]string{"apex-rmm": "Apex RMM"} }}
	_, _ = a.Collect(context.Background(), t0)
	apps[AppSlicesDir+`/hardyos-app-apex\x2drmm.slice/cpu.stat`] = &fstest.MapFile{Data: []byte("usage_usec 21000000\n")}
	apps[AppSlicesDir+`/hardyos-app-apex\x2drmm.slice/io.stat`] = &fstest.MapFile{Data: []byte("8:0 rbytes=11000 wbytes=2000\n")}
	pts, _ = a.Collect(context.Background(), t0.Add(10*time.Second))
	got = map[string]float64{}
	for _, p := range pts {
		got[p.Series] = p.Value
		if p.Label != "Apex RMM" {
			t.Errorf("label %q", p.Label)
		}
	}
	// 20 s of CPU in 10 s over 4 CPUs = 50%.
	if got["app.cpu:apex-rmm"] != 50 || got["app.mem:apex-rmm"] != 524288000 || got["app.read:apex-rmm"] != 1000 {
		t.Errorf("apps %v", got)
	}
	var _ fs.FS = apps
}

func TestHistoryTiersAndQuery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	h, err := OpenHistory(ctx, filepath.Join(dir, "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	si := SeriesInfo{Name: "cpu.percent", Unit: UnitPercent}
	// Two hours at 10 s: a ramp 0..719, with a gap of 10 minutes.
	for i := 0; i < 720; i++ {
		if i >= 300 && i < 360 {
			continue
		}
		if err := h.Record(ctx, si, start.Add(time.Duration(i)*10*time.Second), float64(i)); err != nil {
			t.Fatal(err)
		}
	}
	now := start.Add(2 * time.Hour)
	if err := h.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.Rollup(ctx, now); err != nil {
		t.Fatal(err)
	}
	// Tier 0 for the last hour, every point.
	r, err := h.Query(ctx, []string{"cpu.percent", "missing"}, start, start.Add(time.Hour), now, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if r.Tier != 0 || r.Step != 10 || len(r.Series[0].Values) != 360 || *r.Series[0].Values[5] != 5 || r.Series[0].Values[300] != nil {
		t.Fatalf("tier 0: tier %d step %d n %d", r.Tier, r.Step, len(r.Series[0].Values))
	}
	if len(r.Series[1].Values) != 0 {
		t.Error("unknown series has values")
	}
	// Downsampled to 12 points: 5-minute averages, the gap stays a gap.
	r, _ = h.Query(ctx, []string{"cpu.percent"}, start, start.Add(time.Hour), now, 12)
	if len(r.Series[0].Values) != 12 || r.Step != 300 || *r.Series[0].Values[0] != 14.5 {
		t.Errorf("downsampled %d step %d first %v", len(r.Series[0].Values), r.Step, *r.Series[0].Values[0])
	}
	if r.Series[0].Values[10] != nil {
		t.Errorf("gap filled: %v", *r.Series[0].Values[10])
	}
	// Tier 1 has minute averages.
	vals, _ := h.readRange(ctx, h.ids["cpu.percent"], 1, start, start.Add(3*time.Minute))
	if len(vals) != 3 || vals[0] != 2.5 || vals[2] != 14.5 {
		t.Errorf("tier 1 %v", vals)
	}
	// A range older than a day comes from a coarser tier.
	later := start.Add(3 * 24 * time.Hour)
	_ = h.Rollup(ctx, later)
	r, _ = h.Query(ctx, []string{"cpu.percent"}, start, start.Add(2*time.Hour), later, 500)
	if r.Tier != 1 || r.Step != 60 || *r.Series[0].Values[0] != 2.5 {
		t.Errorf("old range: tier %d step %d", r.Tier, r.Step)
	}
	// Persisted: reopen and read again.
	h.Close()
	h2, err := OpenHistory(ctx, filepath.Join(dir, "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	r, _ = h2.Query(ctx, []string{"cpu.percent"}, start, start.Add(time.Hour), now, 1000)
	if *r.Series[0].Values[100] != 100 {
		t.Error("values lost on reopen")
	}
	if s := h2.Series(); len(s) != 1 || s[0].Unit != UnitPercent {
		t.Errorf("series %+v", s)
	}
	// Prune drops tier 0 after a day (plus a chunk).
	_ = h2.Prune(ctx, start.Add(30*time.Hour))
	var n int
	_ = h2.db.QueryRow(`SELECT COUNT(*) FROM chunks WHERE tier = 0`).Scan(&n)
	if n != 0 {
		t.Errorf("%d tier-0 chunks after a day", n)
	}
	_ = h2.db.QueryRow(`SELECT COUNT(*) FROM chunks WHERE tier = 1`).Scan(&n)
	if n == 0 {
		t.Error("tier 1 pruned too early")
	}
	if names := h2.ExpandNames([]string{"cpu.*", "cpu.percent", "x"}); strings.Join(names, ",") != "cpu.percent,x" {
		t.Errorf("expand %v", names)
	}
	if !math.IsNaN(float64(nanChunk(1)[0])) {
		t.Error("nan chunk")
	}
}

func TestHistorySize(t *testing.T) {
	// A day of 100 series at 10 s stays small: 24 chunks of 1.4 KB each.
	ctx := context.Background()
	h, _ := OpenHistory(ctx, ":memory:")
	defer h.Close()
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for s := 0; s < 100; s++ {
		for i := 0; i < 8640; i += 6 { // every minute is enough to touch every chunk
			_ = h.Record(ctx, SeriesInfo{Name: fmt.Sprintf("s.%d", s)}, start.Add(time.Duration(i)*10*time.Second), 1)
		}
	}
	_ = h.Flush(ctx)
	var n, bytes int
	_ = h.db.QueryRow(`SELECT COUNT(*), SUM(LENGTH(data)) FROM chunks`).Scan(&n, &bytes)
	if n != 2400 || bytes != 2400*360*4 {
		t.Errorf("%d chunks, %d bytes", n, bytes)
	}
}

func TestSettingsValidate(t *testing.T) {
	d := DefaultSettings()
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := d
	bad.PoolCritPct = 70
	if bad.Validate() == nil {
		t.Error("critical below warning accepted")
	}
	bad = d
	bad.SMART.Excluded = []string{"/etc/passwd"}
	if bad.Validate() == nil {
		t.Error("bad excluded disk accepted")
	}
	w := Schedule{WindowStart: 23, WindowEnd: 5}
	if !w.InWindow(time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC)) || w.InWindow(time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)) {
		t.Error("window over midnight")
	}
}

// The review's exploit: an absurd range must be clamped, quick, and must
// not fill the chunk cache.
func TestHistoryHugeRange(t *testing.T) {
	ctx := context.Background()
	h, _ := OpenHistory(ctx, ":memory:")
	defer h.Close()
	now := time.Now()
	_ = h.Record(ctx, SeriesInfo{Name: "cpu.percent"}, now.Add(-time.Minute), 5)
	_ = h.Flush(ctx)
	h.mu.Lock()
	before := len(h.chunks)
	h.mu.Unlock()
	from := time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	start := time.Now()
	r, err := h.Query(ctx, []string{"cpu.percent"}, from, to, now, 2000)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("query took %v", time.Since(start))
	}
	if r.Tier != 3 || len(r.Series[0].Values) > 2000 || r.From.Before(now.Add(-731*24*time.Hour)) || r.To.After(now) {
		t.Errorf("tier %d, %d values, %v..%v", r.Tier, len(r.Series[0].Values), r.From, r.To)
	}
	h.mu.Lock()
	after := len(h.chunks)
	h.mu.Unlock()
	if after != before {
		t.Errorf("query cached chunks: %d -> %d", before, after)
	}
	// Too long for the points asked: refused.
	if _, err := h.Query(ctx, []string{"cpu.percent"}, now.Add(-730*24*time.Hour), now, now, 10); err == nil {
		t.Error("2 years in 10 points accepted")
	}
	if _, err := h.Query(ctx, []string{"cpu.percent"}, to, to.Add(time.Hour), now, 100); err == nil {
		t.Error("a future range accepted")
	}
}
