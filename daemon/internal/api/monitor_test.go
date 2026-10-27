package api

import (
	"context"
	"encoding/json"
	"io/fs"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/monitor"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/ups"
)

type monitorEnv struct {
	*testEnv
	fake   *sysexec.Fake
	mon    *monitor.Service
	upsDir string
}

func newMonitorEnv(t *testing.T) *monitorEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	broker := events.NewBroker()
	root := fstest.MapFS{}
	for _, n := range []string{"sda", "sdb", "sdc", "nvme0n1"} {
		root["dev/disk/by-id/ata-DISK_"+n] = &fstest.MapFile{Data: []byte("../../" + n), Mode: fs.ModeSymlink | 0o777}
	}
	smart, _ := os.ReadFile("../hw/testdata/smart-sata-hdd.json")
	fake := (&sysexec.Fake{}).
		On("lsblk -J -b -o NAME,PATH,SIZE,TYPE,ROTA,MODEL,SERIAL,WWN,TRAN,FSTYPE,LABEL,MOUNTPOINTS,HOTPLUG,PHY-SEC", apiLsblk).
		OnPrefix("smartctl --json=c -a", sysexec.Result{Stdout: smart}).
		OnPrefix("smartctl --json=c -t", sysexec.Result{Stdout: []byte(`{}`)}).
		OnPrefix("systemctl", sysexec.Result{}).
		OnPrefix("upsdrvsvcctl", sysexec.Result{}).
		OnResult("nut-scanner -U -q", sysexec.Result{ExitCode: 1})
	upsDir := t.TempDir()
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	priv.RegisterBuiltins(ps)
	senv := priv.StorageEnv{Runner: fake, Root: root}
	priv.RegisterStorage(ps, senv)
	priv.RegisterMonitor(ps, priv.MonitorEnv{Storage: senv, UPS: &ups.Root{Runner: fake, Root: fstest.MapFS{}, Dir: upsDir,
		Write: func(p string, b []byte, m os.FileMode) error { return os.WriteFile(p, b, m) }, Chown: func(string) error { return nil }}})
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)

	m := &jobs.Manager{DB: db, Events: broker}
	nc := &notify.Center{DB: db, Events: broker}
	alerts := &notify.Dispatcher{DB: db, Center: nc, Channels: &notify.Channels{DB: db}}
	nc.Forward = alerts.Forward
	hist, err := monitor.OpenHistory(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	mon := &monitor.Service{DB: db, Priv: pc, Notify: alerts, History: hist, Root: fstest.MapFS{},
		UPS: &monitor.UPSService{DB: db, Query: func(context.Context, string, string) (*ups.Status, error) {
			c := 97.0
			return &ups.Status{UPS: "ups", OnLine: true, Flags: []string{"OL"}, ChargePct: &c}, nil
		}}}
	RegisterJobKinds(m, pc)
	RegisterMonitorJobs(m, mon, pc)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	go alerts.Run(ctx)
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, Notify: nc, Alerts: alerts, Monitor: mon, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		hist.Close()
		db.Close()
	})
	return &monitorEnv{testEnv: &testEnv{srv: srv, db: db, broker: broker}, fake: fake, mon: mon, upsDir: upsDir}
}

func TestAlertChannelsAPI(t *testing.T) {
	env := newMonitorEnv(t)
	admin := adminClient(t, env.testEnv)
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)

	var ch map[string]any
	code := admin.do("POST", "/api/v1/alerts/channels", map[string]any{"type": "discord", "name": "Family",
		"secrets": map[string]string{"url": "https://discord.com/api/webhooks/42/SECRET-TOKEN"}}, &ch)
	if code != 201 || ch["config"].(map[string]any)["urlHost"] != "discord.com" {
		t.Fatalf("create %d %v", code, ch)
	}
	id := itoa(int(ch["id"].(float64)))
	if code := admin.do("POST", "/api/v1/alerts/channels", map[string]any{"type": "webhook", "name": "LAN",
		"config": map[string]any{"allowAnyHost": true}, "secrets": map[string]string{"url": "https://192.168.1.5/hook"}}, nil); code != 400 {
		t.Errorf("LAN webhook accepted: %d", code)
	}
	if code := kid.do("GET", "/api/v1/alerts/channels", nil, nil); code != 403 {
		t.Errorf("non-admin listed channels: %d", code)
	}
	var raw json.RawMessage
	admin.do("GET", "/api/v1/alerts/channels", nil, &raw)
	if strings.Contains(string(raw), "SECRET-TOKEN") || !strings.Contains(string(raw), `"url":true`) {
		t.Errorf("channel list %s", raw)
	}
	if code := admin.do("PATCH", "/api/v1/alerts/channels/"+id, map[string]any{"name": "Discord", "enabled": false}, &ch); code != 200 || ch["enabled"] != false {
		t.Errorf("update %d %v", code, ch)
	}
	// Routing: disks critical only on Discord.
	var routes []map[string]any
	if code := admin.do("PUT", "/api/v1/alerts/routes", map[string]any{"routes": []map[string]any{
		{"category": "*", "channelId": 1, "minSeverity": "info"}, {"category": "disk", "channelId": ch["id"], "minSeverity": "critical"}}}, &routes); code != 200 || len(routes) != 2 {
		t.Errorf("routes %d %v", code, routes)
	}
	if code := admin.do("PUT", "/api/v1/alerts/routes", map[string]any{"routes": []map[string]any{{"category": "Disk; drop", "channelId": 1, "minSeverity": "info"}}}, nil); code != 400 {
		t.Errorf("bad category accepted: %d", code)
	}
	// Settings.
	var set map[string]any
	if code := admin.do("PUT", "/api/v1/alerts/settings", map[string]any{"quietHours": map[string]any{"enabled": true, "start": "23:00", "end": "06:30", "allow": "critical"},
		"dedupMinutes": 15, "maxPerHour": 4, "serverUrl": "https://nas.example.com"}, &set); code != 200 || set["maxPerHour"].(float64) != 4 {
		t.Errorf("settings %d %v", code, set)
	}
	// The desktop channel's test: a notification the admin sees, unread.
	var res ChannelTestResult
	if code := admin.do("POST", "/api/v1/alerts/channels/1/test", nil, &res); code != 200 || !res.OK {
		t.Fatalf("desktop test %d %+v", code, res)
	}
	var unread UnreadCount
	admin.do("GET", "/api/v1/notifications/unread", nil, &unread)
	if unread.Count != 1 {
		t.Errorf("unread %d", unread.Count)
	}
	var list []map[string]any
	admin.do("GET", "/api/v1/notifications", nil, &list)
	if len(list) != 1 || list[0]["kind"] != "system.test" || list[0]["link"] != "control/notifications" {
		t.Fatalf("notifications %v", list)
	}
	admin.do("POST", "/api/v1/notifications/"+itoa(int(list[0]["id"].(float64)))+"/read", nil, nil)
	admin.do("GET", "/api/v1/notifications/unread", nil, &unread)
	if unread.Count != 0 {
		t.Errorf("unread after reading %d", unread.Count)
	}
	kid.do("GET", "/api/v1/notifications/unread", nil, &unread)
	if unread.Count != 0 {
		t.Errorf("a user sees admin alerts: %d", unread.Count)
	}
	// Audit: channel changes are recorded without secrets.
	var audit []map[string]any
	admin.do("GET", "/api/v1/audit?action=alerts.", nil, &audit)
	if len(audit) < 4 {
		t.Errorf("audit %v", audit)
	}
	b, _ := json.Marshal(audit)
	if strings.Contains(string(b), "SECRET-TOKEN") {
		t.Error("a webhook secret reached the audit log")
	}
	if code := admin.do("DELETE", "/api/v1/alerts/channels/1", nil, nil); code != 400 {
		t.Errorf("deleting the desktop channel: %d", code)
	}
	if code := admin.do("DELETE", "/api/v1/alerts/channels/"+id, nil, nil); code != 204 {
		t.Errorf("delete %d", code)
	}
}

func TestMonitorAPI(t *testing.T) {
	env := newMonitorEnv(t)
	admin := adminClient(t, env.testEnv)
	ctx := context.Background()

	// History: a recorded series comes back.
	now := time.Now()
	for i := range 6 {
		_ = env.mon.History.Record(ctx, monitor.SeriesInfo{Name: "cpu.percent", Unit: "percent"}, now.Add(time.Duration(i-6)*10*time.Second), float64(10*i))
	}
	var series []monitor.SeriesInfo
	admin.do("GET", "/api/v1/monitor/series", nil, &series)
	if len(series) != 1 {
		t.Fatalf("series %v", series)
	}
	var hist monitor.HistoryResult
	if code := admin.do("GET", "/api/v1/monitor/history?series=cpu.*&range=1h&points=400", nil, &hist); code != 200 || len(hist.Series) != 1 || hist.Step != 10 {
		t.Fatalf("history %d %+v", code, hist)
	}
	if code := admin.do("GET", "/api/v1/monitor/history", nil, nil); code != 400 {
		t.Errorf("history without series: %d", code)
	}

	// Settings.
	var set monitor.Settings
	admin.do("GET", "/api/v1/monitor/settings", nil, &set)
	set.SMART.ShortDays = 3
	if code := admin.do("PUT", "/api/v1/monitor/settings", set, &set); code != 200 || set.SMART.ShortDays != 3 {
		t.Errorf("save %d %+v", code, set)
	}
	set.PoolCritPct = 10
	if code := admin.do("PUT", "/api/v1/monitor/settings", set, nil); code != 400 {
		t.Errorf("bad settings: %d", code)
	}

	// Disks and a self-test job.
	var disks []monitor.DiskInfo
	if code := admin.do("GET", "/api/v1/monitor/disks", nil, &disks); code != 200 || len(disks) != 4 {
		t.Fatalf("disks %d %v", code, disks)
	}
	var acc struct{ Job struct{ ID string } }
	if code := admin.do("POST", "/api/v1/monitor/disks/sdb/test", map[string]string{"test": "long"}, &acc); code != 202 {
		t.Fatalf("test %d", code)
	}
	if j := waitJob(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("job %v", j)
	}
	if !strings.Contains(strings.Join(env.fake.Lines(), "\n"), "smartctl --json=c -t long /dev/disk/by-id/ata-DISK_sdb") {
		t.Errorf("no self-test started:\n%s", strings.Join(env.fake.Lines(), "\n"))
	}
	if code := admin.do("POST", "/api/v1/monitor/disks/sdb/test", map[string]string{"test": "short"}, nil); code != 409 {
		t.Errorf("overlapping test: %d", code)
	}
	if code := admin.do("POST", "/api/v1/monitor/disks/sdz/test", map[string]string{"test": "short"}, nil); code != 404 {
		t.Errorf("unknown disk: %d", code)
	}
	if code := admin.do("POST", "/api/v1/monitor/disks/sda/test", map[string]string{"test": "conveyance"}, nil); code != 400 {
		t.Errorf("unknown test: %d", code)
	}
	var conds []monitor.Condition
	if code := admin.do("GET", "/api/v1/monitor/conditions", nil, &conds); code != 200 {
		t.Errorf("conditions %d", code)
	}
}

func TestUPSAPI(t *testing.T) {
	env := newMonitorEnv(t)
	admin := adminClient(t, env.testEnv)
	var acc struct{ Job struct{ ID string } }
	code := admin.do("PUT", "/api/v1/ups", map[string]any{"config": map[string]any{"mode": "local", "serveNetwork": true, "shutdownCharge": 30},
		"secrets": map[string]string{"clientPassword": "family-ups-pw"}}, &acc)
	if code != 202 {
		t.Fatalf("save %d", code)
	}
	if j := waitJob(t, admin, acc.Job.ID); j["state"] != "succeeded" {
		t.Fatalf("job %v", j)
	}
	users, _ := os.ReadFile(filepath.Join(env.upsDir, "upsd.users"))
	conf, _ := os.ReadFile(filepath.Join(env.upsDir, "ups.conf"))
	if !strings.Contains(string(users), "password = family-ups-pw") || !strings.Contains(string(conf), "override.battery.charge.low = 30") {
		t.Errorf("files:\n%s\n%s", users, conf)
	}
	var raw json.RawMessage
	admin.do("GET", "/api/v1/ups", nil, &raw)
	if strings.Contains(string(raw), "family-ups-pw") || !strings.Contains(string(raw), `"clientPassword":true`) || !strings.Contains(string(raw), `"chargePct":97`) {
		t.Errorf("ups view %s", raw)
	}
	if code := admin.do("PUT", "/api/v1/ups", map[string]any{"config": map[string]any{"mode": "local", "driver": "dummy-ups", "port": "/etc/shadow"}}, nil); code != 400 {
		t.Errorf("bad setup: %d", code)
	}
	var devs []ups.Device
	if code := admin.do("GET", "/api/v1/ups/detect", nil, &devs); code != 200 || devs == nil {
		t.Errorf("detect %d %v", code, devs)
	}
}
