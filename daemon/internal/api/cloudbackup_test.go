package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/cloudbackup"
	"github.com/hardyos/hardyos/daemon/internal/cloudbackups"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// stubCloud is hardyd-priv's cloud backup operations, recording what
// hardyd sends.
type stubCloud struct {
	mu       sync.Mutex
	targets  []cloudbackup.Target
	saves    []cloudbackup.SaveArgs
	backups  []cloudbackup.BackupArgs
	restores []cloudbackup.RestoreArgs
	browses  []cloudbackup.BrowseArgs
	tasks    map[string]cloudbackup.Task
}

func (c *stubCloud) register(s *priv.Server) {
	h := func(op string, fn func(json.RawMessage) (any, error)) {
		s.Handle(op, func(_ context.Context, raw json.RawMessage) (any, error) { return fn(raw) })
	}
	h(priv.OpCloudTargets, func(json.RawMessage) (any, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		return priv.CloudTargetsResult{Targets: append([]cloudbackup.Target{}, c.targets...)}, nil
	})
	h(priv.OpCloudTargetSave, func(raw json.RawMessage) (any, error) {
		var a cloudbackup.SaveArgs
		_ = json.Unmarshal(raw, &a)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.saves = append(c.saves, a)
		c.targets = append(c.targets, a.Target)
		return cloudbackup.SaveResult{Target: a.Target, Created: a.RepoPassword == ""}, nil
	})
	h(priv.OpCloudTargetRemove, func(json.RawMessage) (any, error) { return map[string]bool{"removed": true}, nil })
	h(priv.OpCloudKit, func(raw json.RawMessage) (any, error) {
		var a priv.CloudTargetRef
		_ = json.Unmarshal(raw, &a)
		return cloudbackup.RecoveryKit{Target: cloudbackup.Target{ID: a.ID, Name: "Offsite", Kind: "s3", Endpoint: "https://s3.example.com", Bucket: "b"},
			Repository: "s3:https://s3.example.com/b", Key: "REPO-KEY-0123456789abcdef"}, nil
	})
	h(priv.OpCloudBackup, func(raw json.RawMessage) (any, error) {
		var a cloudbackup.BackupArgs
		_ = json.Unmarshal(raw, &a)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.backups = append(c.backups, a)
		res, _ := json.Marshal(cloudbackup.RunResult{Run: a.Run, Items: []cloudbackup.ItemResult{{Item: "share:media", Files: 3, Bytes: 300, Added: 100}}})
		t := cloudbackup.Task{ID: "task-" + a.Run, Kind: "backup", Done: true, Progress: 100, Result: res}
		c.tasks[t.ID] = t
		return t, nil
	})
	h(priv.OpCloudRestore, func(raw json.RawMessage) (any, error) {
		var a cloudbackup.RestoreArgs
		_ = json.Unmarshal(raw, &a)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.restores = append(c.restores, a)
		res, _ := json.Marshal(cloudbackup.RestoreResult{Files: 1})
		t := cloudbackup.Task{ID: "restore-1", Done: true, Result: res}
		c.tasks[t.ID] = t
		return t, nil
	})
	h(priv.OpCloudTask, func(raw json.RawMessage) (any, error) {
		var a priv.CloudTaskRef
		_ = json.Unmarshal(raw, &a)
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.tasks[a.ID], nil
	})
	h(priv.OpCloudVersions, func(json.RawMessage) (any, error) {
		return priv.CloudVersionsResult{Versions: []cloudbackup.Version{{Run: "r1", Task: "t1", Time: time.Now(),
			Items: []cloudbackup.VersionItem{{Item: "share:media", Snapshot: "aaaaaaaa"}, {Item: "share:secret", Snapshot: "bbbbbbbb"}}}}}, nil
	})
	h(priv.OpCloudBrowse, func(raw json.RawMessage) (any, error) {
		var a cloudbackup.BrowseArgs
		_ = json.Unmarshal(raw, &a)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.browses = append(c.browses, a)
		return priv.CloudBrowseResult{Entries: []cloudbackup.Entry{{Name: "a.txt", Path: "a.txt", Type: "file"}}}, nil
	})
	h(priv.OpCloudOffer, func(json.RawMessage) (any, error) { return priv.CloudOfferResult{}, nil })
}

func newCloudEnv(t *testing.T) (*testEnv, *stubCloud) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dir := t.TempDir()
	db, err := store.Open(ctx, filepath.Join(dir, "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "priv.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stub := &stubCloud{tasks: map[string]cloudbackup.Task{}}
	ps := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	stub.register(ps)
	go func() { _ = ps.Serve(ctx, ln) }()
	pc := priv.NewClient(sock)
	broker := events.NewBroker()
	m := &jobs.Manager{DB: db, Events: broker}
	var mu sync.Mutex
	var events []cloudbackups.Event
	svc := &cloudbackups.Service{DB: db, Priv: pc, Jobs: m, Dir: filepath.Join(dir, "work"), Poll: 10 * time.Millisecond, Version: "0.6.0",
		Notifier: cloudbackups.NotifierFunc(func(_ context.Context, e cloudbackups.Event) {
			mu.Lock()
			events = append(events, e)
			mu.Unlock()
		})}
	svc.RegisterJobs(m)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	ff := &fakeFiles{dirs: map[string]string{"media": t.TempDir()}}
	srv := httptest.NewServer(New(Config{DB: db, Jobs: m, Events: broker, Priv: pc, CloudBackups: svc, Files: ff, Insecure: true}))
	t.Cleanup(func() {
		srv.Close()
		cancel()
		m.Wait()
		db.Close()
	})
	return &testEnv{srv: srv, db: db, broker: broker}, stub
}

func TestCloudBackupAPI(t *testing.T) {
	env, stub := newCloudEnv(t)
	admin := env.client(t)
	admin.do("POST", "/api/v1/setup/admin", map[string]string{"username": "cade", "password": "supersecret1"}, nil)

	// A destination: the keys reach hardyd-priv but never the job's parameters.
	var acc struct {
		Job map[string]any `json:"job"`
	}
	req := map[string]any{"id": "offsite", "name": "Offsite", "kind": "s3", "endpoint": "https://s3.example.com", "bucket": "my-bucket",
		"accessKey": "AKIDEXAMPLE1234", "secretKey": "SECRETSECRETSECRET"}
	if code := admin.do("POST", "/api/v1/backup/targets", req, &acc); code != 202 {
		t.Fatalf("create target = %d", code)
	}
	j := waitJobDone(t, admin, acc.Job["id"].(string))
	if j["state"] != "succeeded" {
		t.Fatalf("save job: %v", j)
	}
	params, _ := json.Marshal(j["params"])
	if strings.Contains(string(params), "SECRETSECRET") || strings.Contains(string(params), "AKIDEXAMPLE") {
		t.Fatalf("keys in the job's parameters: %s", params)
	}
	if len(stub.saves) != 1 || stub.saves[0].SecretKey != "SECRETSECRETSECRET" || stub.saves[0].AccessKey != "AKIDEXAMPLE1234" {
		t.Fatalf("hardyd-priv got %+v", stub.saves)
	}
	res, _ := json.Marshal(j["result"])
	if !strings.Contains(string(res), `"created":true`) {
		t.Fatalf("result: %s", res)
	}
	// A plain-http endpoint never gets as far as a job.
	bad := map[string]any{"id": "x", "name": "X", "kind": "s3", "endpoint": "http://s3.example.com", "bucket": "my-bucket", "accessKey": "a", "secretKey": "b"}
	if code := admin.do("POST", "/api/v1/backup/targets", bad, nil); code != 400 {
		t.Fatalf("http endpoint = %d", code)
	}

	// Recovery kit: password again, every try audited.
	var e ErrorResponse
	if code := admin.do("POST", "/api/v1/backup/targets/offsite/recovery-kit", map[string]string{"password": "wrong"}, &e); code != 401 {
		t.Fatalf("kit with a wrong password = %d", code)
	}
	var kit RecoveryKit
	if code := admin.do("POST", "/api/v1/backup/targets/offsite/recovery-kit", map[string]string{"password": "supersecret1"}, &kit); code != 200 {
		t.Fatalf("kit = %d", code)
	}
	k, err := cloudbackup.ParseKit(kit.Text)
	if err != nil || k.Key != "REPO-KEY-0123456789abcdef" || !strings.HasSuffix(kit.FileName, ".txt") {
		t.Fatalf("kit %+v: %v", kit, err)
	}
	var entries []audit.Entry
	admin.do("GET", "/api/v1/audit?action=backup.recovery_kit", nil, &entries)
	if len(entries) != 2 || entries[0].Outcome != audit.Success || entries[1].Outcome != audit.Failure {
		t.Fatalf("kit audit: %+v", entries)
	}
	var ov CloudOverview
	admin.do("GET", "/api/v1/backup", nil, &ov)
	if len(ov.Targets) != 1 || ov.Targets[0].KitDownloadedAt == nil || ov.Targets[0].Maintenance.CheckPercent != 5 {
		t.Fatalf("overview: %+v", ov)
	}

	// A task: validated, audited, run now as a job that follows hardyd-priv.
	if code := admin.do("POST", "/api/v1/backup/tasks", map[string]any{"name": "Nightly", "target": "nowhere", "items": []map[string]string{{"kind": "share", "id": "media"}}}, nil); code != 400 {
		t.Fatalf("task to an unknown destination = %d", code)
	}
	if code := admin.do("POST", "/api/v1/backup/tasks", map[string]any{"name": "Nightly", "target": "offsite", "items": []map[string]string{{"kind": "share", "id": "../x"}}}, nil); code != 400 {
		t.Fatalf("bad item = %d", code)
	}
	var task cloudbackups.Task
	if code := admin.do("POST", "/api/v1/backup/tasks", map[string]any{"name": "Nightly", "target": "offsite",
		"items": []map[string]string{{"kind": "share", "id": "media"}, {"kind": "system"}}}, &task); code != 201 {
		t.Fatalf("create task = %d", code)
	}
	if task.Retention != cloudbackup.DefaultRetention || task.Schedule.Frequency != "daily" || task.NextRun == nil {
		t.Fatalf("defaults: %+v", task)
	}
	if code := admin.do("POST", "/api/v1/backup/tasks/"+task.ID+"/run", nil, &acc); code != 202 {
		t.Fatalf("run = %d", code)
	}
	if j := waitJobDone(t, admin, acc.Job["id"].(string)); j["state"] != "succeeded" {
		t.Fatalf("run job: %v", j)
	}
	if len(stub.backups) != 1 || stub.backups[0].SystemDB == "" || stub.backups[0].System.Users != 1 || stub.backups[0].Retention != cloudbackup.DefaultRetention {
		t.Fatalf("backup args: %+v", stub.backups)
	}
	if _, err := os.Stat(stub.backups[0].SystemDB); err == nil {
		t.Fatal("the database copy was left behind")
	}
	var runs struct {
		Runs []cloudbackups.Run `json:"runs"`
	}
	admin.do("GET", "/api/v1/backup/runs?task="+task.ID, nil, &runs)
	if len(runs.Runs) != 1 || runs.Runs[0].State != "succeeded" || runs.Runs[0].Files != 3 || runs.Runs[0].Added != 100 {
		t.Fatalf("runs: %+v", runs)
	}

	// A rollback needs the name typed.
	if code := admin.do("POST", "/api/v1/backup/restore", map[string]any{"target": "offsite", "snapshot": "aaaaaaaa", "mode": "rollback"}, &e); code != 400 || e.Code != "confirm_required" {
		t.Fatalf("rollback without confirm = %d %+v", code, e)
	}
	if code := admin.do("POST", "/api/v1/backup/restore", map[string]any{"target": "offsite", "snapshot": "aaaaaaaa", "mode": "rollback", "confirm": "Media"}, &acc); code != 202 {
		t.Fatalf("rollback = %d", code)
	}
	waitJobDone(t, admin, acc.Job["id"].(string))
	if len(stub.restores) != 1 || stub.restores[0].Who != nil || stub.restores[0].MaxSchema == 0 {
		t.Fatalf("admin restore args: %+v", stub.restores)
	}

	// Family members don't see backup administration.
	admin.do("POST", "/api/v1/users", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	kid := env.client(t)
	kid.do("POST", "/api/v1/auth/login", map[string]string{"username": "kid", "password": "kidpassword1"}, nil)
	if code := kid.do("GET", "/api/v1/backup", nil, nil); code != 403 {
		t.Fatalf("kid sees backups: %d", code)
	}
	if code := kid.do("POST", "/api/v1/backup/targets/offsite/recovery-kit", map[string]string{"password": "kidpassword1"}, nil); code != 403 {
		t.Fatalf("kid got a kit: %d", code)
	}
	// ...nor versions of folders they can't open.
	if code := kid.do("GET", "/api/v1/files/backups?share=media", nil, nil); code != 404 {
		t.Fatalf("kid listed versions: %d", code)
	}

	// Through the File Manager: only this folder's versions, restored as the person.
	var fv struct {
		Versions []FileBackupVersion `json:"versions"`
	}
	if code := admin.do("GET", "/api/v1/files/backups?share=media", nil, &fv); code != 200 || len(fv.Versions) != 1 || fv.Versions[0].Snapshot != "aaaaaaaa" {
		t.Fatalf("file versions = %d %+v", code, fv)
	}
	if code := admin.do("GET", "/api/v1/files/backups/browse?share=media&target=offsite&snapshot=aaaaaaaa", nil, nil); code != 200 || stub.browses[0].Who == nil || stub.browses[0].Who.Principal != "cade" {
		t.Fatalf("browse = %d %+v", code, stub.browses)
	}
	// Another folder's version can't be restored into this one.
	if code := admin.do("POST", "/api/v1/files/backups/restore", map[string]any{"share": "media", "target": "offsite", "snapshot": "bbbbbbbb", "mode": "copy", "folder": "x"}, nil); code != 404 {
		t.Fatalf("other folder's version = %d", code)
	}
	if code := admin.do("POST", "/api/v1/files/backups/restore", map[string]any{"share": "media", "target": "offsite", "snapshot": "aaaaaaaa", "mode": "rollback"}, nil); code != 400 {
		t.Fatalf("a person's rollback = %d", code)
	}
	if code := admin.do("POST", "/api/v1/files/backups/restore", map[string]any{"share": "media", "target": "offsite", "snapshot": "aaaaaaaa", "mode": "copy", "folder": "Back", "paths": []string{"a.txt"}}, &acc); code != 202 {
		t.Fatalf("person restore = %d", code)
	}
	waitJobDone(t, admin, acc.Job["id"].(string))
	if len(stub.restores) != 2 || stub.restores[1].Who == nil || stub.restores[1].Who.Principal != "cade" || stub.restores[1].Mode != "copy" {
		t.Fatalf("person restore args: %+v", stub.restores)
	}

	// Removing a destination a task uses is refused.
	if code := admin.do("DELETE", "/api/v1/backup/targets/offsite", map[string]string{"confirm": "Offsite"}, &e); code != 409 {
		t.Fatalf("remove used destination = %d", code)
	}
	if code := admin.do("DELETE", "/api/v1/backup/tasks/"+task.ID, nil, nil); code != 204 {
		t.Fatalf("delete task = %d", code)
	}
	admin.do("GET", "/api/v1/audit?action=backup.", nil, &entries)
	actions := map[string]bool{}
	for _, en := range entries {
		actions[en.Action] = true
	}
	for _, want := range []string{"backup.target.create", "backup.task.create", "backup.task.run", "backup.restore.rollback", "backup.task.delete"} {
		if !actions[want] {
			t.Errorf("no audit entry %s (%v)", want, actions)
		}
	}
}

func TestCloudSchedule(t *testing.T) {
	loc := time.FixedZone("x", 0)
	at := func(s string) time.Time {
		tm, _ := time.ParseInLocation("2006-01-02 15:04", s, loc)
		return tm
	}
	cases := []struct {
		s         cloudbackups.Schedule
		now, last string
		next      string
	}{
		{cloudbackups.Schedule{Frequency: "daily", Time: "01:30"}, "2026-10-27 01:29", "2026-10-26 01:30", "2026-10-27 01:30"},
		{cloudbackups.Schedule{Frequency: "daily", Time: "01:30"}, "2026-10-27 01:30", "2026-10-27 01:30", "2026-10-28 01:30"},
		{cloudbackups.Schedule{Frequency: "hourly", Time: "00:15", EveryHours: 6}, "2026-10-27 13:00", "2026-10-27 12:15", "2026-10-27 18:15"},
		{cloudbackups.Schedule{Frequency: "weekly", Time: "03:00", Weekdays: []int{0, 3}}, "2026-10-27 10:00", "2026-10-25 03:00", "2026-10-28 03:00"},
	}
	for _, c := range cases {
		if err := c.s.Check(); err != nil {
			t.Fatal(err)
		}
		if got := c.s.LastSlot(at(c.now)); !got.Equal(at(c.last)) {
			t.Errorf("%+v last at %s = %s", c.s, c.now, got)
		}
		if got := c.s.NextSlot(at(c.now)); !got.Equal(at(c.next)) {
			t.Errorf("%+v next at %s = %s", c.s, c.now, got)
		}
	}
	bad := []cloudbackups.Schedule{{Frequency: "hourly", Time: "00:00", EveryHours: 5}, {Frequency: "weekly", Time: "01:00"}, {Frequency: "daily", Time: "25:00"}, {Frequency: "yearly"}}
	for _, b := range bad {
		if b.Check() == nil {
			t.Errorf("accepted %+v", b)
		}
	}
}
