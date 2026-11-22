package nbstandby

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

func testService(t *testing.T) (*Service, *[]string, *time.Time) {
	t.Helper()
	db, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	var alerts []string
	s := &Service{DB: db, Now: func() time.Time { return now }, PeerWait: 50 * time.Millisecond, PeerPoll: 10 * time.Millisecond,
		Notify: func(_ context.Context, level, title, _ string) { alerts = append(alerts, level+": "+title) }}
	return s, &alerts, &now
}

// fakeBackend records the steps.
type fakeBackend struct {
	mu      sync.Mutex
	st      Status
	steps   []string
	fail    map[string]error
	dnsName string
	aaaa    bool
	vps     VPSStatus
	peers   [][2]int
}

func (f *fakeBackend) step(s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.steps = append(f.steps, s)
	if err := f.fail[strings.Fields(s)[0]]; err != nil {
		return err
	}
	return nil
}

func (f *fakeBackend) Status(context.Context) (*Status, error) { c := f.st; return &c, nil }
func (f *fakeBackend) Sync(context.Context) (*SnapshotRecord, error) {
	if err := f.step("sync"); err != nil {
		return nil, err
	}
	rec := SnapshotRecord{ID: "new", At: time.Now(), Info: Info{Version: "0.83.1"}}
	f.st.Snapshots = append([]SnapshotRecord{rec}, f.st.Snapshots...)
	return &rec, nil
}
func (f *fakeBackend) VPS(context.Context) (*VPSStatus, error) {
	if err := f.step("vps"); err != nil {
		return nil, err
	}
	v := f.vps
	return &v, nil
}
func (f *fakeBackend) Stage(_ context.Context, c string) (*StageResult, error) {
	if err := f.step("stage " + c); err != nil {
		return nil, err
	}
	f.st.Mode = ModeTakenOver
	return &StageResult{Snapshot: f.st.Snapshots[0]}, nil
}
func (f *fakeBackend) Unstage(_ context.Context, c string) error {
	if err := f.step("unstage " + c); err != nil {
		return err
	}
	f.st.Mode = ModeStandby
	return nil
}
func (f *fakeBackend) Network(_ context.Context, open bool) error {
	if open {
		return f.step("network open")
	}
	return f.step("network close")
}
func (f *fakeBackend) Handback(_ context.Context, c string) (*HandbackResult, error) {
	if err := f.step("handback " + c); err != nil {
		return nil, err
	}
	return &HandbackResult{Message: "restored", Bytes: 10}, nil
}
func (f *fakeBackend) AppUp(context.Context) error   { return f.step("up") }
func (f *fakeBackend) AppStop(context.Context) error { return f.step("stop") }
func (f *fakeBackend) DNSStandby(context.Context) (string, bool, error) {
	return f.dnsName, f.aaaa, nil
}
func (f *fakeBackend) DNSSet(_ context.Context, typ, content string) error {
	return f.step("dns-" + typ + " " + content)
}
func (f *fakeBackend) DNSRestore(context.Context) error { return f.step("dns-restore") }
func (f *fakeBackend) Peers(context.Context) (int, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.peers) == 0 {
		return 0, 0, errors.New("no token")
	}
	p := f.peers[0]
	if len(f.peers) > 1 {
		f.peers = f.peers[1:]
	}
	return p[0], p[1], nil
}

func configured() Status {
	return Status{Configured: true, Hostname: testHost, Mode: ModeStandby, KeyCreated: time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC),
		Snapshots: []SnapshotRecord{{ID: "old", At: time.Date(2026, 11, 21, 11, 45, 0, 0, time.UTC), Info: Info{Version: "0.83.1"}}}}
}

func TestSettingsValidate(t *testing.T) {
	s, _, _ := testService(t)
	set, _ := s.Settings(t.Context())
	if set.IntervalMinutes != 15 || !set.AutoSync {
		t.Fatalf("%+v", set)
	}
	for _, bad := range []Settings{{IntervalMinutes: 1}, {IntervalMinutes: 2000}, {PublicIPv4: "192.168.1.2"}, {PublicIPv4: "100.70.0.1"},
		{PublicIPv4: "2001:db8::1"}, {PublicIPv6: "203.0.113.5"}, {PublicIPv6: "fd00::1"}, {ConnectFrom: []string{"x"}}} {
		if _, err := s.SaveSettings(t.Context(), bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	good := Settings{IntervalMinutes: 30, AutoSync: true, PublicIPv4: "203.0.113.5", PublicIPv6: "2001:db8:1::5", ConnectFrom: []string{"100.64.0.5"}}
	if _, err := s.SaveSettings(t.Context(), good); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Settings(t.Context()); got.IntervalMinutes != 30 || got.PublicIPv4 != "203.0.113.5" {
		t.Fatalf("%+v", got)
	}
}

func TestHealthAndAlerts(t *testing.T) {
	s, alerts, now := testService(t)
	set := DefaultSettings()
	st := configured()
	st.LastTry, st.LastOK = now.Add(-10*time.Minute), now.Add(-10*time.Minute)
	if h := HealthOf(&st, set, *now); h.State != "ok" || h.Stale || h.StaleAfter != 75 {
		t.Fatalf("%+v", h)
	}
	if Due(&st, set, *now) {
		t.Fatal("due too early")
	}
	*now = now.Add(6 * time.Minute)
	if !Due(&st, set, *now) {
		t.Fatal("not due")
	}
	// A failure: one warning, not repeated.
	st.LastTry, st.LastError = *now, "can't reach the VPS"
	s.CheckAlerts(t.Context(), &st, set)
	s.CheckAlerts(t.Context(), &st, set)
	if len(*alerts) != 1 || !strings.HasPrefix((*alerts)[0], "warning:") {
		t.Fatalf("%v", *alerts)
	}
	// Stale after 75 minutes without a good copy: one critical alert.
	*now = st.LastOK.Add(76 * time.Minute)
	s.CheckAlerts(t.Context(), &st, set)
	s.CheckAlerts(t.Context(), &st, set)
	if len(*alerts) != 2 || !strings.HasPrefix((*alerts)[1], "error:") {
		t.Fatalf("%v", *alerts)
	}
	if h := HealthOf(&st, set, *now); h.State != "stale" {
		t.Fatalf("%+v", h)
	}
	// Recovery.
	st.LastOK, st.LastTry, st.LastError = *now, *now, ""
	s.CheckAlerts(t.Context(), &st, set)
	if len(*alerts) != 3 || !strings.HasPrefix((*alerts)[2], "info:") {
		t.Fatalf("%v", *alerts)
	}
	// No schedule while taken over or unconfigured.
	st.Mode = ModeTakenOver
	if Due(&st, set, now.Add(time.Hour)) || HealthOf(&st, set, *now).State != "takenover" {
		t.Fatal("taken over")
	}
	if HealthOf(&Status{}, set, *now).State != "unconfigured" {
		t.Fatal("unconfigured")
	}
	// History.
	s.RecordSync(t.Context(), SyncRow{StartedAt: *now, FinishedAt: *now, OK: true, Bytes: 9, Version: "0.83.1"})
	s.RecordSync(t.Context(), SyncRow{StartedAt: *now, FinishedAt: *now, Error: "x"})
	h, err := s.History(t.Context(), 10)
	if err != nil || len(h) != 2 || h[0].OK || !h[1].OK {
		t.Fatalf("%+v %v", h, err)
	}
}

func TestVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
		ok   bool
	}{{"0.83.1", "0.83.1", 0, true}, {"v0.84.0", "0.83.1", 1, true}, {"0.83", "0.83.1", -1, true}, {"latest", "0.83.1", 0, false}} {
		got, ok := CompareVersions(c.a, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("%s vs %s: %d %v", c.a, c.b, got, ok)
		}
	}
	if _, newer := VersionNote("0.90.0"); !newer {
		t.Fatal("newer")
	}
	if n, newer := VersionNote(StandbyVersion); n != "" || newer {
		t.Fatal("same")
	}
}

func TestTakeOverOrderAndChecks(t *testing.T) {
	s, _, _ := testService(t)
	b := &fakeBackend{st: configured(), dnsName: testHost, peers: [][2]int{{5, 2}, {5, 5}}}
	args := TakeOverArgs{Confirm: testHost, By: "admin"}
	// No public address yet; wrong confirmation; DNS not adopted.
	if _, err := s.TakeOver(t.Context(), b, args, nil); err == nil || !strings.Contains(err.Error(), "public IPv4") {
		t.Fatalf("%v", err)
	}
	s.SaveSettings(t.Context(), Settings{IntervalMinutes: 15, AutoSync: true, PublicIPv4: "203.0.113.5"})
	if _, err := s.TakeOver(t.Context(), b, TakeOverArgs{Confirm: "vpn"}, nil); err == nil {
		t.Fatal("no confirmation")
	}
	b.dnsName = ""
	if _, err := s.TakeOver(t.Context(), b, args, nil); err == nil || !strings.Contains(err.Error(), "DNS") {
		t.Fatalf("%v", err)
	}
	b.dnsName, b.aaaa = testHost, true
	if _, err := s.TakeOver(t.Context(), b, args, nil); err == nil || !strings.Contains(err.Error(), "AAAA") {
		t.Fatalf("%v", err)
	}
	b.aaaa = false
	// A VPS on a newer NetBird needs the acknowledgement.
	b.st.Snapshots[0].Info.Version = "0.90.0"
	if _, err := s.TakeOver(t.Context(), b, TakeOverArgs{Confirm: testHost, SkipFinalSync: true}, nil); !errors.Is(err, ErrVersion) {
		t.Fatalf("%v", err)
	}
	b.st.Snapshots[0].Info.Version = "0.83.1"
	if len(b.steps) != 0 {
		t.Fatalf("steps ran before the checks passed: %v", b.steps)
	}
	// The VPS is down: the last copy fails, the saved one is used.
	b.fail = map[string]error{"sync": errors.New("can't reach the VPS")}
	rec, err := s.TakeOver(t.Context(), b, args, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sync", "stage " + testHost, "up", "network open", "dns-A 203.0.113.5"}
	if strings.Join(b.steps, ",") != strings.Join(want, ",") {
		t.Fatalf("%v", b.steps)
	}
	if rec.FinalSync || rec.FinalSyncError == "" || !rec.DNSChanged || rec.PeersConnected != 5 || rec.PeersTotal != 5 || rec.By != "admin" {
		t.Fatalf("%+v", rec)
	}
	if got, _ := s.Takeover(t.Context()); got == nil || !got.DNSChanged {
		t.Fatal("record not saved")
	}
}

func TestTakeOverUndoesLocalSteps(t *testing.T) {
	s, _, _ := testService(t)
	s.SaveSettings(t.Context(), Settings{IntervalMinutes: 15, AutoSync: true, PublicIPv4: "203.0.113.5"})
	for failing, wantSteps := range map[string]string{
		"up":      "stage,up,stop,unstage",
		"network": "stage,up,network,stop,unstage",
		"dns-A":   "stage,up,network,dns-A,network,stop,unstage",
	} {
		b := &fakeBackend{st: configured(), dnsName: testHost, fail: map[string]error{failing: errors.New("boom")}}
		_, err := s.TakeOver(t.Context(), b, TakeOverArgs{Confirm: testHost, SkipFinalSync: true}, nil)
		if err == nil {
			t.Fatalf("%s: no error", failing)
		}
		var got []string
		for _, st := range b.steps {
			got = append(got, strings.Fields(st)[0])
		}
		if strings.Join(got, ",") != wantSteps {
			t.Errorf("%s failing: %v", failing, got)
		}
		if b.st.Mode != ModeStandby {
			t.Errorf("%s failing: left %s", failing, b.st.Mode)
		}
	}
}

func TestHandBack(t *testing.T) {
	s, _, _ := testService(t)
	b := &fakeBackend{st: configured(), vps: VPSStatus{Running: true, RestoreAllowed: true, Hostname: testHost, Version: "0.83.1"}}
	if _, err := s.HandBack(t.Context(), b, HandBackArgs{Confirm: testHost, AcceptSplitBrain: true}, nil); err == nil {
		t.Fatal("handed back without a take-over")
	}
	b.st.Mode = ModeTakenOver
	s.saveTakeover(t.Context(), &TakeoverRecord{DNSChanged: true})
	if _, err := s.HandBack(t.Context(), b, HandBackArgs{Confirm: testHost}, nil); err == nil {
		t.Fatal("no split-brain acknowledgement")
	}
	b.vps.RestoreAllowed = false
	if _, err := s.HandBack(t.Context(), b, HandBackArgs{Confirm: testHost, AcceptSplitBrain: true}, nil); err == nil || !strings.Contains(err.Error(), "allow-handback") {
		t.Fatalf("%v", err)
	}
	if strings.Join(b.steps, ",") != "vps" {
		t.Fatalf("changed something before checking the VPS: %v", b.steps)
	}
	b.vps.RestoreAllowed, b.steps = true, nil
	// The VPS refuses the upload: the standby runs again, DNS untouched.
	b.fail = map[string]error{"handback": errors.New("integrity check failed")}
	if _, err := s.HandBack(t.Context(), b, HandBackArgs{Confirm: testHost, AcceptSplitBrain: true}, nil); err == nil {
		t.Fatal("no error")
	}
	if strings.Join(b.steps, ",") != "vps,stop,handback "+testHost+",up" {
		t.Fatalf("%v", b.steps)
	}
	b.fail, b.steps = nil, nil
	res, err := s.HandBack(t.Context(), b, HandBackArgs{Confirm: testHost, AcceptSplitBrain: true}, nil)
	if err != nil || res.VPSMessage != "restored" {
		t.Fatalf("%+v %v", res, err)
	}
	want := "vps,stop,handback " + testHost + ",dns-restore,network close,unstage " + testHost
	if strings.Join(b.steps, ",") != want {
		t.Fatalf("%v", b.steps)
	}
	if got, _ := s.Takeover(t.Context()); got != nil {
		t.Fatal("record kept")
	}
	// Discarding the standby's changes doesn't need the VPS.
	b.st.Mode, b.steps = ModeTakenOver, nil
	s.saveTakeover(t.Context(), &TakeoverRecord{DNSChanged: true})
	b.fail = map[string]error{"vps": errors.New("down")}
	if _, err := s.HandBack(t.Context(), b, HandBackArgs{Confirm: testHost, AcceptSplitBrain: true, Discard: true}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Join(b.steps, ",") != "stop,dns-restore,network close,unstage "+testHost {
		t.Fatalf("%v", b.steps)
	}
}
