package snapshots

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestSlot(t *testing.T) {
	cases := []struct {
		kind Kind
		now  string
		want string
	}{
		{Hourly, "2026-10-26T13:00:00Z", "2026-10-26T13:00:00Z"},
		{Hourly, "2026-10-26T13:59:59Z", "2026-10-26T13:00:00Z"},
		{Hourly, "2026-12-31T23:30:00Z", "2026-12-31T23:00:00Z"},
		{Daily, "2026-10-26T00:00:00Z", "2026-10-26T00:00:00Z"},
		{Daily, "2026-10-26T23:59:00Z", "2026-10-26T00:00:00Z"},
		{Daily, "2027-01-01T00:00:30Z", "2027-01-01T00:00:00Z"},
		// 2026-10-26 is a Monday.
		{Weekly, "2026-10-26T00:00:00Z", "2026-10-26T00:00:00Z"},
		{Weekly, "2026-10-25T23:59:00Z", "2026-10-19T00:00:00Z"}, // Sunday
		{Weekly, "2026-11-01T12:00:00Z", "2026-10-26T00:00:00Z"},
		{Weekly, "2027-01-03T12:00:00Z", "2026-12-28T00:00:00Z"}, // across a year
		{Monthly, "2026-10-26T13:00:00Z", "2026-10-01T00:00:00Z"},
		{Monthly, "2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z"},
		{Monthly, "2027-01-31T23:59:00Z", "2027-01-01T00:00:00Z"},
		{Monthly, "2028-02-29T10:00:00Z", "2028-02-01T00:00:00Z"},
	}
	for _, c := range cases {
		if got := Slot(c.kind, at(c.now)); !got.Equal(at(c.want)) || got.Location() != time.UTC {
			t.Errorf("Slot(%s, %s) = %s, want %s", c.kind, c.now, got, c.want)
		}
	}
	// Local time zones and DST never matter: slots are UTC. 2026-03-29 01:30 UTC
	// is the hour Europe/Berlin skips.
	berlin := time.FixedZone("CEST", 2*3600)
	if got := Slot(Hourly, time.Date(2026, 3, 29, 3, 30, 0, 0, berlin)); !got.Equal(at("2026-03-29T01:00:00Z")) {
		t.Errorf("hourly in CEST = %s", got)
	}
	if got := Slot(Daily, time.Date(2026, 10, 27, 0, 30, 0, 0, berlin)); !got.Equal(at("2026-10-26T00:00:00Z")) {
		t.Errorf("daily just after local midnight = %s (the UTC day is still the 26th)", got)
	}
}

func TestNameParse(t *testing.T) {
	n := Name(Hourly, at("2026-10-26T13:00:00Z"))
	if n != "hardyos-auto-hourly_2026-10-26-1300" {
		t.Fatalf("name = %s", n)
	}
	if k, slot, ok := Parse(n); !ok || k != Hourly || !slot.Equal(at("2026-10-26T13:00:00Z")) {
		t.Errorf("parse = %s %s %v", k, slot, ok)
	}
	if n := Name(Monthly, time.Date(2026, 11, 1, 1, 0, 0, 0, time.FixedZone("x", 3600))); n != "hardyos-auto-monthly_2026-11-01-0000" {
		t.Errorf("name in UTC = %s", n)
	}
	for _, bad := range []string{
		"hardyos-auto-hourly_2026-10-26-1330",  // not a slot
		"hardyos-auto-daily_2026-10-26-1300",   // a daily isn't at 13:00
		"hardyos-auto-weekly_2026-10-27-0000",  // a Tuesday
		"hardyos-auto-monthly_2026-10-02-0000", // not the 1st
		"hardyos-auto-hourly_2026-02-30-0000",  // no such day
		"hardyos-auto-yearly_2026-01-01-0000",
		"hardyos-auto-hourly_2026-10-26-1300x",
		"xhardyos-auto-hourly_2026-10-26-1300",
		"hardyos-update-20261026-130000",
		"manual-2026-10-26-1300",
		"hardyos-auto-hourly-2026-10-26-1300",
	} {
		if _, _, ok := Parse(bad); ok {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
	if KindOf("hardyos-auto-weekly_2026-10-26-0000", "-") != "weekly" || KindOf("before-upgrade", "manual") != "manual" || KindOf("zrepl_1", "-") != "other" {
		t.Error("KindOf")
	}
}

func TestPrune(t *testing.T) {
	var labels []string
	start := at("2026-10-25T20:00:00Z")
	for i := 0; i < 30; i++ {
		labels = append(labels, Name(Hourly, start.Add(time.Duration(i)*time.Hour)))
	}
	labels = append(labels,
		Name(Daily, at("2026-10-24T00:00:00Z")), Name(Daily, at("2026-10-25T00:00:00Z")), Name(Daily, at("2026-10-26T00:00:00Z")),
		Name(Weekly, at("2026-10-19T00:00:00Z")), Name(Weekly, at("2026-10-26T00:00:00Z")),
		Name(Monthly, at("2026-09-01T00:00:00Z")), Name(Monthly, at("2026-10-01T00:00:00Z")),
		"before-upgrade", "hardyos-update-20261026-130000", "hardyos-auto-hourly_2026-10-26-1330",
	)
	got := Prune(labels, shares.Snapshots{Hourly: 24, Daily: 2, Weekly: 0, Monthly: 6})
	sort.Strings(got)
	want := []string{
		"hardyos-auto-daily_2026-10-24-0000",
		"hardyos-auto-hourly_2026-10-25-2000", "hardyos-auto-hourly_2026-10-25-2100", "hardyos-auto-hourly_2026-10-25-2200",
		"hardyos-auto-hourly_2026-10-25-2300", "hardyos-auto-hourly_2026-10-26-0000", "hardyos-auto-hourly_2026-10-26-0100",
		"hardyos-auto-weekly_2026-10-19-0000", "hardyos-auto-weekly_2026-10-26-0000",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prune =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// fakeShares serves a fixed list.
type fakeShares struct {
	list []shares.Share
	err  error
}

func (f *fakeShares) List(context.Context) ([]shares.Share, error) { return f.list, f.err }
func (f *fakeShares) Get(_ context.Context, id string) (*shares.Share, error) {
	for i := range f.list {
		if f.list[i].ID == id {
			return &f.list[i], nil
		}
	}
	return nil, shares.ErrNotFound
}

func share(id string, mounted bool, keep shares.Snapshots) shares.Share {
	sv := shares.DefaultServices()
	sv.Snapshots = keep
	return shares.Share{ID: id, Name: strings.ToUpper(id[:1]) + id[1:], Pool: "tank", Dataset: "tank/shares/" + id,
		Path: "/mnt/tank/shares/" + id, Mounted: mounted, Services: sv}
}

const listCmd = "zfs list -Hp -t snapshot -o name,used,refer,creation,org.hardyos:snapshot -s creation -d 1 "

func snapRows(ds string, labels ...string) string {
	var b strings.Builder
	for i, l := range labels {
		b.WriteString(ds + "@" + l + "\t1024\t2048\t" + "17615" + string(rune('0'+i%10)) + "00000\t-\n")
	}
	return b.String()
}

func TestTick(t *testing.T) {
	now := at("2026-11-02T00:00:40Z") // Monday 2 Nov: every kind is due
	fs := &fakeShares{list: []shares.Share{
		share("media", true, shares.Snapshots{Hourly: 2, Daily: 1, Weekly: 1, Monthly: 0}),
		share("locked", false, shares.Snapshots{Hourly: 24}),
		share("off", true, shares.Snapshots{}),
	}}
	f := &sysexec.Fake{}
	f.On(listCmd+"tank/shares/media", snapRows("tank/shares/media",
		"hardyos-auto-hourly_2026-11-01-2200", "hardyos-auto-hourly_2026-11-01-2300",
		"hardyos-auto-daily_2026-11-01-0000", "hardyos-auto-monthly_2026-10-01-0000", "keep-me"))
	f.On(listCmd+"tank/shares/off", snapRows("tank/shares/off", "hardyos-auto-hourly_2026-11-01-2300", "mine"))
	f.OnPrefix("zfs snapshot ", sysexec.Result{})
	f.OnPrefix("zfs destroy ", sysexec.Result{})
	m := &Manager{Runner: f, Shares: fs, Log: quiet, Now: func() time.Time { return now }}
	m.Tick(context.Background())

	got := f.Lines()
	want := []string{
		listCmd + "tank/shares/media",
		"zfs snapshot tank/shares/media@hardyos-auto-hourly_2026-11-02-0000 tank/shares/media@hardyos-auto-daily_2026-11-02-0000 tank/shares/media@hardyos-auto-weekly_2026-11-02-0000",
		"zfs destroy tank/shares/media@hardyos-auto-hourly_2026-11-01-2200",
		"zfs destroy tank/shares/media@hardyos-auto-daily_2026-11-01-0000",
		"zfs destroy tank/shares/media@hardyos-auto-monthly_2026-10-01-0000",
		listCmd + "tank/shares/off",
		"zfs destroy tank/shares/off@hardyos-auto-hourly_2026-11-01-2300",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("commands:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// Same minute again, and later in the same hour: nothing to do, not even a listing.
	f.Calls = nil
	m.Tick(context.Background())
	now = now.Add(40 * time.Minute)
	m.Tick(context.Background())
	if len(f.Calls) != 0 {
		t.Errorf("idle ticks ran %v", f.Lines())
	}

	// The next hour: one hourly. The listing now shows what the first tick made.
	now = at("2026-11-02T01:00:05Z")
	f.On(listCmd+"tank/shares/media", snapRows("tank/shares/media",
		"hardyos-auto-hourly_2026-11-01-2300", "keep-me", "hardyos-auto-hourly_2026-11-02-0000",
		"hardyos-auto-daily_2026-11-02-0000", "hardyos-auto-weekly_2026-11-02-0000"))
	m.Tick(context.Background())
	got = f.Lines()
	want = []string{
		listCmd + "tank/shares/media",
		"zfs snapshot tank/shares/media@hardyos-auto-hourly_2026-11-02-0100",
		"zfs destroy tank/shares/media@hardyos-auto-hourly_2026-11-01-2300",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("next hour:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestTickCatchUpOnlyNewest(t *testing.T) {
	// Off from Friday evening to Tuesday afternoon: one of each kind, for
	// the newest slot, nothing back-filled.
	now := at("2026-11-03T15:20:00Z")
	fs := &fakeShares{list: []shares.Share{share("media", true, shares.Snapshots{Hourly: 24, Daily: 14, Weekly: 8, Monthly: 6})}}
	f := &sysexec.Fake{}
	f.On(listCmd+"tank/shares/media", snapRows("tank/shares/media", "hardyos-auto-hourly_2026-10-30-1800", "hardyos-auto-daily_2026-10-30-0000",
		"hardyos-auto-weekly_2026-10-26-0000", "hardyos-auto-monthly_2026-10-01-0000"))
	f.OnPrefix("zfs snapshot ", sysexec.Result{})
	m := &Manager{Runner: f, Shares: fs, Log: quiet, Now: func() time.Time { return now }}
	m.Tick(context.Background())
	want := []string{
		listCmd + "tank/shares/media",
		"zfs snapshot tank/shares/media@hardyos-auto-hourly_2026-11-03-1500 tank/shares/media@hardyos-auto-daily_2026-11-03-0000 tank/shares/media@hardyos-auto-weekly_2026-11-02-0000 tank/shares/media@hardyos-auto-monthly_2026-11-01-0000",
	}
	if got := f.Lines(); !reflect.DeepEqual(got, want) {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
}

func TestTickFailuresAndGoneFolders(t *testing.T) {
	now := at("2026-11-03T15:20:00Z")
	fs := &fakeShares{list: []shares.Share{
		share("gone", true, shares.Snapshots{Hourly: 1}),
		share("media", true, shares.Snapshots{Hourly: 1}),
	}}
	f := &sysexec.Fake{}
	// "gone" was deleted after the listing: zfs says so; media still gets its snapshot.
	f.OnResult(listCmd+"tank/shares/gone", sysexec.Result{ExitCode: 1, Stderr: []byte("cannot open 'tank/shares/gone': dataset does not exist")})
	f.On(listCmd+"tank/shares/media", "")
	f.OnPrefix("zfs snapshot ", sysexec.Result{})
	m := &Manager{Runner: f, Shares: fs, Log: quiet, Now: func() time.Time { return now }}
	m.Tick(context.Background())
	if l := f.Lines(); len(l) != 3 || l[2] != "zfs snapshot tank/shares/media@hardyos-auto-hourly_2026-11-03-1500" {
		t.Fatalf("commands: %v", l)
	}
	// The failed one is tried again next minute; the done one isn't.
	f.Calls = nil
	fs.list = fs.list[1:]
	m.Tick(context.Background())
	if len(f.Calls) != 0 {
		t.Errorf("ran %v", f.Lines())
	}
	if _, ok := m.done["tank/shares/gone"]; ok {
		t.Error("a deleted folder is still remembered")
	}
	// A listing failure of every share (pool exported mid-way) is only logged.
	fs.err = errors.New("zfs list failed")
	m.Tick(context.Background())

	// A failed snapshot is retried.
	fs.err = nil
	fs.list = []shares.Share{share("busy", true, shares.Snapshots{Hourly: 1})}
	f.On(listCmd+"tank/shares/busy", "")
	f.OnResult("zfs snapshot tank/shares/busy@hardyos-auto-hourly_2026-11-03-1500", sysexec.Result{ExitCode: 1, Stderr: []byte("out of space")})
	m.Tick(context.Background())
	f.Calls = nil
	m.Tick(context.Background())
	if len(f.Calls) != 2 {
		t.Errorf("the failed snapshot wasn't retried: %v", f.Lines())
	}
}

func TestLowerCountPrunesAtOnce(t *testing.T) {
	now := at("2026-11-03T15:20:00Z")
	sh := share("media", true, shares.Snapshots{Hourly: 3})
	fs := &fakeShares{list: []shares.Share{sh}}
	f := &sysexec.Fake{}
	f.On(listCmd+"tank/shares/media", snapRows("tank/shares/media", "hardyos-auto-hourly_2026-11-03-1300", "hardyos-auto-hourly_2026-11-03-1400", "hardyos-auto-hourly_2026-11-03-1500"))
	f.OnPrefix("zfs destroy ", sysexec.Result{})
	m := &Manager{Runner: f, Shares: fs, Log: quiet, Now: func() time.Time { return now }}
	m.Tick(context.Background())
	if len(f.Calls) != 1 {
		t.Fatalf("ran %v", f.Lines())
	}
	fs.list[0].Services.Snapshots.Hourly = 1
	m.Tick(context.Background())
	l := f.Lines()
	if len(l) != 4 || l[2] != "zfs destroy tank/shares/media@hardyos-auto-hourly_2026-11-03-1300" || l[3] != "zfs destroy tank/shares/media@hardyos-auto-hourly_2026-11-03-1400" {
		t.Errorf("ran %v", l)
	}
}

func TestManual(t *testing.T) {
	now := at("2026-11-03T15:20:00Z")
	fs := &fakeShares{list: []shares.Share{share("media", true, shares.Snapshots{})}}
	f := &sysexec.Fake{}
	f.On(listCmd+"tank/shares/media", "tank/shares/media@hardyos-auto-hourly_2026-11-03-1500\t0\t2048\t1762182000\t-\n"+
		"tank/shares/media@before-upgrade\t4096\t2048\t1762183000\tmanual\n"+
		"tank/shares/media/child@x\t0\t0\t1762183000\t-\n")
	f.OnPrefix("zfs snapshot ", sysexec.Result{})
	f.OnPrefix("zfs destroy ", sysexec.Result{})
	m := &Manager{Runner: f, Shares: fs, Log: quiet, Now: func() time.Time { return now }}
	ctx := context.Background()

	l, err := m.List(ctx, "media")
	if err != nil || len(l) != 2 || l[0].Name != "before-upgrade" || l[0].Kind != "manual" || l[0].UsedBytes != 4096 || l[1].Kind != "hourly" {
		t.Fatalf("list = %+v %v", l, err)
	}
	if _, err := m.List(ctx, "nope"); !errors.Is(err, shares.ErrNotFound) {
		t.Errorf("list of a missing folder: %v", err)
	}

	var ve *shares.ValidationError
	for _, bad := range []string{"hardyos-auto-hourly_2026-11-03-1600", "Hardyos-Auto-x", "-x", "a b", "a/b", "a@b", strings.Repeat("a", 65), "before-upgrade"} {
		if _, err := m.Create(ctx, "media", bad); !errors.As(err, &ve) {
			t.Errorf("Create(%q) = %v", bad, err)
		}
	}
	f.Calls = nil
	if _, err := m.Create(ctx, "media", ""); err != nil {
		t.Fatal(err)
	}
	if l := f.Lines(); l[1] != "zfs snapshot -o org.hardyos:snapshot=manual tank/shares/media@manual-2026-11-03-1520" {
		t.Errorf("create ran %v", l)
	}

	for _, c := range [][2]string{{"before-upgrade", ""}, {"before-upgrade", "before"}, {"missing", "missing"}, {"x@y", "x@y"}} {
		if err := m.Delete(ctx, "media", c[0], c[1]); !errors.As(err, &ve) {
			t.Errorf("Delete(%q, confirm %q) = %v", c[0], c[1], err)
		}
	}
	f.Calls = nil
	if err := m.Delete(ctx, "media", "before-upgrade", "before-upgrade"); err != nil {
		t.Fatal(err)
	}
	if l := f.Lines(); len(l) != 2 || l[1] != "zfs destroy tank/shares/media@before-upgrade" {
		t.Errorf("delete ran %v", l)
	}
}
