package replica

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

var lim = Limits{QuotaBytes: 1 << 30}

func TestRecvNeedsQuotaAndKeepsSystemRoom(t *testing.T) {
	f := receiverFake()
	m := &Manager{Runner: f, Starter: &fakeStarter{}}
	tg := Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media"}
	if _, _, err := m.Recv(context.Background(), RecvArgs{Target: tg, Task: "abc123", Snapshot: label}); err == nil || !strings.Contains(err.Error(), "space limit") {
		t.Fatalf("no quota: %v", err)
	}
	f.On("zfs get -H -p -o value type tank/system", "filesystem\n")
	f.On("zfs get -H -p -o value reservation tank/system", "0\n")
	m.Now = func() time.Time { return time.Date(2026, 10, 27, 10, 20, 0, 0, time.UTC) }
	_, w, err := m.Recv(context.Background(), RecvArgs{Target: tg, Limits: lim, Task: "abc123", Snapshot: label})
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if !strings.Contains(strings.Join(f.Lines(), "\n"), fmt.Sprintf("zfs set reservation=%d tank/system", SystemReserve)) {
		t.Fatal("no reservation kept for the system dataset")
	}
}

func TestRecvLimits(t *testing.T) {
	now := time.Date(2026, 10, 27, 10, 20, 0, 0, time.UTC)
	tg := Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media"}
	ds := tg.Dataset()
	setup := func() (*sysexec.Fake, *Manager) {
		f := &sysexec.Fake{}
		f.On("zfs list -H -o name tank", "tank\n")
		f.On("zfs list -H -o type tank/replicas", "filesystem\n")
		f.On("zfs get -H -p -o value org.hardyos:role tank/replicas", "replicas\n")
		f.On("zfs list -H -o type tank/replicas/a1b2c3d4", "filesystem\n")
		f.On("zfs get -H -p -o value org.hardyos:replica tank/replicas/a1b2c3d4", "a1b2c3d4\n")
		f.On("zfs get -H -p -o value quota tank/replicas/a1b2c3d4", "1073741824\n")
		f.On("zfs list -H -o type tank/replicas/a1b2c3d4/share", "filesystem\n")
		return f, &Manager{Runner: f, Starter: &fakeStarter{}, Now: func() time.Time { return now }}
	}
	// Too many datasets or snapshots from this source.
	f, m := setup()
	f.On("zfs list -H -o name -r -t filesystem,volume tank/replicas/a1b2c3d4", "a\nb\nc\n")
	f.On("zfs list -H -o name -r -t snapshot tank/replicas/a1b2c3d4", "")
	if _, _, err := m.Recv(context.Background(), RecvArgs{Target: tg, Limits: Limits{QuotaBytes: 1 << 30, MaxDatasets: 3}, Task: "abc123", Snapshot: label}); err == nil || !strings.Contains(err.Error(), "datasets") {
		t.Fatalf("dataset limit: %v", err)
	}
	f, m = setup()
	f.On("zfs list -H -o name -r -t filesystem,volume tank/replicas/a1b2c3d4", "")
	f.On("zfs list -H -o name -r -t snapshot tank/replicas/a1b2c3d4", "x@1\nx@2\n")
	if _, _, err := m.Recv(context.Background(), RecvArgs{Target: tg, Limits: Limits{QuotaBytes: 1 << 30, MaxSnapshots: 2}, Task: "abc123", Snapshot: label}); err == nil || !strings.Contains(err.Error(), "snapshots") {
		t.Fatalf("snapshot limit: %v", err)
	}
	// A label from the future.
	f, m = setup()
	f.OnPrefix("zfs list -H -o name -r -t ", sysexec.Result{})
	if _, _, err := m.Recv(context.Background(), RecvArgs{Target: tg, Limits: lim, Task: "abc123", Snapshot: "hardyos-repl-abc123-20301027T101500Z"}); err == nil || !strings.Contains(err.Error(), "future") {
		t.Fatalf("future label: %v", err)
	}
	// Over an existing replica: only newer snapshots, and not sooner than
	// the minimum interval after the last one arrived.
	f, m = setup()
	f.OnPrefix("zfs list -H -o name -r -t ", sysexec.Result{})
	f.On("zfs list -H -o type "+ds, "filesystem\n")
	f.On("zfs get -H -p -o value org.hardyos:replica "+ds, "a1b2c3d4\n")
	last := "hardyos-repl-abc123-20261027T101000Z"
	f.On("zfs list -H -p -t snapshot -o name,guid,creation -d 1 "+ds, ds+"@"+last+"\t1\t1\n")
	f.On("zfs get -H -p -o value org.hardyos:received "+ds+"@"+last, fmt.Sprint(now.Add(-5*time.Minute).Unix())+"\n")
	if _, _, err := m.Recv(context.Background(), RecvArgs{Target: tg, Limits: lim, Task: "abc123", Snapshot: "hardyos-repl-abc123-20261027T100000Z"}); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("older label: %v", err)
	}
	if _, _, err := m.Recv(context.Background(), RecvArgs{Target: tg, Limits: Limits{QuotaBytes: 1 << 30, MinIntervalMinutes: 60}, Task: "abc123", Snapshot: label}); err == nil || !strings.Contains(err.Error(), "every 60 minutes") {
		t.Fatalf("min interval: %v", err)
	}
	_, w, err := m.Recv(context.Background(), RecvArgs{Target: tg, Limits: Limits{QuotaBytes: 1 << 30, MinIntervalMinutes: 1}, Task: "abc123", Snapshot: label})
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
}

func TestReceivedSnapshotsAreMarked(t *testing.T) {
	f := receiverFake()
	now := time.Date(2026, 10, 27, 10, 20, 0, 0, time.UTC)
	m := &Manager{Runner: f, Starter: &fakeStarter{}, Now: func() time.Time { return now }}
	tg := Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media"}
	rs, w, err := m.Recv(context.Background(), RecvArgs{Target: tg, Limits: lim, Task: "abc123", Snapshot: label})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(header(binary.LittleEndian, hdrSubstream, 0, ObjsetFilesystem, 0, 0, "x@"+label))
	w.Close()
	if st := waitDone(t, m, rs.Stream); !st.OK {
		t.Fatal(st.Error)
	}
	want := fmt.Sprintf("zfs set org.hardyos:received=%d %s@%s", now.Unix(), tg.Dataset(), label)
	if !strings.Contains(strings.Join(f.Lines(), "\n"), want) {
		t.Fatalf("missing %q", want)
	}
}

func TestPruneKeepsYoungSnapshots(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	ds := "tank/replicas/a1b2c3d4/share/media"
	var list, recv []string
	for d := 1; d <= 10; d++ {
		at := now.AddDate(0, 0, -d)
		l := SnapName("abc123", at)
		list = append(list, ds+"@"+l)
		recv = append(recv, fmt.Sprintf("%s@%s\t%d", ds, l, at.Unix()))
	}
	// One without a record of when it arrived: kept.
	odd := SnapName("abc123", now.AddDate(0, 0, -20))
	list = append(list, ds+"@"+odd)
	recv = append(recv, ds+"@"+odd+"\t-")
	f := &sysexec.Fake{}
	f.On("zfs list -H -o type "+ds, "filesystem\n")
	f.On("zfs get -H -p -o value org.hardyos:replica "+ds, "a1b2c3d4\n")
	f.On("zfs list -H -o name -t snapshot -r "+ds, strings.Join(list, "\n")+"\n")
	f.On("zfs list -H -o name,type -r -t filesystem,volume "+ds, ds+"\tfilesystem\n")
	f.On("zfs list -H -p -o name,org.hardyos:received -t snapshot -r "+ds, strings.Join(recv, "\n")+"\n")
	f.OnPrefix("zfs destroy", sysexec.Result{})
	m := &Manager{Runner: f, Now: func() time.Time { return now }}
	// The source asks to keep 1; 7 days' worth stay anyway.
	res, err := m.PruneReplica(context.Background(), RecvPruneArgs{Target: Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media"}, Task: "abc123", Keep: 1, MinAgeDays: 7})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Deleted) != 4 { // days 7 (exactly the minimum), 8, 9, 10
		t.Fatalf("deleted %v", res.Deleted)
	}
	for _, d := range res.Deleted {
		if d == odd {
			t.Fatal("pruned a snapshot without a received time")
		}
		if _, at, _ := ParseSnap(d); now.Sub(at) < 7*24*time.Hour {
			t.Fatalf("pruned a young snapshot %s", d)
		}
	}
}

func TestStreamCapsAndPayload(t *testing.T) {
	var r streams
	for i := 0; i < MaxStreamsPerKind; i++ {
		if _, err := r.add(fmt.Sprint("t", i), kindRecv); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.add("more", kindRecv); !errors.Is(err, ErrTooMany) {
		t.Fatalf("per kind: %v", err)
	}
	for i := 0; i < MaxStreams-MaxStreamsPerKind; i++ {
		if _, err := r.add("", []string{kindSend, kindRestore}[i%2]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.add("", kindSend); !errors.Is(err, ErrTooMany) {
		t.Fatalf("global: %v", err)
	}
	rec := header(binary.LittleEndian, hdrSubstream, 0, ObjsetFilesystem, 0, 0, "x@"+label)
	binary.LittleEndian.PutUint32(rec[4:], MaxBeginPayload+1)
	b, _ := ParseBegin(rec)
	if err := (Policy{Label: label}).Check(b); err == nil {
		t.Fatal("huge first-record payload accepted")
	}
}

type failingRestorer struct{ fakeRestorer }

func (failingRestorer) VMAdopt(context.Context, string) ([]string, error) {
	return nil, errors.New("libvirt refused")
}

type fakeRestorer struct{}

func (fakeRestorer) ShareProps(context.Context, string, string, string) ([]string, error) {
	return []string{"org.hardyos:share=1"}, nil
}
func (fakeRestorer) ShareAdopt(context.Context, string, string) error  { return nil }
func (fakeRestorer) VMFree(context.Context, string) error              { return nil }
func (fakeRestorer) VMAdopt(context.Context, string) ([]string, error) { return []string{"x"}, nil }
func (fakeRestorer) AppsPool(context.Context) (string, error)          { return "tank", nil }
func (fakeRestorer) AppAdopt(context.Context, string) error            { return nil }

// A restore whose adoption fails stays marked, so RestoreAbort removes it.
func TestRestoreMarkerStaysUntilAdopted(t *testing.T) {
	top := "tank/vms/web"
	f := &sysexec.Fake{}
	f.On("zfs get -H -p -o value org.hardyos:restoring "+top, "1\n")
	f.On("zfs list -H -o name,type -r -t filesystem,volume "+top, top+"\tfilesystem\n"+top+"/disk0\tvolume\n")
	f.On("zfs get -H -p -o value mounted "+top, "yes\n")
	f.OnPrefix("zfs ", sysexec.Result{})
	m := &Manager{Runner: f, Restore: failingRestorer{}}
	if _, err := m.RestoreFinish(context.Background(), RestoreFinishArgs{Kind: KindVM, ID: "web", Pool: "tank"}); err == nil {
		t.Fatal("adoption failure ignored")
	}
	for _, l := range f.Lines() {
		if strings.HasPrefix(l, "zfs inherit org.hardyos:restoring") {
			t.Fatal("marker cleared before adoption")
		}
	}
	// An app (or shared folder) restore never brings volumes.
	f2 := &sysexec.Fake{}
	f2.On("zfs get -H -p -o value org.hardyos:restoring tank/apps/x", "1\n")
	f2.On("zfs list -H -o name,type -r -t filesystem,volume tank/apps/x", "tank/apps/x\tfilesystem\ntank/apps/x/v\tvolume\n")
	f2.OnPrefix("zfs ", sysexec.Result{})
	m2 := &Manager{Runner: f2, Restore: fakeRestorer{}}
	if _, err := m2.RestoreFinish(context.Background(), RestoreFinishArgs{Kind: KindApp, ID: "x"}); err == nil || !strings.Contains(err.Error(), "volumes") {
		t.Fatalf("volume under an app: %v", err)
	}
}
