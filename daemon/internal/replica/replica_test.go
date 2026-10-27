package replica

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// header builds a stream's first record.
func header(bo binary.ByteOrder, hdrType int, features uint32, objset, flags uint32, from uint64, toname string) []byte {
	b := make([]byte, BeginRecordSize)
	bo.PutUint32(b[0:], 0) // DRR_BEGIN
	bo.PutUint64(b[8:], backupMagic)
	bo.PutUint64(b[16:], uint64(hdrType)|uint64(features)<<2)
	bo.PutUint64(b[24:], 1700000000)
	bo.PutUint32(b[32:], objset)
	bo.PutUint32(b[36:], flags)
	bo.PutUint64(b[40:], 42)
	bo.PutUint64(b[48:], from)
	copy(b[56:], toname)
	return b
}

const label = "hardyos-repl-abc123-20261027T101500Z"

func TestNames(t *testing.T) {
	now := time.Date(2026, 10, 27, 10, 15, 0, 0, time.UTC)
	n := SnapName("abc123", now)
	if n != label {
		t.Fatalf("SnapName = %s", n)
	}
	task, at, ok := ParseSnap(n)
	if !ok || task != "abc123" || !at.Equal(now) {
		t.Fatalf("ParseSnap = %s %v %v", task, at, ok)
	}
	for _, bad := range []string{"hardyos-auto-hourly_2026-01-01-0000", "manual-1", "hardyos-repl-abc123-20261327T101500Z",
		"hardyos-repl-ABC123-20261027T101500Z", "hardyos-repl-abc123-20261027T101500Z/x", "hardyos-repl-ab-20261027T101500Z"} {
		if _, _, ok := ParseSnap(bad); ok {
			t.Errorf("ParseSnap(%q) accepted", bad)
		}
	}
	if ValidSnap(label, "other1") == nil {
		t.Error("another task's snapshot accepted")
	}
	tg := Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindVM, Item: "web", Child: "disk0"}
	if err := tg.Validate(); err != nil {
		t.Fatal(err)
	}
	if tg.Dataset() != "tank/replicas/a1b2c3d4/vm/web/disk0" || tg.ItemDataset() != "tank/replicas/a1b2c3d4/vm/web" {
		t.Fatal(tg.Dataset())
	}
	if tg.Mountpoint() != "/mnt/tank/replicas/a1b2c3d4/vm/web/disk0" {
		t.Fatal(tg.Mountpoint())
	}
	// Names that would leave the confined path, or confuse zfs.
	for _, bad := range []Target{
		{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "../etc"},
		{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "a/b"},
		{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media", Child: "../../other"},
		{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media", Child: "x@snap"},
		{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media", Child: "a/b/c/d"},
		{Pool: "tank", Source: "../x", Kind: KindShare, Item: "media"},
		{Pool: "tank", Source: "a1b2c3d4", Kind: "pool", Item: "media"},
		{Pool: "rpool", Source: "a1b2c3d4", Kind: KindShare, Item: "media"},
		{Pool: "-o", Source: "a1b2c3d4", Kind: KindShare, Item: "media"},
		{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "-x"},
		{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media", Child: "-o"},
	} {
		if bad.Validate() == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestParseBeginAndPolicy(t *testing.T) {
	to := "tank/shares/media@" + label
	ok := Policy{Label: label}
	for _, bo := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b, err := ParseBegin(header(bo, hdrSubstream, FeatureLZ4|FeatureEmbedData|FeatureLargeBlocks|FeatureCompressed, ObjsetFilesystem, 0, 0, to))
		if err != nil {
			t.Fatal(err)
		}
		if b.ToName != to || b.Objset != ObjsetFilesystem || b.Incremental() || b.Label() != label {
			t.Fatalf("%+v", b)
		}
		if err := ok.Check(b); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name string
		rec  []byte
		pol  Policy
		want string
	}{
		{"package stream (-R/-p)", header(binary.LittleEndian, hdrCompound, 0, ObjsetFilesystem, 0, 0, to), ok, "package"},
		{"dedup", header(binary.LittleEndian, hdrSubstream, FeatureDedup, ObjsetFilesystem, 0, 0, to), ok, "dedup"},
		{"holds", header(binary.LittleEndian, hdrSubstream, FeatureHolds, ObjsetFilesystem, 0, 0, to), ok, "holds"},
		{"redacted", header(binary.LittleEndian, hdrSubstream, FeatureRedacted, ObjsetFilesystem, 0, 0, to), ok, "redacted"},
		{"raw", header(binary.LittleEndian, hdrSubstream, FeatureRaw, ObjsetFilesystem, 0, 0, to), ok, "raw"},
		{"unknown feature", header(binary.LittleEndian, hdrSubstream, 1<<12, ObjsetFilesystem, 0, 0, to), ok, "unknown"},
		{"clone", header(binary.LittleEndian, hdrSubstream, 0, ObjsetFilesystem, drrFlagClone, 0, to), ok, "clone"},
		{"other snapshot", header(binary.LittleEndian, hdrSubstream, 0, ObjsetFilesystem, 0, 0, "tank/shares/media@evil"), ok, "not the snapshot"},
		{"full over a replica", header(binary.LittleEndian, hdrSubstream, 0, ObjsetFilesystem, 0, 0, to), Policy{Label: label, Incremental: true}, "only an incremental"},
		{"incremental without a replica", header(binary.LittleEndian, hdrSubstream, 0, ObjsetFilesystem, 0, 7, to), ok, "needs an existing"},
		{"volume over a file system", header(binary.LittleEndian, hdrSubstream, 0, ObjsetVolume, 0, 7, to), Policy{Label: label, Incremental: true, Objset: ObjsetFilesystem}, "volume"},
		{"meta objset", header(binary.LittleEndian, hdrSubstream, 0, 1, 0, 0, to), ok, "unsupported"},
	}
	for _, c := range cases {
		b, err := ParseBegin(c.rec)
		if err == nil {
			err = c.pol.Check(b)
		}
		if err == nil || !strings.Contains(err.Error(), c.want) || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// Raw streams pass only when allowed; resuming streams continue a replica.
	b, _ := ParseBegin(header(binary.LittleEndian, hdrSubstream, FeatureRaw, ObjsetFilesystem, 0, 0, to))
	if err := (Policy{Label: label, AllowRaw: true}).Check(b); err != nil {
		t.Fatal(err)
	}
	b, _ = ParseBegin(header(binary.LittleEndian, hdrSubstream, FeatureResuming, ObjsetFilesystem, 0, 0, to))
	if err := (Policy{Label: label, Incremental: true, Objset: ObjsetFilesystem}).Check(b); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBegin(make([]byte, 100)); err == nil {
		t.Fatal("short record accepted")
	}
	bad := header(binary.LittleEndian, hdrSubstream, 0, ObjsetFilesystem, 0, 0, to)
	binary.LittleEndian.PutUint64(bad[8:], 1)
	if _, err := ParseBegin(bad); err == nil {
		t.Fatal("bad magic accepted")
	}
	long := header(binary.LittleEndian, hdrSubstream, 0, ObjsetFilesystem, 0, 0, strings.Repeat("a", 256))
	if _, err := ParseBegin(long); err == nil {
		t.Fatal("unterminated name accepted")
	}
}

// fakeStarter records commands and plays them: stdin is read whole,
// stdout gets Output.
type fakeStarter struct {
	mu     sync.Mutex
	calls  [][]string
	stdin  [][]byte
	Output []byte
	Fail   error
	block  chan struct{} // when set, commands wait for it (or a kill)
}

type fakeProc struct {
	done   chan struct{}
	err    error
	killed chan struct{}
	once   sync.Once
}

func (p *fakeProc) Wait() error { <-p.done; return p.err }
func (p *fakeProc) Kill()       { p.once.Do(func() { close(p.killed) }) }

func (f *fakeStarter) Start(name string, args []string, stdin io.Reader, stdout, stderr io.Writer) (Proc, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{name}, args...))
	idx := len(f.calls) - 1
	f.stdin = append(f.stdin, nil)
	out, fail, block := f.Output, f.Fail, f.block
	f.mu.Unlock()
	// A real command has its own copy of the descriptors it was given.
	if of, ok := stdout.(*os.File); ok {
		fd, err := syscall.Dup(int(of.Fd()))
		if err != nil {
			return nil, err
		}
		stdout = os.NewFile(uintptr(fd), "stdout")
	}
	p := &fakeProc{done: make(chan struct{}), killed: make(chan struct{})}
	go func() {
		defer close(p.done)
		if block != nil {
			select {
			case <-block:
			case <-p.killed:
				p.err = errors.New("signal: killed")
				if c, ok := stdout.(io.Closer); ok {
					c.Close()
				}
				return
			}
		}
		if stdin != nil {
			b, _ := io.ReadAll(stdin)
			f.mu.Lock()
			f.stdin[idx] = b
			f.mu.Unlock()
		}
		if stdout != nil {
			_, _ = stdout.Write(out)
			if c, ok := stdout.(io.Closer); ok {
				c.Close()
			}
		}
		if fail != nil {
			_, _ = io.WriteString(stderr, fail.Error())
			p.err = fail
		}
	}()
	return p, nil
}

func (f *fakeStarter) Calls() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]string(nil), f.calls...)
}

func waitDone(t *testing.T, m *Manager, id string) *StreamState {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, err := m.Stream(id)
		if err != nil {
			t.Fatal(err)
		}
		if st.Done {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("stream didn't finish")
	return nil
}

func receiverFake() *sysexec.Fake {
	f := &sysexec.Fake{}
	f.On("zfs list -H -o name tank", "tank\n")
	f.On("zfs list -H -o type tank/replicas", "filesystem\n")
	f.On("zfs get -H -p -o value org.hardyos:role tank/replicas", "replicas\n")
	f.On("zfs list -H -o type tank/replicas/a1b2c3d4", "filesystem\n")
	f.On("zfs get -H -p -o value org.hardyos:replica tank/replicas/a1b2c3d4", "a1b2c3d4\n")
	f.On("zfs get -H -p -o value quota tank/replicas/a1b2c3d4", "0\n")
	f.On("zfs list -H -o type tank/replicas/a1b2c3d4/share", "filesystem\n")
	return f
}

func TestRecvConfinedWithOverrides(t *testing.T) {
	f := receiverFake()
	st := &fakeStarter{}
	m := &Manager{Runner: f, Starter: st}
	tg := Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media"}
	rs, w, err := m.Recv(context.Background(), RecvArgs{Target: tg, Task: "abc123", Snapshot: label})
	if err != nil {
		t.Fatal(err)
	}
	// The sender's own name for the dataset is something else entirely.
	stream := append(header(binary.LittleEndian, hdrSubstream, FeatureLZ4, ObjsetFilesystem, 0, 0, "evil/../../etc@"+label), []byte("payload")...)
	if _, err := w.Write(stream); err != nil {
		t.Fatal(err)
	}
	w.Close()
	res := waitDone(t, m, rs.Stream)
	if !res.OK {
		t.Fatal(res.Error)
	}
	calls := st.Calls()
	if len(calls) != 1 {
		t.Fatalf("calls: %v", calls)
	}
	line := strings.Join(calls[0], " ")
	for _, want := range []string{"zfs receive -u -s ", "-o canmount=off", "-o mountpoint=/mnt/tank/replicas/a1b2c3d4/share/media", "-o readonly=on",
		"-o exec=off", "-o setuid=off", "-o devices=off", "-x sharenfs", "-x sharesmb", "-x org.hardyos:share", "-x org.hardyos:vm",
		"-x org.hardyos:services", "-o org.hardyos:replica=a1b2c3d4"} {
		if !strings.Contains(line, want) {
			t.Errorf("missing %q in %s", want, line)
		}
	}
	if !strings.HasSuffix(line, " tank/replicas/a1b2c3d4/share/media@"+label) {
		t.Errorf("target: %s", line)
	}
	if !bytes.Equal(st.stdin[0], stream) {
		t.Error("the stream wasn't passed on unchanged")
	}
	if res.Bytes != int64(len(stream)) {
		t.Errorf("bytes %d", res.Bytes)
	}
}

func TestRecvRefusesBeforeZFS(t *testing.T) {
	to := "x@" + label
	for name, rec := range map[string][]byte{
		"package":   header(binary.LittleEndian, hdrCompound, 0, ObjsetFilesystem, 0, 0, to),
		"raw":       header(binary.LittleEndian, hdrSubstream, FeatureRaw, ObjsetFilesystem, 0, 0, to),
		"wrong":     header(binary.LittleEndian, hdrSubstream, 0, ObjsetFilesystem, 0, 0, "x@hardyos-repl-abc123-20200101T000000Z"),
		"garbage":   bytes.Repeat([]byte{0xff}, BeginRecordSize),
		"truncated": []byte("short"),
	} {
		f := receiverFake()
		st := &fakeStarter{}
		m := &Manager{Runner: f, Starter: st}
		rs, w, err := m.Recv(context.Background(), RecvArgs{Target: Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media"}, Task: "abc123", Snapshot: label})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(rec)
		w.Close()
		res := waitDone(t, m, rs.Stream)
		if res.OK || len(st.Calls()) != 0 {
			t.Errorf("%s: ok=%v calls=%v", name, res.OK, st.Calls())
		}
	}
}

func TestRecvVolumeAndIncremental(t *testing.T) {
	f := receiverFake()
	f.On("zfs list -H -o type tank/replicas/a1b2c3d4/vm", "filesystem\n")
	f.On("zfs list -H -o type tank/replicas/a1b2c3d4/vm/web", "filesystem\n")
	f.On("zfs list -H -o type tank/replicas/a1b2c3d4/vm/web/disk0", "volume\n")
	f.On("zfs get -H -p -o value org.hardyos:replica tank/replicas/a1b2c3d4/vm/web/disk0", "a1b2c3d4\n")
	st := &fakeStarter{}
	m := &Manager{Runner: f, Starter: st}
	tg := Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindVM, Item: "web", Child: "disk0"}
	// A full stream over the existing replica is refused.
	rs, w, err := m.Recv(context.Background(), RecvArgs{Target: tg, Task: "abc123", Snapshot: label})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(header(binary.LittleEndian, hdrSubstream, 0, ObjsetVolume, 0, 0, "p/vms/web/disk0@"+label))
	w.Close()
	if res := waitDone(t, m, rs.Stream); res.OK || !strings.Contains(res.Error, "incremental") {
		t.Fatalf("full stream over a replica: %+v", res)
	}
	rs, w, err = m.Recv(context.Background(), RecvArgs{Target: tg, Task: "abc123", Snapshot: label})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write(header(binary.LittleEndian, hdrSubstream, 0, ObjsetVolume, 0, 99, "p/vms/web/disk0@"+label))
	w.Close()
	if res := waitDone(t, m, rs.Stream); !res.OK {
		t.Fatal(res.Error)
	}
	line := strings.Join(st.Calls()[0], " ")
	for _, want := range []string{"-o volmode=none", "-o readonly=on", "-o refreservation=none", "-x org.hardyos:vm"} {
		if !strings.Contains(line, want) {
			t.Errorf("missing %q in %s", want, line)
		}
	}
	if strings.Contains(line, "canmount") || strings.Contains(line, "sharenfs") {
		t.Errorf("file system properties on a volume: %s", line)
	}
}

func TestRecvChildNeedsParentAndOneAtATime(t *testing.T) {
	f := receiverFake()
	m := &Manager{Runner: f, Starter: &fakeStarter{block: make(chan struct{})}}
	_, _, err := m.Recv(context.Background(), RecvArgs{Target: Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media", Child: "sub"}, Task: "abc123", Snapshot: label})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("child before its parent: %v", err)
	}
	tg := Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media"}
	rs, w, err := m.Recv(context.Background(), RecvArgs{Target: tg, Task: "abc123", Snapshot: label})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, _, err := m.Recv(context.Background(), RecvArgs{Target: tg, Task: "abc123", Snapshot: label}); !errors.Is(err, ErrBusy) {
		t.Fatalf("second receive: %v", err)
	}
	// Cancel ends it (kills the process group, closes the pipe).
	_, _ = w.Write(header(binary.LittleEndian, hdrSubstream, 0, ObjsetFilesystem, 0, 0, "x@"+label))
	time.Sleep(50 * time.Millisecond)
	if err := m.Cancel(rs.Stream); err != nil {
		t.Fatal(err)
	}
	if res := waitDone(t, m, rs.Stream); res.OK || res.Error != "cancelled" {
		t.Fatalf("%+v", res)
	}
}

func TestEnsureLayoutRefusesForeignDatasets(t *testing.T) {
	f := &sysexec.Fake{}
	f.On("zfs list -H -o name tank", "tank\n")
	f.On("zfs list -H -o type tank/replicas", "filesystem\n")
	f.On("zfs get -H -p -o value org.hardyos:role tank/replicas", "-\n")
	m := &Manager{Runner: f, Starter: &fakeStarter{}}
	_, _, err := m.Recv(context.Background(), RecvArgs{Target: Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media"}, Task: "abc123", Snapshot: label})
	if err == nil || !strings.Contains(err.Error(), "isn't HardyOS's replicas") {
		t.Fatal(err)
	}
	// A new layout: created never mounted, read only, with the source's quota.
	f = &sysexec.Fake{}
	f.On("zfs list -H -o name tank", "tank\n")
	f.OnPrefix("zfs create", sysexec.Result{})
	f.OnPrefix("zfs set quota=", sysexec.Result{})
	f.On("zfs get -H -p -o value quota tank/replicas/a1b2c3d4", "0\n")
	m = &Manager{Runner: f, Starter: &fakeStarter{}}
	if err := m.ensureLayout(context.Background(), Target{Pool: "tank", Source: "a1b2c3d4", Kind: KindShare, Item: "media"}, 1<<30); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(f.Lines(), "\n")
	for _, want := range []string{
		"zfs create -o canmount=off -o mountpoint=/mnt/tank/replicas -o readonly=on -o org.hardyos:role=replicas tank/replicas",
		"zfs create -o canmount=off -o org.hardyos:role=replica-source -o org.hardyos:replica=a1b2c3d4 tank/replicas/a1b2c3d4",
		"zfs set quota=1073741824 tank/replicas/a1b2c3d4",
		"zfs create -o canmount=off -o org.hardyos:replica=a1b2c3d4 tank/replicas/a1b2c3d4/share",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in\n%s", want, all)
		}
	}
}

type fakeItems map[string]string

func (f fakeItems) List(context.Context) ([]LocalItem, error) { return nil, nil }
func (f fakeItems) Resolve(_ context.Context, kind, id string) (string, error) {
	if ds, ok := f[kind+"/"+id]; ok {
		return ds, nil
	}
	return "", ErrNotFound
}

func TestSendArgsAndTokens(t *testing.T) {
	f := &sysexec.Fake{}
	ds := "tank/shares/media"
	from := "hardyos-repl-abc123-20261027T100000Z"
	f.On("zfs list -H -o type "+ds+"@"+label, "snapshot\n")
	f.On("zfs list -H -o type "+ds+"@"+from, "snapshot\n")
	f.On("zfs send -n -P -L -e -c -i "+ds+"@"+from+" "+ds+"@"+label, "incremental\tx\ty\t1234\nsize\t1234\n")
	f.On("zfs send -n -v -P -t 1-abc-10-789c", "resume token contents:\nnvlist version: 0\n\ttoname = "+ds+"@"+label+"\nsize\t99\n")
	f.On("zfs send -n -v -P -t 1-abc-10-789d", "resume token contents:\n\ttoname = tank/shares/secret@"+label+"\n")
	st := &fakeStarter{Output: []byte("stream")}
	m := &Manager{Runner: f, Starter: st, Items: fakeItems{"share/media": ds}}
	res, r, err := m.Send(context.Background(), SendArgs{Task: "abc123", Kind: KindShare, ID: "media", Snapshot: label, From: from})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if string(b) != "stream" || res.Estimate != 1234 || res.Snapshot != label {
		t.Fatalf("%q %+v", b, res)
	}
	if got := strings.Join(st.Calls()[0], " "); got != "zfs send -L -e -c -i "+ds+"@"+from+" "+ds+"@"+label {
		t.Fatal(got)
	}
	if s := waitDone(t, m, res.Stream); !s.OK {
		t.Fatal(s.Error)
	}
	// A token naming this snapshot resumes; one naming anything else doesn't.
	res, r, err = m.Send(context.Background(), SendArgs{Task: "abc123", Kind: KindShare, ID: "media", Token: "1-abc-10-789c"})
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	if res.Snapshot != label || strings.Join(st.Calls()[1], " ") != "zfs send -t 1-abc-10-789c" {
		t.Fatalf("%+v %v", res, st.Calls()[1])
	}
	if _, _, err := m.Send(context.Background(), SendArgs{Task: "abc123", Kind: KindShare, ID: "media", Token: "1-abc-10-789d"}); err == nil {
		t.Fatal("a token for another dataset was used")
	}
	if _, _, err := m.Send(context.Background(), SendArgs{Task: "abc123", Kind: KindShare, ID: "media", Token: "1-abc-10-789c; rm -rf /"}); err == nil {
		t.Fatal("a malformed token was used")
	}
	// Snapshots must be this task's.
	if _, _, err := m.Send(context.Background(), SendArgs{Task: "abc123", Kind: KindShare, ID: "media", Snapshot: "manual-1"}); err == nil {
		t.Fatal("a user snapshot was sent")
	}
	if _, _, err := m.Send(context.Background(), SendArgs{Task: "abc123", Kind: KindShare, ID: "other", Snapshot: label}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown item: %v", err)
	}
}

func TestPruneKeepsCommonAndOthers(t *testing.T) {
	ds := "tank/vms/web"
	snap := func(task string, h int) string {
		return SnapName(task, time.Date(2026, 10, 27, h, 0, 0, 0, time.UTC))
	}
	var list []string
	for h := 1; h <= 5; h++ {
		list = append(list, ds+"@"+snap("abc123", h))
		if h <= 3 { // the disk missed the last two runs
			list = append(list, ds+"/disk0@"+snap("abc123", h))
		}
	}
	list = append(list, ds+"@"+snap("zzz999", 1), ds+"@vm-20261027-010000", ds+"@hardyos-auto-daily_2026-10-27-0000", ds+"/disk0@manual")
	f := &sysexec.Fake{}
	f.On("zfs list -H -o name -t snapshot -r "+ds, strings.Join(list, "\n")+"\n")
	f.On("zfs list -H -o name,type -r -t filesystem,volume "+ds, ds+"\tfilesystem\n"+ds+"/disk0\tvolume\n")
	f.OnPrefix("zfs destroy", sysexec.Result{})
	m := &Manager{Runner: f, Items: fakeItems{"vm/web": ds}}
	res, err := m.Prune(context.Background(), PruneArgs{Task: "abc123", Kind: KindVM, ID: "web", Keep: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Newest common is hour 3 (kept); 4 and 5 are newer than that (kept);
	// 1 and 2 go, from every dataset that has them, one by one.
	want := []string{snap("abc123", 1), snap("abc123", 2)}
	if strings.Join(res.Deleted, ",") != strings.Join(want, ",") {
		t.Fatalf("deleted %v", res.Deleted)
	}
	var destroyed []string
	for _, l := range f.Lines() {
		if strings.HasPrefix(l, "zfs destroy") {
			destroyed = append(destroyed, l)
			if strings.Contains(l, " -r") || strings.Contains(l, "zzz999") || strings.Contains(l, "auto") || strings.Contains(l, "manual") || strings.Contains(l, "vm-2026") {
				t.Errorf("destroyed the wrong thing: %s", l)
			}
		}
	}
	if len(destroyed) != 4 {
		t.Errorf("destroys: %v", destroyed)
	}
	// Forgetting a task removes all of its snapshots, still only its own.
	f.Calls = nil
	res, err = m.Prune(context.Background(), PruneArgs{Task: "abc123", Kind: KindVM, ID: "web", Forget: true})
	if err != nil || len(res.Deleted) != 5 {
		t.Fatalf("%v %v", res, err)
	}
}

func TestDeleteSourceNeedsConfirmation(t *testing.T) {
	f := &sysexec.Fake{}
	f.On("zfs list -H -o type tank/replicas/a1b2c3d4", "filesystem\n")
	f.On("zfs get -H -p -o value org.hardyos:role tank/replicas", "replicas\n")
	f.On("zfs get -H -p -o value org.hardyos:replica tank/replicas/a1b2c3d4", "a1b2c3d4\n")
	f.OnPrefix("zfs destroy", sysexec.Result{})
	m := &Manager{Runner: f}
	if err := m.DeleteSource(context.Background(), DeleteSourceArgs{Pool: "tank", Source: "a1b2c3d4"}); err == nil {
		t.Fatal("deleted without confirmation")
	}
	if err := m.DeleteSource(context.Background(), DeleteSourceArgs{Pool: "tank", Source: "a1b2c3d4", Confirm: "a1b2c3d4"}); err != nil {
		t.Fatal(err)
	}
	if l := f.Lines(); l[len(l)-1] != "zfs destroy -r tank/replicas/a1b2c3d4" {
		t.Fatal(l)
	}
}

func TestBrowsePath(t *testing.T) {
	for in, want := range map[string]string{"": ".", "/": ".", "a/b": "a/b", "/a/../b": "b", "a/./b/": "a/b", "../../etc": "etc"} {
		got, err := cleanBrowsePath(in)
		if err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	dir := t.TempDir()
	res, err := listIn(dir, ".")
	if err != nil || len(res.Entries) != 0 {
		t.Fatal(res, err)
	}
	if _, err := listIn(dir, "missing"); err == nil {
		t.Fatal("missing folder listed")
	}
}
