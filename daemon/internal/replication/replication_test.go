package replication

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/replica"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

type notes struct {
	mu sync.Mutex
	l  []Event
}

func (n *notes) Notify(_ context.Context, e Event) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.l = append(n.l, e)
}

func (n *notes) kinds() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var k []string
	for _, e := range n.l {
		k = append(k, e.Kind+":"+e.Severity)
	}
	return strings.Join(k, ",")
}

type node struct {
	svc   *Service
	root  *simRoot
	jobs  *jobs.Manager
	notes *notes
	srv   *httptest.Server
	addr  string

	mu      sync.Mutex
	secrets map[string]string
}

func newNode(t *testing.T, name string) *node {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), name+".db"))
	if err != nil {
		t.Fatal(err)
	}
	jm := &jobs.Manager{DB: db, Workers: 4}
	n := &node{root: newSimRoot(), jobs: jm, notes: &notes{}, secrets: map[string]string{}}
	n.svc = &Service{DB: db, Root: n.root, Jobs: jm, Notifier: n.notes, Hostname: func() string { return name },
		Sealer: &Sealer{Source: secretbox.NewStaticSource()}, Poll: 5 * time.Millisecond,
		Secrets: func(ref string) (string, bool) {
			n.mu.Lock()
			defer n.mu.Unlock()
			v, ok := n.secrets[ref]
			delete(n.secrets, ref)
			return v, ok
		}}
	n.svc.RegisterJobs(jm)
	if err := jm.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if n.srv != nil {
			n.srv.Close()
		}
		cancel()
		jm.Wait()
		db.Close()
	})
	return n
}

// serve starts the receiving side over TLS like Run does.
func (n *node) serve(t *testing.T) {
	t.Helper()
	id, err := n.svc.Identity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n.srv = httptest.NewUnstartedServer(n.svc.Handler())
	n.srv.TLS = n.svc.newServer(id).TLSConfig
	n.srv.StartTLS()
	n.addr = n.srv.Listener.Addr().String()
}

func (n *node) wait(t *testing.T, j *jobs.Job) *jobs.Job {
	t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		got, err := n.jobs.Get(context.Background(), j.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.State.Done() {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job %s didn't finish", j.Kind)
	return nil
}

func (n *node) submit(t *testing.T, kind string, params any) *jobs.Job {
	t.Helper()
	j, err := n.jobs.Submit(context.Background(), kind, kind, params, nil)
	if err != nil {
		t.Fatal(err)
	}
	return n.wait(t, j)
}

func (n *node) run(t *testing.T, task string) *jobs.Job {
	t.Helper()
	j, err := n.svc.RunNow(context.Background(), task, nil)
	if err != nil {
		t.Fatal(err)
	}
	return n.wait(t, j)
}

func pair(t *testing.T, a, b *node) *Target { t.Helper(); return pairOn(t, a, b, "tank") }

// pairOn pairs a with b, b keeping a's replicas on pool.
func pairOn(t *testing.T, a, b *node, pool string) *Target {
	t.Helper()
	ctx := context.Background()
	raw, code := NewCode()
	if _, err := b.svc.OpenPairing(ctx, raw, PairingParams{Pool: pool, QuotaBytes: 1 << 34, MinKeep: 3}); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.secrets["ref1"] = code
	a.mu.Unlock()
	j := a.submit(t, JobPair, PairParams{Address: a2(b.addr), SecretRef: "ref1"})
	if j.State != jobs.Succeeded {
		t.Fatalf("pairing: %s", j.Error)
	}
	l, err := a.svc.Store().Targets(ctx)
	if err != nil || len(l) != 1 {
		t.Fatal(l, err)
	}
	return &l[0]
}

func a2(addr string) string { return addr }

func TestPairing(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "alpha"), newNode(t, "bravo")
	b.serve(t)
	// No code open on B.
	if _, err := a.svc.Pair(ctx, b.addr, FormatCode(make([]byte, 16))); err == nil || !strings.Contains(err.Error(), "no pairing code") {
		t.Fatalf("pairing without a code: %v", err)
	}
	raw, code := NewCode()
	if _, err := b.svc.OpenPairing(ctx, raw, PairingParams{Pool: "tank", QuotaBytes: 1 << 40, MinKeep: 3}); err != nil {
		t.Fatal(err)
	}
	// A wrong code is refused (and counted).
	_, wrong := NewCode()
	if _, err := a.svc.Pair(ctx, b.addr, wrong); err == nil || !strings.Contains(err.Error(), "doesn't match") {
		t.Fatalf("wrong code: %v", err)
	}
	tgt, err := a.svc.Pair(ctx, b.addr, strings.ToLower(strings.ReplaceAll(code, "-", " ")))
	if err != nil {
		t.Fatal(err)
	}
	bid, _ := b.svc.Identity(ctx)
	aid, _ := a.svc.Identity(ctx)
	if tgt.Pin != bid.Pin || tgt.Name != "bravo" {
		t.Fatalf("target %+v", tgt)
	}
	srcs, _ := b.svc.Store().Sources(ctx)
	if len(srcs) != 1 || srcs[0].Pin != aid.Pin || srcs[0].Name != "alpha" || srcs[0].Pool != "tank" || srcs[0].QuotaBytes != 1<<40 || srcs[0].ID != tgt.SourceID {
		t.Fatalf("sources %+v", srcs)
	}
	// The code is used up.
	if _, err := a.svc.Pair(ctx, b.addr, code); err == nil {
		t.Fatal("a code worked twice")
	}
	if name, err := a.svc.TestTarget(ctx, tgt.ID); err != nil || name != "bravo" {
		t.Fatal(name, err)
	}
	// Five wrong codes close a pairing code.
	raw, code = NewCode()
	_, _ = b.svc.OpenPairing(ctx, raw, PairingParams{Pool: "tank", QuotaBytes: 1 << 30})
	c := newNode(t, "charlie")
	for range MaxPairFailures {
		_, wrong := NewCode()
		_, _ = c.svc.Pair(ctx, b.addr, wrong)
	}
	if _, err := c.svc.Pair(ctx, b.addr, code); err == nil {
		t.Fatal("the code still worked after too many wrong tries")
	}
	// A server that isn't paired can't use anything.
	cid, _ := c.svc.Identity(ctx)
	hc := &http.Client{Transport: newTransport(cid, pinCheck(bid.Pin, nil))}
	for _, path := range []string{"/repl/v1/hello", "/repl/v1/items", "/repl/v1/state?kind=share&id=media", "/repl/v1/send?kind=share&id=media&snapshot=x"} {
		resp, err := hc.Get("https://" + b.addr + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
	// Without a client certificate the TLS handshake fails.
	plain := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if resp, err := plain.Get("https://" + b.addr + "/repl/v1/hello"); err == nil {
		resp.Body.Close()
		t.Fatal("a connection without a client certificate was served")
	}
	// A receiver with another key is refused by the sender.
	tgt.Pin = strings.Repeat("0", 64)
	p, _ := a.svc.peer(ctx, tgt)
	if _, err := p.hello(ctx); err == nil || !strings.Contains(err.Error(), "key changed") {
		t.Fatalf("pin mismatch: %v", err)
	}
}

func TestReplicateResumeRestore(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "alpha"), newNode(t, "bravo")
	b.serve(t)
	a.root.addItem(replica.KindShare, "media", "Media")
	a.root.addItem(replica.KindVM, "web", "Web server", replica.Child{Child: "", Type: "filesystem"}, replica.Child{Child: "disk0", Type: "volume"})
	tgt := pair(t, a, b)

	j := a.submit(t, JobTaskCreate, Task{Name: "Nightly", TargetID: tgt.ID, IntervalMinutes: 60, KeepLocal: 2, KeepRemote: 1, Enabled: true,
		Items: []replica.Item{{Kind: replica.KindShare, ID: "media"}, {Kind: replica.KindVM, ID: "web"}}})
	if j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	tasks, _ := a.svc.Store().Tasks(ctx)
	task := tasks[0]
	// The same item can't go to the same server in two tasks.
	j = a.submit(t, JobTaskCreate, Task{Name: "Again", TargetID: tgt.ID, IntervalMinutes: 60, KeepLocal: 2, KeepRemote: 1, Items: []replica.Item{{Kind: replica.KindShare, ID: "media"}}})
	if j.State != jobs.Failed || !strings.Contains(j.Error, "already goes") {
		t.Fatalf("duplicate item: %s %s", j.State, j.Error)
	}

	// First run: full copies.
	if j := a.run(t, task.ID); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	src := tgt.SourceID
	media := "tank/replicas/" + src + "/share/media"
	disk := "tank/replicas/" + src + "/vm/web/disk0"
	b.root.mu.Lock()
	if len(b.root.replicas[media].snaps) != 1 || len(b.root.replicas[disk].snaps) != 1 || b.root.replicas[disk].typ != "volume" {
		t.Fatalf("replicas: %+v", b.root.replicas)
	}
	first := b.root.replicas[media].snaps[0].Name
	b.root.mu.Unlock()
	for _, s := range a.root.sends {
		if s.From != "" || s.Token != "" {
			t.Fatalf("first run wasn't full: %+v", s)
		}
	}
	// Every receive went to the source's own place on B's pool.
	for _, r := range b.root.recvs {
		if r.Pool != "tank" || r.Source != src {
			t.Fatalf("receive outside the source's place: %+v", r)
		}
	}

	// Second run: incremental from the last common snapshot.
	a.root.sends = nil
	if j := a.run(t, task.ID); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	if len(a.root.sends) != 3 || a.root.sends[0].From != first {
		t.Fatalf("second run: %+v", a.root.sends)
	}
	// B keeps max(task's 1, its own minimum 3).
	if p := b.root.pruned[len(b.root.pruned)-1]; p.Keep != 3 || p.Task != task.ID {
		t.Fatalf("prune %+v", p)
	}

	// Third run is cut off half way: it fails, and says so once.
	b.root.mu.Lock()
	b.root.cutAfter = 1000
	b.root.mu.Unlock()
	if j := a.run(t, task.ID); j.State != jobs.Failed || !strings.Contains(j.Error, "connection reset") {
		t.Fatalf("interrupted run: %s %s", j.State, j.Error)
	}
	if st, _ := b.root.RecvState(ctx, replica.Target{Pool: "tank", Source: src, Kind: replica.KindShare, Item: "media"}); st.Token == "" {
		t.Fatal("no resume token after an interruption")
	}
	if !strings.Contains(a.notes.kinds(), EventFailed+":"+SeverityWarning) {
		t.Fatalf("notifications: %s", a.notes.kinds())
	}
	// The next run resumes, then catches up, and the alert clears.
	a.root.sends = nil
	if j := a.run(t, task.ID); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	if a.root.sends[0].Token == "" {
		t.Fatalf("didn't resume: %+v", a.root.sends[0])
	}
	if !strings.Contains(a.notes.kinds(), EventRecovered) {
		t.Fatalf("notifications: %s", a.notes.kinds())
	}
	runs, _ := a.svc.Store().Runs(ctx, task.ID, 10)
	if len(runs) != 4 || runs[0].State != "succeeded" || runs[1].State != "failed" || runs[0].Bytes == 0 {
		t.Fatalf("history %+v", runs)
	}
	tk, _ := a.svc.Store().Task(ctx, task.ID)
	if tk.LastSuccessAt == nil || tk.LastError != "" || tk.Alert != "" {
		t.Fatalf("task %+v", tk)
	}
	// Local snapshots were pruned to KeepLocal.
	if l, _ := a.root.LocalSnapshots(ctx, replica.LocalSnapshotsArgs{Task: task.ID, Kind: replica.KindShare, ID: "media"}); len(l) != 2 {
		t.Fatalf("local snapshots %d", len(l))
	}

	// What B has, as A sees it, and a restore back as a new shared folder.
	items, err := a.svc.TargetReplicas(ctx, tgt.ID)
	if err != nil || len(items) != 2 || items[0].Name != "Media" {
		t.Fatalf("%+v %v", items, err)
	}
	snaps, err := a.svc.TargetSnapshots(ctx, tgt.ID, replica.KindShare, "media")
	if err != nil || len(snaps) == 0 {
		t.Fatal(snaps, err)
	}
	// Browsing mounts the source's data on B: off until B's admin allows it.
	if _, err := a.svc.TargetBrowse(ctx, tgt.ID, replica.KindShare, "media", "", snaps[0].Name, "/"); err == nil || !strings.Contains(err.Error(), "browsing replicas is off") {
		t.Fatalf("browse allowed by default: %v", err)
	}
	allowBrowse(t, b, tgt.SourceID)
	if br, err := a.svc.TargetBrowse(ctx, tgt.ID, replica.KindShare, "media", "", snaps[0].Name, "/"); err != nil || len(br.Entries) != 2 {
		t.Fatal(br, err)
	}
	j = a.submit(t, JobRestore, RestoreParams{Target: tgt.ID, Kind: replica.KindShare, ID: "media", Snapshot: snaps[len(snaps)-1].Name, Pool: "tank", NewID: "media-restored", Name: "Media (restored)"})
	if j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	if len(a.root.restored) != 1 || a.root.restored[0].From != "bravo" || a.root.finished[0].NewID != "media-restored" {
		t.Fatalf("restore %+v %+v", a.root.restored, a.root.finished)
	}
	// A VM comes back with its disk.
	vsnaps, _ := a.svc.TargetSnapshots(ctx, tgt.ID, replica.KindVM, "web")
	j = a.submit(t, JobRestore, RestoreParams{Target: tgt.ID, Kind: replica.KindVM, ID: "web", Snapshot: vsnaps[len(vsnaps)-1].Name, Pool: "tank"})
	if j.State != jobs.Succeeded || len(a.root.restored) != 3 || a.root.restored[2].Child != "disk0" {
		t.Fatalf("%s %+v", j.Error, a.root.restored)
	}

	// B's admin deletes A's replicas: they're gone and A can't send any more.
	srcRec, _ := b.svc.Store().Source(ctx, src)
	if j := b.submit(t, JobSourceDelete, SourceDeleteParams{Source: src, DeleteReplicas: true, Confirm: "wrong"}); j.State != jobs.Failed {
		t.Fatal("deleted without the name")
	}
	if j := b.submit(t, JobSourceDelete, SourceDeleteParams{Source: src, DeleteReplicas: true, Confirm: srcRec.Name}); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	if len(b.root.replicas) != 0 {
		t.Fatal("replicas left")
	}
	if j := a.run(t, task.ID); j.State != jobs.Failed || !strings.Contains(j.Error, "isn't paired") {
		t.Fatalf("after unpairing: %s %s", j.State, j.Error)
	}
}

func TestNoCommonSnapshot(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "alpha"), newNode(t, "bravo")
	b.serve(t)
	a.root.addItem(replica.KindShare, "media", "Media")
	tgt := pair(t, a, b)
	task := &Task{Name: "T", TargetID: tgt.ID, IntervalMinutes: 60, KeepLocal: 1, KeepRemote: 1, Enabled: true, Items: []replica.Item{{Kind: replica.KindShare, ID: "media"}}}
	if _, err := a.svc.saveTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	if j := a.run(t, task.ID); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
	// Someone deletes the source's snapshots: no incremental is possible,
	// and nothing is overwritten.
	a.root.mu.Lock()
	a.root.local["share/media/"].snaps = nil
	a.root.mu.Unlock()
	if j := a.run(t, task.ID); j.State != jobs.Failed || !strings.Contains(j.Error, "no snapshot in common") {
		t.Fatalf("%s %s", j.State, j.Error)
	}
}

func TestScheduleAndStale(t *testing.T) {
	ctx := context.Background()
	a := newNode(t, "alpha")
	tgt := &Target{Name: "gone", Address: "127.0.0.1:1", SourceID: "abcdef123456", Pin: strings.Repeat("ab", 32)}
	if err := a.svc.Store().AddTarget(ctx, tgt); err != nil {
		t.Fatal(err)
	}
	a.root.addItem(replica.KindShare, "media", "Media")
	task := &Task{Name: "Hourly", TargetID: tgt.ID, IntervalMinutes: 60, KeepLocal: 1, KeepRemote: 1, Enabled: true, Items: []replica.Item{{Kind: replica.KindShare, ID: "media"}}}
	if _, err := a.svc.saveTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	a.svc.Tick(ctx) // never ran: starts now
	j := a.svc.RunningJob(task.ID)
	if j == "" {
		t.Fatal("the task didn't start")
	}
	if done := a.wait(t, &jobs.Job{ID: j}); done.State != jobs.Failed {
		t.Fatal(done.State)
	}
	time.Sleep(20 * time.Millisecond)
	a.svc.Tick(ctx) // ran a moment ago: not due
	if a.svc.RunningJob(task.ID) != "" {
		t.Fatal("started again before its interval")
	}
	// Four hours later with no success: stale (once).
	a.svc.Now = func() time.Time { return time.Now().Add(4 * time.Hour) }
	a.svc.Tick(ctx)
	if id := a.svc.RunningJob(task.ID); id != "" {
		a.wait(t, &jobs.Job{ID: id})
	}
	a.svc.Tick(ctx)
	if id := a.svc.RunningJob(task.ID); id != "" {
		a.wait(t, &jobs.Job{ID: id})
	}
	if k := a.notes.kinds(); strings.Count(k, EventStale+":"+SeverityCritical) != 1 || strings.Count(k, EventFailed) != 1 {
		t.Fatalf("notifications: %s", k)
	}
	if StaleAfter(5) != 65*time.Minute || StaleAfter(24*60) != 72*time.Hour {
		t.Fatal(StaleAfter(5), StaleAfter(24*60))
	}
}

func TestCancelKillsTheTransfer(t *testing.T) {
	a, b := newNode(t, "alpha"), newNode(t, "bravo")
	b.serve(t)
	a.root.addItem(replica.KindShare, "media", "Media")
	a.root.size = 64 << 20
	tgt := pair(t, a, b)
	task := &Task{Name: "Slow", TargetID: tgt.ID, IntervalMinutes: 60, KeepLocal: 1, KeepRemote: 1, BandwidthKBps: 256, Enabled: true,
		Items: []replica.Item{{Kind: replica.KindShare, ID: "media"}}}
	if _, err := a.svc.saveTask(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	j, err := a.svc.RunNow(context.Background(), task.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.svc.RunNow(context.Background(), task.ID, nil); !errors.Is(err, ErrRunning) {
		t.Fatalf("second start: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := a.svc.Cancel(context.Background(), task.ID); err != nil {
		t.Fatal(err)
	}
	if done := a.wait(t, j); done.State != jobs.Cancelled {
		t.Fatalf("%s %s", done.State, done.Error)
	}
	runs, _ := a.svc.Store().Runs(context.Background(), task.ID, 5)
	if runs[0].State != "cancelled" {
		t.Fatal(runs[0])
	}
}

func TestLimit(t *testing.T) {
	src := bytes.NewReader(make([]byte, 60<<10))
	start := time.Now()
	n, err := io.Copy(io.Discard, Limit(context.Background(), src, 100))
	if err != nil || n != 60<<10 {
		t.Fatal(n, err)
	}
	if el := time.Since(start); el < 500*time.Millisecond || el > 3*time.Second {
		t.Fatalf("60 KiB at 100 KiB/s took %v", el)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := io.Copy(io.Discard, Limit(ctx, bytes.NewReader(make([]byte, 1<<20)), 1)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestCodesAndAddresses(t *testing.T) {
	raw, code := NewCode()
	if len(code) != 30 || strings.Count(code, "-") != 4 {
		t.Fatal(code)
	}
	back, err := ParseCode(" " + strings.ToLower(code) + " ")
	if err != nil || !bytes.Equal(back, raw) {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "ABCD", code + "A", "!!!!-" + code[5:]} {
		if _, err := ParseCode(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for in, want := range map[string]string{
		"nas2":                   "nas2:44400",
		"nas2.home.example:8443": "nas2.home.example:8443",
		"https://192.168.1.20/":  "192.168.1.20:44400",
		"100.64.0.7:44400":       "100.64.0.7:44400",
		"fd00::1":                "[fd00::1]:44400",
		"[fd00::1]:9000":         "[fd00::1]:9000",
	} {
		got, err := CleanAddress(in)
		if err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "nas 2", "nas2:0", "nas2:99999", "-nas", "nas2/../x", "user@nas2"} {
		if _, err := CleanAddress(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	tk := &Task{Name: "x", IntervalMinutes: 1, KeepLocal: 1, KeepRemote: 1, Items: []replica.Item{{Kind: "share", ID: "a"}}}
	if CheckTask(tk) == nil {
		t.Fatal("1-minute interval accepted")
	}
	tk.IntervalMinutes = 5
	tk.Items = append(tk.Items, replica.Item{Kind: "share", ID: "a"})
	if CheckTask(tk) == nil {
		t.Fatal("duplicate item accepted")
	}
	tk.Items = []replica.Item{{Kind: "pool", ID: "a"}}
	if CheckTask(tk) == nil {
		t.Fatal("unknown kind accepted")
	}
	if got := cleanLabel("bad\x00name\n"+strings.Repeat("x", 100), 20); strings.ContainsAny(got, "\x00\n") || len([]rune(got)) != 20 {
		t.Fatal(got)
	}
}

func TestIdentitySealed(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := secretbox.NewStaticSource()
	id1, err := loadIdentity(ctx, db, &Sealer{Source: key}, "x")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := loadIdentity(ctx, db, &Sealer{Source: key}, "x")
	if err != nil || id2.Pin != id1.Pin {
		t.Fatal("identity changed", err)
	}
	// Another server's key (a database copied elsewhere) opens nothing.
	if _, err := loadIdentity(ctx, db, &Sealer{Source: secretbox.NewStaticSource()}, "x"); err == nil {
		t.Fatal("identity opened with another key")
	}
	v, _ := db.GetSetting(ctx, keyIdentity)
	if strings.Contains(v, "PRIVATE") || len(v) < 100 {
		t.Fatal("identity stored in the clear")
	}
	st := &Store{DB: db, Sealer: &Sealer{Source: key}}
	tg := &Target{Name: "b", Address: "b:44400", SourceID: "abcdef123456", Pin: "pin1"}
	if err := st.AddTarget(ctx, tg); err != nil {
		t.Fatal(err)
	}
	// A pin moved to another row doesn't open (it's bound to its row).
	if _, err := db.ExecContext(ctx, `INSERT INTO repl_targets (id, name, address, pin_sealed, source_id, created_at) SELECT 'other', name, address, pin_sealed, source_id, created_at FROM repl_targets`); err != nil {
		t.Fatal(err)
	}
	l, _ := st.Targets(ctx)
	for _, x := range l {
		if x.ID == "other" && x.Pin != "" {
			t.Fatal("a copied pin was trusted")
		}
		if x.ID == tg.ID && x.Pin != "pin1" {
			t.Fatal("pin lost")
		}
	}
}

// allowBrowse lets a source browse its replicas on b.
func allowBrowse(t *testing.T, b *node, source string) {
	t.Helper()
	src, err := b.svc.Store().Source(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	r := src.SourceRules
	r.AllowBrowse = true
	if j := b.submit(t, JobSourceUpdate, SourceUpdateParams{Source: source, SourceRules: r}); j.State != jobs.Succeeded {
		t.Fatal(j.Error)
	}
}
