package replication

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/replica"
)

// A peer that answers with a redirect doesn't send this server anywhere.
func TestNoRedirects(t *testing.T) {
	ctx := context.Background()
	a := newNode(t, "alpha")
	hit := make(chan string, 4)
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit <- r.URL.Path }))
	defer elsewhere.Close()
	evil := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/internal", http.StatusFound)
	}))
	evil.StartTLS()
	defer evil.Close()
	pin := PinOf(evil.Certificate())
	p, err := a.svc.peer(ctx, &Target{Name: "evil", Address: evil.Listener.Addr().String(), Pin: pin})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.hello(ctx); err == nil {
		t.Fatal("a redirect was accepted as an answer")
	}
	if _, err := p.send(ctx, "share", "media", "", "x"); err == nil {
		t.Fatal("a redirected download was accepted")
	}
	if _, err := a.svc.Pair(ctx, evil.Listener.Addr().String(), FormatCode(make([]byte, 16))); err == nil {
		t.Fatal("pairing followed a redirect")
	}
	select {
	case path := <-hit:
		t.Fatalf("followed a redirect to %s", path)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestPairingFailuresPerAddress(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "alpha"), newNode(t, "bravo")
	b.serve(t)
	raw, code := NewCode()
	if _, err := b.svc.OpenPairing(ctx, raw, PairingParams{Pool: "tank", QuotaBytes: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	for range MaxPairFailuresPerIP {
		_, wrong := NewCode()
		_, _ = a.svc.Pair(ctx, b.addr, wrong)
	}
	if _, err := a.svc.Pair(ctx, b.addr, code); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("an address past its failures: %v", err)
	}
	// Only that address's tries counted towards closing the code.
	if p, _ := b.svc.Store().Pairing(ctx, time.Now()); p == nil || p.failures != MaxPairFailuresPerIP {
		t.Fatalf("pairing %+v", p)
	}
	// A new code starts afresh.
	raw, code = NewCode()
	_, _ = b.svc.OpenPairing(ctx, raw, PairingParams{Pool: "tank", QuotaBytes: 1 << 30})
	if _, err := a.svc.Pair(ctx, b.addr, code); err != nil {
		t.Fatal(err)
	}
	// No quota, no code.
	if _, err := b.svc.OpenPairing(ctx, raw, PairingParams{Pool: "tank"}); err == nil {
		t.Fatal("a code without a space limit")
	}
}

func TestCleanLabelInvisibles(t *testing.T) {
	r := func(c rune) string { return string(c) }
	in := "nas" + r(0x202E) + "gnp.exe" + r(0x200B) + r(0x2066) + "x" + r(0x2069) + r(0x00AD) + "y" + r(0xFEFF) + r(0x2028) + "z\tq"
	got := cleanLabel(in, 60)
	for _, r := range []rune{0x202E, 0x200B, 0x2066, 0x2069, 0x00AD, 0xFEFF, 0x2028, '\t'} {
		if strings.ContainsRune(got, r) {
			t.Errorf("kept %U in %q", r, got)
		}
	}
	if got != "nasgnp.exexy z q" {
		t.Fatalf("%q", got)
	}
}

func TestConnCaps(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	capped := newConnCaps(10, 2).wrap(ln)
	defer capped.Close()
	accepted := make(chan net.Conn, 10)
	go func() {
		for {
			c, err := capped.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	var conns []net.Conn
	for range 3 {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(accepted); n != 2 {
		t.Fatalf("accepted %d connections from one address, want 2", n)
	}
	// The third was closed at once.
	_ = conns[2].SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conns[2].Read(make([]byte, 1)); err == nil {
		t.Fatal("the extra connection stayed open")
	}
	// Closing one frees a slot.
	(<-accepted).Close()
	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("a freed slot wasn't reused")
	}
	for _, c := range conns {
		c.Close()
	}
}

func TestWatchdog(t *testing.T) {
	ctx, wd := newWatchdog(context.Background(), 150*time.Millisecond, time.Hour)
	defer wd.close()
	pr, pw := io.Pipe()
	go func() {
		for range 5 {
			_, _ = pw.Write([]byte("x"))
			time.Sleep(50 * time.Millisecond)
		}
		// then stall
	}()
	r := watched{r: pr, w: wd}
	buf := make([]byte, 1)
	for range 5 {
		if _, err := r.Read(buf); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("a stalled stream wasn't ended")
	}
}

// What a source does on the receiving server is audited there, and the
// receiver's minimum age reaches its pruning.
func TestPeerActionsAudited(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "alpha"), newNode(t, "bravo")
	b.svc.Audit = &audit.Log{DB: b.svc.DB}
	b.serve(t)
	a.root.addItem(replica.KindShare, "media", "Media")
	tgt := pairOn(t, a, b, "tank")
	task := &Task{Name: "T", TargetID: tgt.ID, IntervalMinutes: 60, KeepLocal: 1, KeepRemote: 1, Enabled: true, Items: []replica.Item{{Kind: replica.KindShare, ID: "media"}}}
	if _, err := a.svc.saveTask(ctx, task); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if j := a.run(t, task.ID); j.State != jobs.Succeeded {
			t.Fatal(j.Error)
		}
	}
	if p := b.root.pruned[len(b.root.pruned)-1]; p.MinAgeDays != DefaultRules.MinAgeDays || p.Keep != 3 {
		t.Fatalf("prune %+v", p)
	}
	l, err := b.svc.Audit.List(ctx, audit.Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range l {
		if e.Actor == "server:alpha" && e.Action == "replication.receive" && e.Outcome == audit.Success {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("audited receives: %d of %+v", n, l)
	}
}
