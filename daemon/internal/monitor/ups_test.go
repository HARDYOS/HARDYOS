package monitor

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/ups"
)

func strp(s string) *string { return &s }

// fakeUPSD answers LIST VAR from a mutable variable set.
type fakeUPSD struct {
	ln   net.Listener
	mu   sync.Mutex
	vars map[string]string
	down bool
}

func newFakeUPSD(t *testing.T) *fakeUPSD {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeUPSD{ln: ln, vars: map[string]string{"ups.status": "OL CHRG", "battery.charge": "100", "battery.runtime": "2400", "ups.load": "31", "ups.mfr": "CPS", "ups.model": "CP1500"}}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				line, _ := r.ReadString('\n')
				f.mu.Lock()
				defer f.mu.Unlock()
				if f.down {
					fmt.Fprint(c, "ERR DATA-STALE\n")
					return
				}
				name := strings.TrimSpace(strings.TrimPrefix(line, "LIST VAR "))
				if name != "ups" {
					fmt.Fprint(c, "ERR UNKNOWN-UPS\n")
					return
				}
				fmt.Fprintf(c, "BEGIN LIST VAR ups\n")
				for k, v := range f.vars {
					fmt.Fprintf(c, "VAR ups %s \"%s\"\n", k, strings.ReplaceAll(v, `"`, `\"`))
				}
				fmt.Fprintf(c, "END LIST VAR ups\n")
			}()
		}
	}()
	return f
}

func (f *fakeUPSD) set(kv ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 0; i+1 < len(kv); i += 2 {
		f.vars[kv[i]] = kv[i+1]
	}
}

type events struct {
	mu  sync.Mutex
	got []notify.Event
}

func (e *events) Notify(_ context.Context, ev notify.Event) {
	e.mu.Lock()
	e.got = append(e.got, ev)
	e.mu.Unlock()
}

func (e *events) titles() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, x := range e.got {
		out = append(out, x.Severity+":"+x.Title)
	}
	return out
}

func newUPSService(t *testing.T, addr string) (*UPSService, *events) {
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "u.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ev := &events{}
	s := &UPSService{DB: db, Notify: ev}
	host, port, _ := net.SplitHostPort(addr)
	var p int
	fmt.Sscan(port, &p)
	if _, _, _, err := s.Save(context.Background(), ups.Config{Mode: ups.ModeNetClient, RemoteHost: host, RemotePort: p, RemoteUser: "monuser"},
		&UPSSecretsInput{RemotePassword: strp("s3cret-pass")}); err != nil {
		t.Fatal(err)
	}
	return s, ev
}

func TestUPSTransitions(t *testing.T) {
	f := newFakeUPSD(t)
	s, ev := newUPSService(t, f.ln.Addr().String())
	ctx := context.Background()
	s.Poll(ctx) // baseline: on mains, nothing to say
	if len(ev.titles()) != 0 {
		t.Fatalf("baseline raised %v", ev.titles())
	}
	f.set("ups.status", "OB DISCHRG", "battery.charge", "88", "battery.runtime", "1500")
	s.Poll(ctx)
	f.set("ups.status", "OB DISCHRG LB", "battery.charge", "19")
	s.Poll(ctx)
	f.set("ups.status", "OL CHRG RB")
	s.Poll(ctx)
	s.Poll(ctx) // nothing new
	want := []string{"warning:UPS on battery", "critical:UPS battery low: shutting down", "info:Power is back", "warning:Replace the UPS battery"}
	if got := ev.titles(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("events\n got %v\nwant %v", got, want)
	}
	if !strings.Contains(ev.got[0].Body, "battery 88%, about 25 minutes left") {
		t.Errorf("on-battery body %q", ev.got[0].Body)
	}
	// Losing contact: an alert after three failed reads, one when it's back.
	f.mu.Lock()
	f.down = true
	f.mu.Unlock()
	for range 5 {
		s.Poll(ctx)
	}
	f.mu.Lock()
	f.down = false
	f.mu.Unlock()
	s.Poll(ctx)
	got := ev.titles()
	if len(got) != 6 || !strings.HasPrefix(got[4], "warning:Lost contact") || !strings.HasPrefix(got[5], "info:Contact with") {
		t.Errorf("comm events %v", got)
	}
	v, _ := s.View(ctx)
	if !v.SecretsSet["remotePassword"] || v.Status == nil {
		t.Errorf("view %+v", v)
	}
	var raw string
	_ = s.DB.QueryRow(`SELECT value FROM settings WHERE key = 'ups.secrets'`).Scan(&raw)
	if strings.Contains(raw, "s3cret") {
		t.Error("UPS password stored in the clear")
	}
}

func TestUPSDestinationAndRollback(t *testing.T) {
	f := newFakeUPSD(t)
	s, _ := newUPSService(t, f.ln.Addr().String())
	ctx := context.Background()
	cfg, _, _ := s.Config(ctx)
	moved := cfg
	moved.RemoteHost = "evil.example.com"
	if _, _, m, err := s.Save(ctx, moved, nil); err == nil || !m || !strings.Contains(err.Error(), "enter the password again") {
		t.Fatalf("moved without a password: %v %v", m, err)
	}
	moved.RemoteHost, moved.RemotePort = cfg.RemoteHost, 3494
	if _, _, _, err := s.Save(ctx, moved, &UPSSecretsInput{}); err == nil {
		t.Fatal("port changed without a password")
	}
	// Same destination: fine without the password.
	if _, _, m, err := s.Save(ctx, cfg, nil); err != nil || m {
		t.Fatalf("unchanged: %v %v", m, err)
	}
	// A new setup that fails to apply is rolled back.
	moved.RemoteHost, moved.RemotePort = "nas2.home.arpa", cfg.RemotePort
	if _, _, _, err := s.Save(ctx, moved, &UPSSecretsInput{RemotePassword: strp("other-pass")}); err != nil {
		t.Fatal(err)
	}
	if c, sec, _ := s.Config(ctx); c.RemoteHost != "nas2.home.arpa" || sec.RemotePassword != "other-pass" {
		t.Fatalf("saved %+v", c)
	}
	if err := s.RestorePrevious(ctx); err != nil {
		t.Fatal(err)
	}
	if c, sec, _ := s.Config(ctx); c.RemoteHost != cfg.RemoteHost || sec.RemotePassword != "s3cret-pass" {
		t.Errorf("after rollback %+v %q", c, sec.RemotePassword)
	}
}
