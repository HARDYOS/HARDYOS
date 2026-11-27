package appstore

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/ports"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Store{DB: db}
}

// Window ports stay inside the window proxy range and never take a fixed
// HardyOS port or another range's (decisions 371, 510).
func TestProxyPortsStayInRange(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	avoid := map[int]bool{}
	for p := ports.AppProxy.First; p < ports.AppProxy.Last; p++ {
		avoid[p] = true
	}
	p, err := s.AllocateProxyPort(ctx, "x", ports.AppProxy, avoid)
	if err != nil || p != ports.AppProxy.Last {
		t.Fatalf("port %d %v", p, err)
	}
	avoid[ports.AppProxy.Last] = true
	if p, err := s.AllocateProxyPort(ctx, "y", ports.AppProxy, avoid); err == nil {
		t.Fatalf("allocated %d outside the range", p)
	}
	// A made-up range across the replication port skips it and stops at
	// its end.
	made := ports.Range{Name: "test", First: ports.Replication - 1, Last: ports.Replication + 1}
	got := map[int]bool{}
	for _, id := range []string{"a", "b", "c"} {
		p, err := s.AllocateProxyPort(ctx, id, made, nil)
		if err == nil {
			got[p] = true
		}
	}
	if got[ports.Replication] || got[ports.Replication-1] || !got[ports.Replication+1] || len(got) != 1 {
		t.Fatalf("made-up range gave %v", got)
	}
	if _, err := s.AllocateProxyPort(ctx, "z", ports.Range{First: 80, Last: 90}, nil); err == nil {
		t.Fatal("a range below 1024")
	}
}

// Ports recorded before the range was fixed are released and reassigned
// inside it.
func TestReleaseStrayProxyPorts(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	for id, p := range map[string]int{"ok": ports.AppProxy.First, "repl": ports.Replication, "past": ports.Replication + 7, "low": 2000} {
		if _, err := s.DB.ExecContext(ctx, `INSERT INTO app_proxy_ports (app_id, port) VALUES (?, ?)`, id, p); err != nil {
			t.Fatal(err)
		}
	}
	gone, err := s.ReleaseStrayProxyPorts(ctx, ports.AppProxy)
	if err != nil || len(gone) != 3 || gone["repl"] != ports.Replication || gone["ok"] != 0 {
		t.Fatalf("%v %v", gone, err)
	}
	left, _ := s.ProxyPorts(ctx)
	if len(left) != 1 || left["ok"] != ports.AppProxy.First {
		t.Fatalf("left %v", left)
	}
	p, err := s.AllocateProxyPort(ctx, "repl", ports.AppProxy, nil)
	if err != nil || p != ports.AppProxy.First+1 {
		t.Fatalf("reassigned %d %v", p, err)
	}
	if gone, _ := s.ReleaseStrayProxyPorts(ctx, ports.AppProxy); len(gone) != 0 {
		t.Fatalf("second sweep %v", gone)
	}
}
