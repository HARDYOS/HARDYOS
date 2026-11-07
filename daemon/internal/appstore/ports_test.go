package appstore

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/ports"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Window ports stay inside the window proxy range and never take a fixed
// HardyOS port (decision 371).
func TestProxyPortsStayInRange(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := &Store{DB: db}
	// A base whose range would cover the replication port.
	base := ports.Replication - ports.AppProxyCount/2
	avoid := map[int]bool{}
	for p := base; p < ports.Replication; p++ {
		avoid[p] = true
	}
	p, err := s.AllocateProxyPort(ctx, "x", base, avoid)
	if err != nil || p != ports.Replication+1 {
		t.Fatalf("port %d %v", p, err)
	}
	for p := base; p < base+ports.AppProxyCount; p++ {
		avoid[p] = true
	}
	if p, err := s.AllocateProxyPort(ctx, "y", base, avoid); err == nil {
		t.Fatalf("allocated %d outside the range", p)
	}
}
