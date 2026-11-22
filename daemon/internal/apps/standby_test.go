package apps

import (
	"errors"
	"strings"
	"testing"

	portreg "github.com/hardyos/hardyos/daemon/internal/ports"
)

// The NetBird standby's fixed ports are kept from every app but their owner
// (decision 420).
func TestOwnedPortsKept(t *testing.T) {
	for _, p := range []int{portreg.NetBirdStandbyHTTP, portreg.NetBirdStandbyHTTPS, portreg.NetBirdStandbySTUN} {
		if keptPort(p, portreg.NetBirdStandbyApp) {
			t.Errorf("%d kept from its owner", p)
		}
		for _, other := range []string{"jellyfin", ""} {
			if !keptPort(p, other) {
				t.Errorf("%d given to %q", p, other)
			}
		}
	}
	if !keptPort(portreg.AppGateway, portreg.NetBirdStandbyApp) || !keptPort(2049, portreg.NetBirdStandbyApp) {
		t.Fatal("the owner got another HardyOS port")
	}
	if keptPort(8096, "jellyfin") {
		t.Fatal("an ordinary port is kept")
	}
}

// The standby's subnet belongs to it (decision 426), and its app can't
// change while taken over (Guard), nor be backed up or snapshotted.
func TestStandbySubnetAndGuard(t *testing.T) {
	net := map[string]any{"ipam": map[string]any{"config": []any{map[string]any{"subnet": "172.16.253.16/28"}}}}
	var p Problems
	checkNetwork(&p, ProjectName("jellyfin"), "default", net, true)
	if p.err() == nil {
		t.Fatal("another app got the standby's subnet")
	}
	p = nil
	checkNetwork(&p, ProjectName(portreg.NetBirdStandbyApp), "default", net, false)
	if p.err() == nil {
		t.Fatal("an uploaded standby got the subnet")
	}
	p = nil
	checkNetwork(&p, ProjectName(portreg.NetBirdStandbyApp), "default", net, true)
	if err := p.err(); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Guard: func(id string) error {
		if id == portreg.NetBirdStandbyApp {
			return errors.New("taken over")
		}
		return nil
	}}
	ctx := t.Context()
	if _, err := m.Reconfigure(ctx, ReconfigureArgs{ID: portreg.NetBirdStandbyApp}); err == nil || !strings.Contains(err.Error(), "taken over") {
		t.Fatalf("reconfigure: %v", err)
	}
	if err := m.Remove(ctx, RemoveArgs{ID: portreg.NetBirdStandbyApp}); err == nil || !strings.Contains(err.Error(), "taken over") {
		t.Fatalf("remove: %v", err)
	}
	if err := m.Rollback(ctx, RollbackArgs{ID: portreg.NetBirdStandbyApp}); err == nil || !strings.Contains(err.Error(), "taken over") {
		t.Fatalf("rollback: %v", err)
	}
	if err := m.RestoreData(ctx, portreg.NetBirdStandbyApp, "", nil); err == nil || !strings.Contains(err.Error(), "taken over") {
		t.Fatalf("restore: %v", err)
	}
	if _, err := m.Snapshot(ctx, SnapshotArgs{ID: portreg.NetBirdStandbyApp, Reason: "manual"}); err == nil {
		t.Fatal("snapshotted the standby")
	}
	if _, err := m.BackupSource(ctx, portreg.NetBirdStandbyApp); err == nil {
		t.Fatal("the standby is a backup source")
	}
}
