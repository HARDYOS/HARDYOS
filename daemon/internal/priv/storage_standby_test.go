package priv

import (
	"context"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// The NetBird standby's dataset stays out of snapshots, recursive ones too,
// and isn't rolled back or destroyed while it has taken over (review L-b).
func TestStorageKeepsStandbyOut(t *testing.T) {
	st, f := storageEnv(t)
	on := false
	st.env.StandbyTakenOver = func() bool { return on }
	ctx := context.Background()
	f.On("zfs list -H -o name tank/apps/netbird-standby", "tank/apps/netbird-standby\n")
	f.On("zfs list -H -o name tank/apps/netbird-standby@daily", "tank/apps/netbird-standby@daily\n")
	f.OnPrefix("zfs list -H -o name", sysexec.Result{ExitCode: 1, Stderr: []byte("does not exist")})
	f.OnPrefix("zfs snapshot", sysexec.Result{})
	f.OnPrefix("zfs destroy", sysexec.Result{})
	f.OnPrefix("zfs rollback", sysexec.Result{})

	for _, ds := range []string{"tank/apps/netbird-standby", "tank/apps/netbird-standby/x"} {
		if _, err := st.createSnapshot(ctx, SnapshotCreateArgs{Dataset: ds, Label: "x", Recursive: true}); err == nil {
			t.Errorf("snapshot of %s", ds)
		}
	}
	for _, ds := range []string{"tank", "tank/apps"} {
		if _, err := st.createSnapshot(ctx, SnapshotCreateArgs{Dataset: ds, Label: "daily", Recursive: true}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.createSnapshot(ctx, SnapshotCreateArgs{Dataset: "tank/family", Label: "daily", Recursive: true}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.Join(f.Lines(), "\n"), "zfs destroy -r tank/apps/netbird-standby@daily"); n != 2 {
		t.Fatalf("standby part removed %d times:\n%s", n, strings.Join(f.Lines(), "\n"))
	}
	for _, l := range f.Lines() {
		if strings.HasPrefix(l, "zfs snapshot") && strings.Contains(l, "netbird-standby") {
			t.Fatalf("snapshot of the standby: %s", l)
		}
	}
	// Not taken over: its snapshots (if any) can be rolled back or removed.
	if _, err := st.rollback(ctx, SnapshotRollbackArgs{Name: "tank/apps/netbird-standby@x", Confirm: true}); err != nil {
		t.Fatal(err)
	}

	on = true
	before := len(f.Calls)
	if _, err := st.rollback(ctx, SnapshotRollbackArgs{Name: "tank/apps/netbird-standby@x", Confirm: true}); err == nil {
		t.Error("rollback while taken over")
	}
	if _, err := st.destroySnapshot(ctx, SnapshotArgs{Name: "tank/apps/netbird-standby@x"}); err == nil {
		t.Error("snapshot destroy while taken over")
	}
	for _, ds := range []string{"tank/apps", "tank/apps/netbird-standby"} {
		if _, err := st.destroyDataset(ctx, DatasetDestroyArgs{Name: ds, Recursive: true, ConfirmName: ds}); err == nil {
			t.Errorf("destroyed %s while taken over", ds)
		}
	}
	if _, err := st.destroyPool(ctx, PoolDestroyArgs{Pool: "tank", ConfirmName: "tank"}); err == nil {
		t.Error("destroyed the pool while taken over")
	}
	for _, l := range f.Lines()[before:] {
		if !strings.HasPrefix(l, "zfs list") {
			t.Fatalf("ran %s", l)
		}
	}
	// Other datasets are unaffected.
	if _, err := st.rollback(ctx, SnapshotRollbackArgs{Name: "tank/family@x", Confirm: true}); err != nil {
		t.Fatal(err)
	}
	if !standbyDataset("tank/apps/netbird-standby@x") || standbyDataset("tank/apps/netbird-standbyx") || standbyDataset("tank/apps/other") || standbyDataset("netbird-standby") {
		t.Fatal("standbyDataset")
	}
}
