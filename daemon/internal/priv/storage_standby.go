package priv

import (
	"context"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/ports"
)

// The NetBird standby's dataset (<pool>/apps/netbird-standby) holds the
// VPS's secrets while HardyOS has taken over, and its copies live sealed
// elsewhere (decision 425). The generic storage operations keep it out of
// snapshots (recursive ones too), and while it has taken over don't roll it
// back or destroy it, its pool or a parent (security review L-b).

// standbyDataset reports whether name (a dataset or a snapshot) is the
// standby's dataset or inside it.
func standbyDataset(name string) bool {
	ds, _, _ := strings.Cut(name, "@")
	pool, rest, ok := strings.Cut(ds, "/")
	if !ok || pool == "" {
		return false
	}
	sb := "apps/" + ports.NetBirdStandbyApp
	return rest == sb || strings.HasPrefix(rest, sb+"/")
}

// standbyIn is the standby's dataset when ds is it or one of its parents
// (the pool or <pool>/apps), else "".
func standbyIn(ds string) string {
	pool := datasetPool(ds)
	sb := pool + "/apps/" + ports.NetBirdStandbyApp
	if ds == pool || ds == pool+"/apps" || standbyDataset(ds) {
		return sb
	}
	return ""
}

func (st *storageOps) standbyTakenOver() bool {
	return st.env.StandbyTakenOver != nil && st.env.StandbyTakenOver()
}

// exists reports whether a dataset or snapshot exists.
func (st *storageOps) exists(ctx context.Context, name string) bool {
	_, err := st.zfs(ctx, "list", "-H", "-o", "name", name)
	return err == nil
}

// standbyGuard refuses changing what would hold or destroy the standby's
// dataset while it has taken over.
func (st *storageOps) standbyGuard(ctx context.Context, ds, what string) error {
	if !st.standbyTakenOver() {
		return nil
	}
	sb := standbyIn(ds)
	if sb == "" || !st.exists(ctx, sb) {
		return nil
	}
	return Errorf(CodeForbidden, "the NetBird standby has taken over and its data is in %s: hand back first (%s)", sb, what)
}

// dropStandbySnapshot removes the standby's part of a recursive snapshot.
func (st *storageOps) dropStandbySnapshot(ctx context.Context, ds, label string) error {
	sb := standbyIn(ds)
	if sb == "" || !st.exists(ctx, sb+"@"+label) {
		return nil
	}
	if _, err := st.zfs(ctx, "destroy", "-r", sb+"@"+label); err != nil {
		return Errorf(CodeFailed, "the snapshot was made, but the NetBird standby's part (%s@%s) couldn't be removed: %v", sb, label, err)
	}
	return nil
}
