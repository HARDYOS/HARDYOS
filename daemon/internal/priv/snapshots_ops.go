package priv

import (
	"context"

	"github.com/hardyos/hardyos/daemon/internal/snapshots"
)

// Shared folder snapshot operation names. The automatic snapshots are
// taken by the scheduler inside hardyd-priv, not through these.
const (
	OpSnapshotsList   = "snapshots.list"
	OpSnapshotsCreate = "snapshots.create"
	OpSnapshotsDelete = "snapshots.delete"
)

// SnapshotsListArgs names a shared folder.
type SnapshotsListArgs struct {
	Share string `json:"share"`
}

// SnapshotsCreateArgs takes a manual snapshot; an empty Name becomes
// manual-<YYYY-MM-DD-HHMM>.
type SnapshotsCreateArgs struct {
	Share string `json:"share"`
	Name  string `json:"name"`
}

// SnapshotsDeleteArgs deletes one snapshot; Confirm must be its name.
type SnapshotsDeleteArgs struct {
	Share    string `json:"share"`
	Snapshot string `json:"snapshot"`
	Confirm  string `json:"confirm"`
}

// SnapshotsResult lists a shared folder's snapshots, newest first.
type SnapshotsResult struct {
	Snapshots []snapshots.Snapshot `json:"snapshots"`
}

// RegisterSnapshots adds the shared folder snapshot operations.
func RegisterSnapshots(s *Server, m *snapshots.Manager) {
	s.Handle(OpSnapshotsList, typed(func(ctx context.Context, a SnapshotsListArgs) (any, error) {
		l, err := m.List(ctx, a.Share)
		if l == nil {
			l = []snapshots.Snapshot{}
		}
		return SnapshotsResult{Snapshots: l}, sharesErr(err)
	}))
	s.Handle(OpSnapshotsCreate, typed(func(ctx context.Context, a SnapshotsCreateArgs) (any, error) {
		sn, err := m.Create(ctx, a.Share, a.Name)
		return sn, sharesErr(err)
	}))
	s.Handle(OpSnapshotsDelete, typed(func(ctx context.Context, a SnapshotsDeleteArgs) (any, error) {
		err := m.Delete(ctx, a.Share, a.Snapshot, a.Confirm)
		return map[string]bool{"deleted": err == nil}, sharesErr(err)
	}))
}
