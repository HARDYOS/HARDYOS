package priv

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
)

// The storage node's operations (docs/plans/cluster.md sections 5 and 8):
// LIO's desired state, fences, the storage firewall, CHAP, cluster zvols and
// datasets, their snapshots, an app's move between NFS and block mode, and
// the cluster NFS exports. Every argument is validated by package san; no
// operation takes a command line, a path outside the cluster trees, or XML.
// Destructive ones need the workload's (or node's, or snapshot's) name
// typed as confirmation.

func sanErr(err error) error {
	var ve *san.ValidationError
	if errors.As(err, &ve) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	return err
}

// VolumeCreateArgs is san.volume.create / .resize: the cluster id names
// the LUN's serial.
type VolumeCreateArgs struct {
	Cluster cluster.ClusterID `json:"cluster"`
	san.VolumeArgs
}

// RegisterSAN adds the storage node's operations.
func RegisterSAN(s *Server, r *san.Root) {
	s.Handle(san.OpStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		st, err := r.Status(ctx)
		return st, sanErr(err)
	})
	s.Handle(san.OpApply, typed(func(ctx context.Context, a san.ApplyArgs) (any, error) {
		st, err := r.Apply(ctx, a)
		return st, sanErr(err)
	}))
	s.Handle(san.OpFence, typed(func(ctx context.Context, a san.FenceArgs) (any, error) {
		res, err := r.Fence(ctx, a)
		if err != nil && res != nil {
			// Partly done: the fence is recorded; the caller retries.
			return nil, Errorf(CodeFailed, "the fence is in place but not complete: %v", err)
		}
		return res, sanErr(err)
	}))
	s.Handle(san.OpUnfence, typed(func(ctx context.Context, a san.UnfenceArgs) (any, error) {
		return map[string]bool{"unfenced": true}, sanErr(r.Unfence(ctx, a))
	}))
	s.Handle(san.OpFirewallApply, typed(func(ctx context.Context, a san.FirewallSpec) (any, error) {
		return map[string]bool{"applied": true}, sanErr(r.FirewallApply(ctx, a))
	}))
	s.Handle(san.OpCHAP, typed(func(ctx context.Context, a san.CHAPArgs) (any, error) {
		res, err := r.CHAP(ctx, a)
		return res, sanErr(err)
	}))
	s.Handle(san.OpCHAPRotate, typed(func(ctx context.Context, a san.CHAPArgs) (any, error) {
		return map[string]bool{"rotated": true}, sanErr(r.RotateCHAP(ctx, a))
	}))
	s.Handle(san.OpVolumeCreate, typed(func(ctx context.Context, a VolumeCreateArgs) (any, error) {
		res, err := r.VolumeCreate(ctx, a.Cluster, a.VolumeArgs)
		return res, sanErr(err)
	}))
	s.Handle(san.OpVolumeResize, typed(func(ctx context.Context, a VolumeCreateArgs) (any, error) {
		res, err := r.VolumeResize(ctx, a.Cluster, a.VolumeArgs)
		return res, sanErr(err)
	}))
	s.Handle(san.OpVolumeDestroy, typed(func(ctx context.Context, a san.DestroyArgs) (any, error) {
		return map[string]bool{"destroyed": true}, sanErr(r.VolumeDestroy(ctx, a))
	}))
	s.Handle(san.OpDatasetCreate, typed(func(ctx context.Context, a san.DatasetCreateArgs) (any, error) {
		res, err := r.DatasetCreate(ctx, a)
		return res, sanErr(err)
	}))
	s.Handle(san.OpDatasetDestroy, typed(func(ctx context.Context, a san.DestroyArgs) (any, error) {
		return map[string]bool{"destroyed": true}, sanErr(r.DatasetDestroy(ctx, a))
	}))
	s.Handle(san.OpDatasetInfo, typed(func(ctx context.Context, a san.WorkloadArgs) (any, error) {
		res, err := r.DatasetInfo(ctx, a)
		return res, sanErr(err)
	}))
	s.Handle(san.OpSnapshotCreate, typed(func(ctx context.Context, a san.SnapshotArgs) (any, error) {
		res, err := r.SnapshotCreate(ctx, a)
		return res, sanErr(err)
	}))
	s.Handle(san.OpSnapshotList, typed(func(ctx context.Context, a san.SnapshotArgs) (any, error) {
		res, err := r.SnapshotList(ctx, a)
		return res, sanErr(err)
	}))
	s.Handle(san.OpSnapshotRoll, typed(func(ctx context.Context, a san.SnapshotArgs) (any, error) {
		return map[string]bool{"rolledBack": true}, sanErr(r.SnapshotRollback(ctx, a))
	}))
	s.Handle(san.OpSnapshotDelete, typed(func(ctx context.Context, a san.SnapshotArgs) (any, error) {
		return map[string]bool{"destroyed": true}, sanErr(r.SnapshotDestroy(ctx, a))
	}))
	s.Handle(san.OpAppMigrate, typed(func(ctx context.Context, a san.MigrateArgs) (any, error) {
		res, err := r.Migrate(ctx, a)
		return res, sanErr(err)
	}))
	s.Handle(san.OpNFSClusterSet, typed(func(ctx context.Context, a san.NFSApplyArgs) (any, error) {
		res, err := r.NFSApply(ctx, a)
		return res, sanErr(err)
	}))
	if s.QuietOps == nil {
		s.QuietOps = map[string]bool{}
	}
	s.QuietOps[san.OpStatus] = true
}
