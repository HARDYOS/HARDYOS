package priv

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// Cluster workload runtime operations (Phase 8 part C): start a cluster VM
// or app only under the placement generation its storage was attached
// with, stop it, list what runs here, and keep HA apps' images pulled.
const (
	OpVMsClusterStart   = "vms.cluster.start"
	OpVMsClusterStop    = "vms.cluster.stop"
	OpVMsClusterStatus  = "vms.cluster.status"
	OpAppsClusterStart  = "apps.cluster.start"
	OpAppsClusterStop   = "apps.cluster.stop"
	OpAppsClusterStatus = "apps.cluster.status"
	OpAppsClusterImages = "apps.cluster.images"
	OpAppsPrepull       = "apps.cluster.prepull"
	OpAppsHaveImages    = "apps.cluster.have"
	// OpAppsClusterHash is the hash of a cluster app's approved settings
	// (after the full policy check of its files on cluster storage).
	OpAppsClusterHash = "apps.cluster.hash"
)

// ImagesResult lists images.
type ImagesResult struct {
	Images []string `json:"images"`
}

// RegisterClusterRuntime adds the cluster runtime operations.
func RegisterClusterRuntime(s *Server, vmm *vms.Manager, am *apps.Manager) {
	if vmm != nil {
		s.Handle(OpVMsClusterStart, typed(func(ctx context.Context, a vms.ClusterStartArgs) (any, error) {
			r, err := vmm.ClusterStart(ctx, a)
			return r, migrateErr(err)
		}))
		s.Handle(OpVMsClusterStop, typed(func(ctx context.Context, a vms.ClusterStopArgs) (any, error) {
			v, err := vmm.ClusterStop(ctx, a)
			return v, migrateErr(err)
		}))
		s.Handle(OpVMsClusterStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
			l, err := vmm.ClusterStatus(ctx)
			return l, vmsErr(err)
		})
	}
	if am != nil {
		s.Handle(OpAppsClusterStart, typed(func(ctx context.Context, a apps.ClusterStartArgs) (any, error) {
			return vmDone(appsClusterErr(am.ClusterStart(ctx, a)))
		}))
		s.Handle(OpAppsClusterStop, typed(func(ctx context.Context, a apps.ClusterStopArgs) (any, error) {
			return vmDone(appsClusterErr(am.ClusterStop(ctx, a)))
		}))
		s.Handle(OpAppsClusterStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
			l, err := am.ClusterStatus(ctx)
			return l, appsClusterErr(err)
		})
		s.Handle(OpAppsClusterImages, typed(func(ctx context.Context, a AppRef) (any, error) {
			l, err := am.ClusterImages(ctx, a.ID)
			return ImagesResult{Images: l}, appsClusterErr(err)
		}))
		s.Handle(OpAppsPrepull, typed(func(ctx context.Context, a apps.PrepullArgs) (any, error) {
			r, err := am.Prepull(ctx, a)
			return r, appsClusterErr(err)
		}))
		s.Handle(OpAppsHaveImages, typed(func(ctx context.Context, a apps.PrepullArgs) (any, error) {
			l, err := am.HaveImages(ctx, a.Images)
			return ImagesResult{Images: l}, appsClusterErr(err)
		}))
		s.Handle(OpAppsClusterHash, typed(func(ctx context.Context, a AppRef) (any, error) {
			h, err := am.ClusterHash(ctx, a.ID)
			return SpecHashResult{Hash: h}, appsClusterErr(err)
		}))
	}
}

func appsClusterErr(err error) error {
	if err == nil {
		return nil
	}
	var p apps.Problems
	if errors.As(err, &p) || errors.Is(err, apps.ErrGeneration) || errors.Is(err, apps.ErrClusterPlaced) || errors.Is(err, apps.ErrSpecChanged) ||
		errors.Is(err, apps.ErrNotInstalled) || errors.Is(err, apps.ErrClusterStorage) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	var pe *Error
	if errors.As(err, &pe) {
		return pe
	}
	return Errorf(CodeFailed, "%v", err)
}
