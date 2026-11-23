package sanclient

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// VMBackend is vms.StorageBackend for cluster VMs: what Attach recorded.
type VMBackend struct{ C *Client }

var _ vms.StorageBackend = VMBackend{}

// Name implements vms.StorageBackend.
func (VMBackend) Name() string { return vms.BackendCluster }

// List implements vms.StorageBackend.
func (b VMBackend) List(ctx context.Context) ([]string, error) {
	recs, err := b.C.loadRecords()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range recs.Workloads {
		if r.Workload.Kind == cluster.KindVM {
			out = append(out, r.Workload.ID)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Locate implements vms.StorageBackend.
func (b VMBackend) Locate(ctx context.Context, id string) (*vms.AttachedStorage, error) {
	recs, err := b.C.loadRecords()
	if err != nil {
		return nil, err
	}
	r, ok := recs.Workloads[recordKey(cluster.WorkloadRef{Kind: cluster.KindVM, ID: id})]
	if !ok {
		return nil, vms.ErrNotFound
	}
	if !strings.HasPrefix(r.StateDir, cluster.RemoteMountRoot+"/") {
		return nil, fmt.Errorf("%s's attachment record is damaged", id)
	}
	return &vms.AttachedStorage{Backend: vms.BackendCluster, StateDir: r.StateDir, Disks: maps.Clone(r.Disks), Generation: r.Generation}, nil
}

// AppBackend is apps.StorageBackend for cluster apps. Docker's data-root
// stays local (LocalDocker).
type AppBackend struct {
	C *Client
	// LocalDocker returns this node's own Docker data-root (dataset and
	// folder), e.g. rpool/hardyos-docker.
	LocalDocker func(ctx context.Context) (dataset, dir string, err error)
}

var _ apps.StorageBackend = AppBackend{}

// Locate implements apps.StorageBackend.
func (b AppBackend) Locate(ctx context.Context, id string) (*apps.AppStorage, error) {
	recs, err := b.C.loadRecords()
	if err != nil {
		return nil, err
	}
	r, ok := recs.Workloads[recordKey(cluster.WorkloadRef{Kind: cluster.KindApp, ID: id})]
	if !ok {
		return nil, apps.ErrNotInstalled
	}
	if !strings.HasPrefix(r.StateDir, cluster.RemoteMountRoot+"/") {
		return nil, fmt.Errorf("%s's attachment record is damaged", id)
	}
	return &apps.AppStorage{Remote: true, Dataset: r.Dataset, Dir: r.StateDir, Generation: r.Generation}, nil
}

// List implements apps.StorageBackend.
func (b AppBackend) List(ctx context.Context) ([]string, error) {
	recs, err := b.C.loadRecords()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range recs.Workloads {
		if r.Workload.Kind == cluster.KindApp {
			out = append(out, r.Workload.ID)
		}
	}
	slices.Sort(out)
	return out, nil
}

// DockerRoot implements apps.StorageBackend.
func (b AppBackend) DockerRoot(ctx context.Context) (string, string, error) {
	if b.LocalDocker == nil {
		return "", "", fmt.Errorf("no local Docker data-root on this server")
	}
	return b.LocalDocker(ctx)
}

// ShareResolver is the cluster apps.ShareResolver: shared folders are the
// storage node's, mounted here under /mnt/hc. Access for an app's user is
// granted on the storage node by hardyd before the app's job reaches
// hardyd-priv (the share's ACL lives with its files), so Grant and Revoke
// only check the share is mounted.
type ShareResolver struct{ C *Client }

var _ apps.ShareResolver = ShareResolver{}

// Resolve implements apps.ShareResolver.
func (s ShareResolver) Resolve(ctx context.Context, share, sub string) (string, error) {
	if sub != "" {
		return "", fmt.Errorf("only whole shared folders can be given to apps")
	}
	recs, err := s.C.loadRecords()
	if err != nil {
		return "", err
	}
	m, ok := recs.Shares[share]
	if !ok || !s.C.mounted(m.MountPath) {
		return "", fmt.Errorf("the shared folder %s isn't mounted from the storage server here", share)
	}
	return m.MountPath, nil
}

// GrantApp implements apps.ShareResolver.
func (s ShareResolver) GrantApp(ctx context.Context, share, app string, uid int, write bool) error {
	_, err := s.Resolve(ctx, share, "")
	return err
}

// RevokeApp implements apps.ShareResolver (done on the storage node).
func (s ShareResolver) RevokeApp(ctx context.Context, app string) error { return nil }
