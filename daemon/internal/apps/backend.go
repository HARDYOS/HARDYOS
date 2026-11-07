package apps

// Storage backends (Phase 8 cluster, docs/plans/cluster.md section 6.2).
// This file is the contract: the apps engine (part C wires it into install,
// start and remove) and the cluster implementation (part B,
// internal/cluster/sanclient) code against it. Without a backend an app's
// data is its dataset on the engine's pool as before.

import (
	"context"
	"errors"
)

// ErrClusterStorage: the operation is the storage node's for an app on
// cluster storage (dataset create and destroy, snapshots, rollback); hardyd
// routes it there instead of to this server's hardyd-priv.
var ErrClusterStorage = errors.New("this app's data is on cluster storage; that's done on the storage server")

// AppStorage is where an app's data is on this server, ready to use.
type AppStorage struct {
	// Remote: an NFS mount of the storage node's <pool>/apps/<id> under
	// /mnt/hc; otherwise the local dataset.
	Remote bool
	// Dataset is the dataset's name (on the storage node when Remote).
	Dataset string
	// Dir is the app's folder on this server (the dataset's mountpoint or
	// the NFS mount); the layout inside is the same either way.
	Dir string
	// Generation is the cluster placement generation it was attached under
	// (0 locally).
	Generation uint64
}

// StorageBackend finds an app's data and Docker's data-root on this server.
// It runs inside hardyd-priv and does local work only (cluster storage is
// attached before, through the sanclient.* ops).
type StorageBackend interface {
	// Locate returns an app's attached storage, or ErrNotInstalled when it
	// isn't attached on this server.
	Locate(ctx context.Context, id string) (*AppStorage, error)
	// List returns the ids of the apps whose storage is attached here.
	List(ctx context.Context) ([]string, error)
	// DockerRoot is Docker's data-root on this server: always local
	// (overlay2 doesn't work on NFS).
	DockerRoot(ctx context.Context) (dataset, dir string, err error)
}
