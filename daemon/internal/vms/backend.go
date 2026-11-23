package vms

// Storage backends (Phase 8 cluster, docs/plans/cluster.md section 6.2).
// This file is the contract: Manager.Backend (part C wires it into the
// lifecycle and the domain XML) and the cluster implementation (part B,
// internal/cluster/sanclient) code against it. Without a backend a VM lives
// on a local pool as before.

import (
	"context"
	"errors"
)

// ErrClusterStorage: the operation is the storage node's for a VM on
// cluster storage (snapshots, rollback, disk resize, delete); hardyd routes
// it there instead of to this server's hardyd-priv.
var ErrClusterStorage = errors.New("this virtual machine is on cluster storage; that's done on the storage server")

// BackendLocal and BackendCluster name the backends.
const (
	BackendLocal   = "local"
	BackendCluster = "cluster"
)

// AttachedStorage is where a VM's storage is on this server, ready to use.
type AttachedStorage struct {
	// Backend is BackendLocal or BackendCluster.
	Backend string
	// StateDir holds vm.json, nvram.fd, tpm/ and cloud-init.iso (the VM's
	// dataset mountpoint locally; an NFS mount under /mnt/hc for cluster
	// VMs).
	StateDir string
	// Disks maps each disk name (disk0, …) to its block device:
	// /dev/zvol/<pool>/vms/<id>/diskN locally; /dev/disk/by-id/wwn-0x… or
	// /dev/mapper/<wwid> for cluster VMs.
	Disks map[string]string
	// Generation is the cluster placement generation the storage was
	// attached under (0 locally). The VM is only started when it matches
	// the placement hardyd sends.
	Generation uint64
}

// StorageBackend finds a VM's storage on this server. It runs inside
// hardyd-priv and does local work only: attaching cluster storage (iSCSI
// logins, NFS mounts) happens before, through the sanclient.* ops, and the
// backend reads what was attached.
type StorageBackend interface {
	// Name is BackendLocal or BackendCluster.
	Name() string
	// List returns the ids of the VMs whose storage is attached here.
	List(ctx context.Context) ([]string, error)
	// Locate returns a VM's attached storage, or ErrNotFound when it isn't
	// attached on this server.
	Locate(ctx context.Context, id string) (*AttachedStorage, error)
}
