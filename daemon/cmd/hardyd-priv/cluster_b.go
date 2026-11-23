package main

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/sanclient"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// clusterB is part B's root side (docs/plans/cluster.md sections 5, 6.1):
// the storage node's LIO, exports and firewall, and a compute node's
// storage client with the engines' cluster storage backends (part C wires
// those into the VM and app engines).
type clusterB struct {
	SAN    *san.Root
	Client *sanclient.Client
	VMs    sanclient.VMBackend
	Apps   sanclient.AppBackend
	Shares sanclient.ShareResolver
}

// wireClusterB registers the san.* and sanclient.* operations. A server's
// role is the cluster's to decide (hardyd calls the ops that fit it); the
// storage node rebuilds LIO, its exports and firewall from root's own
// state here at boot, fences first.
func wireClusterB(ctx context.Context, s *priv.Server, log *slog.Logger, dump func(ctx context.Context, id string) (bool, error)) *clusterB {
	sr := &san.Root{
		Runner: sysexec.Exec{}, FS: san.OSFS{Root: san.ConfigFSRoot}, Dir: filepath.Clean(san.StateDir), Sys: "/", Log: log,
		NFS: &nfs.ClusterManager{Runner: sysexec.Exec{}, Root: "/", Log: log},
	}
	priv.RegisterSAN(s, sr)
	go sr.OnStart(ctx)
	c := &sanclient.Client{Runner: sysexec.Exec{}, Sys: "/", Log: log, Dump: dump}
	priv.RegisterSANClient(s, c)
	return &clusterB{SAN: sr, Client: c, VMs: sanclient.VMBackend{C: c}, Apps: sanclient.AppBackend{C: c}, Shares: sanclient.ShareResolver{C: c}}
}
