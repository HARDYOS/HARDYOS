package main

import (
	"context"
	"log/slog"

	"github.com/hardyos/hardyos/daemon/internal/api"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/cluster/storagesvc"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// clusterParts is what part A's cluster core hands the other parts: the
// membership (state, proposals), the peer client and the peer API. All nil
// on a server that isn't in a cluster (or before part A is wired); part B
// then serves only the storage network wizard.
type clusterParts struct {
	M     cluster.Membership
	Peers cluster.PeerClient
	Mux   cluster.PeerMux
}

// wireClusterB starts part B's hardyd side (docs/plans/cluster.md sections
// 5 and 6.1): the storage service and attacher, the storage agent (LIO,
// exports, firewall and fences on the storage node; cluster shares and
// the migration firewall on compute nodes), the storage appliers, the peer
// handlers and the /cluster/storage API.
func wireClusterB(ctx context.Context, log *slog.Logger, handler *api.Server, db *store.DB, pc *priv.Client, keys secretbox.Source, al *audit.Log, parts clusterParts) *storagesvc.Service {
	svc := &storagesvc.Service{
		M: parts.M, Peers: parts.Peers, Priv: pc, Log: log,
		Store: &storagesvc.Store{DB: db, Keys: keys},
		Network: func(ctx context.Context) (*network.Status, error) {
			var st network.Status
			if err := pc.Call(ctx, priv.OpNetworkStatus, nil, &st); err != nil {
				return nil, err
			}
			return &st, nil
		},
		Audit: func(ctx context.Context, a cluster.Actor, action, target string, err error) {
			e := audit.Entry{Actor: a.Name + " (via " + string(a.Via) + ")", Action: action, Target: target, Outcome: audit.Success}
			if err != nil {
				e.Outcome, e.Detail = audit.Failure, err.Error()
			}
			if rerr := al.Record(ctx, e); rerr != nil {
				log.Error("audit write failed", "action", action, "err", rerr)
			}
		},
	}
	agent := storagesvc.NewAgent(svc)
	if parts.M != nil {
		parts.M.Register(state.Storage{})
		go agent.Run(ctx)
	}
	if parts.Mux != nil {
		svc.RegisterPeer(parts.Mux)
	}
	handler.ClusterStorageRoutes(api.ClusterStorage{Service: svc, Agent: agent})
	return svc
}
