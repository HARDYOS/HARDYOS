package main

import (
	"context"
	"log/slog"

	"github.com/hardyos/hardyos/daemon/internal/api"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/storagesvc"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// clusterB is part B's hardyd side.
type clusterB struct {
	Service *storagesvc.Service
	Agent   *storagesvc.Agent
}

// wireClusterB starts part B's hardyd side (docs/plans/cluster.md sections
// 5 and 6.1): the storage service and attacher, the storage agent (LIO,
// exports, firewall and fences on the storage node; cluster shares and
// the migration firewall on compute nodes) and the peer handlers. The
// storage appliers are in every state machine (internal/cluster/state).
// Call before part C (which attaches through the service) and before the
// core starts; routes adds the /cluster/storage API.
func wireClusterB(ctx context.Context, log *slog.Logger, db *store.DB, pc *priv.Client, keys secretbox.Source, al *audit.Log, parts clusterParts) *clusterB {
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
		go agent.Run(ctx)
	}
	if parts.Mux != nil {
		svc.RegisterPeer(parts.Mux)
	}
	return &clusterB{Service: svc, Agent: agent}
}

// routes adds the /cluster/storage API.
func (b *clusterB) routes(handler *api.Server) {
	if b == nil {
		return
	}
	handler.ClusterStorageRoutes(api.ClusterStorage{Service: b.Service, Agent: b.Agent})
}
