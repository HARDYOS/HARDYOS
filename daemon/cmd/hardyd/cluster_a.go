package main

import (
	"context"
	"log/slog"

	"github.com/hardyos/hardyos/daemon/internal/api"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/member"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/version"
)

// clusterA is the cluster core as hardyd runs it; parts B and C take what
// they need from it (clusterParts) in their own wireClusterB/C.
type clusterA struct {
	Service *member.Service
	Live    *member.Live
	API     *api.ClusterAPI
}

// clusterParts is what part A's cluster core hands the other parts: the
// membership (state, proposals), the peer client and the peer API, all
// following the current core (member.Live). Nil members on the live
// installer.
type clusterParts struct {
	M     cluster.Membership
	Peers cluster.PeerClient
	Mux   cluster.PeerMux
	// Live is the same as the three above, with the current core for the
	// stream layer (live migration connections).
	Live *member.Live
}

// newClusterA builds the cluster core (phase 8 part A, docs/cluster.md):
// the membership service and its jobs. Call before the job manager starts
// and before parts B and C are wired; start runs it. Installed systems
// only (nil on the live installer).
func newClusterA(live bool, db *store.DB, manager *jobs.Manager, broker *events.Broker,
	secrets secretbox.Source, alerts *notify.Dispatcher, log *slog.Logger) *clusterA {
	if live {
		return nil
	}
	svc := &member.Service{DB: db, Keys: secrets, Jobs: manager, Audit: &audit.Log{DB: db, Events: broker},
		Log: log, Version: version.Version, Secrets: api.TakeJobSecret}
	if alerts != nil {
		svc.Notify = alerts
	}
	svc.RegisterJobs(manager)
	return &clusterA{Service: svc, Live: svc.Live()}
}

// parts is what parts B and C get (empty outside an installed system).
func (a *clusterA) parts() clusterParts {
	if a == nil {
		return clusterParts{}
	}
	return clusterParts{M: a.Live, Peers: a.Live, Mux: a.Live, Live: a.Live}
}

// attach adds the cluster routes and the per-node API proxy.
func (a *clusterA) attach(handler *api.Server) {
	if a == nil {
		return
	}
	a.API = handler.AttachCluster(a.Service)
}

// start reads the membership, builds the core (with every part's appliers
// and peer endpoints registered, before the log is replayed) and runs the
// cluster log, heartbeats and paths when this server is a member.
func (a *clusterA) start(ctx context.Context, log *slog.Logger) {
	if a == nil {
		return
	}
	if err := a.Service.Init(ctx); err != nil {
		log.Error("cluster: unavailable", "err", err)
		return
	}
	go a.Service.Run(ctx)
}
