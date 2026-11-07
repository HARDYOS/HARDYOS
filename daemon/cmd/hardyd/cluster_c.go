package main

// Phase 8 part C wiring in hardyd (docs/plans/cluster.md section 11):
// placement, moves, HA and the node's fence agent, on part A's membership,
// peer client and mux and part B's storage attacher. On a server that isn't
// in a cluster the service registers its job kinds and its endpoints answer
// "not a member".

import (
	"log/slog"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
	"github.com/hardyos/hardyos/daemon/internal/cluster/moves"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/publish"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// wireClusterC builds part C; call before the job manager starts and
// before the core starts. The returned service's Start runs its loops.
func wireClusterC(db *store.DB, pc *priv.Client, manager *jobs.Manager, broker *events.Broker, remote *publish.Publisher,
	parts clusterParts, storage *clusterB, log *slog.Logger) *ha.Service {
	hp := ha.Parts{Membership: parts.M, Peers: parts.Peers, Mux: parts.Mux}
	if storage != nil {
		hp.Attacher = storage.Service
	}
	if parts.Live != nil {
		hp.Stream = moves.ALPNStream{Dial: parts.Live.DialMigrate}
	}
	svc := &ha.Service{Parts: hp, Priv: pc, Jobs: manager, DB: db, Audit: &audit.Log{DB: db, Events: broker}, Log: log}
	if remote != nil && remote.Store != nil {
		svc.Publish = publish.Handoff{Store: remote.Store}
	}
	svc.Init()
	if parts.Live != nil && svc.Node != nil {
		parts.Live.SetMigrate(svc.Node.ServeMigrateConn)
	}
	return svc
}

// newHealth is this node's report in part A's heartbeats (part B's storage
// paths, part C's running workloads); its Run refreshes it.
func newHealth(parts clusterParts, storage *clusterB, h *ha.Service) *ha.HealthReporter {
	r := &ha.HealthReporter{Cluster: parts.M, Service: h}
	if storage != nil {
		r.Storage = storage.Service.Healthy
	}
	return r
}
