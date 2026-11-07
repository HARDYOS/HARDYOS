package main

// Phase 8 part C wiring in hardyd (docs/plans/cluster.md section 11):
// placement, moves, HA and the node's fence agent. Parts A and B hand in
// their Membership, peer client and mux, and storage attacher through
// ha.Parts when they land; until then (and on a server that isn't in a
// cluster) the service registers its job kinds and its endpoints answer
// "not a member".

import (
	"log/slog"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/publish"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// clusterParts are parts A and B's pieces on this server (filled in by
// their own wiring).
var clusterParts ha.Parts

// wireClusterC builds part C; call before the job manager starts. The
// returned service's Start runs its loops.
func wireClusterC(db *store.DB, pc *priv.Client, manager *jobs.Manager, broker *events.Broker, remote *publish.Publisher, log *slog.Logger) *ha.Service {
	svc := &ha.Service{Parts: clusterParts, Priv: pc, Jobs: manager, DB: db, Audit: &audit.Log{DB: db, Events: broker}, Log: log}
	if remote != nil && remote.Store != nil {
		svc.Publish = publish.Handoff{Store: remote.Store}
	}
	svc.Init()
	return svc
}
