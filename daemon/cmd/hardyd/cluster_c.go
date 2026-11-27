package main

// Phase 8 part C wiring in hardyd (docs/plans/cluster.md section 11):
// placement, moves, HA and the node's fence agent, on part A's membership,
// peer client and mux and part B's storage attacher. On a server that isn't
// in a cluster the service registers its job kinds and its endpoints answer
// "not a member".

import (
	"context"
	"crypto/tls"
	"log/slog"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/convert"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
	"github.com/hardyos/hardyos/daemon/internal/cluster/moves"
	"github.com/hardyos/hardyos/daemon/internal/cluster/netcheck"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/publish"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// wireClusterC builds part C; call before the job manager starts and
// before the core starts. The returned service's Start runs its loops.
func wireClusterC(db *store.DB, pc *priv.Client, manager *jobs.Manager, broker *events.Broker, remote *publish.Publisher,
	parts clusterParts, storage *clusterB, alerts notify.Notifier, log *slog.Logger) *ha.Service {
	hp := ha.Parts{Membership: parts.M, Peers: parts.Peers, Mux: parts.Mux}
	if storage != nil {
		hp.Attacher = storage.Service
		hp.Migrations = storage.Service
	}
	if parts.Live != nil {
		hp.Stream = moves.ALPNStream{Dial: parts.Live.DialMigrate}
	}
	svc := &ha.Service{Parts: hp, Priv: pc, Jobs: manager, DB: db, Audit: &audit.Log{DB: db, Events: broker}, Log: log, Notify: alerts}
	if remote != nil && remote.Store != nil {
		svc.Publish = publish.Handoff{Store: remote.Store}
	}
	svc.Init()
	if parts.Live != nil && svc.Node != nil {
		parts.Live.SetMigrate(svc.Node.ServeMigrateConn)
	}
	return svc
}

// wireNetCheck is the network check "Make highly available" asks first
// (decisions 487, 492): the cluster's monitor judging this server (the
// one that converts) and the storage server (StatusFor adds every active
// storage server). Without a monitor it always passes.
func wireNetCheck(parts clusterParts, mon *netcheck.Monitor) convert.NetCheck {
	if mon == nil || parts.M == nil {
		return convert.AlwaysOK{}
	}
	return convert.PairCheck{Self: parts.M.Self, Status: mon.StatusFor}
}

// wireConvert builds "Make highly available" and "Make local again"
// (docs/plans/make-ha.md); call before the job manager starts. Its Run
// deletes kept copies past their grace period.
func wireConvert(db *store.DB, pc *priv.Client, manager *jobs.Manager, broker *events.Broker, parts clusterParts, storage *clusterB,
	h *ha.Service, mon *netcheck.Monitor, alerts notify.Notifier, log *slog.Logger) *convert.Converter {
	if parts.M == nil || storage == nil || h == nil {
		return nil
	}
	st := convert.ServiceStorage{Service: storage.Service}
	if parts.Live != nil {
		st.Dial = parts.Live.DialCopy
		// The storage server serves the copy connections of conversions.
		parts.Live.SetCopy(func(conn *tls.Conn, from cluster.Node) { storage.Service.ServeCopy(conn, from) })
	}
	c := &convert.Converter{Cluster: parts.M, Storage: st, Priv: pc, Specs: h, DB: db, Jobs: manager,
		Audit: &audit.Log{DB: db, Events: broker}, Notify: alerts, Net: wireNetCheck(parts, mon), HA: h, Log: log}
	c.RegisterJobs(manager)
	c.OnStart(context.Background())
	return c
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
