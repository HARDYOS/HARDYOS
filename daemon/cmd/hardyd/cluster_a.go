package main

import (
	"context"
	"log/slog"

	"github.com/hardyos/hardyos/daemon/internal/api"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/cluster/member"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/version"
)

// clusterA is the cluster core as hardyd runs it; parts B and C take what
// they need from it in their own wireClusterB/C.
type clusterA struct {
	Service *member.Service
	API     *api.ClusterAPI
}

// wireClusterA runs the cluster core (phase 8 part A, docs/cluster.md):
// the membership service, its jobs, the cluster routes and the per-node
// API proxy. Installed systems only.
func wireClusterA(ctx context.Context, live bool, db *store.DB, manager *jobs.Manager, broker *events.Broker,
	secrets secretbox.Source, alerts *notify.Dispatcher, handler *api.Server, log *slog.Logger) *clusterA {
	if live {
		return nil
	}
	svc := &member.Service{DB: db, Keys: secrets, Jobs: manager, Audit: &audit.Log{DB: db, Events: broker},
		Log: log, Version: version.Version, Secrets: api.TakeJobSecret}
	if alerts != nil {
		svc.Notify = alerts
	}
	svc.RegisterJobs(manager)
	ca := handler.AttachCluster(svc)
	if err := svc.Init(ctx); err != nil {
		log.Error("cluster: unavailable", "err", err)
		return &clusterA{Service: svc, API: ca}
	}
	go svc.Run(ctx) // the cluster log, heartbeats and paths when this server is a member
	return &clusterA{Service: svc, API: ca}
}
