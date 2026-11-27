package main

// The cluster's local-network check (Phase 10, decisions 490-492): this
// server's probes of the other members on the LAN and the storage network,
// its peer endpoints (registered before the core starts) and the
// notification when its own result changes.

import (
	"context"
	"log/slog"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster/netcheck"
	"github.com/hardyos/hardyos/daemon/internal/notify"
)

func wireNetcheck(parts clusterParts, alerts *notify.Dispatcher, log *slog.Logger) *netcheck.Monitor {
	if parts.Live == nil {
		return nil
	}
	m := &netcheck.Monitor{Local: parts.Live, Peers: parts.Live, Log: log}
	if alerts != nil {
		m.OnChange = func(ctx context.Context, mine netcheck.MemberResult, all netcheck.Result) {
			e := notify.Event{Kind: "cluster.netcheck", Link: "cluster", Time: time.Now()}
			if mine.OK {
				e.Severity, e.Title = notify.SeverityInfo, "This server shares the cluster's local network again"
				e.Body = "It reaches the other servers directly on the LAN and the storage network."
				if !all.OK {
					e.Body += " Another server still doesn't: " + all.Reason
				}
			} else {
				e.Severity, e.Title = notify.SeverityWarning, "This server doesn't share the cluster's local network"
				e.Body = mine.Reason + ". The cluster keeps working; turning high availability on and live moves wait until the servers share the LAN and the storage network (Cluster › Overview)."
			}
			alerts.Notify(ctx, e)
		}
	}
	m.Register(parts.Live)
	return m
}
