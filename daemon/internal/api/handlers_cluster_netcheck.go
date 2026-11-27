package api

// The cluster's local-network check (decisions 490-492,
// docs/plans/cluster-gaps.md): GET /cluster/netcheck for the Cluster app's
// overview, ?fresh=1 to have every server probe now ("Check now", at most
// every 10 s on each server). Reading it changes nothing (no job).

import (
	"context"
	"net/http"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cluster/netcheck"
)

// NetChecker is the check as the API uses it (*netcheck.Monitor).
type NetChecker interface {
	Status(ctx context.Context) netcheck.Result
	Fresh(ctx context.Context) netcheck.Result
}

func (s *Server) clusterNetcheckRoutes() {
	s.mux.Handle("GET /api/v1/cluster/netcheck", s.admin(s.handleClusterNetcheck))
}

func (s *Server) handleClusterNetcheck(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	if s.cfg.NetCheck == nil {
		writeJSON(w, http.StatusOK, netcheck.Status(r.Context(), nil))
		return
	}
	if r.URL.Query().Get("fresh") == "1" {
		writeJSON(w, http.StatusOK, s.cfg.NetCheck.Fresh(r.Context()))
		return
	}
	writeJSON(w, http.StatusOK, s.cfg.NetCheck.Status(r.Context()))
}
