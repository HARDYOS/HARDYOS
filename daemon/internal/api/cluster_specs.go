package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha"
)

// Approved settings of cluster workloads (decision 386): a cluster VM or
// app starts only when root's hash of its files on cluster storage equals
// the hash in its placement. A change of its settings is therefore made
// on its owner and followed there by Service.ApproveSpec, which records
// the new hash in the log. VM settings are wired that way; changes to a
// cluster app's settings (update, settings, rollback) are refused until
// the app paths record the hash too.

// clusterSpecs is part C on this server (set by New), for the VM update
// job, which runs without the Server.
var clusterSpecs atomic.Pointer[ha.Service]

// clusterPlacement is a workload's placement when this server is in a
// cluster and the workload is a cluster workload (nil otherwise).
func (s *Server) clusterPlacement(ref cluster.WorkloadRef) *cluster.Placement {
	svc := s.cfg.ClusterHA
	if !svc.Member() {
		return nil
	}
	p, ok := svc.Parts.Membership.State().Placement(ref)
	if !ok || p == nil {
		return nil
	}
	return p
}

// clusterSettings decides whether a settings change of ref may go ahead
// here: not a cluster workload (nil, true); a cluster workload placed on
// this server (its actor for the approval, true); otherwise it answered.
func (s *Server) clusterSettings(w http.ResponseWriter, u *auth.User, ref cluster.WorkloadRef) (*cluster.Actor, bool) {
	p := s.clusterPlacement(ref)
	if p == nil {
		return nil, true
	}
	svc := s.cfg.ClusterHA
	self, err := svc.Parts.Membership.Self()
	if err != nil {
		writeError(w, http.StatusConflict, "not_member", "this server isn't in a cluster")
		return nil, false
	}
	if p.Owner != self.ID {
		writeError(w, http.StatusConflict, "cluster_owner", fmt.Sprintf("%s is a cluster workload placed on %s: change its settings on that server", p.Name, p.Owner))
		return nil, false
	}
	a := s.clusterActor(svc, u)
	return &a, true
}

// refuseClusterApp answers 409 for a change of a cluster app's settings
// (the app paths don't record the approved settings' hash yet).
func (s *Server) refuseClusterApp(w http.ResponseWriter, id string) bool {
	p := s.clusterPlacement(cluster.WorkloadRef{Kind: cluster.KindApp, ID: id})
	if p == nil {
		return false
	}
	writeError(w, http.StatusConflict, "cluster_workload",
		p.Name+" is a cluster app: its settings can't be changed yet (a cluster app starts only with the settings an administrator approved, and changing them isn't wired for apps)")
	return true
}

// approveClusterVM records a cluster VM's changed settings in the log
// (the update job, after root saved them on cluster storage).
func approveClusterVM(ctx context.Context, id string, actor cluster.Actor) error {
	svc := clusterSpecs.Load()
	if svc == nil {
		return errors.New("the cluster service isn't running on this server")
	}
	ref := cluster.WorkloadRef{Kind: cluster.KindVM, ID: id}
	if err := svc.ApproveSpec(ctx, ref, actor); err != nil {
		return fmt.Errorf("the changes are saved, but the cluster didn't record them as approved (%w): the VM won't start with them until it does; save again", err)
	}
	return nil
}
