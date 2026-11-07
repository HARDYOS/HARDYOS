package main

import "github.com/hardyos/hardyos/daemon/internal/priv"

// wireClusterA adds the cluster core's root operation (phase 8 part A):
// cluster.status only. Parts B and C wire theirs in cluster_b.go and
// cluster_c.go.
func wireClusterA(s *priv.Server) {
	priv.RegisterCluster(s, "/")
}
