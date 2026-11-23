package priv

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Cluster operations (phase 8 part A). Part A needs only a read-only
// status: the boot id a rejoin must carry, the watchdog devices part C
// will arm, and whether the cluster state directory is hardyd's. Parts B
// and C add their named operations in their own files (san_ops.go,
// sanclient_ops.go, cluster_fence_ops.go, vms_migrate_ops.go).
const (
	OpClusterStatus = "cluster.status"
)

// ClusterWatchdog is one watchdog device.
type ClusterWatchdog struct {
	Device   string `json:"device"`   // watchdog0
	Identity string `json:"identity"` // iTCO_wdt, sp5100-tco, Software Watchdog, …
	Timeout  int    `json:"timeout"`  // seconds, as the driver reports it
	// Software: softdog (a kernel hang defeats it).
	Software bool `json:"software"`
}

// ClusterHostStatus is cluster.status's answer.
type ClusterHostStatus struct {
	BootID    string            `json:"bootId"`
	Watchdogs []ClusterWatchdog `json:"watchdogs"`
	// StateDir says whether /var/lib/hardyos/cluster exists and is owned
	// by hardyd (the only writer of Raft's files).
	StateDir struct {
		Exists bool   `json:"exists"`
		UID    int    `json:"uid"`
		Mode   string `json:"mode"`
	} `json:"stateDir"`
}

// ClusterHost reads what cluster.status reports, under root ("/" in
// production, a temp tree in tests).
func ClusterHost(root string) ClusterHostStatus {
	var st ClusterHostStatus
	st.Watchdogs = []ClusterWatchdog{}
	if b, err := os.ReadFile(filepath.Join(root, "proc/sys/kernel/random/boot_id")); err == nil {
		st.BootID = strings.TrimSpace(string(b))
	}
	base := filepath.Join(root, "sys/class/watchdog")
	ents, _ := os.ReadDir(base)
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), "watchdog") {
			continue
		}
		w := ClusterWatchdog{Device: e.Name()}
		if b, err := os.ReadFile(filepath.Join(base, e.Name(), "identity")); err == nil {
			w.Identity = strings.TrimSpace(string(b))
		}
		if b, err := os.ReadFile(filepath.Join(base, e.Name(), "timeout")); err == nil {
			w.Timeout, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
		w.Software = strings.Contains(strings.ToLower(w.Identity), "software")
		st.Watchdogs = append(st.Watchdogs, w)
	}
	sort.Slice(st.Watchdogs, func(i, j int) bool { return st.Watchdogs[i].Device < st.Watchdogs[j].Device })
	if fi, err := os.Stat(filepath.Join(root, "var/lib/hardyos/cluster")); err == nil {
		st.StateDir.Exists = true
		st.StateDir.Mode = fi.Mode().Perm().String()
		if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
			st.StateDir.UID = int(sys.Uid)
		}
	}
	return st
}

// RegisterCluster adds the cluster core's root operation.
func RegisterCluster(s *Server, root string) {
	s.Handle(OpClusterStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return ClusterHost(root), nil
	})
}
