package main

// Phase 8 part C wiring in hardyd-priv (docs/plans/cluster.md section 11):
// the watchdog feeder and self-fencing, the cluster workload runtime and
// live migration operations, and the two helper subcommands the same
// binary serves (libvirt's qemu hook and the migration connector).

import (
	"log/slog"
	"os"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cluster/fence"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// init answers the helper subcommands before main parses flags:
//
//	hardyd-priv libvirt-hook <domain> <op> <subop> <extra>  (as root, by libvirt)
//	hardyd-priv migrate-connect <libvirt socket>            (as hardyos-migrate, by hardyd-priv)
func init() {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case priv.LibvirtHookArg:
		os.Exit(priv.RunLibvirtHook(os.Args[2:]))
	case vms.MigrateConnectArg:
		os.Exit(vms.MigrateConnectMain(os.Args[2:]))
	}
}

// wireClusterC registers part C's root operations.
func wireClusterC(s *priv.Server, vmm *vms.Manager, am *apps.Manager, log *slog.Logger) {
	feeder := &fence.Feeder{
		Open:   fence.SystemOpener,
		Detect: func() string { return fence.DetectKind(os.DirFS("/")) },
		// A nowayout driver can't be disarmed: the agent keeps it petted.
		NoWayOut: func() bool { return fence.DetectNoWayOut(os.DirFS("/")) },
	}
	priv.RegisterClusterFence(s, feeder, vmm, am)
	priv.RegisterClusterRuntime(s, vmm, am)
	priv.RegisterVMsMigrate(s, vmm)
	if s.OpTimeouts == nil {
		s.OpTimeouts = map[string]time.Duration{}
	}
	for op, d := range priv.MigrateOpTimeouts() {
		s.OpTimeouts[op] = d
	}
	if s.QuietOps == nil {
		s.QuietOps = map[string]bool{}
	}
	// Polled every half second by the fence agent and every few seconds by
	// the reconciler.
	for _, op := range []string{priv.OpClusterWatchdogPet, priv.OpClusterWatchdogStatus, priv.OpVMsClusterStatus, priv.OpAppsClusterStatus} {
		s.QuietOps[op] = true
	}
	log.Debug("cluster: fencing, runtime and live migration operations ready")
}
