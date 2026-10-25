package priv

import (
	"context"
	"encoding/json"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/install"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Install operation names. They are registered only on the live installer.
const (
	OpInstallCheck     = "install.check"
	OpInstallPartition = "install.partition"
	OpInstallPool      = "install.pool"
	OpInstallSystem    = "install.system"
	OpInstallConfigure = "install.configure"
	OpInstallBoot      = "install.boot"
	OpInstallFinish    = "install.finish"
	OpInstallReset     = "install.reset"
)

// OpSystemReboot restarts the server.
const OpSystemReboot = "system.reboot"

// InstallArgs carries the installer plan to each step.
type InstallArgs struct {
	Plan        install.Plan  `json:"plan"`
	ConfirmWipe bool          `json:"confirmWipe,omitempty"` // install.partition
	Seed        *install.Seed `json:"seed,omitempty"`        // install.configure
}

// InstallInfo answers install.check.
type InstallInfo struct {
	Version string              `json:"version"`
	BE      string              `json:"bootEnvironment"`
	Disks   []install.DiskCheck `json:"disks"`
}

// RegisterInstaller adds the install steps. Call it only on the live ISO
// (install.IsLive): on an installed system these operations must not exist.
func RegisterInstaller(s *Server, in *install.Installer) {
	s.Handle(OpInstallCheck, typed(func(ctx context.Context, a InstallArgs) (any, error) {
		checks, err := in.Check(ctx, a.Plan)
		if err != nil {
			return nil, Errorf(CodeBadArgs, "%v", err)
		}
		return InstallInfo{Version: in.Version, BE: in.BEName(), Disks: checks}, nil
	}))
	s.Handle(OpInstallPartition, typed(func(ctx context.Context, a InstallArgs) (any, error) {
		return done(in.Partition(ctx, a.Plan, a.ConfirmWipe))
	}))
	s.Handle(OpInstallPool, typed(func(ctx context.Context, a InstallArgs) (any, error) {
		return done(in.CreatePool(ctx, a.Plan))
	}))
	s.Handle(OpInstallSystem, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return done(in.CopySystem(ctx))
	})
	s.Handle(OpInstallConfigure, typed(func(ctx context.Context, a InstallArgs) (any, error) {
		if a.Seed == nil {
			return nil, Errorf(CodeBadArgs, "the administrator account is missing")
		}
		return done(in.Configure(ctx, a.Plan, *a.Seed))
	}))
	s.Handle(OpInstallBoot, typed(func(ctx context.Context, a InstallArgs) (any, error) {
		return done(in.InstallBootloader(ctx, a.Plan))
	}))
	s.Handle(OpInstallFinish, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return done(in.Finish(ctx))
	})
	s.Handle(OpInstallReset, func(ctx context.Context, _ json.RawMessage) (any, error) {
		in.Reset(ctx)
		return map[string]bool{"ok": true}, nil
	})
}

func done(err error) (any, error) {
	if err != nil {
		return nil, Errorf(CodeFailed, "%v", err)
	}
	return map[string]bool{"ok": true}, nil
}

// RegisterSystem adds power operations.
func RegisterSystem(s *Server, r sysexec.Runner) {
	s.Handle(OpSystemReboot, func(ctx context.Context, _ json.RawMessage) (any, error) {
		// Answer first; the reboot starts a moment later.
		go func() {
			time.Sleep(time.Second)
			_, _ = r.Run(context.Background(), nil, "systemctl", "reboot")
		}()
		return map[string]bool{"rebooting": true}, nil
	})
}
