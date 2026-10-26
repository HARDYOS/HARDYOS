package priv

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/apps"
)

// App operation names. Installing is split into steps (prepare, pull each
// image, up) so the install job can show progress and no single call runs
// longer than the helper's time limit.
const (
	OpAppsStatus   = "apps.status"
	OpAppsPorts    = "apps.ports"
	OpAppsPrepare  = "apps.prepare"
	OpAppsServices = "apps.services"
	OpAppsPull     = "apps.pull"
	OpAppsUp       = "apps.up"
	OpAppsStart    = "apps.start"
	OpAppsStop     = "apps.stop"
	OpAppsRestart  = "apps.restart"
	OpAppsLogs     = "apps.logs"
	OpAppsRemove   = "apps.remove"

	OpAppsReconfigure = "apps.reconfigure"
	OpAppsSnapshot    = "apps.snapshot"
	OpAppsSnapshots   = "apps.snapshots"
	OpAppsRollback    = "apps.rollback"
	OpAppsConfig      = "apps.config"
)

// AppRef names an installed app.
type AppRef struct {
	ID string `json:"id"`
}

// AppPullArgs downloads one service's image.
type AppPullArgs struct {
	ID      string `json:"id"`
	Service string `json:"service"`
}

// AppLogsArgs asks for the last lines of an app's output.
type AppLogsArgs struct {
	ID    string `json:"id"`
	Lines int    `json:"lines"`
}

// AppLogsResult is an app's recent output.
type AppLogsResult struct {
	Logs string `json:"logs"`
}

// AppPortsArgs asks for free ports.
type AppPortsArgs struct {
	Ports []apps.PortCheck `json:"ports"`
	// ForID: that app's current ports count as free (reinstalling it).
	ForID string `json:"forId,omitempty"`
}

// AppServicesResult lists an app's services and images.
type AppServicesResult struct {
	Services []apps.ServiceImage `json:"services"`
}

// RegisterApps adds the Docker app operations.
func RegisterApps(s *Server, m *apps.Manager) {
	s.Handle(OpAppsStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		o, err := m.Status(ctx)
		return o, appsErr(err)
	})
	s.Handle(OpAppsPorts, typed(func(ctx context.Context, a AppPortsArgs) (any, error) {
		p, err := m.SuggestPorts(ctx, a.Ports, a.ForID)
		return p, appsErr(err)
	}))
	s.Handle(OpAppsPrepare, typed(func(ctx context.Context, a apps.PrepareArgs) (any, error) {
		r, err := m.Prepare(ctx, a)
		return r, appsErr(err)
	}))
	s.Handle(OpAppsServices, typed(func(ctx context.Context, a AppRef) (any, error) {
		sv, err := m.Services(ctx, a.ID)
		return AppServicesResult{Services: sv}, appsErr(err)
	}))
	s.Handle(OpAppsPull, typed(func(ctx context.Context, a AppPullArgs) (any, error) {
		r, err := m.Pull(ctx, a.ID, a.Service)
		return r, appsErr(err)
	}))
	s.Handle(OpAppsUp, typed(func(ctx context.Context, a AppRef) (any, error) {
		return appDone(appsErr(m.Up(ctx, a.ID)))
	}))
	s.Handle(OpAppsStart, typed(func(ctx context.Context, a AppRef) (any, error) {
		return appDone(appsErr(m.Start(ctx, a.ID)))
	}))
	s.Handle(OpAppsStop, typed(func(ctx context.Context, a AppRef) (any, error) {
		return appDone(appsErr(m.Stop(ctx, a.ID)))
	}))
	s.Handle(OpAppsRestart, typed(func(ctx context.Context, a AppRef) (any, error) {
		return appDone(appsErr(m.Restart(ctx, a.ID)))
	}))
	s.Handle(OpAppsLogs, typed(func(ctx context.Context, a AppLogsArgs) (any, error) {
		l, err := m.Logs(ctx, a.ID, a.Lines)
		return AppLogsResult{Logs: l}, appsErr(err)
	}))
	s.Handle(OpAppsRemove, typed(func(ctx context.Context, a apps.RemoveArgs) (any, error) {
		return appDone(appsErr(m.Remove(ctx, a)))
	}))
	s.Handle(OpAppsReconfigure, typed(func(ctx context.Context, a apps.ReconfigureArgs) (any, error) {
		r, err := m.Reconfigure(ctx, a)
		return r, appsErr(err)
	}))
	s.Handle(OpAppsSnapshot, typed(func(ctx context.Context, a apps.SnapshotArgs) (any, error) {
		name, err := m.Snapshot(ctx, a)
		return AppSnapshotResult{Snapshot: name}, appsErr(err)
	}))
	s.Handle(OpAppsSnapshots, typed(func(ctx context.Context, a AppRef) (any, error) {
		l, err := m.Snapshots(ctx, a.ID)
		return AppSnapshotsResult{Snapshots: l}, appsErr(err)
	}))
	s.Handle(OpAppsRollback, typed(func(ctx context.Context, a apps.RollbackArgs) (any, error) {
		return appDone(appsErr(m.Rollback(ctx, a)))
	}))
	s.Handle(OpAppsConfig, typed(func(ctx context.Context, a AppRef) (any, error) {
		c, err := m.Config(ctx, a.ID)
		return c, appsErr(err)
	}))
}

// AppSnapshotResult names the snapshot just taken.
type AppSnapshotResult struct {
	Snapshot string `json:"snapshot"`
}

// AppSnapshotsResult lists an app's snapshots, newest first.
type AppSnapshotsResult struct {
	Snapshots []apps.Snapshot `json:"snapshots"`
}

func appDone(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return map[string]bool{"ok": true}, nil
}

// appsErr maps app errors: the caller's mistakes are bad_args, anything
// else failed.
func appsErr(err error) error {
	if err == nil {
		return nil
	}
	var p apps.Problems
	if errors.As(err, &p) || errors.Is(err, apps.ErrNotInstalled) || errors.Is(err, apps.ErrNoEngine) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	return Errorf(CodeFailed, "%v", err)
}
