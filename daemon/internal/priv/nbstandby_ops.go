package priv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/nbstandby"
	"github.com/hardyos/hardyos/daemon/internal/ports"
)

// The NetBird standby's root operations (decisions 420-427). hardyd names
// what to do; root holds the VPS connection, its SSH key and the sealed
// snapshots, and talks to the VPS only through the forced command's verbs.
// Nothing here takes a command, a path or an address to connect to other
// than the one the administrator configured.
const (
	OpNBStandbyStatus    = "netbird.standby.status"
	OpNBStandbyConfigure = "netbird.standby.configure"
	OpNBStandbySync      = "netbird.standby.sync"
	OpNBStandbyVPS       = "netbird.standby.vps"
	OpNBStandbyStage     = "netbird.standby.stage"
	OpNBStandbyNetwork   = "netbird.standby.network"
	OpNBStandbyHandback  = "netbird.standby.handback"
	OpNBStandbyUnstage   = "netbird.standby.unstage"
	OpNBStandbyForget    = "netbird.standby.forget"
	OpNBStandbyRefresh   = "netbird.standby.refresh"
)

// StandbyApps finds the netbird-standby app for the standby's root side.
func StandbyApps(m *apps.Manager) nbstandby.AppData { return standbyApps{m} }

type standbyApps struct{ m *apps.Manager }

func (a standbyApps) StandbyApp(ctx context.Context) (string, bool, bool, error) {
	dir, running, catalog, err := a.m.DataFolder(ctx, ports.NetBirdStandbyApp)
	if apps.IsNotInstalled(err) {
		return "", false, false, fmt.Errorf("%w", nbstandby.ErrNoApp)
	}
	return dir, running, catalog, err
}

// RegisterNetBirdStandby adds the netbird.standby.* operations.
func RegisterNetBirdStandby(s *Server, r *nbstandby.Root) {
	s.Handle(OpNBStandbyStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		st, err := r.Status(ctx)
		return st, standbyErr(err)
	})
	s.Handle(OpNBStandbyConfigure, typed(func(ctx context.Context, a nbstandby.ConfigureArgs) (any, error) {
		st, err := r.Configure(ctx, a)
		return st, standbyErr(err)
	}))
	s.Handle(OpNBStandbySync, func(ctx context.Context, _ json.RawMessage) (any, error) {
		rec, err := r.Sync(ctx)
		return rec, standbyErr(err)
	})
	s.Handle(OpNBStandbyVPS, func(ctx context.Context, _ json.RawMessage) (any, error) {
		vs, err := r.VPS(ctx)
		return vs, standbyErr(err)
	})
	s.Handle(OpNBStandbyStage, typed(func(ctx context.Context, a nbstandby.ConfirmArgs) (any, error) {
		res, err := r.Stage(ctx, a)
		return res, standbyErr(err)
	}))
	s.Handle(OpNBStandbyNetwork, typed(func(ctx context.Context, a nbstandby.NetworkArgs) (any, error) {
		st, err := r.Network(ctx, a)
		return st, standbyErr(err)
	}))
	s.Handle(OpNBStandbyHandback, typed(func(ctx context.Context, a nbstandby.ConfirmArgs) (any, error) {
		res, err := r.Handback(ctx, a)
		return res, standbyErr(err)
	}))
	s.Handle(OpNBStandbyUnstage, typed(func(ctx context.Context, a nbstandby.ConfirmArgs) (any, error) {
		st, err := r.Unstage(ctx, a)
		return st, standbyErr(err)
	}))
	s.Handle(OpNBStandbyForget, typed(func(ctx context.Context, a nbstandby.ConfirmArgs) (any, error) {
		st, err := r.Forget(ctx, a)
		return st, standbyErr(err)
	}))
	s.Handle(OpNBStandbyRefresh, func(ctx context.Context, _ json.RawMessage) (any, error) {
		r.SyncApp(ctx)
		st, err := r.Status(ctx)
		return st, standbyErr(err)
	})
}

func standbyErr(err error) error {
	if err == nil {
		return nil
	}
	var p *nbstandby.Problem
	var ve *nbstandby.VPSError
	switch {
	case errors.As(err, &p):
		return Errorf(CodeBadArgs, "%s", p.Msg)
	case errors.Is(err, nbstandby.ErrNoApp):
		return Errorf(CodeUnavailable, "%v", err)
	case errors.As(err, &ve):
		return Errorf(CodeFailed, "%s", ve.Error())
	}
	return Errorf(CodeFailed, "%v", err)
}
