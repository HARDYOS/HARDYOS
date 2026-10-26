package priv

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/smb"
)

// File Services (SMB file server) operation names.
const (
	OpFilesStatus = "files.status"
	// OpFilesJoin joins the domain (smb.JoinArgs -> smb.Status).
	OpFilesJoin = "files.join"
	// OpFilesLeave leaves it (smb.LeaveArgs, confirm required).
	OpFilesLeave    = "files.leave"
	OpFilesSettings = "files.settings"
	// OpFilesApply regenerates smb.conf from the shared folders and reloads.
	OpFilesApply = "files.apply"
)

// RegisterFiles adds the SMB file server operations and returns the hook
// that keeps smb.conf in step with shared folder changes (pass it to
// RegisterShares).
func RegisterFiles(s *Server, m *smb.Manager) ShareHook {
	hook := ShareHook{
		BeforeDelete: m.Release,
		AfterDelete:  m.AfterDelete,
		Changed: func(ctx context.Context) {
			if _, err := m.Apply(ctx); err != nil {
				s.logger().Warn("file sharing: applying a shared folder change", "err", err)
			}
		},
	}
	registerFilesOps(s, m)
	s.OnRelease(m.ReleaseDataset, m.ReleaseDone)
	return hook
}

func registerFilesOps(s *Server, m *smb.Manager) {
	s.Handle(OpFilesStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		st, err := m.Status(ctx)
		return st, filesErr(err)
	})
	s.Handle(OpFilesJoin, typed(func(ctx context.Context, a smb.JoinArgs) (any, error) {
		st, err := m.Join(ctx, a)
		return st, filesErr(err)
	}))
	s.Handle(OpFilesLeave, typed(func(ctx context.Context, a smb.LeaveArgs) (any, error) {
		st, err := m.Leave(ctx, a)
		return st, filesErr(err)
	}))
	s.Handle(OpFilesSettings, typed(func(ctx context.Context, a smb.SettingsArgs) (any, error) {
		st, err := m.SetSettings(ctx, a)
		return st, filesErr(err)
	}))
	s.Handle(OpFilesApply, func(ctx context.Context, _ json.RawMessage) (any, error) {
		st, err := m.Apply(ctx)
		return st, filesErr(err)
	})
}

func filesErr(err error) error {
	if err == nil {
		return nil
	}
	var ve *smb.ValidationError
	if errors.As(err, &ve) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	return Errorf(CodeFailed, "%v", err)
}
