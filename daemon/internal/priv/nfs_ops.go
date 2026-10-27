package priv

import (
	"context"
	"encoding/json"

	"github.com/hardyos/hardyos/daemon/internal/nfs"
)

// NFS operation names. Folders are shared over NFS through their settings
// (shares.update); these report and re-apply.
const (
	OpNFSStatus = "nfs.status"
	OpNFSApply  = "nfs.apply"
)

// RegisterNFS adds the NFS operations and returns the hook that keeps the
// exports in step with shared folder changes (pass it to RegisterShares).
func RegisterNFS(s *Server, m *nfs.Manager) ShareHook {
	s.Handle(OpNFSStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return m.Status(ctx), nil
	})
	s.Handle(OpNFSApply, func(ctx context.Context, _ json.RawMessage) (any, error) {
		if err := m.Sync(ctx); err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		return m.Status(ctx), nil
	})
	return ShareHook{BeforeDelete: m.Withdraw, Changed: m.Changed}
}
