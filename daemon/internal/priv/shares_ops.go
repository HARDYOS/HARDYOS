package priv

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// Shared folder operation names.
const (
	OpSharesList    = "shares.list"
	OpSharesCreate  = "shares.create"
	OpSharesUpdate  = "shares.update"
	OpSharesDelete  = "shares.delete"
	OpSharesStarter = "shares.starter"
	OpSharesFolders = "shares.folders"
)

// ShareDeleteArgs deletes a shared folder; Confirm is its name.
type ShareDeleteArgs struct {
	ID      string `json:"id"`
	Confirm string `json:"confirm"`
}

// ShareFoldersArgs lists subfolders of Path inside a share.
type ShareFoldersArgs struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

// SharesResult lists shared folders.
type SharesResult struct {
	Shares []shares.Share `json:"shares"`
}

// ShareFoldersResult lists subfolder names.
type ShareFoldersResult struct {
	Folders []string `json:"folders"`
}

// RegisterShares adds the shared folder operations.
func RegisterShares(s *Server, m *shares.Manager) {
	s.Handle(OpSharesList, func(ctx context.Context, _ json.RawMessage) (any, error) {
		l, err := m.List(ctx)
		return SharesResult{Shares: l}, sharesErr(err)
	})
	s.Handle(OpSharesCreate, typed(func(ctx context.Context, a shares.NewShare) (any, error) {
		sh, err := m.Create(ctx, a)
		return sh, sharesErr(err)
	}))
	s.Handle(OpSharesUpdate, typed(func(ctx context.Context, a shares.ShareUpdate) (any, error) {
		sh, err := m.Update(ctx, a)
		return sh, sharesErr(err)
	}))
	s.Handle(OpSharesDelete, typed(func(ctx context.Context, a ShareDeleteArgs) (any, error) {
		err := m.Delete(ctx, a.ID, a.Confirm)
		return map[string]bool{"deleted": err == nil}, sharesErr(err)
	}))
	s.Handle(OpSharesStarter, typed(func(ctx context.Context, a shares.StarterArgs) (any, error) {
		l, err := m.CreateStarter(ctx, a)
		return SharesResult{Shares: l}, sharesErr(err)
	}))
	s.Handle(OpSharesFolders, typed(func(ctx context.Context, a ShareFoldersArgs) (any, error) {
		l, err := m.Folders(ctx, a.ID, a.Path)
		return ShareFoldersResult{Folders: l}, sharesErr(err)
	}))
}

func sharesErr(err error) error {
	if err == nil {
		return nil
	}
	var ve *shares.ValidationError
	if errors.As(err, &ve) || errors.Is(err, shares.ErrNotFound) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	return Errorf(CodeFailed, "%v", err)
}
