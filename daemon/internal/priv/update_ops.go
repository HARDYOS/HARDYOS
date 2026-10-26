package priv

import (
	"context"
	"encoding/json"
	"regexp"

	"github.com/hardyos/hardyos/daemon/internal/update"
)

// Update operation names.
const (
	OpUpdateStatus   = "update.status"
	OpUpdateStage    = "update.stage"
	OpUpdateConfirm  = "update.confirm"
	OpUpdateActivate = "update.activate"
	OpUpdateDelete   = "update.delete"
)

// UpdateStageArgs names an uploaded bundle (inside the updates directory).
type UpdateStageArgs struct {
	Path string `json:"path"`
}

// VersionArgs names an installed version (boot environment).
type VersionArgs struct {
	Name            string `json:"name"`
	RestoreSettings bool   `json:"restoreSettings,omitempty"` // update.activate
	ConfirmName     string `json:"confirmName,omitempty"`     // update.delete
}

var versionNameRE = regexp.MustCompile(`^hardyos-[A-Za-z0-9._-]{1,110}$`)

// RegisterUpdates adds the update operations.
func RegisterUpdates(s *Server, u *update.Updater) {
	s.Handle(OpUpdateStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return u.Status(ctx)
	})
	s.Handle(OpUpdateStage, typed(func(ctx context.Context, a UpdateStageArgs) (any, error) {
		res, err := u.Stage(ctx, a.Path)
		if err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		return res, nil
	}))
	s.Handle(OpUpdateConfirm, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return u.Confirm(ctx)
	})
	s.Handle(OpUpdateActivate, typed(func(ctx context.Context, a VersionArgs) (any, error) {
		if !versionNameRE.MatchString(a.Name) {
			return nil, Errorf(CodeBadArgs, "invalid version name")
		}
		if err := u.Activate(ctx, a.Name, a.RestoreSettings); err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		return map[string]bool{"restartNeeded": true}, nil
	}))
	s.Handle(OpUpdateDelete, typed(func(ctx context.Context, a VersionArgs) (any, error) {
		if !versionNameRE.MatchString(a.Name) {
			return nil, Errorf(CodeBadArgs, "invalid version name")
		}
		if a.ConfirmName != a.Name {
			return nil, Errorf(CodeBadArgs, "confirmName must repeat the version name exactly")
		}
		if err := u.Delete(ctx, a.Name); err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		return map[string]string{"deleted": a.Name}, nil
	}))
}
