package priv

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/netbird"
)

// NetBird client operation names. The setup key reaches netbird.join in
// its arguments over the socket (never logged: the server logs only op
// names) and goes to `netbird up` in its environment, never on a command
// line.
const (
	OpNetBirdStatus   = "netbird.status"
	OpNetBirdJoin     = "netbird.join"
	OpNetBirdLeave    = "netbird.leave"
	OpNetBirdSettings = "netbird.settings"
)

// RegisterNetBird adds the NetBird client operations.
func RegisterNetBird(s *Server, m *netbird.Manager) {
	s.Handle(OpNetBirdStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		st, err := m.Status(ctx)
		return st, netbirdErr(err)
	})
	s.Handle(OpNetBirdSettings, func(ctx context.Context, _ json.RawMessage) (any, error) {
		st, err := m.Settings(ctx)
		return st, netbirdErr(err)
	})
	s.Handle(OpNetBirdJoin, typed(func(ctx context.Context, a netbird.JoinArgs) (any, error) {
		st, err := m.Join(ctx, a)
		return st, netbirdErr(err)
	}))
	s.Handle(OpNetBirdLeave, typed(func(ctx context.Context, a netbird.LeaveArgs) (any, error) {
		res, err := m.Leave(ctx, a)
		return res, netbirdErr(err)
	}))
}

func netbirdErr(err error) error {
	if err == nil {
		return nil
	}
	var ve *netbird.ValidationError
	if errors.As(err, &ve) || errors.Is(err, netbird.ErrAlreadyJoined) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	if errors.Is(err, netbird.ErrNotInstalled) {
		return Errorf(CodeForbidden, "%v", err)
	}
	return Errorf(CodeFailed, "%v", err)
}
