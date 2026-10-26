package priv

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/network"
)

// Network and time operation names.
const (
	OpNetworkStatus  = "network.status"
	OpNetworkApply   = "network.apply"
	OpNetworkConfirm = "network.confirm"
	OpNetworkRevert  = "network.revert"
	OpTimeStatus     = "time.status"
	OpTimeSet        = "time.set"
	OpTimeSetClock   = "time.set_clock"
)

// SetClockArgs sets the clock by hand.
type SetClockArgs struct {
	Time time.Time `json:"time"`
}

// RegisterNetwork adds the network and time operations.
func RegisterNetwork(s *Server, m *network.Manager) {
	s.Handle(OpNetworkStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return m.Status(ctx)
	})
	s.Handle(OpNetworkApply, typed(func(ctx context.Context, c network.Config) (any, error) {
		info, err := m.Apply(ctx, c)
		return info, netErr(err)
	}))
	s.Handle(OpNetworkConfirm, func(ctx context.Context, _ json.RawMessage) (any, error) {
		c, err := m.Confirm()
		return c, netErr(err)
	})
	s.Handle(OpNetworkRevert, func(ctx context.Context, _ json.RawMessage) (any, error) {
		err := m.Revert(ctx, "undone from the Control Panel")
		return map[string]bool{"reverted": err == nil}, netErr(err)
	})
	s.Handle(OpTimeStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return m.Time(ctx), nil
	})
	s.Handle(OpTimeSet, typed(func(ctx context.Context, t network.TimeConfig) (any, error) {
		if err := m.SetTime(ctx, t); err != nil {
			return nil, netErr(err)
		}
		return m.Time(ctx), nil
	}))
	s.Handle(OpTimeSetClock, typed(func(ctx context.Context, a SetClockArgs) (any, error) {
		if err := m.SetClock(ctx, a.Time); err != nil {
			return nil, Errorf(CodeBadArgs, "%v", err)
		}
		return m.Time(ctx), nil
	}))
}

// netErr maps network errors to protocol errors: bad settings are the
// caller's to fix (bad_args), anything else is a failure.
func netErr(err error) error {
	if err == nil {
		return nil
	}
	var ve *network.ValidationError
	if errors.As(err, &ve) || errors.Is(err, network.ErrPending) || errors.Is(err, network.ErrNothingPending) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	return Errorf(CodeFailed, "%v", err)
}
