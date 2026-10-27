package priv

import (
	"context"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/dsnet"
)

// OpOfficeDSNet finds the office suite's Document Server container and
// keeps its firewall rules in step (decision 266): apply returns its
// address; remove takes the rules away. Nothing in the arguments names an
// address or a rule: root finds the container by its Compose labels.
const OpOfficeDSNet = "office.dsnet"

// OfficeDSNetArgs says what to do.
type OfficeDSNetArgs struct {
	Remove bool `json:"remove,omitempty"`
}

// RegisterOffice adds the office operations.
func RegisterOffice(s *Server, m *dsnet.Manager) {
	s.Handle(OpOfficeDSNet, typed(func(ctx context.Context, a OfficeDSNetArgs) (any, error) {
		if a.Remove {
			return struct{}{}, m.Remove(ctx)
		}
		addr, err := m.Apply(ctx)
		if errors.Is(err, dsnet.ErrNotRunning) {
			return nil, Errorf(CodeNotFound, "%s", err.Error())
		}
		return addr, err
	}))
}
