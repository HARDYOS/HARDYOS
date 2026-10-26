package priv

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/domain"
)

// Domain operation names.
const (
	OpDomainStatus    = "domain.status"
	OpDomainSuggest   = "domain.suggest"
	OpDomainProvision = "domain.provision"
	OpDomainDestroy   = "domain.destroy"
	OpDomainEnable    = "domain.enable"

	OpDomainUsers        = "domain.users"
	OpDomainUserCreate   = "domain.user.create"
	OpDomainUserUpdate   = "domain.user.update"
	OpDomainUserPassword = "domain.user.password"
	OpDomainUserEnable   = "domain.user.enable"
	OpDomainUserDelete   = "domain.user.delete"

	OpDomainGroups      = "domain.groups"
	OpDomainGroupCreate = "domain.group.create"
	OpDomainGroupUpdate = "domain.group.update"
	OpDomainGroupDelete = "domain.group.delete"
)

// DomainDestroyArgs confirms deleting the domain by naming it.
type DomainDestroyArgs struct {
	Confirm string `json:"confirm"`
}

// DomainEnableArgs starts or stops the domain controller.
type DomainEnableArgs struct {
	Enabled bool `json:"enabled"`
}

// DomainUserRef names an account.
type DomainUserRef struct {
	Username string `json:"username"`
}

// DomainUserEnableArgs turns an account on or off.
type DomainUserEnableArgs struct {
	Username string `json:"username"`
	Enabled  bool   `json:"enabled"`
}

// DomainGroupRef names a group.
type DomainGroupRef struct {
	Name string `json:"name"`
}

// DomainUsersResult lists accounts.
type DomainUsersResult struct {
	Users []domain.User `json:"users"`
}

// DomainGroupsResult lists groups.
type DomainGroupsResult struct {
	Groups []domain.Group `json:"groups"`
}

// RegisterDomain adds the domain controller operations.
func RegisterDomain(s *Server, m *domain.Manager) {
	s.Handle(OpDomainStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		st, err := m.Status(ctx)
		return st, domainErr(err)
	})
	s.Handle(OpDomainSuggest, func(ctx context.Context, _ json.RawMessage) (any, error) {
		sg, err := m.Suggest(ctx)
		if err != nil {
			return nil, Errorf(CodeUnavailable, "%v", err)
		}
		return sg, nil
	})
	s.Handle(OpDomainProvision, typed(func(ctx context.Context, a domain.ProvisionArgs) (any, error) {
		c, err := m.Provision(ctx, a)
		return c, domainErr(err)
	}))
	s.Handle(OpDomainDestroy, typed(func(ctx context.Context, a DomainDestroyArgs) (any, error) {
		err := m.Destroy(ctx, a.Confirm)
		return map[string]bool{"deleted": err == nil}, domainErr(err)
	}))
	s.Handle(OpDomainEnable, typed(func(ctx context.Context, a DomainEnableArgs) (any, error) {
		st, err := m.SetEnabled(ctx, a.Enabled)
		return st, domainErr(err)
	}))

	s.Handle(OpDomainUsers, func(ctx context.Context, _ json.RawMessage) (any, error) {
		u, err := m.Users(ctx)
		return DomainUsersResult{Users: u}, domainErr(err)
	})
	s.Handle(OpDomainUserCreate, typed(func(ctx context.Context, a domain.NewUser) (any, error) {
		u, err := m.CreateUser(ctx, a)
		return u, domainErr(err)
	}))
	s.Handle(OpDomainUserUpdate, typed(func(ctx context.Context, a domain.UserUpdate) (any, error) {
		u, err := m.UpdateUser(ctx, a)
		return u, domainErr(err)
	}))
	s.Handle(OpDomainUserPassword, typed(func(ctx context.Context, a domain.PasswordReset) (any, error) {
		u, err := m.ResetPassword(ctx, a)
		return u, domainErr(err)
	}))
	s.Handle(OpDomainUserEnable, typed(func(ctx context.Context, a DomainUserEnableArgs) (any, error) {
		u, err := m.SetUserEnabled(ctx, a.Username, a.Enabled)
		return u, domainErr(err)
	}))
	s.Handle(OpDomainUserDelete, typed(func(ctx context.Context, a DomainUserRef) (any, error) {
		err := m.DeleteUser(ctx, a.Username)
		return map[string]bool{"deleted": err == nil}, domainErr(err)
	}))

	s.Handle(OpDomainGroups, func(ctx context.Context, _ json.RawMessage) (any, error) {
		g, err := m.Groups(ctx)
		return DomainGroupsResult{Groups: g}, domainErr(err)
	})
	s.Handle(OpDomainGroupCreate, typed(func(ctx context.Context, a domain.NewGroup) (any, error) {
		g, err := m.CreateGroup(ctx, a)
		return g, domainErr(err)
	}))
	s.Handle(OpDomainGroupUpdate, typed(func(ctx context.Context, a domain.GroupUpdate) (any, error) {
		g, err := m.UpdateGroup(ctx, a)
		return g, domainErr(err)
	}))
	s.Handle(OpDomainGroupDelete, typed(func(ctx context.Context, a DomainGroupRef) (any, error) {
		err := m.DeleteGroup(ctx, a.Name)
		return map[string]bool{"deleted": err == nil}, domainErr(err)
	}))
}

// domainErr maps domain errors: the caller's mistakes are bad_args,
// anything else failed.
func domainErr(err error) error {
	if err == nil {
		return nil
	}
	var ve *domain.ValidationError
	if errors.As(err, &ve) || errors.Is(err, domain.ErrNotProvisioned) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	return Errorf(CodeFailed, "%v", err)
}
