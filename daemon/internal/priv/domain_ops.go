package priv

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/domain"
)

// Domain operation names.
const (
	OpDomainStatus     = "domain.status"
	OpDomainSuggest    = "domain.suggest"
	OpDomainProvision  = "domain.provision"
	OpDomainDestroy    = "domain.destroy"
	OpDomainEnable     = "domain.enable"
	OpDomainJoin       = "domain.join"
	OpDomainLeave      = "domain.leave"
	OpDomainRemoveDead = "domain.remove_dead"
	OpDomainForwarders = "domain.forwarders"

	OpDomainUsers        = "domain.users"
	OpDomainUserCreate   = "domain.user.create"
	OpDomainUserUpdate   = "domain.user.update"
	OpDomainUserPassword = "domain.user.password"
	OpDomainUserEnable   = "domain.user.enable"
	OpDomainUserDelete   = "domain.user.delete"
	// OpDomainUserGroups looks up one account's state and groups for
	// desktop sign-in (DomainUserRef -> domain.UserGroups).
	OpDomainUserGroups = "domain.user_groups"

	OpDomainGroups      = "domain.groups"
	OpDomainGroupCreate = "domain.group.create"
	OpDomainGroupUpdate = "domain.group.update"
	OpDomainGroupDelete = "domain.group.delete"
	// OpDomainAdminsGroupCreate creates the HardyOS Admins group (or adopts
	// an existing one, if an administrator confirmed it) and records its
	// SID in the domain's settings (domain.AdminsGroupArgs ->
	// domain.AdminsGroup).
	OpDomainAdminsGroupCreate = "domain.admins_group.create"
)

// DomainDestroyArgs confirms deleting the domain by naming it.
type DomainDestroyArgs struct {
	Confirm string `json:"confirm"`
}

// DomainEnableArgs starts or stops the domain controller.
type DomainEnableArgs struct {
	Enabled bool `json:"enabled"`
}

// DomainLeaveArgs removes this DC from the domain.
type DomainLeaveArgs struct {
	AdminPassword string `json:"adminPassword"`
}

// DomainRemoveDeadArgs takes a DC that's gone for good out of the domain.
type DomainRemoveDeadArgs struct {
	Name    string `json:"name"`
	Confirm string `json:"confirm"`
}

// DomainForwardersArgs sets the domain's internet DNS servers.
type DomainForwardersArgs struct {
	Forwarders []string `json:"forwarders"`
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

	s.Handle(OpDomainJoin, typed(func(ctx context.Context, a domain.JoinArgs) (any, error) {
		c, err := m.Join(ctx, a)
		return c, domainErr(err)
	}))
	s.Handle(OpDomainLeave, typed(func(ctx context.Context, a DomainLeaveArgs) (any, error) {
		err := m.Leave(ctx, a.AdminPassword)
		return map[string]bool{"left": err == nil}, domainErr(err)
	}))
	s.Handle(OpDomainRemoveDead, typed(func(ctx context.Context, a DomainRemoveDeadArgs) (any, error) {
		err := m.RemoveDead(ctx, a.Name, a.Confirm)
		return map[string]bool{"removed": err == nil}, domainErr(err)
	}))
	s.Handle(OpDomainForwarders, typed(func(ctx context.Context, a DomainForwardersArgs) (any, error) {
		st, err := m.SetForwarders(ctx, a.Forwarders)
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

	s.Handle(OpDomainUserGroups, typed(func(ctx context.Context, a DomainUserRef) (any, error) {
		g, err := m.UserGroups(ctx, a.Username)
		return g, domainErr(err)
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
	s.Handle(OpDomainAdminsGroupCreate, typed(func(ctx context.Context, a domain.AdminsGroupArgs) (any, error) {
		g, err := m.SetUpAdminsGroup(ctx, a)
		return g, domainErr(err)
	}))
}

// domainErr maps domain errors: the caller's mistakes are bad_args,
// anything else failed.
func domainErr(err error) error {
	if err == nil {
		return nil
	}
	var ve *domain.ValidationError
	var exists *domain.AdminsGroupExistsError
	if errors.As(err, &ve) || errors.As(err, &exists) || errors.Is(err, domain.ErrNotProvisioned) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	return Errorf(CodeFailed, "%v", err)
}
