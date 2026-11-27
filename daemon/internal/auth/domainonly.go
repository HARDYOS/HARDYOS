package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

// DomainUser finds the row of a domain account that has signed in here,
// from what someone typed (alice, HOME\alice, alice@home.example.net),
// without checking a password: for app passwords. Local accounts, other
// domains and accounts that never signed in are store.ErrNotFound.
func (s *SignIn) DomainUser(ctx context.Context, typed string) (*User, error) {
	if s.Domain == nil {
		return nil, store.ErrNotFound
	}
	part, name, form := splitName(typed)
	if !samRE.MatchString(name) || strings.HasSuffix(name, ".") {
		return nil, store.ErrNotFound
	}
	if form == formBare {
		if u, err := s.Users.GetByName(ctx, name); err == nil && u.Source == SourceLocal {
			return nil, store.ErrNotFound
		}
	}
	info, err := s.Domain.Info(ctx)
	if err != nil {
		return nil, err
	}
	if info == nil || (form != formBare && !ourDomain(info, part, form)) {
		return nil, store.ErrNotFound
	}
	u, err := s.Users.GetByName(ctx, info.NetBIOS+`\`+name)
	if err != nil {
		return nil, err
	}
	if u.Source != SourceDomain {
		return nil, store.ErrNotFound
	}
	return u, nil
}

// CheckDomainAccount asks the directory whether a domain account may still
// be used (exists, turned on, not expired or locked) and is still the same
// directory object, for sign-ins that didn't ask Kerberos (app passwords).
func (s *SignIn) CheckDomainAccount(ctx context.Context, u *User) error {
	if s.Domain == nil || u.Source != SourceDomain {
		return ErrBadCredentials
	}
	if u.Disabled {
		return ErrDisabledHere
	}
	_, name, _ := splitName(u.Principal)
	a, err := s.Domain.Account(ctx, name)
	if err != nil {
		return ErrDomainUnavailable
	}
	if err := accountUsable(a); err != nil {
		return err
	}
	if a.LockedOut {
		return ErrAccountLocked
	}
	if s.Anchor != nil {
		if anchor := AccountAnchor(a); anchor != "" {
			if err := s.Anchor.CheckAnchor(ctx, u, anchor, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// ErrLocalAccount refuses a HardyOS account where only domain accounts may
// sign in (WebDAV).
var ErrLocalAccount = errors.New("only domain accounts can use WebDAV; sign in with your domain account (HOME\\name)")

// AuthenticateDomain is Authenticate for domain accounts only. A name that
// is a local HardyOS account is refused without its password being checked
// (so WebDAV can't be used to guess the administrator's), after the same
// dummy work an unknown name costs.
func (s *SignIn) AuthenticateDomain(ctx context.Context, typed, pw string) (*User, error) {
	_, name, form := splitName(typed)
	if form == formBare {
		if u, err := s.Users.GetByName(ctx, name); err == nil && u.Source == SourceLocal {
			VerifyPassword(pw, dummyHash)
			return nil, ErrLocalAccount
		}
		if s.Domain == nil {
			VerifyPassword(pw, dummyHash)
			return nil, ErrBadCredentials
		}
	}
	u, err := s.Authenticate(ctx, typed, pw)
	if err != nil {
		return nil, err
	}
	if u.Source != SourceDomain {
		return nil, ErrLocalAccount
	}
	return u, nil
}

// SyncDomainAccount makes or brings up to date the row of a domain account
// whose password another service just checked with the domain (sshd's
// pam_winbind, decision 519), from the directory, as a desktop sign-in
// would after Kerberos: the account must exist and be usable, its groups
// and role are refreshed, its identity anchor is checked and what was
// signed in with an older password ends. Local accounts' names and other
// domains are refused.
func (s *SignIn) SyncDomainAccount(ctx context.Context, typed string) (*User, error) {
	if s.Domain == nil {
		return nil, ErrNoLocalDC
	}
	part, name, form := splitName(typed)
	if !samRE.MatchString(name) || strings.HasSuffix(name, ".") {
		return nil, ErrBadCredentials
	}
	if form == formBare {
		if u, err := s.Users.GetByName(ctx, name); err == nil && u.Source == SourceLocal {
			return nil, ErrLocalAccount
		}
	}
	ctx, cancel := context.WithTimeout(ctx, domainCheckTimeout)
	defer cancel()
	info, err := s.Domain.Info(ctx)
	if err != nil {
		return nil, ErrDomainUnavailable
	}
	if info == nil {
		return nil, ErrNoLocalDC
	}
	if form != formBare && !ourDomain(info, part, form) {
		return nil, ErrUnknownDomain
	}
	a, err := s.Domain.Account(ctx, name)
	if err != nil {
		return nil, ErrDomainUnavailable
	}
	if err := accountUsable(a); err != nil {
		return nil, err
	}
	if a.LockedOut {
		return nil, ErrAccountLocked
	}
	u, err := s.Users.UpsertDomain(ctx, domainUpdate(info, a))
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, ErrDisabledHere
	}
	if err := s.checkDirectory(ctx, u, a, true); err != nil {
		s.log().Warn("domain sign-in: recording the account's identity", "user", name, "err", err)
		return nil, ErrDomainUnavailable
	}
	s.Users.touchLogin(ctx, u.ID)
	return u, nil
}
