package auth

import (
	"context"
	"errors"
)

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
