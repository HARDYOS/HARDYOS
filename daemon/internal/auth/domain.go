package auth

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DomainInfo is what desktop sign-in needs to know about this server's
// domain.
type DomainInfo struct {
	Realm   string   // HOME.EXAMPLE.NET
	NetBIOS string   // HOME
	DNS     string   // home.example.net
	KDCs    []string // the domain controllers' addresses, this server's own first
}

// DomainAccount is a domain user's state and groups, from the directory.
type DomainAccount struct {
	// Exists is false when the directory has no such user.
	Exists      bool
	Username    string // sAMAccountName as the directory spells it
	DisplayName string
	Email       string
	Enabled     bool
	LockedOut   bool
	Expired     bool
	// Groups are group names without the domain (Domain Users, Family),
	// nested memberships included.
	Groups []string
}

// DomainDirectory answers questions about the domain. hardyd implements it
// with hardyd-priv's domain.status and domain.user_groups.
type DomainDirectory interface {
	// Info returns the domain, or nil, nil when this server has none.
	Info(ctx context.Context) (*DomainInfo, error)
	// Account looks a user up by sAMAccountName.
	Account(ctx context.Context, username string) (*DomainAccount, error)
}

// PasswordChecker verifies a domain password (KerberosChecker in
// production, a fake in tests). It returns nil, ErrBadCredentials,
// ErrAccountRevoked, ErrPasswordExpired, ErrClockSkew or ErrDomainUnavailable.
type PasswordChecker interface {
	CheckPassword(ctx context.Context, d DomainInfo, username, password string) error
}

// Sign-in errors for domain accounts. The messages are shown on the sign-in
// screen.
var (
	ErrDomainUnavailable = errors.New("can't reach the domain controller to check the password; try again in a minute, or sign in with a local HardyOS account")
	ErrUnknownDomain     = errors.New("that isn't this server's domain; sign in with your name, DOMAIN\\name or name@domain")
	ErrClockSkew         = errors.New("this server's clock and the domain controller's are more than 5 minutes apart; check the time in Control Panel > Date & Time")
	ErrAccountRevoked    = errors.New("this domain account can't sign in right now: it's turned off, locked or expired; ask an administrator (Control Panel > Domain > Users)")
	ErrAccountDisabled   = errors.New("this domain account is turned off; an administrator can turn it on in Control Panel > Domain > Users")
	ErrAccountLocked     = errors.New("this domain account is locked after too many wrong passwords; wait a while, or ask an administrator to set a new password in Control Panel > Domain > Users")
	ErrAccountExpired    = errors.New("this domain account has expired; ask an administrator")
	ErrPasswordExpired   = errors.New("this password has expired or must be changed first; change it on a computer in the domain, or ask an administrator to set a new one in Control Panel > Domain > Users")
	ErrDisabledHere      = errors.New("this account is turned off in HardyOS; an administrator can turn it on in Control Panel > Users & Groups")
	// ErrAccountGone ends the sessions of a domain account that was
	// deleted, turned off or expired since it signed in.
	ErrAccountGone = errors.New("the domain account is no longer allowed to sign in")
)

// Groups whose members become HardyOS administrators.
const (
	GroupDomainAdmins  = "Domain Admins"
	GroupHardyOSAdmins = "HardyOS Admins"
)

// GroupRefreshInterval is how long a domain account's groups are trusted
// before they're looked up again during a session.
const GroupRefreshInterval = 10 * time.Minute

// refreshRetry spaces out lookups while the domain can't be asked.
const refreshRetry = time.Minute

// domainCheckTimeout bounds a whole domain password check and lookup.
const domainCheckTimeout = 15 * time.Second

// samRE is the shape of a domain user name (domain.CheckUsername).
var samRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,19}$`)

// SignIn checks desktop sign-ins: local HardyOS accounts, and domain
// accounts when this server has a domain.
type SignIn struct {
	Users    *Users
	Domain   DomainDirectory // nil: local accounts only
	Kerberos PasswordChecker // nil: KerberosChecker{}
	Log      *slog.Logger

	refreshing sync.Map // user ID -> *refreshState
}

type refreshState struct {
	mu      sync.Mutex
	nextTry time.Time
}

func (s *SignIn) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *SignIn) kerberos() PasswordChecker {
	if s.Kerberos != nil {
		return s.Kerberos
	}
	return KerberosChecker{}
}

// nameForm is how a sign-in name was written.
type nameForm int

const (
	formBare      nameForm = iota // alice
	formDownLevel                 // HOME\alice
	formUPN                       // alice@home.example.net
)

// splitName separates a typed name into the domain part and the name.
func splitName(typed string) (domainPart, name string, form nameForm) {
	typed = strings.TrimSpace(typed)
	if i := strings.IndexByte(typed, '\\'); i >= 0 {
		return typed[:i], typed[i+1:], formDownLevel
	}
	if i := strings.LastIndexByte(typed, '@'); i >= 0 {
		return typed[i+1:], typed[:i], formUPN
	}
	return "", typed, formBare
}

// ourDomain reports whether a typed domain part names info's domain.
func ourDomain(info *DomainInfo, part string, form nameForm) bool {
	part = strings.TrimSuffix(strings.TrimSpace(part), ".")
	if part == "" {
		return false
	}
	switch form {
	case formDownLevel:
		return strings.EqualFold(part, info.NetBIOS) || strings.EqualFold(part, info.DNS) || strings.EqualFold(part, info.Realm)
	case formUPN:
		return strings.EqualFold(part, info.DNS) || strings.EqualFold(part, info.Realm)
	}
	return false
}

// LimitKey is the rate-limit key for a typed name. Every spelling of one
// domain account (alice, HOME\alice, alice@home.example.net) shares a key,
// so switching spellings doesn't buy more guesses.
func (s *SignIn) LimitKey(ctx context.Context, typed string) string {
	part, name, form := splitName(typed)
	name = strings.ToLower(name)
	if form == formBare {
		if _, err := s.Users.GetByName(ctx, name); err == nil || s.Domain == nil {
			return "user:" + name
		}
	}
	if s.Domain != nil {
		if info, err := s.Domain.Info(ctx); err == nil && info != nil && (form == formBare || ourDomain(info, part, form)) {
			return "user:" + strings.ToLower(info.NetBIOS) + `\` + name
		}
	}
	return "user:" + strings.ToLower(strings.TrimSpace(typed))
}

// Authenticate signs someone in with what they typed: a local username, or
// a domain account as alice, HOME\alice or alice@home.example.net. A local
// account wins over a domain account with the same bare name.
//
// Wrong passwords and unknown names both give ErrBadCredentials, as for
// local accounts. The domain's own state errors (ErrAccountDisabled and
// friends) are shown too: any device on the network can already ask the
// domain controller these questions directly.
func (s *SignIn) Authenticate(ctx context.Context, typed, pw string) (*User, error) {
	part, name, form := splitName(typed)
	if form == formBare {
		u, err := s.Users.GetByName(ctx, name)
		if err == nil && u.Source == SourceLocal {
			return s.Users.Authenticate(ctx, name, pw)
		}
		if s.Domain == nil {
			return s.Users.Authenticate(ctx, name, pw)
		}
	}
	if s.Domain == nil {
		VerifyPassword(pw, dummyHash)
		return nil, ErrBadCredentials
	}
	info, err := s.Domain.Info(ctx)
	if err != nil || info == nil {
		if err != nil {
			s.log().Warn("domain sign-in: can't read the domain", "err", err)
		}
		if form == formBare {
			// Same answer and timing as an unknown local name.
			return s.Users.Authenticate(ctx, name, pw)
		}
		if err != nil {
			return nil, ErrDomainUnavailable
		}
		return nil, ErrUnknownDomain
	}
	if form != formBare && !ourDomain(info, part, form) {
		return nil, ErrUnknownDomain
	}
	if form == formBare {
		// Keep a bare domain name as slow as a local one, so timing doesn't
		// tell local and domain accounts apart.
		VerifyPassword(pw, dummyHash)
	}
	if !samRE.MatchString(name) || strings.HasSuffix(name, ".") {
		return nil, ErrBadCredentials
	}
	return s.domainSignIn(ctx, info, name, pw)
}

func (s *SignIn) domainSignIn(ctx context.Context, info *DomainInfo, name, pw string) (*User, error) {
	ctx, cancel := context.WithTimeout(ctx, domainCheckTimeout)
	defer cancel()
	if pw == "" || len(pw) > 1024 {
		return nil, ErrBadCredentials
	}
	err := s.kerberos().CheckPassword(ctx, *info, name, pw)
	switch {
	case err == nil:
	case errors.Is(err, ErrAccountRevoked):
		// Say which, if the directory can tell.
		if a, aerr := s.Domain.Account(ctx, name); aerr == nil && a.Exists {
			switch {
			case !a.Enabled:
				return nil, ErrAccountDisabled
			case a.Expired:
				return nil, ErrAccountExpired
			case a.LockedOut:
				return nil, ErrAccountLocked
			}
		}
		return nil, ErrAccountRevoked
	case isAny(err, ErrBadCredentials, ErrPasswordExpired, ErrClockSkew, ErrDomainUnavailable):
		return nil, err
	default:
		s.log().Warn("domain sign-in: Kerberos failed", "user", name, "err", err)
		return nil, ErrDomainUnavailable
	}

	a, err := s.Domain.Account(ctx, name)
	if err != nil {
		s.log().Warn("domain sign-in: group lookup failed", "user", name, "err", err)
		return nil, ErrDomainUnavailable
	}
	if err := accountUsable(a); err != nil {
		return nil, err
	}
	u, err := s.Users.UpsertDomain(ctx, domainUpdate(info, a))
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, ErrDisabledHere
	}
	s.Users.touchLogin(ctx, u.ID)
	return u, nil
}

func accountUsable(a *DomainAccount) error {
	switch {
	case a == nil || !a.Exists:
		return ErrBadCredentials
	case !a.Enabled:
		return ErrAccountDisabled
	case a.Expired:
		return ErrAccountExpired
	}
	return nil
}

func domainUpdate(info *DomainInfo, a *DomainAccount) DomainUpdate {
	groups := make([]string, 0, len(a.Groups))
	role := RoleUser
	for _, g := range a.Groups {
		if strings.EqualFold(g, GroupDomainAdmins) || strings.EqualFold(g, GroupHardyOSAdmins) {
			role = RoleAdmin
		}
		groups = append(groups, info.NetBIOS+`\`+g)
	}
	return DomainUpdate{
		Principal:   info.NetBIOS + `\` + a.Username,
		DisplayName: a.DisplayName,
		Email:       a.Email,
		Role:        role,
		Groups:      groups,
	}
}

// Verify checks the password of someone already signed in (the terminal
// asks again before opening a root shell).
func (s *SignIn) Verify(ctx context.Context, u *User, pw string) error {
	if u.Source != SourceDomain {
		_, err := s.Users.Authenticate(ctx, u.Username, pw)
		return err
	}
	if s.Domain == nil {
		return ErrDomainUnavailable
	}
	info, err := s.Domain.Info(ctx)
	if err != nil {
		return ErrDomainUnavailable
	}
	part, name, _ := splitName(u.Principal)
	if info == nil || !strings.EqualFold(part, info.NetBIOS) {
		return ErrAccountGone
	}
	ctx, cancel := context.WithTimeout(ctx, domainCheckTimeout)
	defer cancel()
	err = s.kerberos().CheckPassword(ctx, *info, name, pw)
	if err != nil && !isAny(err, ErrBadCredentials, ErrAccountRevoked, ErrPasswordExpired, ErrClockSkew, ErrDomainUnavailable) {
		return ErrDomainUnavailable
	}
	return err
}

// Refresh looks a domain account's groups up again when they're older than
// GroupRefreshInterval, updating its role. It returns ErrAccountGone when
// the account was deleted, turned off or expired in the domain (end its
// sessions). While the domain can't be asked, the account keeps the groups
// it has and the lookup is retried a minute later. Local accounts are
// returned unchanged.
func (s *SignIn) Refresh(ctx context.Context, u *User) (*User, error) {
	if u.Source != SourceDomain || time.Since(u.groupsCheckedAt) < GroupRefreshInterval {
		return u, nil
	}
	v, _ := s.refreshing.LoadOrStore(u.ID, &refreshState{})
	st := v.(*refreshState)
	if !st.mu.TryLock() {
		return u, nil // another request is already asking
	}
	defer st.mu.Unlock()
	if time.Now().Before(st.nextTry) {
		return u, nil
	}
	if s.Domain == nil {
		return nil, ErrAccountGone
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	info, err := s.Domain.Info(ctx)
	if err != nil {
		st.nextTry = time.Now().Add(refreshRetry)
		s.log().Warn("domain groups refresh: can't read the domain", "user", u.Username, "err", err)
		return u, nil
	}
	part, name, _ := splitName(u.Principal)
	if info == nil || !strings.EqualFold(part, info.NetBIOS) {
		return nil, ErrAccountGone
	}
	a, err := s.Domain.Account(ctx, name)
	if err != nil {
		st.nextTry = time.Now().Add(refreshRetry)
		s.log().Warn("domain groups refresh failed", "user", u.Username, "err", err)
		return u, nil
	}
	if accountUsable(a) != nil {
		return nil, ErrAccountGone
	}
	nu, err := s.Users.UpsertDomain(ctx, domainUpdate(info, a))
	if err != nil {
		return nil, err
	}
	s.refreshing.Delete(u.ID)
	return nu, nil
}

func isAny(err error, targets ...error) bool {
	for _, t := range targets {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}
