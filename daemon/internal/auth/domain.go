package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DomainInfo is what desktop sign-in needs to know about this server's
// domain.
type DomainInfo struct {
	Realm   string // HOME.EXAMPLE.NET
	NetBIOS string // HOME
	DNS     string // home.example.net
	// LocalKDC is the address of the domain controller this server runs
	// itself, reached inside the host (the shim route). It's the only one
	// asked for passwords: a partner DC's answer could come from anyone who
	// can take over its address on the LAN. Empty when this server runs no
	// DC of its own; domain sign-in is refused then (ErrNoLocalDC).
	LocalKDC string
	// AdminsGroupSID is the objectSid of the HardyOS Admins group, recorded
	// when HardyOS created (or an administrator adopted) it; empty when
	// there's none. Members are HardyOS administrators whatever the group is
	// called now.
	AdminsGroupSID string
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
	// nested memberships included. For access rules and display only:
	// the role comes from GroupSIDs, since anyone who may create or rename
	// a group can choose its name.
	Groups []string
	// DomainSID is the domain's SID (S-1-5-21-...); GroupSIDs are the
	// objectSids of the groups in Groups.
	DomainSID string
	GroupSIDs []string
	// SID and ObjectGUID identify the account itself (empty when the
	// directory didn't say). The sign-in provider's subject is the GUID.
	SID        string
	ObjectGUID string
	// PasswordSetAt is when the password was last set (pwdLastSet; zero
	// when unknown or when it must be changed at next sign-in).
	PasswordSetAt time.Time
}

// AccountAnchor is what ties a HardyOS account row to one directory
// object: its objectGUID (lower case), else its SID; "" when the directory
// said neither. A name can be given to another person (delete alice, make
// a new alice); the anchor can't.
func AccountAnchor(a *DomainAccount) string {
	if a == nil {
		return ""
	}
	if a.ObjectGUID != "" {
		return strings.ToLower(a.ObjectGUID)
	}
	return strings.ToUpper(a.SID)
}

// IdentityAnchor remembers which directory object each domain account row
// belongs to (the sign-in provider keeps it with the account's subject).
type IdentityAnchor interface {
	// CheckAnchor compares anchor (AccountAnchor of what the directory says
	// now) with the one recorded for u, recording it when there's none. On
	// a mismatch everything the previous person held (desktop and app
	// sessions, app sign-ins and tokens) is ended. interactive: the person
	// just proved the password, so they are the new owner of the name and
	// the new anchor is recorded (nil is returned); otherwise
	// ErrAccountReplaced.
	CheckAnchor(ctx context.Context, u *User, anchor string, interactive bool) error
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
	ErrDomainUnavailable = errors.New("the domain controller on this server isn't answering; sign in with a HardyOS account")
	// ErrNoLocalDC refuses domain sign-in on a server that doesn't run a
	// domain controller itself: an AS exchange with a DC elsewhere on the
	// LAN can't tell the real one from an impostor.
	ErrNoLocalDC       = errors.New("domain accounts can sign in only on a server that runs the domain controller itself; sign in with a HardyOS account")
	ErrUnknownDomain   = errors.New("that isn't this server's domain; sign in with your name, DOMAIN\\name or name@domain")
	ErrClockSkew       = errors.New("this server's clock and the domain controller's are more than 5 minutes apart; check the time in Control Panel > Date & Time")
	ErrAccountRevoked  = errors.New("this domain account can't sign in right now: it's turned off, locked or expired; ask an administrator (Control Panel > Domain > Users)")
	ErrAccountDisabled = errors.New("this domain account is turned off; an administrator can turn it on in Control Panel > Domain > Users")
	ErrAccountLocked   = errors.New("this domain account is locked after too many wrong passwords; wait a while, or ask an administrator to set a new password in Control Panel > Domain > Users")
	ErrAccountExpired  = errors.New("this domain account has expired; ask an administrator")
	ErrPasswordExpired = errors.New("this password has expired or must be changed first; change it on a computer in the domain, or ask an administrator to set a new one in Control Panel > Domain > Users")
	ErrDisabledHere    = errors.New("this account is turned off in HardyOS; an administrator can turn it on in Control Panel > Users & Groups")
	// ErrAccountGone ends the sessions of a domain account that was
	// deleted, turned off or expired since it signed in.
	ErrAccountGone = errors.New("the domain account is no longer allowed to sign in")
	// ErrAccountReplaced: the name now belongs to another directory object
	// (the account was deleted and another made with the same name). It is
	// an ErrAccountGone for whoever holds a session of the previous one.
	ErrAccountReplaced = fmt.Errorf("%w: the name now belongs to another domain account", ErrAccountGone)
)

// RIDDomainAdmins is the relative ID of the domain's Domain Admins group
// (<domain SID>-512), whose members are HardyOS administrators. The other
// administrators' group is HardyOS Admins, known by the SID in
// DomainInfo.AdminsGroupSID.
const RIDDomainAdmins = 512

// GroupRefreshInterval is how long a domain account's groups are trusted
// before they're looked up again during a session.
const GroupRefreshInterval = 10 * time.Minute

// GroupTrustWindow is how long a domain account keeps its role while its
// groups can't be looked up again: after that it's a user until a lookup
// works.
const GroupTrustWindow = 3 * GroupRefreshInterval

// staleRoleNote is what /auth/me says while the role is held back.
const staleRoleNote = "The domain couldn't be asked about your groups for over 30 minutes, so you have user rights until it answers again."

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
	// Anchor checks that a domain account row still belongs to the same
	// directory object, at every sign-in and every groups refresh (nil:
	// not checked).
	Anchor IdentityAnchor
	// PasswordSet is told when the directory says a domain account's
	// password was set (at sign-in and at every groups refresh), so what was
	// signed in with an older password can end (nil: nothing is done).
	PasswordSet func(ctx context.Context, u *User, at time.Time)

	refreshing sync.Map // user ID -> *refreshState
}

// checkDirectory runs the anchor and password-change hooks for what the
// directory said about u.
func (s *SignIn) checkDirectory(ctx context.Context, u *User, a *DomainAccount, interactive bool) error {
	if s.Anchor != nil {
		if anchor := AccountAnchor(a); anchor != "" {
			if err := s.Anchor.CheckAnchor(ctx, u, anchor, interactive); err != nil {
				return err
			}
		}
	}
	if s.PasswordSet != nil && !a.PasswordSetAt.IsZero() {
		s.PasswordSet(ctx, u, a.PasswordSetAt)
	}
	return nil
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
	if info.LocalKDC == "" {
		return nil, ErrNoLocalDC
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
	case isAny(err, ErrBadCredentials, ErrPasswordExpired, ErrClockSkew, ErrDomainUnavailable, ErrNoLocalDC):
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
	// The password was just proved: whoever had this name before (another
	// directory object) loses everything, and so does anything signed in
	// with an older password.
	if err := s.checkDirectory(ctx, u, a, true); err != nil {
		s.log().Warn("domain sign-in: recording the account's identity", "user", name, "err", err)
		return nil, ErrDomainUnavailable
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

// AdminBySID reports whether group SIDs make an account a HardyOS
// administrator: Domain Admins (<domain SID>-512) or the recorded HardyOS
// Admins group. Group names never count.
func AdminBySID(domainSID, adminsGroupSID string, groupSIDs []string) bool {
	da := ""
	if strings.HasPrefix(domainSID, "S-1-5-21-") {
		da = domainSID + "-" + strconv.Itoa(RIDDomainAdmins)
	}
	for _, sid := range groupSIDs {
		if (da != "" && strings.EqualFold(sid, da)) || (adminsGroupSID != "" && strings.EqualFold(sid, adminsGroupSID)) {
			return true
		}
	}
	return false
}

func domainUpdate(info *DomainInfo, a *DomainAccount) DomainUpdate {
	groups := make([]string, 0, len(a.Groups))
	for _, g := range a.Groups {
		groups = append(groups, info.NetBIOS+`\`+g)
	}
	role := RoleUser
	if AdminBySID(a.DomainSID, info.AdminsGroupSID, a.GroupSIDs) {
		role = RoleAdmin
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
	if info.LocalKDC == "" {
		return ErrNoLocalDC
	}
	ctx, cancel := context.WithTimeout(ctx, domainCheckTimeout)
	defer cancel()
	err = s.kerberos().CheckPassword(ctx, *info, name, pw)
	if err != nil && !isAny(err, ErrBadCredentials, ErrAccountRevoked, ErrPasswordExpired, ErrClockSkew, ErrDomainUnavailable, ErrNoLocalDC) {
		return ErrDomainUnavailable
	}
	return err
}

// Refresh looks a domain account's groups up again when they're older than
// GroupRefreshInterval, updating its role. It returns ErrAccountGone when
// the account was deleted, turned off or expired in the domain (end its
// sessions). While the domain can't be asked, the account keeps the groups
// it has and the lookup is retried a minute later; once GroupTrustWindow
// has passed without a lookup it's a user (RoleNote says why) until one
// works again. Local accounts are returned unchanged.
func (s *SignIn) Refresh(ctx context.Context, u *User) (*User, error) {
	if u.Source != SourceDomain || time.Since(u.groupsCheckedAt) < GroupRefreshInterval {
		return u, nil
	}
	nu, asked, err := s.refresh(ctx, u)
	if err != nil || asked {
		return nu, err
	}
	return s.unverified(ctx, u), nil
}

// refresh asks the domain about u. asked is false when the domain couldn't
// be asked (or another request is asking, or it's too soon to ask again).
func (s *SignIn) refresh(ctx context.Context, u *User) (nu *User, asked bool, err error) {
	v, _ := s.refreshing.LoadOrStore(u.ID, &refreshState{})
	st := v.(*refreshState)
	if !st.mu.TryLock() {
		return u, false, nil // another request is already asking
	}
	defer st.mu.Unlock()
	if time.Now().Before(st.nextTry) {
		return u, false, nil
	}
	if s.Domain == nil {
		return nil, true, ErrAccountGone
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	info, err := s.Domain.Info(ctx)
	if err != nil {
		st.nextTry = time.Now().Add(refreshRetry)
		s.log().Warn("domain groups refresh: can't read the domain", "user", u.Username, "err", err)
		return u, false, nil
	}
	part, name, _ := splitName(u.Principal)
	if info == nil || !strings.EqualFold(part, info.NetBIOS) {
		return nil, true, ErrAccountGone
	}
	a, err := s.Domain.Account(ctx, name)
	if err != nil {
		st.nextTry = time.Now().Add(refreshRetry)
		s.log().Warn("domain groups refresh failed", "user", u.Username, "err", err)
		return u, false, nil
	}
	if accountUsable(a) != nil {
		return nil, true, ErrAccountGone
	}
	// Another directory object behind the name: this session was the
	// previous person's.
	if err := s.checkDirectory(ctx, u, a, false); errors.Is(err, ErrAccountGone) {
		return nil, true, err
	} else if err != nil {
		s.log().Warn("domain groups refresh: checking the account's identity", "user", u.Username, "err", err)
	}
	nu, err = s.Users.UpsertDomain(ctx, domainUpdate(info, a))
	if err != nil {
		return nil, true, err
	}
	s.refreshing.Delete(u.ID)
	return nu, true, nil
}

// unverified is u while its groups can't be looked up: unchanged within
// GroupTrustWindow of the last lookup, a user after it. The demotion is
// written to the account's row too, so nothing reading it later sees an
// administrator; the next lookup that works sets the role from the groups
// again.
func (s *SignIn) unverified(ctx context.Context, u *User) *User {
	if time.Since(u.groupsCheckedAt) < GroupTrustWindow {
		return u
	}
	c := *u
	c.RoleNote = staleRoleNote
	if c.Role == RoleAdmin {
		c.Role = RoleUser
		if err := s.Users.holdBackRole(ctx, u.ID); err != nil {
			s.log().Warn("domain groups refresh: can't record the role held back", "user", u.Username, "err", err)
		} else {
			s.log().Warn("domain groups couldn't be checked for too long: administrator rights held back", "user", u.Username)
		}
	}
	return &c
}

func isAny(err error, targets ...error) bool {
	for _, t := range targets {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}
