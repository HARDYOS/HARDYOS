package auth

import "strings"

// Identity is who a signed-in person is, for access checks such as app
// access and shared folders. *User implements it; handlers get one from the
// session (userFrom / the authed handler's argument).
//
// Principals are written the way the contract stores them:
//
//	local account   "alice"
//	domain user     "HOME\alice"   (NETBIOS\sAMAccountName)
//	domain group    "HOME\Family"
//	everybody       kind "everyone"
//
// Names compare case-insensitively, like Windows does. A rule naming a bare
// "alice" matches only the local account, never HOME\alice.
type Identity interface {
	// IdentitySource is SourceLocal or SourceDomain.
	IdentitySource() string
	// IdentityPrincipal is "alice" or "HOME\alice".
	IdentityPrincipal() string
	// IdentityGroups are the domain groups ("HOME\Family"), Domain Users
	// included; nil for local accounts. Refreshed at sign-in and at most
	// every 10 minutes while signed in.
	IdentityGroups() []string
	// IsAdmin: administrators may use and manage everything.
	IsAdmin() bool
	// Matches reports whether an access rule of kind "user", "group" or
	// "everyone" with the given name applies to this person.
	Matches(kind, name string) bool
}

// Principal kinds in access rules.
const (
	PrincipalUser     = "user"
	PrincipalGroup    = "group"
	PrincipalEveryone = "everyone"
)

var _ Identity = (*User)(nil)

// IdentitySource implements Identity.
func (u *User) IdentitySource() string {
	if u.Source == "" {
		return SourceLocal
	}
	return u.Source
}

// IdentityPrincipal implements Identity.
func (u *User) IdentityPrincipal() string {
	if u.Principal == "" {
		return u.Username
	}
	return u.Principal
}

// IdentityGroups implements Identity.
func (u *User) IdentityGroups() []string {
	if u.IdentitySource() != SourceDomain {
		return nil
	}
	return u.Groups
}

// Matches implements Identity.
func (u *User) Matches(kind, name string) bool {
	if u == nil || u.Disabled {
		return false
	}
	name = strings.TrimSpace(name)
	switch kind {
	case PrincipalEveryone:
		return true
	case PrincipalUser:
		return SamePrincipal(u.IdentityPrincipal(), name)
	case PrincipalGroup:
		for _, g := range u.IdentityGroups() {
			if SamePrincipal(g, name) {
				return true
			}
		}
	}
	return false
}

// SamePrincipal compares two principal names the way the domain does
// (case-insensitively).
func SamePrincipal(a, b string) bool { return a != "" && strings.EqualFold(a, b) }
