package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// privDirectory answers desktop sign-in's questions about the domain
// through hardyd-priv: domain.status for the realm and domain controllers
// (cached briefly: it's asked on every sign-in with a domain name), and
// domain.user_groups for an account's state and groups.
type privDirectory struct {
	pc  *priv.Client
	ttl time.Duration

	mu     sync.Mutex
	info   *auth.DomainInfo
	infoAt time.Time
}

func (d *privDirectory) Info(ctx context.Context) (*auth.DomainInfo, error) {
	ttl := d.ttl
	if ttl == 0 {
		ttl = 30 * time.Second
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.infoAt.IsZero() && time.Since(d.infoAt) < ttl {
		return d.info, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var st domain.Status
	if err := d.pc.Call(ctx, priv.OpDomainStatus, nil, &st); err != nil {
		var pe *priv.Error
		if errors.As(err, &pe) && pe.Code == priv.CodeUnknownOp {
			// A root helper without the domain controller (dev machines).
			d.info, d.infoAt = nil, time.Now()
			return nil, nil
		}
		return nil, err
	}
	d.info = domainInfo(&st)
	d.infoAt = time.Now()
	return d.info, nil
}

// domainInfo is sign-in's view of the domain's status, or nil without a
// domain. Passwords are checked only with the DC this server runs itself
// (its address, reached through the shim route inside the host), never
// with its partners: see auth.KerberosChecker.
func domainInfo(st *domain.Status) *auth.DomainInfo {
	if st == nil || !st.Provisioned || st.Config == nil || st.Config.Realm == "" {
		return nil
	}
	c := st.Config
	return &auth.DomainInfo{Realm: c.Realm, NetBIOS: c.NetBIOS, DNS: c.Domain, LocalKDC: c.IP(), AdminsGroupSID: c.AdminsGroupSID}
}

func (d *privDirectory) Account(ctx context.Context, username string) (*auth.DomainAccount, error) {
	var g domain.UserGroups
	if err := d.pc.Call(ctx, priv.OpDomainUserGroups, priv.DomainUserRef{Username: username}, &g); err != nil {
		var pe *priv.Error
		if errors.As(err, &pe) && pe.Code == priv.CodeBadArgs {
			// A name the directory can't hold is no account at all.
			return &auth.DomainAccount{}, nil
		}
		return nil, err
	}
	return &auth.DomainAccount{
		Exists: g.Exists, Username: g.Username, DisplayName: g.DisplayName, Email: g.Email,
		Enabled: g.Enabled, LockedOut: g.LockedOut, Expired: g.Expired, Groups: g.Groups,
		DomainSID: g.DomainSID, GroupSIDs: g.GroupSIDs, SID: g.SID, ObjectGUID: g.ObjectGUID,
	}, nil
}

// domainSignInAvailable reports whether the sign-in page should mention
// domain accounts.
func (s *Server) domainSignInAvailable(ctx context.Context) bool {
	if s.signin == nil || s.signin.Domain == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	info, err := s.signin.Domain.Info(ctx)
	return err == nil && info != nil
}

// loginError answers a failed sign-in. counts reports whether it is a
// failed guess for the rate limiter (an unreachable domain isn't).
func loginError(w http.ResponseWriter, err error) (detail string, counts bool) {
	a, msg, ok := classifyLoginError(err)
	if !ok {
		return "", false
	}
	writeError(w, a.status, a.code, msg)
	return a.code, a.counts
}

// loginAnswer is how a failed sign-in is answered.
type loginAnswer struct {
	status int
	code   string
	counts bool
}

// classifyLoginError says how to answer a failed sign-in (the desktop's and
// the sign-in provider's pages share it); ok is false for other errors.
func classifyLoginError(err error) (loginAnswer, string, bool) {
	type answer = loginAnswer
	answers := []struct {
		err error
		answer
	}{
		{auth.ErrBadCredentials, answer{http.StatusUnauthorized, "bad_credentials", true}},
		{auth.ErrUnknownDomain, answer{http.StatusUnauthorized, "unknown_domain", true}},
		{auth.ErrAccountDisabled, answer{http.StatusUnauthorized, "account_disabled", true}},
		{auth.ErrAccountLocked, answer{http.StatusUnauthorized, "account_locked", true}},
		{auth.ErrAccountExpired, answer{http.StatusUnauthorized, "account_expired", true}},
		{auth.ErrAccountRevoked, answer{http.StatusUnauthorized, "account_unavailable", true}},
		{auth.ErrPasswordExpired, answer{http.StatusUnauthorized, "password_expired", true}},
		{auth.ErrDisabledHere, answer{http.StatusUnauthorized, "account_disabled", false}},
		{auth.ErrClockSkew, answer{http.StatusServiceUnavailable, "clock_skew", false}},
		{auth.ErrDomainUnavailable, answer{http.StatusServiceUnavailable, "domain_unavailable", false}},
		{auth.ErrNoLocalDC, answer{http.StatusServiceUnavailable, "no_local_dc", false}},
	}
	for _, a := range answers {
		if errors.Is(err, a.err) {
			return a.answer, a.err.Error(), true
		}
	}
	return loginAnswer{}, "", false
}
