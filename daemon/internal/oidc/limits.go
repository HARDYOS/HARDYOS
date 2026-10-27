package oidc

import (
	"context"
	"errors"
	"net/url"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Bounds on sign-ins in progress (authorize requests not finished yet): a
// stranger on the internet can open sso.<base>/authorize as often as they
// like, and each one is a database row for 10 minutes.
const (
	maxPendingPerIP  = 30
	maxPendingGlobal = 5000
)

// admitAuthRequest reports whether another sign-in may start for the
// request's client address (at most maxPendingPerIP in authRequestTTL) and
// overall (at most maxPendingGlobal unfinished ones in the database).
func (p *Provider) admitAuthRequest(ctx context.Context) bool {
	var n int
	if err := p.cfg.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM oidc_auth_requests WHERE code_hash IS NULL AND expires_at > ?`,
		store.FormatTime(p.now())).Scan(&n); err != nil || n >= maxPendingGlobal {
		return false
	}
	ip := ""
	if r := requestFrom(ctx); r != nil {
		ip = p.cfg.ClientIP(r)
	}
	now := p.now()
	cutoff := now.Add(-authRequestTTL)
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.pending) > 10000 {
		for k, list := range p.pending {
			if len(list) == 0 || list[len(list)-1].Before(cutoff) {
				delete(p.pending, k)
			}
		}
	}
	kept := p.pending[ip][:0]
	for _, t := range p.pending[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= maxPendingPerIP {
		p.pending[ip] = kept
		return false
	}
	p.pending[ip] = append(kept, now)
	return true
}

// exchangeAllowed checks a token request for a code before the code is
// used up: the client the code was issued to, authenticated (its secret,
// for a confidential client), the PKCE verifier and the redirect URI. The
// op package checks the same again afterwards; doing it first means a code
// presented by anyone else is refused without being burnt (a burnt code
// presented again counts as a replay and revokes the real sign-in).
func (p *Provider) exchangeAllowed(ctx context.Context, a *authRequest) error {
	r := requestFrom(ctx)
	if r == nil {
		return errors.New("no request")
	}
	clientID, secret := r.Form.Get("client_id"), r.Form.Get("client_secret")
	if u, pw, ok := r.BasicAuth(); ok {
		var err1, err2 error
		clientID, err1 = url.QueryUnescape(u)
		secret, err2 = url.QueryUnescape(pw)
		if err1 != nil || err2 != nil {
			return errors.New("malformed client credentials")
		}
	}
	if clientID == "" || clientID != a.ClientID {
		return errors.New("the code wasn't issued to this client")
	}
	c, err := p.Clients.Get(ctx, clientID)
	if err != nil || c.Disabled {
		return errors.New("unknown client")
	}
	if c.Kind == KindConfidential && !c.checkSecret(secret) {
		return errors.New("client authentication failed")
	}
	if ch := a.GetCodeChallenge(); ch != nil {
		if err := op.AuthorizeCodeChallenge(r.Form.Get("code_verifier"), ch); err != nil {
			return errors.New("wrong PKCE verifier")
		}
	} else if c.Kind == KindPublic {
		return errors.New("PKCE required")
	}
	if r.Form.Get("redirect_uri") != a.RedirectURI {
		return errors.New("redirect_uri does not correspond")
	}
	return nil
}
