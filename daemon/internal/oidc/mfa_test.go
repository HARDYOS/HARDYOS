package oidc

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// homeOnlyMFA asks for nothing at home and a code from outside; must
// makes MustEnroll say yes.
type homeOnlyMFA struct{ must *atomic.Bool }

func (homeOnlyMFA) Requirement(_ context.Context, _ *auth.User, outside bool) (auth.Need, error) {
	if outside {
		return auth.NeedCode, nil
	}
	return auth.NeedNothing, nil
}
func (h homeOnlyMFA) MustEnroll(context.Context, *auth.User) (bool, error) {
	return h.must != nil && h.must.Load(), nil
}
func (homeOnlyMFA) Verify(context.Context, *auth.User, string, auth.Origin) (auth.Factor, error) {
	return "", auth.ErrBadCode
}
func (homeOnlyMFA) ConsumeSetupCode(context.Context, int64, string, auth.Origin) error {
	return auth.ErrBadSetupCode
}
func (homeOnlyMFA) BeginEnroll(context.Context, *auth.User, string, string) (*auth.Enrollment, error) {
	return nil, errors.New("no")
}
func (homeOnlyMFA) ConfirmEnroll(context.Context, *auth.User, string, string, auth.Origin) ([]string, error) {
	return nil, errors.New("no")
}

// A sign-in made at home without a second factor can't be refreshed from
// outside, nor while the person must set one up (decision 441).
func TestRefreshFromOutsideNeedsSecondFactor(t *testing.T) {
	e := newEnv(t)
	must := &atomic.Bool{}
	e.p.cfg.MFA = homeOnlyMFA{must: must}
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	f.scopes = "openid profile offline_access"
	cb := e.browser().login(f, "alice", "pw")
	tok := e.exchange(f, cb.Get("code"))
	if tok.RefreshToken == "" {
		t.Fatalf("no refresh token: %+v", tok)
	}
	// At home it refreshes.
	t2 := e.refresh(f, tok.RefreshToken)
	if t2.Status != 200 {
		t.Fatalf("refresh at home: %+v", t2)
	}
	// From outside the sign-in ends.
	e.public.Store(true)
	if t3 := e.refresh(f, t2.RefreshToken); t3.Status != 400 {
		t.Fatalf("refresh from outside: %+v", t3)
	}
	if !e.sawAudit("oidc.token.revoke success sign-in ended at refresh: this sign-in was made without a second factor") {
		t.Fatalf("not audited: %v", e.audits)
	}
	// And from outside, the password alone leads to the code page.
	b := e.browser()
	page := body(b.authorize(f))
	resp, page := b.signIn(page, "alice", "pw")
	if resp.StatusCode != 200 || !strings.Contains(page, `action="/oidc/login/code"`) || strings.Contains(page, "http-equiv=\"refresh\"") {
		t.Fatalf("no code page from outside: %d %.300s", resp.StatusCode, page)
	}

	// While the person must set up two-factor sign-in, a sign-in without
	// one doesn't refresh even at home.
	e.public.Store(false)
	cb = e.browser().login(f, "alice", "pw")
	tok = e.exchange(f, cb.Get("code"))
	must.Store(true)
	if t4 := e.refresh(f, tok.RefreshToken); t4.Status != 400 {
		t.Fatalf("refresh while enrollment is due: %+v", t4)
	}
}

// The grant remembers where the browser was: one made outside without a
// second factor (before two-factor sign-in existed) never refreshes.
func TestGrantRemembersOutsideBrowser(t *testing.T) {
	e := newEnv(t)
	e.domain.add("alice", "pw", aliceGUID)
	_, f := confidentialClient(e, ClientSpec{})
	f.scopes = "openid profile offline_access"
	// No second factors yet (an older HardyOS): signed in from outside.
	e.public.Store(true)
	cb := e.browser().login(f, "alice", "pw")
	tok := e.exchange(f, cb.Get("code"))
	var outside bool
	if err := e.db.QueryRow(`SELECT browser_outside FROM oidc_grants ORDER BY created_at DESC LIMIT 1`).Scan(&outside); err != nil || !outside {
		t.Fatalf("browser_outside not recorded: %v %v", outside, err)
	}
	// Two-factor sign-in turned on; the app's server refreshes from home.
	e.p.cfg.MFA = homeOnlyMFA{}
	e.public.Store(false)
	if t2 := e.refresh(f, tok.RefreshToken); t2.Status != 400 {
		t.Fatalf("refresh of an outside sign-in without a second factor: %+v", t2)
	}
}
