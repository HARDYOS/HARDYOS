package oidc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// homeOnlyMFA asks for nothing at home and a code from outside.
type homeOnlyMFA struct{}

func (homeOnlyMFA) Requirement(_ context.Context, _ *auth.User, outside bool) (auth.Need, error) {
	if outside {
		return auth.NeedCode, nil
	}
	return auth.NeedNothing, nil
}
func (homeOnlyMFA) Verify(context.Context, *auth.User, string) (auth.Factor, error) {
	return "", auth.ErrBadCode
}
func (homeOnlyMFA) CheckSetupCode(context.Context, int64, string) error { return auth.ErrBadSetupCode }
func (homeOnlyMFA) BeginEnroll(context.Context, *auth.User, string) (*auth.Enrollment, error) {
	return nil, errors.New("no")
}
func (homeOnlyMFA) ConfirmEnroll(context.Context, *auth.User, string) ([]string, error) {
	return nil, errors.New("no")
}

// A sign-in made at home without a second factor can't be refreshed from
// outside (decision 441).
func TestRefreshFromOutsideNeedsSecondFactor(t *testing.T) {
	e := newEnv(t)
	e.p.cfg.MFA = homeOnlyMFA{}
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
}
