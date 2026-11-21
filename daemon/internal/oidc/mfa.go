package oidc

import (
	"context"
	"encoding/base32"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/qrsvg"
)

// SecondFactors is what the provider needs of auth.MFA (decisions
// 440-449): what a sign-in still needs after the password, checking codes,
// and enrollment.
type SecondFactors interface {
	Requirement(ctx context.Context, u *auth.User, outside bool) (auth.Need, error)
	MustEnroll(ctx context.Context, u *auth.User) (bool, error)
	Verify(ctx context.Context, u *auth.User, code string, o auth.Origin) (auth.Factor, error)
	ConsumeSetupCode(ctx context.Context, uid int64, code string, o auth.Origin) error
	BeginEnroll(ctx context.Context, u *auth.User, issuer, bind string) (*auth.Enrollment, error)
	ConfirmEnroll(ctx context.Context, u *auth.User, code, bind string, o auth.Origin) ([]string, error)
}

var _ SecondFactors = (*auth.MFA)(nil)

// chal is the challenges store: the desktop's own (one budget for both)
// when hardyd shares it, else the provider's.
func (p *Provider) chal() *auth.Challenges {
	if p.cfg.Challenges != nil {
		return p.cfg.Challenges
	}
	return &p.challenges
}

// origin is where r's codes count (decision 444).
func (p *Provider) origin(r *http.Request) auth.Origin {
	return auth.Origin{Outside: p.outside(r), IP: p.cfg.ClientIP(r)}
}

type outsideKey struct{}

func withOutside(ctx context.Context, outside bool) context.Context {
	return context.WithValue(ctx, outsideKey{}, outside)
}

// outsideFrom is what withOutside recorded (false when nothing was: the
// op package's own background work).
func outsideFrom(ctx context.Context) bool {
	v, _ := ctx.Value(outsideKey{}).(bool)
	return v
}

// outside reports whether r is from outside (two-factor sign-in required).
func (p *Provider) outside(r *http.Request) bool {
	if p.cfg.Outside != nil {
		return p.cfg.Outside(r)
	}
	return p.cfg.PublicOrigin != nil && p.cfg.PublicOrigin(r)
}

// secondFactorNeed is what u still needs after the password here. If it
// can't be told, a code is asked for (failing closed).
func (p *Provider) secondFactorNeed(r *http.Request, u *auth.User) auth.Need {
	if p.cfg.MFA == nil {
		return auth.NeedNothing
	}
	need, err := p.cfg.MFA.Requirement(r.Context(), u, p.outside(r))
	if err != nil {
		p.cfg.Log.Warn("oidc: two-factor requirement", "user", u.Username, "err", err)
		return auth.NeedCode
	}
	return need
}

func (p *Provider) totpIssuer() string {
	if p.cfg.TOTPIssuer != nil {
		if s := p.cfg.TOTPIssuer(); s != "" {
			return s
		}
	}
	return "HardyOS"
}

// askSecondFactor starts a challenge for a right password and shows the
// page for what is still needed.
func (p *Provider) askSecondFactor(w http.ResponseWriter, r *http.Request, base string, a *authRequest, c *Client, b string, u *auth.User, need auth.Need) {
	tok, _, err := p.chal().Issue(u.ID, need, p.outside(r))
	if err != nil {
		p.problem(w, base, http.StatusServiceUnavailable, "Can't sign you in right now", sentence(err.Error()))
		return
	}
	if need == auth.NeedCode {
		p.codePage(w, http.StatusOK, base, a, c, b, tok, "")
		return
	}
	p.setupPage(w, http.StatusOK, base, a, c, b, tok, need == auth.NeedSetupCode, "")
}

func (p *Provider) codePage(w http.ResponseWriter, status int, base string, a *authRequest, c *Client, b, tok, msg string) {
	p.render(w, status, &page{Kind: "code", Base: base, Title: "Two-factor sign-in", Heading: "Enter your code",
		Lead:   "Open your authenticator app and enter the 6-digit code for HardyOS, or one of your recovery codes.",
		Client: c.Name, AppHost: appHost(a.RedirectURI), ID: a.ID, Challenge: tok, CSRF: p.mac("code", a.ID, b, tok), Error: msg})
}

func (p *Provider) setupPage(w http.ResponseWriter, status int, base string, a *authRequest, c *Client, b, tok string, setupCode bool, msg string) {
	lead := "Administrators must use two-factor sign-in. Set up an authenticator app now to continue."
	if setupCode {
		lead = "Signing in from outside your home network needs two-factor sign-in, and this account hasn't set it up. " +
			"Set it up at home (Settings > Two-factor sign-in on the HardyOS desktop), or enter the one-time setup code an administrator gave you."
	}
	p.render(w, status, &page{Kind: "setup", Base: base, Title: "Set up two-factor sign-in", Heading: "Set up two-factor sign-in",
		Lead: lead, Client: c.Name, ID: a.ID, Challenge: tok, CSRF: p.mac("setup", a.ID, b, tok), SetupCode: setupCode, Error: msg})
}

func (p *Provider) enrollPage(w http.ResponseWriter, status int, base string, a *authRequest, c *Client, b, tok string, e *auth.Enrollment, msg string) {
	pg := &page{Kind: "enroll", Base: base, Title: "Set up two-factor sign-in", Heading: "Scan this code",
		Lead:   "Scan the code with an authenticator app (or type the key), then enter the 6-digit code it shows.",
		Client: c.Name, ID: a.ID, Challenge: tok, CSRF: p.mac("enroll", a.ID, b, tok), Secret: e.Secret, Error: msg}
	if q, err := qrsvg.Encode(e.URI); err == nil {
		// qrsvg's markup holds only numbers and fixed tags.
		pg.QR = template.HTML(q.SVG(208)) //nolint:gosec
	}
	p.render(w, status, pg)
}

// enrollmentFromForm rebuilds the enrollment shown on the page (to show it
// again after a wrong code) from the key the form carried back. It only
// shows the person what they already saw: the code is checked against the
// pending secret in the database.
func (p *Provider) enrollmentFromForm(secretText string, u *auth.User) *auth.Enrollment {
	clean := strings.ToUpper(strings.ReplaceAll(secretText, " ", ""))
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil || len(raw) == 0 || len(raw) > 64 {
		return &auth.Enrollment{}
	}
	return &auth.Enrollment{Secret: auth.TOTPSecretText(raw), URI: auth.TOTPURI(p.totpIssuer(), u.IdentityPrincipal(), raw)}
}

func codeError(err error) string {
	var rl *auth.CodeRateLimited
	switch {
	case errors.As(err, &rl):
		return sentence(rl.Error())
	case errors.Is(err, auth.ErrCodeLocked), errors.Is(err, auth.ErrSecretUnusable), errors.Is(err, auth.ErrBadSetupCode), errors.Is(err, auth.ErrNoPending):
		return sentence(err.Error())
	}
	return "That code isn't right. Check your authenticator app's clock and try the newest code."
}

// secondFactorPost handles the code, setup and enroll forms.
func (p *Provider) secondFactorPost(w http.ResponseWriter, r *http.Request, base, step string) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		p.problem(w, base, http.StatusBadRequest, "Something went wrong", "Go back to the app and sign in again.")
		return
	}
	a, c, b, ok := p.openRequest(w, r, base, r.PostForm.Get("id"))
	if !ok {
		return
	}
	tok := r.PostForm.Get("challenge")
	if !sameOrigin(r) || !p.macOK(r.PostForm.Get("csrf"), step, a.ID, b, tok) {
		p.problem(w, base, http.StatusForbidden, "This form has expired", "Go back to the app and sign in again.")
		return
	}
	expired := func() {
		p.problem(w, base, http.StatusUnauthorized, "This sign-in has expired", "Go back to the app and sign in again.")
	}
	ch, err := p.chal().Get(tok)
	if err != nil || ch.Outside != p.outside(r) || p.cfg.MFA == nil {
		expired()
		return
	}
	ctx := r.Context()
	u, err := p.cfg.LoadUser(ctx, ch.UserID)
	if err != nil || u.Disabled || p.adminRefused(r, u) {
		p.chal().Done(tok)
		expired()
		return
	}
	ip := p.cfg.ClientIP(r)
	note := publicNote(p.outside(r))
	switch step {
	case "code":
		if ch.Need != auth.NeedCode {
			expired()
			return
		}
		fac, err := p.cfg.MFA.Verify(ctx, u, r.PostForm.Get("code"), p.origin(r))
		if err != nil {
			p.audit(ctx, ip, u, "oidc.signin", c.Name, audit.Failure, "two-factor code: "+err.Error()+note)
			status := http.StatusUnauthorized
			var rl *auth.CodeRateLimited
			if errors.As(err, &rl) {
				status = http.StatusTooManyRequests
			}
			p.codePage(w, status, base, a, c, b, tok, codeError(err))
			return
		}
		p.chal().Done(tok)
		how := "password and two-factor code"
		if fac == auth.FactorRecovery {
			how = "password and recovery code (two-factor)"
		}
		now := p.now()
		p.startSessionMFA(w, r, u, now, true)
		p.proceed(w, r, base, a, c, u, now, how, true)
	case "setup":
		if ch.Need != auth.NeedEnroll && ch.Need != auth.NeedSetupCode {
			expired()
			return
		}
		if ch.Need == auth.NeedSetupCode && !ch.SetupOK {
			// Used up the moment it's accepted (one compare-and-clear).
			if err := p.cfg.MFA.ConsumeSetupCode(ctx, u.ID, r.PostForm.Get("setup_code"), p.origin(r)); err != nil {
				p.audit(ctx, ip, u, "oidc.signin", c.Name, audit.Failure, "two-factor setup code: "+err.Error()+note)
				p.setupPage(w, http.StatusUnauthorized, base, a, c, b, tok, true, codeError(err))
				return
			}
		}
		p.chal().Update(tok, func(c *auth.Challenge) { c.SetupOK = true })
		p.audit(ctx, ip, u, "auth.2fa.enroll_start", u.Username, audit.Success, "from the sign-in page"+note)
		e, err := p.cfg.MFA.BeginEnroll(ctx, u, p.totpIssuer(), auth.BindHash("challenge", tok))
		if err != nil {
			p.cfg.Log.Error("oidc: begin two-factor enrollment", "err", err)
			p.problem(w, base, http.StatusInternalServerError, "Something went wrong", "Go back to the app and sign in again.")
			return
		}
		p.chal().Update(tok, func(c *auth.Challenge) { c.Started, c.SetupOK = true, true })
		p.enrollPage(w, http.StatusOK, base, a, c, b, tok, e, "")
	case "enroll":
		if (ch.Need != auth.NeedEnroll && ch.Need != auth.NeedSetupCode) || !ch.Started || !ch.SetupOK {
			expired()
			return
		}
		codes, err := p.cfg.MFA.ConfirmEnroll(ctx, u, r.PostForm.Get("code"), auth.BindHash("challenge", tok), p.origin(r))
		if err != nil {
			p.audit(ctx, ip, u, "auth.2fa.enable", u.Username, audit.Failure, "from the sign-in page: "+err.Error()+note)
			if errors.Is(err, auth.ErrNoPending) {
				p.chal().Done(tok)
				expired()
				return
			}
			p.enrollPage(w, http.StatusUnauthorized, base, a, c, b, tok, p.enrollmentFromForm(r.PostForm.Get("secret"), u), codeError(err))
			return
		}
		p.chal().Done(tok)
		p.audit(ctx, ip, u, "auth.2fa.enable", u.Username, audit.Success, "set up from the sign-in page"+note)
		// Everything signed in before ends: desktop and app sessions, WebDAV,
		// Office, and every app sign-in and token (decision 442).
		if p.cfg.SecondFactorSet != nil {
			p.cfg.SecondFactorSet(ctx, u.ID)
		} else if p.cfg.EndSessions != nil {
			p.cfg.EndSessions(ctx, u.ID)
		}
		p.EndUser(ctx, u.ID)
		p.startSessionMFA(w, r, u, p.now(), true)
		next := base + "/login?" + url.Values{"id": {a.ID}}.Encode()
		p.render(w, http.StatusOK, &page{Kind: "recovery", Base: base, Title: "Recovery codes", Heading: "Save your recovery codes",
			Lead:  "Two-factor sign-in is on. If you lose your phone, each of these codes signs you in once. Write them down or print this page now: they aren't shown again.",
			Codes: codes, Link: next, LinkText: "Continue to " + c.Name})
	default:
		expired()
	}
}
