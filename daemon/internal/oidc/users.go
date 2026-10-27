package oidc

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"slices"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
)

// Why a person can't sign in to an app.
var (
	ErrLocalAccountsOff = errors.New("HardyOS accounts can't sign in to apps here; sign in with your domain account (DOMAIN\\name)")
	ErrNotInGroups      = errors.New("your account isn't in a group allowed to use this app; ask an administrator")
	ErrNoSubject        = errors.New("the domain controller on this server isn't answering, so your account can't be confirmed; try again in a moment")
)

// allowed checks that u may use client c: local accounts only when they're
// turned on; members of the client's groups when it has any.
func (p *Provider) allowed(ctx context.Context, c *Client, u *auth.User) error {
	if c.Disabled {
		return errors.New("this app is turned off")
	}
	if u.IdentitySource() != auth.SourceDomain && !p.loadSettings(ctx).localAccounts {
		return ErrLocalAccountsOff
	}
	if len(c.AllowedGroups) == 0 {
		return nil
	}
	for _, g := range c.AllowedGroups {
		if u.Matches(auth.PrincipalGroup, g) {
			return nil
		}
	}
	return ErrNotInGroups
}

// subjectFor returns the stable subject (sub) for u, recording it the
// first time: a domain account's objectGUID (its SID with an older
// directory helper), which survives renames; a random value for a local
// account. If the directory says the account's GUID changed (the account
// was deleted and another made with the same name), the old person's
// grants and consents are dropped and the new one gets its own subject.
func (p *Provider) subjectFor(ctx context.Context, u *auth.User) (string, error) {
	db := p.cfg.DB
	var cur, curGUID string
	err := db.QueryRowContext(ctx, `SELECT sub, guid FROM oidc_subjects WHERE user_id = ?`, u.ID).Scan(&cur, &curGUID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if u.IdentitySource() != auth.SourceDomain {
		if cur != "" {
			return cur, nil
		}
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		sub := "local-" + base64.RawURLEncoding.EncodeToString(b)
		if _, err := db.ExecContext(ctx, `INSERT INTO oidc_subjects (user_id, sub) VALUES (?, ?)`, u.ID, sub); err != nil {
			return "", err
		}
		return sub, nil
	}
	guid := p.domainGUID(ctx, u)
	if guid == "" {
		if cur != "" {
			return cur, nil // the directory can't be asked: keep what we know
		}
		return "", ErrNoSubject
	}
	if cur == guid {
		return cur, nil
	}
	if cur != "" {
		// Another person with the same name: nothing of the old one carries over.
		_, _ = revokeWhere(ctx, db, p.now(), `user_id = ?`, u.ID)
		_, _ = db.ExecContext(ctx, `DELETE FROM oidc_consents WHERE user_id = ?`, u.ID)
		p.audit(ctx, "", u, "oidc.subject.change", u.Username, audit.Success, "the domain account was replaced by another with the same name; its app sign-ins were revoked")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	// A row of a forgotten-and-recreated users row with this GUID goes.
	if _, err := tx.ExecContext(ctx, `DELETE FROM oidc_subjects WHERE sub = ? OR user_id = ?`, guid, u.ID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO oidc_subjects (user_id, sub, guid) VALUES (?, ?, ?)`, u.ID, guid, guid); err != nil {
		return "", err
	}
	return guid, tx.Commit()
}

// domainGUID asks the directory for u's objectGUID (or SID); "" when it
// can't be asked.
func (p *Provider) domainGUID(ctx context.Context, u *auth.User) string {
	d := p.cfg.SignIn.Domain
	if d == nil {
		return ""
	}
	_, name, ok := strings.Cut(u.IdentityPrincipal(), `\`)
	if !ok {
		return ""
	}
	a, err := d.Account(ctx, name)
	if err != nil || a == nil || !a.Exists {
		return ""
	}
	if a.ObjectGUID != "" {
		return strings.ToLower(a.ObjectGUID)
	}
	return strings.ToUpper(a.SID)
}

// userForSubject loads the account behind a subject, checking it may still
// sign in (LoadUser refreshes a domain account's groups like the desktop).
func (p *Provider) userForSubject(ctx context.Context, sub string) (*auth.User, error) {
	var id int64
	if err := p.cfg.DB.QueryRowContext(ctx, `SELECT user_id FROM oidc_subjects WHERE sub = ?`, sub).Scan(&id); err != nil {
		return nil, errors.New("unknown subject")
	}
	u, err := p.cfg.LoadUser(ctx, id)
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, auth.ErrDisabledHere
	}
	if u.IdentitySource() != auth.SourceDomain && !p.loadSettings(ctx).localAccounts {
		return nil, ErrLocalAccountsOff
	}
	return u, nil
}

// fillUserinfo sets the claims for u:
//
//	profile: name, preferred_username (alice), groups, hardyos_admin
//	email:   email, email_verified
//	groups:  groups (HOME\Family, ...), hardyos_admin
//
// A domain account without an email address in the directory gets its
// user principal name (alice@home.example.net), marked unverified.
func (p *Provider) fillUserinfo(ctx context.Context, info *oidc.UserInfo, u *auth.User, sub string, scopes []string) {
	info.Subject = sub
	short := u.IdentityPrincipal()
	if _, n, ok := strings.Cut(short, `\`); ok {
		short = n
	}
	if slices.Contains(scopes, oidc.ScopeProfile) {
		info.Name = u.DisplayName
		if info.Name == "" {
			info.Name = short
		}
		info.PreferredUsername = short
	}
	if slices.Contains(scopes, oidc.ScopeEmail) {
		switch {
		case u.Email != "":
			info.Email = u.Email
			info.EmailVerified = true
		case u.IdentitySource() == auth.SourceDomain:
			if d := p.cfg.SignIn.Domain; d != nil {
				if di, err := d.Info(ctx); err == nil && di != nil && di.DNS != "" {
					info.Email = strings.ToLower(short + "@" + di.DNS)
					info.AppendClaims("email_verified", false)
				}
			}
		}
	}
	if slices.Contains(scopes, ScopeGroups) || slices.Contains(scopes, oidc.ScopeProfile) {
		groups := u.IdentityGroups()
		if groups == nil {
			groups = []string{}
		}
		info.AppendClaims("groups", groups)
		info.AppendClaims(ClaimAdmin, u.IsAdmin())
	}
}
