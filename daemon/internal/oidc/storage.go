package oidc

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// storage is op.Storage over hardyd's database.
type storage struct{ p *Provider }

var (
	_ op.Storage                        = (*storage)(nil)
	_ op.CanSetUserinfoFromRequest      = (*storage)(nil)
	_ op.CanTerminateSessionFromRequest = (*storage)(nil)
)

// authRequest is a sign-in in progress, stored as JSON.
type authRequest struct {
	ID                  string                   `json:"id"`
	ClientID            string                   `json:"clientId"`
	RedirectURI         string                   `json:"redirectUri"`
	State               string                   `json:"state"`
	Nonce               string                   `json:"nonce"`
	ResponseType        oidc.ResponseType        `json:"responseType"`
	ResponseMode        oidc.ResponseMode        `json:"responseMode"`
	Scopes              []string                 `json:"scopes"`
	Prompt              []string                 `json:"prompt"`
	MaxAge              *uint                    `json:"maxAge"`
	LoginHint           string                   `json:"loginHint"`
	CodeChallenge       string                   `json:"codeChallenge"`
	CodeChallengeMethod oidc.CodeChallengeMethod `json:"codeChallengeMethod"`
	CreatedAt           time.Time                `json:"createdAt"`

	// Set once the person signed in.
	UserID   int64     `json:"userId"`
	Subject  string    `json:"subject"`
	AuthTime time.Time `json:"authTime"`
	AMR      []string  `json:"amr"`

	done     bool
	codeHash string
}

func (a *authRequest) GetID() string         { return a.ID }
func (a *authRequest) GetACR() string        { return "" }
func (a *authRequest) GetAMR() []string      { return a.AMR }
func (a *authRequest) GetAudience() []string { return []string{a.ClientID} }
func (a *authRequest) GetAuthTime() time.Time {
	return a.AuthTime
}
func (a *authRequest) GetClientID() string { return a.ClientID }
func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{Challenge: a.CodeChallenge, Method: a.CodeChallengeMethod}
}
func (a *authRequest) GetNonce() string                   { return a.Nonce }
func (a *authRequest) GetRedirectURI() string             { return a.RedirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType { return a.ResponseType }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return a.ResponseMode }
func (a *authRequest) GetScopes() []string                { return a.Scopes }
func (a *authRequest) GetState() string                   { return a.State }
func (a *authRequest) GetSubject() string                 { return a.Subject }
func (a *authRequest) Done() bool                         { return a.done }

func (a *authRequest) hasPrompt(p string) bool { return slices.Contains(a.Prompt, p) }

// refreshRequest is a grant being refreshed.
type refreshRequest struct {
	grant  *grant
	scopes []string
	hash   string // the refresh token presented
}

func (r *refreshRequest) GetAMR() []string            { return r.grant.AMR }
func (r *refreshRequest) GetAudience() []string       { return []string{r.grant.ClientID} }
func (r *refreshRequest) GetAuthTime() time.Time      { return r.grant.AuthTime }
func (r *refreshRequest) GetClientID() string         { return r.grant.ClientID }
func (r *refreshRequest) GetScopes() []string         { return r.scopes }
func (r *refreshRequest) GetSubject() string          { return r.grant.Subject }
func (r *refreshRequest) SetCurrentScopes(s []string) { r.scopes = s }

type grant struct {
	ID        string
	ClientID  string
	UserID    int64
	Subject   string
	Scopes    []string
	AuthTime  time.Time
	AMR       []string
	ExpiresAt time.Time
	Revoked   bool
}

func randomID(prefix string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// ---- clients ----------------------------------------------------------------

// opClient is a Client as the op package sees it.
type opClient struct {
	c         *Client
	loginBase string // the issuer's path, for LoginURL
}

func (c *opClient) GetID() string                    { return c.c.ID }
func (c *opClient) RedirectURIs() []string           { return c.c.RedirectURIs }
func (c *opClient) PostLogoutRedirectURIs() []string { return c.c.PostLogoutRedirectURIs }

// ApplicationType is web for every client: the op package then matches
// redirect URIs exactly for all of them (its native type would accept any
// port on localhost).
func (c *opClient) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (c *opClient) AuthMethod() oidc.AuthMethod {
	if c.c.Kind == KindPublic {
		return oidc.AuthMethodNone
	}
	return oidc.AuthMethodBasic
}
func (c *opClient) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}
func (c *opClient) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}
func (c *opClient) LoginURL(id string) string {
	return c.loginBase + "/login?id=" + url.QueryEscape(id)
}

// AccessTokenType: JWTs, so a relying party that checks access tokens
// itself (NetBird's management, when HardyOS is its only identity
// provider) can, with the JWKS.
func (c *opClient) AccessTokenType() op.AccessTokenType  { return op.AccessTokenTypeJWT }
func (c *opClient) IDTokenLifetime() time.Duration       { return idTokenTTL }
func (c *opClient) DevMode() bool                        { return false }
func (c *opClient) ClockSkew() time.Duration             { return 0 }
func (c *opClient) IDTokenUserinfoClaimsAssertion() bool { return true }
func (c *opClient) IsScopeAllowed(scope string) bool {
	return scope == ScopeGroups || scope == ScopePhotos
}
func (c *opClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}
func (c *opClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(s []string) []string { return s }
}

type notFound struct{ error }

func (notFound) IsNotFound() {}

func (s *storage) GetClientByClientID(ctx context.Context, id string) (op.Client, error) {
	c, err := s.p.Clients.Get(ctx, id)
	if err != nil {
		return nil, notFound{err}
	}
	if c.Disabled {
		return nil, notFound{errors.New("this client is turned off")}
	}
	_, base := s.p.issuerParts(ctx)
	return &opClient{c: c, loginBase: base}, nil
}

func (s *storage) AuthorizeClientIDSecret(ctx context.Context, id, secret string) error {
	c, err := s.p.Clients.Get(ctx, id)
	if err != nil || c.Disabled || c.Kind != KindConfidential || !c.checkSecret(secret) {
		return oidc.ErrInvalidClient().WithDescription("client authentication failed")
	}
	return nil
}

// ---- authorization requests -------------------------------------------------

func (s *storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, _ string) (op.AuthRequest, error) {
	c, err := s.p.Clients.Get(ctx, req.ClientID)
	if err != nil || c.Disabled {
		return nil, oidc.ErrInvalidRequestRedirectURI().WithDescription("unknown client")
	}
	// Exactly as registered, character for character.
	if !slices.Contains(c.RedirectURIs, req.RedirectURI) {
		return nil, oidc.ErrInvalidRequestRedirectURI().WithDescription("the redirect_uri isn't registered for this client")
	}
	if req.ResponseType != oidc.ResponseTypeCode {
		return nil, unsupportedResponseType().WithDescription("only the authorization code flow is supported")
	}
	if !slices.Contains(req.Scopes, oidc.ScopeOpenID) {
		return nil, oidc.ErrInvalidScope().WithDescription("the openid scope is required")
	}
	switch {
	case req.CodeChallenge == "" && c.Kind == KindPublic:
		return nil, oidc.ErrInvalidRequest().WithDescription("PKCE (code_challenge with S256) is required for public clients")
	case req.CodeChallenge != "" && req.CodeChallengeMethod != oidc.CodeChallengeMethodS256:
		return nil, oidc.ErrInvalidRequest().WithDescription("code_challenge_method must be S256")
	}
	// form_post needs a script on the page, and the pages run none.
	if req.ResponseMode != "" && req.ResponseMode != oidc.ResponseModeQuery {
		return nil, oidc.ErrInvalidRequest().WithDescription("response_mode must be query")
	}
	now := s.p.now()
	a := &authRequest{
		ID: randomID("ar_"), ClientID: c.ID, RedirectURI: req.RedirectURI, State: req.State, Nonce: req.Nonce,
		ResponseType: req.ResponseType, ResponseMode: req.ResponseMode, Scopes: req.Scopes, Prompt: req.Prompt,
		MaxAge: req.MaxAge, LoginHint: req.LoginHint, CodeChallenge: req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod, CreatedAt: now.UTC(),
	}
	if len(a.State) > 2048 || len(a.Nonce) > 512 || len(a.LoginHint) > 256 || len(a.Scopes) > 20 {
		return nil, oidc.ErrInvalidRequest().WithDescription("request too large")
	}
	if !s.p.admitAuthRequest(ctx) {
		return nil, oidc.ErrServerError().WithDescription("too many sign-ins in progress; try again in a few minutes")
	}
	b, _ := json.Marshal(a)
	_, err = s.p.cfg.DB.ExecContext(ctx, `INSERT INTO oidc_auth_requests (id, client_id, request, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		a.ID, a.ClientID, string(b), store.FormatTime(now), store.FormatTime(now.Add(authRequestTTL)))
	if err != nil {
		return nil, err
	}
	return a, nil
}

const authReqCols = `request, done, COALESCE(code_hash, ''), browser_hash, expires_at`

func (s *storage) scanAuthRequest(row *sql.Row) (*authRequest, string, error) {
	var raw, codeHash, browser, expires string
	var done int
	if err := row.Scan(&raw, &done, &codeHash, &browser, &expires); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", notFound{errors.New("no such sign-in request (it may have expired)")}
		}
		return nil, "", err
	}
	if s.p.now().After(store.ParseTime(expires)) {
		return nil, "", notFound{errors.New("the sign-in request expired")}
	}
	var a authRequest
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		return nil, "", err
	}
	a.done, a.codeHash = done != 0, codeHash
	return &a, browser, nil
}

func (s *storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	a, _, err := s.loadAuthRequest(ctx, id)
	if err != nil {
		return nil, err
	}
	if a.codeHash != "" {
		return nil, notFound{errors.New("this sign-in was already completed")}
	}
	return a, nil
}

func (s *storage) loadAuthRequest(ctx context.Context, id string) (*authRequest, string, error) {
	return s.scanAuthRequest(s.p.cfg.DB.QueryRowContext(ctx, `SELECT `+authReqCols+` FROM oidc_auth_requests WHERE id = ?`, id))
}

func (s *storage) saveAuthRequest(ctx context.Context, a *authRequest, done bool) error {
	b, _ := json.Marshal(a)
	_, err := s.p.cfg.DB.ExecContext(ctx, `UPDATE oidc_auth_requests SET request = ?, user_id = ?, done = ? WHERE id = ? AND code_hash IS NULL`,
		string(b), nullID(a.UserID), boolInt(done), a.ID)
	return err
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func (s *storage) SaveAuthCode(ctx context.Context, id, code string) error {
	res, err := s.p.cfg.DB.ExecContext(ctx, `UPDATE oidc_auth_requests SET code_hash = ?, code_at = ?, expires_at = ?
		WHERE id = ? AND done = 1 AND code_hash IS NULL`,
		hashHex(code), store.FormatTime(s.p.now()), store.FormatTime(s.p.now().Add(usedCodeKeepFor)), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return oidc.ErrInvalidRequest().WithDescription("this sign-in was already completed")
	}
	return nil
}

// AuthRequestByCode uses up a code: it works once, within 60 seconds. A
// code presented again revokes what the first exchange gave (RFC 6749
// 4.1.2: someone else may have it).
func (s *storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	h := hashHex(code)
	db := s.p.cfg.DB
	now := s.p.now()
	var id, codeAt, raw string
	var consumed sql.NullString
	err := db.QueryRowContext(ctx, `SELECT id, code_at, consumed_at, request FROM oidc_auth_requests WHERE code_hash = ?`, h).Scan(&id, &codeAt, &consumed, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("unknown code")
	}
	if err != nil {
		return nil, err
	}
	// Before the code is used up: only its own client, with its secret and
	// the PKCE verifier, may spend it. Someone else presenting a stolen (or
	// guessed) code mustn't burn it, which would revoke the real client's
	// sign-in as a replay.
	var pre authRequest
	if err := json.Unmarshal([]byte(raw), &pre); err != nil {
		return nil, err
	}
	if err := s.p.exchangeAllowed(ctx, &pre); err != nil {
		return nil, err
	}
	res, err := db.ExecContext(ctx, `UPDATE oidc_auth_requests SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL`, store.FormatTime(now), id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		_, _ = db.ExecContext(ctx, `UPDATE oidc_auth_requests SET replayed = 1 WHERE id = ?`, id)
		n, _ := revokeWhere(ctx, db, now, `code_hash = ?`, h)
		s.p.audit(ctx, "", nil, "oidc.code.replay", id, audit.Denied, fmt.Sprintf("an authorization code was used twice; %d grant(s) revoked", n))
		return nil, errors.New("code already used")
	}
	if now.Sub(store.ParseTime(codeAt)) > codeTTL {
		return nil, errors.New("code expired")
	}
	var a authRequest
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		return nil, err
	}
	a.done, a.codeHash = true, h
	return &a, nil
}

// DeleteAuthRequest forgets a finished sign-in. One that gave a code is kept
// (as used) until it expires, to recognise the code if it comes back.
func (s *storage) DeleteAuthRequest(ctx context.Context, id string) error {
	_, err := s.p.cfg.DB.ExecContext(ctx, `DELETE FROM oidc_auth_requests WHERE id = ? AND code_hash IS NULL`, id)
	return err
}

// ---- tokens -------------------------------------------------------------------

func (s *storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	a, ok := req.(*authRequest)
	if !ok {
		return "", time.Time{}, oidc.ErrUnsupportedGrantType()
	}
	g, err := s.newGrant(ctx, a)
	if err != nil {
		return "", time.Time{}, err
	}
	return s.newAccessToken(ctx, g.ID)
}

func (s *storage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, current string) (string, string, time.Time, error) {
	db := s.p.cfg.DB
	now := s.p.now()
	var grantID string
	var grantEnd time.Time
	switch r := req.(type) {
	case *authRequest:
		g, err := s.newGrant(ctx, r)
		if err != nil {
			return "", "", time.Time{}, err
		}
		grantID, grantEnd = g.ID, g.ExpiresAt
	case *refreshRequest:
		// Rotation: the presented token is used up now; if another request
		// already used it, the grant is revoked (a stolen copy is in use).
		res, err := db.ExecContext(ctx, `UPDATE oidc_refresh_tokens SET used_at = ? WHERE hash = ? AND used_at IS NULL`, store.FormatTime(now), hashHex(current))
		if err != nil {
			return "", "", time.Time{}, err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			_, _ = revokeWhere(ctx, db, now, `id = ?`, r.grant.ID)
			s.p.audit(ctx, "", nil, "oidc.token.reuse", r.grant.ClientID, audit.Denied, "a refresh token was used twice; the sign-in was revoked")
			return "", "", time.Time{}, oidc.ErrInvalidGrant().WithDescription("refresh token already used")
		}
		grantID, grantEnd = r.grant.ID, r.grant.ExpiresAt
	default:
		return "", "", time.Time{}, oidc.ErrUnsupportedGrantType()
	}
	rt := randomID("hrt_")
	exp := now.Add(refreshIdleTTL)
	if exp.After(grantEnd) {
		exp = grantEnd
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO oidc_refresh_tokens (hash, grant_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		hashHex(rt), grantID, store.FormatTime(now), store.FormatTime(exp)); err != nil {
		return "", "", time.Time{}, err
	}
	id, atExp, err := s.newAccessToken(ctx, grantID)
	return id, rt, atExp, err
}

func (s *storage) newGrant(ctx context.Context, a *authRequest) (*grant, error) {
	db := s.p.cfg.DB
	if a.UserID == 0 || a.Subject == "" {
		return nil, oidc.ErrInvalidGrant()
	}
	if a.codeHash != "" {
		var replayed int
		if err := db.QueryRowContext(ctx, `SELECT replayed FROM oidc_auth_requests WHERE code_hash = ?`, a.codeHash).Scan(&replayed); err != nil || replayed != 0 {
			return nil, oidc.ErrInvalidGrant().WithDescription("code already used")
		}
	}
	now := s.p.now()
	g := &grant{ID: randomID("g_"), ClientID: a.ClientID, UserID: a.UserID, Subject: a.Subject, Scopes: a.Scopes,
		AuthTime: a.AuthTime, AMR: a.AMR, ExpiresAt: now.Add(refreshMaxTTL)}
	_, err := db.ExecContext(ctx, `INSERT INTO oidc_grants (id, client_id, user_id, subject, scopes, auth_time, amr, code_hash, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.ClientID, g.UserID, g.Subject, jsonString(g.Scopes), store.FormatTime(g.AuthTime), jsonString(g.AMR), a.codeHash,
		store.FormatTime(now), store.FormatTime(g.ExpiresAt))
	if err != nil {
		return nil, err
	}
	return g, nil
}

func (s *storage) newAccessToken(ctx context.Context, grantID string) (string, time.Time, error) {
	id := randomID("at_")
	exp := s.p.now().Add(accessTokenTTL)
	_, err := s.p.cfg.DB.ExecContext(ctx, `INSERT INTO oidc_access_tokens (id, grant_id, expires_at) VALUES (?, ?, ?)`, id, grantID, store.FormatTime(exp))
	return id, exp, err
}

func (s *storage) loadGrant(ctx context.Context, where string, arg any) (*grant, error) {
	var g grant
	var scopes, authTime, amr, expires string
	var revoked sql.NullString
	err := s.p.cfg.DB.QueryRowContext(ctx, `SELECT id, client_id, user_id, subject, scopes, auth_time, amr, expires_at, revoked_at FROM oidc_grants WHERE `+where, arg).
		Scan(&g.ID, &g.ClientID, &g.UserID, &g.Subject, &scopes, &authTime, &amr, &expires, &revoked)
	if err != nil {
		return nil, err
	}
	g.Scopes, g.AMR = jsonList(scopes), jsonList(amr)
	g.AuthTime, g.ExpiresAt = store.ParseTime(authTime), store.ParseTime(expires)
	g.Revoked = revoked.Valid
	return &g, nil
}

// TokenRequestByRefreshToken checks a refresh token and the account behind
// it: a turned-off, deleted or domain-removed account, a client turned off
// or a person no longer in the client's groups revokes the grant.
func (s *storage) TokenRequestByRefreshToken(ctx context.Context, rt string) (op.RefreshTokenRequest, error) {
	db := s.p.cfg.DB
	now := s.p.now()
	h := hashHex(rt)
	var grantID, expires string
	var used sql.NullString
	err := db.QueryRowContext(ctx, `SELECT grant_id, expires_at, used_at FROM oidc_refresh_tokens WHERE hash = ?`, h).Scan(&grantID, &expires, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, op.ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, err
	}
	g, err := s.loadGrant(ctx, `id = ?`, grantID)
	if err != nil {
		return nil, op.ErrInvalidRefreshToken
	}
	if used.Valid {
		_, _ = revokeWhere(ctx, db, now, `id = ?`, g.ID)
		s.p.audit(ctx, "", nil, "oidc.token.reuse", g.ClientID, audit.Denied, "a refresh token was used twice; the sign-in was revoked")
		return nil, errors.New("refresh token already used")
	}
	if g.Revoked || now.After(g.ExpiresAt) || now.After(store.ParseTime(expires)) {
		return nil, errors.New("refresh token expired or revoked")
	}
	u, err := s.p.userForSubject(ctx, g.Subject)
	if err == nil {
		var c *Client
		if c, err = s.p.Clients.Get(ctx, g.ClientID); err == nil {
			err = s.p.allowed(ctx, c, u)
		}
	}
	if err != nil {
		_, _ = revokeWhere(ctx, db, now, `id = ?`, g.ID)
		s.p.audit(ctx, "", nil, "oidc.token.revoke", g.ClientID, audit.Success, "sign-in ended at refresh: "+err.Error())
		return nil, err
	}
	return &refreshRequest{grant: g, scopes: g.Scopes, hash: h}, nil
}

func (s *storage) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	var grantID string
	err := s.p.cfg.DB.QueryRowContext(ctx, `SELECT grant_id FROM oidc_refresh_tokens WHERE hash = ?`, hashHex(token)).Scan(&grantID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", op.ErrInvalidRefreshToken
	}
	if err != nil {
		return "", "", err
	}
	g, err := s.loadGrant(ctx, `id = ?`, grantID)
	if err != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return g.Subject, "grant:" + g.ID, nil
}

// RevokeToken revokes an access token (that token) or a refresh token (the
// whole grant: every token of that sign-in), for the client it was issued
// to. Unknown tokens succeed quietly (RFC 7009).
func (s *storage) RevokeToken(ctx context.Context, tokenOrID, _ string, clientID string) *oidc.Error {
	db := s.p.cfg.DB
	now := s.p.now()
	var g *grant
	var err error
	var what string
	switch {
	case strings.HasPrefix(tokenOrID, "grant:"):
		g, err = s.loadGrant(ctx, `id = ?`, strings.TrimPrefix(tokenOrID, "grant:"))
		what = "refresh token"
	case strings.HasPrefix(tokenOrID, "at_"):
		var grantID string
		if err = db.QueryRowContext(ctx, `SELECT grant_id FROM oidc_access_tokens WHERE id = ?`, tokenOrID).Scan(&grantID); err == nil {
			g, err = s.loadGrant(ctx, `id = ?`, grantID)
		}
		what = "access token"
	default:
		return nil
	}
	if err != nil {
		return nil
	}
	if g.ClientID != clientID {
		return oidc.ErrInvalidClient().WithDescription("the token wasn't issued to this client")
	}
	if what == "access token" {
		_, err = db.ExecContext(ctx, `UPDATE oidc_access_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, store.FormatTime(now), tokenOrID)
	} else {
		_, err = revokeWhere(ctx, db, now, `id = ?`, g.ID)
	}
	if err != nil {
		return oidc.ErrServerError()
	}
	s.p.audit(ctx, "", nil, "oidc.token.revoke", clientID, audit.Success, what+" revoked by the app (subject "+g.Subject+")")
	return nil
}

// revokeWhere revokes the grants matching where (and with them their
// refresh and access tokens).
func revokeWhere(ctx context.Context, db *store.DB, now time.Time, where string, args ...any) (int64, error) {
	ts := store.FormatTime(now)
	res, err := db.ExecContext(ctx, `UPDATE oidc_grants SET revoked_at = ? WHERE revoked_at IS NULL AND `+where, append([]any{ts}, args...)...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	_, _ = db.ExecContext(ctx, `UPDATE oidc_access_tokens SET revoked_at = ? WHERE revoked_at IS NULL AND grant_id IN (SELECT id FROM oidc_grants WHERE `+where+`)`, append([]any{ts}, args...)...)
	_, _ = db.ExecContext(ctx, `DELETE FROM oidc_refresh_tokens WHERE grant_id IN (SELECT id FROM oidc_grants WHERE `+where+`)`, args...)
	return n, nil
}

func revokeClientGrants(ctx context.Context, db *store.DB, clientID string) error {
	_, err := revokeWhere(ctx, db, time.Now(), `client_id = ?`, clientID)
	return err
}

// activeAccessToken returns the grant behind a live access token.
func (s *storage) activeAccessToken(ctx context.Context, tokenID string) (*grant, error) {
	var grantID, expires string
	var revoked sql.NullString
	err := s.p.cfg.DB.QueryRowContext(ctx, `SELECT grant_id, expires_at, revoked_at FROM oidc_access_tokens WHERE id = ?`, tokenID).Scan(&grantID, &expires, &revoked)
	if err != nil {
		return nil, errors.New("unknown access token")
	}
	if revoked.Valid || s.p.now().After(store.ParseTime(expires)) {
		return nil, errors.New("access token expired or revoked")
	}
	g, err := s.loadGrant(ctx, `id = ?`, grantID)
	if err != nil || g.Revoked {
		return nil, errors.New("the sign-in was revoked")
	}
	return g, nil
}

// ---- sessions -----------------------------------------------------------------

func (s *storage) TerminateSession(ctx context.Context, userID, clientID string) error {
	return nil // TerminateSessionFromRequest is used
}

// TerminateSessionFromRequest ends an app's sign-in (RP-initiated logout):
// with a valid id_token_hint the grants of that person at that client are
// revoked. The browser's own HardyOS sign-in ends on the sign-out page this
// returns (only a handler with the browser can clear its cookie), which
// then goes on to the app's post-logout redirect URI (already checked
// against the client's list by the op package).
func (s *storage) TerminateSessionFromRequest(ctx context.Context, req *op.EndSessionRequest) (string, error) {
	issuer := s.p.Issuer(ctx)
	next := req.RedirectURI
	if next == "" || strings.HasPrefix(next, "logged-out") {
		next = issuer + "/" + next
		if next == issuer+"/" {
			next = issuer + "/logged-out"
		}
	}
	if req.UserID != "" && req.ClientID != "" {
		if n, err := revokeWhere(ctx, s.p.cfg.DB, s.p.now(), `subject = ? AND client_id = ?`, req.UserID, req.ClientID); err == nil && n > 0 {
			s.p.audit(ctx, "", nil, "oidc.token.revoke", req.ClientID, audit.Success, fmt.Sprintf("signed out of the app: %d sign-in(s) revoked", n))
		}
	}
	return issuer + "/logout?" + s.p.signLogout(req.UserID, next).Encode(), nil
}

// ---- user info and claims -------------------------------------------------------

func (s *storage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil // SetUserinfoFromRequest is used
}

func (s *storage) SetUserinfoFromRequest(ctx context.Context, info *oidc.UserInfo, req op.IDTokenRequest, scopes []string) error {
	u, err := s.p.userForSubject(ctx, req.GetSubject())
	if err != nil {
		return err
	}
	s.p.fillUserinfo(ctx, info, u, req.GetSubject(), scopes)
	return nil
}

func (s *storage) SetUserinfoFromToken(ctx context.Context, info *oidc.UserInfo, tokenID, subject, _ string) error {
	g, err := s.activeAccessToken(ctx, tokenID)
	if err != nil {
		return err
	}
	if g.Subject != subject {
		return errors.New("token subject mismatch")
	}
	u, err := s.p.userForSubject(ctx, subject)
	if err != nil {
		return err
	}
	s.p.fillUserinfo(ctx, info, u, subject, g.Scopes)
	return nil
}

func (s *storage) SetIntrospectionFromToken(ctx context.Context, resp *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	g, err := s.activeAccessToken(ctx, tokenID)
	if err != nil || g.Subject != subject || g.ClientID != clientID {
		return nil // inactive
	}
	u, err := s.p.userForSubject(ctx, subject)
	if err != nil {
		return nil
	}
	info := new(oidc.UserInfo)
	s.p.fillUserinfo(ctx, info, u, subject, g.Scopes)
	resp.SetUserInfo(info)
	resp.Active = true
	resp.ClientID = g.ClientID
	resp.Scope = g.Scopes
	return nil
}

// GetPrivateClaimsFromScopes adds the person's groups, role and names to
// JWT access tokens (NetBird's JWT group sync reads groups from them).
func (s *storage) GetPrivateClaimsFromScopes(ctx context.Context, subject, _ string, scopes []string) (map[string]any, error) {
	u, err := s.p.userForSubject(ctx, subject)
	if err != nil {
		return nil, err
	}
	info := new(oidc.UserInfo)
	s.p.fillUserinfo(ctx, info, u, subject, []string{oidc.ScopeProfile, oidc.ScopeEmail, ScopeGroups})
	return map[string]any{
		"groups": info.Claims["groups"], ClaimAdmin: info.Claims[ClaimAdmin],
		"email": info.Email, "name": info.Name, "preferred_username": info.PreferredUsername,
	}, nil
}

func (s *storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("JWT client authentication isn't supported")
}

func (s *storage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("the JWT profile grant isn't supported")
}

// ---- keys ---------------------------------------------------------------------

func (s *storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	s.p.ensureKeys(ctx)
	return s.p.keys.signing(ctx)
}
func (s *storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}
func (s *storage) KeySet(ctx context.Context) ([]op.Key, error) {
	s.p.ensureKeys(ctx)
	return s.p.keys.published(ctx)
}

func (s *storage) Health(ctx context.Context) error { return s.p.cfg.DB.PingContext(ctx) }

// Error codes the op package has no constructor for.
func consentRequired() *oidc.Error {
	e := oidc.ErrInteractionRequired()
	e.ErrorType = "consent_required"
	e.Description = "the person hasn't allowed this app yet"
	return e
}

func unsupportedResponseType() *oidc.Error {
	e := oidc.ErrInvalidRequest()
	e.ErrorType = "unsupported_response_type"
	return e
}
