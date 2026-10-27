// Package oidc makes HardyOS an OpenID Connect provider: apps (NetBird
// first: its identity provider, and through it the sign-in in front of
// public apps on its reverse proxy) sign people in with their domain
// accounts, the same way the desktop does.
//
// The protocol is zitadel/oidc's op package (OpenID Certified): discovery,
// JWKS, authorization code with PKCE, refresh tokens, userinfo,
// introspection, revocation and RP-initiated logout. This package is its
// storage (internal/store tables, migration 0010), the sign-in, consent and
// sign-out pages, the clients administrators register and the signing keys
// (RS256, rotated every 30 days, sealed at rest with a key from
// hardyd-priv).
package oidc

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/cors"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Lifetimes.
const (
	authRequestTTL  = 10 * time.Minute
	codeTTL         = time.Minute
	accessTokenTTL  = 15 * time.Minute
	idTokenTTL      = time.Hour
	refreshIdleTTL  = 14 * 24 * time.Hour
	refreshMaxTTL   = 30 * 24 * time.Hour
	browserTTL      = 12 * time.Hour
	usedCodeKeepFor = 10 * time.Minute
)

// Names are Remote Access's public names (part A's settings): the base
// domain apps are published under and the desktop's name in it. Empty
// base: not set up.
type Names interface {
	PublicNames(ctx context.Context) (base, desktop string)
}

// Settings keys.
const (
	settingIssuer        = "oidc.issuer"
	settingLocalAccounts = "oidc.local_accounts"
	settingPublicAdmins  = "oidc.public_admins"
	// Remote Access's names, read by SettingsNames when no Names is
	// configured.
	SettingRemoteBase    = "remote.base_domain"
	SettingRemoteDesktop = "remote.desktop_name"
)

// SettingsNames reads Remote Access's names from hardyd's settings table.
type SettingsNames struct{ DB *store.DB }

// PublicNames implements Names.
func (s SettingsNames) PublicNames(ctx context.Context) (string, string) {
	base, _ := s.DB.GetSetting(ctx, SettingRemoteBase)
	desk, _ := s.DB.GetSetting(ctx, SettingRemoteDesktop)
	return strings.ToLower(strings.TrimSpace(base)), strings.ToLower(strings.TrimSpace(desk))
}

// AuditFunc records an audit entry for a sign-in event.
type AuditFunc func(ctx context.Context, ip string, u *auth.User, action, target string, outcome audit.Outcome, detail string)

// LoginErrorFunc says what a failed sign-in means: the code shown and
// logged, the HTTP status, and whether it counts as a wrong guess for the
// rate limiter. ok is false for errors that aren't sign-in answers.
type LoginErrorFunc func(err error) (code string, status int, counts, ok bool)

// Config wires the provider into hardyd.
type Config struct {
	DB      *store.DB
	Users   *auth.Users
	SignIn  *auth.SignIn
	Limiter *auth.LoginLimiter
	// Secrets seals the signing keys (secretbox.PrivSource in production).
	Secrets secretbox.Source
	// Names are Remote Access's names; nil reads SettingsNames.
	Names Names
	// FallbackHost is the desktop's own HTTPS name, for the issuer when
	// Remote Access has no base domain.
	FallbackHost func() string
	// LoadUser loads an account behind a session or token, refreshing a
	// domain account's groups like the desktop does; an error means it
	// can't be signed in any more.
	LoadUser func(ctx context.Context, id int64) (*auth.User, error)
	// DesktopUser is the person signed in to the desktop in this browser,
	// when the request carries the desktop's session (the issuer is on the
	// desktop's own host), and when that session started.
	DesktopUser func(r *http.Request) (*auth.User, time.Time, bool)
	// ClientIP is the request's address (trusted proxies honoured).
	ClientIP   func(r *http.Request) string
	Audit      AuditFunc
	LoginError LoginErrorFunc
	// PublicOrigin reports whether a request came from the internet (through
	// the app gateway, for a public service). Such sign-ins count in their
	// own buckets of PublicLimiter (slowed down, never locked out), so
	// strangers can't lock anyone out of signing in at home or over
	// NetBird; every failure looks the same; administrators are refused
	// unless the "public admins" setting allows them. nil: never public.
	PublicOrigin  func(r *http.Request) bool
	PublicLimiter *auth.DelayLimiter
	// EndSessions ends a person's desktop and app window sessions (their
	// account row now belongs to another directory object).
	EndSessions func(ctx context.Context, userID int64)
	// ManagedAccess, when set, is asked about every sign-in to a client
	// another part of HardyOS keeps (Clients.Ensure, by its key): Photos
	// lets only the people who may use the Immich app in. An error refuses
	// the sign-in (and, at refresh, revokes the grant) with its message.
	ManagedAccess func(ctx context.Context, managedBy string, u *auth.User) error
	// Insecure allows an http:// issuer (development without TLS).
	Insecure bool
	Log      *slog.Logger
	Now      func() time.Time
}

// Provider is HardyOS's OpenID Connect provider.
type Provider struct {
	cfg     Config
	Clients *Clients
	keys    *keyring
	op      *op.Provider
	csrfKey []byte
	keysOK  atomic.Bool

	mu       sync.Mutex
	settings settingsCache
	// anchorOK: when a person's directory anchor was last confirmed (the
	// token endpoints look the account up several times per request).
	anchorOK map[int64]time.Time
	// pending counts sign-in requests in progress per client address.
	pending map[string][]time.Time
}

type settingsCache struct {
	at            time.Time
	issuer        string
	issuerSet     bool
	derived       string
	localAccounts bool
	publicAdmins  bool
}

// New builds the provider. Run Start to keep the signing keys on schedule.
func New(cfg Config) (*Provider, error) {
	if cfg.DB == nil || cfg.Users == nil || cfg.SignIn == nil || cfg.LoadUser == nil {
		return nil, errors.New("oidc: DB, Users, SignIn and LoadUser are required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Limiter == nil {
		cfg.Limiter = auth.NewLoginLimiter()
	}
	if cfg.PublicLimiter == nil {
		cfg.PublicLimiter = auth.NewDelayLimiter()
	}
	if cfg.PublicOrigin == nil {
		cfg.PublicOrigin = func(*http.Request) bool { return false }
	}
	if cfg.Secrets == nil {
		cfg.Secrets = secretbox.NewStaticSource()
	}
	if cfg.Names == nil {
		cfg.Names = SettingsNames{DB: cfg.DB}
	}
	if cfg.ClientIP == nil {
		cfg.ClientIP = func(r *http.Request) string {
			h, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				return r.RemoteAddr
			}
			return h
		}
	}
	p := &Provider{cfg: cfg, csrfKey: make([]byte, 32), anchorOK: map[int64]time.Time{}, pending: map[string][]time.Time{}}
	_, _ = rand.Read(p.csrfKey)
	p.keys = &keyring{db: cfg.DB, secrets: cfg.Secrets, now: cfg.Now}
	p.Clients = &Clients{DB: cfg.DB}

	var cryptoKey [32]byte
	_, _ = rand.Read(cryptoKey[:])
	opCfg := &op.Config{
		CryptoKey:             cryptoKey,
		CodeMethodS256:        true,
		AuthMethodPost:        true,
		GrantTypeRefreshToken: true,
		SupportedScopes:       []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, ScopeGroups, ScopePhotos, oidc.ScopeOfflineAccess},
		SupportedClaims: []string{"sub", "aud", "exp", "iat", "iss", "auth_time", "nonce", "amr", "azp", "at_hash", "c_hash",
			"name", "preferred_username", "email", "email_verified", "groups", ClaimAdmin, ClaimPhotosRole, ClaimStorageLabel},
		DefaultLogoutRedirectURI: "logged-out", // made absolute in TerminateSessionFromRequest
	}
	opts := []op.Option{
		op.WithCORSOptions(&cors.Options{
			AllowOriginFunc:  p.corsAllowed,
			AllowedMethods:   []string{http.MethodGet, http.MethodPost},
			AllowedHeaders:   []string{"Authorization", "Content-Type", "Accept"},
			AllowCredentials: false,
		}),
		op.WithHttpInterceptors(p.withRequest),
	}
	if cfg.Insecure {
		opts = append(opts, op.WithAllowInsecure())
	}
	o, err := op.NewProvider(opCfg, &storage{p: p}, func(bool) (op.IssuerFromRequest, error) {
		return func(r *http.Request) string { return p.Issuer(r.Context()) }, nil
	}, opts...)
	if err != nil {
		return nil, err
	}
	p.op = o
	return p, nil
}

// Scopes and claims of our own.
const (
	ScopeGroups = "groups"
	ClaimAdmin  = "hardyos_admin"

	// ScopePhotos asks for what Immich (the Photos app, docs/photos.md)
	// maps from a sign-in: ClaimPhotosRole ("admin" for HardyOS
	// administrators, else "user"; Immich's roleClaim), ClaimStorageLabel
	// (the folder Immich files the person's photos in) and an email
	// address for every account (Immich registers people by email): one
	// that has none gets PlaceholderEmail, marked unverified.
	ScopePhotos       = "hardyos_photos"
	ClaimPhotosRole   = "hardyos_photos_role"
	ClaimStorageLabel = "hardyos_storage_label"
)

func (p *Provider) now() time.Time {
	if p.cfg.Now != nil {
		return p.cfg.Now()
	}
	return time.Now()
}

// Start makes sure there are signing keys and keeps them on schedule (hourly
// check), and removes expired sign-in state. It returns once ctx ends.
func (p *Provider) Start(ctx context.Context) {
	if p.CheckKeys(ctx, false) == nil {
		p.keysOK.Store(true)
	}
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.CheckKeys(ctx, false)
			p.cleanup(ctx)
		}
	}
}

// CheckKeys runs the key schedule now (force: rotate at once) and audits
// what it did.
func (p *Provider) CheckKeys(ctx context.Context, force bool) error {
	events, err := p.keys.check(ctx, force)
	if err != nil {
		p.cfg.Log.Warn("oidc: signing keys", "err", err)
		return err
	}
	for _, e := range events {
		p.cfg.Log.Info("oidc: signing keys", "action", e.Action, "detail", e.Detail)
		p.audit(ctx, "", nil, e.Action, "signing keys", audit.Success, e.Detail)
	}
	return nil
}

// ensureKeys runs the key check once before the first signature, in case
// Start hasn't (yet) or it failed.
func (p *Provider) ensureKeys(ctx context.Context) {
	if p.keysOK.Load() {
		return
	}
	if p.CheckKeys(ctx, false) == nil {
		p.keysOK.Store(true)
	}
}

// Keys lists the signing keys.
func (p *Provider) Keys(ctx context.Context) ([]KeyInfo, error) { return p.keys.list(ctx) }

func (p *Provider) cleanup(ctx context.Context) {
	now := store.FormatTime(p.now())
	for _, q := range []string{
		`DELETE FROM oidc_auth_requests WHERE expires_at < ?`,
		`DELETE FROM oidc_browser_sessions WHERE expires_at < ?`,
		`DELETE FROM oidc_access_tokens WHERE expires_at < ?`,
		`DELETE FROM oidc_refresh_tokens WHERE expires_at < ?`,
		`DELETE FROM oidc_grants WHERE expires_at < ?`,
	} {
		if _, err := p.cfg.DB.ExecContext(ctx, q, now); err != nil {
			p.cfg.Log.Warn("oidc: cleanup", "err", err)
		}
	}
}

func (p *Provider) audit(ctx context.Context, ip string, u *auth.User, action, target string, outcome audit.Outcome, detail string) {
	if p.cfg.Audit != nil {
		if ip == "" {
			if r := requestFrom(ctx); r != nil {
				ip = p.cfg.ClientIP(r)
			}
		}
		p.cfg.Audit(ctx, ip, u, action, target, outcome, detail)
	}
}

type ctxKey int

const requestKey ctxKey = 1

// withRequest keeps the request in the context, so storage calls can audit
// with the client's address and the code exchange can check the client and
// PKCE before it uses the code up. Posted forms are parsed here (at most
// 64 KiB), so the copy in the context has them.
func (p *Provider) withRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestKey, r)))
	})
}

func requestFrom(ctx context.Context) *http.Request {
	r, _ := ctx.Value(requestKey).(*http.Request)
	return r
}

// ---- settings and the issuer ----------------------------------------------

func (p *Provider) loadSettings(ctx context.Context) settingsCache {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.settings.at.IsZero() && p.now().Sub(p.settings.at) < 5*time.Second {
		return p.settings
	}
	var s settingsCache
	if v, err := p.cfg.DB.GetSetting(ctx, settingIssuer); err == nil && v != "" {
		s.issuer, s.issuerSet = v, true
	}
	if v, err := p.cfg.DB.GetSetting(ctx, settingLocalAccounts); err == nil {
		s.localAccounts = v == "true"
	}
	if v, err := p.cfg.DB.GetSetting(ctx, settingPublicAdmins); err == nil {
		s.publicAdmins = v == "true"
	}
	// Every request to hardyd asks whether it's the provider's: the derived
	// issuer is cached with the settings rather than read each time.
	s.derived = p.DerivedIssuer(ctx)
	s.at = p.now()
	p.settings = s
	return s
}

// NamesChanged tells the provider Remote Access's names changed (it would
// notice within 5 seconds anyway).
func (p *Provider) NamesChanged() { p.dropSettings() }

func (p *Provider) dropSettings() {
	p.mu.Lock()
	p.settings = settingsCache{}
	p.mu.Unlock()
}

// Issuer is the provider's issuer URL (decision 116): the administrator's
// choice when set; else https://sso.<base> once Remote Access has a base
// domain (a host of its own, published publicly by NetBird's proxy, so the
// desktop itself can stay NetBird-only); else https://<desktop's HTTPS
// name>/oidc on the server's own name.
func (p *Provider) Issuer(ctx context.Context) string {
	s := p.loadSettings(ctx)
	if s.issuerSet {
		return s.issuer
	}
	return s.derived
}

// DerivedIssuer is the issuer when the administrator hasn't chosen one.
func (p *Provider) DerivedIssuer(ctx context.Context) string {
	if base, _ := p.cfg.Names.PublicNames(ctx); base != "" {
		return "https://sso." + base
	}
	host := "localhost"
	if p.cfg.FallbackHost != nil {
		if h := p.cfg.FallbackHost(); h != "" {
			host = h
		}
	}
	scheme := "https"
	if p.cfg.Insecure {
		scheme = "http"
	}
	return scheme + "://" + host + "/oidc"
}

// Settings is what Control Panel shows and changes.
type Settings struct {
	Issuer        string `json:"issuer"`
	IssuerChosen  bool   `json:"issuerChosen"`
	DerivedIssuer string `json:"derivedIssuer"`
	Discovery     string `json:"discovery"`
	LocalAccounts bool   `json:"localAccounts"`
	// PublicAdmins: administrators may sign in through HardyOS sign-in
	// from the internet (off by default: from a public address they get the
	// same answer as a wrong password).
	PublicAdmins bool `json:"publicAdmins"`
}

// GetSettings returns the settings.
func (p *Provider) GetSettings(ctx context.Context) Settings {
	s := p.loadSettings(ctx)
	iss := p.Issuer(ctx)
	return Settings{Issuer: iss, IssuerChosen: s.issuerSet, DerivedIssuer: p.DerivedIssuer(ctx),
		Discovery: iss + oidc.DiscoveryEndpoint, LocalAccounts: s.localAccounts, PublicAdmins: s.publicAdmins}
}

// LocalAccounts reports whether HardyOS's own accounts may sign in to apps.
func (p *Provider) LocalAccounts(ctx context.Context) bool { return p.loadSettings(ctx).localAccounts }

// SetIssuer chooses the issuer ("" goes back to the derived one).
func (p *Provider) SetIssuer(ctx context.Context, issuer string) error {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer != "" {
		if err := checkIssuer(issuer, p.cfg.Insecure); err != nil {
			return err
		}
		// sso.<base> is the provider's own host, published publicly with
		// nothing in front: the provider must own all of it, so the issuer
		// there has no path.
		if base, _ := p.cfg.Names.PublicNames(ctx); base != "" {
			if u, _ := url.Parse(issuer); u != nil && strings.EqualFold(u.Hostname(), "sso."+base) && u.Path != "" {
				return &ValidationError{Problems: []string{"on sso." + base + " the issuer is https://sso." + base + " without a path"}}
			}
		}
	}
	defer p.dropSettings()
	return p.cfg.DB.SetSetting(ctx, settingIssuer, issuer)
}

// SetLocalAccounts lets HardyOS (non-domain) accounts sign in to apps.
func (p *Provider) SetLocalAccounts(ctx context.Context, on bool) error {
	defer p.dropSettings()
	return p.cfg.DB.SetSetting(ctx, settingLocalAccounts, fmt.Sprint(on))
}

// SetPublicAdmins lets administrators sign in through HardyOS sign-in from
// the internet.
func (p *Provider) SetPublicAdmins(ctx context.Context, on bool) error {
	defer p.dropSettings()
	return p.cfg.DB.SetSetting(ctx, settingPublicAdmins, fmt.Sprint(on))
}

// adminRefused: an administrator signing in from the internet while that
// isn't allowed.
func (p *Provider) adminRefused(r *http.Request, u *auth.User) bool {
	return u != nil && u.IsAdmin() && p.cfg.PublicOrigin(r) && !p.loadSettings(r.Context()).publicAdmins
}

func checkIssuer(s string, insecure bool) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || !u.IsAbs() {
		return &ValidationError{Problems: []string{"the issuer must be a full address such as https://sso.home.example.net"}}
	}
	if u.Scheme != "https" && !(insecure && u.Scheme == "http") {
		return &ValidationError{Problems: []string{"the issuer must use https"}}
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return &ValidationError{Problems: []string{"the issuer can't have a query, fragment or user name"}}
	}
	if u.Path != "" && u.Path != "/oidc" {
		return &ValidationError{Problems: []string{"the issuer is either a host of its own (https://sso.example.net) or the desktop's address with /oidc"}}
	}
	return nil
}

// ---- routing --------------------------------------------------------------

// issuerParts splits the issuer into host (no port) and path ("" or "/oidc").
func (p *Provider) issuerParts(ctx context.Context) (host, path string) {
	u, err := url.Parse(p.Issuer(ctx))
	if err != nil {
		return "", ""
	}
	return strings.ToLower(u.Hostname()), strings.TrimRight(u.Path, "/")
}

// Owns reports whether hardyd should hand a request to the provider: any
// request to the issuer's own host when the issuer is a host of its own
// (nothing else is served there), or a request under /oidc on the
// issuer's host when it lives on the desktop's.
func (p *Provider) Owns(r *http.Request) bool {
	host, path := p.issuerParts(r.Context())
	reqHost := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(reqHost); err == nil {
		reqHost = h
	}
	reqHost = strings.TrimSuffix(reqHost, ".")
	if reqHost != host {
		return false
	}
	if path == "" {
		return true
	}
	return r.URL.Path == path || strings.HasPrefix(r.URL.Path, path+"/")
}

// ServeHTTP serves the provider (call it only when Owns says so).
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, base := p.issuerParts(r.Context())
	rest := strings.TrimPrefix(r.URL.Path, base)
	if rest == "" {
		rest = "/"
	}
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	if r.TLS != nil {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	if p.servePage(w, r, rest, base) {
		return
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = rest
	r2.URL.RawPath = ""
	p.op.ServeHTTP(w, r2)
}

// corsAllowed lets browser apps (NetBird's dashboard when HardyOS is its
// only identity provider) call the token, userinfo and revocation
// endpoints from the origins of registered redirect URIs, and no others.
func (p *Provider) corsAllowed(origin string) bool {
	if origin == "" || origin == "null" {
		return false
	}
	list, err := p.Clients.List(context.Background())
	if err != nil {
		return false
	}
	for _, c := range list {
		if c.Disabled {
			continue
		}
		for _, u := range c.RedirectURIs {
			if pu, err := url.Parse(u); err == nil && strings.EqualFold(pu.Scheme+"://"+pu.Host, origin) {
				return true
			}
		}
	}
	return false
}

// RevokeClient revokes every sign-in (grant and token) at a client.
func (p *Provider) RevokeClient(ctx context.Context, clientID string) (int64, error) {
	return revokeWhere(ctx, p.cfg.DB, p.now(), `client_id = ?`, clientID)
}

// EndUser ends a person's sign-in sessions and revokes every token apps
// hold for them (password changed or reset, account turned off).
func (p *Provider) EndUser(ctx context.Context, userID int64) {
	_, _ = p.cfg.DB.ExecContext(ctx, `DELETE FROM oidc_browser_sessions WHERE user_id = ?`, userID)
	_, _ = revokeWhere(ctx, p.cfg.DB, p.now(), `user_id = ?`, userID)
}

// PasswordSet ends what a person signed in to with a password older than
// at (the directory's pwdLastSet: a password changed on a computer in the
// domain, which HardyOS doesn't otherwise hear of): the provider's sign-in
// sessions and the grants (and tokens) made before it. It reports how many
// sessions and grants ended.
func (p *Provider) PasswordSet(ctx context.Context, userID int64, at time.Time) int64 {
	ts := store.FormatTime(at)
	var n int64
	if res, err := p.cfg.DB.ExecContext(ctx, `DELETE FROM oidc_browser_sessions WHERE user_id = ? AND auth_time < ?`, userID, ts); err == nil {
		n, _ = res.RowsAffected()
	}
	g, _ := revokeWhere(ctx, p.cfg.DB, p.now(), `user_id = ? AND created_at < ?`, userID, ts)
	return n + g
}

// GrantActive reports whether the sign-in behind an access token this
// provider issued (its jti) is still in force: not revoked (an
// administrator, sign-out, a new password, the account replaced) and not
// past the grant's end. The token's own 15 minutes don't matter here: the
// app gateway checks its sessions against the grant every 30 seconds.
func (p *Provider) GrantActive(ctx context.Context, accessTokenID string) bool {
	var grantID string
	if err := p.cfg.DB.QueryRowContext(ctx, `SELECT grant_id FROM oidc_access_tokens WHERE id = ?`, accessTokenID).Scan(&grantID); err != nil {
		return false
	}
	g, err := p.storage().loadGrant(ctx, `id = ?`, grantID)
	return err == nil && !g.Revoked && p.now().Before(g.ExpiresAt)
}
