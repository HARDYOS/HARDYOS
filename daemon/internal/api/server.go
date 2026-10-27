// Package api implements hardyd's HTTP API and serves the web desktop.
package api

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/backups"
	"github.com/hardyos/hardyos/daemon/internal/clientip"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/installer"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/metrics"
	"github.com/hardyos/hardyos/daemon/internal/monitor"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/oidc"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/publish"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/sharelinks"
	"github.com/hardyos/hardyos/daemon/internal/storage"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

// Config controls the API server. Every dependency except DB is optional in
// tests; New fills in defaults.
type Config struct {
	DB      *store.DB
	Jobs    *jobs.Manager
	Events  *events.Broker
	Priv    *priv.Client
	Limiter *auth.LoginLimiter
	Storage *storage.Service // nil disables storage endpoints
	Notify  *notify.Center   // nil disables notification endpoints
	// Alerts routes events to channels (Control Panel > Notifications);
	// nil leaves those endpoints out.
	Alerts *notify.Dispatcher
	// Monitor is resource history, disk health and the UPS (nil: none).
	Monitor *monitor.Service
	Metrics *metrics.Collector
	// Installer, when set, turns hardyd into the live ISO's web installer:
	// only the installer API is served.
	Installer *installer.Service
	// Updates enables the update and version endpoints (nil disables them).
	Updates *updates.Service
	// Backups enables settings backups (nil disables them).
	Backups *backups.Service
	// Apps finds Docker app packages and keeps app access, imported
	// catalogs and window proxy ports; nil uses the default folders and DB.
	Apps *appstore.Store
	// AppPrincipals says who a signed-in person is for app access (domain
	// sign-in plugs in here); nil treats every account as a HardyOS user.
	AppPrincipals AppPrincipals
	Root          fs.FS // filesystem rooted at "/" for system info; nil uses the real one
	Logger        *slog.Logger
	WebRoot       string // directory with the built web desktop; empty disables static serving
	Insecure      bool   // allow session cookies over plain HTTP (true until TLS lands)
	// Kerberos checks domain passwords; nil uses the real Kerberos client
	// (tests pass a fake).
	Kerberos auth.PasswordChecker
	// DomainInfoTTL is how long the domain's realm and DCs are cached for
	// sign-in (default 30 s; tests use less).
	DomainInfoTTL time.Duration

	// Files reads and writes files as a person (internal/files); share
	// links use it. nil: links can't be made and existing ones don't open.
	// When it's also a files.Service (files.Client is), the File Manager's
	// /files endpoints are served.
	Files files.Access

	// Remote publishes the desktop and apps through NetBird's reverse
	// proxy (Control Panel › Remote Access); nil leaves publishing out.
	Remote *publish.Publisher
	// SSOIssuer is HardyOS's own OIDC provider's issuer, for the setup
	// check (part B, internal/oidc, plugs in here; nil: none yet).
	SSOIssuer publish.SSOIssuer
	// Resolver looks up the base domain's CNAME (nil: the system's DNS).
	Resolver publish.Resolver

	// TrustedProxies are the reverse proxies whose X-Forwarded-For is
	// believed for the client's address (sign-in limits, audit, share link
	// limits). Empty (the default): the header is never read.
	TrustedProxies []netip.Prefix

	// Secrets seals what hardyd keeps encrypted at rest (the sign-in
	// provider's signing keys); nil: a key that lasts as long as the
	// process (tests, development).
	Secrets secretbox.Source
	// OIDCNames are Remote Access's base domain and desktop name, for the
	// sign-in provider's issuer; nil reads them from the settings table.
	OIDCNames oidc.Names
	// PublicHost is the desktop's own HTTPS name (the issuer without a base
	// domain); nil uses the hostname.
	PublicHost func() string
	// GPUUploadDir is where uploaded vGPU driver files are saved for
	// hardyd-priv (default gpu.UploadDir; tests use a temp dir).
	GPUUploadDir string
}

// Server is hardyd's HTTP handler.
type Server struct {
	cfg      Config
	users    *auth.Users
	sessions *auth.Sessions
	signin   *auth.SignIn
	audit    *audit.Log
	mux      *http.ServeMux
	tickets  terminalTickets
	proxy    *appProxy
	remote   *remoteRuntime
	links    *sharelinks.Store
	uploads  uploads
	dav      davState
	started  time.Time
	log      *slog.Logger
	ips      *clientip.Resolver
	oidc     *oidc.Provider
	// pubLimiter slows down failed sign-ins from the internet (through the
	// app gateway) in buckets of their own: decision 156.
	pubLimiter *auth.DelayLimiter
	// waits hands a job's in-memory outcome (a new client secret) back to
	// the request that started it.
	waits jobWaits
}

// New builds the API server and registers its routes.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Events == nil {
		cfg.Events = events.NewBroker()
	}
	if cfg.Limiter == nil {
		cfg.Limiter = auth.NewLoginLimiter()
	}
	if cfg.Root == nil {
		cfg.Root = os.DirFS("/")
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux(), started: time.Now(), log: cfg.Logger,
		ips: &clientip.Resolver{Trusted: cfg.TrustedProxies}, pubLimiter: auth.NewDelayLimiter()}
	s.proxy = &appProxy{s: s}
	s.remote = &remoteRuntime{s: s}
	if cfg.DB != nil {
		s.users = &auth.Users{DB: cfg.DB}
		s.sessions = &auth.Sessions{DB: cfg.DB}
		s.audit = &audit.Log{DB: cfg.DB, Events: cfg.Events}
		s.signin = &auth.SignIn{Users: s.users, Kerberos: cfg.Kerberos, Log: cfg.Logger}
		if cfg.Priv != nil && cfg.Installer == nil {
			s.signin.Domain = &privDirectory{pc: cfg.Priv, ttl: cfg.DomainInfoTTL}
		}
		if cfg.Installer == nil {
			if s.cfg.PublicHost == nil {
				s.cfg.PublicHost = func() string { h, _ := os.Hostname(); return strings.ToLower(h) }
			}
			s.oidc = s.newOIDC()
			if s.oidc != nil {
				// A domain account row stays one directory object's (decision
				// 144), and a password set in the domain ends what was signed
				// in with the old one.
				s.signin.Anchor = s.oidc
				s.signin.PasswordSet = s.passwordSet
				if cfg.Jobs != nil {
					s.registerOIDCJobs(cfg.Jobs)
				}
			}
		}
	}
	// Remote access and the sign-in provider see each other: the provider's
	// issuer follows Remote Access's names (https://sso.<base>), and the
	// setup check looks for that issuer among NetBird's identity providers.
	if s.cfg.Remote != nil && s.oidc != nil {
		s.cfg.Remote.OnNamesChanged = s.oidc.NamesChanged
		s.cfg.Remote.Issuer = s.oidc.Issuer
		if s.cfg.SSOIssuer == nil {
			s.cfg.SSOIssuer = s.oidc.Issuer
		}
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	m := s.mux
	// Public
	m.HandleFunc("GET /api/v1/health", s.handleHealth)
	m.HandleFunc("GET /api/v1/version", s.handleVersion)

	if s.cfg.Installer != nil {
		s.installerRoutes()
	} else if s.cfg.DB != nil {
		m.HandleFunc("GET /api/v1/installer", s.handleInstallerStatus)
		m.HandleFunc("GET /api/v1/setup", s.handleSetupStatus)
		m.HandleFunc("POST /api/v1/setup/admin", s.handleSetupAdmin)
		m.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
		m.HandleFunc("POST /api/v1/auth/logout", s.handleLogout)

		// Signed in
		m.Handle("GET /api/v1/auth/me", s.authed(s.handleMe))
		m.Handle("POST /api/v1/auth/password", s.authed(s.handleChangePassword))
		m.Handle("GET /api/v1/jobs", s.authed(s.handleListJobs))
		m.Handle("GET /api/v1/jobs/{id}", s.authed(s.handleGetJob))
		m.Handle("POST /api/v1/jobs/{id}/cancel", s.authed(s.handleCancelJob))
		m.Handle("GET /api/v1/events", s.authed(s.handleEvents))
		m.Handle("GET /api/v1/system/info", s.authed(s.handleSystemInfo))
		m.Handle("GET /api/v1/system/metrics", s.authed(s.handleMetrics))
		s.shareLinkRoutes() // includes the public /s/<token> pages

		// Admin
		m.Handle("GET /api/v1/users", s.admin(s.handleListUsers))
		m.Handle("POST /api/v1/users", s.admin(s.handleCreateUser))
		m.Handle("GET /api/v1/users/{id}", s.admin(s.handleGetUser))
		m.Handle("PATCH /api/v1/users/{id}", s.admin(s.handleUpdateUser))
		m.Handle("DELETE /api/v1/users/{id}", s.admin(s.handleDeleteUser))
		m.Handle("POST /api/v1/users/{id}/password", s.admin(s.handleResetPassword))
		m.Handle("GET /api/v1/audit", s.admin(s.handleListAudit))
		m.Handle("POST /api/v1/system/self-test", s.admin(s.handleSelfTest))
		s.storageRoutes()
		s.notifyRoutes()
		s.monitorRoutes()
		if s.cfg.Updates != nil {
			// Installed systems only, like updates (the live installer has neither).
			s.updateRoutes()
			s.networkRoutes()
			s.bootRoutes()
			s.terminalRoutes()
			s.domainRoutes()
			s.appRoutes()
			s.remoteRoutes()
			s.shareRoutes()
			s.fileServiceRoutes()
			s.snapshotRoutes()
			s.vmRoutes()
			s.deviceRoutes()
		}
		if s.cfg.Backups != nil {
			s.backupRoutes()
		}
		s.oidcRoutes() // Control Panel > Sign-in (OIDC); the provider itself is routed in ServeHTTP
		if _, ok := s.cfg.Files.(files.Service); ok {
			s.fileRoutes()
			s.davRoutes() // WebDAV at /dav/, outside /api and the desktop session
		}
	}

	m.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "no such API endpoint")
	})
	if s.cfg.WebRoot != "" {
		m.Handle("/", spaHandler(os.DirFS(s.cfg.WebRoot)))
	}
}

// ServeHTTP implements http.Handler with request logging, baseline security
// headers and CSRF protection for state-changing API calls.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if s.oidc != nil && s.oidc.Owns(r) {
		s.serveProvider(w, r, start)
		return
	}
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy", "default-src 'self'; font-src 'self' data:; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; frame-src "+frameSrc(r)+s.remote.frameSrc()+"; frame-ancestors 'self'")

	rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	if strings.HasPrefix(r.URL.Path, "/api/") && !csrfSafe(r) {
		writeError(rw, http.StatusForbidden, "csrf", "missing X-HardyOS-Request header or cross-site origin")
	} else {
		s.mux.ServeHTTP(rw, r)
	}
	s.log.Debug("http request",
		"method", r.Method, "path", logPath(r.URL.Path), "status", rw.status,
		"duration", time.Since(start).String())
}

// serveProvider hands a request to the sign-in provider: its own host
// (sso.<base>) or /oidc on the desktop's, with its own headers and no
// desktop routes.
func (s *Server) serveProvider(w http.ResponseWriter, r *http.Request, start time.Time) {
	rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	s.oidc.ServeHTTP(rw, r)
	s.log.Debug("http request", "method", r.Method, "path", r.URL.Path, "status", rw.status,
		"duration", time.Since(start).String())
}

// logPath is a request path as it may be logged: a share link's token is
// as good as the link, so "/s/<token>/download" is logged as "/s/…/download".
func logPath(p string) string {
	rest, ok := strings.CutPrefix(p, "/s/")
	if !ok || strings.HasPrefix(rest, "-/") {
		return p
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return "/s/…" + rest[i:]
	}
	return "/s/…"
}

// csrfSafe allows safe methods, and requires state-changing requests to carry
// a custom header (which browsers won't send cross-site without a CORS
// preflight we never approve) and, when present, a same-host Origin.
func csrfSafe(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if r.Header.Get("X-HardyOS-Request") != "1" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		o := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
		if o != r.Host {
			return false
		}
	}
	return true
}

// spaHandler serves files from root and falls back to index.html for client-side routes.
func spaHandler(root fs.FS) http.Handler {
	files := http.FileServerFS(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "."
		}
		if _, err := fs.Stat(root, p); errors.Is(err, fs.ErrNotExist) {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController (and the WebSocket upgrade) reach the
// underlying writer's Hijacker and Flusher.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
