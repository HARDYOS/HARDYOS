package api

// WebDAV at /dav/ (file sharing part E): the shared folders with WebDAV on,
// and Home, for domain accounts, with HTTP Basic sign-in over HTTPS. Files
// are read and written as the person through internal/files (see
// internal/dav); the password is checked like a desktop sign-in.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/dav"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/smb"
	"golang.org/x/net/webdav"
)

// WebDAV tuning.
const (
	// davAuthTTL is how long a checked password is trusted (WebDAV clients
	// send it with every request).
	davAuthTTL = 2 * time.Minute
	// davConfigTTL is how long File Services' settings are cached.
	davConfigTTL = 15 * time.Second
	// davLoginAuditEvery: a successful sign-in is written to the audit log
	// at most this often per account (failures always are).
	davLoginAuditEvery = time.Hour
	davMaxCache        = 4096
	davMaxLockUsers    = 1024
	davRealm           = `Basic realm="HardyOS", charset="UTF-8"`
)

// davState is the WebDAV server's memory: checked passwords (only an HMAC
// of name and password under a key made at start-up, never the password),
// per-person lock tables and the cached settings.
type davState struct {
	once sync.Once
	key  []byte

	mu      sync.Mutex
	checked map[[32]byte]davChecked
	logged  map[int64]time.Time
	locks   map[string]webdav.LockSystem

	cfgMu sync.Mutex
	cfg   *davConfig
	cfgAt time.Time
}

type davChecked struct {
	userID int64
	until  time.Time
}

// davConfig is what File Services says about WebDAV.
type davConfig struct {
	enabled bool
	shares  map[string]bool // id -> WebDAV on
}

func (d *davState) init() {
	d.once.Do(func() {
		d.key = make([]byte, 32)
		if _, err := rand.Read(d.key); err != nil {
			panic(err)
		}
		d.checked = map[[32]byte]davChecked{}
		d.logged = map[int64]time.Time{}
		d.locks = map[string]webdav.LockSystem{}
	})
}

func (d *davState) cacheKey(limitKey, password string) [32]byte {
	m := hmac.New(sha256.New, d.key)
	m.Write([]byte(limitKey))
	m.Write([]byte{0})
	m.Write([]byte(password))
	var k [32]byte
	copy(k[:], m.Sum(nil))
	return k
}

func (d *davState) lookup(k [32]byte) (int64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.checked[k]
	if !ok || time.Now().After(c.until) {
		delete(d.checked, k)
		return 0, false
	}
	return c.userID, true
}

func (d *davState) store(k [32]byte, userID int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.checked) >= davMaxCache {
		now := time.Now()
		for kk, c := range d.checked {
			if now.After(c.until) {
				delete(d.checked, kk)
			}
		}
		if len(d.checked) >= davMaxCache {
			d.checked = map[[32]byte]davChecked{}
		}
	}
	d.checked[k] = davChecked{userID: userID, until: time.Now().Add(davAuthTTL)}
}

func (d *davState) drop(k [32]byte) {
	d.mu.Lock()
	delete(d.checked, k)
	d.mu.Unlock()
}

// dropUser forgets every checked password of an account.
func (d *davState) dropUser(id int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, c := range d.checked {
		if c.userID == id {
			delete(d.checked, k)
		}
	}
}

func (d *davState) shouldLog(id int64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.logged[id]; ok && time.Since(t) < davLoginAuditEvery {
		return false
	}
	if len(d.logged) > davMaxCache {
		d.logged = map[int64]time.Time{}
	}
	d.logged[id] = time.Now()
	return true
}

// lockSystem is the person's own lock table: paths are only unique within
// one person's view (everyone has a /Home).
func (d *davState) lockSystem(principal string) webdav.LockSystem {
	k := strings.ToLower(principal)
	d.mu.Lock()
	defer d.mu.Unlock()
	if ls, ok := d.locks[k]; ok {
		return ls
	}
	if len(d.locks) >= davMaxLockUsers {
		d.locks = map[string]webdav.LockSystem{}
	}
	ls := webdav.NewMemLS()
	d.locks[k] = ls
	return ls
}

// config asks hardyd-priv's File Services status (cached briefly).
func (s *Server) davConfig(ctx context.Context) (*davConfig, error) {
	d := &s.dav
	d.cfgMu.Lock()
	defer d.cfgMu.Unlock()
	if d.cfg != nil && time.Since(d.cfgAt) < davConfigTTL {
		return d.cfg, nil
	}
	if s.cfg.Priv == nil {
		return &davConfig{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var st smb.Status
	if err := s.cfg.Priv.Call(ctx, priv.OpFilesStatus, nil, &st); err != nil {
		var pe *priv.Error
		if errors.As(err, &pe) && pe.Code == priv.CodeUnknownOp {
			d.cfg, d.cfgAt = &davConfig{}, time.Now()
			return d.cfg, nil
		}
		return nil, err
	}
	c := &davConfig{enabled: st.Joined && st.Settings.WebDAVEnabled, shares: map[string]bool{}}
	for _, sh := range st.Shares {
		c.shares[sh.ID] = sh.WebDAV
	}
	d.cfg, d.cfgAt = c, time.Now()
	return c, nil
}

func (s *Server) davRoutes() {
	h := http.HandlerFunc(s.handleDAV)
	s.mux.Handle("/dav/", h)
	s.mux.Handle("/dav", h)
	// Windows asks the server's top for OPTIONS before it maps a drive.
	s.mux.HandleFunc("OPTIONS /{$}", func(w http.ResponseWriter, r *http.Request) {
		if c, err := s.davConfig(r.Context()); err == nil && c.enabled {
			w.Header().Set("DAV", "1, 2")
			w.Header().Set("MS-Author-Via", "DAV")
		}
		w.Header().Set("Allow", "OPTIONS, GET, HEAD")
		w.WriteHeader(http.StatusOK)
	})
}

// davError answers in plain text (WebDAV clients show it, if anything).
func davError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg+"\n")
}

func (s *Server) handleDAV(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	// Nothing served here may run on this origin: files are attachments,
	// and any page is sandboxed.
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "private, no-store")
	if r.TLS == nil && !s.cfg.Insecure {
		davError(w, http.StatusForbidden, "WebDAV works over HTTPS only: use https://"+r.Host+"/dav/")
		return
	}
	cfg, err := s.davConfig(r.Context())
	if err != nil {
		s.log.Warn("webdav: reading the file services settings", "err", err)
		davError(w, http.StatusServiceUnavailable, "WebDAV isn't available right now; try again in a minute")
		return
	}
	if !cfg.enabled {
		davError(w, http.StatusNotFound, "WebDAV is turned off on this server (Control Panel > File Services)")
		return
	}
	u, ok := s.davSignIn(w, r)
	if !ok {
		return
	}
	fs := s.files()
	who := files.WhoFor(u)
	list, err := fs.Shares(r.Context(), who)
	if err != nil {
		if errors.Is(err, files.ErrNoAccess) {
			davError(w, http.StatusForbidden, "this account can't use the shared folders")
			return
		}
		s.log.Warn("webdav: listing folders", "user", u.Username, "err", err)
		davError(w, http.StatusServiceUnavailable, "the shared folders can't be listed right now")
		return
	}
	body := &davBody{ReadCloser: r.Body}
	r.Body = body
	d := &dav.FS{
		Files: fs, Who: who,
		Roots:      dav.Roots(list, func(id string) bool { return cfg.shares[id] }),
		BodyFailed: body.failed,
		Changed: func(op, target string, size int64) {
			detail := "webdav"
			if op == "put" {
				detail = fmt.Sprintf("webdav, %d bytes", size)
			}
			action := map[string]string{"put": "files.upload", "delete": "files.delete", "move": "files.move"}[op]
			s.record(r, u, action, target, audit.Success, detail)
		},
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.Set("Content-Disposition", "attachment")
	}
	handler := &webdav.Handler{
		Prefix: "/dav", FileSystem: d, LockSystem: s.dav.lockSystem(u.Username),
		Logger: func(r *http.Request, err error) {
			if err != nil && !errors.Is(err, context.Canceled) {
				s.log.Debug("webdav", "method", r.Method, "path", r.URL.Path, "user", u.Username, "err", err)
			}
		},
	}
	handler.ServeHTTP(w, r)
}

// davBody notes whether the request body broke off before its end.
type davBody struct {
	io.ReadCloser
	mu  sync.Mutex
	bad bool
}

func (b *davBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		b.mu.Lock()
		b.bad = true
		b.mu.Unlock()
	}
	return n, err
}

func (b *davBody) failed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.bad
}

// davSignIn checks the request's Basic credentials, the same way as a
// desktop sign-in (domain accounts only): the same rate limits and lockout
// (shared with the desktop's), Kerberos with this server's own DC, and an
// unreachable DC is a 503 that doesn't count as a guess. A password that
// worked is trusted for davAuthTTL; the account itself is looked up again
// on every request (turned off here = locked out at once) and its domain
// groups refreshed like a session's.
func (s *Server) davSignIn(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	s.dav.init()
	name, pw, ok := r.BasicAuth()
	if !ok || name == "" {
		w.Header().Set("WWW-Authenticate", davRealm)
		davError(w, http.StatusUnauthorized, "sign in with your domain account")
		return nil, false
	}
	ctx := r.Context()
	userKey := s.signin.LimitKey(ctx, name)
	k := s.dav.cacheKey(userKey, pw)
	if id, ok := s.dav.lookup(k); ok {
		u, err := s.davUser(r, id)
		if err == nil {
			return u, true
		}
		s.dav.drop(k)
		w.Header().Set("WWW-Authenticate", davRealm)
		davError(w, http.StatusUnauthorized, "this account can't sign in any more")
		return nil, false
	}
	ip := s.clientIP(r)
	for _, key := range []string{"ip:" + ip, userKey} {
		if ok, wait := s.cfg.Limiter.Allowed(key); !ok {
			secs := int(math.Ceil(wait.Seconds()))
			w.Header().Set("Retry-After", fmt.Sprint(secs))
			s.record(r, nil, "dav.login", name, audit.Denied, "rate limited")
			davError(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed sign-ins; try again in %d minutes", (secs+59)/60))
			return nil, false
		}
	}
	u, err := s.signin.AuthenticateDomain(ctx, name, pw)
	if err != nil {
		status, counts := davLoginStatus(err)
		if counts {
			s.cfg.Limiter.Fail("ip:" + ip)
			s.cfg.Limiter.Fail(userKey)
		}
		s.record(r, nil, "dav.login", name, audit.Failure, err.Error())
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", davRealm)
		}
		msg := err.Error()
		if status == http.StatusInternalServerError {
			s.log.Error("webdav sign-in", "err", err)
			msg = "something went wrong; see the system log"
		}
		davError(w, status, msg)
		return nil, false
	}
	s.cfg.Limiter.Succeed("ip:" + ip)
	s.cfg.Limiter.Succeed(userKey)
	s.dav.store(k, u.ID)
	if s.dav.shouldLog(u.ID) {
		s.record(r, u, "dav.login", u.Username, audit.Success, "webdav")
	}
	return u, true
}

// davUser loads an account whose password was checked a moment ago: gone
// or turned off means no, a domain account's groups are refreshed like a
// session's.
func (s *Server) davUser(r *http.Request, id int64) (*auth.User, error) {
	u, err := s.users.Get(r.Context(), id)
	if err != nil || u.Disabled || u.Source != auth.SourceDomain {
		s.dav.dropUser(id)
		return nil, errAccountUnavailable
	}
	nu, err := s.signin.Refresh(r.Context(), u)
	if errors.Is(err, auth.ErrAccountGone) {
		s.dav.dropUser(id)
		_ = s.sessions.RevokeUser(r.Context(), u.ID)
		s.record(r, u, "auth.session.end", u.Username, audit.Success, "the domain account was deleted, turned off or expired")
		return nil, err
	}
	if err == nil {
		u = nu
	}
	return u, nil
}

// davLoginStatus is the HTTP status for a failed WebDAV sign-in and
// whether it counts as a guess (as on the desktop: the domain being
// unreachable doesn't).
func davLoginStatus(err error) (int, bool) {
	switch {
	case errors.Is(err, auth.ErrLocalAccount):
		return http.StatusForbidden, false
	case isErr(err, auth.ErrBadCredentials, auth.ErrUnknownDomain, auth.ErrAccountDisabled, auth.ErrAccountLocked,
		auth.ErrAccountExpired, auth.ErrAccountRevoked, auth.ErrPasswordExpired):
		return http.StatusUnauthorized, true
	case errors.Is(err, auth.ErrDisabledHere):
		return http.StatusUnauthorized, false
	case isErr(err, auth.ErrClockSkew, auth.ErrDomainUnavailable, auth.ErrNoLocalDC):
		return http.StatusServiceUnavailable, false
	}
	return http.StatusInternalServerError, false
}
