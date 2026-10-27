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
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// davMaxBody bounds every request body but an upload's (XML).
	davMaxBody = 1 << 20
	// Locks: at most an hour each (clients refresh them), so many per
	// person and in all, and an owner note at most this long.
	davMaxLockTime     = time.Hour
	davMaxLocksPerUser = 256
	davMaxLocks        = 8192
	davMaxLockOwner    = 1024
	// davLimitedLogEvery: a rate-limited sign-in is written to the audit log
	// at most this often per key (with how many were turned away).
	davLimitedLogEvery = 15 * time.Minute
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
	locks   map[string]*cappedLS
	// lockCount is every person's locks together.
	lockCount atomic.Int64
	// limited: rate-limited sign-ins per key since the last audit entry.
	limited map[string]*davLimited

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
		d.locks = map[string]*cappedLS{}
		d.limited = map[string]*davLimited{}
	})
}

type davLimited struct {
	since time.Time
	n     int
}

// noteLimited counts a rate-limited sign-in for key and reports whether it
// should be written to the audit log now (the first in davLimitedLogEvery),
// with how many were turned away since the last entry.
func (d *davState) noteLimited(key string) (bool, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	l := d.limited[key]
	if l != nil && now.Sub(l.since) < davLimitedLogEvery {
		l.n++
		return false, 0
	}
	if len(d.limited) >= davMaxCache {
		d.limited = map[string]*davLimited{}
	}
	prev := 0
	if l != nil {
		prev = l.n
	}
	d.limited[key] = &davLimited{since: now}
	return true, prev
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
func (d *davState) lockSystem(principal string) *cappedLS {
	k := strings.ToLower(principal)
	d.mu.Lock()
	defer d.mu.Unlock()
	if ls, ok := d.locks[k]; ok {
		return ls
	}
	if len(d.locks) >= davMaxLockUsers {
		for _, ls := range d.locks {
			d.lockCount.Add(-int64(ls.count()))
		}
		d.locks = map[string]*cappedLS{}
	}
	ls := &cappedLS{LockSystem: webdav.NewMemLS(), total: &d.lockCount, held: map[string]time.Time{}}
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
	if r.Method != http.MethodPut {
		// Only uploads are big; XML bodies (PROPFIND, PROPPATCH, LOCK) and
		// anything else are bounded.
		r.Body = http.MaxBytesReader(w, r.Body, davMaxBody)
	}
	body := &davBody{ReadCloser: r.Body}
	r.Body = body
	copySrc := ""
	d := &dav.FS{
		Files: fs, Who: who,
		Roots:      dav.Roots(list, func(id string) bool { return cfg.shares[id] }),
		BodyFailed: body.failed,
		Changed: func(op, target, detail string, size int64) {
			action := map[string]string{"put": "files.upload", "delete": "files.delete", "move": "files.move",
				"mkdir": "files.mkdir", "settime": "files.settime"}[op]
			if op == "put" {
				detail = fmt.Sprintf("%d bytes", size)
				if r.Method == "COPY" {
					action, detail = "files.copy", "from "+copySrc+", "+detail
				}
			}
			if detail != "" {
				detail = "webdav, " + detail
			} else {
				detail = "webdav"
			}
			s.record(r, u, action, target, audit.Success, detail)
		},
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		h.Set("Content-Disposition", "attachment")
	case http.MethodPost:
		// Nothing is posted to WebDAV; x/net/webdav would serve it like GET.
		h.Set("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, PROPPATCH, LOCK, UNLOCK")
		davError(w, http.StatusMethodNotAllowed, "POST isn't used by WebDAV")
		return
	case "PROPFIND":
		// A whole tree in one answer is a way to keep the server busy (and
		// to start a file worker per folder): RFC 4918 9.1 lets a server
		// refuse it. No Depth header means infinity.
		if dh := strings.TrimSpace(r.Header.Get("Depth")); dh == "" || strings.EqualFold(dh, "infinity") {
			h.Set("Content-Type", "application/xml; charset=utf-8")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="utf-8"?>`+"\n"+`<D:error xmlns:D="DAV:"><D:propfind-finite-depth/></D:error>`+"\n")
			return
		}
	case "LOCK":
		// What the client is told matches what's kept (cappedLS).
		r.Header.Set("Timeout", davLockTimeout(r.Header.Get("Timeout")))
	case http.MethodPut:
		if !s.davCheckReplace(w, r, d, strings.TrimPrefix(r.URL.Path, "/dav")) {
			return
		}
	case "COPY", "MOVE":
		src, dst, ok := davDestination(w, r)
		if !ok {
			return
		}
		if d.Same(src, dst) {
			davError(w, http.StatusForbidden, "the destination is the same as the source")
			return
		}
		if d.Inside(src, dst) {
			davError(w, http.StatusForbidden, "a folder can't be copied or moved into itself")
			return
		}
		if r.Header.Get("Overwrite") != "F" && !s.davCheckReplace(w, r, d, dst) {
			return
		}
		copySrc = d.Name(src)
		// x/net/webdav compares the raw paths: give it the cleaned ones.
		r.URL.Path, r.URL.RawPath = "/dav"+src, ""
		r.Header.Set("Destination", escapedDAV(dst))
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

// davCheckReplace answers 403 (and false) when the request would replace a
// file the person may not write.
func (s *Server) davCheckReplace(w http.ResponseWriter, r *http.Request, d *dav.FS, name string) bool {
	if err := d.CheckReplace(r.Context(), name); errors.Is(err, os.ErrPermission) {
		davError(w, http.StatusForbidden, "you may not change that file")
		return false
	}
	return true
}

// davClean cleans a request path and takes /dav off it ("/" for the top);
// ok is false for anything outside /dav.
func davClean(p string) (string, bool) {
	c := path.Clean("/" + p)
	if c == "/dav" {
		return "/", true
	}
	rest, ok := strings.CutPrefix(c, "/dav/")
	return "/" + rest, ok
}

// davDestination reads a COPY or MOVE's source and Destination, cleaned
// and below /dav (answering the request itself when they aren't usable).
func davDestination(w http.ResponseWriter, r *http.Request) (src, dst string, ok bool) {
	hdr := r.Header.Get("Destination")
	u, err := url.Parse(hdr)
	if hdr == "" || err != nil {
		davError(w, http.StatusBadRequest, "a Destination header is needed")
		return "", "", false
	}
	if u.Host != "" && u.Host != r.Host {
		davError(w, http.StatusBadGateway, "the destination is on another server")
		return "", "", false
	}
	src, ok1 := davClean(r.URL.Path)
	dst, ok2 := davClean(u.Path)
	if !ok1 || !ok2 {
		davError(w, http.StatusForbidden, "the destination must be inside /dav/")
		return "", "", false
	}
	return src, dst, true
}

// escapedDAV is a /dav path as a header value (x/net/webdav parses the
// Destination as a URL: a "#" or "%" in a name must stay a name).
func escapedDAV(p string) string { return (&url.URL{Path: "/dav" + p}).EscapedPath() }

// davLockTimeout is a LOCK's Timeout header with at most davMaxLockTime:
// the client's first choice when it is a number of seconds within it,
// else the most allowed ("Infinite" or nothing included).
func davLockTimeout(h string) string {
	first, _, _ := strings.Cut(h, ",")
	first = strings.TrimSpace(first)
	if n, ok := strings.CutPrefix(first, "Second-"); ok {
		if v, err := strconv.ParseUint(n, 10, 32); err == nil && time.Duration(v)*time.Second <= davMaxLockTime {
			return first
		}
	}
	return fmt.Sprintf("Second-%d", int(davMaxLockTime/time.Second))
}

// errTooManyLocks: the person (or the server) holds as many WebDAV locks
// as it allows.
var errTooManyLocks = errors.New("too many WebDAV locks; unlock some files or wait for their locks to run out")

// cappedLS is a person's lock table with bounds: no lock lasts longer
// than davMaxLockTime (an "Infinite" timeout included), a person holds at
// most davMaxLocksPerUser and the server davMaxLocks, and an owner note
// longer than davMaxLockOwner isn't kept.
type cappedLS struct {
	webdav.LockSystem
	total *atomic.Int64

	mu   sync.Mutex
	held map[string]time.Time // token -> when it runs out
}

func capDuration(d time.Duration) time.Duration {
	if d < 0 || d > davMaxLockTime {
		return davMaxLockTime
	}
	return d
}

// prune forgets locks that ran out (the memory table drops them itself).
func (c *cappedLS) prune(now time.Time) {
	for t, until := range c.held {
		if now.After(until) {
			delete(c.held, t)
			c.total.Add(-1)
		}
	}
}

func (c *cappedLS) Create(now time.Time, d webdav.LockDetails) (string, error) {
	d.Duration = capDuration(d.Duration)
	if len(d.OwnerXML) > davMaxLockOwner {
		d.OwnerXML = ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prune(now)
	if len(c.held) >= davMaxLocksPerUser || c.total.Load() >= davMaxLocks {
		return "", errTooManyLocks
	}
	tok, err := c.LockSystem.Create(now, d)
	if err == nil {
		c.held[tok] = now.Add(d.Duration)
		c.total.Add(1)
	}
	return tok, err
}

func (c *cappedLS) Refresh(now time.Time, token string, d time.Duration) (webdav.LockDetails, error) {
	d = capDuration(d)
	ld, err := c.LockSystem.Refresh(now, token, d)
	if err == nil {
		c.mu.Lock()
		if _, ok := c.held[token]; ok {
			c.held[token] = now.Add(d)
		}
		c.mu.Unlock()
	}
	return ld, err
}

func (c *cappedLS) Unlock(now time.Time, token string) error {
	err := c.LockSystem.Unlock(now, token)
	c.mu.Lock()
	if _, ok := c.held[token]; ok {
		delete(c.held, token)
		c.total.Add(-1)
	}
	c.mu.Unlock()
	return err
}

func (c *cappedLS) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.held)
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
	// A local account's name is counted under a key of its own: guesses at
	// it over WebDAV must not lock its owner out of the desktop.
	localKey := "dav-local:" + userKey
	for _, key := range []string{"ip:" + ip, userKey, localKey} {
		if ok, wait := s.cfg.Limiter.Allowed(key); !ok {
			secs := int(math.Ceil(wait.Seconds()))
			w.Header().Set("Retry-After", fmt.Sprint(secs))
			// Not one audit row per refused request (a script could fill
			// the log): the first per key and window, with the count since.
			if first, n := s.dav.noteLimited(key); first {
				detail := "rate limited"
				if n > 0 {
					detail = fmt.Sprintf("rate limited (%d more refused since the last entry)", n)
				}
				s.record(r, nil, "dav.login", name, audit.Denied, detail)
			} else {
				s.log.Debug("webdav: rate-limited sign-in", "key", key)
			}
			davError(w, http.StatusTooManyRequests, fmt.Sprintf("too many failed sign-ins; try again in %d minutes", (secs+59)/60))
			return nil, false
		}
	}
	u, err := s.signin.AuthenticateDomain(ctx, name, pw)
	if err != nil {
		status, counts := davLoginStatus(err)
		local := errors.Is(err, auth.ErrLocalAccount)
		if counts {
			s.cfg.Limiter.Fail("ip:" + ip)
			if local {
				s.cfg.Limiter.Fail(localKey)
			} else {
				s.cfg.Limiter.Fail(userKey)
			}
		}
		detail := err.Error()
		if local {
			detail = "a local account's name (refused unchecked)"
		}
		s.record(r, nil, "dav.login", name, audit.Failure, detail)
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", davRealm)
		}
		msg := err.Error()
		if local {
			// Answered like a wrong password: nothing tells a guesser which
			// names are the server's own accounts.
			msg = auth.ErrBadCredentials.Error()
		}
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
	case isErr(err, auth.ErrLocalAccount, auth.ErrBadCredentials, auth.ErrUnknownDomain, auth.ErrAccountDisabled, auth.ErrAccountLocked,
		auth.ErrAccountExpired, auth.ErrAccountRevoked, auth.ErrPasswordExpired):
		return http.StatusUnauthorized, true
	case errors.Is(err, auth.ErrDisabledHere):
		return http.StatusUnauthorized, false
	case isErr(err, auth.ErrClockSkew, auth.ErrDomainUnavailable, auth.ErrNoLocalDC):
		return http.StatusServiceUnavailable, false
	}
	return http.StatusInternalServerError, false
}
