package api

// The office suite (phase 7 part B, docs/office.md, decisions 250-262):
// Control Panel › Office, opening documents from the File Manager and share
// links in the OnlyOffice editor, and the two listeners around the Document
// Server:
//
//   - the office origin, https://<desktop host>:44250, with the desktop's
//     certificate: the editor page and the Document Server proxy for people
//     using the desktop. A port of its own keeps the Document Server's
//     scripts off the desktop's origin. Share link editors use it on the
//     LAN, and files.<base> (through the app gateway) from the internet.
//   - the internal listener, http://<docker0 address>:44251: document
//     downloads and save callbacks from the Document Server container, and
//     nothing else.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/office"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/sharelinks"
)

// Office job kinds.
const (
	JobKindOfficeEnable   = "office.enable"
	JobKindOfficeDisable  = "office.disable"
	JobKindOfficeSettings = "office.settings"
	// DefaultOfficePort is the office origin's port.
	DefaultOfficePort = 44250
	// officeTicketLifetime: how long the desktop has to load the editor
	// window after asking to open a document.
	officeTicketLifetime = time.Minute
)

// OfficeOptions configures the office listeners.
type OfficeOptions struct {
	// TLS is the desktop's certificate (nil: plain HTTP, development).
	TLS *tls.Config
	// Port is the office origin's port (default 44250).
	Port int
	// ListenHost is where the office origin listens (the desktop's host).
	ListenHost string
	// InternalListen is the internal listener's address; "" = the Docker
	// host gateway (docker0) on office.InternalPort, found at run time.
	InternalListen string
	// Interval between checks (default 15 s).
	Interval time.Duration
}

type officeTicket struct {
	ed       *office.Editor
	title    string
	sessHash string
	frame    string // the desktop's origin, for frame-ancestors
	expires  time.Time
}

type officeRuntime struct {
	s        *Server
	svc      *office.Service
	settings *office.SettingsStore
	gate     *office.Gate
	proxy    *office.Proxy
	links    *sharelinks.Public

	mu         sync.Mutex
	opts       OfficeOptions
	running    bool
	srv, isrv  *http.Server
	iaddr      string
	tickets    map[string]*officeTicket
	dsURL      *url.URL
	dsErr      error
	dsAt       time.Time
	kick       chan struct{}
	internalFn func() (*url.URL, error) // tests
}

type officeOriginKey struct{}
type officeIPKey struct{}

// newOffice builds the office runtime (always: the routes say "off" while
// the suite isn't turned on).
func (s *Server) newOffice() *officeRuntime {
	keys := s.cfg.Secrets
	if keys == nil {
		keys = secretbox.NewStaticSource()
	}
	rt := &officeRuntime{s: s, settings: &office.SettingsStore{DB: s.cfg.DB, Keys: keys}, gate: &office.Gate{},
		tickets: map[string]*officeTicket{}, kick: make(chan struct{}, 1), internalFn: s.cfg.OfficeInternal}
	rt.svc = &office.Service{
		DB:       s.cfg.DB,
		Identity: s.officeIdentity,
		Secret:   rt.settings.Secret,
		Internal: rt.internal,
		CallbackBase: func() string {
			return "http://host.docker.internal:" + strconv.Itoa(office.InternalPort)
		},
		MaxFileBytes: func() int64 {
			st, err := rt.settings.Load(context.Background())
			if err != nil {
				return 0
			}
			return int64(st.MaxFileMB) << 20
		},
		Audit: s.officeAudit,
		Log:   s.log,
	}
	if s.cfg.OfficeCallbackBase != "" {
		base := s.cfg.OfficeCallbackBase
		rt.svc.CallbackBase = func() string { return base }
	}
	if fs, ok := s.cfg.Files.(files.Service); ok {
		rt.svc.Files = fs
	}
	rt.svc.PublicBase = func(scheme, host string) bool {
		if f := s.remote.filesURL(); f != "" && scheme == "https" && strings.EqualFold(host, strings.TrimPrefix(f, "https://")) {
			return true
		}
		_, port, err := net.SplitHostPort(host)
		rt.mu.Lock()
		own := strconv.Itoa(rt.port())
		rt.mu.Unlock()
		return err == nil && port == own
	}
	rt.proxy = &office.Proxy{Service: rt.svc, Gate: rt.gate}
	return rt
}

// OfficeService is the office integration (tests, the integration job).
func (s *Server) OfficeService() *office.Service {
	if s.office == nil {
		return nil
	}
	return s.office.svc
}

// internal is the Document Server's address on this server: the
// onlyoffice app's WEB port on 127.0.0.1, while the suite is on and the
// app runs (looked up at most every 10 s).
func (rt *officeRuntime) internal() (*url.URL, error) {
	if rt.internalFn != nil {
		return rt.internalFn()
	}
	rt.mu.Lock()
	if time.Since(rt.dsAt) < 10*time.Second {
		u, err := rt.dsURL, rt.dsErr
		rt.mu.Unlock()
		return u, err
	}
	rt.mu.Unlock()
	u, err := rt.lookupInternal()
	rt.mu.Lock()
	rt.dsURL, rt.dsErr, rt.dsAt = u, err, time.Now()
	rt.mu.Unlock()
	return u, err
}

var errOfficeOff = errors.New("the office suite is turned off")

func (rt *officeRuntime) lookupInternal() (*url.URL, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := rt.settings.Load(ctx)
	if err != nil {
		return nil, err
	}
	if !st.Enabled {
		return nil, errOfficeOff
	}
	if rt.s.cfg.Priv == nil {
		return nil, errors.New("the Document Server isn't available here")
	}
	o, err := rt.s.appsStatus(ctx)
	if err != nil {
		return nil, err
	}
	a := findApp(o, office.AppID)
	if a == nil {
		return nil, errors.New("the Document Server app isn't installed")
	}
	for _, p := range a.Ports {
		if p.Name == "WEB" && p.Port > 0 {
			return &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(p.Port))}, nil
		}
	}
	return nil, errors.New("the Document Server app has no port")
}

func findApp(o *apps.Overview, id string) *apps.App {
	for i := range o.Apps {
		if o.Apps[i].ID == id {
			return &o.Apps[i]
		}
	}
	return nil
}

func (rt *officeRuntime) forget() {
	rt.mu.Lock()
	rt.dsAt = time.Time{}
	rt.mu.Unlock()
	select {
	case rt.kick <- struct{}{}:
	default:
	}
}

// enabled reports whether documents open now.
func (rt *officeRuntime) enabled(ctx context.Context) bool {
	st, err := rt.settings.Load(ctx)
	return err == nil && st.Enabled
}

// ---- identities and audit -------------------------------------------------------

// officeIdentity says who a participant reads and writes as now: a signed-in
// person as themselves (a disabled account, or one gone from the domain,
// fails), a share link visitor as the link's creator while the link is
// usable, still points at (or contains) the file and, to write, still allows
// editing.
func (s *Server) officeIdentity(ctx context.Context, p office.Participant, sess *office.Session, write bool) (files.Who, error) {
	switch p.Kind {
	case office.KindUser:
		who, err := s.linkOwner(ctx, p.UserID)
		if err != nil {
			return files.Who{}, errors.New("the account is turned off or gone")
		}
		return who, nil
	case office.KindLink:
		if s.links == nil {
			return files.Who{}, errors.New("share links aren't available")
		}
		l, err := s.links.Get(ctx, p.LinkID)
		if err != nil {
			return files.Who{}, errors.New("the share link is gone")
		}
		if l.Revoked || !time.Now().Before(l.ExpiresAt) {
			return files.Who{}, errors.New("the share link was turned off or has expired")
		}
		if write && l.Access != sharelinks.AccessEdit {
			return files.Who{}, errors.New("the share link doesn't allow editing")
		}
		inside := sess.Share == l.Share && (sess.Path == l.Path || (l.Dir && (l.Path == "" || strings.HasPrefix(sess.Path, l.Path+"/"))))
		if !inside {
			return files.Who{}, errors.New("the file isn't in the shared link any more")
		}
		who, err := s.linkOwner(ctx, l.CreatedByID)
		if err != nil {
			return files.Who{}, errors.New("the person who shared the link can't use it any more")
		}
		return who, nil
	}
	return files.Who{}, errors.New("unknown participant")
}

// officeAudit writes office's audit entries: for a person as them, for a
// link as "link #3 of HOME\alice (visitor: Sam)", for the Document Server
// itself as "hardyos".
func (s *Server) officeAudit(ctx context.Context, e office.AuditEvent) {
	if s.audit == nil {
		return
	}
	ip, _ := ctx.Value(officeIPKey{}).(string)
	en := audit.Entry{Action: e.Action, Target: e.Target, Outcome: e.Outcome, Detail: e.Detail, IP: ip, Actor: "hardyos"}
	if p := e.Participant; p != nil {
		switch p.Kind {
		case office.KindUser:
			id := p.UserID
			en.ActorID = &id
			en.Actor = p.Name
			if s.users != nil {
				if u, err := s.users.Get(ctx, p.UserID); err == nil {
					en.Actor = u.Username
				}
			}
		case office.KindLink:
			en.Actor = "link #" + strconv.FormatInt(p.LinkID, 10)
			if s.links != nil {
				if l, err := s.links.Get(ctx, p.LinkID); err == nil {
					en.Actor += " of " + l.CreatedBy
				}
			}
			en.Actor += " (visitor: " + p.Name + ")"
		}
	}
	if err := s.audit.Record(context.WithoutCancel(ctx), en); err != nil {
		s.log.Error("audit write failed", "action", e.Action, "err", err)
	}
}

func (s *Server) officeCtx(r *http.Request) context.Context {
	return context.WithValue(r.Context(), officeIPKey{}, s.clientIP(r))
}

// ---- routes -----------------------------------------------------------------------

func (s *Server) officeRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/office", s.authed(s.handleOfficeStatus))
	m.Handle("PUT /api/v1/office/settings", s.admin(s.handleOfficeSettings))
	m.Handle("POST /api/v1/office/enable", s.admin(s.handleOfficeEnable))
	m.Handle("POST /api/v1/office/disable", s.admin(s.handleOfficeDisable))
	m.Handle("POST /api/v1/office/open", s.authed(s.handleOfficeOpen))
	m.Handle("POST /api/v1/office/new", s.authed(s.handleOfficeNew))
	// The Document Server proxy on the desktop's own listener only for
	// files.<base> (through the app gateway); never on the desktop's origin.
	m.HandleFunc("/s/-/ds/", func(w http.ResponseWriter, r *http.Request) {
		if !s.onFilesHost(r) {
			http.NotFound(w, r)
			return
		}
		s.office.proxy.ServeHTTP(w, r)
	})
	m.HandleFunc("GET /s/-/office/static/", office.ServeStatic)
	if s.cfg.Jobs != nil {
		s.registerOfficeJobs(s.cfg.Jobs)
	}
}

// onFilesHost reports whether a request came through the app gateway for
// files.<base>.
func (s *Server) onFilesHost(r *http.Request) bool {
	if !viaGateway(r) {
		return false
	}
	u := s.remote.filesURL()
	if u == "" {
		return false
	}
	return strings.EqualFold(hostOnly(r.Host), strings.TrimPrefix(u, "https://"))
}

// officeHandler is the office origin's handler.
func (rt *officeRuntime) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /s/-/office/editor", rt.serveDesktopEditor)
	mux.HandleFunc("GET /s/-/office/static/", office.ServeStatic)
	mux.Handle("/s/-/ds/", rt.proxy)
	if rt.links != nil {
		mux.HandleFunc("GET /s/{token}/office", rt.links.ServeOffice)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		office.ServeMessage(w, http.StatusNotFound, "Nothing here", "This address only opens documents.", "")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), officeOriginKey{}, true))
		mux.ServeHTTP(w, r)
	})
}

// ---- status and settings ------------------------------------------------------------

// OfficeStatus is Control Panel › Office and what the File Manager needs.
type OfficeStatus struct {
	Enabled bool `json:"enabled"`
	// Ready: documents open now (on, and the Document Server answers).
	Ready         bool            `json:"ready"`
	EditorLimit   int             `json:"editorLimit"`
	ActiveEditors int             `json:"activeEditors"`
	OpenDocuments int             `json:"openDocuments"`
	MaxFileMB     int             `json:"maxFileMB"`
	Formats       []office.Format `json:"formats"`
	// Administrators also get the rest.
	Settings  *office.Settings     `json:"settings,omitempty"`
	Installed bool                 `json:"installed"`
	AppState  string               `json:"appState,omitempty"`
	Version   string               `json:"version,omitempty"`
	Problem   string               `json:"problem,omitempty"`
	Sessions  []OfficeSessionView  `json:"sessions,omitempty"`
	Fonts     []OfficeFontsChoice  `json:"fontsChoices,omitempty"`
	Listeners *OfficeListenerState `json:"listeners,omitempty"`
}

// OfficeSessionView is one open document.
type OfficeSessionView struct {
	Share   string    `json:"share"`
	Path    string    `json:"path"`
	Editors []string  `json:"editors"`
	Opened  time.Time `json:"opened"`
	Saves   int       `json:"saves"`
	State   string    `json:"state"`
	Error   string    `json:"error,omitempty"`
}

// OfficeFontsChoice is a shared folder that can hold extra fonts.
type OfficeFontsChoice struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// OfficeListenerState says whether the two listeners are up.
type OfficeListenerState struct {
	OfficePort int    `json:"officePort"`
	Office     bool   `json:"office"`
	Internal   string `json:"internal"`
}

func (s *Server) handleOfficeStatus(w http.ResponseWriter, r *http.Request, u *auth.User) {
	rt := s.office
	ctx := r.Context()
	st, err := rt.settings.Load(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	out := OfficeStatus{Enabled: st.Enabled, EditorLimit: office.EditorLimit, MaxFileMB: st.MaxFileMB, Formats: office.Formats}
	sessions, _ := rt.svc.OpenSessions(ctx)
	for _, x := range sessions {
		out.ActiveEditors += len(x.Active)
		if len(x.Active) > 0 {
			out.OpenDocuments++
		}
	}
	if st.Enabled {
		_, err := rt.internal()
		out.Ready = err == nil
		if err != nil && u.IsAdmin() {
			out.Problem = err.Error()
		}
	}
	if !u.IsAdmin() {
		writeJSON(w, http.StatusOK, out)
		return
	}
	out.Settings = &st
	if s.cfg.Priv != nil {
		if o, err := s.appsStatus(ctx); err == nil {
			if a := findApp(o, office.AppID); a != nil {
				out.Installed, out.AppState, out.Version = true, a.State, a.Version
			}
		} else if out.Problem == "" {
			out.Problem = err.Error()
		}
		if list, err := s.listShares(ctx); err == nil {
			for _, sh := range list {
				out.Fonts = append(out.Fonts, OfficeFontsChoice{ID: sh.ID, Name: sh.Name})
			}
		}
	}
	for _, x := range sessions {
		v := OfficeSessionView{Share: x.Share, Path: x.Path, Opened: x.CreatedAt, Saves: x.Saves, State: x.State, Error: x.Error, Editors: []string{}}
		names, _ := rt.svc.ActiveNames(ctx, x)
		v.Editors = append(v.Editors, names...)
		out.Sessions = append(out.Sessions, v)
	}
	rt.mu.Lock()
	out.Listeners = &OfficeListenerState{OfficePort: rt.port(), Office: rt.srv != nil, Internal: rt.iaddr}
	rt.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

func (rt *officeRuntime) port() int {
	if rt.opts.Port != 0 {
		return rt.opts.Port
	}
	return DefaultOfficePort
}

// OfficeSettingsRequest changes Control Panel › Office's settings.
type OfficeSettingsRequest struct {
	MaxFileMB  int     `json:"maxFileMB"`
	FontsShare *string `json:"fontsShare,omitempty"`
}

type officeSettingsParams struct {
	MaxFileMB  int     `json:"maxFileMB"`
	FontsShare *string `json:"fontsShare,omitempty"`
}

func (s *Server) checkFontsShare(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	list, err := s.listShares(ctx)
	if err != nil {
		return err
	}
	for _, sh := range list {
		if sh.ID == id {
			return nil
		}
	}
	return errors.New("there's no shared folder " + id)
}

func (s *Server) handleOfficeSettings(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req OfficeSettingsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	probs := office.Settings{MaxFileMB: req.MaxFileMB}.Valid()
	if req.FontsShare != nil && s.cfg.Priv != nil {
		if err := s.checkFontsShare(r.Context(), *req.FontsShare); err != nil {
			probs = append(probs, err.Error())
		}
	}
	if len(probs) > 0 {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Code: "invalid", Message: probs[0], Details: probs})
		return
	}
	detail := fmt.Sprintf("largest document %d MB", req.MaxFileMB)
	if req.FontsShare != nil {
		detail += ", fonts folder " + strconv.Quote(*req.FontsShare)
	}
	s.submit(w, r, u, JobKindOfficeSettings, "Change office settings", officeSettingsParams(req), "office.settings", detail, nil)
}

// OfficeEnableRequest turns the office suite on.
type OfficeEnableRequest struct {
	// Pool for Docker and apps, when no app is installed yet.
	Pool       string  `json:"pool,omitempty"`
	FontsShare *string `json:"fontsShare,omitempty"`
}

type officeEnableParams struct {
	Pool       string  `json:"pool,omitempty"`
	FontsShare *string `json:"fontsShare,omitempty"`
	Host       string  `json:"host,omitempty"`
}

func (s *Server) handleOfficeEnable(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req OfficeEnableRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.FontsShare != nil && s.cfg.Priv != nil {
		if err := s.checkFontsShare(r.Context(), *req.FontsShare); err != nil {
			writeError(w, http.StatusBadRequest, "invalid", err.Error())
			return
		}
	}
	s.submit(w, r, u, JobKindOfficeEnable, "Turn on the office suite", officeEnableParams{Pool: req.Pool, FontsShare: req.FontsShare, Host: requestHost(r)},
		"office.enable", office.AppID, nil)
}

// OfficeDisableRequest turns the office suite off; Confirm is needed while
// people are editing (their unsaved changes are lost).
type OfficeDisableRequest struct {
	Confirm bool `json:"confirm"`
}

func (s *Server) handleOfficeDisable(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req OfficeDisableRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !req.Confirm {
		if list, _ := s.office.svc.OpenSessions(r.Context()); len(list) > 0 {
			n := 0
			for _, x := range list {
				n += len(x.Active)
			}
			if n > 0 {
				writeError(w, http.StatusConflict, "confirm_required",
					fmt.Sprintf("%d people are editing documents; turning the office suite off now loses what they haven't saved", n))
				return
			}
		}
	}
	s.submit(w, r, u, JobKindOfficeDisable, "Turn off the office suite", struct{}{}, "office.disable", office.AppID, nil)
}

// registerOfficeJobs adds office.enable, office.disable and office.settings
// (one at a time: lock "office").
func (s *Server) registerOfficeJobs(m *jobs.Manager) {
	lock := func(json.RawMessage) string { return "app:" + office.AppID }
	m.Register(jobs.Kind{Name: JobKindOfficeEnable, AdminOnly: true, LockKey: lock, Run: s.runOfficeEnable})
	m.Register(jobs.Kind{Name: JobKindOfficeDisable, AdminOnly: true, LockKey: lock, Run: s.runOfficeDisable})
	m.Register(jobs.Kind{Name: JobKindOfficeSettings, AdminOnly: true, LockKey: lock, Run: s.runOfficeSettings})
}

func fontsChoice(id string) map[string]apps.ShareChoice {
	if id == "" {
		return map[string]apps.ShareChoice{"FONTS": {}}
	}
	return map[string]apps.ShareChoice{"FONTS": {Share: id, Access: "read"}}
}

// runOfficeEnable installs the Document Server app from the catalog (or
// reconfigures it) with HardyOS's secret, starts it and waits until it
// answers.
func (s *Server) runOfficeEnable(jc *jobs.Context) (any, error) {
	var p officeEnableParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	rt := s.office
	pc := s.cfg.Priv
	if pc == nil {
		return nil, errors.New("apps aren't available here")
	}
	st, err := rt.settings.Load(jc)
	if err != nil {
		return nil, err
	}
	if p.FontsShare != nil {
		st.FontsShare = *p.FontsShare
	}
	jc.Progress(2, "Preparing the office secret")
	secret, _, err := rt.settings.EnsureSecret(jc)
	if err != nil {
		return nil, err
	}
	o, err := s.appsStatus(jc)
	if err != nil {
		return nil, err
	}
	settings := map[string]string{"JWT_SECRET": string(secret)}
	var notes []string
	if findApp(o, office.AppID) == nil {
		ref := AppPackageRef{Source: appstore.SourceCatalog, Ref: office.AppID}
		plan, err := s.appPlan(jc, ref)
		if err != nil {
			return nil, fmt.Errorf("the Document Server isn't in this server's catalog: %w", err)
		}
		if plan.EnginePool == "" && p.Pool == "" {
			return nil, errors.New("choose the pool apps go on (no app is installed yet)")
		}
		pkg, err := s.appStore().LoadFrom(jc, appstore.SourceCatalog, office.AppID, 0)
		if err != nil {
			return nil, err
		}
		jc.Progress(5, "Setting up the Document Server")
		ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
		var prep apps.PrepareResult
		err = pc.Call(ctx, priv.OpAppsPrepare, apps.PrepareArgs{
			Package: pkg.Raw, Pool: p.Pool, Host: p.Host, Ports: plan.Ports, Settings: settings,
			Source: apps.SourceCatalog, Shares: fontsChoice(st.FontsShare),
		}, &prep)
		cancel()
		if err != nil {
			return nil, err
		}
		notes = append(notes, prep.Warnings...)
		pulled, err := pullImages(jc, pc, office.AppID, prep.Services, 10, 80)
		notes = append(notes, pulled...)
		if err != nil {
			return nil, err
		}
		_ = s.appStore().SetOrigin(context.WithoutCancel(jc), appstore.Origin{AppID: office.AppID, Source: appstore.SourceCatalog, Ref: office.AppID})
	} else {
		jc.Progress(10, "Giving the Document Server its settings")
		ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
		var prep apps.PrepareResult
		err = pc.Call(ctx, priv.OpAppsReconfigure, apps.ReconfigureArgs{ID: office.AppID, Settings: settings, Shares: fontsChoice(st.FontsShare)}, &prep)
		cancel()
		if err != nil {
			return nil, err
		}
		notes = append(notes, prep.Warnings...)
	}
	jc.Progress(82, "Starting the Document Server")
	if err := appUp(jc, pc, office.AppID); err != nil {
		return nil, err
	}
	st.Enabled = true
	if err := rt.settings.Save(context.WithoutCancel(jc), st); err != nil {
		return nil, err
	}
	rt.forget()
	jc.Progress(85, "Waiting for the Document Server to answer (the first start takes a minute or two)")
	if err := rt.waitHealthy(jc, 8*time.Minute); err != nil {
		return nil, &jobs.FailedWith{Err: err, Result: map[string]any{"enabled": true}}
	}
	jc.Progress(100, "The office suite is on")
	if notes == nil {
		notes = []string{}
	}
	return map[string]any{"enabled": true, "notes": notes}, nil
}

// waitHealthy polls the Document Server's /healthcheck until it says true.
func (rt *officeRuntime) waitHealthy(ctx context.Context, max time.Duration) error {
	deadline := time.Now().Add(max)
	c := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for {
		rt.forget()
		if u, err := rt.internal(); err == nil {
			resp, err := c.Get(u.String() + "/healthcheck")
			if err == nil {
				b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK && strings.TrimSpace(string(b)) == "true" {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			return errors.New("the Document Server didn't answer in time; it may still be starting. Check its logs in the App Store")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (s *Server) runOfficeDisable(jc *jobs.Context) (any, error) {
	rt := s.office
	st, err := rt.settings.Load(jc)
	if err != nil {
		return nil, err
	}
	st.Enabled = false
	if err := rt.settings.Save(jc, st); err != nil {
		return nil, err
	}
	rt.forget()
	if err := rt.svc.CloseAll(jc, "the office suite was turned off"); err != nil {
		s.log.Warn("office: closing sessions", "err", err)
	}
	if s.cfg.Priv != nil {
		if o, err := s.appsStatus(jc); err == nil && findApp(o, office.AppID) != nil {
			jc.Progress(30, "Stopping the Document Server")
			ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
			defer cancel()
			if err := s.cfg.Priv.Call(ctx, priv.OpAppsStop, priv.AppRef{ID: office.AppID}, nil); err != nil {
				return nil, err
			}
		}
	}
	jc.Progress(100, "The office suite is off")
	return map[string]any{"enabled": false}, nil
}

func (s *Server) runOfficeSettings(jc *jobs.Context) (any, error) {
	var p officeSettingsParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	rt := s.office
	st, err := rt.settings.Load(jc)
	if err != nil {
		return nil, err
	}
	st.MaxFileMB = p.MaxFileMB
	fontsChanged := p.FontsShare != nil && *p.FontsShare != st.FontsShare
	if p.FontsShare != nil {
		st.FontsShare = *p.FontsShare
	}
	if probs := st.Valid(); len(probs) > 0 {
		return nil, errors.New(probs[0])
	}
	if err := rt.settings.Save(jc, st); err != nil {
		return nil, err
	}
	if fontsChanged && s.cfg.Priv != nil {
		if o, err := s.appsStatus(jc); err == nil && findApp(o, office.AppID) != nil {
			jc.Progress(30, "Giving the Document Server the fonts folder")
			ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
			var prep apps.PrepareResult
			err := s.cfg.Priv.Call(ctx, priv.OpAppsReconfigure, apps.ReconfigureArgs{ID: office.AppID, Shares: fontsChoice(st.FontsShare)}, &prep)
			cancel()
			if err != nil {
				return nil, err
			}
			if st.Enabled {
				jc.Progress(60, "Restarting the Document Server (it reads the fonts as it starts)")
				if err := appUp(jc, s.cfg.Priv, office.AppID); err != nil {
					return nil, err
				}
			}
		}
	}
	rt.forget()
	jc.Progress(100, "Saved")
	return st, nil
}

// ---- opening documents --------------------------------------------------------------

// OfficeOpenRequest opens a file in the editor.
type OfficeOpenRequest struct {
	Share string `json:"share"`
	Path  string `json:"path"`
	// Mode: "edit" (default; read only when the person can't change it)
	// or "view".
	Mode string `json:"mode,omitempty"`
}

// OfficeOpened is where the editor window goes.
type OfficeOpened struct {
	URL        string `json:"url"`
	Mode       string `json:"mode"`
	Title      string `json:"title"`
	ViewReason string `json:"viewReason,omitempty"`
}

func (s *Server) writeOfficeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, office.ErrNotDocument), errors.Is(err, office.ErrIsFolder):
		writeError(w, http.StatusBadRequest, "not_document", err.Error())
	case errors.Is(err, office.ErrTooBig):
		writeError(w, http.StatusRequestEntityTooLarge, "too_big", err.Error())
	case errors.Is(err, office.ErrNoSecret), errors.Is(err, errOfficeOff):
		writeError(w, http.StatusConflict, "office_off", "the office suite is turned off; an administrator turns it on in Control Panel › Office")
	default:
		var fe *files.Error
		if errors.As(err, &fe) || isErr(err, files.ErrNotFound, files.ErrNoAccess, files.ErrNotAllowed) {
			s.writeFilesError(w, err)
			return
		}
		s.writePrivError(w, err)
	}
}

// officeReady answers itself when documents can't open now.
func (s *Server) officeReady(w http.ResponseWriter, r *http.Request) bool {
	rt := s.office
	if !rt.enabled(r.Context()) {
		writeError(w, http.StatusConflict, "office_off", "the office suite is turned off; an administrator turns it on in Control Panel › Office")
		return false
	}
	if _, err := rt.internal(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "office_unavailable", "the Document Server isn't running: "+err.Error())
		return false
	}
	return true
}

func (s *Server) handleOfficeOpen(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req OfficeOpenRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	if req.Mode != "" && req.Mode != "edit" && req.Mode != "view" {
		writeError(w, http.StatusBadRequest, "invalid", "mode is edit or view")
		return
	}
	p, err := sharelinks.CleanPath(req.Path)
	if err != nil || p == "" {
		writeError(w, http.StatusBadRequest, "invalid", "choose a file")
		return
	}
	if !s.officeReady(w, r) {
		return
	}
	rt := s.office
	origin, ok := rt.originFor(r)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "office_unavailable", "the editor's address isn't listening yet; try again in a few seconds")
		return
	}
	token, _ := s.sessionToken(r)
	name := u.DisplayName
	if name == "" {
		name = displayName(u.Username)
	}
	ed, err := rt.svc.Open(s.officeCtx(r), office.OpenRequest{
		Who: who, Share: req.Share, Path: p, Kind: office.KindUser, UserID: u.ID, Name: name,
		WantEdit: req.Mode != "view", MayEdit: true, Lang: editorLang(r),
	})
	if err != nil {
		s.writeOfficeError(w, err)
		return
	}
	t := rt.addTicket(&officeTicket{ed: ed, title: path.Base(p), sessHash: hashSecret(token), frame: desktopOrigin(r), expires: time.Now().Add(officeTicketLifetime)})
	writeJSON(w, http.StatusOK, OfficeOpened{URL: origin + "/s/-/office/editor?t=" + t, Mode: string(ed.Mode), Title: path.Base(p), ViewReason: ed.ViewReason})
}

func displayName(principal string) string {
	if i := strings.LastIndex(principal, `\`); i >= 0 {
		return principal[i+1:]
	}
	return principal
}

// editorLang is the browser's first language as the editor takes it ("en", "de", ...).
func editorLang(r *http.Request) string {
	al := r.Header.Get("Accept-Language")
	tag, _, _ := strings.Cut(al, ",")
	tag, _, _ = strings.Cut(strings.TrimSpace(tag), ";")
	tag = strings.ToLower(tag)
	if len(tag) >= 2 && tag[0] >= 'a' && tag[0] <= 'z' && tag[1] >= 'a' && tag[1] <= 'z' {
		return tag[:2]
	}
	return "en"
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func desktopOrigin(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

// originFor is the office origin as the browser behind r reaches it.
func (rt *officeRuntime) originFor(r *http.Request) (string, bool) {
	rt.mu.Lock()
	up := rt.srv != nil
	tlsOn := rt.opts.TLS != nil
	rt.mu.Unlock()
	if !up {
		return "", false
	}
	scheme := "https"
	if !tlsOn {
		scheme = "http"
	}
	return scheme + "://" + net.JoinHostPort(hostOnly(r.Host), strconv.Itoa(rt.port())), true
}

func (rt *officeRuntime) addTicket(t *officeTicket) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	tok := hex.EncodeToString(b)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	now := time.Now()
	for k, x := range rt.tickets {
		if now.After(x.expires) {
			delete(rt.tickets, k)
		}
	}
	if len(rt.tickets) > 10000 {
		return tok // refuse to grow without bound; that ticket just won't work
	}
	rt.tickets[hashSecret(tok)] = t
	return tok
}

func (rt *officeRuntime) takeTicket(tok string) *officeTicket {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	k := hashSecret(tok)
	t := rt.tickets[k]
	delete(rt.tickets, k)
	if t == nil || time.Now().After(t.expires) {
		return nil
	}
	return t
}

// serveDesktopEditor is the editor window: a one-minute single-use ticket
// from POST /office/open, accepted only in the browser holding the desktop
// session it was made for.
func (rt *officeRuntime) serveDesktopEditor(w http.ResponseWriter, r *http.Request) {
	t := rt.takeTicket(r.URL.Query().Get("t"))
	if t == nil {
		office.ServeMessage(w, http.StatusGone, "Open the document again", "This editor link was already used or has expired.", "")
		return
	}
	tok, ok := rt.s.sessionToken(r)
	if !ok || hashSecret(tok) != t.sessHash {
		office.ServeMessage(w, http.StatusForbidden, "Open the document again", "Open documents from the HardyOS desktop you're signed in to.", "")
		return
	}
	if _, err := rt.s.peekSession(r.Context(), tok); err != nil {
		office.ServeMessage(w, http.StatusForbidden, "Sign in again", "Your desktop session has ended.", "")
		return
	}
	rt.gate.Set(w, r)
	office.ServeEditor(w, t.ed, t.title, t.ed.ViewReason, t.frame)
}

// ---- share links ------------------------------------------------------------------------

// officeLinks plugs the editor into share link pages.
type officeLinks struct{ rt *officeRuntime }

func (o officeLinks) Opens(name string) bool {
	if _, ok := office.FormatOf(name); !ok {
		return false
	}
	return o.rt.enabled(context.Background())
}

func (o officeLinks) Serve(w http.ResponseWriter, r *http.Request, l *sharelinks.Link, owner files.Who, target string, e *files.Entry, visitor string) {
	rt := o.rt
	onOffice, _ := r.Context().Value(officeOriginKey{}).(bool)
	if !onOffice && !rt.s.onFilesHost(r) {
		// On the desktop's own address: the editor runs on the office origin.
		origin, ok := rt.originFor(r)
		if !ok {
			office.ServeMessage(w, http.StatusServiceUnavailable, "The editor isn't available", "The office suite isn't running right now. Download the file instead.", "")
			return
		}
		http.Redirect(w, r, origin+r.URL.RequestURI(), http.StatusSeeOther)
		return
	}
	if _, err := rt.internal(); err != nil {
		office.ServeMessage(w, http.StatusServiceUnavailable, "The editor isn't available", "The office suite isn't running right now. Download the file instead.", "")
		return
	}
	edit := l.Access == sharelinks.AccessEdit
	ed, err := rt.svc.Open(rt.s.officeCtx(r), office.OpenRequest{
		Who: owner, Share: l.Share, Path: target, Kind: office.KindLink, LinkID: l.ID,
		Name: office.CleanName(visitor, "Guest") + " (guest)", WantEdit: edit, MayEdit: edit, Lang: editorLang(r),
	})
	if err != nil {
		msg := "This document can't be opened in the browser right now."
		if errors.Is(err, office.ErrTooBig) {
			msg = "This document is too big for the browser editor. Download it instead."
		}
		office.ServeMessage(w, http.StatusConflict, "Can't open the document", msg, "")
		return
	}
	rt.gate.Set(w, r)
	office.ServeEditor(w, ed, e.Name, ed.ViewReason, "")
}

// ---- new documents --------------------------------------------------------------------

// OfficeNewRequest makes an empty document.
type OfficeNewRequest struct {
	Share string `json:"share"`
	// Dir is the folder it goes in.
	Dir string `json:"dir"`
	// Kind: document, spreadsheet or presentation.
	Kind string `json:"kind"`
	// Name of the file; the extension is added when missing.
	Name string `json:"name"`
}

func (s *Server) handleOfficeNew(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req OfficeNewRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	who, ok := s.filesWho(w, u)
	if !ok {
		return
	}
	ext, ok := office.NewKinds[req.Kind]
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid", "kind is document, spreadsheet or presentation")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = map[string]string{"docx": "New document", "xlsx": "New spreadsheet", "pptx": "New presentation"}[ext]
	}
	if !strings.EqualFold(path.Ext(name), "."+ext) {
		name += "." + ext
	}
	if err := fileworker.CleanName(name); err != nil || sharelinks.Hidden(name) {
		writeError(w, http.StatusBadRequest, "invalid", "give the file a valid name")
		return
	}
	dir, err := sharelinks.CleanPath(req.Dir)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", "that folder isn't allowed")
		return
	}
	body, err := office.Blank(req.Kind)
	if err != nil {
		internalError(s, w, err)
		return
	}
	fs := s.files()
	ctx := r.Context()
	target := sharelinks.Join(dir, name)
	f, err := fs.Create(ctx, who, req.Share, target, false)
	if err != nil {
		s.writeFilesError(w, err)
		return
	}
	_, werr := f.Write(body)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_, _ = fs.DeleteItem(context.WithoutCancel(ctx), who, req.Share, target, true)
		s.writeFilesError(w, werr)
		return
	}
	s.record(r, u, "files.create", req.Share+":/"+target, audit.Success, "new "+req.Kind)
	e, err := fs.Stat(ctx, who, req.Share, target)
	if err != nil {
		s.writeFilesError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, e)
}

// ---- listeners ----------------------------------------------------------------------------

// RunOffice runs the office origin and the internal listener while the
// office suite is on (checked every 15 s and after every office job).
func (s *Server) RunOffice(ctx context.Context, opts OfficeOptions) {
	rt := s.office
	if rt == nil {
		return
	}
	if opts.Port == 0 {
		opts.Port = DefaultOfficePort
	}
	if opts.Interval == 0 {
		opts.Interval = 15 * time.Second
	}
	rt.mu.Lock()
	rt.opts, rt.running = opts, true
	rt.mu.Unlock()
	defer rt.stopAll()
	t := time.NewTicker(opts.Interval)
	defer t.Stop()
	for {
		rt.reconcile(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-rt.kick:
		}
	}
}

func (rt *officeRuntime) reconcile(ctx context.Context) {
	on := rt.enabled(ctx)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if !on {
		rt.stopLocked()
		return
	}
	if rt.srv == nil {
		addr := net.JoinHostPort(rt.opts.ListenHost, strconv.Itoa(rt.opts.Port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			rt.s.log.Warn("office: can't listen", "addr", addr, "err", err)
		} else {
			srv := &http.Server{Handler: rt.handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
			if rt.opts.TLS != nil {
				ln = tls.NewListener(ln, rt.opts.TLS)
			}
			rt.srv = srv
			go func() { _ = srv.Serve(ln) }()
			rt.s.log.Info("office: listening", "addr", addr)
		}
	}
	if rt.isrv == nil {
		addr := rt.opts.InternalListen
		if addr == "" {
			gw, ok := office.HostGateway()
			if !ok {
				return // Docker isn't up yet
			}
			addr = netip.AddrPortFrom(gw, office.InternalPort).String()
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			rt.s.log.Warn("office: can't listen for the Document Server", "addr", addr, "err", err)
			return
		}
		srv := &http.Server{Handler: rt.svc.InternalHandler(office.DockerPeers()), ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout: 2 * time.Minute, IdleTimeout: 60 * time.Second}
		rt.isrv, rt.iaddr = srv, addr
		go func() { _ = srv.Serve(ln) }()
		rt.s.log.Info("office: listening for the Document Server", "addr", addr)
	}
}

func (rt *officeRuntime) stopLocked() {
	if rt.srv != nil {
		_ = rt.srv.Close()
		rt.srv = nil
	}
	if rt.isrv != nil {
		_ = rt.isrv.Close()
		rt.isrv, rt.iaddr = nil, ""
	}
}

func (rt *officeRuntime) stopAll() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.stopLocked()
	rt.running = false
}
