package api

// Remote access (docs/remote-access.md): the NetBird client on this server
// (join, status, leave) and publishing the desktop and apps through
// NetBird's reverse proxy (internal/publish). Every change runs as a job
// and is audited; the setup key and the access token travel from the
// request to the job through the in-memory secret box, never in job
// parameters, results, logs or API answers.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/netbird"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/publish"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Remote access job kinds.
const (
	JobKindRemoteJoin     = "remote.join"
	JobKindRemoteLeave    = "remote.leave"
	JobKindRemoteSettings = "remote.settings"
	JobKindRemoteService  = "remote.service"
	JobKindRemoteSync     = "remote.sync"
	JobKindRemoteDomain   = "remote.domain"
	JobKindRemoteRotate   = "remote.gateway.rotate"
)

// remoteInputs asks the root helper for this server's NetBird state and
// installed apps with a web page.
func remoteInputs(ctx context.Context, pc *priv.Client, db *store.DB) (publish.Inputs, *netbird.ClientStatus, []apps.App) {
	var in publish.Inputs
	in.ShareLinks = activeShareLinks(ctx, db)
	in.MailHost = mailPublishHost(ctx, db)
	st := &netbird.ClientStatus{State: "unknown"}
	if pc == nil {
		return in, st, nil
	}
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := pc.Call(sctx, priv.OpNetBirdStatus, nil, st); err != nil {
		st = &netbird.ClientStatus{State: "unknown", Problem: "Couldn't ask the root helper: " + err.Error()}
	}
	in.ManagementURL = st.ManagementURL
	if st.Connected {
		in.NetBirdIP = st.IP
	}
	var o apps.Overview
	var list []apps.App
	if err := pc.Call(sctx, priv.OpAppsStatus, nil, &o); err == nil {
		in.Known = true
		for _, a := range o.Apps {
			if a.Web != nil {
				in.Apps = append(in.Apps, publish.App{ID: a.ID, Name: a.Name})
				list = append(list, a)
			}
		}
	}
	return in, st, list
}

// activeShareLinks reports whether any share link can still be opened
// (files.<base> is published for them).
func activeShareLinks(ctx context.Context, db *store.DB) bool {
	if db == nil {
		return false
	}
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM share_links WHERE revoked = 0 AND expires_at > ?
		AND (max_downloads = 0 OR download_count < max_downloads)`, store.Now()).Scan(&n)
	return err == nil && n > 0
}

type remoteJoinParams struct {
	ManagementURL string `json:"managementUrl"`
	Hostname      string `json:"hostname"`
	SetupKeyRef   string `json:"setupKeyRef"`
}

type remoteLeaveParams struct {
	Confirm string `json:"confirm"`
}

// remoteSettingsParams: the settings request without the token, which
// waits in jobSecrets (TokenRef; TokenChange says the request set or
// cleared it).
type remoteSettingsParams struct {
	publish.Settings
	TokenChange bool   `json:"tokenChange"`
	TokenRef    string `json:"tokenRef,omitempty"`
}

type remoteServiceParams struct {
	Key           string   `json:"key"`
	Mode          string   `json:"mode"`
	Auth          string   `json:"auth"`
	Groups        []string `json:"groups"`
	HardyOSSignIn bool     `json:"hardyosSignIn"`
	SecretChange  bool     `json:"secretChange"`
	SecretRef     string   `json:"secretRef,omitempty"`
}

type remoteDomainParams struct {
	Action  string `json:"action"`
	Cluster string `json:"cluster,omitempty"`
}

func dbOf(pub *publish.Publisher) *store.DB {
	if pub == nil || pub.Store == nil {
		return nil
	}
	return pub.Store.DB
}

var errSecretLost = errors.New("the secret was lost (HardyOS restarted); try again")

// RegisterRemoteJobs adds the remote access job kinds. pub may be nil
// (publishing unavailable).
func RegisterRemoteJobs(m *jobs.Manager, pc *priv.Client, pub *publish.Publisher) {
	lock := func(json.RawMessage) string { return "remote" }
	sync := func(jc *jobs.Context) (*publish.Result, error) {
		if pub == nil {
			return nil, errors.New("publishing isn't available")
		}
		jc.Progress(50, "Updating NetBird's services")
		in, _, _ := remoteInputs(jc, pc, dbOf(pub))
		ctx, cancel := context.WithTimeout(jc, 3*time.Minute)
		defer cancel()
		return pub.Sync(ctx, in)
	}
	m.Register(jobs.Kind{Name: JobKindRemoteJoin, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p remoteJoinParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		key, ok := jobSecrets.take(p.SetupKeyRef)
		if !ok {
			return nil, errSecretLost
		}
		jc.Progress(20, "Joining "+p.ManagementURL)
		ctx, cancel := context.WithTimeout(jc, 4*time.Minute)
		defer cancel()
		var st netbird.ClientStatus
		if err := pc.Call(ctx, priv.OpNetBirdJoin, netbird.JoinArgs{ManagementURL: p.ManagementURL, SetupKey: key, Hostname: p.Hostname}, &st); err != nil {
			return nil, err
		}
		return st, nil
	}})
	m.Register(jobs.Kind{Name: JobKindRemoteLeave, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p remoteLeaveParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		var notes []string
		if pub != nil {
			jc.Progress(20, "Removing HardyOS's services from NetBird")
			in, _, _ := remoteInputs(jc, pc, dbOf(pub))
			if s, _ := pub.Store.Load(jc); s.Instance != "" && pub.Store.HasToken(jc) {
				if n, err := pub.RemoveAll(jc, in); err != nil {
					notes = append(notes, "couldn't remove HardyOS's services from NetBird ("+err.Error()+"): remove the services named "+publish.ServicePrefix(s)+"… in NetBird's dashboard")
				} else if n > 0 {
					notes = append(notes, "removed "+strconv.Itoa(n)+" services from NetBird")
				}
				s.Enabled = false
				_, _ = pub.SaveSettings(jc, s)
			}
			// Whatever NetBird (or anyone who read its services) still holds
			// stops opening the gateway.
			if err := pub.Store.RotateGatewaySecret(jc); err != nil {
				notes = append(notes, "couldn't replace the gateway secret: "+err.Error())
			}
		}
		jc.Progress(60, "Leaving the NetBird network")
		ctx, cancel := context.WithTimeout(jc, 2*time.Minute)
		defer cancel()
		var res netbird.LeaveResult
		if err := pc.Call(ctx, priv.OpNetBirdLeave, netbird.LeaveArgs{Confirm: p.Confirm}, &res); err != nil {
			return nil, err
		}
		if res.Notes != "" {
			notes = append(notes, res.Notes)
		}
		res.Notes = strings.Join(notes, "; ")
		return res, nil
	}})
	m.Register(jobs.Kind{Name: JobKindRemoteSettings, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		if pub == nil {
			return nil, errors.New("publishing isn't available")
		}
		var p remoteSettingsParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		if p.TokenChange {
			tok := ""
			if p.TokenRef != "" {
				var ok bool
				if tok, ok = jobSecrets.take(p.TokenRef); !ok {
					return nil, errSecretLost
				}
			}
			if err := pub.Store.SetToken(jc, tok); err != nil {
				return nil, err
			}
		}
		before, _ := pub.Store.Load(jc)
		if _, err := pub.SaveSettings(jc, p.Settings); err != nil {
			return nil, err
		}
		res, err := sync(jc)
		if err == nil && before.Enabled && !p.Settings.Enabled {
			// Publishing turned off: the services are gone, and so is the
			// secret they carried.
			if rerr := pub.Store.RotateGatewaySecret(jc); rerr != nil {
				return nil, rerr
			}
		}
		return res, err
	}})
	m.Register(jobs.Kind{Name: JobKindRemoteRotate, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		if pub == nil {
			return nil, errors.New("publishing isn't available")
		}
		jc.Progress(20, "Making a new gateway secret")
		if err := pub.Store.RotateGatewaySecret(jc); err != nil {
			return nil, err
		}
		return sync(jc)
	}})
	m.Register(jobs.Kind{Name: JobKindRemoteService, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		if pub == nil {
			return nil, errors.New("publishing isn't available")
		}
		var p remoteServiceParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		var secret *string
		if p.SecretChange {
			v := ""
			if p.SecretRef != "" {
				var ok bool
				if v, ok = jobSecrets.take(p.SecretRef); !ok {
					return nil, errSecretLost
				}
			}
			secret = &v
		}
		c := publish.ServiceConfig{Mode: p.Mode, Auth: p.Auth, Groups: p.Groups, HardyOSSignIn: p.HardyOSSignIn}
		if err := pub.Store.SetConfig(jc, p.Key, c, secret); err != nil {
			return nil, err
		}
		return sync(jc)
	}})
	m.Register(jobs.Kind{Name: JobKindRemoteSync, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		return sync(jc)
	}})
	m.Register(jobs.Kind{Name: JobKindRemoteDomain, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		if pub == nil {
			return nil, errors.New("publishing isn't available")
		}
		var p remoteDomainParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		in, _, _ := remoteInputs(jc, pc, dbOf(pub))
		ctx, cancel := context.WithTimeout(jc, time.Minute)
		defer cancel()
		var err error
		if p.Action == "add" {
			err = pub.AddDomain(ctx, in, p.Cluster)
		} else {
			err = pub.VerifyDomain(ctx, in)
		}
		if err != nil {
			return nil, err
		}
		return map[string]string{"done": p.Action}, nil
	}})
}

func (s *Server) remoteRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/remote", s.admin(s.handleRemote))
	m.Handle("POST /api/v1/remote/join", s.admin(s.handleRemoteJoin))
	m.Handle("POST /api/v1/remote/leave", s.admin(s.handleRemoteLeave))
	m.Handle("PUT /api/v1/remote/publishing", s.admin(s.handleRemotePublishing))
	m.Handle("GET /api/v1/remote/check", s.admin(s.handleRemoteCheck))
	m.Handle("POST /api/v1/remote/domain", s.admin(s.handleRemoteDomain))
	m.Handle("POST /api/v1/remote/sync", s.admin(s.handleRemoteSync))
	m.Handle("POST /api/v1/remote/gateway/rotate", s.admin(s.handleRemoteRotate))
	m.Handle("PUT /api/v1/remote/desktop", s.admin(s.handleRemoteService))
	m.Handle("GET /api/v1/apps/{id}/publish", s.admin(s.handleAppPublish))
	m.Handle("PUT /api/v1/apps/{id}/publish", s.admin(s.handleRemoteService))
}

// RemoteSettingsView is the publishing settings as the API shows them:
// the token only as whether one is saved.
type RemoteSettingsView struct {
	publish.Settings
	HasToken bool `json:"hasToken"`
	// TokenUnreadable: a token is saved but can't be opened on this server
	// (a settings restore from another server).
	TokenUnreadable bool `json:"tokenUnreadable"`
}

// RemoteStatus is Control Panel › Remote Access.
type RemoteStatus struct {
	Available bool                  `json:"available"`
	Client    *netbird.ClientStatus `json:"client"`
	// DefaultManagementURL fills the join form.
	DefaultManagementURL string              `json:"defaultManagementUrl"`
	Settings             *RemoteSettingsView `json:"settings,omitempty"`
	Items                []publish.Item      `json:"items"`
	LastSync             *RemoteSyncInfo     `json:"lastSync,omitempty"`
	Gateway              RemoteGatewayInfo   `json:"gateway"`
}

// RemoteSyncInfo is the last sync's outcome.
type RemoteSyncInfo struct {
	At      time.Time `json:"at"`
	Problem string    `json:"problem,omitempty"`
	Created int       `json:"created"`
	Updated int       `json:"updated"`
	Deleted int       `json:"deleted"`
}

// RemoteGatewayInfo says where the app gateway listens.
type RemoteGatewayInfo struct {
	Listening bool   `json:"listening"`
	Address   string `json:"address,omitempty"`
	Problem   string `json:"problem,omitempty"`
}

func (s *Server) handleRemote(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	in, st, _ := remoteInputs(r.Context(), s.cfg.Priv, s.cfg.DB)
	out := RemoteStatus{Client: st, DefaultManagementURL: netbird.DefaultManagementURL, Items: []publish.Item{}}
	pub := s.cfg.Remote
	out.Available = pub != nil
	if pub != nil {
		set, err := pub.Store.Load(r.Context())
		if err != nil {
			internalError(s, w, err)
			return
		}
		view := &RemoteSettingsView{Settings: set, HasToken: pub.Store.HasToken(r.Context())}
		if view.HasToken {
			if _, err := pub.Store.Token(r.Context()); err != nil {
				view.TokenUnreadable = true
			}
		}
		out.Settings = view
		if items, err := pub.Items(r.Context(), in); err == nil {
			out.Items = items
		}
		out.LastSync, out.Gateway = s.remote.info()
	}
	writeJSON(w, http.StatusOK, out)
}

// RemoteJoinRequest joins this server to a NetBird network.
type RemoteJoinRequest struct {
	ManagementURL string `json:"managementUrl"`
	SetupKey      string `json:"setupKey"`
	Hostname      string `json:"hostname"`
}

func (s *Server) handleRemoteJoin(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req RemoteJoinRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	mgmt, err := netbird.ValidManagementURL(req.ManagementURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	host := strings.ToLower(strings.TrimSpace(req.Hostname))
	if host == "" {
		host = "nas"
	}
	if !netbird.ValidDNSLabel(host) {
		writeError(w, http.StatusBadRequest, "invalid", "the server's name in NetBird is letters, digits and dashes (like nas)")
		return
	}
	key := strings.TrimSpace(req.SetupKey)
	if !netbird.ValidSetupKey(key) {
		writeError(w, http.StatusBadRequest, "invalid", "that doesn't look like a NetBird setup key (Setup Keys in NetBird's dashboard)")
		return
	}
	s.submit(w, r, u, JobKindRemoteJoin, "Join the NetBird network at "+hostOnly(strings.TrimPrefix(mgmt, "https://")),
		remoteJoinParams{ManagementURL: mgmt, Hostname: host, SetupKeyRef: jobSecrets.put(key)}, "remote.join", mgmt+" as "+host, nil)
}

// RemoteLeaveRequest leaves the NetBird network.
type RemoteLeaveRequest struct {
	Confirm string `json:"confirm"`
}

func (s *Server) handleRemoteLeave(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req RemoteLeaveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var set netbird.Settings
	if err := s.cfg.Priv.Call(r.Context(), priv.OpNetBirdSettings, nil, &set); err != nil {
		s.writePrivError(w, err)
		return
	}
	if set.ManagementURL == "" {
		writeError(w, http.StatusConflict, "refused", "this server isn't in a NetBird network")
		return
	}
	mu, _ := url.Parse(set.ManagementURL)
	if mu == nil || !strings.EqualFold(strings.TrimSpace(req.Confirm), mu.Hostname()) {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the NetBird server's name ("+hostOnly(strings.TrimPrefix(set.ManagementURL, "https://"))+") to confirm")
		return
	}
	s.submit(w, r, u, JobKindRemoteLeave, "Leave the NetBird network", remoteLeaveParams{Confirm: strings.TrimSpace(req.Confirm)},
		"remote.leave", set.ManagementURL, nil)
}

// RemotePublishingRequest changes the publishing settings. Token: absent
// keeps the saved one, "" forgets it, anything else replaces it.
type RemotePublishingRequest struct {
	Enabled     bool   `json:"enabled"`
	BaseDomain  string `json:"baseDomain"`
	APIURL      string `json:"apiUrl"`
	Cluster     string `json:"cluster"`
	DesktopName string `json:"desktopName"`
	DefaultMode string `json:"defaultMode"`
	// PublicShareLinks keeps files.<base> published with no active link.
	PublicShareLinks bool    `json:"publicShareLinks"`
	Token            *string `json:"token,omitempty"`
}

func (s *Server) remoteAvailable(w http.ResponseWriter) (*publish.Publisher, bool) {
	if s.cfg.Remote == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "publishing apps isn't available on this server")
		return nil, false
	}
	return s.cfg.Remote, true
}

func (s *Server) handleRemotePublishing(w http.ResponseWriter, r *http.Request, u *auth.User) {
	pub, ok := s.remoteAvailable(w)
	if !ok {
		return
	}
	var req RemotePublishingRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	cur, err := pub.Store.Load(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	set := publish.Settings{Enabled: req.Enabled, BaseDomain: strings.ToLower(strings.TrimSpace(req.BaseDomain)), APIURL: strings.TrimSpace(req.APIURL),
		Cluster: strings.ToLower(strings.TrimSpace(req.Cluster)), DesktopName: strings.ToLower(strings.TrimSpace(req.DesktopName)),
		DefaultMode: req.DefaultMode, PublicShareLinks: req.PublicShareLinks, Instance: cur.Instance}
	set.Defaults()
	if err := set.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	p := remoteSettingsParams{Settings: set}
	detail := "enabled=" + boolWord(set.Enabled) + " base=" + set.BaseDomain + " desktop=" + set.DesktopName + " default=" + set.DefaultMode +
		" publicShareLinks=" + boolWord(set.PublicShareLinks)
	if req.Token != nil {
		tok := strings.TrimSpace(*req.Token)
		if len(tok) > 512 || strings.ContainsAny(tok, " \r\n\t") {
			writeError(w, http.StatusBadRequest, "invalid", "that doesn't look like a NetBird access token")
			return
		}
		p.TokenChange = true
		if tok != "" {
			p.TokenRef = jobSecrets.put(tok)
			detail += " token=new"
		} else {
			detail += " token=removed"
		}
	} else if set.Enabled && !pub.Store.HasToken(r.Context()) {
		writeError(w, http.StatusBadRequest, "invalid", "paste a NetBird access token to publish apps")
		return
	} else if pub.Store.HasToken(r.Context()) && apiAddress(set.APIURL) != apiAddress(cur.APIURL) {
		// The saved token must never be sent to an address it wasn't pasted
		// for.
		writeError(w, http.StatusBadRequest, "token_required", "paste the NetBird access token again when changing NetBird's API address")
		return
	}
	s.submit(w, r, u, JobKindRemoteSettings, "Save the publishing settings", p, "remote.publishing", detail, nil)
}

// apiAddress is a NetBird API address as compared for "did it change"
// ("" is the joined management server).
func apiAddress(s string) string {
	if n, err := netbird.NormalizeBaseURL(s); err == nil {
		return strings.ToLower(n)
	}
	return strings.ToLower(strings.TrimSpace(s))
}

func boolWord(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func (s *Server) handleRemoteCheck(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	pub, ok := s.remoteAvailable(w)
	if !ok {
		return
	}
	in, _, _ := remoteInputs(r.Context(), s.cfg.Priv, s.cfg.DB)
	res := s.cfg.Resolver
	if res == nil {
		res = publish.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	c, err := pub.Check(ctx, in, res, s.cfg.SSOIssuer)
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// RemoteDomainRequest adds the base domain to NetBird or verifies it.
type RemoteDomainRequest struct {
	Action  string `json:"action"`
	Cluster string `json:"cluster,omitempty"`
}

func (s *Server) handleRemoteDomain(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if _, ok := s.remoteAvailable(w); !ok {
		return
	}
	var req RemoteDomainRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Action != "add" && req.Action != "verify" {
		writeError(w, http.StatusBadRequest, "invalid", "action is add or verify")
		return
	}
	title := map[string]string{"add": "Add the base domain to NetBird", "verify": "Verify the base domain in NetBird"}[req.Action]
	s.submit(w, r, u, JobKindRemoteDomain, title, remoteDomainParams{Action: req.Action, Cluster: strings.ToLower(strings.TrimSpace(req.Cluster))},
		"remote.domain."+req.Action, req.Cluster, nil)
}

func (s *Server) handleRemoteSync(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if _, ok := s.remoteAvailable(w); !ok {
		return
	}
	s.submit(w, r, u, JobKindRemoteSync, "Update NetBird's services", struct{}{}, "remote.sync", "", nil)
}

// handleRemoteRotate makes a new gateway secret and puts the new values in
// every service (for when a NetBird administrator, or anyone who could read
// the services, shouldn't hold the old ones).
func (s *Server) handleRemoteRotate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if _, ok := s.remoteAvailable(w); !ok {
		return
	}
	s.submit(w, r, u, JobKindRemoteRotate, "Replace the gateway secret", struct{}{}, "remote.gateway.rotate", "every service's gateway value replaced", nil)
}

// PublishRequest is how the desktop or an app is published. Secret (a
// password or PIN): absent keeps the saved one.
type PublishRequest struct {
	Mode          string   `json:"mode"`
	Auth          string   `json:"auth"`
	Groups        []string `json:"groups"`
	HardyOSSignIn bool     `json:"hardyosSignIn"`
	Secret        *string  `json:"secret,omitempty"`
	// ConfirmPublic must be true to publish the desktop publicly: it has
	// administration in it.
	ConfirmPublic bool `json:"confirmPublic,omitempty"`
	// ConfirmOpen must be true to publish an app publicly with nothing in
	// front and HardyOS sign-in off: anyone on the internet reaches the
	// app's own page.
	ConfirmOpen bool `json:"confirmOpen,omitempty"`
}

func (s *Server) handleRemoteService(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if _, ok := s.remoteAvailable(w); !ok {
		return
	}
	key, what := publish.DesktopKey, "the desktop"
	if id := r.PathValue("id"); id != "" {
		a, ok := s.installedApp(w, r)
		if !ok {
			return
		}
		if a.Web == nil {
			writeError(w, http.StatusBadRequest, "invalid", a.Name+" has no web page to publish")
			return
		}
		key, what = publish.AppKey(a.ID), a.Name
	}
	var req PublishRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if key == publish.DesktopKey && req.Mode == "" {
		req.Mode = publish.ModeNetBird
	}
	if key == publish.DesktopKey && req.Mode == publish.ModePublic && !req.ConfirmPublic {
		writeError(w, http.StatusBadRequest, "confirm_required",
			"the desktop includes administration: confirm (confirmPublic) to put it on the internet")
		return
	}
	if err := publish.ValidateConfig(publish.ServiceConfig{Mode: req.Mode, Auth: req.Auth, Groups: req.Groups}, req.Secret); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if key != publish.DesktopKey && req.Auth == publish.AuthNone && !req.HardyOSSignIn && !req.ConfirmOpen {
		mode := req.Mode
		if mode == "" {
			if set, err := s.cfg.Remote.Store.Load(r.Context()); err == nil {
				mode = set.DefaultMode
			}
		}
		if mode == publish.ModePublic {
			writeError(w, http.StatusBadRequest, "confirm_required",
				what+" would be on the internet with no sign-in in front and HardyOS sign-in off: confirm (confirmOpen) that its own sign-in is enough")
			return
		}
	}
	p := remoteServiceParams{Key: key, Mode: req.Mode, Auth: req.Auth, Groups: nonNilStrings(req.Groups), HardyOSSignIn: req.HardyOSSignIn}
	if req.Secret != nil {
		p.SecretChange = true
		if *req.Secret != "" {
			p.SecretRef = jobSecrets.put(*req.Secret)
		}
	}
	mode := req.Mode
	if mode == "" {
		mode = "default"
	}
	detail := key + " mode=" + mode + " auth=" + req.Auth
	if key != publish.DesktopKey && !req.HardyOSSignIn {
		detail += " hardyosSignIn=off"
	}
	if req.ConfirmOpen {
		detail += " confirmedOpen"
	}
	s.submit(w, r, u, JobKindRemoteService, "Publish "+what, p, "remote.publish", detail, nil)
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *Server) handleAppPublish(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	pub, ok := s.remoteAvailable(w)
	if !ok {
		return
	}
	a, ok := s.installedApp(w, r)
	if !ok {
		return
	}
	if a.Web == nil {
		writeError(w, http.StatusBadRequest, "invalid", a.Name+" has no web page to publish")
		return
	}
	items, err := pub.Items(r.Context(), publish.Inputs{Apps: []publish.App{{ID: a.ID, Name: a.Name}}})
	if err != nil {
		internalError(s, w, err)
		return
	}
	set, _ := pub.Store.Load(r.Context())
	out := AppPublishView{Enabled: set.Enabled && set.BaseDomain != "", BaseDomain: set.BaseDomain, DefaultMode: set.DefaultMode}
	for _, it := range items {
		if it.Key == publish.AppKey(a.ID) {
			out.Item = it
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// AppPublishView is an app's publishing on its App Store page.
type AppPublishView struct {
	// Enabled: publishing is set up (Control Panel › Remote Access).
	Enabled     bool   `json:"enabled"`
	BaseDomain  string `json:"baseDomain"`
	DefaultMode string `json:"defaultMode"`
	publish.Item
}

// recordSystem writes an audit entry for something hardyd did by itself.
func (s *Server) recordSystem(ctx context.Context, action, target, detail string) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Record(ctx, audit.Entry{Action: action, Target: target, Outcome: audit.Success, Detail: detail, Actor: "hardyos"}); err != nil {
		s.log.Error("audit write failed", "action", action, "err", err)
	}
}
