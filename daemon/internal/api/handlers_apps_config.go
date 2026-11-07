package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// AppPrincipals says who a signed-in person is for app access: their name
// as access lists write it and the groups they're in. The default treats
// every account as a HardyOS user without groups; domain sign-in plugs in
// here (Config.AppPrincipals) to give domain accounts their NETBIOS\name
// and groups from the session.
type AppPrincipals interface {
	Who(ctx context.Context, sessionToken string, u *auth.User) appstore.Who
}

// appIdentity is who a signed-in person is for app access: matched by
// their principal ("alice" or "HOME\alice") and domain groups.
type appIdentity = auth.Identity

var _ appIdentity = (*auth.User)(nil)

// localPrincipals is the default AppPrincipals.
type localPrincipals struct{}

func (localPrincipals) Who(_ context.Context, _ string, u *auth.User) appstore.Who {
	return whoOf(u)
}

func whoOf(u any) appstore.Who {
	if id, ok := u.(appIdentity); ok && id.IdentityPrincipal() != "" {
		return appstore.Who{Username: id.IdentityPrincipal(), Groups: id.IdentityGroups(), Admin: id.IsAdmin()}
	}
	if au, ok := u.(*auth.User); ok {
		return appstore.Who{Username: au.Username, Admin: au.IsAdmin()}
	}
	return appstore.Who{}
}

func (s *Server) appWho(ctx context.Context, token string, u *auth.User) appstore.Who {
	p := s.cfg.AppPrincipals
	if p == nil {
		p = localPrincipals{}
	}
	who := p.Who(ctx, token, u)
	who.Admin = u.IsAdmin() // an administrator's role always comes from the account
	return who
}

// sessionToken is the desktop session's token from the request's cookie
// (only for requests the desktop's session check already let through).
func sessionToken(r *http.Request) string { return anySessionCookie(r) }

// anySessionCookie is the desktop session cookie under either name (the
// app gateway removes the old name from what it hands hardyd, and the app
// window proxy ports are only on the desktop's own address).
func anySessionCookie(r *http.Request) string {
	for _, n := range []string{SessionCookie, LegacySessionCookie} {
		if c, err := r.Cookie(n); err == nil {
			return c.Value
		}
	}
	return ""
}

// mayUse checks the access list for an app.
func (s *Server) mayUse(ctx context.Context, token string, u *auth.User, appID string) (bool, error) {
	if u.IsAdmin() {
		return true, nil
	}
	list, err := s.appStore().Access(ctx, appID)
	if err != nil {
		return false, err
	}
	return appstore.MayUse(list, s.appWho(ctx, token, u)), nil
}

// appConfig asks the root helper for an installed app's configuration.
func (s *Server) appConfig(ctx context.Context, id string) (*apps.AppConfig, error) {
	var c apps.AppConfig
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := s.cfg.Priv.Call(ctx, priv.OpAppsConfig, priv.AppRef{ID: id}, &c); err != nil {
		return nil, err
	}
	if c.Source == "" {
		c.Source = apps.SourceUpload // root decides "catalog"; an unknown source is never trusted
	}
	if c.Settings == nil {
		c.Settings = []apps.SettingValue{}
	}
	if c.Shares == nil {
		c.Shares = []apps.AppShare{}
	}
	if c.Grants == nil {
		c.Grants = []string{}
	}
	if c.Ports == nil {
		c.Ports = map[string]int{}
	}
	return &c, nil
}

// AppConfigView is an installed app's settings screen: its configuration
// and the manifest's choices in the App Store's words.
type AppConfigView struct {
	apps.AppConfig
	Package appstore.Entry `json:"package"`
}

func (s *Server) handleAppConfig(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	a, ok := s.installedApp(w, r)
	if !ok {
		return
	}
	c, err := s.appConfig(r.Context(), a.ID)
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, configView(c, a))
}

func configView(c *apps.AppConfig, a *apps.App) AppConfigView {
	pkg := &apps.Package{Manifest: c.Manifest}
	e := appstore.EntryOf(string(c.Source), "", pkg)
	e.Icon, e.SourceName = a.Icon, c.SourceName
	return AppConfigView{AppConfig: *c, Package: e}
}

// AppConfigUpdate changes an installed app. Omitted fields keep their
// values; a password setting left empty keeps its value.
type AppConfigUpdate struct {
	Ports    map[string]int              `json:"ports,omitempty"`
	Settings map[string]string           `json:"settings,omitempty"`
	Shares   map[string]apps.ShareChoice `json:"shares,omitempty"`
	Grants   *[]string                   `json:"grants,omitempty"`
	Limits   *apps.Limits                `json:"limits,omitempty"`
}

func (s *Server) handleAppReconfigure(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req AppConfigUpdate
	if !decodeJSON(w, r, &req) {
		return
	}
	a, ok := s.installedApp(w, r)
	if !ok {
		return
	}
	cur, err := s.appConfig(r.Context(), a.ID)
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	mf := cur.Manifest
	var p apps.Problems
	checkPorts(&p, mf, req.Ports)
	plain, secret := splitSettings(&p, mf, req.Settings)
	for k, v := range secret {
		if v == "" {
			delete(secret, k) // empty keeps the current password
		}
	}
	checkShares(&p, mf, req.Shares, false)
	if req.Grants != nil {
		checkGrants(&p, mf, cur.Source, *req.Grants)
	}
	checkLimits(&p, req.Limits)
	if len(p) > 0 {
		s.writeAppError(w, p)
		return
	}
	params := appReconfigureParams{
		ReconfigureArgs: apps.ReconfigureArgs{ID: a.ID, Ports: req.Ports, Settings: plain, Shares: req.Shares, Grants: req.Grants, Limits: req.Limits},
		Name:            a.Name,
	}
	if len(params.Settings) == 0 {
		params.Settings = nil
	}
	if len(secret) > 0 {
		b, _ := json.Marshal(secret)
		params.SecretRef = jobSecrets.put(string(b))
	}
	var changed []string
	for k, v := range map[string]bool{"ports": len(req.Ports) > 0, "settings": len(req.Settings) > 0,
		"shares": len(req.Shares) > 0, "grants": req.Grants != nil, "limits": req.Limits != nil} {
		if v {
			changed = append(changed, k)
		}
	}
	if len(changed) == 0 {
		writeError(w, http.StatusBadRequest, "invalid", "nothing to change")
		return
	}
	if req.Grants != nil {
		s.recordGrants(r, u, a.ID, cur.Grants, *req.Grants)
	}
	sort.Strings(changed)
	s.submit(w, r, u, JobKindAppReconfigure, "Change "+a.Name+"'s settings", params,
		"apps.reconfigure", a.ID+" "+strings.Join(changed, ","), nil)
}

// AppAccess is who may use an app. An empty list means everyone signed in.
type AppAccess struct {
	Principals []appstore.Principal `json:"principals"`
}

func (s *Server) handleAppAccess(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	id := r.PathValue("id")
	if apps.ValidID(id) != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such app")
		return
	}
	list, err := s.appStore().Access(r.Context(), id)
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, AppAccess{Principals: list})
}

func (s *Server) handleSetAppAccess(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req AppAccess
	if !decodeJSON(w, r, &req) {
		return
	}
	a, ok := s.installedApp(w, r)
	if !ok {
		return
	}
	var p apps.Problems
	list := s.checkAccess(r.Context(), &p, req.Principals)
	if len(p) > 0 {
		s.writeAppError(w, p)
		return
	}
	defer s.photosNudge() // Photos follows who may use Immich
	if err := s.appStore().SetAccess(r.Context(), a.ID, list); err != nil {
		s.writeAppError(w, err)
		return
	}
	s.record(r, u, "apps.access", a.ID, audit.Success, describeAccess(list))
	// Open windows (and WebSockets) of people who lost access end now.
	s.proxy.recheckApp(r.Context(), a.ID)
	stored, err := s.appStore().Access(r.Context(), a.ID)
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, AppAccess{Principals: stored})
}

func (s *Server) handleAppSnapshots(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	a, ok := s.installedApp(w, r)
	if !ok {
		return
	}
	res, err := s.appSnapshots(r.Context(), a.ID)
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) appSnapshots(ctx context.Context, id string) (*priv.AppSnapshotsResult, error) {
	var res priv.AppSnapshotsResult
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := s.cfg.Priv.Call(ctx, priv.OpAppsSnapshots, priv.AppRef{ID: id}, &res); err != nil {
		return nil, err
	}
	if res.Snapshots == nil {
		res.Snapshots = []apps.Snapshot{}
	}
	return &res, nil
}

// AppRollbackRequest puts an app back to one of its snapshots.
type AppRollbackRequest struct {
	Snapshot string `json:"snapshot"`
	// Confirm repeats the app's name.
	Confirm string `json:"confirm"`
}

func (s *Server) handleAppRollback(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req AppRollbackRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	a, ok := s.installedApp(w, r)
	if !ok {
		return
	}
	if !confirmsApp(req.Confirm, a.ID, a.Name) {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the app's name ("+a.Name+") to confirm")
		return
	}
	if !snapshotRE.MatchString(req.Snapshot) {
		writeError(w, http.StatusBadRequest, "invalid", "choose one of the app's snapshots")
		return
	}
	list, err := s.appSnapshots(r.Context(), a.ID)
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	found := false
	for _, sn := range list.Snapshots {
		found = found || sn.Name == req.Snapshot
	}
	if !found {
		writeError(w, http.StatusNotFound, "not_found", a.Name+" has no snapshot called "+req.Snapshot)
		return
	}
	params := appRollbackParams{RollbackArgs: apps.RollbackArgs{ID: a.ID, Snapshot: req.Snapshot, Confirm: a.Name}, Name: a.Name}
	s.submit(w, r, u, JobKindAppRollback, "Roll "+a.Name+" back to "+req.Snapshot, params,
		"apps.rollback", a.ID+" "+req.Snapshot, nil)
}

// AppOpen is where to open an app's web page.
type AppOpen struct {
	// URL opens the app. Through the window proxy it carries a short-lived,
	// single-use sign-in token, so ask again for every window or tab.
	URL string `json:"url"`
	// Proxied is true when URL goes through HardyOS's HTTPS window proxy
	// (so the desktop can show it in a window); false is the app's own
	// address, for a new tab.
	Proxied bool `json:"proxied"`
	// Published: URL is the app's own published address
	// (https://<app>.<base>, through NetBird's reverse proxy).
	Published bool `json:"published,omitempty"`
}

func (s *Server) handleAppOpen(w http.ResponseWriter, r *http.Request, u *auth.User) {
	a, ok := s.installedApp(w, r)
	if !ok {
		return
	}
	token := sessionToken(r)
	may, err := s.mayUse(r.Context(), token, u, a.ID)
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	if !may {
		s.record(r, u, "apps.open", a.ID, audit.Denied, "")
		writeError(w, http.StatusForbidden, "forbidden", "you haven't been given "+a.Name)
		return
	}
	if a.Web == nil {
		writeError(w, http.StatusBadRequest, "invalid", a.Name+" has no web page")
		return
	}
	// Through the desktop's published address, published apps open at
	// their own (the app gateway signs the person in there).
	if u, ok := s.remote.publishedURL(r, a.ID); ok {
		writeJSON(w, http.StatusOK, AppOpen{URL: u, Proxied: true, Published: true})
		return
	}
	host := requestHost(r)
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if !s.proxy.isRunning() {
		writeJSON(w, http.StatusOK, AppOpen{URL: fmt.Sprintf("%s://%s:%d%s", a.Web.Scheme, host, a.Web.Port, webPath(a.Web)), Proxied: false})
		return
	}
	port, err := s.proxy.ensure(r.Context(), *a)
	if err != nil {
		s.log.Error("app window proxy", "app", a.ID, "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "couldn't start "+a.Name+"'s window: "+err.Error())
		return
	}
	tok := s.proxy.mint(a.ID, u.ID, token, webPath(a.Web))
	writeJSON(w, http.StatusOK, AppOpen{
		URL:     fmt.Sprintf("%s://%s:%s%s?token=%s", s.proxy.scheme(), host, strconv.Itoa(port), proxyAuthPath, tok),
		Proxied: true,
	})
}

func webPath(w *apps.AppWeb) string {
	if w == nil || w.Path == "" {
		return "/"
	}
	return w.Path
}

// hostOnly strips a port from host:port.
func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return strings.Trim(h, "[]")
}
