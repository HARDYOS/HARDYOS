package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// App job kinds.
const (
	JobKindAppInstall = "apps.install"
	JobKindAppUpdate  = "apps.update"
	JobKindAppRemove  = "apps.remove"
)

// appInstallParams are an install or update job's parameters. Password
// settings wait in jobSecrets (job parameters are kept in the job history).
type appInstallParams struct {
	Source    string            `json:"source"`
	Ref       string            `json:"ref"`
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Pool      string            `json:"pool,omitempty"`
	Host      string            `json:"host,omitempty"`
	Ports     map[string]int    `json:"ports,omitempty"`
	Settings  map[string]string `json:"settings,omitempty"`
	SecretRef string            `json:"secretRef,omitempty"`
}

// RegisterAppJobs adds the Docker app jobs.
func RegisterAppJobs(m *jobs.Manager, pc *priv.Client, store *appstore.Store) {
	lock := func(raw json.RawMessage) string {
		var p struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &p)
		return "app:" + p.ID
	}
	install := func(jc *jobs.Context) (any, error) {
		var p appInstallParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		pkg, err := store.Load(p.Source, p.Ref)
		if err != nil {
			return nil, err
		}
		if pkg.Manifest.ID != p.ID {
			return nil, fmt.Errorf("the package changed: it's now %s", pkg.Manifest.ID)
		}
		settings := map[string]string{}
		for k, v := range p.Settings {
			settings[k] = v
		}
		if p.SecretRef != "" {
			raw, ok := jobSecrets.take(p.SecretRef)
			if !ok {
				return nil, errors.New("the passwords for this install were lost (HardyOS restarted); start the install again")
			}
			var secret map[string]string
			if err := json.Unmarshal([]byte(raw), &secret); err != nil {
				return nil, err
			}
			for k, v := range secret {
				settings[k] = v
			}
		}
		jc.Progress(3, "Checking the package and setting up "+p.Name)
		ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
		var prep apps.PrepareResult
		err = pc.Call(ctx, priv.OpAppsPrepare, apps.PrepareArgs{
			Package: pkg.Raw, Pool: p.Pool, Host: p.Host, Ports: p.Ports, Settings: settings,
		}, &prep)
		cancel()
		if err != nil {
			return nil, err
		}
		notes := append([]string{}, prep.Warnings...)
		for i, sv := range prep.Services {
			jc.Progress(10+float64(i)*75/float64(max(len(prep.Services), 1)),
				fmt.Sprintf("Downloading %s (%d of %d): %s", sv.Service, i+1, len(prep.Services), sv.Image))
			var pr apps.PullResult
			// Each call gets the helper's full time limit; big images on slow
			// links take a while.
			if err := pc.Call(jc, priv.OpAppsPull, priv.AppPullArgs{ID: p.ID, Service: sv.Service}, &pr); err != nil {
				return nil, err
			}
			if pr.Cached {
				notes = append(notes, pr.Message)
			}
		}
		jc.Progress(88, "Starting "+p.Name)
		ctx, cancel = context.WithTimeout(jc, 8*time.Minute)
		defer cancel()
		if err := pc.Call(ctx, priv.OpAppsUp, priv.AppRef{ID: p.ID}, nil); err != nil {
			return nil, err
		}
		verb := "installed"
		if prep.Upgrade {
			verb = "updated"
		}
		jc.Progress(100, p.Name+" is "+verb)
		return map[string]any{"id": p.ID, "upgrade": prep.Upgrade, "notes": notes}, nil
	}
	m.Register(jobs.Kind{Name: JobKindAppInstall, AdminOnly: true, LockKey: lock, Run: install})
	m.Register(jobs.Kind{Name: JobKindAppUpdate, AdminOnly: true, LockKey: lock, Run: install})
	m.Register(jobs.Kind{
		Name: JobKindAppRemove, AdminOnly: true, LockKey: lock,
		Run: func(jc *jobs.Context) (any, error) {
			var a apps.RemoveArgs
			if err := jc.Params(&a); err != nil {
				return nil, err
			}
			msg := "Stopping and removing the app (its data is kept)"
			if a.DeleteData {
				msg = "Stopping and removing the app and deleting its data"
			}
			jc.Progress(20, msg)
			ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
			defer cancel()
			if err := pc.Call(ctx, priv.OpAppsRemove, a, nil); err != nil {
				return nil, err
			}
			return map[string]any{"id": a.ID, "dataDeleted": a.DeleteData}, nil
		},
	})
}

func (s *Server) appRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/apps", s.authed(s.handleApps))
	m.Handle("GET /api/v1/apps/catalog", s.admin(s.handleAppCatalog))
	m.Handle("POST /api/v1/apps/packages", s.admin(s.handleAppUpload))
	m.Handle("POST /api/v1/apps/plan", s.admin(s.handleAppPlan))
	m.Handle("POST /api/v1/apps/install", s.admin(s.handleAppInstall))
	m.Handle("POST /api/v1/apps/{id}/update", s.admin(s.handleAppUpdate))
	m.Handle("POST /api/v1/apps/{id}/{action}", s.admin(s.handleAppAction))
	m.Handle("GET /api/v1/apps/{id}/logs", s.admin(s.handleAppLogs))
	m.Handle("DELETE /api/v1/apps/{id}", s.admin(s.handleAppRemove))
}

func (s *Server) appStore() *appstore.Store {
	if s.cfg.Apps != nil {
		return s.cfg.Apps
	}
	return &appstore.Store{CatalogDir: appstore.DefaultCatalogDir, UploadDir: appstore.DefaultUploadDir}
}

// AppsOverview is the App Store's main view.
type AppsOverview struct {
	apps.Overview
	// Updates maps an installed app's id to the newer version in the catalog.
	Updates map[string]string `json:"updates"`
}

func (s *Server) appsStatus(ctx context.Context) (*apps.Overview, error) {
	var o apps.Overview
	if err := s.cfg.Priv.Call(ctx, priv.OpAppsStatus, nil, &o); err != nil {
		return nil, err
	}
	if o.Apps == nil {
		o.Apps = []apps.App{}
	}
	if o.KeptData == nil {
		o.KeptData = []apps.KeptAppData{}
	}
	return &o, nil
}

func (s *Server) handleApps(w http.ResponseWriter, r *http.Request, u *auth.User) {
	o, err := s.appsStatus(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	resp := AppsOverview{Overview: *o, Updates: map[string]string{}}
	if u.IsAdmin() {
		st := s.appStore()
		for _, a := range o.Apps {
			if v := st.CatalogVersion(a.ID); v != "" && apps.NewerVersion(v, a.Version) {
				resp.Updates[a.ID] = v
			}
		}
	} else {
		// Family members see what's installed and can open it; how it's
		// set up is for administrators.
		resp.KeptData = []apps.KeptAppData{}
		resp.Pool, resp.Problem = "", ""
		for i := range resp.Apps {
			resp.Apps[i].Containers = []apps.Container{}
			resp.Apps[i].Dataset = ""
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAppCatalog(w http.ResponseWriter, _ *http.Request, _ *auth.User) {
	c, err := s.appStore().Catalog()
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) handleAppUpload(w http.ResponseWriter, r *http.Request, u *auth.User) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, apps.MaxPackageBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "couldn't read the upload: "+err.Error())
		return
	}
	if len(raw) > apps.MaxPackageBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", fmt.Sprintf("an app package can be at most %d KB", apps.MaxPackageBytes>>10))
		return
	}
	e, err := s.appStore().Save(raw)
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	s.record(r, u, "apps.upload", e.ID+" "+e.Version, audit.Success, "sha256 "+e.Ref)
	writeJSON(w, http.StatusOK, e)
}

// AppPackageRef names a package: from the catalog (ref = app id) or
// uploaded (ref = the package's SHA-256).
type AppPackageRef struct {
	Source string `json:"source"`
	Ref    string `json:"ref"`
}

// AppPlan is what the install dialog needs.
type AppPlan struct {
	Package appstore.Entry `json:"package"`
	// Ports suggested for each of the app's ports (free on this server).
	Ports map[string]int `json:"ports"`
	// Pools to choose from, when Docker isn't set up yet (EnginePool empty).
	Pools      []string `json:"pools"`
	EnginePool string   `json:"enginePool"`
	// Installed: this replaces an installed copy (InstalledVersion), keeping
	// its data, passwords and ports.
	Installed        bool   `json:"installed"`
	InstalledVersion string `json:"installedVersion"`
	// KeptData: the app was removed with its data kept; it's picked back up.
	KeptData  bool   `json:"keptData"`
	Available bool   `json:"available"`
	Problem   string `json:"problem"`
}

func (s *Server) handleAppPlan(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var ref AppPackageRef
	if !decodeJSON(w, r, &ref) {
		return
	}
	pkg, err := s.appStore().Load(ref.Source, ref.Ref)
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	o, err := s.appsStatus(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	mf := pkg.Manifest
	plan := AppPlan{Package: appstore.EntryOf(ref.Source, ref.Ref, pkg), Pools: []string{},
		EnginePool: o.Pool, Available: o.Available, Problem: o.Problem}
	for _, a := range o.Apps {
		if a.ID == mf.ID {
			plan.Installed, plan.InstalledVersion = true, a.Version
		}
	}
	for _, k := range o.KeptData {
		if k.ID == mf.ID {
			plan.KeptData = true
		}
	}
	if o.Pool == "" {
		var pools []zfs.Pool
		if err := s.cfg.Priv.Call(r.Context(), priv.OpPools, nil, &pools); err != nil {
			s.writePrivError(w, err)
			return
		}
		for _, p := range pools {
			if p.Health == "ONLINE" || p.Health == "DEGRADED" {
				plan.Pools = append(plan.Pools, p.Name)
			}
		}
	}
	checks := make([]apps.PortCheck, 0, len(mf.Ports))
	for _, p := range mf.Ports {
		checks = append(checks, apps.PortCheck{Name: p.Name, Default: p.Default, Protocol: p.Protocol})
	}
	if err := s.cfg.Priv.Call(r.Context(), priv.OpAppsPorts, priv.AppPortsArgs{Ports: checks, ForID: mf.ID}, &plan.Ports); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

// AppInstallRequest installs an app.
type AppInstallRequest struct {
	AppPackageRef
	// Pool for Docker and every app; only the first time (see AppPlan).
	Pool     string            `json:"pool,omitempty"`
	Ports    map[string]int    `json:"ports,omitempty"`
	Settings map[string]string `json:"settings,omitempty"`
}

func (s *Server) handleAppInstall(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req AppInstallRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	pkg, err := s.appStore().Load(req.Source, req.Ref)
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	mf := pkg.Manifest
	// Catch the quick mistakes before a long job; hardyd-priv checks again.
	var p apps.Problems
	ports := map[string]bool{}
	for _, pt := range mf.Ports {
		ports[pt.Name] = true
	}
	for name, port := range req.Ports {
		if !ports[name] {
			p = append(p, fmt.Sprintf("%s has no port called %s", mf.Name, name))
		} else if port < 1024 || port > 65535 {
			p = append(p, fmt.Sprintf("port %d: choose a port from 1024 to 65535", port))
		}
	}
	plain, secret := map[string]string{}, map[string]string{}
	for k, v := range req.Settings {
		st := mf.Setting(k)
		switch {
		case st == nil || st.Generate != "":
			p = append(p, fmt.Sprintf("%s isn't one of %s's settings", k, mf.Name))
		case st.Secret():
			secret[k] = v
		default:
			plain[k] = v
		}
	}
	if req.Pool != "" {
		if err := zfs.ValidPoolName(req.Pool); err != nil {
			p = append(p, err.Error())
		}
	}
	if len(p) > 0 {
		s.writeAppError(w, p)
		return
	}
	params := appInstallParams{Source: req.Source, Ref: req.Ref, ID: mf.ID, Name: mf.Name,
		Pool: req.Pool, Host: requestHost(r), Ports: req.Ports, Settings: plain}
	if len(secret) > 0 {
		b, _ := json.Marshal(secret)
		params.SecretRef = jobSecrets.put(string(b))
	}
	s.submit(w, r, u, JobKindAppInstall, "Install "+mf.Name+" "+mf.Version, params,
		"apps.install", mf.ID+" "+mf.Version, nil)
}

func (s *Server) installedApp(w http.ResponseWriter, r *http.Request) (*apps.App, bool) {
	id := r.PathValue("id")
	if apps.ValidID(id) != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such app")
		return nil, false
	}
	o, err := s.appsStatus(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return nil, false
	}
	for i := range o.Apps {
		if o.Apps[i].ID == id {
			return &o.Apps[i], true
		}
	}
	writeError(w, http.StatusNotFound, "not_found", id+" isn't installed")
	return nil, false
}

func (s *Server) handleAppUpdate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var ref AppPackageRef
	if r.ContentLength != 0 && !decodeJSON(w, r, &ref) {
		return
	}
	a, ok := s.installedApp(w, r)
	if !ok {
		return
	}
	if ref.Source == "" {
		ref = AppPackageRef{Source: appstore.SourceCatalog, Ref: a.ID}
	}
	pkg, err := s.appStore().Load(ref.Source, ref.Ref)
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	if pkg.Manifest.ID != a.ID {
		writeError(w, http.StatusBadRequest, "invalid", "that package is "+pkg.Manifest.Name+", not "+a.Name)
		return
	}
	// No host, ports or settings: the update keeps the app's own.
	params := appInstallParams{Source: ref.Source, Ref: ref.Ref, ID: a.ID, Name: a.Name}
	s.submit(w, r, u, JobKindAppUpdate, "Update "+a.Name+" to "+pkg.Manifest.Version, params,
		"apps.update", a.ID+" "+a.Version+" -> "+pkg.Manifest.Version, nil)
}

func (s *Server) handleAppAction(w http.ResponseWriter, r *http.Request, u *auth.User) {
	action := r.PathValue("action")
	op := map[string]string{"start": priv.OpAppsStart, "stop": priv.OpAppsStop, "restart": priv.OpAppsRestart}[action]
	if op == "" {
		writeError(w, http.StatusNotFound, "not_found", "no such API endpoint")
		return
	}
	a, ok := s.installedApp(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if err := s.cfg.Priv.Call(ctx, op, priv.AppRef{ID: a.ID}, nil); err != nil {
		s.record(r, u, "apps."+action, a.ID, audit.Failure, err.Error())
		s.writePrivError(w, err)
		return
	}
	s.record(r, u, "apps."+action, a.ID, audit.Success, "")
	o, err := s.appsStatus(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	for _, x := range o.Apps {
		if x.ID == a.ID {
			writeJSON(w, http.StatusOK, x)
			return
		}
	}
	writeJSON(w, http.StatusOK, a)
}

// AppLogs is an app's recent output.
type AppLogs struct {
	Logs string `json:"logs"`
}

func (s *Server) handleAppLogs(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	id := r.PathValue("id")
	if apps.ValidID(id) != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such app")
		return
	}
	lines := 300
	if v := r.URL.Query().Get("lines"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 5000 {
			writeError(w, http.StatusBadRequest, "invalid", "lines must be from 1 to 5000")
			return
		}
		lines = n
	}
	var res priv.AppLogsResult
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	if err := s.cfg.Priv.Call(ctx, priv.OpAppsLogs, priv.AppLogsArgs{ID: id, Lines: lines}, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, AppLogs(res))
}

// AppRemoveRequest removes an app.
type AppRemoveRequest struct {
	// Confirm repeats the app's name.
	Confirm string `json:"confirm"`
	// DeleteData destroys the app's files and database; otherwise they're
	// kept for installing it again.
	DeleteData bool `json:"deleteData"`
}

func (s *Server) handleAppRemove(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req AppRemoveRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	if apps.ValidID(id) != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such app")
		return
	}
	o, err := s.appsStatus(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	name := ""
	for _, a := range o.Apps {
		if a.ID == id {
			name = a.Name
		}
	}
	// Kept data can be deleted for good too.
	for _, k := range o.KeptData {
		if k.ID == id && name == "" {
			name = k.Name
			req.DeleteData = true
		}
	}
	if name == "" {
		writeError(w, http.StatusNotFound, "not_found", id+" isn't installed")
		return
	}
	conf := strings.TrimSpace(req.Confirm)
	if !strings.EqualFold(conf, name) && conf != id {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the app's name ("+name+") to confirm")
		return
	}
	title := "Remove " + name
	if req.DeleteData {
		title += " and its data"
	}
	s.submit(w, r, u, JobKindAppRemove, title, apps.RemoveArgs{ID: id, Confirm: conf, DeleteData: req.DeleteData},
		"apps.remove", fmt.Sprintf("%s deleteData=%t", id, req.DeleteData), nil)
}

// writeAppError answers package and request problems with 400 and every
// problem listed.
func (s *Server) writeAppError(w http.ResponseWriter, err error) {
	var p apps.Problems
	switch {
	case errors.As(err, &p):
		msg := "the app package has problems"
		if len(p) == 1 {
			msg = p[0]
		}
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Code: "invalid", Message: msg, Details: p})
	case errors.Is(err, appstore.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	default:
		internalError(s, w, err)
	}
}

// requestHost is the server's name as the browser reached it, which is how
// people on the network reach the apps too.
func requestHost(r *http.Request) string {
	h := r.Host
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.Trim(h, "[]")
}
