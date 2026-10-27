package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
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
	JobKindAppInstall     = "apps.install"
	JobKindAppUpdate      = "apps.update"
	JobKindAppRemove      = "apps.remove"
	JobKindAppReconfigure = "apps.reconfigure"
	JobKindAppRollback    = "apps.rollback"
)

// appInstallParams are an install or update job's parameters. Password
// settings wait in jobSecrets (job parameters are kept in the job history).
type appInstallParams struct {
	Source     string `json:"source"`
	Ref        string `json:"ref"`
	SourceName string `json:"sourceName,omitempty"`
	// CatalogID is the imported catalog the package came from.
	CatalogID int64                       `json:"catalogId,omitempty"`
	ID        string                      `json:"id"`
	Name      string                      `json:"name"`
	Pool      string                      `json:"pool,omitempty"`
	Host      string                      `json:"host,omitempty"`
	Ports     map[string]int              `json:"ports,omitempty"`
	Settings  map[string]string           `json:"settings,omitempty"`
	SecretRef string                      `json:"secretRef,omitempty"`
	Shares    map[string]apps.ShareChoice `json:"shares,omitempty"`
	Grants    []string                    `json:"grants,omitempty"`
	Limits    *apps.Limits                `json:"limits,omitempty"`
}

// appReconfigureParams is a settings change; passwords wait in jobSecrets.
type appReconfigureParams struct {
	apps.ReconfigureArgs
	Name      string `json:"name"`
	SecretRef string `json:"secretRef,omitempty"`
}

// appRollbackParams puts an app back to a snapshot.
type appRollbackParams struct {
	apps.RollbackArgs
	Name string `json:"name"`
}

// takeSettings adds the passwords waiting under ref to settings.
func takeSettings(settings map[string]string, ref, what string) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range settings {
		out[k] = v
	}
	if ref == "" {
		return out, nil
	}
	raw, ok := jobSecrets.take(ref)
	if !ok {
		return nil, fmt.Errorf("the passwords for this %s were lost (HardyOS restarted); start again", what)
	}
	var secret map[string]string
	if err := json.Unmarshal([]byte(raw), &secret); err != nil {
		return nil, err
	}
	for k, v := range secret {
		out[k] = v
	}
	return out, nil
}

// pullImages downloads each service's image, reporting from% to to%. While
// an image downloads, the root helper is asked every couple of seconds how
// far it has got, so a big image moves the bar instead of sitting still.
func pullImages(jc *jobs.Context, pc *priv.Client, id string, services []apps.ServiceImage, from, to float64) ([]string, error) {
	var notes []string
	step := (to - from) / float64(max(len(services), 1))
	for i, sv := range services {
		base := from + float64(i)*step
		what := fmt.Sprintf("Downloading %s (%d of %d)", sv.Service, i+1, len(services))
		jc.Progress(base, what+": "+sv.Image)
		var pr apps.PullResult
		done := make(chan error, 1)
		// Each call gets the helper's full time limit; big images on slow
		// links take a while.
		go func() { done <- pc.Call(jc, priv.OpAppsPull, priv.AppPullArgs{ID: id, Service: sv.Service}, &pr) }()
		tick := time.NewTicker(2 * time.Second)
		var err error
	wait:
		for {
			select {
			case err = <-done:
				break wait
			case <-tick.C:
				var p apps.PullProgress
				ctx, cancel := context.WithTimeout(jc, 5*time.Second)
				perr := pc.Call(ctx, priv.OpAppsPullStatus, priv.AppPullArgs{ID: id, Service: sv.Service}, &p)
				cancel()
				if perr == nil && p.Active && p.Total > 0 {
					jc.Progress(base+step*pullFraction(p), fmt.Sprintf("%s: %s of %s", what, mb(p.Current), mb(p.Total)))
				}
			}
		}
		tick.Stop()
		if err != nil {
			return notes, err
		}
		if pr.Cached {
			notes = append(notes, pr.Message)
		}
	}
	return notes, nil
}

// pullFraction is how much of an image is down, kept a little short of the
// end: Docker learns layer sizes as it goes and still unpacks afterwards.
func pullFraction(p apps.PullProgress) float64 {
	if p.Total <= 0 {
		return 0
	}
	return min(float64(p.Current)/float64(p.Total), 1) * 0.95
}

func mb(n int64) string {
	if n >= 1<<30 {
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	}
	return fmt.Sprintf("%d MB", (n+(1<<19))>>20)
}

func appUp(jc *jobs.Context, pc *priv.Client, id string) error {
	ctx, cancel := context.WithTimeout(jc, 8*time.Minute)
	defer cancel()
	return pc.Call(ctx, priv.OpAppsUp, priv.AppRef{ID: id}, nil)
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
	load := func(jc *jobs.Context, p appInstallParams) (*apps.Package, error) {
		pkg, err := store.LoadFrom(jc, p.Source, p.Ref, p.CatalogID)
		if err != nil {
			return nil, err
		}
		if pkg.Manifest.ID != p.ID {
			return nil, fmt.Errorf("the package changed: it's now %s", pkg.Manifest.ID)
		}
		return pkg, nil
	}
	// remember where the app came from: updates follow the same imported
	// catalog, and installing the same id from elsewhere needs replaceSource.
	remember := func(p appInstallParams) {
		if store.DB == nil {
			return
		}
		_ = store.SetOrigin(context.Background(), appstore.Origin{AppID: p.ID, Source: p.Source, CatalogID: p.CatalogID, CatalogName: p.SourceName, Ref: p.Ref})
	}
	install := func(jc *jobs.Context) (any, error) {
		var p appInstallParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		pkg, err := load(jc, p)
		if err != nil {
			return nil, err
		}
		settings, err := takeSettings(p.Settings, p.SecretRef, "install")
		if err != nil {
			return nil, err
		}
		jc.Progress(3, "Checking the package and setting up "+p.Name)
		ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
		var prep apps.PrepareResult
		err = pc.Call(ctx, priv.OpAppsPrepare, apps.PrepareArgs{
			Package: pkg.Raw, Pool: p.Pool, Host: p.Host, Ports: p.Ports, Settings: settings,
			Source: apps.Source(p.Source), SourceName: p.SourceName, Shares: p.Shares, Grants: p.Grants, Limits: p.Limits,
		}, &prep)
		cancel()
		if err != nil {
			return nil, err
		}
		notes := append([]string{}, prep.Warnings...)
		pulled, err := pullImages(jc, pc, p.ID, prep.Services, 10, 85)
		notes = append(notes, pulled...)
		if err != nil {
			return nil, err
		}
		jc.Progress(88, "Starting "+p.Name)
		if err := appUp(jc, pc, p.ID); err != nil {
			return nil, err
		}
		verb := "installed"
		if prep.Upgrade {
			verb = "updated"
		}
		remember(p)
		jc.Progress(100, p.Name+" is "+verb)
		return map[string]any{"id": p.ID, "upgrade": prep.Upgrade, "notes": notes}, nil
	}
	// update takes a snapshot first, then prepares the new package, pulls its
	// images and starts it. If anything after the snapshot fails, the job
	// ends with the snapshot's name so the App Store can offer to roll back.
	update := func(jc *jobs.Context) (any, error) {
		var p appInstallParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		pkg, err := load(jc, p)
		if err != nil {
			return nil, err
		}
		jc.Progress(2, "Taking a snapshot of "+p.Name+" first")
		ctx, cancel := context.WithTimeout(jc, 2*time.Minute)
		var snap priv.AppSnapshotResult
		err = pc.Call(ctx, priv.OpAppsSnapshot, apps.SnapshotArgs{ID: p.ID, Reason: "update"}, &snap)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("couldn't take a snapshot before updating, so nothing was changed: %w", err)
		}
		failed := func(err error) error {
			return &jobs.FailedWith{
				Err:    fmt.Errorf("%w. A snapshot was taken first (%s): roll back to it to undo the update", err, snap.Snapshot),
				Result: map[string]any{"id": p.ID, "snapshot": snap.Snapshot},
			}
		}
		jc.Progress(6, "Checking the new package")
		ctx, cancel = context.WithTimeout(jc, 5*time.Minute)
		var prep apps.PrepareResult
		// No host, ports, settings, shares or limits: the update keeps the
		// app's own. Grants only when an administrator allowed new ones.
		err = pc.Call(ctx, priv.OpAppsPrepare, apps.PrepareArgs{
			Package: pkg.Raw, Source: apps.Source(p.Source), SourceName: p.SourceName, Grants: p.Grants,
		}, &prep)
		cancel()
		if err != nil {
			return nil, failed(err)
		}
		notes := append([]string{}, prep.Warnings...)
		pulled, err := pullImages(jc, pc, p.ID, prep.Services, 10, 85)
		notes = append(notes, pulled...)
		if err != nil {
			return nil, failed(err)
		}
		jc.Progress(88, "Starting "+p.Name)
		if err := appUp(jc, pc, p.ID); err != nil {
			return nil, failed(err)
		}
		remember(p)
		jc.Progress(100, p.Name+" is updated")
		return map[string]any{"id": p.ID, "upgrade": true, "snapshot": snap.Snapshot, "notes": notes}, nil
	}
	m.Register(jobs.Kind{Name: JobKindAppInstall, AdminOnly: true, LockKey: lock, Run: install})
	m.Register(jobs.Kind{Name: JobKindAppUpdate, AdminOnly: true, LockKey: lock, Run: update})
	m.Register(jobs.Kind{
		Name: JobKindAppReconfigure, AdminOnly: true, LockKey: lock,
		Run: func(jc *jobs.Context) (any, error) {
			var p appReconfigureParams
			if err := jc.Params(&p); err != nil {
				return nil, err
			}
			settings, err := takeSettings(p.Settings, p.SecretRef, "change")
			if err != nil {
				return nil, err
			}
			args := p.ReconfigureArgs
			if len(settings) > 0 {
				args.Settings = settings
			}
			jc.Progress(10, "Applying "+p.Name+"'s new settings")
			ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
			var prep apps.PrepareResult
			err = pc.Call(ctx, priv.OpAppsReconfigure, args, &prep)
			cancel()
			if err != nil {
				return nil, err
			}
			jc.Progress(60, "Restarting "+p.Name)
			if err := appUp(jc, pc, p.ID); err != nil {
				return nil, err
			}
			jc.Progress(100, p.Name+" uses its new settings")
			notes := prep.Warnings
			if notes == nil {
				notes = []string{}
			}
			return map[string]any{"id": p.ID, "notes": notes}, nil
		},
	})
	m.Register(jobs.Kind{
		Name: JobKindAppRollback, AdminOnly: true, LockKey: lock,
		Run: func(jc *jobs.Context) (any, error) {
			var p appRollbackParams
			if err := jc.Params(&p); err != nil {
				return nil, err
			}
			jc.Progress(10, "Stopping "+p.Name+" and putting it back to "+p.Snapshot)
			ctx, cancel := context.WithTimeout(jc, 10*time.Minute)
			defer cancel()
			if err := pc.Call(ctx, priv.OpAppsRollback, p.RollbackArgs, nil); err != nil {
				// The data may be back with the app left stopped because it
				// needs a permission removed since (decision 77): say so, so
				// the App Store shows "restored" rather than a failed rollback.
				var o apps.Overview
				if serr := pc.Call(ctx, priv.OpAppsStatus, nil, &o); serr == nil {
					for _, a := range o.Apps {
						if a.ID == p.ID && a.Blocked != "" {
							return nil, &jobs.FailedWith{Err: err, Result: map[string]any{
								"id": p.ID, "snapshot": p.Snapshot, "restored": true, "blocked": a.Blocked}}
						}
					}
				}
				return nil, err
			}
			jc.Progress(100, p.Name+" is back to "+p.Snapshot)
			return map[string]any{"id": p.ID, "snapshot": p.Snapshot}, nil
		},
	})
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
			if a.DeleteData && store.DB != nil {
				// Who could use it and its window port go with its data; kept
				// data keeps them for installing it again.
				_ = store.ForgetApp(ctx, a.ID)
			}
			return map[string]any{"id": a.ID, "dataDeleted": a.DeleteData}, nil
		},
	})
}

func (s *Server) appRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/apps", s.authed(s.handleApps))
	m.Handle("GET /api/v1/apps/catalog", s.admin(s.handleAppCatalog))
	m.Handle("GET /api/v1/apps/catalogs", s.admin(s.handleAppCatalogs))
	m.Handle("POST /api/v1/apps/catalogs", s.admin(s.handleAddAppCatalog))
	m.Handle("DELETE /api/v1/apps/catalogs", s.admin(s.handleRemoveAppCatalog))
	m.Handle("POST /api/v1/apps/packages", s.admin(s.handleAppUpload))
	m.Handle("POST /api/v1/apps/custom", s.admin(s.handleAppCustom))
	m.Handle("POST /api/v1/apps/plan", s.admin(s.handleAppPlan))
	m.Handle("POST /api/v1/apps/install", s.admin(s.handleAppInstall))
	m.Handle("GET /api/v1/apps/{id}/config", s.admin(s.handleAppConfig))
	m.Handle("PATCH /api/v1/apps/{id}/config", s.admin(s.handleAppReconfigure))
	m.Handle("GET /api/v1/apps/{id}/access", s.admin(s.handleAppAccess))
	m.Handle("PUT /api/v1/apps/{id}/access", s.admin(s.handleSetAppAccess))
	m.Handle("GET /api/v1/apps/{id}/snapshots", s.admin(s.handleAppSnapshots))
	m.Handle("POST /api/v1/apps/{id}/rollback", s.admin(s.handleAppRollback))
	m.Handle("POST /api/v1/apps/{id}/open", s.authed(s.handleAppOpen))
	m.Handle("POST /api/v1/apps/{id}/update", s.admin(s.handleAppUpdate))
	m.Handle("POST /api/v1/apps/{id}/{action}", s.admin(s.handleAppAction))
	m.Handle("GET /api/v1/apps/{id}/logs", s.admin(s.handleAppLogs))
	m.Handle("DELETE /api/v1/apps/{id}", s.admin(s.handleAppRemove))
}

func (s *Server) appStore() *appstore.Store {
	if s.cfg.Apps != nil {
		return s.cfg.Apps
	}
	return &appstore.Store{CatalogDir: appstore.DefaultCatalogDir, UploadDir: appstore.DefaultUploadDir, DB: s.cfg.DB}
}

// AppsOverview is the App Store's main view.
type AppsOverview struct {
	apps.Overview
	// Updates maps an installed app's id to the newer version in the catalog
	// it came from (HardyOS's own or an imported one).
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
	for i := range o.Apps {
		a := &o.Apps[i]
		if a.Source == "" {
			a.Source = apps.SourceUpload // root decides "catalog"; an unknown source is never trusted
		}
		if a.Shares == nil {
			a.Shares = []apps.AppShare{}
		}
		if a.Grants == nil {
			a.Grants = []string{}
		}
		if a.Permissions == nil {
			a.Permissions = []string{}
		}
		if a.Ports == nil {
			a.Ports = []apps.AppPort{}
		}
		if a.Containers == nil {
			a.Containers = []apps.Container{}
		}
	}
	return &o, nil
}

// newerVersion is the version an app can update to from the catalog it came
// from, or "".
func (s *Server) newerVersion(ctx context.Context, a apps.App) (version, ref string) {
	st := s.appStore()
	switch a.Source {
	case apps.SourceCatalog:
		v := st.CatalogVersion(a.ID)
		if v != "" && apps.NewerVersion(v, a.Version) {
			return v, a.ID
		}
	case apps.SourceImported:
		v, sha, _ := s.importedLatest(ctx, a)
		if v != "" && apps.NewerVersion(v, a.Version) {
			return v, sha
		}
	}
	return "", ""
}

// importedLatest is the newest version of an imported app in the catalog it
// was installed from: by the catalog id hardyd recorded at install, or (apps
// installed before that was recorded) by the catalog's name.
func (s *Server) importedLatest(ctx context.Context, a apps.App) (version, sha string, catalogID int64) {
	st := s.appStore()
	if o := st.OriginOf(ctx, a.ID); o != nil && o.Source == appstore.SourceImported && o.CatalogID > 0 {
		v, sha := st.ImportedLatestIn(ctx, o.CatalogID, a.ID)
		return v, sha, o.CatalogID
	}
	return st.ImportedLatest(ctx, a.SourceName, a.ID)
}

func (s *Server) handleApps(w http.ResponseWriter, r *http.Request, u *auth.User) {
	o, err := s.appsStatus(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	resp := AppsOverview{Overview: *o, Updates: map[string]string{}}
	if u.IsAdmin() {
		for _, a := range o.Apps {
			if v, _ := s.newerVersion(r.Context(), a); v != "" {
				resp.Updates[a.ID] = v
			}
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	// Family members see the apps they may use, so they can open them; how
	// they're set up is for administrators.
	access, err := s.appStore().AllAccess(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	who := s.appWho(r.Context(), sessionToken(r), u)
	resp.KeptData = []apps.KeptAppData{}
	resp.Pool, resp.Problem = "", ""
	visible := []apps.App{}
	for _, a := range resp.Apps {
		if !appstore.MayUse(access[a.ID], who) {
			continue
		}
		a.Containers = []apps.Container{}
		a.Dataset, a.UID = "", 0
		a.Shares, a.Grants, a.Permissions = []apps.AppShare{}, []string{}, []string{}
		a.Limits = apps.Limits{}
		visible = append(visible, a)
	}
	resp.Apps = visible
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

// AppPackageRef names a package: from the catalog (ref = app id), or
// uploaded, imported or custom (ref = the package's SHA-256). An imported
// package also names its catalog (CatalogID), which must list that hash.
type AppPackageRef struct {
	Source    string `json:"source"`
	Ref       string `json:"ref"`
	CatalogID int64  `json:"catalogId,omitempty"`
}

func (s *Server) loadRef(ctx context.Context, ref AppPackageRef) (*apps.Package, error) {
	return s.appStore().LoadFrom(ctx, ref.Source, ref.Ref, ref.CatalogID)
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
	KeptData bool `json:"keptData"`
	// InstalledSource and InstalledSourceName are where the installed (or
	// kept) app with this id came from ("" when nothing is installed or it
	// isn't known).
	InstalledSource     string `json:"installedSource"`
	InstalledSourceName string `json:"installedSourceName"`
	// ReplaceSourceRequired: this package comes from another source or
	// catalog than the installed (or kept) app with the same id, which it
	// would replace, data and passwords included. The install must then send
	// replaceSource: true.
	ReplaceSourceRequired bool   `json:"replaceSourceRequired"`
	Available             bool   `json:"available"`
	Problem               string `json:"problem"`
}

func (s *Server) handleAppPlan(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var ref AppPackageRef
	if !decodeJSON(w, r, &ref) {
		return
	}
	plan, err := s.appPlan(r.Context(), ref)
	if err != nil {
		s.writeAppOrPrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

// appPlan works out the install dialog for a package.
func (s *Server) appPlan(ctx context.Context, ref AppPackageRef) (*AppPlan, error) {
	st := s.appStore()
	pkg, err := s.loadRef(ctx, ref)
	if err != nil {
		return nil, err
	}
	o, err := s.appsStatus(ctx)
	if err != nil {
		return nil, err
	}
	mf := pkg.Manifest
	plan := &AppPlan{Package: appstore.EntryOf(ref.Source, ref.Ref, pkg), Pools: []string{},
		EnginePool: o.Pool, Available: o.Available, Problem: o.Problem}
	plan.Package.SourceName = st.SourceNameOf(ctx, ref.Source, ref.Ref, ref.CatalogID)
	plan.Package.CatalogID = importedCatalog(ref)
	for _, a := range o.Apps {
		if a.ID == mf.ID {
			plan.Installed, plan.InstalledVersion = true, a.Version
		}
	}
	sc := s.sourceChange(ctx, o, mf.ID, ref, plan.Package.SourceName)
	plan.InstalledSource, plan.InstalledSourceName, plan.ReplaceSourceRequired = sc.fromSource, sc.fromName, sc.differs
	for _, k := range o.KeptData {
		if k.ID == mf.ID {
			plan.KeptData = true
		}
	}
	if o.Pool == "" {
		var pools []zfs.Pool
		if err := s.cfg.Priv.Call(ctx, priv.OpPools, nil, &pools); err != nil {
			return nil, err
		}
		for _, p := range pools {
			if p.Health == "ONLINE" || p.Health == "DEGRADED" {
				plan.Pools = append(plan.Pools, p.Name)
			}
		}
	}
	checks := make([]portCheck, 0, len(mf.Ports))
	for _, p := range mf.Ports {
		checks = append(checks, portCheck{PortCheck: apps.PortCheck{Name: p.Name, Default: p.Default, Protocol: p.Protocol},
			Fixed: mf.Permissions.HostNetwork})
	}
	args := struct {
		Ports []portCheck `json:"ports"`
		ForID string      `json:"forId,omitempty"`
	}{checks, mf.ID}
	if err := s.cfg.Priv.Call(ctx, priv.OpAppsPorts, args, &plan.Ports); err != nil {
		return nil, err
	}
	if plan.Ports == nil {
		plan.Ports = map[string]int{}
	}
	return plan, nil
}

// AppInstallRequest installs an app.
type AppInstallRequest struct {
	AppPackageRef
	// Pool for Docker and every app; only the first time (see AppPlan).
	Pool     string            `json:"pool,omitempty"`
	Ports    map[string]int    `json:"ports,omitempty"`
	Settings map[string]string `json:"settings,omitempty"`
	// Shares: the shared folder (and subfolder) for each of the app's shares.
	Shares map[string]apps.ShareChoice `json:"shares,omitempty"`
	// Grants are extra permissions an administrator ticked for an app that
	// isn't from HardyOS's catalog; each is audited.
	Grants []string     `json:"grants,omitempty"`
	Limits *apps.Limits `json:"limits,omitempty"`
	// Access is who may use the app; empty or omitted = everyone.
	Access []appstore.Principal `json:"access,omitempty"`
	// ReplaceSource confirms replacing an installed (or kept) app with the
	// same id from another source or catalog (AppPlan.ReplaceSourceRequired):
	// the new package gets the old one's data and passwords.
	ReplaceSource bool `json:"replaceSource,omitempty"`
}

// sourceChangeInfo compares a package with what's installed under its id.
type sourceChangeInfo struct {
	fromSource, fromName string
	differs              bool
}

func (c sourceChangeInfo) describe(toSource, toName string) string {
	label := func(src, name string) string {
		switch {
		case src == appstore.SourceImported && name != "":
			return "imported from " + name
		case src == "":
			return "unknown"
		}
		return src
	}
	return label(c.fromSource, c.fromName) + " -> " + label(toSource, toName)
}

// sourceChange works out whether installing ref (from the catalog called
// sourceName) would replace an installed or kept app with the same id that
// came from somewhere else: another source, or another imported catalog (by
// the catalog id hardyd recorded, else by name).
func (s *Server) sourceChange(ctx context.Context, o *apps.Overview, id string, ref AppPackageRef, sourceName string) sourceChangeInfo {
	origin := s.appStore().OriginOf(ctx, id)
	var c sourceChangeInfo
	found := false
	for _, a := range o.Apps {
		if a.ID == id {
			c.fromSource, c.fromName, found = string(a.Source), a.SourceName, true
		}
	}
	if !found {
		kept := false
		for _, k := range o.KeptData {
			kept = kept || k.ID == id
		}
		if !kept || origin == nil {
			return sourceChangeInfo{}
		}
		c.fromSource, c.fromName = origin.Source, origin.CatalogName
	}
	switch {
	case c.fromSource != ref.Source:
		c.differs = true
	case ref.Source == appstore.SourceImported:
		if origin != nil && origin.Source == appstore.SourceImported && origin.CatalogID > 0 {
			c.differs = origin.CatalogID != ref.CatalogID
		} else {
			c.differs = c.fromName != sourceName
		}
	}
	return c
}

var (
	shareIDRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	snapshotRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)
	maxLimitCPU = 1024.0
)

// portCheck asks the root helper for a free port. Fixed (the app uses the
// host network, so it can't move) is the engine's PortCheck.Fixed; it's
// spelled out here so this builds against the contract types too.
type portCheck struct {
	apps.PortCheck
	Fixed bool `json:"fixed,omitempty"`
}

// checkPorts catches quick port mistakes before a long job.
func checkPorts(p *apps.Problems, mf apps.Manifest, ports map[string]int) {
	defaults := map[string]int{}
	for _, pt := range mf.Ports {
		defaults[pt.Name] = pt.Default
	}
	for name, port := range ports {
		def, ok := defaults[name]
		switch {
		case !ok:
			*p = append(*p, fmt.Sprintf("%s has no port called %s", mf.Name, name))
		case mf.Permissions.HostNetwork && port != def:
			// Host-network apps listen on their own ports; nothing remaps them.
			*p = append(*p, fmt.Sprintf("%s uses the server's network directly, so port %s stays %d", mf.Name, name, def))
		case !mf.Permissions.HostNetwork && (port < 1024 || port > 65535):
			*p = append(*p, fmt.Sprintf("port %d: choose a port from 1024 to 65535", port))
		}
	}
}

// splitSettings sorts settings into plain values and passwords.
func splitSettings(p *apps.Problems, mf apps.Manifest, settings map[string]string) (plain, secret map[string]string) {
	plain, secret = map[string]string{}, map[string]string{}
	for k, v := range settings {
		st := mf.Setting(k)
		switch {
		case st == nil || st.Generate != "":
			*p = append(*p, fmt.Sprintf("%s isn't one of %s's settings", k, mf.Name))
		case st.Secret():
			secret[k] = v
		default:
			plain[k] = v
		}
	}
	return plain, secret
}

// checkShares checks the shared folders chosen for an app's shares.
func checkShares(p *apps.Problems, mf apps.Manifest, shares map[string]apps.ShareChoice, install bool) {
	declared := map[string]apps.ShareMount{}
	for _, sm := range mf.Shares {
		declared[sm.Name] = sm
	}
	for name, c := range shares {
		sm, ok := declared[name]
		if !ok {
			*p = append(*p, fmt.Sprintf("%s doesn't ask for a shared folder called %s", mf.Name, name))
			continue
		}
		if c.Share != "" && !shareIDRE.MatchString(c.Share) {
			*p = append(*p, fmt.Sprintf("%s: %q isn't a shared folder id", sm.Label, c.Share))
		}
		if c.Path != "" {
			// Whole shared folders only: a container could swap a subfolder
			// for a link to somewhere else.
			*p = append(*p, fmt.Sprintf("%s: apps get a whole shared folder, not a subfolder", sm.Label))
		}
		switch c.Access {
		case "", "read":
		case "write":
			if sm.Access != "write" {
				*p = append(*p, fmt.Sprintf("%s only gets to read %s", mf.Name, sm.Label))
			}
		default:
			*p = append(*p, fmt.Sprintf("%s: access must be read or write", sm.Label))
		}
	}
	if install {
		for _, sm := range mf.Shares {
			if sm.Required && shares[sm.Name].Share == "" {
				*p = append(*p, fmt.Sprintf("choose a shared folder for %s", sm.Label))
			}
		}
	}
}

// checkGrants checks extra permissions: only for apps not from HardyOS's
// catalog, and only ones the package asks for.
func checkGrants(p *apps.Problems, mf apps.Manifest, source apps.Source, grants []string) {
	if len(grants) == 0 {
		return
	}
	if source.Trusted() {
		*p = append(*p, "apps from HardyOS's catalog get the permissions they declare; there's nothing to tick")
		return
	}
	asked := map[string]bool{}
	for _, g := range appstore.GrantsOf(mf) {
		asked[g.Grant] = true
	}
	seen := map[string]bool{}
	for _, g := range grants {
		if !asked[g] {
			*p = append(*p, fmt.Sprintf("%s doesn't ask for %q", mf.Name, g))
		}
		if seen[g] {
			*p = append(*p, fmt.Sprintf("%q is listed twice", g))
		}
		seen[g] = true
	}
}

func checkLimits(p *apps.Problems, l *apps.Limits) {
	if l == nil {
		return
	}
	if l.MemoryMB < 0 || l.MemoryMB > 1<<22 || (l.MemoryMB > 0 && l.MemoryMB < 64) {
		*p = append(*p, "memory limit: 0 for none, or at least 64 MB")
	}
	if l.CPUs < 0 || l.CPUs > maxLimitCPU {
		*p = append(*p, "CPU limit: 0 for none, or a number of CPUs like 1.5")
	}
}

// checkLocalUsers makes sure HardyOS user names in an access list exist.
func (s *Server) checkAccess(ctx context.Context, p *apps.Problems, in []appstore.Principal) []appstore.Principal {
	list, err := appstore.NormalizePrincipals(in)
	if err != nil {
		*p = append(*p, err.Error())
		return nil
	}
	for _, pr := range list {
		if pr.Kind == appstore.KindUser && !pr.Domain() {
			if _, err := s.users.GetByName(ctx, pr.Name); err != nil {
				*p = append(*p, fmt.Sprintf("there's no HardyOS user called %s", pr.Name))
			}
		}
	}
	return list
}

func (s *Server) handleAppInstall(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req AppInstallRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	st := s.appStore()
	pkg, err := s.loadRef(r.Context(), req.AppPackageRef)
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	mf := pkg.Manifest
	source := apps.Source(req.Source)
	sourceName := st.SourceNameOf(r.Context(), req.Source, req.Ref, req.CatalogID)
	o, err := s.appsStatus(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	sc := s.sourceChange(r.Context(), o, mf.ID, req.AppPackageRef, sourceName)
	if sc.differs && !req.ReplaceSource {
		writeError(w, http.StatusConflict, "replace_source_required",
			fmt.Sprintf("%s is already installed from somewhere else (%s); this package would take over its data and passwords. Confirm replaceSource to do that", mf.Name, sc.describe(req.Source, sourceName)))
		return
	}
	// Catch the quick mistakes before a long job; hardyd-priv checks again.
	var p apps.Problems
	checkPorts(&p, mf, req.Ports)
	plain, secret := splitSettings(&p, mf, req.Settings)
	if req.Pool != "" {
		if err := zfs.ValidPoolName(req.Pool); err != nil {
			p = append(p, err.Error())
		}
	}
	checkShares(&p, mf, req.Shares, true)
	checkGrants(&p, mf, source, req.Grants)
	if !source.Trusted() {
		for _, g := range appstore.MissingGrants(mf, req.Grants) {
			p = append(p, "allow this to install "+mf.Name+": "+g.Label)
		}
	}
	checkLimits(&p, req.Limits)
	var access []appstore.Principal
	if req.Access != nil {
		access = s.checkAccess(r.Context(), &p, req.Access)
	}
	if len(p) > 0 {
		s.writeAppError(w, p)
		return
	}
	params := appInstallParams{Source: req.Source, Ref: req.Ref, SourceName: sourceName, CatalogID: importedCatalog(req.AppPackageRef),
		ID: mf.ID, Name: mf.Name, Pool: req.Pool, Host: requestHost(r), Ports: req.Ports, Settings: plain,
		Shares: req.Shares, Grants: req.Grants, Limits: req.Limits}
	if len(secret) > 0 {
		b, _ := json.Marshal(secret)
		params.SecretRef = jobSecrets.put(string(b))
	}
	if req.Access != nil {
		if err := st.SetAccess(r.Context(), mf.ID, access); err != nil {
			internalError(s, w, err)
			return
		}
		s.record(r, u, "apps.access", mf.ID, audit.Success, describeAccess(access))
	}
	target := mf.ID + " " + mf.Version
	if source != apps.SourceCatalog {
		target += " (" + req.Source + ")"
	}
	if sc.differs {
		s.record(r, u, "apps.replace_source", mf.ID, audit.Success, sc.describe(req.Source, sourceName))
	}
	s.recordGrants(r, u, mf.ID, nil, req.Grants)
	s.submit(w, r, u, JobKindAppInstall, "Install "+mf.Name+" "+mf.Version, params, "apps.install", target, nil)
}

// recordGrants audits each extra permission given or taken away.
func (s *Server) recordGrants(r *http.Request, u *auth.User, id string, before, after []string) {
	had := map[string]bool{}
	for _, g := range before {
		had[g] = true
	}
	has := map[string]bool{}
	for _, g := range after {
		has[g] = true
		if !had[g] {
			s.record(r, u, "apps.grant", id+" "+g, audit.Success, "extra permission ticked by an administrator")
		}
	}
	for _, g := range before {
		if !has[g] {
			s.record(r, u, "apps.grant.remove", id+" "+g, audit.Success, "")
		}
	}
}

func describeAccess(list []appstore.Principal) string {
	if len(list) == 0 || list[0].Kind == appstore.KindEveryone {
		return "everyone"
	}
	names := make([]string, 0, len(list))
	for _, p := range list {
		names = append(names, p.Kind+":"+p.Name)
	}
	return strings.Join(names, ", ")
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

// AppUpdateRequest updates an app: to its catalog's newest version when
// source and ref are left out.
type AppUpdateRequest struct {
	AppPackageRef
	// Grants replaces the app's extra permissions, for an update that asks
	// for a new one (apps not from HardyOS's catalog); omitted keeps them.
	Grants *[]string `json:"grants,omitempty"`
	// ReplaceSource confirms updating with a package from another source or
	// catalog than the app came from (see AppInstallRequest).
	ReplaceSource bool `json:"replaceSource,omitempty"`
}

// importedCatalog is the catalog id of an imported package ref (0 otherwise).
func importedCatalog(ref AppPackageRef) int64 {
	if ref.Source == appstore.SourceImported {
		return ref.CatalogID
	}
	return 0
}

// GrantsNeeded answers an update that asks for permissions the app doesn't
// have yet: the administrator ticks each and sends the update again.
type GrantsNeeded struct {
	ErrorResponse
	Grants []appstore.EntryGrant `json:"grants"`
}

func (s *Server) handleAppUpdate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req AppUpdateRequest
	if r.ContentLength != 0 && !decodeJSON(w, r, &req) {
		return
	}
	ref := req.AppPackageRef
	a, ok := s.installedApp(w, r)
	if !ok {
		return
	}
	st := s.appStore()
	if ref.Source == "" {
		switch a.Source {
		case apps.SourceCatalog:
			ref = AppPackageRef{Source: appstore.SourceCatalog, Ref: a.ID}
		case apps.SourceImported:
			_, sha, catalogID := s.importedLatest(r.Context(), *a)
			if sha == "" {
				writeError(w, http.StatusNotFound, "not_found", "the imported catalog "+a.Name+" came from ("+a.SourceName+") doesn't list it any more")
				return
			}
			ref = AppPackageRef{Source: appstore.SourceImported, Ref: sha, CatalogID: catalogID}
		default:
			writeError(w, http.StatusBadRequest, "invalid", a.Name+" was "+map[apps.Source]string{apps.SourceUpload: "uploaded", apps.SourceCustom: "made here"}[a.Source]+": choose the new package to update it")
			return
		}
	}
	pkg, err := s.loadRef(r.Context(), ref)
	if err != nil {
		s.writeAppError(w, err)
		return
	}
	if pkg.Manifest.ID != a.ID {
		writeError(w, http.StatusBadRequest, "invalid", "that package is "+pkg.Manifest.Name+", not "+a.Name)
		return
	}
	sourceName := st.SourceNameOf(r.Context(), ref.Source, ref.Ref, ref.CatalogID)
	o, err := s.appsStatus(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	sc := s.sourceChange(r.Context(), o, a.ID, ref, sourceName)
	if sc.differs && !req.ReplaceSource {
		writeError(w, http.StatusConflict, "replace_source_required",
			fmt.Sprintf("%s came from somewhere else (%s); confirm replaceSource to update it with this package", a.Name, sc.describe(ref.Source, sourceName)))
		return
	}
	if sc.differs {
		s.record(r, u, "apps.replace_source", a.ID, audit.Success, sc.describe(ref.Source, sourceName))
	}
	params := appInstallParams{Source: ref.Source, Ref: ref.Ref, SourceName: sourceName, CatalogID: importedCatalog(ref), ID: a.ID, Name: a.Name}
	mf := pkg.Manifest
	if !apps.Source(ref.Source).Trusted() {
		var p apps.Problems
		if req.Grants != nil {
			checkGrants(&p, mf, apps.Source(ref.Source), *req.Grants)
		}
		if len(p) > 0 {
			s.writeAppError(w, p)
			return
		}
		have := a.Grants
		if req.Grants != nil {
			have = *req.Grants
		}
		// Asking before the snapshot: the engine would refuse the new
		// version until each new permission is allowed.
		if missing := appstore.MissingGrants(mf, have); len(missing) > 0 {
			resp := GrantsNeeded{ErrorResponse: ErrorResponse{Code: "grants_required",
				Message: fmt.Sprintf("%s %s asks for permissions it doesn't have yet; tick each one to update", a.Name, mf.Version)}, Grants: missing}
			for _, g := range missing {
				resp.Details = append(resp.Details, g.Label)
			}
			writeJSON(w, http.StatusBadRequest, resp)
			return
		}
		if req.Grants != nil {
			params.Grants = *req.Grants
			s.recordGrants(r, u, a.ID, a.Grants, *req.Grants)
		}
	} else if req.Grants != nil {
		writeError(w, http.StatusBadRequest, "invalid", "apps from HardyOS's catalog get the permissions they declare; there's nothing to tick")
		return
	}
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
	if !confirmsApp(conf, id, name) {
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

// confirmsApp reports whether a typed confirmation names the app.
func confirmsApp(typed, id, name string) bool {
	typed = strings.TrimSpace(typed)
	return typed != "" && (strings.EqualFold(typed, name) || typed == id)
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
	case errors.Is(err, appstore.ErrNoDB):
		writeError(w, http.StatusServiceUnavailable, "unavailable", err.Error())
	default:
		internalError(s, w, err)
	}
}

// writeAppOrPrivError answers an error from the store or the root helper.
func (s *Server) writeAppOrPrivError(w http.ResponseWriter, err error) {
	var pe *priv.Error
	if errors.As(err, &pe) {
		s.writePrivError(w, err)
		return
	}
	s.writeAppError(w, err)
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
