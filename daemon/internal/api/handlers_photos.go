package api

// Photos (docs/photos.md): HardyOS sets up the Immich catalog app as the
// desktop's Photos. Every change to Immich runs in a photos.* job (locked
// with the app's own jobs, "app:immich"), started by an administrator's
// request or by RunPhotos when something it depends on changed (the app
// was installed or changed, publishing changed, a VM gave a GPU back, a
// new person signed in to Immich). internal/photos does the Immich side;
// this file gathers what it needs from the rest of HardyOS.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/devices"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/oidc"
	"github.com/hardyos/hardyos/daemon/internal/photos"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/publish"
	"github.com/hardyos/hardyos/daemon/internal/shares"
)

// Photos job kinds.
const (
	JobKindPhotosSync     = "photos.sync"
	JobKindPhotosSettings = "photos.settings"
	JobKindPhotosLink     = "photos.link"
)

var (
	errPhotosNotInstalled = errors.New("Immich isn't installed: install it from the App Store (Discover > Immich)")
	errPhotosNotCatalog   = errors.New("the installed Immich didn't come from HardyOS's catalog; Photos only sets up the catalog's Immich")
	errPhotosAccess       = errors.New("your account isn't one of the people who may use Photos; ask an administrator")
)

type photosSettingsParams struct {
	Settings photos.Settings `json:"settings"`
}

type photosLinkParams struct {
	KeyRef string `json:"keyRef"`
}

// photosState is RunPhotos' bookkeeping: the last job it started, and the
// nudge that starts a sync soon (an account or who may use Immich
// changed).
type photosState struct {
	mu          sync.Mutex
	lastJob     string
	nudge       chan struct{}
	accessPrint string
}

// AppNewDataSetting is set ("1") by an install that started the app from
// empty data, "" by one that picked kept data back up.
func AppNewDataSetting(appID string) string { return "apps.new_data." + appID }

func (s *Server) newPhotos() {
	if s.cfg.DB == nil || s.oidc == nil {
		return
	}
	s.photos = &photos.Store{DB: s.cfg.DB, Secrets: s.cfg.Secrets}
	s.photosRun.nudge = make(chan struct{}, 1)
	if s.cfg.Jobs != nil {
		s.registerPhotosJobs(s.cfg.Jobs)
	}
}

// photosAccess lets only the people who may use the Immich app sign in to
// it with HardyOS (oidc.Config.ManagedAccess).
func (s *Server) photosAccess(ctx context.Context, key string, u *auth.User) error {
	if key != photos.ClientKey {
		return nil
	}
	rules, err := s.appStore().Access(ctx, photos.AppID)
	if err != nil {
		return err
	}
	if !appstore.MayUse(rules, whoOf(u)) {
		return errPhotosAccess
	}
	return nil
}

func (s *Server) registerPhotosJobs(m *jobs.Manager) {
	lock := func(json.RawMessage) string { return "app:" + photos.AppID }
	m.Register(jobs.Kind{Name: JobKindPhotosSync, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		return s.photosSync(jc)
	}})
	m.Register(jobs.Kind{Name: JobKindPhotosSettings, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p photosSettingsParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		if _, err := s.photos.SaveSettings(jc, p.Settings); err != nil {
			return nil, err
		}
		return s.photosSync(jc)
	}})
	m.Register(jobs.Kind{Name: JobKindPhotosLink, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p photosLinkParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		key, ok := jobSecrets.take(p.KeyRef)
		if !ok {
			return nil, errSecretLost
		}
		a, err := s.photosApp(jc)
		if err != nil {
			return nil, err
		}
		jc.Progress(10, "Checking the key with Immich")
		rec := s.photosReconciler(a)
		ctx, cancel := context.WithTimeout(jc, time.Minute)
		err = rec.Link(ctx, key)
		cancel()
		if err != nil {
			return nil, err
		}
		return s.photosSync(jc)
	}})
}

// photosApp is the installed Immich, if it's the catalog's.
func (s *Server) photosApp(ctx context.Context) (*apps.App, error) {
	o, err := s.photosOverview(ctx)
	if err != nil {
		return nil, err
	}
	for i := range o.Apps {
		if a := &o.Apps[i]; a.ID == photos.AppID {
			if a.Source != apps.SourceCatalog {
				return a, errPhotosNotCatalog
			}
			if a.Web == nil || a.Web.Port == 0 {
				return a, errors.New("Immich has no web port")
			}
			return a, nil
		}
	}
	return nil, errPhotosNotInstalled
}

func (s *Server) photosOverview(ctx context.Context) (*apps.Overview, error) {
	if s.cfg.Priv == nil {
		return nil, errors.New("the root helper isn't available")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var o apps.Overview
	if err := s.cfg.Priv.Call(ctx, priv.OpAppsStatus, nil, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// photosNudge asks RunPhotos for a sync soon: a HardyOS account, its
// role, or who may use Immich changed, and Immich must follow.
func (s *Server) photosNudge() {
	if s.photos == nil || s.photosRun.nudge == nil {
		return
	}
	select {
	case s.photosRun.nudge <- struct{}{}:
	default:
	}
}

// photosConfirmRedirect: a sign-in for Immich's phone app (its mobile
// redirect) is always confirmed on HardyOS's page.
func photosConfirmRedirect(key, uri string) bool {
	return key == photos.ClientKey && strings.HasSuffix(uri, "/api/oauth/mobile-redirect")
}

func (s *Server) photosReconciler(a *apps.App) *photos.Reconciler {
	return &photos.Reconciler{
		Immich: &photos.Immich{Base: "http://127.0.0.1:" + strconv.Itoa(a.Web.Port)},
		Store:  s.photos,
		Dir:    photosDirectory{s},
		Log:    s.log,
		Audit:  s.recordSystem,
	}
}

// photosDirectory is the Directory internal/photos asks about accounts.
type photosDirectory struct{ s *Server }

func (d photosDirectory) UserByID(ctx context.Context, id int64) (*auth.User, error) {
	u, err := d.s.oidcUser(ctx, id)
	if err != nil {
		return nil, nil
	}
	return u, nil
}

func (d photosDirectory) Profile(ctx context.Context, u *auth.User) (*oidc.AppProfile, error) {
	return d.s.oidc.ProfileFor(ctx, u)
}

func (d photosDirectory) UserForSubject(ctx context.Context, sub string) (*auth.User, error) {
	return d.s.oidc.UserForSubject(ctx, sub)
}

func (d photosDirectory) People(ctx context.Context) ([]*auth.User, error) {
	return d.s.users.List(ctx)
}

// photosSync runs one sync and saves its status. Immich not installed,
// not the catalog's, or needing a link aren't failures: the status says so.
func (s *Server) photosSync(jc *jobs.Context) (*photos.Status, error) {
	st := &photos.Status{At: time.Now().UTC(), Notes: []string{}, Libraries: []photos.LibraryState{},
		People: []photos.PersonState{}, SSO: photos.SSOState{RedirectURIs: []string{}}}
	err := s.photosSyncInto(jc, st)
	if err != nil {
		st.Problem = err.Error()
	}
	if serr := s.photos.SaveStatus(context.WithoutCancel(jc), st); serr != nil {
		s.log.Warn("photos: saving the status", "err", serr)
	}
	if len(st.Notes) > 0 {
		s.recordSystem(context.WithoutCancel(jc), "photos.sync", photos.AppID, strings.Join(st.Notes, "; "))
	}
	if st.Incident != "" {
		s.recordSystem(context.WithoutCancel(jc), "photos.incident", photos.AppID, st.Incident)
		if s.cfg.Alerts != nil {
			s.cfg.Alerts.Notify(context.WithoutCancel(jc), notify.Event{Kind: "security.photos", Severity: notify.SeverityCritical,
				Title: "Photos: Immich has an administrator HardyOS didn't make", Body: st.Incident, Link: "control-panel/photos"})
		}
	}
	if err != nil && !errors.Is(err, photos.ErrNeedsLink) && !errors.Is(err, errPhotosNotInstalled) && !errors.Is(err, errPhotosNotCatalog) {
		return st, err
	}
	return st, nil
}

func (s *Server) photosSyncInto(jc *jobs.Context, st *photos.Status) error {
	ctx := context.Context(jc)
	jc.Progress(5, "Looking at Immich")
	o, err := s.photosOverview(ctx)
	if err != nil {
		return err
	}
	var a *apps.App
	for i := range o.Apps {
		if o.Apps[i].ID == photos.AppID {
			a = &o.Apps[i]
		}
	}
	if a == nil {
		kept := slices.ContainsFunc(o.KeptData, func(k apps.KeptAppData) bool { return k.ID == photos.AppID })
		if !kept {
			// Removed with its data: the accounts HardyOS made there are
			// gone, and so is what its sign-in client was for.
			if err := s.photos.ForgetImmich(ctx); err != nil {
				return err
			}
			s.photosForgetClient(ctx)
		}
		return errPhotosNotInstalled
	}
	st.Installed, st.Version = true, a.Version
	if a.Source != apps.SourceCatalog {
		return errPhotosNotCatalog
	}
	st.Catalog = true
	if a.Web == nil || a.Web.Port == 0 {
		return errors.New("Immich has no web port")
	}
	set, err := s.photos.Settings(ctx)
	if err != nil {
		return err
	}
	// HardyOS's administrator account first, before anything slow: in a
	// fresh Immich nobody else may make one.
	fresh := false
	if v, err := s.cfg.DB.GetSetting(ctx, AppNewDataSetting(a.ID)); err == nil && v == "1" {
		fresh = true
	}
	jc.Progress(8, "Signing in to Immich")
	rec := s.photosReconciler(a)
	if _, err := rec.EnsureAdmin(ctx, fresh, st); err != nil {
		return err
	}

	// Machine learning on the GPU HardyOS finds, the processor otherwise.
	jc.Progress(10, "Choosing where machine learning runs")
	st.ML = photos.ChooseML(set.MLAcceleration, s.photosGPUs(ctx), runtime.GOARCH)
	if err := s.photosApplyML(jc, a, st.ML, st); err != nil {
		return err
	}

	// Where Immich is reached: its published address and the desktop's
	// window for it.
	var published string
	var pset publish.Settings
	if pub := s.cfg.Remote; pub != nil {
		pset, _ = pub.Store.Load(ctx)
		if items, err := pub.Items(ctx, publish.Inputs{Apps: []publish.App{{ID: a.ID, Name: a.Name}}}); err == nil {
			for _, it := range items {
				if it.Key != publish.AppKey(a.ID) || it.Domain == "" || it.Config.Mode == publish.ModeOff || !pset.Enabled {
					continue
				}
				published = "https://" + it.Domain
				if it.Published {
					st.PublishedURL = published
				}
				st.PhoneReady = it.Published && !it.Config.HardyOSSignIn &&
					(it.Config.Mode == publish.ModeNetBird || it.Config.Auth == publish.AuthNone)
				if it.Published && !st.PhoneReady {
					st.Notes = append(st.Notes, "Immich's published address asks for a sign-in in front (HardyOS sign-in or NetBird SSO), which the Immich phone app can't do: publish it with \"Phone backup from anywhere\" in Control Panel > Photos")
				}
			}
		}
	}
	var others []string
	if ports, err := s.appStore().ProxyPorts(ctx); err == nil && ports[a.ID] > 0 && s.cfg.PublicHost != nil {
		if h := s.cfg.PublicHost(); h != "" {
			others = append(others, "https://"+h+":"+strconv.Itoa(ports[a.ID]))
		}
	}

	// Sign-in with HardyOS: only with the provider at sso.<base>, whose
	// certificate Immich's server can check (the desktop's own is
	// self-signed).
	issuer := s.oidc.Issuer(ctx)
	ssoReady := pset.Enabled && pset.BaseDomain != "" && issuer == publish.SSOIssuerFor(pset.BaseDomain)
	w := photos.Wanted{PasswordLogin: set.PasswordLogin, DefaultQuotaGiB: set.DefaultQuotaGiB,
		MLURLs: photos.MLURLs(st.ML.Mode), ScanCron: set.ScanCron(), Watch: set.Watch, ExternalDomain: st.PublishedURL}
	plan := photos.Plan{Settings: set, Shares: map[string]bool{}, FreshInstall: fresh,
		Links: map[string]*shares.LinkScan{}, LinkErrors: map[string]string{}}
	used := map[string]bool{}
	for _, l := range set.Libraries {
		used[l.Share] = true
	}
	if set.Family.Enabled {
		used[photos.FamilyShare] = true
	}
	for _, sh := range a.Shares {
		if sh.Share == "" {
			continue
		}
		plan.Shares[sh.Name] = true
		if used[sh.Name] {
			// Links leading out of the folder: Immich's crawler would follow
			// them to whatever the container has there.
			jc.Progress(20, "Checking "+sh.Share+" for links that lead out of it")
			var scan shares.LinkScan
			if err := s.cfg.Priv.Call(ctx, priv.OpSharesLinks, priv.ShareLinksArgs{ID: sh.Share}, &scan); err != nil {
				plan.LinkErrors[sh.Name] = err.Error()
			} else {
				plan.Links[sh.Name] = &scan
			}
		}
	}
	if plan.Access, err = s.appStore().Access(ctx, a.ID); err != nil {
		return err
	}
	switch {
	case set.SSO && ssoReady:
		uris := photos.RedirectURIs(published, others)
		jc.Progress(25, "Keeping Immich's sign-in client")
		id, secret, err := s.photosClient(ctx, uris)
		if err != nil {
			return err
		}
		o := &photos.OAuth{Issuer: issuer, ClientID: id, ClientSecret: secret, AutoLaunch: set.AutoLaunch}
		if published != "" {
			o.MobileRedirect = photos.MobileRedirect(published)
		} else {
			st.Notes = append(st.Notes, "Immich isn't published, so the phone app can only sign in with HardyOS once it is (Control Panel > Photos > Phone backup from anywhere)")
		}
		w.OAuth = o
		st.SSO = photos.SSOState{Issuer: issuer, ClientID: id, RedirectURIs: uris}
		plan.CheckOAuthFrom = uris[0]
	case set.SSO:
		st.SSO.Why = "Sign-in with HardyOS needs Remote Access publishing with a base domain: Immich's server signs people in through https://sso.<base>, whose certificate it can check (the desktop's own is self-signed)"
		s.photosForgetClient(ctx)
	default:
		s.photosForgetClient(ctx)
	}
	plan.Wanted = w

	jc.Progress(40, "Configuring Immich")
	return rec.Run(ctx, plan, st)
}

// photosGPUs lists the server's GPUs from the devices inventory (none when
// it can't be read: Immich then uses the processor).
func (s *Server) photosGPUs(ctx context.Context) []photos.GPU {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var inv devices.Inventory
	if err := s.cfg.Priv.Call(ctx, priv.OpDevicesInventory, nil, &inv); err != nil {
		s.log.Debug("photos: no devices inventory", "err", err)
		return nil
	}
	var out []photos.GPU
	for _, g := range inv.GPUs {
		out = append(out, photos.GPU{Vendor: g.Vendor, Model: g.Model, Driver: g.Driver, Owner: g.Owner.Kind, VM: g.Owner.VM, Assigned: len(g.Assigned) > 0})
	}
	return out
}

// photosApplyML turns the accelerated machine learning service for the
// chosen mode on (downloading its image first) and the others off, through
// the apps engine's named operations, and starts it again once a GPU is
// back from a VM.
func (s *Server) photosApplyML(jc *jobs.Context, a *apps.App, ch photos.MLChoice, st *photos.Status) error {
	pc := s.cfg.Priv
	svcName := photos.MLService(ch.Mode)
	applied := s.photos.MLApplied(jc)
	if applied == "" {
		// A fresh install runs on the processor (the package's defaults).
		applied = photos.MLCPU
	}
	has := func(svc string) bool {
		return slices.ContainsFunc(a.Containers, func(c apps.Container) bool { return c.Service == svc })
	}
	running := func(svc string) bool {
		return slices.ContainsFunc(a.Containers, func(c apps.Container) bool {
			return c.Service == svc && (c.State == "running" || c.State == "restarting")
		})
	}
	// What runs can differ from what was recorded (Immich reinstalled with
	// its defaults, a rollback): a service with 0 replicas has no container.
	if applied == ch.Mode && len(a.Containers) > 0 {
		for _, m := range photos.AccelModes {
			if (m == ch.Mode) != has(photos.MLService(m)) {
				applied = ""
			}
		}
	}
	// An app an administrator stopped stays stopped: the change applies at
	// its next start.
	up := running(photos.ServerService)
	if applied != ch.Mode {
		if svcName != "" {
			var sv priv.AppServicesResult
			if err := pc.Call(jc, priv.OpAppsServices, priv.AppRef{ID: a.ID}, &sv); err != nil {
				return err
			}
			var pull []apps.ServiceImage
			for _, x := range sv.Services {
				if x.Service == svcName {
					x.Idle = false
					pull = append(pull, x)
				}
			}
			if len(pull) == 0 {
				return errors.New("this Immich package has no " + svcName + " service: update Immich in the App Store")
			}
			if _, err := pullImages(jc, pc, a.ID, pull, 10, 20); err != nil {
				return err
			}
		}
		jc.Progress(20, "Setting Immich's machine learning to "+ch.Mode)
		ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
		var prep apps.PrepareResult
		err := pc.Call(ctx, priv.OpAppsReconfigure, apps.ReconfigureArgs{ID: a.ID, Settings: photos.MLSettings(ch.Mode)}, &prep)
		cancel()
		if err != nil {
			return err
		}
		if up {
			if err := appUp(jc, pc, a.ID); err != nil {
				return err
			}
		}
		if err := s.photos.SetMLApplied(jc, ch.Mode); err != nil {
			return err
		}
		st.Notes = append(st.Notes, "Machine learning now runs on "+mlWords(ch.Mode))
		return nil
	}
	if svcName == "" || ch.Lent || !up || running(svcName) {
		return nil
	}
	// The GPU is back (a VM that had it stopped): start its service again.
	if err := appUp(jc, pc, a.ID); err != nil {
		return err
	}
	st.Notes = append(st.Notes, "Started GPU machine learning again")
	return nil
}

func mlWords(mode string) string {
	switch mode {
	case photos.MLCUDA:
		return "the NVIDIA GPU (CUDA)"
	case photos.MLOpenVINO:
		return "the Intel GPU (OpenVINO)"
	case photos.MLROCm:
		return "the AMD GPU (ROCm)"
	}
	return "the processor"
}

// photosClient keeps the sign-in client for Immich with exactly these
// redirect URIs and returns its id and secret (sealed in Photos' store; a
// lost secret is replaced). Changes are audited as HardyOS's own.
func (s *Server) photosClient(ctx context.Context, uris []string) (string, string, error) {
	before, err := s.oidc.Clients.Managed(ctx, photos.ClientKey)
	if err != nil && !errors.Is(err, oidc.ErrNotFound) {
		return "", "", err
	}
	id, secret, err := s.oidc.Clients.Ensure(ctx, photos.ClientKey, "Photos (Immich)", uris, nil)
	if err != nil {
		return "", "", err
	}
	if before == nil {
		s.recordSystem(ctx, "oidc.client.create", "Photos (Immich) ("+id+")", "kept by Photos; redirects "+strings.Join(uris, " "))
	} else {
		old := slices.Clone(before.RedirectURIs)
		slices.Sort(old)
		now := slices.Clone(uris)
		slices.Sort(now)
		if !slices.Equal(old, now) {
			added, removed := diffLists(old, now)
			s.recordSystem(ctx, "oidc.client.update", "Photos (Immich) ("+id+")",
				"kept by Photos; redirects added: "+strings.Join(added, " ")+"; removed: "+strings.Join(removed, " "))
		}
	}
	if secret == "" {
		saved, err := s.photos.Client(ctx)
		if err != nil {
			return "", "", err
		}
		if saved.ID == id && saved.Secret != "" {
			return id, saved.Secret, nil
		}
		if id, secret, err = s.oidc.Clients.EnsuredSecret(ctx, photos.ClientKey); err != nil {
			return "", "", err
		}
		s.recordSystem(ctx, "oidc.client.secret", "Photos (Immich) ("+id+")", "kept by Photos; a new secret (the saved one couldn't be read)")
	}
	if err := s.photos.SaveClient(ctx, photos.ClientCreds{ID: id, Secret: secret}); err != nil {
		return "", "", err
	}
	return id, secret, nil
}

// photosForgetClient removes the sign-in client when sign-in with HardyOS
// is off (Immich's configuration loses the secret in the same sync).
func (s *Server) photosForgetClient(ctx context.Context) {
	c, err := s.oidc.Clients.Managed(ctx, photos.ClientKey)
	if err != nil {
		return
	}
	if err := s.oidc.Clients.Forget(ctx, photos.ClientKey); err != nil {
		s.log.Warn("photos: removing the sign-in client", "err", err)
		return
	}
	_ = s.photos.SaveClient(ctx, photos.ClientCreds{})
	s.recordSystem(ctx, "oidc.client.delete", "Photos (Immich) ("+c.ID+")", "sign-in with HardyOS is off for Photos")
}

// ---- background -----------------------------------------------------------

// PhotosOptions tune RunPhotos (tests make them short).
type PhotosOptions struct {
	// CheckEvery: how often it looks for something to do (default 5 min).
	CheckEvery time.Duration
	// SyncEvery: a full sync at least this often (default 6 hours).
	SyncEvery time.Duration
	// StartDelay: the first sync after hardyd starts (default 1 min).
	StartDelay time.Duration
	// Debounce after an event (default 5 s).
	Debounce time.Duration
}

// RunPhotos keeps Photos set up until ctx ends: a sync after hardyd
// starts, after the Immich app's jobs, publishing and VM jobs finish, at
// least every SyncEvery, and whenever the periodic check finds work (a
// GPU back from a VM, someone new signed in to Immich).
func (s *Server) RunPhotos(ctx context.Context, opts PhotosOptions) {
	if s.photos == nil || s.cfg.Jobs == nil || s.cfg.Priv == nil {
		return
	}
	if opts.CheckEvery == 0 {
		opts.CheckEvery = 5 * time.Minute
	}
	if opts.SyncEvery == 0 {
		opts.SyncEvery = 6 * time.Hour
	}
	if opts.StartDelay == 0 {
		opts.StartDelay = time.Minute
	}
	if opts.Debounce == 0 {
		opts.Debounce = 5 * time.Second
	}
	sub := s.cfg.Events.Subscribe(0, true, 256)
	defer s.cfg.Events.Unsubscribe(sub)
	check := time.NewTicker(opts.CheckEvery)
	defer check.Stop()
	full := time.NewTicker(opts.SyncEvery)
	defer full.Stop()
	start := time.After(opts.StartDelay)
	var debounce <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-start:
			if _, err := s.photosApp(ctx); err == nil {
				s.photosKick(ctx)
			}
		case <-full.C:
			if _, err := s.photosApp(ctx); err == nil {
				s.photosKick(ctx)
			}
		case <-check.C:
			if s.photosNeedsSync(ctx) {
				s.photosKick(ctx)
			}
		case <-debounce:
			debounce = nil
			s.photosKick(ctx)
		case <-s.photosRun.nudge:
			if _, err := s.photosApp(ctx); err == nil {
				debounce = time.After(opts.Debounce)
			}
		case e, ok := <-sub.C:
			if !ok {
				return
			}
			if photosTrigger(e) {
				debounce = time.After(opts.Debounce)
			}
		}
	}
}

// photosTrigger: a finished job that can change what Photos applies.
func photosTrigger(e events.Event) bool {
	if e.Type != events.TypeJobUpdated {
		return false
	}
	if finishedAppJob(e) == photos.AppID {
		return true
	}
	var j struct {
		Kind  string     `json:"kind"`
		State jobs.State `json:"state"`
	}
	if json.Unmarshal(e.Data, &j) != nil || !j.State.Done() {
		return false
	}
	return strings.HasPrefix(j.Kind, "remote.") || strings.HasPrefix(j.Kind, "vms.") || strings.HasPrefix(j.Kind, "domain.") ||
		j.Kind == JobKindOIDCSettings || j.Kind == JobKindNvidiaInstall || j.Kind == JobKindNvidiaRemove
}

// photosAccessPrint sums up what decides who has an Immich account and
// who is an Immich administrator: every HardyOS account's state, role and
// groups, and Immich's access list. A change starts a sync.
func (s *Server) photosAccessPrint(ctx context.Context) string {
	users, err := s.users.List(ctx)
	if err != nil {
		return ""
	}
	rules, err := s.appStore().Access(ctx, photos.AppID)
	if err != nil {
		return ""
	}
	h := sha256.New()
	lines := make([]string, 0, len(users)+1)
	for _, u := range users {
		lines = append(lines, fmt.Sprintf("%d\x00%s\x00%s\x00%v\x00%s\x00%s", u.ID, u.IdentityPrincipal(), u.Role, u.Disabled, u.Email, strings.Join(u.IdentityGroups(), "\x01")))
	}
	slices.Sort(lines)
	b, _ := json.Marshal(rules)
	lines = append(lines, string(b))
	for _, l := range lines {
		h.Write([]byte(l + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// photosKick starts a sync unless one is already waiting or running.
func (s *Server) photosKick(ctx context.Context) {
	s.photosRun.mu.Lock()
	defer s.photosRun.mu.Unlock()
	if id := s.photosRun.lastJob; id != "" {
		if j, err := s.cfg.Jobs.Get(ctx, id); err == nil && !j.State.Done() {
			return
		}
	}
	j, err := s.cfg.Jobs.Submit(ctx, JobKindPhotosSync, "Keep Photos set up", map[string]string{"id": photos.AppID}, nil)
	if err != nil {
		s.log.Warn("photos: starting a sync", "err", err)
		return
	}
	s.photosRun.lastJob = j.ID
}

// photosNeedsSync is the cheap periodic check: is a GPU service down while
// its GPU is back, or has someone new signed in to Immich since the last
// sync (they may need the family library)?
func (s *Server) photosNeedsSync(ctx context.Context) bool {
	a, err := s.photosApp(ctx)
	if err != nil {
		return false
	}
	last, err := s.photos.Status(ctx)
	if err != nil || last == nil || last.Version != a.Version {
		return true
	}
	if !last.Linked && !last.NeedsLink && last.Incident == "" {
		// HardyOS hasn't made its administrator yet: keep trying.
		return true
	}
	if fp := s.photosAccessPrint(ctx); fp != "" {
		s.photosRun.mu.Lock()
		changed := fp != s.photosRun.accessPrint
		s.photosRun.accessPrint = fp
		s.photosRun.mu.Unlock()
		if changed {
			return true
		}
	}
	if svc := photos.MLService(last.ML.Mode); svc != "" {
		up, down := false, false
		for _, c := range a.Containers {
			live := c.State == "running" || c.State == "restarting"
			switch c.Service {
			case photos.ServerService:
				up = live
			case svc:
				down = !live
			}
		}
		if up && down && !photos.ChooseML(last.ML.Mode, s.photosGPUs(ctx), runtime.GOARCH).Lent {
			return true
		}
	}
	set, err := s.photos.Settings(ctx)
	if err != nil || !set.Family.Enabled {
		return false
	}
	acct, err := s.photos.Account(ctx)
	if err != nil || acct.AdminKey == "" {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	users, err := s.photosReconciler(a).Immich.WithAPIKey(acct.AdminKey).Users(cctx)
	if err != nil {
		return false
	}
	known := map[string]bool{}
	for _, p := range last.People {
		if p.Linked {
			known[p.ImmichID] = true
		}
	}
	for _, u := range users {
		if u.OAuthID != "" && u.DeletedAt == "" && !known[u.ID] {
			return true
		}
	}
	return false
}

// ---- HTTP -------------------------------------------------------------------

func (s *Server) photosRoutes() {
	if s.photos == nil {
		return
	}
	m := s.mux
	m.Handle("GET /api/v1/photos", s.authed(s.handlePhotos))
	m.Handle("GET /api/v1/photos/settings", s.admin(s.handlePhotosSettings))
	m.Handle("PUT /api/v1/photos/settings", s.admin(s.handlePhotosSave))
	m.Handle("POST /api/v1/photos/sync", s.admin(s.handlePhotosSyncNow))
	m.Handle("POST /api/v1/photos/link", s.admin(s.handlePhotosLink))
}

// PhotosInfo is what the desktop needs for its Photos icon.
type PhotosInfo struct {
	// Installed: the catalog's Immich is installed.
	Installed bool `json:"installed"`
	// MayUse: this person may open it.
	MayUse bool   `json:"mayUse"`
	AppID  string `json:"appId"`
	// SSO: Immich signs people in with HardyOS.
	SSO bool `json:"sso"`
	// PublishedURL is Immich's address for phones ("" when not published).
	PublishedURL string `json:"publishedUrl"`
}

func (s *Server) handlePhotos(w http.ResponseWriter, r *http.Request, u *auth.User) {
	out := PhotosInfo{AppID: photos.AppID}
	if _, err := s.photosApp(r.Context()); err == nil {
		out.Installed = true
		rules, err := s.appStore().Access(r.Context(), photos.AppID)
		if err != nil {
			internalError(s, w, err)
			return
		}
		out.MayUse = appstore.MayUse(rules, s.appWho(r.Context(), sessionToken(r), u))
	}
	if st, _ := s.photos.Status(r.Context()); st != nil {
		out.SSO, out.PublishedURL = st.SSO.Active, st.PublishedURL
	}
	writeJSON(w, http.StatusOK, out)
}

// PhotosView is Control Panel > Photos.
type PhotosView struct {
	Settings photos.Settings `json:"settings"`
	// Status of the last sync (nil before the first).
	Status *photos.Status `json:"status"`
	// Shares the app was given a shared folder for, by the package's name.
	Shares []apps.AppShare `json:"shares"`
	// LibraryShares can hold personal libraries.
	LibraryShares []string `json:"libraryShares"`
	// Running: a Photos job is waiting or running.
	Running bool `json:"running"`
}

func (s *Server) handlePhotosSettings(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	set, err := s.photos.Settings(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	st, err := s.photos.Status(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	out := PhotosView{Settings: set, Status: st, Shares: []apps.AppShare{}, LibraryShares: photos.LibraryShares()}
	if a, err := s.photosApp(r.Context()); a != nil && err == nil {
		out.Shares = a.Shares
	}
	s.photosRun.mu.Lock()
	if id := s.photosRun.lastJob; id != "" && s.cfg.Jobs != nil {
		if j, err := s.cfg.Jobs.Get(r.Context(), id); err == nil && !j.State.Done() {
			out.Running = true
		}
	}
	s.photosRun.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePhotosSave(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req photos.Settings
	if !decodeJSON(w, r, &req) {
		return
	}
	set, err := req.Normalize()
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	detail := "sso=" + strconv.FormatBool(set.SSO) + " passwordLogin=" + strconv.FormatBool(set.PasswordLogin) +
		" ml=" + set.MLAcceleration + " libraries=" + strconv.Itoa(len(set.Libraries)) + " family=" + strconv.FormatBool(set.Family.Enabled)
	s.submit(w, r, u, JobKindPhotosSettings, "Change Photos settings", photosSettingsParams{Settings: set}, "photos.settings", detail, nil)
}

func (s *Server) handlePhotosSyncNow(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.submit(w, r, u, JobKindPhotosSync, "Set up Photos", map[string]string{"id": photos.AppID}, "photos.sync", photos.AppID, nil)
}

// PhotosLinkRequest links an Immich set up before Photos.
type PhotosLinkRequest struct {
	APIKey string `json:"apiKey"`
}

func (s *Server) handlePhotosLink(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req PhotosLinkRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	key := strings.TrimSpace(req.APIKey)
	if len(key) < 16 || len(key) > 512 {
		writeError(w, http.StatusBadRequest, "invalid", "paste an API key from an Immich administrator (Account Settings > API Keys)")
		return
	}
	s.submit(w, r, u, JobKindPhotosLink, "Link Immich to Photos", photosLinkParams{KeyRef: jobSecrets.put(key)}, "photos.link", photos.AppID, nil)
}
