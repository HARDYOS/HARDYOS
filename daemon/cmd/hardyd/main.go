// Command hardyd is the HardyOS control-plane API server. It runs as the
// unprivileged "hardyd" user and asks hardyd-priv for anything that needs root.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/api"
	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/backups"
	"github.com/hardyos/hardyos/daemon/internal/clientip"
	"github.com/hardyos/hardyos/daemon/internal/cloudbackups"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/install"
	"github.com/hardyos/hardyos/daemon/internal/installer"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/metrics"
	"github.com/hardyos/hardyos/daemon/internal/monitor"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/publish"
	"github.com/hardyos/hardyos/daemon/internal/replication"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/storage"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/tlscert"
	"github.com/hardyos/hardyos/daemon/internal/updates"
	"github.com/hardyos/hardyos/daemon/internal/version"
)

func main() {
	var (
		httpsAddr   = flag.String("https", ":443", "HTTPS address (empty disables HTTPS and serves the app over -http)")
		httpAddr    = flag.String("http", ":80", "HTTP address; redirects to HTTPS when HTTPS is enabled (empty disables)")
		tlsDir      = flag.String("tls-dir", "/var/lib/hardyos/tls", "directory for the HTTPS certificate")
		dbPath      = flag.String("db", store.DefaultPath, "SQLite database path")
		privSocket  = flag.String("priv-socket", priv.DefaultSocket, "hardyd-priv socket")
		webRoot     = flag.String("web-root", "/usr/share/hardyos/web", "directory holding the built web desktop (empty to disable)")
		logLevel    = flag.String("log-level", "info", "debug, info, warn or error")
		showVersion = flag.Bool("version", false, "print version and exit")
		proxies     = flag.String("trusted-proxies", "", "reverse proxies (addresses or CIDRs, comma separated) whose X-Forwarded-For is believed; empty for none")
	)
	flag.Parse()

	if *showVersion {
		v := version.Get()
		fmt.Printf("hardyd %s (%s) %s %s/%s\n", v.Version, v.Commit, v.GoVersion, v.OS, v.Arch)
		return
	}
	log := newLogger(*logLevel)
	slog.SetDefault(log)
	trusted, err := clientip.ParseTrusted(*proxies)
	if err != nil {
		log.Error("hardyd failed", "err", err)
		os.Exit(2)
	}
	if err := run(log, *httpsAddr, *httpAddr, *tlsDir, *dbPath, *privSocket, *webRoot, trusted); err != nil {
		log.Error("hardyd failed", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, httpsAddr, httpAddr, tlsDir, dbPath, privSocket, webRoot string, trustedProxies []netip.Prefix) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if webRoot != "" {
		if _, err := os.Stat(webRoot); err != nil {
			log.Warn("web root not found, serving API only", "web_root", webRoot)
			webRoot = ""
		}
	}

	db, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	broker := events.NewBroker()
	pc := priv.NewClient(privSocket)
	live := install.IsLive("/")
	if !live {
		// First boot after an install: create the administrator chosen in the installer.
		if u, err := installer.ApplySeed(ctx, &auth.Users{DB: db}, install.SeedFile); err != nil {
			log.Error("could not create the administrator from the installer", "err", err)
		} else if u != nil {
			log.Info("created the administrator chosen in the installer", "user", u.Username)
		}
	}

	jobCtx, cancelJobs := context.WithCancel(context.Background())
	manager := &jobs.Manager{DB: db, Events: broker, Logger: log, Workers: 4}
	notifications := &notify.Center{DB: db, Events: broker}
	collector := &metrics.Collector{Root: os.DirFS("/")}
	stor := &storage.Service{Priv: pc, Jobs: manager, DB: db, Notify: notifications, Log: log}
	api.RegisterJobKinds(manager, pc)
	stor.RegisterJobs(manager)
	var upd *updates.Service
	if !live {
		upd = &updates.Service{Priv: pc, Jobs: manager, Notify: notifications, DB: db, Log: log, Current: version.Version}
		upd.RegisterJobs(manager)
	}
	var bk *backups.Service
	if !live {
		bk = &backups.Service{DB: db, Priv: pc, Jobs: manager, Notify: notifications, Log: log, Current: version.Version}
		bk.RegisterJobs(manager)
	}
	// Versioned cloud backups: tasks, runs and the schedule here, restic in
	// hardyd-priv. Their events (kinds backup.*) go to the alert dispatcher
	// once it exists, below.
	var cloud *cloudbackups.Service
	if !live {
		cloud = &cloudbackups.Service{DB: db, Priv: pc, Jobs: manager, Notifier: cloudbackups.NopNotifier{}, Log: log, Version: version.Version}
		cloud.RegisterJobs(manager)
	}
	appStore := &appstore.Store{CatalogDir: appstore.DefaultCatalogDir, UploadDir: appstore.DefaultUploadDir, DB: db}
	if !live {
		api.RegisterAppJobs(manager, pc, appStore)
	}
	// Secrets hardyd keeps encrypted at rest (the sign-in provider's keys,
	// the NetBird access token) are sealed with keys from hardyd-priv (the
	// master key is root's).
	var secrets secretbox.Source
	if !live {
		secrets = &secretbox.PrivSource{Priv: pc}
	}
	// Remote access: the NetBird client and publishing through NetBird's
	// reverse proxy. api.New connects it to the sign-in provider (names,
	// issuer).
	var remote *publish.Publisher
	if !live {
		remote = &publish.Publisher{Store: &publish.Store{DB: db, Sealer: &publish.Sealer{Source: secrets}}}
	}
	api.RegisterRemoteJobs(manager, pc, remote)
	// Alerts and monitoring (docs/monitoring.md): every event goes through
	// the dispatcher (desktop, Discord/Slack/Teams, email), including the
	// notifications packages send through the center; the monitor checks
	// disks, pools, the UPS, apps, VMs and services and keeps resource
	// history in metrics.db next to the database.
	var alerts *notify.Dispatcher
	var mon *monitor.Service
	if !live {
		alerts = &notify.Dispatcher{DB: db, Center: notifications, Channels: &notify.Channels{DB: db, Keys: secrets}, Log: log}
		notifications.Forward = alerts.Forward
		history, err := monitor.OpenHistory(ctx, filepath.Join(filepath.Dir(dbPath), "metrics.db"))
		if err != nil {
			log.Error("resource history unavailable", "err", err)
			history = nil
		} else {
			defer history.Close()
		}
		mon = &monitor.Service{DB: db, Priv: pc, Notify: alerts, History: history, Log: log, Root: os.DirFS("/"),
			UPS: &monitor.UPSService{DB: db, Keys: secrets, Log: log}}
		if cloud != nil {
			cloud.Notifier = backupAlerts(alerts)
		}
		if remote != nil {
			mon.PublishErrors = func(ctx context.Context) (map[string]string, error) {
				recs, err := remote.Store.Records(ctx)
				if err != nil {
					return nil, err
				}
				out := map[string]string{}
				for k, r := range recs {
					if r.Error != "" {
						out[k] = r.Error
					}
				}
				return out, nil
			}
		}
		mon.AddSource(monitor.SystemSource{Collector: collector})
		mon.AddSource(&monitor.DiskIOSource{Root: os.DirFS("/")})
		mon.AddSource(monitor.HwmonSource{Root: os.DirFS("/")})
		mon.AddSource(&monitor.AppsSource{Root: os.DirFS("/"), CPUs: func() int { return collector.Snapshot().CPUs }, Names: mon.AppNames})
		mon.AddSource(monitor.UPSSource(mon.UPS))
		stor.HealthElsewhere = true
		stor.ScrubAllowed = mon.ScrubAllowed
		api.RegisterMonitorJobs(manager, mon, pc)
	}
	// File Manager and share links: files read and written as the person.
	var fileAccess files.Service
	if !live {
		fileAccess = &files.Client{Priv: pc, Lookup: files.UserLookup(&auth.Users{DB: db})}
		api.RegisterFileJobs(manager, fileAccess)
	}
	// Replication to and from other HardyOS servers. Its events (kinds
	// "replication.*", so they route as the replication category) go to
	// the alert dispatcher.
	var repl *replication.Service
	if !live {
		repl = &replication.Service{DB: db, Root: &replication.PrivRoot{Priv: pc}, Jobs: manager, Notifier: replNotifier{alerts},
			Audit: &audit.Log{DB: db, Events: broker}, Sealer: &replication.Sealer{Source: secrets}, Log: log}
		repl.RegisterJobs(manager)
	}
	var inst *installer.Service
	if live {
		inst = &installer.Service{Priv: pc, Jobs: manager, Limiter: auth.NewLoginLimiter()}
		inst.RegisterJobs(manager)
		log.Info("live installer mode: serving the web installer")
	}
	if err := manager.Start(jobCtx); err != nil {
		cancelJobs()
		return fmt.Errorf("start jobs: %w", err)
	}
	defer func() { cancelJobs(); manager.Wait() }()

	handler := api.New(api.Config{
		DB: db, Jobs: manager, Events: broker, Priv: pc, Logger: log,
		Storage: stor, Notify: notifications, Metrics: collector,
		WebRoot: webRoot, Insecure: httpsAddr == "", Installer: inst, Updates: upd, Backups: bk, CloudBackups: cloud,
		Apps: appStore, Files: fileAccess, TrustedProxies: trustedProxies, Secrets: secrets, Remote: remote,
		Replication: repl,
		Alerts:      alerts, Monitor: mon,
	})

	go housekeeping(ctx, log, &auth.Sessions{DB: db})
	go collector.Run(ctx) // CPU, memory and network history
	if !live {
		go stor.Run(ctx) // snapshot, scrub and SMART schedules
		// After an update, confirm the new version once it has stayed up for
		// a minute and report the result.
		go upd.ConfirmWhenHealthy(ctx, time.Minute)
		go upd.RunChecks(ctx) // look for new versions on GitHub daily
		go bk.Run(ctx)        // nightly settings backup
		go cloud.Run(ctx)     // cloud backup schedules, prunes and checks
		go repl.Run(ctx)      // replication schedule, stale alerts, receiving from other servers
		go alerts.Run(ctx)    // alert delivery and quiet-hours summaries
		go mon.Run(ctx)       // checks, self-test schedule, UPS, resource history
		if p := handler.OIDC(); p != nil {
			go p.Start(ctx) // sign-in provider: signing keys on schedule, expired sign-ins removed
		}
	}

	var servers []*http.Server
	errCh := make(chan error, 2)
	serve := func(srv *http.Server, tlsOn bool) {
		servers = append(servers, srv)
		go func() {
			var err error
			if tlsOn {
				log.Info("hardyd listening (https)", "addr", srv.Addr, "version", version.Version)
				err = srv.ListenAndServeTLS("", "")
			} else {
				log.Info("hardyd listening (http)", "addr", srv.Addr, "version", version.Version)
				err = srv.ListenAndServe()
			}
			if !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
	}

	if httpsAddr != "" {
		cert, err := tlscert.LoadOrCreate(tlsDir)
		if err != nil {
			return fmt.Errorf("tls certificate: %w", err)
		}
		if !live {
			// App windows: an HTTPS proxy per app with a web page (44300 + n).
			// They listen where the desktop listens (-https's host), like the
			// plain-HTTP branch below.
			host, p, _ := net.SplitHostPort(httpsAddr)
			port, _ := strconv.Atoi(p)
			go handler.RunAppProxy(ctx, api.AppProxyOptions{
				TLS:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
				DesktopPort: port,
				ListenHost:  host,
			})
			// The office suite: the editor's own origin (44250) and the
			// listener the Document Server container calls back on.
			go handler.RunOffice(ctx, api.OfficeOptions{
				TLS:        &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
				ListenHost: host,
			})
			// The app gateway on the NetBird address, for NetBird's reverse
			// proxy, and the publishing sync.
			go handler.RunRemote(ctx, api.RemoteOptions{
				TLS: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
			})
		}
		serve(&http.Server{
			Addr:              httpsAddr,
			Handler:           handler,
			TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}, true)
		if httpAddr != "" {
			serve(&http.Server{Addr: httpAddr, Handler: redirectToHTTPS(httpsAddr), ReadHeaderTimeout: 10 * time.Second}, false)
		}
	} else if httpAddr != "" {
		log.Warn("HTTPS disabled: serving over plain HTTP (development only)")
		if !live {
			_, p, _ := net.SplitHostPort(httpAddr)
			port, _ := strconv.Atoi(p)
			host, _, _ := net.SplitHostPort(httpAddr)
			go handler.RunAppProxy(ctx, api.AppProxyOptions{DesktopPort: port, ListenHost: host})
			go handler.RunOffice(ctx, api.OfficeOptions{ListenHost: host})
		}
		serve(&http.Server{Addr: httpAddr, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}, false)
	} else {
		return errors.New("both -https and -http are empty; nothing to serve")
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func(s *http.Server) {
			defer wg.Done()
			_ = s.Shutdown(shutdownCtx)
		}(srv)
	}
	wg.Wait()
	return nil
}

// redirectToHTTPS sends every plain-HTTP request to the HTTPS port, except the
// health check, which monitoring may poll over HTTP.
func redirectToHTTPS(httpsAddr string) http.Handler {
	_, port, _ := net.SplitHostPort(httpsAddr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		target := "https://" + host
		if port != "" && port != "443" {
			target += ":" + port
		}
		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}

func housekeeping(ctx context.Context, log *slog.Logger, sessions *auth.Sessions) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := sessions.PurgeExpired(ctx); err != nil {
				log.Warn("purge sessions", "err", err)
			} else if n > 0 {
				log.Info("purged expired sessions", "count", n)
			}
		}
	}
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

// backupAlerts sends cloud backup events (kinds backup.*, routed in the
// "backup" category) through the alert dispatcher.
func backupAlerts(d *notify.Dispatcher) cloudbackups.Notifier {
	return cloudbackups.NotifierFunc(func(ctx context.Context, e cloudbackups.Event) {
		d.Notify(ctx, notify.Event(e))
	})
}

// replNotifier hands replication's events to the alert dispatcher.
type replNotifier struct{ to notify.Notifier }

func (n replNotifier) Notify(ctx context.Context, e replication.Event) {
	n.to.Notify(ctx, notify.Event{Kind: e.Kind, Severity: e.Severity, Title: e.Title, Body: e.Body, Link: e.Link, Time: e.Time})
}
