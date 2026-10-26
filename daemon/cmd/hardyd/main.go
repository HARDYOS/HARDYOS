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
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/api"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/install"
	"github.com/hardyos/hardyos/daemon/internal/installer"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/metrics"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/storage"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/tlscert"
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
	)
	flag.Parse()

	if *showVersion {
		v := version.Get()
		fmt.Printf("hardyd %s (%s) %s %s/%s\n", v.Version, v.Commit, v.GoVersion, v.OS, v.Arch)
		return
	}
	log := newLogger(*logLevel)
	slog.SetDefault(log)
	if err := run(log, *httpsAddr, *httpAddr, *tlsDir, *dbPath, *privSocket, *webRoot); err != nil {
		log.Error("hardyd failed", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, httpsAddr, httpAddr, tlsDir, dbPath, privSocket, webRoot string) error {
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
		WebRoot: webRoot, Insecure: httpsAddr == "", Installer: inst,
	})

	go housekeeping(ctx, log, &auth.Sessions{DB: db})
	go collector.Run(ctx) // CPU, memory and network history
	if !live {
		go stor.Run(ctx) // snapshot, scrub and SMART schedules
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
