// Command hardyd is the HardyOS control-plane API server. It runs as the
// unprivileged "hardyd" user and asks hardyd-priv for anything that needs root.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/api"
	"github.com/hardyos/hardyos/daemon/internal/version"
)

func main() {
	var (
		listen      = flag.String("listen", ":8080", "address to serve the API and web desktop on")
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

	if *webRoot != "" {
		if _, err := os.Stat(*webRoot); err != nil {
			log.Warn("web root not found, serving API only", "web_root", *webRoot)
			*webRoot = ""
		}
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           api.New(api.Config{WebRoot: *webRoot, Logger: log}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Info("hardyd listening", "addr", *listen, "version", version.Version)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", "err", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error("shutdown failed", "err", err)
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
