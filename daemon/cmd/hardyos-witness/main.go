// Command hardyos-witness is the HardyOS cluster witness for a plain
// Linux VPS (docs/cluster.md, decision 335): the cluster core only. It
// votes when the cluster needs a tie-breaker, holds the log, and runs
// nothing. It is installed and joined by the script a member generates
// (Cluster › Witness) and reached over NetBird only.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/witness"
	"github.com/hardyos/hardyos/daemon/internal/version"
)

func usage() {
	fmt.Fprintf(os.Stderr, `usage:
  hardyos-witness run [--config /etc/hardyos-witness/witness.json] [--state DIR]
  hardyos-witness status [--state DIR]
  hardyos-witness version
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/hardyos-witness/witness.json", "configuration written by the install script")
	stateDir := fs.String("state", defaultState(), "state directory (key, log, membership)")
	level := fs.String("log-level", "info", "debug, info, warn or error")
	_ = fs.Parse(os.Args[2:])
	var lv slog.Level
	_ = lv.UnmarshalText([]byte(*level))
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))

	switch os.Args[1] {
	case "version":
		v := version.Get()
		fmt.Printf("hardyos-witness %s (%s) %s %s/%s\n", v.Version, v.Commit, v.GoVersion, v.OS, v.Arch)
	case "status":
		b, err := os.ReadFile(filepath.Join(*stateDir, "status.json"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "no status yet:", err)
			os.Exit(1)
		}
		os.Stdout.Write(b)
		fmt.Println()
	case "run":
		if err := run(log, *cfgPath, *stateDir); err != nil {
			log.Error("hardyos-witness failed", "err", err)
			os.Exit(1)
		}
	default:
		usage()
	}
}

func defaultState() string {
	if d := os.Getenv("STATE_DIRECTORY"); d != "" {
		return strings.Split(d, ":")[0]
	}
	return "/var/lib/hardyos-witness"
}

// joinCode reads the code systemd hands over as a credential (only while
// the install script runs).
func joinCode() (string, error) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return "", errors.New("no join code: run the install script from Cluster › Witness again")
	}
	b, err := os.ReadFile(filepath.Join(dir, "join"))
	if err != nil {
		return "", errors.New("no join code: run the install script from Cluster › Witness again")
	}
	return strings.TrimSpace(string(b)), nil
}

func run(log *slog.Logger, cfgPath, stateDir string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, err := witness.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	w, err := witness.New(ctx, witness.Options{Config: cfg, Dir: stateDir, Version: version.Version,
		BootID: strings.TrimSpace(string(boot)), JoinCode: joinCode, Net: cluster.TCP{}, Log: log})
	if err != nil {
		return err
	}
	log.Info("hardyos-witness starting", "version", version.Version, "listen", cfg.Listen, "cluster", cfg.Cluster)
	return w.Run(ctx)
}
