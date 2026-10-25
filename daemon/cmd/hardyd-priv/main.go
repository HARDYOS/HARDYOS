// Command hardyd-priv is the HardyOS root helper. It listens on a unix socket
// and runs only the operations registered in internal/priv, for callers whose
// user ID is allowed.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/version"
)

func main() {
	var (
		socket      = flag.String("socket", priv.DefaultSocket, "unix socket path")
		allowUser   = flag.String("allow-user", "hardyd", "user allowed to connect besides root")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("hardyd-priv %s (%s)\n", version.Version, version.Commit)
		return
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)

	if os.Geteuid() != 0 {
		log.Warn("hardyd-priv is not running as root; privileged operations will fail")
	}

	s := &priv.Server{Logger: log}
	gid := -1
	if u, err := user.Lookup(*allowUser); err == nil {
		uid, _ := strconv.ParseUint(u.Uid, 10, 32)
		s.AllowedUIDs = append(s.AllowedUIDs, uint32(uid))
		if g, err := strconv.Atoi(u.Gid); err == nil {
			gid = g
		}
	} else {
		log.Warn("allowed user not found; only root may connect", "user", *allowUser)
	}
	priv.RegisterBuiltins(s)
	priv.RegisterStorage(s, priv.StorageEnv{Runner: sysexec.Exec{}, Root: os.DirFS("/")})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("hardyd-priv listening", "socket", *socket, "ops", s.Ops())
	if err := s.ListenAndServe(ctx, *socket, 0o660, gid); err != nil {
		log.Error("serve failed", "err", err)
		os.Exit(1)
	}
}
