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
	"time"

	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/install"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/update"
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

	reboot := func() { _, _ = sysexec.Exec{}.Run(context.Background(), nil, "systemctl", "reboot") }
	updater := &update.Updater{
		Runner: sysexec.Exec{}, Root: "/",
		Keys:   func() []update.PublicKey { return update.TrustedKeys("/") },
		Reboot: reboot,
	}
	live := install.IsLive("/")
	if live {
		priv.RegisterSystem(s, sysexec.Exec{}, nil)
	} else {
		// Before hardyd touches the state dataset: finish a settings restore,
		// undo a failed update, or start the new version's confirm watchdog.
		updater.OnBoot(ctx)
		priv.RegisterSystem(s, sysexec.Exec{}, updater.BeforeReboot)
		priv.RegisterUpdates(s, updater)
		if len(updater.Keys()) == 0 {
			log.Warn("no trusted release key: updates can't be installed until one is added")
		}
	}

	if live {
		// Live installer: publish the one-time code on the console and offer
		// the install steps. Installed systems never get these operations.
		code, err := install.NewCode()
		if err == nil {
			err = install.PublishCode("/", code, gid)
		}
		if err != nil {
			log.Error("could not create the install code", "err", err)
			os.Exit(1)
		}
		// Refresh the login banners that are already on screen.
		_, _ = sysexec.Exec{}.Run(context.Background(), nil, "agetty", "--reload")
		priv.RegisterInstaller(s, &install.Installer{
			Runner:  sysexec.Exec{},
			Root:    "/",
			Version: version.Version,
			ListDisks: func(ctx context.Context) ([]hw.Disk, error) {
				return hw.ListDisks(ctx, sysexec.Exec{}, os.DirFS("/"))
			},
		})
		s.OpTimeout = 45 * time.Minute // copying the system from a slow USB stick
		log.Info("live installer mode: install code published on the console")
	}

	s.OnListen = priv.NotifyReady
	log.Info("hardyd-priv listening", "socket", *socket, "ops", s.Ops())
	if err := s.ListenAndServe(ctx, *socket, 0o660, gid); err != nil {
		log.Error("serve failed", "err", err)
		os.Exit(1)
	}
}
