// Command hardyd-priv is the HardyOS root helper. It listens on a unix socket
// and runs only the operations registered in internal/priv, for callers whose
// user ID is allowed.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/backup"
	"github.com/hardyos/hardyos/daemon/internal/boot"
	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/install"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/shares"
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
	} else {
		// State files in hardyd's directory are only acted on if root wrote them.
		rootfile.Enforce = true
	}

	s := &priv.Server{Logger: log}
	gid, hardydUID := -1, -1
	if u, err := user.Lookup(*allowUser); err == nil {
		uid, _ := strconv.ParseUint(u.Uid, 10, 32)
		s.AllowedUIDs = append(s.AllowedUIDs, uint32(uid))
		hardydUID = int(uid)
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
		// The domain controller, if one was set up. The NAS's resolver puts the
		// domain's DCs first, and settings backups include the domain.
		dc := &domain.Manager{Runner: sysexec.Exec{}, Root: "/", Log: log}
		netm := &network.Manager{Runner: sysexec.Exec{}, Root: "/", Log: log, DomainDNS: dc.DNSServers}
		dc.DNSChanged = func(ctx context.Context) {
			if err := netm.SyncDomainDNS(ctx); err != nil {
				log.Warn("updating the NAS's DNS servers for the domain", "err", err)
			}
		}
		// A settings restore chosen before the restart is applied now,
		// before hardyd opens its database and before networking starts.
		bk := &backup.Root{Runner: sysexec.Exec{}, Root: "/", UID: hardydUID, GID: gid, Network: netm, Domain: dc}
		if res := bk.ApplyPending(ctx); res != nil {
			log.Info("settings restore", "ok", res.OK, "message", res.Message, "notes", res.Notes)
		}
		// Undo a network change that wasn't confirmed before a restart.
		netm.OnStart(ctx)
		priv.RegisterNetwork(s, netm)
		priv.RegisterBackup(s, bk)
		priv.RegisterTerminal(s)
		// Kept attached to the LAN and running through network changes and
		// crashes.
		priv.RegisterDomain(s, dc)
		go dc.Watch(ctx)
		// Docker apps: Docker stays off at boot until hardyd-priv has pointed
		// it at its dataset on the pool, then the apps come back by themselves.
		shm := &shares.Manager{Runner: sysexec.Exec{}, Root: "/", Log: log}
		priv.RegisterShares(s, shm)
		am := &apps.Manager{Runner: sysexec.Exec{}, Root: "/", Log: log, Shares: shm}
		priv.RegisterApps(s, am)
		go am.OnStart(ctx)
		priv.RegisterBootRepair(s, priv.StorageEnv{Runner: sysexec.Exec{}, Root: os.DirFS("/")}, "/", boot.ConfigPath)
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
