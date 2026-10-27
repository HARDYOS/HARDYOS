// Command hardyd-priv is the HardyOS root helper. It listens on a unix socket
// and runs only the operations registered in internal/priv, for callers whose
// user ID is allowed.
package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/hardyos/hardyos/daemon/internal/rootauth"
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
	"github.com/hardyos/hardyos/daemon/internal/cloudbackup"
	"github.com/hardyos/hardyos/daemon/internal/devices"
	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/gpu"
	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/install"
	"github.com/hardyos/hardyos/daemon/internal/netbird"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/sftp"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/smb"
	"github.com/hardyos/hardyos/daemon/internal/snapshots"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/syslock"
	"github.com/hardyos/hardyos/daemon/internal/update"
	"github.com/hardyos/hardyos/daemon/internal/ups"
	"github.com/hardyos/hardyos/daemon/internal/version"
	"github.com/hardyos/hardyos/daemon/internal/vms"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

func main() {
	// A file worker: the same binary, re-run as the person whose files it
	// reads or writes (internal/fileworker). Never returns.
	if len(os.Args) == 2 && os.Args[1] == fileworker.Subcommand {
		fileworker.ChildMain()
	}
	// restic's sandbox: the same binary sets up restic's mount namespace and
	// capabilities, then executes restic (internal/cloudbackup).
	if len(os.Args) > 1 && os.Args[1] == cloudbackup.SandboxArg {
		os.Exit(cloudbackup.SandboxMain(os.Args[1:]))
	}
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
		// Boot menu changes, updates and GPU driver tasks take turns, with
		// hardyctl boot-sync too (a lock file in root's runtime directory).
		syslock.Init()
		// Root's own state directory on the shared dataset; files early
		// builds put in hardyd's directory move there.
		if err := boot.MigrateRootState(boot.Env{Runner: sysexec.Exec{}, Root: "/"}); err != nil {
			log.Warn("root's state directory", "dir", rootfile.RootStateDir, "err", err)
		}
		if err := devices.MigrateRoms("/"); err != nil {
			log.Warn("GPU ROM library", "err", err)
		}
		// Before hardyd touches the state dataset: finish a settings restore,
		// undo a failed update, or start the new version's confirm watchdog.
		if release, err := syslock.Acquire(ctx, "Checking the last update"); err == nil {
			updater.OnBoot(ctx)
			release()
		} else {
			log.Warn("system lock", "err", err)
			updater.OnBoot(ctx)
		}
		// GPUs and devices for VMs. The NVIDIA driver HardyOS installed is
		// rebuilt inside every new version before it's offered for boot.
		gpus := &gpu.Manager{Runner: sysexec.Exec{}, Root: "/", Log: log}
		updater.Hooks = append(updater.Hooks, update.Hook{Name: "Installing the NVIDIA driver into the new version", Run: gpus.PrepareNewRoot})
		// Testing a cloud backup destination waits for the bucket (bounded
		// inside to 90 s per step).
		s.OpTimeouts = map[string]time.Duration{priv.OpUpdateStage: 45 * time.Minute, priv.OpCloudTargetSave: 5 * time.Minute}
		devs := &devices.Host{Runner: sysexec.Exec{}, Root: "/", Log: log}
		priv.RegisterDevices(s, devs, gpus)
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
		// Keys hardyd encrypts its own secrets with (sign-in provider keys).
		priv.RegisterSecrets(s, zfs.KeyDir)
		// Kept attached to the LAN and running through network changes and
		// crashes.
		priv.RegisterDomain(s, dc)
		go dc.Watch(ctx)
		// Docker apps: Docker stays off at boot until hardyd-priv has pointed
		// it at its dataset on the pool, then the apps come back by themselves.
		shm := &shares.Manager{Runner: sysexec.Exec{}, Root: "/", Log: log}
		// NFS follows every shared folder change; automatic snapshots tick each minute.
		nfsm := &nfs.Manager{Runner: sysexec.Exec{}, Shares: shm, Root: "/", Log: log}
		// SMB file server: the host's Samba as a member of the domain.
		fsm := &smb.Manager{Runner: sysexec.Exec{}, Log: log, Shares: shm, LocalDomain: localSMBDomain(dc),
			Addresses: func(ctx context.Context) []string { return smb.LANAddresses(ctx, sysexec.Exec{}) }}
		// SFTP for domain accounts: sshd's settings and each person's view of the folders.
		fsm.SFTP = &sftp.Manager{Runner: sysexec.Exec{}, Log: log}
		shareHooks := []priv.ShareHook{priv.RegisterNFS(s, nfsm), priv.RegisterFiles(s, fsm)}
		priv.RegisterShares(s, shm, shareHooks...)
		go nfsm.Watch(ctx)
		go fsm.Watch(ctx)
		snaps := &snapshots.Manager{Runner: sysexec.Exec{}, Shares: shm, Log: log}
		priv.RegisterSnapshots(s, snaps)
		go snaps.Run(ctx)
		am := &apps.Manager{Runner: sysexec.Exec{}, Root: "/", Log: log, Shares: shm}
		priv.RegisterApps(s, am)
		// Remote access: the NetBird client (off until the server joins a
		// NetBird network; back on after an update if it had joined).
		nbm := &netbird.Manager{Runner: sysexec.Exec{}, Root: "/"}
		priv.RegisterNetBird(s, nbm)
		go func() {
			if err := nbm.OnStart(ctx); err != nil {
				log.Warn("starting NetBird", "err", err)
			}
		}()
		// File Manager and share links: files read and written as the person.
		fw, err := priv.StartFiles(ctx, s, shm, fsm.HomesPool, log)
		if err != nil {
			log.Error("file access isn't available", "err", err)
		}
		go am.OnStart(ctx)
		// Virtual machines: libvirt is driven from here only. Adding or
		// removing the VM bridge takes the domain controller off the port
		// first and puts it on the new parent after.
		netm.BeforeBridges = dc.HoldNetwork
		netm.AfterBridges = dc.ReleaseNetwork
		// Devices go to VMs through part D's Host, the same one its ops use;
		// the Devices view shows which VM each device is assigned to.
		vmm := &vms.Manager{Runner: sysexec.Exec{}, Root: "/", Log: log, Network: netm, Library: priv.VMLibrary(shm, shareHooks...), Devices: devs}
		devs.Assignments = vmm.Assignments
		go reconcileDevices(ctx, devs, log)
		priv.RegisterVMs(s, vmm)
		// Versioned cloud backups (restic) of shared folders, apps, VMs and
		// the settings; the destination an installer's "Restore from
		// backup" left is taken over now (after the settings restore above).
		cb := &cloudbackup.Root{
			Restic: &cloudbackup.Restic{Sandbox: &cloudbackup.Sandbox{}}, Vol: &cloudbackup.ZFS{Runner: sysexec.Exec{}}, DBOwner: hardydUID,
			Shares: shm, Apps: am, VMs: vmm, System: bk, Log: log,
			Key: func() ([]byte, error) { return priv.RootKeyFor(zfs.KeyDir, "cloud-backup") },
		}
		if fw != nil {
			cb.Files = fw
		}
		cb.OnStart()
		// Root checks an administrator's password itself for the recovery
		// kit (decision 180); the installer's first administrator is taken
		// at the first start, before hardyd has ever run.
		ra := &rootauth.Checker{Domain: dc}
		if err := ra.Seed(install.SeedFile); err != nil {
			log.Warn("administrator verifiers", "err", err)
		}
		priv.RegisterCloudBackup(s, cb, ra)
		go vmm.OnStart(ctx)
		go vmm.Watch(ctx)
		priv.RegisterBootRepair(s, priv.StorageEnv{Runner: sysexec.Exec{}, Root: os.DirFS("/")}, "/", boot.ConfigPath)
		// Monitoring: SMART self-tests and the UPS (NUT's configuration in
		// /etc/nut and its services). The monitor's polling is logged quietly.
		priv.RegisterMonitor(s, priv.MonitorEnv{
			Storage: priv.StorageEnv{Runner: sysexec.Exec{}, Root: os.DirFS("/")},
			UPS:     &ups.Root{Runner: sysexec.Exec{}, Root: os.DirFS("/")},
		})
		priv.QuietMonitoringOps(s)
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
		// "Restore from backup": list a repository's versions and stage one's
		// settings into the new system.
		priv.RegisterInstallCloud(s, &cloudbackup.Root{Restic: &cloudbackup.Restic{Sandbox: &cloudbackup.Sandbox{}}, Log: log}, "/target")
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

// reconcileDevices gives back devices held for VMs that stopped while
// hardyd-priv wasn't running. libvirt may come up after hardyd-priv, so
// it tries for a while; nothing is released while the running VMs can't
// be listed.
func reconcileDevices(ctx context.Context, h *devices.Host, log *slog.Logger) {
	for i := 0; i < 20; i++ {
		err := h.Reconcile(ctx)
		if err == nil {
			return
		}
		log.Warn("devices: reconcile", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

// localSMBDomain tells the file server about the domain this server's own
// DC runs (its DCs, this one first, and the HardyOS Admins group).
func localSMBDomain(dc *domain.Manager) func() *smb.Domain {
	return func() *smb.Domain {
		c, err := dc.Load()
		if err != nil || c == nil || c.NetBIOS == "" {
			return nil
		}
		return &smb.Domain{Domain: c.Domain, Realm: c.Realm, NetBIOS: c.NetBIOS, DCs: c.DNSServers(), AdminsGroupSID: c.AdminsGroupSID}
	}
}
