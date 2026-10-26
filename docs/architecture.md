# Architecture

HardyOS is a Debian 13 system with a small set of HardyOS services on top.
Every change to the system flows through one daemon, and every workload keeps
its data on one ZFS pool.

```
 Browser (web desktop) ─┐
 hardyctl (CLI) ────────┼──► hardyd (API, auth, jobs)  ──unix socket──►  hardyd-priv (root)
 Apps and sync clients ─┘        runs as user "hardyd"                    fixed operation allowlist
                                                                                │
                                         Docker apps · KVM VMs · SMB/NFS · Samba AD / Authentik
                                                                                │
                                                        ZFS data pool "tank" (datasets per app/user/share/VM)
                                                                                │
                                                   Debian 13 · kernel · OpenZFS · mirrored boot drive
```

## Components

| Component | Language | Runs as | Purpose |
| --- | --- | --- | --- |
| `hardyd` | Go | `hardyd` user | HTTP API, sessions, job queue, audit log, serves the web desktop |
| `hardyd-priv` | Go | root | Executes a fixed allowlist of privileged operations over `/run/hardyos/priv.sock` |
| `hardyctl` | Go | any | CLI over the same API (and the priv socket for recovery) |
| Web desktop | React + TypeScript | browser | macOS-style shell: menu bar, dock, windows, built-in apps |
| `@hardy/sdk` | TypeScript | browser | Contract between the shell and app windows |
| `@hardy/api-client` | TypeScript | browser | Typed client generated from `api/openapi.yaml` |

## Privilege boundary

`hardyd-priv` accepts a connection only when the peer's user ID (checked with
`SO_PEERCRED`) is root or the `hardyd` user. Each request names one operation;
unknown operations are rejected. Operations validate their own arguments and
never accept raw shell commands. The socket is mode `0660`, owned by
`root:hardyd`.

`/var/lib/hardyos` belongs to the `hardyd` account, so `hardyd` could replace
any file in it. hardyd-priv keeps some of its own state there (the boot
configuration, a waiting update, a waiting network change, a staged restore).
It only acts on such a file when root wrote it (root-owned, a regular file,
not writable by group or others: `internal/rootfile`), and it still checks
what's inside (an update may only remove its own boot environment; a network
undo only writes the network files).

## Sign-in and sessions

- Passwords are hashed with Argon2id. Five failed sign-ins in 15 minutes lock
  that IP and that username for 15 minutes.
- Sessions are random 256-bit tokens in an HttpOnly, Secure, SameSite=Strict
  cookie; only a SHA-256 hash is stored. They expire after 24 hours idle and
  30 days at most. Password changes and disabling an account end its sessions.
- State-changing requests must carry `X-HardyOS-Request: 1` (CSRF defense).
- Every state-changing action is written to the audit log.
- hardyd serves HTTPS on 443 with a self-signed certificate created on first
  start; port 80 redirects to it.

## Jobs and events

Long operations run as jobs: queued, persisted in SQLite, run by a worker
pool, cancellable, and serialized per resource when needed (for example one
operation per pool at a time). Progress streams to the browser over the
`/api/v1/events` WebSocket. Jobs interrupted by a restart are marked failed.

## Storage

- `hardyd-priv` owns every disk and ZFS command. Operations that consume
  disks (create, add, attach, replace) re-scan disks themselves and refuse
  anything that is the boot disk, mounted, removable, or in another pool,
  then clear old signatures. They also require `confirmWipe: true`.
  Destroying a pool or dataset requires repeating its exact name.
  The boot pool (`rpool`) can be read but never changed through the API.
- Pools are built from stable `/dev/disk/by-id` paths and mount under `/mnt/<pool>`.
  Defaults: ashift 12, autotrim, lz4, atime off, xattr=sa, POSIX ACLs.
  Optional native encryption uses a per-pool key file in `/var/lib/hardyos/keys`
  so pools unlock at boot (protects disks removed from the server).
- New pools get standard datasets (`system`, `apps`, `users`, `shares`, `vms`),
  a monthly scrub, and daily (keep 14) + weekly (keep 8) snapshots of `users`
  and `shares`. The ARC limit is set once from the hardware profile.
- hardyd checks every minute: due snapshots (with retention), due scrubs,
  pool health changes, and every 6 hours each disk's SMART health.
  Changes raise notifications.
- Layout recommendations follow the plan: 1 disk stripe, 2-3 mirror, 4-5
  RAIDZ1, 6-11 RAIDZ2, 12+ several RAIDZ2 vdevs (leftovers become spares);
  spare SSDs become a special mirror, then an SLOG (only with power-loss
  protection), then L2ARC (only with 32 GB+ RAM).

## Install and boot

- The ISO is a live system with the marker `/etc/hardyos/live-installer`.
  When it is present, hardyd-priv prints a one-time code on the console
  (`/etc/issue.d`) and registers the `install.*` operations, and hardyd serves
  only the installer API. Installed systems have neither. The code unlocks
  the browser with an in-memory session (cookie `hardyos_installer`); wrong
  codes are rate limited.
- The install runs as a job of fixed steps, each a privileged operation:
  check, partition, pool, copy system, configure, boot loader, finish. A
  failure resets the target so the person can retry.
- Boot disk layout (GPT): 1 MiB BIOS boot, 1 GiB EFI system partition (FAT32),
  the rest a ZFS partition. Two or more disks form a mirrored `rpool`.
- Datasets: `rpool/ROOT/hardyos-<version>` is one boot environment per
  version (mounted at `/`, `org.hardyos:version` property);
  `rpool/hardyos` is `/var/lib/hardyos`, shared by every boot environment
  (database, TLS, `boot.json`).
- The system is copied from the live image (`unsquashfs`), so installing
  needs no network. Live-only packages are purged, the initramfs is rebuilt
  with ZFS support, and the host ID is copied so the pool imports cleanly.
- GRUB never reads ZFS. `internal/boot` copies each boot environment's
  kernel and initramfs to every ESP (`/hardyos/<be>/`) and writes one
  `grub.cfg` with an entry per boot environment (newest five, the pool's
  `bootfs` first, kernel argument `root=ZFS=<dataset>`). GRUB is installed at
  the removable path (`EFI/BOOT/BOOTX64.EFI`, no NVRAM entry needed) and for
  BIOS on x86. `hardyctl boot-sync` runs this after every kernel or
  initramfs update (hooks in `/etc/kernel/*.d` and
  `/etc/initramfs/post-update.d`).
- The first administrator is created in the installer, but only its argon2id
  hash travels to root. It is written as `install-seed.json`; hardyd creates
  the account on first boot (only if no accounts exist) and deletes the file.
- Secure Boot is not supported yet (GRUB is unsigned).

### Boot disk repair

Storage Manager's System pool card manages the boot mirror (hardyd-priv's
`boot.*` operations):

- **Replace** a failed or missing disk: the new disk is wiped, gets a copy of
  a working boot disk's partition table (`sgdisk --replicate`, then new GUIDs),
  a fresh EFI partition, joins the pool with `zpool replace` and gets GRUB and
  the kernels (`boot.Sync` with `InstallGRUB`). `boot.json` and the UEFI boot
  entries are updated. The new disk must be at least as big as the boot disks.
- **Add** a disk the same way with `zpool attach`, to mirror a single boot disk
  or widen the mirror (up to 4).
- **Remove** a dead disk that won't be replaced (`zpool detach`); never the
  last working one.

## Updates and rollback

- A release is a signed update file (`.hupd`): a tar of `manifest.json`
  (version, architecture, the system image's size and SHA-256),
  `manifest.sig` (ed25519 over the manifest) and `rootfs.squashfs` (the same
  image the ISO boots). `make release` builds the ISO and signs the image
  with the release key, which lives only on the release computer
  (`~/.config/hardyos/release.key`). Servers trust the public keys compiled
  in from `daemon/internal/update/keys/` plus `/etc/hardyos/trusted-keys.d/`.
- Installing (Control Panel > Updates: upload or https download) runs as a
  job: hardyd-priv checks the signature before reading the image and the
  hash while extracting, creates `rpool/ROOT/hardyos-<version>`, unpacks the
  image, carries this server's identity and settings over (hostname, host ID,
  network, SSH host keys, machine ID, time zone, pool cache), runs the same
  finishing steps as the installer, adds it to the boot menu and sets GRUB's
  one-time `next_entry`. Nothing changes for the running version.
- Restarting snapshots `rpool/hardyos` first (`@pre-<be>-<time>`).
- First boot of the new version: hardyd-priv starts a 15-minute watchdog;
  hardyd confirms after a minute of being healthy (root helper and database
  answer). Confirming makes the version the pool's `bootfs` (the default),
  clears the one-time choice and keeps the newest three versions.
- If the new version never confirms (kernel panic, hardyd failing, hang),
  the watchdog or a power cycle brings the server back: the one-time choice
  is already used up, so GRUB starts the previous default. hardyd-priv
  (`Type=notify`, ready only after this) then rolls `rpool/hardyos` back to
  the snapshot, removes the failed version and records the result, before
  hardyd opens the database.
- Going back by hand: "Use this version" makes an older version the default
  for the next restart, optionally restoring the settings snapshot taken
  before the running version was installed (applied at boot, before hardyd
  starts).

### Checking for new versions

hardyd checks the latest release of HARDYOS/HARDYOS on GitHub (stable only:
drafts and pre-releases are skipped) a few minutes after starting and then
daily, while the daily check is on (Control Panel > Updates; on by default).
A release is offered when its version sorts after the running one, using
Debian's ordering (`0.1.0~ci2 < 0.1.0 < 0.1.0+3.gabc < 0.1.1`), and it has a
`hardyos-<version>-<arch>.hupd` file. Administrators get one notification
per version. Install downloads that file through the normal download job,
so the signature check is the same as for an uploaded file; nothing installs
by itself. Uploading a file or giving an address still works for manual
updates.

## Network and time

Network settings live in Control Panel > Network and are stored in
`/var/lib/hardyos/network/settings.json` (on the shared dataset, so every
version uses them). hardyd-priv renders them into ifupdown's
`/etc/network/interfaces` (bonds through `ifenslave`, VLANs through `vlan`),
`/etc/resolv.conf`, `/etc/hosts` and `/etc/hostname`. Servers set up before
this existed have their installer-written files imported on first use.

Applying is the one place a settings change can cut the server off, so it has
a safety net:

1. The current files are saved into `pending.json` before anything changes.
2. Interfaces that ifupdown has up are taken down under their old
   definitions, the new files are written, and interfaces come up under the
   new ones. DHCP ports start in the background so an unplugged port doesn't
   hold things up.
3. The change must be confirmed (Keep settings) within 3 minutes, from any
   browser that can still reach the server. Otherwise hardyd-priv restores
   the saved files and restarts the network the same way. A restart while a
   change is waiting counts as not confirmed once the deadline passes.

The desktop shows the keep-or-undo prompt to administrators, so a change of
address can be confirmed right after signing in at the new one.

Date & Time sets the time zone (`/etc/localtime`, `/etc/timezone`) and
chrony (`/etc/chrony/chrony.conf`): automatic time with the Debian pool or
chosen servers, or a clock set by hand. Clock changes can't cut the server
off, so they apply at once. Both files carry over to new versions with
updates; the automatic-time on/off choice is re-applied when hardyd-priv
starts.

## Settings backups

A settings backup (`.hbak`) holds the hardyd database (users, schedules,
settings), network and time settings and the HTTPS certificate. Backups can
also hold secrets (encryption keys for storage, SSH host keys); those are
always password-protected (argon2id and AES-256-GCM) and never kept on a pool.

- **Nightly**: hardyd snapshots its database (`VACUUM INTO`), hardyd-priv adds
  the root-owned files, and the backup is kept on a data pool in
  `<pool>/hardyos-backups` (14 by default), so it survives a reinstall.
- **Download**: a password-protected file, made on request. Downloads and
  restores don't run as jobs, because job parameters are kept and these carry
  a password.
- **Restore**: hardyd checks the file (password, checksums, a database this
  version understands, at least one account), then hardyd-priv unpacks it
  again as root into a root-only staging folder. It's applied at the next
  start, by hardyd-priv before hardyd opens the database and before
  networking starts. Archives can only restore a fixed list of paths; network
  settings that don't work on the machine (different ports) are skipped, so
  restoring onto new hardware can't leave the server unreachable.

## Terminal

The Terminal app is a root shell in the browser, for administrators only. It's
the one deliberate exception to the fixed-operations rule (decision 37): a
person types into it, but no API call can run a command through it.

1. The administrator enters their password again (`POST /terminal/session`,
   rate limited) and gets a one-time ticket that lasts 30 seconds.
2. The browser opens `GET /terminal/ws?ticket=…`. hardyd asks hardyd-priv for
   `terminal.open`, which starts `bash --login` on a new pseudo-terminal in the
   host's mount namespace and passes the terminal's file descriptor back over
   the socket (SCM_RIGHTS). At most 4 run at once.
3. hardyd relays bytes over the WebSocket (binary frames; resize and "closed"
   messages are text frames). It closes the session after 15 minutes without
   typing or 8 hours in total. Every unlock attempt, open and close (with the
   reason and length) goes in the security log.

Control Panel > Security has the on/off switch (`terminal.enabled`, on by
default).

## Domain controller

HardyOS can run an Active Directory domain (Samba 4) so every family member
has one account for Windows PCs, the NAS's shares and, later, every app. It
is set up from Control Panel > Domain, which asks for the domain name (a
subdomain of a domain the owner has, never `.local`), suggests a free address
for the domain controller and sets the domain Administrator's password.

```
            LAN (192.168.1.0/24)
   ─────────────┬──────────────────────┬───────────
                │ enp1s0 (NAS .105)    │ hdc0 (DC .20, own MAC)
         ┌──────┴─────────┐     ┌──────┴──────────────────────┐
         │ NAS            │     │ netns hardyos-dc            │
         │ hdc-shim       │────▶│ samba (hardyos-dc.service)  │
         │ 169.254.250.1  │     │ /run/samba -> its run dir   │
         └────────────────┘     └─────────────────────────────┘
```

- **Its own address.** The DC lives in the network namespace `hardyos-dc`
  on a macvlan (`hdc0`) of the NAS's LAN port, with a fixed, locally
  administered MAC. Its DNS (port 53), Kerberos and SMB never collide with
  the NAS's own services, and Samba's recommended "DC is not the file server"
  layout holds on one box.
- **The NAS reaching it.** A macvlan can't talk to its parent port, so a
  second macvlan on the host (`hdc-shim`) carries the link-local address
  169.254.250.1 and a route to the DC; the DC has the matching route back.
  The shim never claims the NAS's LAN address, so other devices see exactly
  one answer when they look the NAS up.
- **Its data.** Everything is in `/var/lib/hardyos-dc` (the dataset
  `rpool/hardyos-dc`, shared by all boot environments): Samba's databases,
  the `smb.conf` HardyOS writes, logs, and the run folder that the unit binds
  over `/run/samba` so the DC's winbind socket is its own.
- **Keeping it running.** hardyd-priv checks every 30 seconds that the
  namespace, `hdc0`, the shim and the service are in place and repairs what
  isn't: a network change that recreates the LAN port, or a crash, heals by
  itself. `GET /domain` reports `responding` only when a DNS query from the
  NAS for the domain's LDAP record gets an answer.
- **Accounts.** Users and groups are managed through `hardyos-dc-admin`, a
  small helper using Samba's Python API that reads its arguments, passwords
  included, from stdin. Creating and deleting the domain are jobs; the
  Administrator password reaches the provision job through a one-time
  in-memory reference, never its stored parameters. Built-in accounts and
  groups can't be deleted, and passwords don't expire by default.

The local HardyOS accounts (Control Panel > Users & Groups) stay separate for
now; the local admin remains the break-glass account. Shares (Phase 2) use
the domain's users and groups, and Authentik (Phase 3) signs apps in with
them.

## Data and state

- Control-plane state: SQLite on the pool (`tank/system`), with a nightly
  config export to the boot drive so a fresh install can restore settings.
- Web desktop assets: `/usr/share/hardyos/web`.
- OS: ZFS root with boot environments; each update installs into a new boot
  environment and falls back automatically if the health check fails.

## Build outputs

| Output | Built by | Contents |
| --- | --- | --- |
| `hardyos-core_<ver>_amd64.deb` | `make deb` (nfpm) | the three binaries, web desktop, systemd units |
| `hardyos-<ver>-amd64.iso` | `make iso` (live-build in Docker) | Debian 13 live system with OpenZFS and `hardyos-core` |

See the full plan in the "HardyOS Core Plan" doc for phases and gates.
