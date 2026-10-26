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
  that IP and that username for 15 minutes. Domain accounts can sign in too
  (see Domain controller > Desktop sign-in with domain accounts).
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

- **More than one DC.** A second HardyOS server joins the domain from its
  own Domain page (`samba-tool domain join`, run inside its namespace with
  the existing DC as its DNS) and becomes dc2; accounts, groups and DNS
  replicate both ways. Each DC lists its partners from the domain's DNS
  (refreshed every 5 minutes) and uses them in its own `resolv.conf`, after
  itself. Leaving demotes cleanly (roles move to a partner); a DC that's gone
  for good is removed from a survivor, which seizes its roles. Deleting the
  domain is refused while partners exist.
- **Name settings.** Each DC has its own `resolv.conf` and `krb5.conf`
  (the domain mapped to its realm) in its folder, bound over `/etc` by the
  unit and mirrored in `/etc/netns/<namespace>/` for commands run there.
- **The NAS's own DNS.** hardyd-priv keeps the NAS's `resolv.conf` listing
  the domain's DCs first (with a dhclient hook when DNS comes from DHCP),
  and the Domain page tells you what to put in the router's DHCP settings.
- **Backups.** Settings backups include the DC's settings and an offline
  backup of its databases. Restoring at start-up unpacks plain files and
  folders only (no links or escaping paths), puts group policies back,
  removes Samba's backup marker and lets the watcher start the DC. A domain
  already on the server is kept, and a DC that had partners isn't restored
  (it rejoins instead).

The local HardyOS accounts (Control Panel > Users & Groups) stay alongside
the domain's; the local admin remains the break-glass account. Shares
(Phase 2) use the domain's users and groups, and Authentik (Phase 3) signs
apps in with them.

### Desktop sign-in with domain accounts

When the server has a domain, its accounts sign in to the web desktop too
(`internal/auth` `SignIn`, used by `POST /auth/login`):

- **Names.** `alice`, `HOME\alice` and `alice@home.example.net` all mean
  the domain's alice; `DNS-domain\alice` and `alice@REALM` work as well. A
  local HardyOS account wins for a bare name, so the break-glass admin can't
  be shadowed by a domain account. A prefix or suffix that isn't this
  server's domain is refused (`unknown_domain`).
- **Password check.** hardyd (not root) asks the domain's DCs for a
  ticket-granting ticket with a Kerberos AS exchange (gokrb5, pure Go, TCP,
  no krb5.conf or DNS lookups): the realm and the DCs' addresses (this
  server's own first, then its partners) come from `domain.status`, cached
  for 30 seconds. hardyd reaches its own DC through the shim route. DCs that
  don't accept a connection within 2 seconds are skipped and the whole check
  is bounded at 10 seconds. The ticket is thrown away.
- **Answers.** A wrong password and an unknown name give the same
  `bad_credentials` as for local accounts (a bare name not known locally
  also runs a dummy Argon2 check, so timing doesn't tell local from domain).
  A turned-off, locked or expired account, or an expired password, gets its
  own message: the KDC already tells any device on the network that much.
  An unreachable DC or a clock more than 5 minutes off answer 503 and don't
  count as failed guesses. Failed guesses count against the IP and against
  the account under one key for every spelling (`user:home\alice`), with the
  same 5-in-15-minutes lockout as local sign-in.
- **Groups and role.** After the password, hardyd-priv's
  `domain.user_groups {username}` runs `hardyos-dc-admin user.groups`, which
  reads the account's state and its `tokenGroups` (nested groups and the
  primary group included; BUILTIN groups left out). Turned-off and expired
  accounts are refused. Members of `Domain Admins` or `HardyOS Admins` are
  administrators, everyone else is a user. `HardyOS Admins` isn't created
  automatically; the Domain page has a button for it.
- **Records.** The first sign-in creates a row in `users` with
  `source = domain`, `username = HOME\alice` and an empty password hash, so
  sessions, jobs and the audit log point at domain users the same way as at
  local ones. The row holds the name, email, role and groups (`HOME\Family`)
  from the domain; sessions record `source` and `principal`. While signed
  in, the groups are looked up again at most every 10 minutes (from the
  request that finds them older); a deleted, turned-off or expired account,
  or a different domain, ends all its sessions. If the domain can't be
  asked, the known groups stay and the lookup is retried a minute later.
- **What a domain account can't do here.** Change its password through
  HardyOS (`/auth/password` and the admin reset answer `domain_account`,
  pointing to Domain > Users), have its name, email or role edited, be a
  break-glass account, or count as the last administrator. An admin can turn
  it off in HardyOS (a local switch) or forget it (delete the row). A domain
  admin can open the terminal: the password is checked by Kerberos again.
- **For access checks.** `auth.Identity` (implemented by `*auth.User`)
  gives `IdentitySource()`, `IdentityPrincipal()` (`alice` or `HOME\alice`),
  `IdentityGroups()` and `Matches(kind, name)` for rules of kind `user`,
  `group` or `everyone`, compared case-insensitively. `/auth/me` returns
  `source`, `principal` and `groups`.

## Shared folders

Folders on the data pools for the family's files and for apps (user and
developer notes in [shares.md](shares.md)).

- **Storage.** Each shared folder is a dataset `<pool>/shares/<id>`,
  mounted at `/mnt/<pool>/shares/<id>`. Its settings are `org.hardyos:*`
  user properties on the dataset (`share=1`, `name`, `description`,
  `access`, `apps`, `recycle`, `guest`) and its quota is the ZFS `quota`,
  so they move with the pool. Datasets get `acltype=posixacl`, `xattr=sa`,
  `devices=off` and `setuid=off`.
- **Root side.** `internal/shares` (in hardyd-priv) behind the ops
  `shares.list/create/update/delete/starter/folders`. The apps engine uses
  the same Manager in-process through `apps.ShareResolver`: `Resolve` gives
  the real path of a share or a subfolder (never outside it), `GrantApp` and
  `RevokeApp` add or remove the app user's ACL entries (the share root at
  once with setfacl, everything below in a background walk that never
  follows links) and record them in `org.hardyos:apps`.
- **API.** `GET /shares` and `GET /shares/{id}` for everyone signed in
  (family members don't see access rules, apps or pools); admins create,
  change and delete through jobs (`shares.create`, `shares.update`,
  `shares.delete`, `shares.starter`, run one at a time and audited) and
  browse subfolders with `GET /shares/{id}/folders`.
- **Control Panel › Shared Folders.** The list with usage and quota, the
  create/edit dialog (pool, name, quota, recycle bin, guest, who can use
  it), delete with the name typed, and the starter set when there are none.
- **Later.** File sharing (SMB, NFS, Time Machine, SFTP/WebDAV) publishes
  these same datasets and enforces the access rules; home folders arrive
  with it.

## Apps

One-click Docker apps install from `.hardyapp` packages (format in
[apps.md](apps.md)). The pieces:

- **Packages.** `internal/apps` reads and checks packages and the Compose
  policy. The catalog ships in `hardyos-core` at `/usr/share/hardyos/apps`
  (built from `apps/catalog/` by `make build-apps`); uploads are kept by
  hash in `/var/lib/hardyos/app-packages`. `internal/appstore` is hardyd's
  view of both.
- **Running.** `hardyd-priv` owns Docker: `apps.prepare` creates the app's
  dataset and files and checks the resolved Compose file, `apps.pull` gets
  one image (with retries, falling back to a copy already on the server),
  `apps.up`, `apps.stop`, `apps.logs` and `apps.remove` do what they say.
  Docker's data-root is `<pool>/docker`; its config is in
  `/var/lib/hardyos/apps/engine.json` (root-written). Docker is disabled at
  boot and started by hardyd-priv once that pool is mounted.
- **Apps engine (App Store v2).** Each app has its own user ID
  (30000-30999, in its `state.json` on the pool, kept with kept data) and a
  source (`catalog`, `upload`, `imported`, `custom`); untrusted sources need
  per-app grants for host network, GPU, devices and extra capabilities.
  Shared folders reach apps through `apps.ShareResolver` (implemented by
  `internal/shares`, wired in hardyd-priv's main): `Resolve` gives the
  host folder for `${HARDY_SHARE_<NAME>}`, `GrantApp`/`RevokeApp` set the
  app user's ACLs. The policy allows binds in the data folder or a chosen
  share (read grants forced read-only) and is re-checked against freshly
  resolved shares before every start. Limits are a systemd slice per app in
  `/run/systemd/system` plus `cgroup_parent` injected after the check; GPU
  devices and NVIDIA reservations are fitted to the hardware found at
  install. `apps.reconfigure`, `apps.config`, `apps.snapshot`,
  `apps.snapshots` and `apps.rollback` change, show, snapshot and roll back
  an installed app (code in `internal/apps/access.go`, `resources.go`,
  `lifecycle.go`).
- **API.** `GET /apps` (everyone: installed apps to open; admins also see
  containers, updates and kept data), `GET /apps/catalog`,
  `POST /apps/packages`, `POST /apps/plan`, and jobs for install, update
  and remove. Start, stop and restart are quick synchronous calls, audited.
- **App Store window.** My apps (open, start, stop, logs, update, remove)
  and Discover (the catalog and the install dialog: permissions in plain
  words, ports, settings, and the pool the first time).

### App Store API, catalogs and app windows (App Store v2)

hardyd's side of the App Store v2 (plan: `docs/plans/app-store-v2.md`
section 3; decisions 65-69):

- **Records in hardyd's database** (migration `0005_apps_web.sql`, so
  settings backups carry them): `app_access` (who may use each app; no rows
  = everyone), `app_catalogs` (imported catalogs with their last good
  index) and `app_proxy_ports` (each app's window port). `internal/appstore`
  owns them next to the package store.
- **Access.** `GET /apps` shows non-admins only the apps they may use;
  `POST /apps/{id}/open` and the window proxy check the same list.
  Principals are HardyOS users, `NETBIOS\user`, `NETBIOS\group` and
  everyone; a signed-in person's principal and groups come from
  `api.AppPrincipals` / the account's `auth.Identity` methods (domain
  sign-in), else the HardyOS username.
- **Jobs.** `apps.install` and `apps.update` call `apps.prepare` with the
  package's source (catalog, upload, imported + catalog name, custom),
  shares, grants and limits; `apps.update` takes `apps.snapshot
  reason=update` first and, if a later step fails, ends with
  `result.snapshot`. `apps.reconfigure` runs `apps.reconfigure` then
  `apps.up`; `apps.rollback` runs `apps.rollback`. Passwords reach jobs
  through the in-memory secret box. Grants come only from an admin's
  request, are checked against what the package asks for, and are audited
  one by one (`apps.grant`, `apps.grant.remove`).
- **Imported catalogs.** hardyd fetches `index.json` (https only, 30 s, at
  most 1 MB, redirects only to https) and packages (at most 512 KB) itself;
  a package is used only if its SHA-256 matches the index and it is the app
  and version the index names. Packages are cached in
  `/var/lib/hardyos/app-imports`. hardyd-priv never touches the network for
  them.
- **Custom apps.** `POST /apps/custom` packs a manifest, the pasted
  Compose file and a generated icon into a `.hardyapp` (source `custom`,
  stored like an upload) and answers with an install plan.
- **Window proxy** (`api/appproxy.go`). For every installed app with a web
  page hardyd listens on its own port (44300 + n, kept in the database) with
  the desktop's certificate and reverse-proxies to `127.0.0.1:<web port>`,
  WebSockets included. `X-Frame-Options` and `frame-ancestors` from the app
  are removed and replaced with `frame-ancestors` for the desktop's origin;
  the desktop's own CSP allows `frame-src` on its host's ports. Sign-in:
  `POST /apps/{id}/open` mints a single-use token (one minute) bound to the
  person, the app and their desktop session; the proxy swaps it for an
  HttpOnly, SameSite=Lax cookie named for that app. Every 30 seconds the
  proxy checks that the desktop session still exists and the person may
  still use the app. HardyOS's own cookies (the desktop session and every
  app's proxy cookie) are stripped from requests before they reach the app.
  A reconcile loop starts proxies for new apps and stops them for removed
  ones. To be replaced by per-app subdomains when the reverse proxy lands.
- **Web.** `apps/store/`: the stepped install dialog (settings, shared
  folders, permissions, who can use it, limits under Advanced), the app
  details view (overview, settings, access, snapshots, logs), Catalogs,
  Create an app, and `AppFrame` (an installed app as a desktop window, id
  `os.hardy.appwindow:<app id>`).

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
