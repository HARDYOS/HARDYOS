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
- **Password check.** hardyd (not root) asks this server's own DC for a
  ticket-granting ticket with a Kerberos AS exchange (gokrb5, pure Go, TCP,
  no krb5.conf or DNS lookups): the realm and the DC's address come from
  `domain.status`, cached for 30 seconds. hardyd reaches its DC through the
  shim route, inside the host; `SetupNetwork` pins the ARP entries on both
  ends of it (`ip neigh ... nud permanent`), so answers from the LAN can't
  pull that traffic away. Partner DCs are never asked, not even when the
  local one is down: an AS reply only shows that whoever answered knows a
  key for the password typed, which anyone answering for a partner's
  address can make up. If the local DC doesn't accept a connection within
  2 seconds, sign-in answers 503 `domain_unavailable` ("the domain
  controller on this server isn't answering; sign in with a HardyOS
  account"); the whole check is bounded at 10 seconds. A server without a
  DC of its own (member mode, later) refuses domain sign-in with 503
  `no_local_dc` until a service-ticket check with a machine keytab exists.
  The ticket is thrown away.
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
  primary group included; BUILTIN groups left out) with each group's SID
  (`groupSids`) and the domain's SID (`domainSid`). Turned-off and expired
  accounts are refused. The role goes by SID, never by name (anyone allowed
  to create or rename a group picks its name): members of `<domainSid>-512`
  (Domain Admins) or of the HardyOS Admins group whose objectSid is
  recorded in the domain settings (`adminsGroupSid` in `hardyos-dc.json`,
  so it's in domain backups) are administrators, everyone else is a user.
  A renamed HardyOS Admins keeps working. It isn't created automatically:
  the Domain page's button runs `POST /domain/admins-group` (a job,
  audited), whose root op `domain.admins_group.create` creates the group
  and records its SID. If a group of that name already exists, HardyOS
  didn't make it: the page shows its members and records it only when an
  administrator adopts it (`adopt: true`); built-in groups are never
  adopted. A DC that joined a domain records the group again the same way.
- **Records.** The first sign-in creates a row in `users` with
  `source = domain`, `username = HOME\alice` and an empty password hash, so
  sessions, jobs and the audit log point at domain users the same way as at
  local ones. The row holds the name, email, role and groups (`HOME\Family`)
  from the domain; sessions record `source` and `principal`. While signed
  in, the groups are looked up again at most every 10 minutes (from the
  request that finds them older); a deleted, turned-off or expired account,
  or a different domain, ends all its sessions. If the domain can't be
  asked, the known groups stay and the lookup is retried a minute later;
  after 30 minutes (3 refresh intervals) without a lookup that worked, the
  account is a user (written to its row) and `/auth/me` says why in
  `roleNote`, until a lookup works again.
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
- **What a pool says isn't trusted.** A pool can come from anywhere, so
  `shares.Manager.List` reads it defensively (decision 105): `zfs list -Hp`
  rows are accepted only when they line up exactly with `zfs list -H -o
  name` (one row per dataset, one field per property, each dataset once),
  which a tab or line break in a user property breaks; otherwise each
  `<pool>/shares/<id>` is read alone with `zfs get -Hp -o property,value`
  (exactly one line per property). Every value is checked again like
  input (`CleanName`, the description rules, `CleanRules`, app grants,
  `CheckServices`; invalid ones are logged once and replaced by the id, no
  description, administrators only, no apps, the default services). The
  folder's path is used for root work only when `/proc/self/mountinfo`
  says the visible mount there is a ZFS mount of that very dataset's root;
  its device is kept in `Share.RootDev` (never sent to hardyd), and every
  root-side user opens the folder with `shares.OpenRoot` (`openat2` from
  `/` with `RESOLVE_NO_SYMLINKS`, must be on that device): the ACL walkers,
  the people root, app, NFS and hardyos-files grants (checked right before
  `setfacl`), smb.conf, the recycle bin and its cleaner, and the file
  workers' roots. NFS exports go by `Mounted`, which is false for an
  unverified folder.
- **Root side.** `internal/shares` (in hardyd-priv) behind the ops
  `shares.list/create/update/delete/starter/folders`. The apps engine uses
  the same Manager in-process through `apps.ShareResolver`: `Resolve` gives
  the real path of a share or a subfolder (never outside it), `GrantApp` and
  `RevokeApp` add or remove the app user's ACL entries (the share root at
  once with setfacl, everything below in a background walk that never
  follows links and never enters `.recycle` or `.zfs` at the top) and
  record them in `org.hardyos:apps`.
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

## Shared folder snapshots and NFS

File sharing part B ([plans/file-sharing.md](plans/file-sharing.md)
section 2; user notes in [shares.md](shares.md)).

- **Automatic snapshots.** `internal/snapshots` runs inside hardyd-priv
  (`Manager.Run`, wired in `cmd/hardyd-priv/main.go`): a tick at start and a
  couple of seconds after every minute, in UTC. For every mounted shared
  folder and every kind kept by `services.snapshots` it takes the snapshot
  of the kind's current slot (hourly at :00, daily 00:00, weekly Monday
  00:00, monthly the 1st 00:00) if it's missing, named
  `<dataset>@hardyos-auto-<kind>_<YYYY-MM-DD-HHMM>` after the slot, all kinds
  due together in one `zfs snapshot` (one transaction group). Then each
  kind is pruned to its count by slot time, oldest first. Only labels that
  parse exactly as an automatic snapshot of a real slot are ever pruned:
  manual snapshots, app snapshots and anything else are never touched.
  Missed slots are not back-filled; a server that was off gets one
  snapshot per kind for the newest slot. A per-dataset memory of the plan
  last carried out (slots and counts) makes an idle minute one `zfs list`
  of the shares; folders that are unmounted (locked or exported pools) are
  skipped, a folder deleted mid-tick only logs, failures are retried next
  minute.
- **Manual snapshots.** Root ops `snapshots.list {share}`,
  `snapshots.create {share, name}` (name checked, `hardyos-auto-` refused,
  marked `org.hardyos:snapshot=manual`), `snapshots.delete {share,
  snapshot, confirm}` (confirm = the name; `zfs destroy` of that one
  snapshot, never `-r`). API `GET /shares/{id}/snapshots` for admins and
  anyone the folder's rules let in (a matching `none` rule wins; 404
  otherwise); `POST /shares/{id}/snapshots` and
  `DELETE /shares/{id}/snapshots/{snapshot}` are admin jobs
  (`snapshots.create`, `snapshots.delete`, on the shares lock), audited as
  `shares.snapshot.create` / `shares.snapshot.delete`. Restoring files is
  the File Manager's (part C), read-only from `.zfs/snapshot/<name>`.
- **NFS.** `internal/nfs` (hardyd-priv) renders
  `/etc/exports.d/hardyos.exports` from every mounted folder with NFS on:
  one line per folder, clients most specific first (addresses, then
  networks by prefix length), `rw`/`ro` per client plus
  `sync,no_subtree_check,all_squash,anonuid=<uid>,anongid=<uid>,sec=sys,insecure`.
  The uid is the folder's own NFS identity from 31000-31999 in
  `org.hardyos:nfs-uid` (allocated lowest free when NFS is first turned on,
  kept while the dataset exists, clashes from imported pools resolved in
  favour of folders with NFS on). It gets `r-X` or `rwX` (write if any
  client writes) as access and default ACL entries through the shares
  walker (`shares.GrantNFS` / `RevokeNFS`, root at once, below in the
  background), before the folder is exported. Clients are re-validated with
  `shares.CheckServices`, paths must be plain absolute names, and the whole
  file is checked again (`nfs.Validate`) before an atomic write; then
  `exportfs -ra`, and if that fails the previous file is put back.
  `nfs-server.service` is enabled and started (`--no-block`) while
  anything is exported and disabled and stopped when nothing is.
- **Staying in sync.** `priv.RegisterShares` takes `ShareHook`s:
  `RegisterNFS` returns one whose `BeforeDelete` withdraws the folder's
  export (a file system nfsd holds can't be unmounted) and whose `Changed`
  re-syncs after every create, update, delete and starter set. `Watch`
  also syncs at start and every 2 minutes (pools imported or unlocked
  later). Ops `nfs.status` and `nfs.apply`; API `GET /shares/{id}/nfs`
  (admin: path, uid, server running, last problem).
- **Web.** The shared folder dialog's `ShareSnapshotsSection.tsx`
  (retention counts, list, take now, delete with confirmation) and
  `ShareNFSSection.tsx` (on/off, clients with read/write, the mount
  commands for Linux, fstab and macOS). Each saves only its part of
  `services`, re-reading the folder first (`shareServices.ts`).
- **Tests.** Unit tests with `sysexec.Fake` (slots across hour, day, week,
  month and year boundaries, UTC only; pruning; idempotent ticks;
  catch-up; exports rendering including IPv6; uid allocation).
  `TestZFSIntegrationSnapshots` runs the scheduler on a file-backed pool in
  CI's ZFS job; `TestNFSIntegration` (CI's "NFS (loopback)" job,
  `HARDYOS_NFS_INTEGRATION=1`) mounts real exports over 127.0.0.1 with
  NFSv3 and v4.

## SMB file server

File sharing part A ([plans/file-sharing.md](plans/file-sharing.md)
section 1; user guide in [file-sharing.md](file-sharing.md)).

```
   Windows / Mac ──SMB 445──► smbd (host) ──► /mnt/<pool>/shares/<id>   POSIX ACLs per rule
                                 │ winbindd (host): HOME\alice → uid 101103 (rid)
                                 ▼
                     hdc-shim ──► DC (netns hardyos-dc, its own Samba)
```

- **Two Samba instances.** The DC's Samba stays in its namespace with its
  own config and `/run/samba` (Domain controller). The host runs Debian's
  `smbd.service` and `winbind.service` as a **member server** of the
  domain; they're unmasked in the image but stay disabled until the join,
  nmbd is masked (no NetBIOS). `internal/smb` (in hardyd-priv) owns
  `/etc/samba/smb.conf`, `/etc/krb5.conf` (the realm, its DCs as KDCs) and
  the winbind entries in `/etc/nsswitch.conf`. Samba's own databases
  (machine account, ID map) and the keytab live in `/var/lib/hardyos-files`,
  the dataset `rpool/hardyos-files` shared by every boot environment, with
  `settings.json` (SMB on/off, home folders) and `state.json` (membership,
  which shares' trees have their permissions).
- **Joining.** `files.join` writes the config, then runs `net ads join`
  with `PASSWD_FD=0` and the password on stdin (sysexec's `RunEnv`), never
  on argv. For this server's own domain it uses the DC's details
  (`domain.Manager.Load`: NetBIOS name, DCs with this one first as
  `password server`, the HardyOS Admins SID); for another domain it asks a
  DC found through DNS for the short name (`net ads lookup`). The
  server registers its LAN addresses in the domain's DNS. The provision
  and DC-join jobs in hardyd call `files.join` with the same password at
  their end (a failure only leaves a note in the job), and deleting the
  domain calls `files.leave` without a password. `files.leave {confirm}`
  deletes the computer account when given the password, then disables the
  units and wipes the machine secrets and ID map here.
- **ID mapping.** `* : tdb 3000-7999`, `<NETBIOS> : rid 100000-999999`, so
  `HOME\alice` (RID 1103) is uid 101103 on every HardyOS server, clear of
  local users, app UIDs (30000-30999), NFS (31000-31999) and hardyos-files
  (29999). `winbind use default domain = no`; template shell nologin.
- **Shares.** One `[<Name>]` per shared folder with SMB on, mounted:
  `vfs objects = catia fruit streams_xattr [shadow_copy2] acl_xattr
  [recycle]`, `read only = yes` plus `valid users` / `read list` /
  `write list` / `invalid users` from the rules (Everyone =
  `@HOME\Domain Users`; `@HOME\Domain Admins` and the HardyOS Admins SID
  always in the write list), `inherit acls`, `map acl inherit`,
  `access based share enum`, guest (`guest ok`, `nobody` read-only) when
  the folder's guest flag is on, `.recycle` hidden, `.hardyos*` vetoed.
  Generated configs are checked with `testparm` before they replace the
  old one; a changed `[global]` restarts winbind and smbd, a changed share
  list reloads smbd.
- **Permissions on disk.** The same rules become POSIX ACL entries
  (`shares.PeopleACL`: users and groups resolved through winbind with
  `getent`; write rwX, read r-X, a user with no access ---, `u:nobody:r-X`
  for guests, Domain Admins rwX) on the share root at once
  (`shares.SetPeopleRoot`, "other" cleared) and everything below in a
  background walk (`shares.ApplyPeopleTree`, the app grants' no-follow fd
  walker). Only entries in the domain and Samba ID ranges and the guest's
  are file sharing's; app, NFS and file-manager entries are kept. A walk
  runs again only when the entries changed (hash in `state.json`) or the
  root's ACL differs. If Domain Admins can't be looked up (winbind down),
  nothing is changed.
- **Previous Versions.** `shadow_copy2` with `shadow:snapdir =
  .zfs/snapshot`, `shadow:mountpoint` = the folder,
  `shadow:snapprefix = ^hardyos-auto-\(hourly\|daily\|weekly\|monthly\)$`
  (a basic regex, as Samba compiles it), `shadow:delimiter = _`,
  `shadow:format = _%Y-%m-%d-%H%M`, UTC: part B's automatic snapshots.
- **Recycle bin.** `vfs_recycle` into `.recycle/<netbios>.%U` (the same
  bin names as the File Manager's, decision 106; folders and versions
  kept, access time set on delete, bins and their folders made 0700); off
  on Time Machine folders. Every apply makes sure `.recycle` is root's,
  1777 and without ACL entries (fixed through an `O_NOFOLLOW` descriptor; a
  link, a file or another file system there is refused) and looks at every
  bin named after an account: one that isn't a folder owned by that
  account (anyone can make folders in `.recycle`) is renamed to
  `.hardyos-quarantine-<time>-<name>` and locked (root's, 0700), one that
  is the owner's but open to others is closed up (0700, no ACLs). Once a
  day hardyd-priv removes what has been there 30 days, through fds opened
  with `O_NOFOLLOW` and `unlinkat`, staying on the folder's file system;
  a folder is only entered when the descriptor opened is the inode it
  looked at, with its times read again from the descriptor. The people
  walker never enters `.recycle` or `.zfs` at the top.
- **Name lookups** go through `rangeChecked`: an ID winbind (or anything
  else in NSS) gives outside the idmap ranges (3000-7999, 100000-999999)
  makes the name unknown, so it never reaches an ACL entry or a chown.
  The homes dataset's mount is verified like a shared folder's before its
  mode is set.
- **Time Machine and Avahi.** Folders with Time Machine get
  `fruit:time machine` (+ `max size`); `fruit:metadata = stream`,
  `fruit:model = MacSamba` are global. hardyd-priv writes
  `/etc/avahi/services/hardyos-smb.service` (`_smb._tcp`, `_device-info`,
  `_adisk._tcp` with one `dkN` record per Time Machine folder) while smbd
  serves; Samba's own mDNS registration is off.
- **Home folders.** With File Services › Home folders on, hardyd-priv
  makes `<pool>/homes` (posixacl, devices/setuid off, mode 0711) and one
  dataset `<pool>/homes/<netbios>.<user>` (lower case, owner the user and
  Domain Users, 0700, the default quota) for every turned-on account (an
  LDAP search with the machine account), when turned on and every 10
  minutes; it never removes one. `[homes]` has no path: winbind's
  `template homedir = <mount>/<netbios>.%U` gives it, so no script runs
  as root on connect.
- **Staying in step.** `priv.RegisterFiles` returns a `ShareHook`:
  `Changed` runs `files.apply` after every shared folder change (even a
  failed one), `BeforeDelete` takes the folder out of smb.conf, stops its
  walk and has smbd close it (`smbcontrol close-share`) so its dataset
  isn't busy. `smb.Manager.Watch` applies again every 10 minutes (new
  accounts' homes, a DC that moved) and empties old recycle-bin files
  daily.
- **Ops and API.** Root ops `files.status`, `files.join`, `files.leave`,
  `files.settings`, `files.apply` (`priv/files_ops.go`). API
  `GET /files` (everyone signed in; settings and problems for admins),
  `POST /files/join`, `POST /files/leave` (`confirm: true`),
  `PATCH /files/settings`, all three jobs (lock `files`), audited, with
  passwords only in the job secret box.
- **Web.** Control Panel › File Services (`FileServices.tsx`: join,
  status, SMB on/off, home folders, leave, how to connect from Windows,
  Mac, Linux and Time Machine) and the shared folder dialog's SMB section
  (`ShareSMBSection.tsx`: SMB, Previous Versions, Time Machine and its
  size, the folder's addresses).
- **Tests.** Unit tests with `sysexec.Fake` (golden `smb.conf` with
  tricky names, rule mapping, the password never on argv, homes, recycle
  cleanup that never follows links); `TestPeopleACL` runs the walker on
  the machine's file system; `TestSMBMemberIntegration` (CI's Samba job,
  `HARDYOS_DC_INTEGRATION=1`, root) creates a DC, joins the host's Samba
  to it from a temporary folder on port 4455 and checks read, write, no
  access, guest, the recycle bin and Previous Versions with smbclient.

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
  source (`catalog`, `upload`, `imported`, `custom`) that hardyd-priv
  derives from the package bytes (catalog only if they match a package in
  `/usr/share/hardyos/apps`; decision 75); untrusted sources need
  per-app grants for host network, GPU, devices and extra capabilities.
  Shared folders reach apps through `apps.ShareResolver` (implemented by
  `internal/shares`, wired in hardyd-priv's main): `Resolve` gives the
  share root for `${HARDY_SHARE_<NAME>}` (apps never get subfolders),
  `GrantApp`/`RevokeApp` set the app user's ACLs. The policy allows binds
  in the data folder or of a chosen share's root (read grants forced
  read-only), never one bind source inside another (decision 76), and is
  re-checked against freshly resolved shares before every start. Folders
  in an app's data are created with fd-relative calls that never follow
  links. A rollback never brings back grants or shares removed since
  (decision 77). Limits are a systemd slice per app in
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
section 3; decisions 65-69, security review 80-82):

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
  the desktop's own CSP allows `frame-src` on its host's ports. Proxies
  listen on the desktop's own listen host. Ports don't isolate apps
  (cookies are per host, and SameSite counts every port of a host as one
  site), so until per-app subdomains replace them (with the reverse proxy)
  the proxy does (decisions 80-81): app cookies are renamed
  `a_<app id>_<name>` on the way out (no `Domain`, `hardyos_*` dropped) and
  only that app's are forwarded, prefix removed; changes and WebSockets from
  another Origin and same-site non-navigations (`Sec-Fetch-*`) are refused.
  Sign-in: `POST /apps/{id}/open` mints a single-use token (one minute)
  bound to the person, the app and their desktop session; the proxy accepts
  it only for an iframe or document load (same-site or none) in a browser
  that sends that same desktop session cookie, and swaps it for an
  HttpOnly, SameSite=Strict cookie named for that app; every later request
  needs the matching desktop cookie too. At most every 30 seconds per
  request, and on a 30-second sweep, the proxy checks the desktop session
  with `peekSession` (no idle-timeout slide), the account through
  `sessionUser` (the same domain refresh as the desktop's own requests) and
  the access list. Hijacked connections (WebSockets) are tracked per
  session and closed when a check fails, on sign-out, access change,
  account disable or password reset, on stop, and when an app job
  (install, update, remove, reconfigure, rollback) finishes: the proxy
  watches job events and then drops that app's listener, tokens and
  sessions before reconciling. A 20-second reconcile loop also starts
  proxies for new apps and stops them for removed ones.
- **Provenance** (decision 82). `app_origins` (migration
  `0006_apps_web_sec.sql`) records each install's source and, for imported
  apps, the catalog's id; an imported package ref carries `catalogId` and
  that catalog must list the sha. Installing or updating an id from another
  source or catalog needs `replaceSource`. Custom-built packages live in
  their own folder (`app-packages/custom`), apart from uploads. Catalog
  fetches go through a dialer guard (`appstore/netguard.go`) that refuses
  local addresses unless the catalog has `local_network` set.
- **Web.** `apps/store/`: the stepped install dialog (settings, shared
  folders, permissions, who can use it, limits under Advanced), the app
  details view (overview, settings, access, snapshots, logs), Catalogs,
  Create an app, and `AppFrame` (an installed app as a desktop window, id
  `os.hardy.appwindow:<app id>`).

## File access as the person

The File Manager, share links and (later) WebDAV read and write files in
shared folders through one interface, `files.Access` (plus `files.Extended`
for chunked uploads, copies with progress and permanent deletes;
`files.Service` is both). hardyd's implementation, `files.Client`, calls the
`files.*` operations of hardyd-priv; neither daemon ever touches a person's
files as itself (decisions 92-95).

```
browser ── /api/v1/files/* ──▶ hardyd (files.Client) ── files.open … ──▶ hardyd-priv
                                   ▲  fd (SCM_RIGHTS)                        │ fork+exec, already the person
                                   └─────────────── fd ◀── worker: "hardyd-priv fileworker"
                                                           openat2 beneath the share root
```

- **Who.** hardyd looks the person up again on every call (`files.UserLookup`:
  disabled or deleted accounts stop working, domain groups as of the last
  refresh, the current role). Domain accounts act as their own Linux user:
  hardyd-priv asks NSS (winbind) through `/usr/lib/hardyos/hardyos-nss`, a
  tiny cgo helper that only calls `getpwnam_r` and `getgrouplist` (the
  rest of hardyd-priv is built without cgo, and Go's pure lookup never
  reaches winbind). Only IDs in winbind's ranges (3000-7999,
  100000-999999) are accepted; other groups (root, disk, ...) are dropped.
  HardyOS administrators (local accounts) act as the `hardyos-files` system
  user (UID 29999, made by the package's postinst), which hardyd-priv gives
  `rwX` on every shared folder with the same no-follow ACL walker as app
  grants (at start-up, every 10 minutes and before an administrator's
  folders are listed). Family members with HardyOS accounts get no files.
  Root is never acted as. A person's home folder is only looked for on the
  pool File Services keeps homes on, as `<pool>/homes/<netbios>.<user>`
  whose `org.hardyos:home` (set when hardyd-priv made it) names that very
  account, mounted (verified in the mount table) where it says.
- **Accountability.** hardyd-priv logs every `files.*` operation with the
  principal, Local and Admin as hardyd sent them, the uid/gid it ran as,
  the folder and path(s), and the outcome (`file operation`), and every
  refusal before an identity was found (`file operation refused`). See
  "Trusting hardyd" below for what this does and doesn't protect.
- **How many at once.** At most 32 workers run at once and 8 for one
  principal (`MaxWorkers`, `MaxWorkersPerPerson`); more wait for a slot
  until their request's context ends, so a flood of requests can't fork the
  server to death or starve everyone else.
- **The folder's rules** are checked first (`fileworker.Level`: a `none`
  rule beats everything, otherwise the highest matching level; no match =
  no access; administrators may use every folder). Read-only folders refuse
  every change before a worker starts. Then the disk's permissions decide,
  because the worker *is* the person.
- **Workers.** For each operation hardyd-priv opens the share root
  (`O_PATH`, with `shares.OpenRoot`: only a folder whose mount was
  verified, reached without following any link and on that mount's
  device), and starts `hardyd-priv fileworker` with the person's
  credentials set between fork and exec (`setgroups`, `setgid`, `setuid`),
  so not one instruction runs as root. The worker refuses to run as root or
  with any capability, sets `PR_SET_NO_NEW_PRIVS` (all threads) and
  `PR_SET_DUMPABLE 0`, reads one JSON request on stdin (fd 3: a socket back,
  fd 4+: the roots) and writes one JSON answer. Every path is resolved with
  `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`
  from the root's descriptor; changes use the `*at` calls on the parent's
  descriptor (`renameat2(RENAME_NOREPLACE)`, `mkdirat`, `unlinkat`), and
  recursive deletes walk by descriptor. Links, devices, pipes and sockets
  are never listed or opened; `..`, `.recycle`, `.zfs` and `.hardyos*` are
  refused in paths. An upload's own temporary name (`.hardyos-upload-<hex>`)
  may only end the path of create and openwrite, a rename's source and a
  permanent delete (`fileworker.OpPath`), never a rename's destination. A
  worker costs about 10 ms.
- **Files, not bytes.** `files.open`, `files.create` and `files.openwrite`
  hand the open file to hardyd over SCM_RIGHTS (worker → hardyd-priv →
  hardyd); hardyd streams it (`http.ServeContent`: Range, If-Range), writes
  upload chunks into it, or copies between two of them (`copy_file_range`,
  so ZFS can clone blocks). No file content goes through JSON. Before
  passing it on, hardyd-priv checks the descriptor: a regular file, opened
  read only for open and write only for create/openwrite (`F_GETFL`, never
  `O_PATH`), on the folder's own device unless it's an older version.
- **Recycle bin.** Deleting in a folder with the recycle bin on moves the
  item to `.recycle/<bin>/<its folders>/`; a name already there gets
  " (deleted <date time>)". Bins are named so a name can only be one
  account's (decision 106): `<netbios>.<user>` in lower case for domain
  accounts (as in SMB's `recycle:repository`), `hardyos-files` for
  administrators (a domain bin always has a dot, so it can never be that).
  Before a recycled delete hardyd-priv makes sure `.recycle` is root's,
  1777 and without ACL entries (`shares.EnsureRecycle`, through an
  `O_NOFOLLOW` descriptor; a link or file there is refused). The worker
  then makes or opens the person's bin and checks it on the descriptor: a
  folder owned by the person (someone else's is refused with a clear
  error: "delete permanently instead") with no group, other or ACL access
  (its own, if too open, is closed up first). The ACL walkers (people,
  apps, NFS, hardyos-files) never enter `.recycle` or `.zfs` at the top,
  so bins stay owner-only: administrators don't get into other people's
  bins (a root shell can).
- **Older versions** come from `.zfs/snapshot/hardyos-auto-<kind>_<UTC
  time>/…` (contract section 2), read only. A file's versions leave out
  copies equal to the current file or to the next newer version. Restore
  copies the version back to its path, or to "name (restored
  2026-10-24).ext" when the name is taken.
- **Uploads** go to `.hardyos-upload-<id>` next to the target, chunk by
  chunk at the offset the server has, and are renamed into place (never
  over a folder; over a file only with `overwrite`). Abandoned ones are
  dropped after a day by hardyd and removed after two days when their
  folder is listed.
- **API** (`handlers_files.go`, `/api/v1/files/*`): shares, list, stat,
  download (file with Range, or a streamed zip for folders and several
  items; previews only for safe types, under `sandbox` CSP), upload
  (start / chunk / status / cancel), mkdir, rename, move, copy, delete,
  snapshots, restore. Small copies, moves and deletes answer at once;
  more than five items, folders and big files run as jobs with progress
  (`files.copy`, `files.move`, `files.delete`, `files.restore`). Deletes,
  restores, uploads, renames, moves and job-run copies are audited.
- **Code.** Root side `internal/fileworker` (`server.go`: identity, rules,
  roots; `spawn_linux.go`: starting workers, receiving descriptors;
  `worker_linux.go`: the operations), operations in
  `priv/fileworker_ops.go`, the NSS helper in `cmd/hardyos-nss`, the
  hardyos-files grant in `shares/filesuser_linux.go`; hardyd side
  `internal/files` (`client.go`, `copy.go`). Tests run real workers (the
  test binary re-runs itself as the worker): as root they create files owned
  by made-up users and check each can do exactly what its user can; without
  root they run as the test's own user.

### Trusting hardyd (and what comes next)

hardyd is unprivileged and treated as possibly compromised, yet today the
`Who` of a `files.*` call (principal, Local, Admin, groups) is hardyd's
word: hardyd-priv works out the Linux identity from it and never runs as
root for the person, but a compromised hardyd could still claim to be any
domain account, or a HardyOS administrator (and so hardyos-files). What
holds today: no operation ever runs as root or outside a verified shared
folder or home, the folder rules and disk permissions still apply to the
identity claimed, workers are capped, and every operation is logged with
the principal and resulting uid by hardyd-priv, which hardyd can't edit.

The planned fix is a **root-issued session attestation** (not built yet):

- Sign-in is checked on the root side: hardyd-priv (not hardyd) verifies
  the password or the SSO/Kerberos assertion and the account's state
  (enabled, role, domain groups from winbind), so hardyd never decides who
  someone is.
- hardyd-priv then issues a short-lived token binding the session id, the
  principal, Local/Admin, the groups and an expiry, MACed with a key only
  hardyd-priv holds (`/run/hardyos/priv`, root 0700, new at every boot);
  hardyd keeps it with the session and sends it with each `files.*` call
  instead of a bare `Who`.
- hardyd-priv verifies the MAC and the expiry, re-checks that the account
  is still enabled (cached for a minute), and acts only as the attested
  identity; sign-out and expiry revoke it (a revocation list in
  hardyd-priv). Share links would carry a creator attestation renewed while
  the creator still signs in, so a link can't outlive its creator's
  access even if hardyd's database is changed.

Without the root-side sign-in check an attestation would only launder
hardyd's claim, so both parts come together.

## File Manager and share links

The web desktop's File Manager and web share links (part D of
[plans/file-sharing.md](plans/file-sharing.md); user notes in
[file-sharing.md](file-sharing.md#file-manager)).

- **File Manager** (`web/apps/shell/src/apps/files/`). A desktop app over
  the files API (`/files/shares`, `/files/list`, `/files/download`,
  `/files/upload`, `/files/mkdir|rename|move|copy|delete`,
  `/files/snapshots`, `/files/restore`; part C), so every read and write
  happens as the signed-in person. Uploads are chunked (8 MiB PUTs at an
  offset after `POST /files/upload`, three files at a time, a failed chunk
  retried three times from what the server has, cancel = `DELETE`); they
  never overwrite (a taken name gets " (2)"). Downloads, previews
  (`inline=1`) and older versions (`snapshot=`) are plain links to
  `/files/download`, so the browser streams them and seeks with Range.
  Moves, copies and deletes accept an immediate answer or a job and follow
  the job. The layout switches on container queries (the window's width,
  not the screen's).
- **Share links** (`internal/sharelinks`, API in
  `api/handlers_sharelinks.go`). Table `share_links` (migration 0007):
  SHA-256 of a 32-byte random token (the token is returned once), share,
  path, folder or file, creator's user id and principal, created and
  expires (default 7 days, 1-90), argon2id password hash (the account
  hasher), uploads (folders only), download limit and count, revoked.
  Making one needs `files.Access.Stat(...).Writable` as the person, or an
  admin; revoking needs the creator or an admin; `GET /sharelinks?scope=all`
  is admin only. Audited: `sharelink.create`, `.revoke`, `.download`,
  `.upload` and `.password` (wrong passwords).
- **Public pages** (`sharelinks.Public`, mounted at `/s/` by hardyd,
  outside `/api` and the desktop session). Server-rendered `html/template`
  pages, one stylesheet and the mark (`/s/-/static/`), no scripts:
  `Content-Security-Policy: default-src 'none'; style-src 'self';
  img-src 'self'; form-action 'self'; frame-ancestors 'none'`,
  `Referrer-Policy: no-referrer`, noindex. Every request: per-IP (240/min)
  and per-token (600/min) limits; look the link up by hash; check it is not
  revoked, expired or used up; load the creator now (disabled, deleted or
  gone from the domain stops it); check the password cookie (an HMAC over
  link id, password hash and expiry, keyed per process, path `/s/<token>`);
  and `Stat` the target as the creator. Then `List`, `Open` or `Create` as
  the creator through `files.Access`. Sub paths are cleaned (no `..`, no
  hidden `.recycle`, `.zfs`, `.hardyos*`) and joined below the link's path;
  listings and zips leave hidden names out and never touch snapshots.
  Downloads are `attachment` with `Content-Security-Policy: sandbox`, Range
  via `http.ServeContent`, counted and audited once per download (decision
  103): every GET of a file is counted unless it asks for exactly one range
  that doesn't include byte 0 (parsed as ServeContent does, whitespace and
  all; an If-Range that would send the whole file counts too) **and**
  carries the download ticket the counted response set (cookie
  `hardyos_dl_<id>_<path hash>`, path `/s/<token>`, HMAC over link id,
  file path and expiry, 6 hours). A used-up link still lets a ticketed
  resume finish; nothing else. HEAD is never counted or audited and reads
  no folder. Folder downloads stream a zip, always counted whatever Range
  says, at most one at a time per link and two per address (429), at most
  20 000 entries, 32 levels and the link's zip cap (`max_zip_bytes`,
  default 20 GB, 1 MB-1 TB); a bound ends the zip with a "Not included.txt"
  note, any other failure aborts the connection. Zip entry names have `\`,
  `:` and control characters replaced by `_` (the File Manager's zips too).
  Uploads are multipart, same-origin only, never replacing a file, names
  starting with `.` or with control characters refused; each link has an
  upload budget (`max_upload_bytes`, default 10 GB, 1 MB-1 TB) reserved in
  8 MiB steps as bytes arrive (`Store.ReserveUpload`, atomic in SQL) and a
  per-file cap (5 GB, `Public.MaxFileBytes`); a failed or refused file is
  deleted permanently (`DeleteItem(..., permanent=true)`), never recycled,
  and its reservation given back. Wrong passwords lock one address out of
  one link for 15 minutes after five tries, and the link for everyone only
  after 200 from all addresses in 15 minutes (`auth.LoginLimiter`).
- **Client address.** One helper, `internal/clientip`, gives the address
  for audit, sign-in limits and link limits: the peer, or the right-most
  untrusted `X-Forwarded-For` entry when the peer is one of
  `-trusted-proxies` (`api.Config.TrustedProxies`, empty by default, so the
  header is ignored until the reverse proxy sets it). The debug request
  log writes link paths as `/s/…`, never the token.
- **Wiring.** `api.Config.Files` is the `files.Access` from part C; while
  it's nil, links can't be made and existing ones say they don't work any
  more. The dev server proxies `/s/` to hardyd too.

## SFTP and WebDAV

File sharing part E ([plans/file-sharing.md](plans/file-sharing.md)
section 5; user guide in [file-sharing.md](file-sharing.md#sftp-and-webdav-from-anywhere)).
Both are for domain accounts only; both off until File Services turns
them on (`settings.json`: `sftpEnabled`, `webdavEnabled`) and per folder
(`services.sftp`, `services.webdav`, off for new folders).

```
 SFTP client ──22──► sshd (host) ── PAM: pam_winbind for uid 100000-999999 only
                       │ Match Group *\* / User *\*,*@*: internal-sftp, chroot /srv/hardyos/sftp/%U
                       ▼
               /srv/hardyos/sftp/101103/{Home,Media,...}   root's 0755, bind mounts (ro for read access)
                                                           → the person's own uid on disk (ACLs decide)
 WebDAV client ─443 /dav/─► hardyd (Basic, Kerberos like sign-in) ── internal/dav ── files.Client ── fileworker (the person)
```

- **SFTP is OpenSSH's.** hardyd-priv (`internal/sftp`, driven by
  `smb.Manager.applySFTP` on every apply: shared folder changes, settings,
  the 10-minute watch) writes `/etc/ssh/sshd_config.d/hardyos-sftp.conf`,
  checks the whole config with `sshd -t` (the previous file is put back if
  sshd refuses it) and reloads `ssh.service` only if it runs (HardyOS
  never starts or stops sshd). Domain accounts are matched two ways, by
  their groups (`Match Group *\*`: winbind names every domain group
  `HOME\...`, local groups never contain a backslash) and by the name typed
  (`Match User *\*,*@*`), with unquoted patterns that every sshd parses
  the same; both blocks set `AllowGroups hardyos-sftp`,
  `ChrootDirectory /srv/hardyos/sftp/%U`, `ForceCommand internal-sftp -d /`,
  `DisableForwarding yes` (and each forwarding switch), `PermitTTY no`,
  `PermitUserRC no`, `PubkeyAuthentication no`, `AuthorizedKeysFile none`,
  `AuthenticationMethods password`; the file ends with `Match all`. With
  SFTP off (or the server out of the domain) the file says `DenyGroups *`
  for the same matches. Local accounts' SSH is untouched. Order on
  every apply (decision 109): views, group, drop-in (`sshd -t`, reload),
  then `sshd -T -C user=<first planned account's NSS name>,host=x,addr=127.0.0.1`
  must show `forcecommand internal-sftp -d /`, `chrootdirectory <root>/%U`,
  `disableforwarding yes`, `allowgroups hardyos-sftp` (only),
  `authenticationmethods password`, `pubkeyauthentication no`,
  `permittty no` and the forwarding switches off (`sftp.CheckEffective`);
  only then does the PAM block go in. Any failure (no Include, another
  file setting something first, `sshd -T` failing, the session check
  below) takes the PAM block out and File Services shows *SFTP sign-in
  for domain accounts is off until this is fixed*. With nobody to let in
  the PAM block stays out.
- **PAM, sshd only.** A marked block goes in front of `@include
  common-auth` and `@include common-account` in `/etc/pam.d/sshd`:
  `pam_succeed_if uid >= 100000 uid <= 999999` selects domain accounts
  (anything else skips to the usual stack), `pam_succeed_if user ingroup
  hardyos-sftp` refuses non-members before winbind is asked (sshd hands
  PAM a deliberately wrong password for accounts AllowGroups refuses;
  that must not count towards their lockout in AD), then
  `pam_faillock preauth/authfail/authsucc deny=10 unlock_time=900` around
  `pam_winbind`, which decides alone (wrong password, turned off,
  expired, must-change all refused); the account block has the same
  membership check. A third block before `@include common-session` gives
  domain accounts `pam_limits` and ends their session stack
  (`pam_permit`, `done`), so common-session's `pam_systemd` (a
  `systemd --user` outside the chroot running `~/.config/systemd/user`)
  never runs for them; `sftp.CheckPAMSession` refuses the edit if a
  `pam_systemd` session line comes before that block (directly or via an
  include). Jumps never cross an `@include`. winbind stays out of the system-wide stacks:
  the image diverts libpam-winbind's pam-auth-update profile, and File
  Services warns if `common-auth` has winbind anyway. Debian's file
  without its includes is refused (`ErrPAMLayout`). Passwords go to the
  domain through winbind's machine-account secure channel, so this works
  on member servers too.
- **Views.** One per domain account (from the domain's turned-on accounts,
  IDs through the NSS helper) that has something to see:
  `/srv/hardyos/sftp/<uid>/`, root's 0755 (`/srv/hardyos/sftp` is a
  private mount, so binds don't spread into other mount namespaces).
  `sftp.Plan` uses the File Manager's rule (`fileworker.Level`: none beats
  all, highest match, admins by Domain Admins / HardyOS Admins gid all
  folders; group rules matched by gid): write → a read-write bind, read →
  read-only bind, none → nothing; Home is a bind of the home dataset. Only
  folders whose mount was verified get a view (decision 105), and a home
  only when the mount table says it's that home dataset's mount; the bind's
  source is opened with `shares.OpenRoot` on that mount's device. Binds
  (decision 108) are `open_tree(OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC)` of
  that descriptor (no `AT_RECURSIVE`), `mount_setattr` to
  `nosuid,nodev,noexec` (+`rdonly`) and `MS_PRIVATE` while still
  detached, then `move_mount` onto the target's O_PATH descriptor; the
  fallback is a non-recursive `MS_BIND`, `MS_PRIVATE` at once, the
  restricting remount, and the bind is dropped if anything appeared
  inside it meanwhile. A view is thus in no peer group: nothing the host
  mounts later shows up in it (no rw or suid copies inside read-only
  views), and nothing unmounted in it reaches the host. Not recursive on
  purpose: a dataset mounted inside a shared folder is an empty folder in
  views (accepted: ZFS makes mountpoint folders root's 0755, writes there
  would land hidden under the child mount on the host; SMB, WebDAV and
  the File Manager see the child). Every sync and release first makes
  the root private and then everything below it (`MS_PRIVATE`, then
  `MS_PRIVATE|MS_REC`), which also detaches binds made by earlier
  versions from the shared folders' peer groups before anything is
  unmounted. The sync manages only mounts exactly at
  `<root>/<uid>/<name>`: one is kept only if it's alone there, has
  nothing mounted inside, has the planned read-only flag, is restricted
  and private, shows the dataset's root (mountinfo field 4 `/`), the
  dataset as source and the verified device; anything else there is
  unmounted (detached with what's inside, if busy) and bound again;
  nothing deeper is ever unmounted by itself. Existing folders in the
  views are never chowned or chmodded (one could be a shared folder's top
  mounted there): only ones just made; a target on another device than
  its folder (something mounted) or still holding a mount that couldn't
  go is skipped. Folders are only ever `rmdir`ed when empty, never one
  something is mounted on. The
  `hardyos-sftp` system group (`gpasswd -M`) lists exactly the accounts
  with a view, as NSS names them. Before a folder is deleted
  (`ShareHook.BeforeDelete`) and before a pool is exported or destroyed or
  a dataset destroyed (`priv.Server.OnRelease`, called by the storage ops)
  its binds are unmounted, and the dataset (with everything below it)
  is held out of the views until the operation is over
  (`ShareHook.AfterDelete`, the done function `priv.Server.OnRelease`
  takes; at most 30 minutes), so the watch can't bind it again in
  between. Domain administrators get no view unless
  `settings.json` `sftpAdmins` (File Services › *Domain administrators
  too*) is on. Views are rebuilt after a reboot by the watch.
- **WebDAV is hardyd's.** `/dav/` (and `/dav`, plus `OPTIONS /` for
  Windows) in `api/handlers_dav.go`: HTTPS only (403 on plain HTTP unless
  the dev `Insecure` flag), WebDAV and the folders' switches from
  `files.status` (cached 15 s), Basic sign-in with
  `auth.SignIn.AuthenticateDomain` (a local HardyOS account's name is
  refused without its password being checked, answered 401 like a wrong
  password and counted against the address and `dav-local:<key>`, never
  the account's own key), the desktop's limiter keys
  (`ip:<addr>` via the trusted-proxy aware client address, and the
  account's key for every spelling), 503 without counting when the DC
  can't be asked. A password that worked is remembered for 2 minutes
  under HMAC-SHA256(per-process random key, account key + password); the
  account row is read again on every request (turned off here = out), and
  domain groups refresh like a session's. Successful sign-ins are audited
  at most hourly per account, failures always, rate-limited ones once per
  key per 15 minutes (with the count refused since); uploads, deletes,
  `MKCOL` (`files.mkdir`), modification times set by PROPPATCH
  (`files.settime`), moves (source and destination) and COPY
  (`files.copy`, from where) are audited with detail `webdav`. Request
  limits (decision 110): bodies other than PUT's at most 1 MiB;
  `PROPFIND` with `Depth: infinity` (or none) 403 with
  `<D:propfind-finite-depth/>`; `POST` 405; COPY/MOVE `Destination` is
  cleaned and must stay below `/dav`, the same file or folder as the
  source (after cleaning and resolving) or a folder into itself is 403
  before x/net/webdav (which would delete the destination first) sees
  it, and it gets the cleaned, escaped paths; LOCK timeouts are capped
  at an hour (the `Timeout` header is rewritten so the answer matches),
  256 locks per person, 8192 in all, owner notes over 1 KiB dropped.
- **The FileSystem** (`internal/dav`, `golang.org/x/net/webdav` with a
  memory lock table per person) maps `/<Folder>/<path>` to `files.Service`
  calls as the person; the top is virtual (nothing can be made, moved or
  deleted there); hidden names never listed or reachable; files open
  lazily (a listing doesn't start a worker per file; content types come
  from names); uploads stream into `.hardyos-upload-<id>` and are
  `Replace`d into place on Close only if the body, writes and (for COPY)
  the source read all succeeded, else deleted; replacing an existing file
  (PUT, or COPY/MOVE with Overwrite) first opens it for writing as the
  person (`OpenWrite`; refused = 403, nothing changed), and in a folder
  with a recycle bin its old version is recycled just before the rename
  (without a bin the rename replaces it in one step; if the rename then
  fails the old version is in the bin, not lost); deletes use the recycle
  bin; PROPPATCH stores nothing (answered 200; `Win32LastModifiedTime`
  sets the modification time). Every response has `Content-Security-Policy:
  default-src 'none'; sandbox`, nosniff, no-store, and GET/HEAD
  `Content-Disposition: attachment`.
- **Tests.** `internal/sftp` (drop-in rendering, PAM edits on Debian's
  file incl. faillock, the membership check and jump targets, the session
  check, planning, view sync with a fake mounter that models propagation
  (migration of shared binds, every keep condition, never chmod an
  existing target, never mount over a mount that stayed), held datasets,
  `sshd -T` parsing and PAM only after it, rollback of a refused config;
  `TestRealSSHD` checks the drop-in and `CheckEffective` with a real sshd
  when `HARDYOS_SSHD` is set; `TestRealBindNamespace` makes real binds
  both ways in a private mount namespace of its own when
  `HARDYOS_MOUNT_NS=1` as root: private, read-only, child mounts not
  propagated, an old shared view replaced without unmounting anything on
  the host), `smb` `TestApplySFTP` (views from rules and accounts,
  administrators only with the switch, release, leave), `api` `TestDAV*`
  (browse, hidden names, read/write/move/copy/delete/lock, a broken
  upload, PUT/COPY/MOVE over a read-only file, the old version in the
  bin, depth, POST, body and lock limits, Destination spelled as the
  source, audit rows, dead properties, sign in, local names, cache,
  lockout shared with the desktop, DC down, switches, HTTPS),
  and `TestSFTPMemberIntegration` (CI's Samba job, `HARDYOS_DC_INTEGRATION=1`):
  a real DC, the host's Samba joined, a private sshd on port 2222 (in a
  fresh private mount namespace per (re)start, with a copy of `/etc/pam.d`
  whose common-* stacks have no winbind, as on the image), SFTP as
  domain users by rule, no TTY, no tunnels, refused passwords and
  accounts, the domain administrator refused by default, a faillock
  lockout after ten wrong passwords, and an overriding drop-in caught by
  the effective-config check (PAM off, problem shown) and recovered.

## Virtual machines

Phase 5 part C (decisions 120-125; user guide `docs/vms.md`; plan
`docs/plans/vms.md`). QEMU/KVM through libvirt, driven only by hardyd-priv.

```
 browser ──► hardyd  /api/v1/vms*  (admin, jobs + audit)   ──► hardyd-priv  vms.* ops ──► virsh / libvirt ──► QEMU
                     /vms/{id}/console/ws  ◄── VNC socket fd (SCM_RIGHTS) ◄──┘     │
                                                                                  ├─► zfs: <pool>/vms/<id>, zvol disks, snapshots
                                                                                  ├─► ISOs shared folder (verified fds only)
                                                                                  ├─► network.Manager.EnsureBridge (br0, rollback)
                                                                                  └─► devices.Host (part D): Check / Prepare / Release
```

- **Code**: `internal/vms` (spec and validation, templates, domain XML,
  manager, storage and snapshots, ISO library and downloads, imports,
  cloud-init, console tokens), `priv/vms_ops.go`, `api/handlers_vms*.go`
  and `api/vmconsole.go`, the bridge in `internal/network/bridge.go`, web
  in `apps/vms/`.
- **Spec, not XML**: hardyd sends a `vms.Spec`; hardyd-priv normalizes and
  validates it against the host (CPUs, memory, pools, Secure Boot firmware
  from QEMU's firmware descriptors, swtpm) and renders the domain XML with
  `encoding/xml`. Architecture differences (machine type, SATA, TPM model,
  Hyper-V enlightenments, SMM) are a table keyed by `GOARCH`; UEFI uses
  libvirt's firmware auto-selection, so no firmware path is in the code.
  Device fragments from part D must parse as 1-8 `<hostdev>` elements
  without namespaces; the whole document is checked again before
  `virsh define --validate`.
- **Where a VM lives**: `<pool>/vms/<id>` (`org.hardyos:vm=<id>`, mounted,
  `exec,setuid,devices` off, mode 0711) holds `vm.json` (0600), `nvram.fd`,
  `tpm/` and `cloud-init.iso`; disks are sparse zvols
  `<pool>/vms/<id>/diskN`. hardyd-priv finds VMs by listing datasets with
  the property and reads `vm.json` only when root wrote it. At start it
  waits for libvirt, defines every VM afresh, releases devices of VMs that
  are off, and starts VMs set to start with the server in order.
- **Lifecycle**: start = check media, give QEMU read access to the discs
  (ACL on the descriptor), restore TPM state, `devices.Check` +
  `Prepare`, define with the fragments, `virsh start`, put VLAN NICs on
  their VLAN, then redefine without devices (the stored definition never
  holds them). A watcher reads `virsh domstats` every 3 s: CPU use, memory
  (balloon stats), and VMs that stopped by themselves get `afterStop`
  (devices released, TPM state saved to the pool). Graceful stops ask the
  agent, then ACPI; the stop job waits up to 3 minutes.
- **Network**: `network.Config.Bridges` (`br0` over a port or bond, the
  port's MAC kept, VLAN filtering on, VIDs 2-4094 on the uplink).
  `EnsureBridge` builds it from the default route's interface, applies it
  like any change (saved first), checks the bridge got the old address and
  the router answers, and confirms or undoes it. The domain controller's
  `HoldNetwork`/`ReleaseNetwork` run around any change that adds or removes
  a bridge.
- **ISO library**: the `isos` shared folder. Listing, downloads (https
  only, internet addresses only, optional SHA-256, background task with
  progress followed by the hardyd job) and deletes go through the folder's
  verified mount and `openat2(RESOLVE_BENEATH|NO_SYMLINKS)`.
- **Console**: `vms.console` issues a 60-second one-time token for one VM;
  `vms.console.open` redeems it, finds the VNC socket in the live domain
  (only libvirt's own folders accepted), connects and hands the
  connection over. hardyd relays it over a WebSocket to noVNC.
- **Tests**: golden XML files per template (`internal/vms/testdata`), a
  ZFS/libvirt simulator for the manager, priv ops over a real socket, the
  API with a stub root helper (including the console relay), the bridge
  with rollback and the DC's move onto it, web component tests, and
  `TestLibvirtIntegration` (real ZFS, libvirt and KVM; CI job "Virtual
  machines (KVM)").

## Devices and GPUs

Phase 5 part D (decisions 126-130; user guide `docs/gpus.md`). Two packages
run inside hardyd-priv: `internal/devices` (inventory, IOMMU, passthrough,
GPU ownership, vGPU slices; `devices.Host` implements the `devices.Manager`
contract in `contract.go` that the VM engine calls) and `internal/gpu`
(NVIDIA driver and vGPU host driver installs, the update hook). Named ops in
`priv/devices_ops.go`; API in `api/handlers_devices*.go`; web in
`apps/vms/devices/` (the Control Panel's Devices & GPUs view and the device
pickers the VM wizard imports).

- **Inventory** reads sysfs and procfs only (any architecture): PCI functions
  with vendor/device names from `pci.ids`, plain-words class, driver, IOMMU
  group, `reset_method`; IOMMU groups with an explanation of what lending one
  member means; USB devices (not root hubs or interfaces); GPUs grouped by
  slot with their functions (HDMI audio, USB-C), VRAM (amdgpu sysfs,
  `nvidia-smi`), owner, processes using them, vGPU slices and hints (AMD
  reset bug list, no reset method, console card). Host-critical devices are
  found from the boot configuration, `zpool list -v -H -P` and the default
  routes (walking `lower_*` and `brif` links down to physical ports).
- **Kernel arguments**: `boot.KernelArgsPath` on the shared dataset, rendered
  by `boot.Sync` into every entry (`RenderGrubWithArgs`). "Turn on IOMMU"
  (`devices.iommu.enable`, a job) adds the CPU vendor's flags.
- **Lending** (`Prepare`, called by the VM engine before `virsh start`):
  check everything first (`Check` returns every problem as `devices.Problems`),
  record the plan in `/run/hardyos/devices/state.json`, then bind each
  function and group companion to `vfio-pci`, create vGPU instances, and
  return libvirt `<hostdev>` fragments (`managed='no'` for PCI; mdev by
  UUID; USB by vendor:product with `startupPolicy='optional'`, or by the
  bus/device a port has at start). A failure undoes everything.
  `Release` (after the VM stops) removes slices and rebinds each device to
  the driver recorded for it; a device that won't rebind is listed as
  stuck. `Reconcile` (at start, and from the Devices view) releases devices
  of VMs libvirt doesn't list as running.
- **GPU drivers**: tasks in hardyd-priv (`gpu.nvidia.prepare`, `.install`,
  `.remove`, `gpu.vgpu.install`, `.remove`), one at a time, each with a
  64 KiB log; `gpu.task` reports progress and hardyd's jobs follow it every
  2 s, so no privileged call is long. apt sources: Debian `non-free` (in the
  image; added for older systems) and NVIDIA's container toolkit repository
  with the pinned key embedded in hardyd-priv. Root's state, the licence
  agreement and the admin's vGPU driver file are in `/var/lib/hardyos-gpu`
  (root, 0700), never in hardyd's `/var/lib/hardyos`.
- **Updates**: `update.Updater.Hooks` run after `install.FinishRoot` and
  before `boot.Sync`. `gpu.Manager.PrepareNewRoot` copies root's GPU
  directory into the new system, reinstalls the packages (or reruns NVIDIA's
  vGPU installer per kernel) in a chroot, checks the DKMS module exists for
  every kernel and rebuilds the initramfs; an error removes the new boot
  environment and the current version stays.

What only real hardware can verify (no GPUs in CI): rebinding NVIDIA cards
with `nvidia_drm` loaded, AMD reset behaviour and vendor-reset, GPU ROM
needs, `boot_vga` consoles going blank, NVIDIA's vGPU driver on Debian's
kernel (mdev and per-VF type files, `sriov-manage`, the installer's
`--kernel-name`/`--skip-module-load` in a chroot), Intel SR-IOV with
i915/xe, the exact Debian package set and the licence file location in it,
and IOMMU flags on real firmware.

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
