# Cloud backups

HardyOS backs up shared folders, apps, virtual machines and the server's own
settings to cloud storage, keeps many versions, and restores anything from a
single file to a whole server. Backups are encrypted on the server before
they leave it; the bucket only ever holds encrypted data. Architecture and
decisions: [architecture.md](architecture.md#cloud-backups), decisions
160-172.

## For administrators

Open **Backup** in the dock. It has four tabs: Tasks, Restore, Destinations
and History.

### 1. Add a destination

**Destinations > Add destination.** Choose the service:

| Service | Endpoint | Region |
| --- | --- | --- |
| Amazon S3 | `https://s3.<region>.amazonaws.com` | the bucket's region |
| Wasabi | `https://s3.wasabisys.com` (or the bucket's regional endpoint) | `us-east-1` |
| Cloudflare R2 | `https://<account-id>.r2.cloudflarestorage.com` | `auto` |
| MinIO or other S3 | `https://<host>[:port]` | as configured |
| Backblaze B2 | (none) | (none) |

Then the bucket, an optional folder inside it (several servers can share a
bucket, one folder each), and an access key that can read, write, list and
delete in that bucket (B2: a key ID and application key). Endpoints must be
https. A MinIO on your own network needs **More options > The server is on my
network**; addresses on the server itself and link-local addresses are never
used.

Saving tests the bucket and creates the backup repository with a key
HardyOS generates. **Then save the recovery kit** (you're asked right away):

- It holds the repository key, the bucket's address and how to rebuild a
  server. Without it, nobody can open these backups if the server is lost.
- Downloading it needs your password again, and every download is recorded
  in the audit log. Print it, or keep it in a password manager, away from
  the server.
- A destination whose kit was never saved shows **Kit not saved**.

To use a bucket that already holds HardyOS backups (this server before a
reinstall, or another server), open **More options > Connect to existing
backups** and enter the key from that repository's recovery kit. HardyOS
never takes over an existing repository without its key.

The access keys and the repository key are kept sealed on the server and
are never shown again. **Change** a destination to give new keys (empty
fields keep the saved ones); a new endpoint, bucket or folder is a
different repository and needs its recovery kit's key.

**Upkeep.** Once a week (default Sunday 04:30) each destination frees the
space of versions no task keeps (prune), then checks the repository and
reads part of its data back (default 5%). **Check now** and **Free space**
run them at once. A failed check is a critical notification.

**Limits.** Upload and download limits (KiB/s) per destination.

### 2. Make a backup task

**Tasks > New task**, four steps:

1. **What**: any shared folders, apps (their data and settings, restorable
   as working apps), virtual machines (disks and settings) and **Settings
   and domain** (accounts, network, the HTTPS certificate, encryption keys
   and the domain controller: with the shared folders, apps and VMs in the
   same task, what a dead server needs to be rebuilt; each version also
   records the shared folders' own settings).
2. **Where**: a destination.
3. **When**: every day, some days of the week, every 1-12 hours, or only
   when started by hand (server time). A backup that can't start within 30
   minutes of its time (the server was off, or the previous one was still
   running) is reported as **missed** and the next one is waited for.
4. **Keep**: daily, weekly and monthly versions (default 7, 4 and 12), and
   the task's name.

Everything is backed up from a ZFS snapshot taken at the start, so each
folder is as it was at one moment. Running VMs with the QEMU guest agent are
frozen for that moment; others are backed up like after a power cut
(crash-consistent), which the version notes. Recycle bins are left out.

**Back up now** runs a task at once; **Versions** opens its versions in
Restore. Turning a task off stops its schedule. Deleting a task stops it;
its versions stay at the destination.

### 3. Restore

**Restore**: choose a destination (and a task), a version, then what's in
it:

- **Shared folder**: browse it, tick files and folders, **Restore…**:
  - **Into a new folder** at the top of the shared folder: nothing current
    is touched.
  - **Where they were**: replaces the current files with the version's.
    Newer files elsewhere stay.
  - **Roll back to this version**: the whole folder becomes exactly as it
    was; newer files are removed. Type the folder's name to confirm. A
    snapshot `hardyos-manual-<time>` of the folder as it was first is kept,
    so this can be undone.
- **App**: **Roll back** (type its name): the app stops, its data and
  settings go back to the version, and it starts again. Permissions you
  have removed since stay removed. A snapshot is taken first.
- **Virtual machine**: **Roll back** (type its name): it must be off. Its
  disks, settings, firmware variables and TPM go back; a VM snapshot
  "Before restoring from a backup" is taken first.
- **Settings and domain**: **Restore settings** (type `settings`): applied
  at the next restart, like a settings backup.

Owners, permissions (ACLs) and times come back as they were. Links come back
as links.

**History** lists every backup, restore, check and prune with its result.

### Family members restoring their own files

In the File Manager, **Previous versions** of a file or folder also lists
**In cloud backups**: the versions of that shared folder. Anyone whose access
rules let them into the folder sees them; restoring needs write access, and
puts the file into a new folder or back in place. It runs as the person:
they can only bring back files they could read at the time of the backup,
into places they can write today.

### Rebuilding a dead server

1. Install HardyOS from the ISO on the new hardware. At **Restore from
   backup**, choose **Restore from a cloud backup**, open or paste the
   recovery kit, enter the bucket's access and secret keys, **Find the
   backups**, and pick a version.
2. Finish the install. At the first start the version's settings, accounts
   and domain are applied (network settings that don't fit the new
   hardware are skipped). The administrator typed in the installer is
   used only if that fails.
3. Sign in, create a storage pool in Storage Manager, open **Backup** and
   choose **Rebuild…** in the banner: shared folders (with their settings),
   apps and VMs of that version come back onto the pool.

Without HardyOS, the backups are a plain restic repository: with the kit,
`RESTIC_REPOSITORY=<repository> restic snapshots` (the key as the
password) lists them.

### Notifications

Backups that finish, fail, finish incomplete or are missed, and failed
checks, are reported through HardyOS's notifications (severity info,
warning or critical).

## For developers

### Pieces

| Where | What |
| --- | --- |
| `daemon/internal/cloudbackup` | root side in hardyd-priv: destinations, restic, egress guard, backups, versions, restores, rebuilds, the installer's restore |
| `daemon/internal/priv/cloudbackup_ops.go` | the `cloudbackup.*` and `install.cloud.*` operations |
| `daemon/internal/cloudbackups` | hardyd: tasks, runs, schedule, upkeep, jobs, the `Notifier` |
| `daemon/internal/api/handlers_cloudbackup.go` | `/api/v1/backup*`, `/api/v1/files/backups*`, recovery kit |
| `apps/backup.go`, `vms/backup.go`, `fileworker` `DoIn` | hooks for apps, VMs and people's restores |
| `web/apps/shell/src/apps/backup` | the Backup app (`tabs.ts` for more tabs) |
| `os/live/config/hooks/normal/0160-restic.hook.chroot`, `scripts/install-restic.sh` | the pinned restic |

### Operations (hardyd-priv)

| Operation | Does |
| --- | --- |
| `cloudbackup.targets` | list destinations (nothing secret) |
| `cloudbackup.target.save` | test the bucket, create or open the repository, keep the destination sealed |
| `cloudbackup.target.remove` | forget a destination (name to confirm); the bucket is untouched |
| `cloudbackup.kit` | the recovery kit: hardyd-priv checks the administrator's password itself (`internal/rootauth`) |
| `rootauth.change` | an administrator's own password change, taken by root's verifier only with the old password |
| `cloudbackup.backup` / `.restore` / `.prune` / `.check` / `.rebuild` | start a task |
| `cloudbackup.task` / `.cancel` | follow or stop a task |
| `cloudbackup.versions` / `.browse` | versions of a destination, a folder of a version |
| `cloudbackup.offer` / `.offer.dismiss` | the rebuild a restored install left |
| `install.cloud.probe` / `install.cloud.stage` | live installer only |

### Repository layout

- Host name `hardyos` for every snapshot.
- Tags: `hardyos`, `task=<task id>`, `run=<run id>`, `item=share:<id>` /
  `app:<id>` / `vm:<id>` / `system` / `manifest`, `server=<install id>`,
  and `part=files` or `part=disk:<name>` for VMs.
- Paths: `/run/hardyos-backup/mnt/<kind>/<id>` for folders, and the stdin
  names `vm-<vm>-<disk>.raw`, `hardyos-settings.hbak`, `hardyos-run.json`.
- The settings archive is the `.hbak` format of settings backups, sealed
  with the repository key.

### How restic is contained

- **Network**: each run gets its own network namespace with only loopback.
  The egress proxy's socket is made inside it (by a thread that entered it
  and then starts restic); the proxy dials out from the host. The proxy
  allows only the destination's host (and, for S3, exactly
  `<bucket>.<endpoint host>`), resolves names itself and refuses loopback,
  link-local, private (unless "on my network"), translation and
  documentation ranges and this server's own addresses.
- **Files**: hardyd-priv re-executes itself (`__hardyos-restic-sandbox`) in
  a new mount namespace, makes every mount read-only except restic's cache
  and a restore's staging folder, hides `/var/lib/hardyos`, `/etc/hardyos`,
  `/etc/ssh`, `/root` and Samba's private folder under empty tmpfs mounts,
  keeps only the run's capabilities (`DAC_READ_SEARCH` for a backup of
  folders; `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `MKNOD` for a
  restore; none otherwise), sets no_new_privs and executes restic.
- **Restores** unpack into a staging dataset with a quota (the version's
  size plus headroom; refused when the pool hasn't that much free) and are
  copied from there by descriptor. Links never come back into an app's own
  files or a VM's folder, ACL entries of hardyos-files, apps and NFS
  identities are taken from the destination as it is now, and people's
  restores check their access today.

### Testing

- `go test ./internal/cloudbackup` needs `restic` on PATH (or
  `HARDYOS_RESTIC`); `scripts/install-restic.sh` installs the pinned
  version. It uses `local:` repositories in temp folders, folders as fake
  datasets, a fake S3 over TLS and a fake restic.
- The tests run without root too:
  `setpriv --reuid=65534 --regid=65534 --clear-groups env -C daemon/internal/cloudbackup TMPDIR=/dev/shm/<dir> <test binary>`.
- `HARDYOS_ZFS_INTEGRATION=1` (root, a throwaway machine) runs
  `TestZFSIntegrationCloudBackup` on a file-backed pool (CI's ZFS job).
- As root, the tests run restic in the sandbox (the test binary is the
  helper) and `TestSandbox` checks what a sandboxed process can reach;
  without root restic runs directly.

### Notifications

`cmd/hardyd` hands `cloudbackups` events to the alert dispatcher
(`notify.Event` has the same fields). Kinds start with `backup.` (the
routing category); links are `backup/tasks/<id>` and `backup/targets/<id>`
(the desktop opens the Backup app on that tab).

### Adding a tab

Add an entry to `EXTRA_TABS` in `web/apps/shell/src/apps/backup/tabs.ts`
(replication's sending side is one; its receiving side stays in Control
Panel › Replication). A tab gets `go(tab, args)` and `args`.

### Not yet

- Restic's listing has no ACLs, so a version shows the names of everything
  in a folder to anyone the folder's rules let in; contents are still read
  as the person.
- VM disks are read whole at every backup (zvol streams; restic deduplicates
  but still reads every block).
- Hard links come back as separate files.
- A compromised hardyd can't get a repository key, but it can still add a
  destination of its own and back everything up to it, the settings item
  included (which holds the master key, pool keys, TLS and SSH host
  keys). hardyd-priv writes every new destination and every settings
  backup to the journal ("AUDIT cloud backup: ..."), which hardyd can't
  change; watch for unexpected ones.
- Local administrators made in the web interface aren't known to root's
  verifier until `hardyctl reset-password` sets their password (root can't
  tell a real administrator from one a compromised hardyd made); until then
  they download the recovery kit through the first administrator or a
  domain administrator.
