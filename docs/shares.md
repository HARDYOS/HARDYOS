# Shared folders

Shared folders are where the family's files live on the NAS: a Media
library for Jellyfin, Plex or Immich, Backups for computers and phones,
anything else you make. Apps can be given a shared folder when they're
installed. Opening them from Windows, Macs and phones (SMB, NFS, Time
Machine) arrives with file sharing, on top of the same folders.

## Using them

Control Panel › **Shared Folders**.

- **Starter set.** With no shared folders yet, the page offers **Media**
  (with Movies, TV, Music and Photos inside; everyone may read it) and
  **Backups** (administrators only). Pick the pool and create one or both.
- **New shared folder.** Choose the pool (a folder can't move to another
  pool later), a name (up to 40 letters, digits, spaces and `. - _ ( ) ' &`),
  an optional description and quota, and:
  - **Recycle bin**: files deleted over the network go to a recycle bin
    first (with file sharing).
  - **Guest access**: people on the network can read it without signing in
    (with file sharing).
  - **Who can use it**: Everyone, and with a domain its users and groups,
    each with read only, read and write, or no access. No rules means
    administrators only. The rules are saved now and enforced when file
    sharing arrives.
- **Edit** changes all of that except the pool.
- **Delete** destroys the folder, every file in it and its snapshots. Type
  its name to confirm. A folder an app uses can't be deleted until the app
  no longer has it.

Family members see the list (names, descriptions, usage) but not who may
use each folder or which apps have it.

## Snapshots

Every shared folder keeps automatic snapshots: read-only copies of the
folder as it was, which cost only the space of what changed since. New
folders keep **24 hourly, 14 daily, 8 weekly and 6 monthly** snapshots;
change the counts in the folder's dialog (0 turns a kind off; at most 168
hourly, 90 daily, 104 weekly, 120 monthly). Lowering a count deletes the
oldest snapshots of that kind beyond it within a minute.

- **When.** Hourly on the hour, daily at midnight, weekly on Mondays at
  midnight, monthly on the 1st at midnight, all in **UTC**. A snapshot is
  named after the time it stands for, like
  `hardyos-auto-daily_2026-10-26-0000`. If the server was off, it takes one
  snapshot of each kind when it's back (named for the newest time it
  missed), not one for every hour it was off.
- **Take one now.** "Take snapshot" in the dialog, with an optional name
  (`before-cleanup`; letters, digits and `. _ : -`). Snapshots you take are
  never deleted automatically.
- **Delete.** The bin next to a snapshot deletes that one snapshot and frees
  the space only it holds. Nothing in the folder itself changes.
- **Getting files back.** In the File Manager's "Previous versions" panel,
  and from Windows' Previous Versions tab over SMB (with Previous Versions
  on). Whole folders are never rolled back from the desktop.
- Snapshots made outside HardyOS (by hand, by apps, by replication tools)
  are listed as "Other" and never deleted automatically.
- Family members who may use a folder see its snapshots; only
  administrators take and delete them.

## NFS

For Linux and Unix computers (and Macs that prefer NFS). Off for every
folder until you turn it on in the folder's dialog and list who may mount
it:

- **Computers and networks**: an address (`192.168.1.50`, `fd00::50`) or a
  network (`192.168.1.0/24`, `2001:db8:1::/64`), each **Read only** or
  **Read and write**. Names, `*` and "everyone" (`0.0.0.0/0`) aren't
  accepted; up to 32 entries. When a computer is in more than one entry, its
  own address wins, then the smallest network.
- **Who they are.** Every computer listed acts as the folder's own NFS user
  (a number from 31000-31999 shown in the dialog), whatever user it says it
  is, root included. That user can read the folder, and write it if any
  entry may write; read-only computers can't change anything. Files created
  over NFS belong to that user.
- **Mounting.** The dialog shows the commands with this server's name, for
  example:

  ```sh
  sudo mkdir -p /mnt/media
  sudo mount -t nfs nas.home:/mnt/tank/shares/media /mnt/media
  # /etc/fstab
  nas.home:/mnt/tank/shares/media  /mnt/media  nfs  defaults,_netdev  0  0
  # macOS
  sudo mount -t nfs -o resvport,rw nas.home:/mnt/tank/shares/media ~/media
  ```

  NFSv3 and v4 both work. NFS doesn't encrypt or check passwords: list only
  computers on your own network (or reach it over the NetBird VPN).
- The NFS server only runs while at least one folder is shared over NFS.

## How it works

Each shared folder is a ZFS dataset `<pool>/shares/<id>` mounted at
`/mnt/<pool>/shares/<id>`. The id comes from the name (`Family Photos` →
`family-photos`; give one yourself for names without letters a-z). Its
settings are user properties on the dataset, so importing the pool on a
reinstalled server brings everything back:

| Property | Value |
| --- | --- |
| `org.hardyos:share` | `1` |
| `org.hardyos:name`, `org.hardyos:description` | as shown |
| `org.hardyos:access` | `[{"kind":"user"\|"group"\|"everyone","name":"HOME\\alice","level":"read"\|"write"\|"none"}]` |
| `org.hardyos:apps` | `[{"app":"jellyfin","uid":30001,"level":"read"}]` |
| `org.hardyos:recycle`, `org.hardyos:guest` | `on` / `off` |
| `quota` | the quota, `none` for no limit |
| `org.hardyos:nfs-uid` | the folder's NFS identity (31000-31999), set when NFS is first turned on |
| `org.hardyos:snapshot` (on snapshots) | `manual` for snapshots taken from HardyOS |

Datasets are created with `acltype=posixacl`, `xattr=sa`,
`aclinherit=passthrough`, `devices=off`, `setuid=off`, and `compression=lz4`
unless the pool sets its own.

### Apps

Every installed app has its own Linux user ID (30000-30999). Giving it a
shared folder adds `u:<uid>:r-X` (read) or `u:<uid>:rwX` (write) as both an
access and a default ACL entry:

- on the share's folder at once (`setfacl -m … -- <path>`), so the app can
  start using it;
- on everything inside it in the background. The walk opens each entry
  relative to its parent folder with `O_NOFOLLOW` and changes the ACL through
  that file descriptor; links, devices, pipes and other file systems are
  skipped. An app with write access can't trick it into changing files
  outside the share by swapping a folder for a link while it runs.

New files and folders inherit the default entries. As with any POSIX ACL,
a new file's group-class bits (its mode's group part, the ACL mask) limit
what inherited entries allow, so apps that should be able to change each
other's files need to create them group-writable (`UMASK=002` on the
linuxserver.io images).

`RevokeApp` removes the app's entries the same way and takes it off
`org.hardyos:apps`. `Resolve(share, sub)` gives the real path of a share or
a subfolder for a bind mount: links are followed only while they stay
inside the share, and `..` is refused.

### For developers

- Root side: `daemon/internal/shares` (Manager, validation, the ACL walker
  in `acltree_linux.go`), operations in `daemon/internal/priv/shares_ops.go`.
- API: `daemon/internal/api/handlers_shares.go`; paths `/shares…` in
  `api/openapi.yaml`.
- Web: `web/apps/shell/src/apps/control-panel/SharedFolders.tsx`, form rules
  mirroring the server in `sharesRules.ts`.
- Snapshots: `daemon/internal/snapshots` (schedule maths in `schedule.go`,
  the scheduler and manual operations in `manager.go`), ops in
  `daemon/internal/priv/snapshots_ops.go`, API in
  `daemon/internal/api/handlers_snapshots.go`, web
  `control-panel/ShareSnapshotsSection.tsx`.
- NFS: `daemon/internal/nfs` (identities, exports file, server), the NFS
  identity's ACLs in `daemon/internal/shares/nfs_grant.go`, ops and the
  shares hook in `daemon/internal/priv/nfs_ops.go` and `share_hooks.go`, web
  `control-panel/ShareNFSSection.tsx` and `nfsRules.ts`.
- Tests: unit tests use `sysexec.Fake` and a temporary directory as `Root`;
  `TestApplyTree` runs the walker on the test machine's file system (skipped
  without ACL support); `TestZFSIntegrationShares` in `internal/priv` runs
  against real ZFS on a file-backed pool in CI's ZFS job
  (`HARDYOS_ZFS_INTEGRATION=1`, root), and `TestZFSIntegrationSnapshots`
  there runs the snapshot scheduler with a test clock. `TestNFSIntegration`
  (CI's "NFS (loopback)" job, also `HARDYOS_NFS_INTEGRATION=1`) exports
  folders with the real NFS server and mounts them over 127.0.0.1.
