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
- Tests: unit tests use `sysexec.Fake` and a temporary directory as `Root`;
  `TestApplyTree` runs the walker on the test machine's file system (skipped
  without ACL support); `TestZFSIntegrationShares` in `internal/priv` runs
  against real ZFS on a file-backed pool in CI's ZFS job
  (`HARDYOS_ZFS_INTEGRATION=1`, root).
