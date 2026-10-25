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
