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
