# Replication between HardyOS servers

Phase 6 part B. Keep a copy of chosen shared folders, apps and VMs on a
second HardyOS server, updated on a schedule, over your home network or
NetBird. After the first full copy only the changes travel (ZFS incremental
send). Architecture: [architecture.md](architecture.md#replication-between-servers);
decisions 180-192.

Not in this part: failing over to the copy (promotion), two-way
replication, and raw (still encrypted) sends. The layout and records are
made so a replica can be promoted later (phase 8, clusters of 3+ servers).

## For administrators

### 1. Let the second server accept replicas

On the server that will **keep** the copies (call it B): Control Panel ›
Replication › **Accept from another server** › **Make a pairing code…**

- **Keep its replicas on**: the pool the copies go to (`<pool>/replicas`).
- **Space limit**: a quota for everything that server sends (0 = none).
- **Snapshots kept at least**: per item, whatever the sending server asks
  (default 3). A sending server can never make B delete more than that.

B shows the code (`XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX`) once. It works one
time, for 30 minutes; five wrong tries close it. While a code is open or a
server is paired, B listens on port **44400** (TCP) on all its addresses.

### 2. Pair from the server that sends

On the server whose data you want copied (A): Control Panel › Replication
(or the Backup app's Replication tab) › **Pair with a server…**, enter B's
address (`nas2.home.example`, a LAN IP or its NetBird IP; `:port` if not
44400) and the code. Both servers prove they know the code, and each pins
the other's key. No password is stored anywhere.

**Test** checks that B answers and still knows A. **Change address**
keeps the pinned key: a different machine at the new address is refused.

### 3. Make a task

**New task…**: a name, the server, what to copy (shared folders, VMs,
apps), how often (every 5 minutes to 7 days), an optional bandwidth limit
(KiB/s), how many replication snapshots to keep here and there. A task
runs on schedule, or on **Run now**; **Cancel** stops it (the next run
picks up where it stopped). **History** lists each run with what it sent.

- An item can go to a given server in one task only.
- Running VMs are frozen by their guest agent for the instant of the
  snapshot when they have one; otherwise the copy is crash-consistent
  (like pulling the plug). Replication snapshots count against a VM's space
  limit: keep few on A.
- Running apps are copied as they are (crash-consistent).
- A task that fails sends a notification once; one with no success for
  three intervals (at least an interval plus an hour) is reported as
  behind; the first success afterwards says so.

### 4. Restore

On A: **Restore from a replica** lists what B keeps of A. **Browse &
restore…** shows the copies by time and the files in one (B mounts that
snapshot read-only for the moment it takes), then copies it back:

- **Shared folder**: as a **new** shared folder (name and id you choose,
  on the pool you choose). Only administrators can open it and SMB is off
  until you change its settings: nothing is published before you look.
- **VM**: back under its own name, off, on the pool its settings name,
  only if no VM with that name exists on A (delete or rename the broken
  one first).
- **App**: its data comes back as the app's kept data, only if the app
  isn't installed; reinstall it from the App Store to use it (the package
  is checked like any install; restored compose files never run as they
  are).

Nothing on A is overwritten. A restore that fails removes what it copied.

### On the receiving server

Control Panel › Replication › Accept from another server lists the
servers that send here: the pool, space used and limit, when each was last
seen, and each replica's size, newest copy and whether an interrupted
transfer waits to be resumed. **Limits** changes the space limit and the
minimum kept snapshots. **Delete** (type the server's name) stops
accepting from it, and with "Delete its replicas" destroys everything it
sent.

Replicas are never mounted, shared over SMB/NFS, listed as shared folders,
VMs or apps, and they're read only.

## How it works

```
 A: hardyd ──priv socket──► hardyd-priv: zfs send ─┐ (pipe fd handed to hardyd)
          ◄─────────────────────────────────────────┘
    │ HTTPS PUT /repl/v1/stream (mutual TLS, pinned keys, bandwidth limit)
    ▼
 B: hardyd ──priv socket──► hardyd-priv: checks the stream's first record,
                                         then zfs receive -u -s … <pool>/replicas/<source>/<kind>/<id>
```

Per item, each run:

1. A's root takes `<item>@hardyos-repl-<task>-<YYYYMMDD>T<HHMMSS>Z`
   recursively (one transaction group; a VM frozen first when it can be).
2. A tells B the item's name and pool (for B's list and a later
   promotion).
3. For each dataset of the item (the item first, then a VM's disks): A asks
   B for the replica's snapshots (with GUIDs) and any resume token.
   - A token: A's root checks what it names (`zfs send -nvt`) is this
     dataset and one of this task's snapshots, then sends the rest
     (`zfs send -t`). If it can't, B discards the partial state
     (`zfs receive -A`).
   - Otherwise the newest local snapshot whose GUID B has is the base:
     `zfs send -L -e -c -i <base> <new>`; a new replica gets the whole
     snapshot. A replica that exists but shares no snapshot with A is
     reported (delete it on B to start over); nothing is ever forced
     (`-F`).
4. When every dataset has the new snapshot, B prunes (keeping
   max(task's keep, its own minimum)), then A prunes (always keeping the
   new snapshot).

Only snapshots whose names parse exactly as this task's replication
snapshots are pruned; user, automatic, app and VM snapshots are never
touched, and manual snapshots can't take a `hardyos-repl-` name.

### What the receiver refuses

Root on B reads the stream's first record (`DRR_BEGIN`, 312 bytes)
before `zfs receive` sees a byte, and refuses:

- packages (`zfs send -R`, `-I`, `-p`, `-h`, `-b`): they carry properties
  and other datasets; HardyOS sends single datasets without properties;
- dedup, redacted, holds and clone streams, unknown features, raw streams
  (allowed by a switch for later);
- a stream for another snapshot than the one asked for, a full stream over
  an existing replica, an incremental for a new one, a volume over a file
  system.

Whatever the stream says, the dataset name is B's: `<pool>/replicas/<source
id>/<kind>/<item>[/<child>]`, built from B's own record of the source
(pool, id) and names checked like any input (no `/`, `..`, `@`, `-`
leading). Received file systems get `canmount=off`,
`mountpoint=/mnt/<pool>/replicas/…`, `readonly=on`, `exec/setuid/devices=off`,
`-x sharenfs -x sharesmb` and `-x` for every HardyOS service property;
volumes get `readonly=on`, `volmode=none` (no device nodes: the host never
looks at a guest's partitions) and `refreservation=none`. Each carries
`org.hardyos:replica=<source id>`.

### Security

- Each server has one replication key (ECDSA P-256, self-signed
  certificate) sealed in hardyd's database with a key from hardyd-priv
  (`secrets.key`, purpose `replication`); pinned keys and the open pairing
  code are sealed too, bound to their row. A copied database opens none of
  them.
- Pairing: a 128-bit code; A sends `HMAC(code, "source", pinA, pinB)`
  over a TLS connection on which it learned pinB; B answers with
  `HMAC(code, "receiver", pinA, pinB, sourceID)`. A connection in between
  would have to know the code.
- The receiving port takes TLS 1.3 with a client certificate only; every
  request is matched to a paired source by its key. A source can add to
  its own replicas, read them back (restore) and nothing else: it can't
  delete replicas, choose a pool, or reach another source's.
- Every change through the API is a job and audited; pairing attempts on B
  (good and bad) are audited with the caller's address.

### Limits and what's not verified here

- Integration test: two file-backed pools on one machine, through two
  hardyd services over loopback (`TestZFSReplicationIntegration`, CI's ZFS
  job). Real networks, NetBird, large pools, encrypted pools and VMs with
  real guest agents are not covered by CI.
- Browsing mounts a replica snapshot with `mount -t zfs` (read-only,
  nosuid, nodev, noexec) in a root-only folder under `/run/hardyos`.
- Pools encrypted with HardyOS's native encryption are sent decrypted (not
  raw) and stored with the receiving pool's settings.

## For developers

- Root side: `daemon/internal/replica` (names, stream check, send/receive
  registry with process groups, pruning, restore, browse) and
  `daemon/internal/priv/replication_ops.go` (`repl.*` operations; streams
  travel as file descriptors, SCM_RIGHTS).
- hardyd side: `daemon/internal/replication` (identity, pairing, store,
  receiving HTTPS server, client, runs, restores, schedule, notifications)
  and `daemon/internal/api/handlers_replication.go`.
- Web: `web/apps/shell/src/apps/backup/replication/` exports
  `ReplicationTab` (sending side, for the Backup app), `AcceptPanel`
  (receiving side) and `ReplicationPage` (Control Panel › Replication).
- Notifications: `replication.Notifier` with
  `Event{Kind, Severity, Title, Body, Link string; Time time.Time}`
  (severities info, warning, critical); main wires `NopNotifier` until
  `internal/notify` provides the interface.
- Tests: `internal/replica` (stream policy, confinement, argument
  building, pruning, tokens) with fakes; `internal/replication` with a
  simulated root and two services over real mutual TLS (pairing, full,
  incremental, interrupted and resumed, cancel, stale alerts, restore,
  deleting a source) and through a real priv socket;
  `internal/api/replication_test.go`; web tests; and
  `TestZFSReplicationIntegration` (`HARDYOS_ZFS_INTEGRATION=1`, root).
