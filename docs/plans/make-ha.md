# Phase 10: "Make highly available" (build plan)

Owner's choices (2026-11-27). Builds the conversion that Phase 8's plan
(cluster.md section 6.5) left open: nothing created a cluster workload
before this. Decisions 480-489; migration 0140.

## Flows

**Make highly available (VM)** — a job on the server that holds the VM
(`cluster.ha.convert`):

1. Checks (refused with reasons): the cluster has quorum and a storage
   server; this is a compute server, eligible for HA; the LAN check is OK
   (`NetCheck`, decision 487); the VM has no passthrough devices, no ISO
   from the library, no unattended install pending; its id isn't a cluster
   workload yet. Root computes the hash of the converted settings
   (`vms.ha.check`: the spec with the storage server's pool and, if asked,
   the cluster's CPU baseline).
2. **Pre-copy while it runs**: a recursive snapshot
   `hardyos-ha-<conv>-pre`, then every dataset (state folder, each disk) is
   sent snapshot by snapshot: the oldest one full, each later one as an
   increment (`zfs send -i`), so every existing snapshot arrives. Only
   single-dataset streams are sent and received (never `-R` packages: they
   carry properties and other datasets; replication's stream policy).
3. **Stop** (graceful, 3 minutes), final snapshot `hardyos-ha-<conv>-final`,
   final increment. Downtime is this step's copy time; progress shows bytes.
4. The storage server adopts what it received (`san.ha.adopt`: cluster
   properties, mounted, zvols `volmode=dev`). Root on this server **parks**
   the local copy (`<pool>/hardyos-ha-parked/vm-<id>-<time>`, not a VM any
   more, libvirt definition gone) so the same VM can never run twice from
   two copies.
5. `workload.add` (spec hash, owner = this server, HA policy: priority and
   preferred server = this server, requested stopped), the reconciler held;
   the grant is applied, storage attached here, root rewrites `vm.json` on
   cluster storage (pool, CPU model) and checks its hash, `ApproveSpec`.
6. Requested running; the job waits until this server reports it running
   under that generation. Then the parked copy gets its **grace period**
   (24 h; Delete now with typed confirmation). If the HA start fails the
   job fails with the workload stopped in the cluster and the parked copy
   kept without expiry: **Undo** (typed) puts the local copy back and
   removes the cluster copy, or Retry starts it again.

Copy failures and cancelling: before step 4 nothing local changed apart
from snapshots; the VM is started again if it was running. What arrived
stays on the storage server (marked incoming, never exported) so **the
next run resumes** (interrupted streams resume from `zfs receive -s`
tokens, which the sender checks belong to that dataset); **Abandon**
destroys it.

**Apps** take the same path for their dataset `<pool>/apps/<id>` (NFS
mode). The app's user id is claimed cluster-wide (`storage.appuid` with
its own id; refused if another cluster app has it). Apps with a database
then move to block mode with part B's `SwitchAppMode` (stopped), as their
default says. After attach root rewrites the resolved compose file's data
folder (`apps.ha.adopt`) and the hash is approved. Apps with shared
folders, node-local apps (decision 472) and custom compose apps stay
local (refused, a reason shown).

**Make local again** (`cluster.ha.local`, on the chosen compute server):
requested stopped, wait stopped (block-mode apps go back to NFS mode
first); snapshot on the storage server; send everything back to that
server's pool (incoming, resumable); the cluster workload is removed
(`workload.remove`), the storage server parks its copy (grace period);
root adopts the local copy (pool rewritten), and the VM or app starts if
it ran. A failure before `workload.remove` leaves the cluster workload as
it was (requested again as before).

## Data path

zfs streams go root → hardyd (a file descriptor, as replication does) →
the cluster port's new ALPN `hardyos-copy/1` (LAN, then storage network,
never NetBird; compute servers dial the storage server only) → hardyd →
root. A copy session is opened by a peer call on the storage server
(`storage/ha/recv` or `storage/ha/send`, admin assertion required), which
returns a one-time token valid for one minute and one connection.

## Failover (item 4)

The coordinator already restarts HA workloads only after the confirmed
fence. Added: least-loaded scoring (memory and CPU headroom, after
preferred servers and anti-affinity), an alert per failover and per
"nowhere to run" (`cluster.ha.failover`, `cluster.ha.nowhere`), and a
persistent history (`cluster_failovers`) that the API merges from every
member. Conversions never turn fail back on.

## HA VM features (item 5, amends 471)

- Snapshot schedules: kept in `vm.json` like on one server; changing one
  for a cluster VM runs on its owner and is approved (`ApproveSpec`). The
  storage server's hardyd takes and prunes the automatic snapshots
  (`san.vm.schedules` lists them from the cluster VMs' state datasets).
- Game streaming may be published; the server running the VM forwards it.
  A live move stays refused while it is published (decision 470).
- Save as template: the storage server copies the HA VM's disks into a
  template on its own pool.
- USB hot-plug `persist` stays refused.

## Install completion (item 6)

Root records, when it ends an unattended install of a cluster VM, the
hash before and after its own change. hardyd (the owner) approves exactly
that transition (`vms.cluster.installed`): the placement's hash must be
the "before" and the stored spec must hash to the "after".

## LAN check (item 7)

Wired to the cluster's `netcheck.Monitor` (PR #46, decisions 490-492):
"Make highly available" asks `StatusFor` for this server (the monitor
adds the storage servers; `convert.PairCheck`, `wireNetCheck` in
`cmd/hardyd/cluster_c.go`), then `ha.Service.CheckHA` with the policy it
registers (every server it could fail over to), at the start and again
before the workload shuts down; a refusal is 409 `network`. Live moves:
the Mover's `LocalNetwork` (any live move) and `Coordinator.LiveOK` (its
evacuations and fail backs, before they start), both the pair check of
the move's two servers. Restarts and failovers never ask it.

## Tests

Unit tests with fakes (root's rules, the job's phases, scheduling,
coordinator alerts, API authz). CI's Cluster (namespaces) job runs
`TestHAConvertIntegration`: a file-backed "local" pool and a "storage"
pool, a VM disk and state with snapshots sent across through root's ops,
adopted, exported through LIO, read by an iSCSI initiator, then sent back
and adopted locally.

## After the security review (PR #47)

- **Park (H1, M2, M3)**: every park carries the conversion's mark
  (`org.hardyos:ha-conv`) and is idempotent; root puts the datasets back
  when a park fails after the rename; the local park refuses a copy
  written after the final snapshot (`written@<final>`). Any park failure
  sends the conversion back before the park (local copy restarted, the
  unregistered cluster copy put aside for an hour under the attempt's own
  mark); the phase moves past the park only once the parked copy's name is
  saved, and `register` refuses without it. A lost answer is recovered by
  looking (only looking) for the copy the conversion parked.
- **Undo and kept copies (H2, M1, L2)**: Undo puts this server's copy back
  first and checks it, then parks the cluster copy with no expiry; its
  grace period starts once this server's copy ran again, never when the
  cluster copy changed after the final snapshot or may have run. Root
  deletes a copy without an expiry only with `lastCopy`; expiries are only
  pushed back, never under an hour away. "Make local again" gives the
  cluster copy its grace period once the workload ran here.
- **Streams (M4)**: an unused copy session is dropped at its expiry (file
  closed, root's stream cancelled); the compute side cancels the storage
  server's stream when its own step fails (`storage/ha/cancel`, only for
  the server that opened it); root cancels a stream that never moved a
  byte for five minutes when another wants its dataset.
- **Resumes (M5, L7)**: a conversion whose workload was registered and then
  left the cluster isn't resumed; "make local" goes on after the cluster
  forgot the workload only when it removed it itself (intent saved before
  `workload.remove`). A cluster log marker for open "make local"
  conversions wasn't added: the intent flag, the generation and change-time
  check before the removal, and the conversion-marked park on the storage
  server keep two servers from both adopting it.
- **Smaller (L1, L5, L6)**: the storage server follows a cluster VM's
  schedule only when its stored settings hash to the approved ones;
  Abandon puts a copy it adopted aside and releases a claimed app user id;
  a dataset with more than 512 snapshots is refused up front. Root's
  install-completion records survive a hardyd-priv restart
  (`/var/lib/hardyos/vms/cluster-installs.json`).
