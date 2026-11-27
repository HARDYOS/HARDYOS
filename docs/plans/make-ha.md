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

`convert.NetCheck` (`LocalNetworkOK(ctx) (bool, string)`), default OK.
"Make highly available" and live moves refuse when it isn't OK. The
`cluster/netcheck` package (another builder) plugs in in
`cmd/hardyd/cluster_c.go` (`wireNetCheck`).

## Tests

Unit tests with fakes (root's rules, the job's phases, scheduling,
coordinator alerts, API authz). CI's Cluster (namespaces) job runs
`TestHAConvertIntegration`: a file-backed "local" pool and a "storage"
pool, a VM disk and state with snapshots sent across through root's ops,
adopted, exported through LIO, read by an iSCSI initiator, then sent back
and adopted locally.
