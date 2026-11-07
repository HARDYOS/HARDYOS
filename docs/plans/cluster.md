# Phase 8: cluster with a shared storage node (build contract)

Cade's decisions (2026-11-07):

- A **cluster of 3+ HardyOS servers**. One desktop manages all of them: sign in
  once, switch server, cluster-wide views; move apps and VMs between servers;
  **high availability**; shared domain accounts (DC replication already exists).
- **Storage: one dedicated storage node** for now (an accepted single point of
  failure; designed so a standby storage node can be added later). It is the
  full HardyOS with the **storage** role, not a separate ISO. Compute servers
  use it over **iSCSI** (VM disks = zvols as LUNs) and **NFS** (app data and
  shared folders = ZFS datasets). Snapshots, backups and replication stay on
  the storage node.
- **HA by shared storage**: when a compute server dies, its HA apps and VMs
  restart on another compute server from the same storage (nothing lost beyond
  in-flight writes). **Fencing is mandatory**: a VM or app never runs on two
  nodes against the same disk.
- **Quorum**: the VPS (`vpn.hardynetworks.net`, plain Ubuntu, NetBird server)
  runs a tiny **witness** installed by a script (like the mail relay script). It
  votes and runs nothing.
- **Networking**: the LAN for everything in normal operation; **NetBird is the
  failover path for cluster control traffic** (heartbeats, membership, API).
  iSCSI/NFS go over a **dedicated storage network** (own NIC or VLAN, ideally
  10GbE), picked by the setup wizard when present. Bulk storage never goes over
  NetBird.
- **Joining**: a pairing code + mutual TLS, as replication does.

Read first: `CLAUDE.md`, `docs/architecture.md` (Privilege boundary, Jobs,
Network and time, Domain controller, Shared folder snapshots and NFS, Apps,
Remote access, Virtual machines, Replication between servers, Monitoring),
`docs/decisions.md` 54 and 180-199, and the code in `internal/replication`
(identity, pairing, pinned mTLS), `internal/vms`, `internal/apps`,
`internal/nfs`, `internal/network`, `internal/netbird`, `internal/publish`.

The Go contract is `daemon/internal/cluster/contract.go`, plus
`daemon/internal/vms/backend.go` and `daemon/internal/apps/backend.go`. Decisions
320-329 record the design; parts take 330-339 (A), 340-349 (B), 350-359 (C).

---

## 1. Architecture

```
                         NetBird (WireGuard; control failover, witness always)
        ┌──────────────── vpn.hardynetworks.net ─ hardyos-witness :44500 ──────────────┐
        │                                                                             │
 LAN 192.168.1.0/24 — users, VMs on br0, cluster control (first path) :44500 mTLS
 ───────┬────────────────────────────┬────────────────────────────┬───────────────────
        │ enp1s0 .21                 │ enp1s0 .22                 │ enp1s0 .105
 ┌──────┴──────────────┐      ┌──────┴──────────────┐      ┌──────┴──────────────────────┐
 │ compute "c1"        │      │ compute "c2"        │      │ storage "nas" (role storage) │
 │ hardyd  (raft voter)│      │ hardyd  (raft voter)│      │ hardyd  (raft voter)         │
 │ hardyd-priv         │      │ hardyd-priv         │      │ hardyd-priv                  │
 │  open-iscsi, NFS    │      │  open-iscsi, NFS    │      │  LIO target, nfsd, ZFS "tank"│
 │  libvirt, Docker    │      │  libvirt, Docker    │      │  snapshots, backups, repl.   │
 │  watchdog (armed)   │      │  watchdog (armed)   │      │  SMB/NFS for the LAN as today│
 └──────┬──────────────┘      └──────┬──────────────┘      └──────┬──────────────────────┘
        │ enp2s0 10.77.0.21          │ 10.77.0.22                 │ 10.77.0.10
 ───────┴─ storage network 10.77.0.0/24 (dedicated NIC/VLAN, 10GbE): iSCSI 3260, NFS 2049, live migration ─
```

- **One control plane per node, joined by Raft.** Each HardyOS server keeps its
  own hardyd, hardyd-priv, database, jobs and audit log. What must be agreed
  cluster-wide (members, roles, addresses, which node owns which workload,
  storage grants, fences, HA policies, the feature level) lives in a small
  replicated state machine (section 2). Everything else stays per node.
- **Roles.** `compute` (runs cluster VMs and apps), `storage` (exactly one in
  Phase 8: holds the pool, serves iSCSI/NFS to members, is the single arbiter of
  disk access), `witness` (the VPS: votes when its vote is useful, holds the log,
  runs nothing). A role is fixed at join; changing it means leave and rejoin.
- **Workloads.** A *cluster workload* is a VM or app whose data is on the
  storage node. Workloads on a node's own local pool stay local (today's
  behaviour, never moved or failed over). A local workload can be converted
  into a cluster one (section 6.5).
- **The safety argument in one paragraph.** Raft coordinates; it is not what
  keeps disks safe on its own. Safety rests on two independent mechanisms:
  (1) the **storage node only exposes a workload's LUNs and exports to the one
  node its own applied log names** (one linear history; it maps a volume into
  one node's iSCSI target at a time, except the two named nodes during a live
  migration), and on a node's death it **revokes that node's access before**
  anything restarts elsewhere; (2) every node holding HA workloads
  **self-fences** (stops them, and a hardware watchdog resets it if that fails)
  when it loses quorum, before the cluster could declare it dead. Either alone
  prevents a double run against the same disk; both together also stop a
  partitioned node's VM from answering on the LAN with a stale IP.

## 2. Membership and state

### 2.1 Consensus: embedded Raft with `hashicorp/raft`

Choice: `github.com/hashicorp/raft` (v1.7.x, pinned) with
`github.com/hashicorp/raft-boltdb/v2` (bbolt) as log and stable store and
`raft.FileSnapshotStore`, embedded in hardyd. Why:

- It is a complete, production-hardened implementation (Consul, Nomad, Vault):
  transport abstraction, snapshots and log compaction, joint-safe membership
  changes, **non-voters** (catch up before voting; the witness's standby mode),
  leadership transfer, observers for heartbeat failures and leader changes, and
  pre-vote (v1.7+) so a node coming back from a partition doesn't disrupt the
  leader. We only write the FSM, the stream layer and the wiring.
- `go.etcd.io/raft/v3` is the better pure algorithm library but leaves the
  transport, storage, snapshots, ticking and membership plumbing to us: more
  code on the one path that must be right. etcd itself (an external daemon) is
  too heavy for a witness on a small VPS and adds a second state store.
- Licence: MPL-2.0 (file-level copyleft). Used unmodified as a dependency it
  places no obligation on HardyOS's proprietary code; if we ever patch it, the
  patched files stay MPL. Recorded in decision 320.

Parameters (LAN; the stream layer hides the NetBird fallback): heartbeat
timeout 2 s, election timeout 3 s, leader lease 1 s, commit timeout 50 ms,
snapshot every 1024 entries (keep 3), `TrailingLogs` 4096. Data in
`/var/lib/hardyos/cluster/raft/` (the shared `rpool/hardyos` dataset, so it
survives updates and boot environment switches; section 9 covers rollback).

### 2.2 Voters and the witness

- Voters: every HardyOS member that is `active` (not `joining`, not in
  `maintenance`), **plus the witness when that count is even**. Otherwise the
  witness is a non-voter that still receives the log (promotion is one
  configuration change, no catch-up).
  - 3 servers (storage + 2 compute): 3 voters, the witness standby. Losing any
    one server keeps quorum; a 4th vote would not tolerate more failures and a
    2-2 split would stall.
  - Storage node in maintenance (rolling update): voters = 2 compute + witness.
  - 4 servers: 4 + witness = 5 voters, tolerating two failures.
- The leader re-evaluates the voter set only when every current voter is
  reachable (a planned join, leave or maintenance). It **never** removes or
  demotes an unreachable voter by itself; that is the admin's "Remove node"
  (section 3.4). This keeps the classic auto-shrink split brain out.
- The witness must never coordinate: if it becomes leader it transfers
  leadership (`LeadershipTransfer`) to an up-to-date HardyOS voter at once. It
  cannot propose commands (its key may only sign `witness.hello`), so as a
  short-lived leader it can only order, delay or drop proposals that members
  forward to it.

### 2.3 The replicated state

The FSM state (`cluster.Snapshot` in the contract) is small JSON: cluster id
and name, `FeatureLevel`, members (id, name, role, pin, addresses, state,
version, features, boot id, fence epoch), workloads (placement: owner,
generation, requested state, HA policy, constraints), storage grants, fences,
per-proposer sequence numbers, and the storage node's acknowledgements. No
secrets ever go in the log (CHAP secrets and keys travel point-to-point).

Commands are `cluster.Command` envelopes: type, cluster id, proposer node,
proposer sequence, actor (the person and the node they used), time, body. The
proposer **signs** the canonical bytes with its cluster key (ES256);
`SignedCommand` is what the log holds. Every node's FSM verifies, at apply:

1. the signature against the proposer's pinned key in the *current* state;
2. the proposer is an allowed signer for that type (the witness signs nothing
   but `witness.hello`; `storage.*` acknowledgements only from the storage
   node; `member.add` only from an `active` HardyOS member);
3. `Seq` is greater than the last applied one for that proposer (no replay of
   old signed entries by a misbehaving leader);
4. the body's own preconditions (expected generation, states).

A rejected entry is a no-op on every node (deterministic). Unknown command
types stop the node's FSM (it would diverge): the node leaves the voter set's
calculations, raises a critical alert and asks for an update. New types are
only proposed once `FeatureLevel` allows them (section 9).

FSM appliers are pure functions `Apply(*Snapshot, Command) error` registered per
command type, each part owning its own file in `internal/cluster/state/`.

Followers forward proposals to the leader over the peer channel
(`POST /cluster/v1/propose`, signed command inside); `Propose` returns the
log index, and `WaitApplied(index)` lets a caller act only after its own node
has applied it.

### 2.4 Liveness and paths

- **Transport.** One TLS 1.3 listener per node on **44500** (`ports.Cluster`),
  ALPN-multiplexed: `hardyos-raft/1` (the Raft stream layer), `hardyos-peer/1`
  (HTTP/2: heartbeats, proposals, API proxy, storage control, join) and
  `hardyos-migrate/1` (the libvirt connection of a live migration, section 6.3).
  Mutual TLS with pinned keys (the replication model): the client checks the
  server's pin against the member it dialled; the server maps the client's pin
  to a member (or to an open join code).
- **Paths.** Each member announces its LAN address and its NetBird address
  (from `netbird.status`). The stream layer dials LAN first and keeps a
  NetBird connection warm; it probes both every second and switches after 3
  missed LAN probes, back after 10 good ones. Raft addresses are node ids that
  the stream layer resolves to the current path, so Raft never sees the switch.
  The witness is reached over NetBird only. Path in use and round-trip times
  are shown per pair in the Cluster app.
- **Heartbeats.** Every node sends `POST /cluster/v1/heartbeat` to the leader
  every second: boot id, version, path, health (`StorageOK`: its iSCSI
  sessions and NFS mounts answer; `LANOK`: its bridge has carrier and the
  gateway answers ARP), running workloads with generations. The leader answers
  only after confirming it is still leader (`VerifyLeader`, cached within the
  leader lease); the answer carries the term and the leader's view of the node.
  **Quorum lease:** a node counts itself quorate until `sendTime + Q` of the
  last heartbeat that got such an answer (send time, monotonic clock). The
  leader records `lastHeard[node]` (receive time); a newly elected leader
  starts every node's `lastHeard` at its own election time.

## 3. Join, leave and the witness

### 3.1 Creating a cluster

Control Panel › **Cluster** › Create: cluster name, this server's role
(`storage` for the NAS, else `compute`), and the storage network (section 5.1).
hardyd makes the cluster id (128 random bits), its cluster identity (ECDSA
P-256, self-signed, sealed in `settings` `cluster.identity`, secretbox purpose
`cluster`; separate from the replication identity so leaving the cluster never
touches replication pairings) and bootstraps Raft as the single voter. Job
`cluster.create`, audited.

### 3.2 Adding a server

1. On any member: **Add server** → a one-time code (128 bits, shown like
   replication's, 30 minutes, 5 failures; sealed in `cluster_join_codes`), with
   the role it admits and this member's LAN and NetBird addresses.
2. On the new server (installed, its own admin signed in): Cluster › **Join**,
   address + code. The two prove the code over both pins (replication's
   `sourceProof`/`receiverProof` scheme), so a man in the middle learns
   nothing and can't swap keys.
3. Checks before anything is committed (all reported at once): version within
   the window (section 9); hostname and node id unique; for compute, the LAN
   is the cluster's LAN subnet (VMs bridge onto the same L2) and the node has a
   storage network address in the cluster's storage subnet that reaches the
   storage node's portal; NetBird joined to the same management server (a
   warning when not: no failover path); for storage, no other storage node
   exists. The joining node keeps its local pools and local workloads.
4. The member proposes `member.add` (role, pin, addresses, `joining`). The
   joiner starts Raft as a non-voter, catches up, sends `member.ready`; the
   leader promotes it and re-evaluates the witness (section 2.2).
5. For compute nodes the storage node then creates the node's iSCSI target and
   CHAP secrets (section 5.2) and hands the secrets to the node over the peer
   channel; the node seals them (purpose `cluster`).
6. The wizard offers to join the domain as another DC (the existing domain
   join), recommended on at least two servers.

### 3.3 The witness

Cluster › **Witness** › Add: needs NetBird on the members. hardyd generates
`hardyos-witness.sh` (as `mail.VPSScript` does) with: the cluster id, a join
code, the members' NetBird addresses and pins, and the SHA-256 of the
`hardyos-witness` binary of this HardyOS version. Run as root on the VPS, the
script:

- downloads the binary from a member over NetBird
  (`https://<member>:44500/cluster/v1/witness/binary`, allowed only while that
  code is open) and checks its SHA-256;
- installs `/usr/local/bin/hardyos-witness` and a systemd unit:
  `DynamicUser=yes`, `StateDirectory=hardyos-witness`, `ProtectSystem=strict`,
  `NoNewPrivileges`, `MemoryMax=128M`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
  listening on the VPS's NetBird address only, port 44500;
- runs `hardyos-witness join` (the code on stdin), which pairs like a server and
  is committed as `member.add` with role `witness` (non-voter until needed);
- `--remove` uninstalls (after Cluster › Witness › Remove commits the removal).

The witness binary is the cluster core only: the stream layer, Raft, the pure
state machine (`internal/cluster/state`, no system dependencies) so it can
apply and snapshot the log, and `witness.hello` heartbeats. No hardyd-priv, no
API, no workloads. Updated by re-running the script (members serve the
matching binary).

### 3.4 Leaving and removing

- **Leave** (on the node, admin): refused while cluster workloads are placed on
  it (the dialog offers **Drain**, section 6.4). Then: demote to non-voter,
  re-evaluate the witness, `member.remove`, the storage node removes the node's
  target, CHAP and exports, the node logs out, unmounts, wipes its cluster
  state and key. Job `cluster.leave`.
- **Remove a dead node** (from another member, typed node name as
  confirmation): commits `node.dead` if not already, waits for the storage
  fence, recovers its HA workloads (section 7), lists its non-HA workloads as
  *orphaned* (start elsewhere, one click each), then `member.remove`. Its pin
  is dropped, so the machine can't reconnect; it must be reinstalled or reset
  to join again.
- The storage node leaves last: **Dissolve cluster** (typed cluster name)
  needs every compute node gone; cluster workloads on the pool become local
  workloads of the storage node (defined off).

## 4. The cluster desktop

- **Sign in once.** The person signs in on any member (its own address, its
  published NetBird desktop, or the optional cluster address below). The
  session lives on that *entry node* only; nothing about sessions is
  replicated.
- **Per-node API.** The shell's API client gets a node scope:
  `/api/v1/nodes/{node}/<path>` is handled locally when `{node}` is the entry
  node and otherwise proxied by hardyd over the peer channel to the member's
  `/api/v1/<path>`. CSRF (`X-HardyOS-Request`) and the session cookie are
  checked on the entry node; cookies never cross. The forwarded request
  carries `X-Hardyos-Cluster-Assertion`: a compact ES256 JWS signed with the
  entry node's cluster key: `iss` entry node, `aud` target node, `sub` the
  principal (kind `local` or `domain`, name, SID for domain accounts, admin),
  `sid` (SHA-256 of the session id), `iat`/`exp` (60 s), `jti`, and `req`
  (SHA-256 of method, path, query and body). The target checks: mTLS peer pin
  = the issuer member's pin, signature, `aud`, freshness, `jti` not seen in
  the last 2 minutes, `req`; then authorizes:
  - a **domain account** is resolved by SID against the target's own view of
    the domain (the same directory, replicated DCs) and gets what it would get
    signing in there;
  - an **administrator** of any member is an administrator on every member
    (cluster admin; decision 324);
  - a **local non-admin** account gets 403 ("sign in on <node>"): local
    accounts are per server.
  The target audits as `alice (via c1)`. WebSockets (events, VM console,
  terminal) are proxied the same way at upgrade; the entry node rechecks the
  session every 15 s and closes the relay when it ends.
- **Cluster-wide endpoints** (`/api/v1/cluster/...`, part A unless noted):
  status, members and health, join codes, witness, events (merged stream of
  every member's job and alert events, tagged with the node), workloads list
  (from the state, with live stats fanned out), storage (B), placement, moves
  and HA (C).
- **Shell.** A server switcher in the menu bar (`nas`, `c1`, `c2`, …, health
  dot, "Cluster" overview). Windows opened for a node show its name in the
  title bar. The Cluster app: overview (nodes, quorum, leader, paths, witness,
  storage, alerts), Nodes, Workloads (all VMs/apps with owner, HA, move),
  Storage (B), HA (C). Built-in apps (VMs, App Store, Storage Manager…) take a
  node scope from the window and otherwise work as now.
- **App windows for apps on other nodes** go through the entry node's window
  proxy, which forwards to the owner's window proxy over the peer channel with
  an assertion, so no second sign-in is needed.
- **Cluster address (optional).** A floating LAN address for the desktop held
  by the leader (a macvlan like the DC's, gratuitous ARP on change), so
  bookmarks survive a node loss. NetBird-published desktops and apps are
  re-targeted by the publish sync of whichever node now owns them (C, 6.6).

## 5. Storage node (part B)

### 5.1 The storage network

- The wizard (create and join) lists interfaces with link speed and carrier.
  It prefers a port that is not the default route's, fastest first, then
  offers a VLAN on the LAN port (needs switch support), and only then "use
  the LAN" with a warning (performance, and iSCSI/NFS on the same wire as
  users). Addressing is static, suggested `10.77.0.0/24`, `.10` for storage;
  the cluster records the subnet. Applied through `internal/network` like any
  change (saved, confirm-or-revert), MTU 9000 offered when every member's port
  supports it.
- Storage traffic never uses NetBird: before logging in or mounting, the
  compute side checks `ip route get <portal>` leaves on the storage interface
  (never `wt0`, never a NetBird range) and refuses otherwise.

### 5.2 iSCSI (LIO)

- LIO is configured through **configfs from Go** (`/sys/kernel/config/target`),
  the kernel ABI that `targetcli` itself writes, inside hardyd-priv's named
  `san.*` ops; `targetcli-fb` stays in the image for diagnostics only. Root
  keeps the desired configuration in a root-written file
  (`/var/lib/hardyos/root/cluster/san.json`, `rootfile.WriteAtomic`) and
  rebuilds LIO from it at boot and on every change (idempotent reconcile);
  no `saveconfig.json`.
- **One target per compute node**: `iqn.2026-11.net.hardynetworks:hardyos.<cluster8>.<node>`,
  TPG 1, portal `<storage address>:3260` only, `authentication=1` with
  **mutual CHAP** (random 24-character secrets each way, per node),
  `generate_node_acls=0`, one ACL: the node's initiator
  `iqn.2026-11.net.hardynetworks:hardyos.<cluster8>.<node>.init`.
- **Backstores**: `iblock` on `/dev/zvol/<pool>/vms/<vm>/diskN`, name
  `hc_<vm>_<disk>` (hashed when long), `wwn` and unit serial derived from the
  zvol's GUID (stable `/dev/disk/by-id/wwn-0x6001405…` on compute nodes),
  `emulate_tpu=1` (discard → zvol free), `emulate_write_cache` per the zvol's
  `sync` property, `is_nonrot` from the pool.
- **Granting** = mapping the backstore as a LUN into the owner node's TPG
  (lowest free LUN number; compute nodes find disks by WWN, never by LUN
  number). A backstore is mapped into at most one TPG, except into exactly two
  during a live migration (the grant says so).
- Only datasets and zvols with HardyOS's properties
  (`org.hardyos:vm=<id>` / `org.hardyos:app=<id>`, role `cluster`) under
  `<pool>/vms/` and `<pool>/apps/` can be exported; every name is validated.

### 5.3 NFS

- Exports are rendered into their own file, `/etc/exports.d/hardyos-cluster.exports`
  (`internal/nfs/cluster.go`, the same validate-then-write-then-`exportfs -ra`
  with rollback), separate from the LAN shares file.
- **VM state** `<pool>/vms/<id>` (vm.json, nvram, TPM state, cloud-init seed)
  and **app data** `<pool>/apps/<id>`: exported to the **owner's storage
  address only** (both during a live migration),
  `rw,sync,no_subtree_check,no_root_squash,sec=sys,fsid=<dataset GUID>`.
  `no_root_squash` because containers and QEMU set ownership on their own
  data; the export is exclusive to one node, on the storage network.
- **Shared folders** with "Use in the cluster" on: exported to every active
  compute node's storage address, `rw,sync,root_squash,sec=sys` (no
  `all_squash`: apps reach shares as their own user ids, which are allocated
  cluster-wide, and domain ids come from the domain). LAN clients keep using
  SMB/NFS on the storage node exactly as today.
- NFSv4.2 only for cluster mounts; nfsd lease and grace times lowered to 15 s
  (`/proc/fs/nfsd/nfsv4leasetime`, `nfsv4gracetime`) so a storage reboot
  blocks opens for seconds, not 90.
- App and VM ids, and app user ids (30000-30999), are allocated in the cluster
  state, so they are unique across nodes.

### 5.4 Firewall

`san.firewall.apply` renders an nft table (`/etc/hardyos/cluster-storage.nft`,
like mail's) allowing 3260 and 2049 on the storage interface only from
members' storage addresses, and dropping a fenced node's address. Compute nodes
get the live-migration range 49152-49215 open only from members' storage
addresses.

### 5.5 Snapshots, backups, replication

They stay on the storage node and operate on the same datasets. What needs the
running workload goes to its owner over the peer channel: the VM guest-agent
freeze for replication and backup snapshots (`vms.Manager.Frozen` becomes a
`Freezer` whose cluster implementation asks the owner to freeze, with an
automatic thaw after 60 s), and an app's `backup.dump` (`apps.PreBackup`) run on
the owner. Snapshot, rollback and delete of a cluster VM or app from the desktop
are storage-node jobs (rollback needs the workload stopped, as now).

## 6. Compute side, placement and moves

### 6.1 Storage clients (part B)

- **open-iscsi**: `iscsid` running; `node.startup = manual` (hardyd-priv logs
  in only when the cluster state says so; a fenced node never auto-logs in at
  boot), `replacement_timeout = 15`, NOP-out every 5 s. Node records (with
  CHAP) are written by root as files under `/etc/iscsi/nodes/` (0600), never
  with `iscsiadm -o update -v <secret>` (argv is world-readable). Initiator
  name written by root. After a grant: session rescan, wait (10 s) for the WWN
  device.
- **Multipath (optional)**: only when the storage node has two portals:
  `multipath-tools` with `find_multipaths strict`, a WWID allow list of
  attached volumes, `no_path_retry 3` (never queue forever: that would hang
  fencing). Device `/dev/mapper/<wwid>`.
- **NFS mounts**: `mount -t nfs4 -o vers=4.2,hard,proto=tcp,timeo=600,retrans=2,nconnect=4,nosuid,nodev`
  (VM state also `noexec`) at the same layout under `/mnt/hc/<pool>/…`
  (`hc` = HardyOS cluster), so a node's own pool called `tank` never clashes.
- **Attachment records**: what is attached for which workload and generation,
  root-written in `/run/hardyos/cluster/attached.json`; `vms.StorageBackend`
  and `apps.StorageBackend` read them.

### 6.2 How the engines use remote storage

- **VMs**: `vms.Manager.Backend` (nil = local pool, today). The cluster backend
  `Locate(id)` returns the NFS state folder and each disk's block device.
  Domain XML for cluster disks: `type='block'`, `cache='none' io='native'
  discard='unmap' error_policy='stop' rerror_policy='stop'` (an I/O error
  pauses the VM instead of failing the guest; hardyd resumes it when the path
  is back). Cluster VMs default to the **cluster CPU baseline**
  (`virsh hypervisor-cpu-baseline` over members' host CPU models, kept in the
  state); `host-passthrough` stays possible and limits live migration to
  identical CPUs. VMs with passthrough devices are pinned to their node.
- **Apps**: Docker's data-root stays local on each compute node
  (`rpool/hardyos-docker`, or a local pool when one exists; overlay2 does not
  work on NFS). An app's own dataset is the NFS mount from `Locate(id)`;
  images are pulled on whichever node runs it. Shared folders resolve to their
  NFS mounts (a cluster `apps.ShareResolver`); share ACL grants for an app's
  user are made on the storage node by hardyd before the app job reaches
  hardyd-priv.
- **Known risk: SQLite and databases over NFS.** Many catalog apps use SQLite.
  With a single exclusive NFSv4.2 client, `hard,sync` and working POSIX locks
  this is supported by SQLite in practice, but it is the weakest spot of the
  design. The contract leaves room for a per-app **block mode** (a zvol LUN
  with ext4, exclusive like a VM disk) as a follow-up; see open questions.

### 6.3 Placement (part C)

Pure function over the state: filter compute nodes that are `active`, quorate,
`StorageOK`, have the bridge and VLANs the workload's NICs need, enough
uncommitted memory (VM memory + app limits; memory is never overcommitted for
HA placement) and CPUs, a compatible CPU model, and the devices it needs; then
score: the policy's preferred nodes first, anti-affinity groups, least
committed memory. The reasons a node was skipped are returned for the UI.

### 6.4 Moves

- **Offline move** (VMs and apps; first to build). Job on the entry node,
  per step a peer call: `move.begin{from,to,gen}` → graceful stop on A (VMs:
  guest agent/ACPI, 3 minutes; apps: compose stop) → A detaches → commit
  `placement.set{owner=B, gen+1}` → the storage node applies: unmaps from A,
  maps to B, acknowledges (`storage.applied{gen}`) → B attaches, defines and
  starts (if it was running) → `move.end`. Apps pre-pull images on B before
  stopping on A. A failure leaves the last committed owner; the workload stays
  stopped with a clear message and **Retry** / **Back to A**.
- **Live migration** (VMs without passthrough devices, compatible CPU, same
  bridge/VLANs, memory on B). `move.begin{mode: live}` → grant to A *and* B
  (`GrantMigration`) → B attaches (LUNs and the state folder) → B's priv
  `vms.migrate.accept {vm, from, token, deadline 120 s}` → A's priv
  `vms.migrate.send {vm, to, token}` runs `virsh migrate --live --p2p
  --persistent --undefinesource` with the destination URI on a one-shot unix
  socket that hardyd relays (fd passing, as the VM console does) over the
  peer channel (ALPN `hardyos-migrate/1`) to B, where B's priv hands hardyd a
  connection to B's libvirt for that one session; the memory stream goes
  directly over the storage network (`--migrateuri tcp://<B storage
  addr>`). B's libvirt `qemu` hook (`migrate` operation) accepts the incoming
  domain only if its XML equals B's own rendering of the VM's stored spec
  (`vms.migrate.check`); the same check runs for every start of QEMU of a
  cluster VM (`prepare`/`start`/`restore`, decision 385). On success:
  `placement.set{owner=B}`, the grant shrinks to B, A detaches. On failure
  both nodes' root is asked what runs (`moves/migrate/state`): B's copy is
  destroyed by B's root (`moves/migrate/abort`) before the grant collapses
  onto A, unless only B runs the VM (decision 388). Every step is accepted
  only from the member that began the move or the leader (decision 387).
- **Drain a node**: live-migrate what can be, offline-move the rest (HA ones
  first by priority), stop non-HA workloads that can't move (asking first).
  Used before maintenance and leaving.

### 6.5 Converting local workloads

"Move to cluster storage" for a local VM or app: replication's stream machinery
sends its datasets to the storage node (incremental while running, a final
increment with the workload stopped), the storage node adopts them with the
`cluster` role, and the workload is defined on a compute node.

### 6.6 Addresses after a move

VMs keep their MAC and get the same address from the router. Apps' ports move
to the new node's address, so LAN users should reach apps through the desktop,
the NetBird-published name (re-targeted by the new owner's publish sync; cluster
service names use the cluster's id, not the node's), or an optional per-app
**cluster address** (a macvlan address that moves with the app, like the DC's).

## 7. High availability and fencing (part C)

### 7.1 Timings (defaults; `cluster.Timings`)

| Name | Default | Meaning |
| --- | --- | --- |
| heartbeat | 1 s | node → leader |
| `Suspect` | 10 s | leader marks a node suspect (UI, warning alert) |
| `Q` quorum lease | 15 s | a node without a confirmed heartbeat for Q starts self-fencing |
| `S` self-stop | 5 s | time to stop HA workloads cleanly before letting the watchdog fire |
| `W` watchdog | 10 s | hardware watchdog timeout once petting stops |
| `F` dead | 40 s | leader declares a node dead after F without hearing it |
| `StorageIsolated` | 15 s | a node reporting storage down while others are fine |
| fence ack | 30 s | storage node must confirm a fence before recovery (retried, never skipped) |

Invariant (checked when settings change): `F ≥ Q + W + 10 s` and `S < W`.
With it, by the time the leader declares a node dead, that node has either
heard the leader recently (so it wasn't dead) or has stopped its HA workloads
or been reset. Typical failover: ~40 s detection + ~5 s fence + ~5 s attach +
the guest's boot.

### 7.2 Node fence agent (node-local state machine)

```
            no HA workloads                          ≥1 HA workload placed here
 DISARMED ───────────────────────────────► ARMED (watchdog open, petted every 1 s
     ▲                                       │       while now < lastQuorumAck + Q)
     │ all HA workloads stopped,             │ lease expires (no quorum)
     │ confirmed within S                    │   or the state says node.isolated
     │                                       ▼
     └─────────────────────────────── SELF-FENCING: virsh destroy / docker kill
                                         HA workloads, detach storage, stop petting
                                         at lease expiry. Not all stopped by S →
                                         keep not petting → hardware reset ≤ W.
```

- The watchdog is owned by hardyd-priv (`cluster.watchdog.arm {timeout}`,
  `.pet {until}`, `.disarm`, `.expire`): root opens `/dev/watchdog0` (hardware:
  `iTCO_wdt`, `sp5100_tco`, IPMI; `softdog` as a fallback, which a kernel hang
  defeats; the Cluster app says which) and pets it itself only while the
  `until` deadline hardyd last gave is in the future (monotonic). A hung
  hardyd, a hung hardyd-priv or a lost lease all end in no pets. Disarm writes
  the magic close only from DISARMED. systemd's own `RuntimeWatchdogSec` is
  left off on cluster nodes so there is one owner of the device.
- The storage node is never armed (it runs no cluster HA workloads) and never
  self-fences: rebooting the NAS would take everything down.

### 7.3 Cluster-side states

Node (committed): `joining → active ⇄ maintenance`, `active → dead(epoch) →
fenced(epoch, confirmed by storage) → rejoining → active`, any → `removed`.
`suspect` and `isolated` are the leader's observations (isolated is committed
as `node.isolated` so the node itself acts on it).

Workload (committed placement + owner's report): `stopped`, `starting`,
`running`, `stopping`, `migrating(A→B)`, `moving(A→B)`, `recovering` (owner
dead, waiting for the fence), `pending` (no node fits; retried every 30 s),
`error` (too many restarts), `frozen` (shown when the viewing node has no
quorum: no changes possible). Each placement has `Requested` (running/stopped,
what the person asked) and a `Generation`; a node runs a workload only when
the placement names it with the generation of its own attachment **and** the
storage grant for that generation is applied.

### 7.4 Scenarios

- **Compute node dies.** `lastHeard` ages: Suspect at 10 s, `node.dead{N, e+1}`
  at F. The storage node applies it: disables N's TPG (drops all its sessions),
  removes N from every export, `exportfs -ra` and `exportfs -f`, expires N's
  NFSv4 clients (`/proc/fs/nfsd/clients/*/ctl`), drops N's address in nft, then
  proposes `storage.fenced{N, e}` (signed by the storage node). Only then does
  the HA coordinator (the leader, a HardyOS node) re-place N's HA workloads by
  priority with `placement.set{gen+1}`; targets attach and start them.
  Non-HA workloads of N show as *orphaned*.
- **The node comes back.** It boots (watchdog or power), hardyd starts, joins
  Raft, sees `fenced` with its epoch, starts nothing, proposes
  `node.rejoin{bootID}`; the storage node re-enables its target with nothing
  mapped and returns it to the exports of shares; the node is `active`. Its
  former HA workloads stay where they are (an optional "fail back" policy moves
  them back by live migration when it's idle).
- **A workload crashes (node fine).** The owner restarts it in place up to the
  policy's `MaxRestarts` per hour, then asks for relocation (`MaxRelocations`).
- **Network partition.** The majority side keeps quorum and acts as above; the
  minority side's armed nodes self-fence at Q and are reset by W; the storage
  fence happens anyway. If the storage node is on the minority side, the
  majority can't get a fence acknowledgement and recovers nothing (correct:
  without the storage node nothing could run anyway); the storage node keeps its
  current grants and applies nothing new.
- **LAN fails, NetBird works.** Control traffic moves to NetBird within ~3 s;
  quorum holds. Storage is on its own network, so workloads keep running. A node
  whose LAN alone failed (`LANOK=false` while others are fine) is *LAN-isolated*:
  its VMs can't serve anyone, so after 60 s the leader live-migrates its HA VMs
  away (storage network still works); policy per cluster (default on).
- **One node loses the storage network** (others fine). After
  `StorageIsolated` the leader commits `node.isolated{N}`; N self-fences its HA
  workloads (likely stuck in I/O, so usually by watchdog reset); the storage
  node fences N; recovery waits for the fence acknowledgement and
  `max(N's "all stopped", W + 10 s)`.
- **Storage node lost** (all compute nodes report storage down). No failover
  (there is nowhere to fail to). iSCSI fails I/O after 15 s and QEMU pauses VMs
  (`error_policy=stop`); NFS mounts are `hard`, so apps block. Placements are
  frozen; critical alert. When the storage node is back, sessions recover,
  hardyd resumes paused VMs, apps continue. If quorum was also lost (storage
  node + one compute down in a 3-node cluster), armed nodes self-fence: HA VMs
  are stopped rather than left paused; they restart when quorum and storage are
  back.
- **Witness lost.** Only matters while it is a voter: one vote fewer; an alert.
  Nothing else changes. If it was the tie-breaker and another voter fails,
  quorum is lost and armed nodes self-fence. It's never removed automatically.
- **Leader lost.** Raft elects a new leader within ~3-5 s; the new HA
  coordinator starts every node's `lastHeard` at its election, so a leader
  change never shortens F.
- **Total quorum loss** (e.g. the switch carrying both LAN and the router
  reboots): HA workloads are stopped by self-fencing on every compute node; they
  restart when quorum returns. Non-HA cluster workloads keep running (only HA
  workloads are armed). This is the price of mandatory fencing; Q can be raised
  (with F) to ride out longer blips.

### 7.5 What is never done

- Recovery never starts without a confirmed storage fence of the old owner.
- No node starts a cluster workload without its own applied grant.
- No automatic voter removal; no automatic "force quorum".
- Passthrough-device VMs are not HA unless the policy names an alternate node
  and device mapping (follow-up).

### 7.6 Later: power fencing and persistent reservations

- **IPMI/Redfish** (`cluster.PowerFencer`): when configured for a node, the
  leader powers it off and waits for "off" before proposing `node.dead`, which
  allows a shorter F. Never instead of the storage fence.
- **SCSI-3 persistent reservations** are not used in Phase 8: with one storage
  node the LUN-to-target mapping already gives exclusive access, PR on the host
  device needs `qemu-pr-helper` plumbing, and it conflicts with guests that use
  PR themselves (Windows failover clustering). They are reconsidered with a
  standby storage node (decision 327).

## 8. Security model

- **Identities.** One ECDSA P-256 key per node (cluster identity, sealed with
  secretbox purpose `cluster`); the witness's key in its state directory
  (0600). Pins are in the replicated state; every connection is mutual TLS 1.3
  with pins checked against the current members. Removed nodes' pins are
  rejected; fenced nodes may only use Raft and `rejoin`.
- **Signed log.** Only HardyOS members sign commands; per-proposer sequence
  numbers stop replays; appliers check signer roles (section 2.3).
- **What a compromised compute node can do.** Cluster membership is full
  trust, as in other HA hypervisor clusters: its root can assert any
  administrator to other members, propose placements that grant it any
  workload's volumes, and read and write every shared folder exported to
  compute nodes. It is a cluster compromise and the docs say so. What limits
  it: everything is audited on both ends (assertions carry the person and the
  node; log entries carry actor and proposer); the storage node logs every
  grant and fence; a removed node is locked out by its pin; destructive
  operations still need their typed confirmations.
- **What a compromised witness can do.** Deny quorum (withhold or equivocate
  votes) and, as a short-lived leader, delay or drop proposals. It can't forge
  or replay commands, and it can't make the storage node grant one disk to two
  nodes: the storage node applies a single linear history. Its log holds
  names, addresses and placements (no secrets); it's reachable only over
  NetBird.
- **Storage network.** iSCSI (mutual CHAP) and NFS (`sec=sys`, address-bound
  exports) are unencrypted, as is the live migration memory stream: the
  storage network is a trusted physical segment, firewalled to members'
  addresses. NFS `sec=krb5p` is a possible later hardening.
- **Root operations** (all named, validated, secrets on stdin or as file
  descriptors, never argv):
  - storage node (B): `san.status`, `san.apply` (the desired LIO state: targets,
    CHAP via a sealed-secret reference, backstores, mappings; validated names),
    `san.fence {node, epoch, confirm}` (confirm = node id), `san.unfence {node,
    epoch}`, `san.firewall.apply`, `san.volume.create` / `.resize` /
    `.destroy {confirm}` (zvols under `<pool>/vms/<id>/`), `san.dataset.create` /
    `.destroy {confirm}` (under `<pool>/vms/` and `<pool>/apps/`),
    `nfs.cluster.apply`;
  - compute node (B): `sanclient.status`, `sanclient.iscsi.login` /
    `.logout` / `.rescan`, `sanclient.nfs.mount` / `.umount {force}`,
    `sanclient.multipath.apply`, `sanclient.initiator.set`;
  - compute node (C): `cluster.watchdog.arm` / `.pet {validForMs, lease}` /
    `.disarm` (refused while cluster workloads run) / `.expire` / `.keys`,
    `cluster.selffence {epoch}` (destroy HA domains, kill HA containers, detach),
    `vms.migrate.accept` / `.send` / `.check` / `.health`, `vms.cpu.baseline`,
    `vms.cluster.hash`, `apps.cluster.hash` (decisions 385-394).
  No operation takes a command line, a path outside the named trees, or XML.

### 8.1 Storage: what holds today, and member isolation (pending)

The security review of part B (decisions 375-384) was fixed so that it
holds whichever way the owner decides the open question below: what
matters regardless is fixed, and for member-against-member isolation the
cheap containment is in place.

**In place.** The storage node's root no longer takes hardyd's word for
who may reach what: it pins each compute node's storage address, cluster
key and MAC and the storage subnet (first use; changes only through
`hardyctl cluster-storage` as root), keeps fences by node and key with an
epoch high-water mark, lifts one only with the fenced node's own signed
rejoin statement, refuses old or implausibly new Raft indexes, and keeps
export clients to pinned nodes that hold the workload's volumes. Peer
requests carry the person only in an assertion the calling node signs;
destructive storage operations need an administrator's. Owner-only
exports never go over the LAN itself, the storage firewall checks source
MACs and closes NFSv3's side protocols, node-written file systems are
checked before any kernel mounts them, and cluster LUNs are invisible to
the compute host's own disk tools.

**Open question (owner): do members fully trust each other?** Proxmox-style
clusters do (section 8: a member's root is a cluster compromise). If
instead a compromised compute node must not be able to reach other
workloads' storage, these remain, in order of value:

1. **Root-side log verification on the storage node.** Root keeps the
   members' keys (seeded from the pins) and verifies every applied entry
   that affects storage itself: hardyd hands root the signed entries
   (`cluster.SignedCommand`) since root's last index, root replays the
   storage-relevant appliers (`state.Storage`, placements, fences,
   membership) on its own copy and builds the desired LIO state, exports
   and firewall from that copy instead of hardyd's `Desired`. Needs part A
   to expose raw entries (or the snapshot plus entries) to hardyd, and a
   log compaction story (root keeps its own snapshot). It would also let
   root clear a removed node's fence on a signed `member.remove` instead of
   `hardyctl cluster-storage forget`, and verify `node.rejoin` itself.
2. **Step-up re-authentication for destructive storage operations.** A
   compromised member can still sign an administrator's assertion (its key
   signs every assertion it relays). The storage node would require a
   fresh proof from the person (a WebAuthn assertion or TOTP checked on
   the storage node, or the person's password verified by the storage
   node's own account store for domain accounts) for destroy, rollback,
   snapshot delete, mode and share changes.
3. **Authenticated, encrypted storage transport.** A member on the storage
   segment can spoof another's IP and MAC (the MAC pin stops only casual
   spoofing) and then mount `no_root_squash` exports or read iSCSI traffic.
   NFS RPC-with-TLS (`xprtsec=mtls`, kernel 6.12 with `tlshd` from
   ktls-utils) binds an export to a client certificate; it needs per-node
   X.509 keys on disk for root and tlshd (distinct from the sealed cluster
   key), a CA or pinned trust list in `/etc/tlshd.conf`, and testing in CI
   (the namespace job can't run tlshd per namespace easily). iSCSI has no
   TLS in LIO: IPsec (strongSwan, per-node certificates) between the
   storage node and each compute node, or NVMe/TCP with TLS later.
   Prototyped neither yet: the key handling is the larger part.
4. **Owner-side data moves.** Switching an app between NFS and block mode
   copies on the storage node today (checked and read-only, decision 380).
   Copying on the owner instead needs a placement holding both layouts for
   the move (a state change in part C's placement rules).

## 9. Upgrades in a cluster

- **Version window.** Members may differ by one release while upgrading. Each
  member announces its version and supported features; `FeatureLevel` in the
  state is raised only by **Finish upgrade** (an admin action, refused until
  every member including the witness supports it). New command types and new
  fields that older appliers would treat differently wait for it. This also
  makes a boot-environment rollback on one node safe until then.
- **Rolling update** (`cluster.update.rolling`, one job, resumable):
  pre-checks (quorum healthy, every node up, capacity to drain each compute node
  in turn, the witness reachable when it will be needed); then each compute node:
  drain → `maintenance` (non-voter; witness re-evaluated) → the normal update
  with its health-check rollback → back `active`, voter → optional give-back.
  Then the storage node: **planned storage maintenance** pauses cluster VMs
  (`virsh suspend`, in memory) and stops cluster apps, updates and reboots the
  storage node, then resumes VMs and starts apps; HA is held off for the window.
  Last, the witness (the Cluster app shows the command to re-run the script).
- A node that rolled back to an older version keeps working as long as
  `FeatureLevel` wasn't raised.

## 10. CI test strategy

- **Unit (every PR, `go test ./...`).** Pure appliers and the FSM (signatures,
  replay, roles, generations; property tests: never two owners with a grant,
  never a recovery before `storage.fenced`); the HA coordinator and the node
  fence agent against a fake clock (timing invariants, every scenario of 7.4);
  the scheduler; assertion signing and checking; the stream layer's path
  switching with a fake dialer; LIO configfs rendering against a temp
  directory tree; exports rendering; iSCSI node record files; the witness
  script (golden).
- **In-process cluster (every PR).** 3-5 cluster cores in one test with Raft's
  in-memory transport, fake hardyd-priv clients and fake runtimes: partitions,
  leader loss, witness promotion, joins and leaves, rolling-update sequencing.
- **Multi-node on one runner (CI job "Cluster (namespaces)").** Three network
  namespaces (`c1`, `c2`, `w`) plus the init namespace as the storage node,
  bridges for LAN, storage and a third "netbird" network; the test binary runs
  as real cluster nodes in each namespace. Storage: a file-backed ZFS pool, LIO
  in the init namespace (its iSCSI listener lives there), `iscsid` per namespace
  where open-iscsi supports it, else in the init namespace with the `tcm_loop`
  fabric for block-path tests; NFS over the veth links. Link cuts and `tc
  netem` delays exercise path failover, partitions, isolation and fencing. The
  watchdog is a fake device (a file whose "expiry" is recorded); a real
  watchdog is never armed on a runner.
- **VM tier (nightly and on a `cluster-full` label).** Four small KVM guests
  (Debian cloud image + `hardyos-core` .deb): real failover with `softdog` in a
  guest, `virsh destroy` of a node, LAN and storage link cuts, live migration
  (nested KVM where available, else TCG).
- **Never** real disks: file-backed vdevs only (`HARDYOS_CLUSTER_INTEGRATION=1`
  gates the jobs, like the NFS and ZFS jobs).

## 11. Work split and file ownership

Merge order **A → B → C**; each part rebases on the previous and re-runs
`make gen` (the generated client is regenerated, never hand-merged). B and C
code against the contract with fakes until A lands.

| Part | Owns | Decisions | Migration |
| --- | --- | --- | --- |
| **A cluster core**: membership, Raft, FSM core, signed commands, stream layer and paths (LAN/NetBird), heartbeats and quorum lease reporting, join/leave/remove, witness binary and script, peer API, assertions, API proxy, cluster desktop | `internal/cluster/contract.go` (after this commit; changes by agreement), `internal/cluster/*.go` (identity, raft, transport, paths, heartbeat, join, peer, proxy, assertion, events), `internal/cluster/state/{fsm,members,witness}.go`, `internal/cluster/witness/` (incl. script), `cmd/hardyos-witness/`, `priv/cluster_ops.go` (`cluster.status` only), `api/handlers_cluster.go`, `api/clusterproxy*.go`, `api/windowproxy` changes for remote apps, `internal/ports` (44500 reserved here), web `apps/shell/src/cluster/` (switcher, node-scoped client) and `apps/shell/src/apps/cluster/` (overview, nodes, join, witness), Makefile/nfpm for the witness binary, `docs/cluster.md` (user guide; B and C add sections) | 330-339 | `0070_cluster.sql` |
| **B storage role + compute storage clients** | `internal/cluster/san/` (LIO configfs, desired state, fence/unfence, firewall), `internal/cluster/sanclient/` (open-iscsi, multipath, NFS mounts, attachment records, `vms.StorageBackend` and `apps.StorageBackend` implementations, cluster `apps.ShareResolver`), `internal/cluster/storagesvc/` (hardyd side: provisioning, snapshots on the storage node, grant application from the state, CHAP distribution, freeze/dump forwarding), `internal/cluster/state/storage.go`, `internal/nfs/cluster.go`, `internal/network/storagenet.go`, `priv/san_ops.go`, `priv/sanclient_ops.go`, `api/handlers_cluster_storage.go`, web `apps/shell/src/apps/cluster/storage/` (incl. the storage network step), `os/live/config/package-lists/cluster.list.chroot` (`targetcli-fb open-iscsi multipath-tools nfs-common sg3-utils`) | 340-349 | `0071_cluster_storage.sql` |
| **C placement, moves, HA, fencing** | `internal/cluster/placement/`, `internal/cluster/moves/`, `internal/cluster/ha/` (coordinator), `internal/cluster/fence/` (node agent, watchdog client, power fencer interface), `internal/cluster/runtime/` (VM and app runtimes over hardyd-priv), `internal/cluster/state/{placement,fence}.go`, `internal/vms/migrate.go`, `internal/vms` wiring of `Backend` (lifecycle, XML disk sources, CPU baseline), `internal/apps` wiring of `Backend`, `priv/cluster_fence_ops.go`, `priv/vms_migrate_ops.go`, libvirt hook `packaging/libvirt/hooks/qemu`, `internal/publish` re-targeting after moves, `api/handlers_cluster_ha.go`, `api/handlers_cluster_moves.go`, web `apps/shell/src/apps/cluster/ha/`, Move dialogs in `apps/vms/` and the App Store | 350-359 | `0072_cluster_ha.sql` |

Shared files, one small edit each, in its own place:

- `api/openapi.yaml`: each part adds its paths under its marker comment
  (already in the file before `components:`), tags `cluster`,
  `cluster-storage`, `cluster-ha`.
- `cmd/hardyd/main.go`, `cmd/hardyd-priv/main.go`: one call each to a
  `wireCluster{A,B,C}` function in the part's own file next to `main.go`.
- `docs/architecture.md`: A adds a "Cluster" section; B and C add subsections.
- `docs/decisions.md`: each part's own range.

Contract between the parts (`internal/cluster/contract.go`):

- A provides `Membership` (state, quorum, propose, wait-applied, events),
  `PeerClient`/`PeerMux` (signed-peer HTTP between members), the FSM that calls
  registered `Applier`s, and `Timings`.
- B provides `StorageService` (any node; executes on the storage node),
  `StorageAttacher` (compute nodes), the `storage.*` appliers and the storage
  node's agent that turns the applied state into LIO/exports and proposes
  `storage.applied` / `storage.fenced`.
- C provides `Scheduler`, `Mover`, `HA`, the node `FenceAgent` over a
  `Watchdog`, `Runtime` adapters for VMs and apps, and the `placement.*`,
  `node.dead/isolated/rejoin`, `ha.*` appliers.

## 12. Open questions and risks

1. **Witness voting with 3 servers.** The owner asked for the witness to vote;
   this plan has it vote only when the HardyOS voter count is even (it is a hot
   standby with 3 servers and votes during maintenance or with 2/4 servers).
   Always voting would give 4 voters (still one failure tolerated, a 2-2 split
   stalls). Confirm.
2. **SQLite/databases on NFS** (6.2). Accept NFS for all app data, or add the
   per-app block mode (zvol LUN + ext4) in this phase for database-heavy apps?
3. **Storage network as a control path.** The owner chose LAN then NetBird for
   control. Heartbeats over the storage network as a middle path would keep
   quorum through a LAN switch failure without the internet; it would also
   hide LAN loss (handled by LAN isolation). Add it?
4. **Witness architecture.** The VPS is probably amd64; the build targets
   x86_64 only (CLAUDE.md). An arm64 witness build is a Makefile line when
   needed.
5. **LIO and open-iscsi in network namespaces** for CI: the iSCSI target
   listens in the init namespace and `iscsid` namespace support is partial;
   the namespace job may need the VM tier for real iSCSI paths. GitHub's
   runner kernels may lack `target_core_mod`/`iscsi_target_mod`
   (`linux-modules-extra`); check first.
6. **Live migration trust.** The libvirt connection relayed for a migration is
   a full libvirt session on the destination for its duration (bounded by the
   token, the deadline, the source member and the hook's XML check). Members
   are trusted already (8), but this is the widest root-to-root channel in the
   design; part C should look for a narrower libvirt ACL (polkit access driver)
   before shipping.
7. **Hardware watchdogs.** Not every board exposes one; `softdog` doesn't
   survive a kernel hang. Should HA be refused on nodes without a hardware
   watchdog, or allowed with a warning (current plan: warning)?
8. **Failover time** (~40 s + boot) vs riding out blips. Q/F are settings; the
   defaults may need tuning on real hardware, especially NetBird relay latency.
9. **Docker images on compute nodes.** Recovery pulls images if the new node
   doesn't have them; an internet outage then blocks app failover. Option:
   keep every HA app's images pulled on all compute nodes (disk cost).
10. **Standby storage node (later).** It would hold ZFS replicas (existing
    replication) and be promoted only with quorum and a confirmed fence of the
    primary (power or storage isolation). Two arbiters break the "one linear
    history" safety argument, so promotion must be an explicit, fenced,
    log-committed step; PR and power fencing come back into scope then.
11. **IPMI/Redfish power fencing** is designed as an interface only; which
    boards the owner has decides when it's built.
