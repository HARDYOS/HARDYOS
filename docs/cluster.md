# Clusters of HardyOS servers

Phase 8. Join three or more HardyOS servers into one cluster: sign in once
and manage every server from one desktop, keep VM and app data on one
storage server, move workloads between servers and restart them elsewhere
when a server dies. Architecture: [architecture.md](architecture.md#cluster);
design: [plans/cluster.md](plans/cluster.md) and
[plans/cluster-gaps.md](plans/cluster-gaps.md); decisions 320-359, 365-399,
470-475 and 490-495.

This guide covers the cluster core (part A: creating and joining a
cluster, the witness on the VPS, the server switcher and how the servers
talk to each other), the storage server (part B) and moving workloads,
high availability and fencing (part C).

## What a cluster is

- Every server keeps its own control plane, database, jobs and audit log.
  What the servers must agree on (who is a member, with which role and
  addresses, and later which server runs which VM or app) is kept in a
  small replicated log (Raft) that every member holds a copy of.
- **Roles**, fixed when a server joins:
  - **storage**: the NAS that holds the pool. Exactly one.
  - **compute**: runs cluster VMs and apps.
  - **witness**: a tiny program on the VPS (`vpn.hardynetworks.net`) that
    only votes. It runs nothing and holds no data beyond the log.
- **Quorum**: changes need a majority of the voting members. With three
  servers all three vote and the witness waits on standby (a fourth vote
  wouldn't let the cluster survive more failures, and a 2-2 split would
  stall). The witness votes whenever the number of voting servers is even:
  with two servers, or with three while one is in maintenance.
- A server that loses the majority for 15 seconds counts itself as without
  quorum: it makes no changes, and (part C) stops its high-availability
  workloads so they can safely start elsewhere.

## Networks

- **The LAN** carries the desktop and the servers' control traffic in
  normal operation, on port **44500** (TLS 1.3, each server's key pinned;
  nothing on that port answers a computer that isn't a member).
- **The storage network** (a dedicated port or VLAN, ideally 10GbE) carries
  iSCSI and NFS (part B) and is the **second** control path: if the LAN
  switch fails, the servers keep talking over it.
- **NetBird** is the last control path, and the witness's only one. Bulk
  traffic (storage, live migration) never goes over NetBird.

Each server checks every path to every other server once a second. It
leaves the path in use after 3 missed checks and goes back to a better one
after 10 good checks in a row, so a flapping link doesn't make it jump back
and forth. Cluster › Overview shows the path in use (highlighted) and the
round-trip time for each server.

**The local-network check** (decisions 490-492). A cluster works when its
servers reach each other only over NetBird, but **high availability and
live moves need a local network**: every compute server and the storage
server must reach each other directly on the LAN *and* on the storage
network. Every 30 seconds each server sends signed probes on the cluster
port (no other port) to every other one, on each of the two paths, and
checks:

- the probe is answered, by the server's own key;
- it leaves from this server's own address on that path and arrives as
  coming from it (no NAT, no detour through NetBird or another port);
- the best round trip is at most 5 ms (same subnet or routed both count);
- a 64 KiB probe gets through (jumbo frames the switch drops stall it);
- on the storage network, both ports have the same MTU.

Cluster › Overview › **Local network** shows each server's probes of the
others per path, with round trip, MTU, same subnet or routed, and what
failed; **Check now** probes at once. Servers in maintenance or rejoining
aren't checked. Each decision looks only at the servers it involves, with
the storage server (decision 496): a live move at its two servers (the Move
dialog says per server whether it can go live; the HA coordinator's own
live moves are checked too), turning high availability on at the servers
the workload could run on (its preferred ones when it is restricted to
them). Those are refused with the reason; offline moves still work, and
workloads that already are highly available keep failing over. **Move
everything off…** leaves a VM that can't move live because of the network
running where it is and reports it, unless you tick **Move offline**. Each
server sends a notification when its own result changes.

## Creating the cluster

Usually on the NAS: Cluster › **Create a cluster**.

- **Cluster name**: what the menu bar and the other servers show.
- **This server's role**: Storage for the NAS, Compute otherwise.
- **Storage network**: the subnet of the storage network (suggested
  `10.77.0.0/24`). Compute servers must have an address in it to join.

The server makes its cluster key (kept sealed in its database, separate
from its replication key), starts the log as its only voter and records
the cluster. This is a job (Log Center shows it).

## Adding a server

1. On any member: Cluster › **Add server** › choose the role › **Make a
   join code**. The code is shown once with the member's addresses. It
   works once, for 30 minutes. One address may get it wrong 3 times; 5
   wrong tries in all close it.
2. On the new server (installed, its own administrator signed in): Cluster
   › **Join a cluster**: the member's address, the code and this server's
   role.

The two servers prove to each other that they know the code, binding both
servers' keys into the proof, so someone in between learns nothing and
can't swap a key. Before anything is committed the member checks
everything at once and lists every problem: HardyOS versions at most one
release apart, a unique hostname, only one storage node, an address on the
storage network for compute servers; a server without NetBird gets a
warning (no failover path).

The new server then copies the log as a non-voter and, once it has caught
up, becomes a voter (the witness steps down to standby if the count is now
odd). It keeps its own pools, apps and VMs as they are.

## The witness on the VPS

The VPS must be in the same NetBird network as the servers, and this
server must be on NetBird (Control Panel › Remote Access).

1. Cluster › **Witness** › **Make the install script**. The script holds a
   one-time join code (30 minutes); don't keep it.
2. Copy it to the VPS and run it as root: `sudo sh hardyos-witness.sh`.

The script downloads the witness program from this server over NetBird
(checking this server's key and the file's checksum), installs it as
`/usr/local/bin/hardyos-witness` with a systemd service that runs under a
throw-away user in a strict sandbox (no root, read-only system, 128 MB of
memory, listening on the VPS's NetBird address only), joins with the code
(handed to the service as a systemd credential, never on a command line)
and deletes the code. `hardyos-witness status` on the VPS shows whether it
joined and whether it votes.

- **Updating**: make a new script and run it again (members hand out the
  witness of their own HardyOS version).
- **Removing**: Cluster › Witness › **Remove the witness…** (type its
  name), then `sudo sh hardyos-witness.sh --remove` on the VPS.

The witness signs nothing but its own hello. If it ever ends up leading the
log it hands leadership to a server at once. A compromised VPS can refuse
to vote or delay changes, but can't forge or replay changes.

## One desktop for the whole cluster

- **Sign in once**, on any server. Your session stays on that server (the
  *entry* server).
- The **server switcher** in the menu bar lists the servers with a health
  dot. Windows you open after picking a server work on that server and show
  its name in their title. **Cluster overview** opens the Cluster app.
- Behind the scenes the entry server forwards each request to the other
  server with a signed statement of who you are, valid for 60 seconds and
  for that one request only; your session cookie never leaves the entry
  server. The other server decides what you may do there:
  - **domain accounts** get what they would get signing in there (checked
    by the account's SID against the domain);
  - an **administrator of another server** acts as an administrator here
    for what the cluster desktop does: VMs, apps from the catalogs,
    storage, shared folders, files, backups, monitoring and the cluster's
    workloads (the audit log says `alice (via c1)`). Accounts, sign-in,
    the terminal, network settings, updates, remote access, custom apps
    and the cluster's membership (join codes, the witness script, leaving,
    removing, dissolving) need signing in on that server itself;
  - each server chooses which other servers' administrators it accepts:
    **Cluster › Servers › Administrators of other servers** (all of them
    until an administrator of that server turns one off);
  - **local non-admin accounts** belong to one server: sign in on that
    server to use it.
- Live views (events, VM screens) are forwarded too and close within 15
  seconds of signing out, or of the account being turned off or losing its
  administrator role. **App windows from any server** (decisions
  493-495): an app's window opens on the server that runs it, through the
  entry server's window proxy and the cluster relay, after that server
  confirmed you may use the app. A cluster app opens wherever it runs now,
  whatever server the window was opened for; App Store › My apps lists the
  apps of the other servers you may open under **On other servers**. The
  server running the app checks its access list on every request and every
  15 seconds on an open WebSocket; the entry server's two-factor rules hold
  as for every relayed request. Idle windows close after 30 minutes. With
  per-app hostnames, `<app>.<base>` works on every server: it serves the
  app wherever it runs (its own app first, then the cluster app's server,
  then the one other server that has it; an app on several other servers
  says which, open it from the desktop). Webmail stays each server's own.
  Documents on another server
  open in that server's editor at its LAN address (if the browser warns
  about its certificate, accept it once for that address).
- Each person has at most 16 requests and 8 live views to other servers
  open at once (128 and 64 for everyone); uploads to another server wait in
  hardyd's own folder on the entry server, up to 8 GiB at a time.

## Leaving and removing

- **Leave** (on the server, Cluster › Servers › Leave the cluster, type the
  cluster's name): refused while cluster workloads run on it. The server
  hands over its vote, is removed, and forgets its cluster key; it keeps its
  own pools and apps.
- **Remove** a dead or gone server from another member (Cluster › Servers ›
  Remove…, type its name). Its key is refused from then on; to join again
  it must be reset and join with a new key. Servers are never removed
  automatically, even when unreachable: an administrator decides.
- **Dissolve** (on the last server): ends the cluster.

## The storage server (cluster storage)

One server, the NAS with the **storage** role, holds the pool for every
cluster VM and app. Compute servers use it over the storage network:

- a VM's **disks** are ZFS volumes on the NAS, each an iSCSI disk that the
  NAS gives to exactly one compute server (the one running the VM; two only
  while a VM migrates live);
- a VM's **state folder** (settings, firmware variables, TPM, cloud-init
  disc) and an **app's data** are datasets on the NAS, mounted over NFS by
  that one server only;
- **shared folders** put in the cluster (Cluster › Storage › Shared folders
  in the cluster) are mounted by every compute server, so cluster apps use
  them as on one server. People on the LAN keep using SMB and NFS on the
  NAS as before.

Snapshots, backups and replication of cluster VMs and apps stay on the NAS
(Cluster › Storage › Workloads on cluster storage › Snapshots). For a
snapshot of a running VM the NAS asks the server running it to freeze the
guest's file systems first (thawed after 60 seconds at most); a running
app's backup dump runs on its server first. Rolling back needs the VM or
app stopped.

**The storage network.** The create and join wizards (and Cluster ›
Storage › Storage network) list this server's ports with their speed: a
dedicated port (best, fastest first), a VLAN on the LAN port (the switch
must carry it), or the LAN itself (it works, but iSCSI and NFS then share
the wire with everyone; not recommended). The address is static and
private, without a gateway, in the cluster's storage subnet (suggested
`10.77.0.0/24`, `.10` for the NAS). Jumbo frames (MTU 9000) are offered on
ports of 1 Gb/s and up; the switch must allow them. Like every network
change it is kept only once you confirm it. Compute servers refuse to use
cluster storage over any other path, never over NetBird. The LAN itself
can carry only shared folders and apps in block mode: VMs and apps whose
data is a folder need a dedicated port or a VLAN. Changing a server's
storage address later asks for its name, and the storage server keeps it
cut off until its administrator runs `hardyctl cluster-storage repin
<server>` there.

**App data: folder or volume.** An app's data is an NFS folder (default:
plain files) or a **block volume** (a ZFS volume with ext4 or xfs that only
the app's server mounts). Apps that keep a database get a block volume by
default (their package says so, or the compose file runs a known database
server): databases need a disk that behaves like a local one. A stopped
app can be switched (Cluster › Storage › the app › Data mode, typed
confirmation; a snapshot is taken first).

**Fencing on the NAS.** When the cluster declares a compute server dead
(see High availability), the NAS disables that server's iSCSI target
(dropping its sessions), removes it from every export, expires its NFS
clients and blocks its address, and only then confirms in the log. It
keeps refusing the server until it rejoins (with a request signed by the
server's own key) and gives it new secrets then. Each compute server has
its own iSCSI target and login secrets (mutual CHAP) that the NAS's root
keeps and hands to that server alone; **New CHAP secrets** next to the
server's target in Cluster › Storage replaces them (only while nothing is
mapped to it: move or stop its workloads first; its sessions are dropped).

## Moving VMs and apps

Cluster VMs and apps show a **Move…** button (VMs app, App Store) and are
listed in Cluster › **Workloads and HA**. The Move dialog lists every
compute server with whether it fits (memory, CPU, bridges and VLANs,
watchdog, devices) and why not.

- **Offline move** (VMs and apps): the VM shuts down (guest agent or ACPI,
  up to 3 minutes) or the app stops, its server lets go of the storage, the
  NAS hands it to the new server, which starts it. An app's images are
  downloaded on the new server before it stops on the old one. If a step
  fails the workload stays stopped where the log last put it, with Retry
  and Move back.
- **Live migration** (running VMs without passthrough devices, to a server
  with a compatible CPU and the same bridge and VLANs): the VM keeps
  running while its memory is copied over the storage network. If it fails
  the VM keeps running where it was: both servers are asked what really
  runs, and a copy left on the new server is destroyed before the VM is
  recorded on the old one (or, if the memory did arrive, it stays on the
  new one). Cluster VMs use the cluster's CPU baseline so they can migrate
  between servers with different CPUs; a VM set to the host's exact CPU
  migrates only between servers with an identical CPU (same model, vendor
  and features). Live migration needs the cluster port's own connection
  (LAN or storage network); it never falls back to NetBird, and it waits
  until the local-network check passes (Networks, above).
- **VMs with passthrough devices** (GPU, USB) are pinned to their server:
  never HA, never migrated live. An offline move to a server you pick is
  possible once that server confirms it has matching devices (typed
  confirmation).
- **Move everything off…** (Cluster › Workloads and HA › Compute servers)
  drains a server: migrates live what can be, moves the rest offline (HA
  workloads first) and, if you agree, stops what can't move. Use it before
  maintenance and before a server leaves.

## High availability

Turn HA on per VM or app in Cluster › Workloads and HA: priority (higher
recovers first), restarts in place per hour before it moves elsewhere,
preferred servers (optionally *only* those), an anti-affinity group (kept
on different servers when possible) and fail back. Turning it on needs the
local-network check to pass (Networks, above); changing or turning off a
policy doesn't.

**When a compute server dies** (default timings):

1. After 10 seconds without hearing it, the cluster shows it as suspect.
2. The server itself, if it still runs but is cut off, loses its quorum
   lease after 15 seconds and **stops its HA workloads at once**; it also
   stops feeding its hardware watchdog, so if stopping hangs the watchdog
   resets the machine within 10 seconds. (The root helper that feeds the
   watchdog doesn't take hardyd's word for the lease: it checks the
   leader's signed answer to the server's own heartbeat each time.)
3. After 40 seconds the leader declares it **dead**; the NAS cuts it off
   (above) and confirms.
4. Only then are its HA workloads started on other servers, by priority,
   from the same disks: nothing is lost beyond writes in flight. A workload
   that fits nowhere waits (*pending*, retried every 30 seconds). Its
   non-HA workloads are marked *orphaned*; start them elsewhere with Move.
5. When the server comes back it starts nothing, sees it was fenced and,
   after a new boot, rejoins; the NAS lets it in again with nothing mapped.
   Its former workloads stay where they are (unless fail back is on).

A VM or app is **never** run by two servers against the same disk: the log
names one owner per generation, the NAS maps the disk to that owner only,
recovery waits for the NAS's confirmed fence, and every server stops
whatever the log no longer places on it. A server rejoins only from a boot
other than the one that was declared dead (the boot id is recorded at
every start).

**Approved settings.** A cluster VM or app starts only with the settings an
administrator approved: the log keeps a hash of them, and the server
starting it checks the files on cluster storage against it (an app's
compose file also passes the install policy check again). Changing a
cluster VM's settings (on the server it is placed on) records the new
hash; a cluster app's settings can't be changed yet.

Other cases: a server that loses only the storage network while the others
still reach the NAS is isolated and fenced the same way. If **every**
server loses the NAS nothing fails over (there is nowhere to go): VMs pause
on I/O errors and resume when it is back. If the cluster loses quorum
altogether, HA workloads stop everywhere and start again when quorum
returns: that is the price of never running a disk twice.

**Watchdogs.** HA needs a hardware watchdog on the compute server (most
boards have one: `iTCO_wdt`, `sp5100_tco`, IPMI; `hardyos-watchdog.service`
loads the driver, which Debian otherwise blacklists). A server with only
the software watchdog (a kernel hang defeats it) is skipped for HA; an
administrator can allow it per server (Compute servers › **Allow HA
anyway…**, typed confirmation, behind a warning). A server without any
watchdog can't be allowed. A watchdog that can't be stopped once started
(nowayout) stays armed and fed. Restarting hardyd keeps HA workloads
running; if hardyd-priv restarts while they run, the watchdog is armed
again at once and an alert is recorded (drain a server before updating
it).

**Timings** (Workloads and HA › Failover timings) can be changed within
safe bounds: a server is declared dead no sooner than quorum lease +
watchdog + 10 seconds, and the self-stop time is shorter than the
watchdog's. Every server refuses unsafe values, not only the desktop.

**Images.** Every HA app's container images are kept downloaded on every
server that could take it over, so a failover never needs the internet.

**Published apps** (NetBird) follow the app: its new server re-targets the
app's published name after a move or a failover.

**Not there yet.** The HA coordinator's LAN isolation (a server whose own
LAN alone fails while the others' works) still reports the LAN as always
working, so it never triggers; the local-network check above is about how
the servers are connected, and doesn't fail anything over.

## Making a VM or app highly available

Phase 10 (decisions 480-489, plan: [plans/make-ha.md](plans/make-ha.md)).
A VM's page and an app's details show **Make highly available…** on a
compute server of a cluster.

- **What it does**: a snapshot and a copy of its storage (a VM's settings
  folder and disks, an app's folder), with every snapshot it has, to the
  storage server while it runs; then it shuts down (a VM: the guest, up to
  3 minutes), what changed is copied, the storage server takes it as
  cluster storage, and it starts from there on the same server, now
  highly available (priority as chosen, this server preferred). Downtime
  is the final copy only. The job shows the bytes copied.
- **The dialog** says what can't move now and why: passthrough devices
  (they pin a VM), discs from this server's ISO library, an unfinished
  Windows install, this server without a hardware watchdog, the local
  network check (this server and the storage server, and every server it
  could fail over to, as turning HA on; asked again before it shuts
  down). A VM can take the cluster's
  CPU model (default; it then moves live between any servers) or keep its
  own. Type the name to confirm.
- **An app's shared folders move with it** (decisions 500-503): a cluster
  app runs on any compute server, so each shared folder it was given goes
  to the storage server too, copied like the app's own folder (every
  snapshot, a copy while people still use it, the final increment once the
  app is off), and becomes one of the storage server's shared folders,
  used in the cluster: same name, description, permissions, quota,
  recycle bin, snapshot schedule and SMB, NFS, Time Machine, WebDAV and
  SFTP settings, and its files keep their permissions (the app's user id
  is the same everywhere; domain accounts are, on servers in the same
  domain). From the final copy on, nobody uses this server's copy (it is
  read-only and taken out of file sharing); the storage server's copy is
  shared only once this server's copy is put aside, so there are never two
  copies anyone can write. People then reach the folder on the storage
  server (File Manager, SMB, NFS, Time Machine) under the same name; this
  server's copy is kept like the app's, for 24 hours after the app ran
  from cluster storage. The dialog lists the folders and says why one
  can't move: another app of this server uses it too, it is in one of this
  server's backup or replication tasks (back it up from the storage server
  afterwards), it is the VMs' ISO library, the storage server has a shared
  folder with its name or id, or its permissions name domain accounts and
  the storage server isn't in the same domain. Web links into it stop
  working (make them again on the storage server). **Undo** puts this
  server's shared folders back as they were (the storage server's copies
  go aside: kept until you delete them if they were shared from there).
  An app whose shared folders moved stays highly available: **Make local
  again** refuses it.
- **If the conversion stopped after the app was shut down** (a crash),
  **Abandon** starts the app again when it ran before (decision 504: the
  state is recorded with the app's hold), as giving up does.
- **This server's copy** is kept, unused (it is no longer a VM or app),
  until the workload has run from cluster storage, then for 24 hours.
  Cluster › HA › **Kept copies** lists these copies on **every server** of
  the cluster (decision 505) with when they go; **Delete now…** (type the
  name) frees the space sooner, through the server that holds the copy
  (its own rules apply: whether it accepts administrators of other
  servers, the "last copy" confirmation). A copy marked *Kept until you
  delete it* has no expiry because its workload hasn't run from its other
  copy yet, so it may be the only good one: deleting it also asks you to
  confirm that.
- **If it fails or is cancelled**: before the local copy is put aside
  nothing changed (it starts again if it ran); what was copied stays on the
  storage server so trying again copies only what's new (**Abandon…**
  deletes it). If this server's copy was used after its final snapshot,
  it isn't put aside and the conversion starts over from the copy. After
  that, nothing is undone by itself: try again to carry on, or **Undo…**
  (type the name) to put this server's copy back. Undo puts this server's
  copy back first; the cluster copy is then kept, and goes 24 hours after
  this server's copy has run again, or is kept until you delete it if it
  may have changed on cluster storage. Cluster › HA › **Conversions** shows
  each one and where it stopped.
- **Apps** with a database move to a block volume (as their package or
  compose file says); their user id is kept, cluster-wide.
- **Make local again…** (Cluster › HA › Workloads) brings a cluster
  workload to a compute server's own pool: it stops, its storage and
  snapshots are copied there, it leaves the cluster (no failover any
  more) and runs there; the cluster copy is kept until it has run there,
  then for 24 hours.
- **HA VMs** keep their snapshot schedule (the storage server takes the
  snapshots), may publish game streaming (the server running the VM
  forwards it; it can't move live while published), and **Save as
  template** (stopped) makes the template on the storage server. Keeping a
  plugged-in USB device in an HA VM's settings stays refused.
- **Copies travel** over the cluster port on the LAN or the storage
  network, never over NetBird, from the compute server to the storage
  server only.

**Failover history**: Cluster › HA › **Failover history** lists every
restart elsewhere and every "nowhere to run", from every server (the
coordinator is whichever server leads). A workload restarts on the server
with the most room (memory and CPUs), its preferred server first; it never
moves back by itself.

## Alerts

- *This server lost the cluster's quorum* (warning) after 30 seconds
  without a majority, and *has quorum again* when it's back.
- *This server doesn't share the cluster's local network* (warning,
  `cluster.netcheck`) with the first problem, and *shares … again* (info)
  when it's back; sent after two checks in a row agree.
- *This server stopped following the cluster* (critical): the log holds a
  change this version doesn't understand. Update HardyOS on this server.
- High-availability actions (a server declared dead or isolated,
  recoveries, workloads pending or in error) are recorded as finished jobs
  (`cluster.ha.*`) and in the audit log; so is every step a server runs for
  a move (`cluster.move.step`), with the member that asked.
- *X is restarting on Y* (warning, `cluster.ha.failover`) for every
  failover, *No server can run X* (critical, `cluster.ha.nowhere`), and a
  conversion that stopped or finished (`cluster.ha.convert`,
  `cluster.ha.local`).
- *polkit isn't running* (critical, `cluster.polkit.down`): with live
  migration set up, libvirt refuses every call until polkitd is back (a
  forced stop still works).

## Security notes

- Every connection between members is mutual TLS 1.3 with pinned keys;
  every request between members is authenticated by the key and authorized
  by the member's role (the witness may only check paths, send its heartbeat
  and propose its own hello).
- Every change in the log is signed by the server that proposed it and
  numbered; every member checks the signature, that the server's role may
  make that change, and that the number is new. A member can't forge
  another's changes, and an old change can't be replayed.
- No secrets go into the log.
- The cluster log (Raft) only believes what the connection proves: every
  message must come from the member whose key made the connection, and
  only servers that may lead (active, rejoining or in maintenance) may send
  a leader's or a candidate's messages. The witness, a joining server and a
  dead or fenced one can't take over the log or make others follow them; a
  snapshot can't swap a member's key, raise its role, roll a server back
  or drop it. A server only counts itself in contact with the cluster when
  the leader signed the answer to its heartbeat.
- A change of a kind a server doesn't know never stops the cluster: every
  server refuses it, unless the cluster enabled a feature level that server
  lacks (then it stops and asks to be updated).
- **Members of one cluster trust each other fully**, as in Proxmox
  (the owner's decision, decision 399). A cluster is one administrative
  domain: add only servers you'd give the same administrators and the same
  root. A member whose root is compromised is out of scope: it can act as
  an administrator on the others within the limits above, misbehave as a
  leader of the log (Raft isn't Byzantine fault tolerant), and reach
  cluster storage. Not planned, because of that: the target re-asking the
  person to sign in (or step up) before destroying storage, the storage
  server checking the log itself, limiting which members may propose
  placements, deaths and moves, encrypting the storage network, and
  end-to-end libvirt TLS for migrations. The checks described here stay:
  they stop mistakes, a hung or confused hardyd and replays, not a hostile
  member. Each server can still turn off administrators of other servers
  (**Cluster › Servers**), and both ends audit every forwarded change with
  the person and the server.
- Known limit: a server that was offline while another server joined (or
  rejoined after a fence) catches up once the leader is a server it already
  knows as active; until then it stays behind (the others are unaffected).
- The storage server's root doesn't take its own hardyd's word for who may
  reach what: it remembers each compute server's storage address, key and
  network card (MAC) from the first time it sees them, and keeps a fenced
  server cut off until that server itself asks to come back, signed with
  its own key. When a server's storage address or key really changes (a new
  network card, a reinstall), its storage stays off until an administrator
  confirms it **as root on the storage server**:
  `hardyctl cluster-storage repin <server>` (or `repin --subnet` for a new
  storage network). After removing a server for good,
  `hardyctl cluster-storage forget <server>` clears what the storage
  server kept of it, its fence included (the address can't be reused
  before that).
- Destroying, rolling back, deleting snapshots of, resizing or moving the
  data of cluster storage, and putting shared folders in or out of the
  cluster, need an administrator's request; a server on its own may only
  snapshot its own workloads (at most once a minute).
- VMs' and apps' own data is exported to their server without root
  squashing, so it is never exported when the storage network is the LAN
  itself: use a dedicated port or a VLAN. The storage network carries no
  encryption: a server on that network could still pretend to be another
  (decision 379); under full trust between members (decision 399) that is
  accepted and encrypting it is not planned.
- Compute servers never treat cluster disks as their own (they aren't
  offered for pools, imported or probed), and a block volume another server
  wrote is checked before it is mounted.
- Conversions (decisions 480-489): streams are single datasets only (never
  `zfs send -R` packages, which carry properties) and land in a folder of
  their own that is never exported; a copy connection takes a one-time
  token the storage server gave that compute server less than a minute
  before; the storage server's own VM engine never runs a cluster VM's
  datasets; the copy a workload left can't run (it is no longer a VM or
  app); administrators of other servers may convert like they may move.
