# Clusters of HardyOS servers

Phase 8. Join three or more HardyOS servers into one cluster: sign in once
and manage every server from one desktop, keep VM and app data on one
storage server, move workloads between servers and restart them elsewhere
when a server dies. Architecture: [architecture.md](architecture.md#cluster);
design: [plans/cluster.md](plans/cluster.md); decisions 320-359.

This guide covers the cluster core (part A): creating and joining a
cluster, the witness on the VPS, the server switcher and how the servers
talk to each other. Parts B (the storage node) and C (moves, high
availability, fencing) add their sections below.

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
  - an **administrator of any server is an administrator on every
    server** (the audit log says `alice (via c1)`);
  - **local non-admin accounts** belong to one server: sign in on that
    server to use it.
- Live views (events, VM screens, terminals) are forwarded too and close
  within 15 seconds of signing out. App windows for apps on another server
  open through the entry server's window proxy.

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

## Alerts

- *This server lost the cluster's quorum* (warning) after 30 seconds
  without a majority, and *has quorum again* when it's back.
- *This server stopped following the cluster* (critical): the log holds a
  change this version doesn't understand. Update HardyOS on this server.

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
- Membership is full trust, as in other clusters of this kind: a server
  whose root is compromised can act as an administrator on the others. Both
  ends audit every forwarded change with the person and the server.
