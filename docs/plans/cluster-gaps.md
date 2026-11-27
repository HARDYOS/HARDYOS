# Cluster gaps (Phase 10): the local-network check and app windows from any server

Two gaps left by Phase 8 (`docs/cluster.md` › "Not there yet", the PR #35
notes). Decisions 490-499. No migration.

## 1. The local-network check

**Owner's choice: warn, block HA only.** A cluster whose members reach each
other only over NetBird keeps working (the desktop, offline moves, storage
over its own network), but turning high availability on for a workload and
moving a VM live are refused until the members share the LAN and the
storage network. Workloads that already are HA keep failing over: refusing
a recovery would only make an outage longer.

**What "share a local network" means** (decision 490). For every pair of
servers that hold or run workloads (the compute servers and the storage
server; not the witness, not a dead or fenced server), on both the LAN path
and the storage-network path:

- both have an address on that path;
- a signed probe over the cluster port (44500, `hardyos-peer/1`, the
  normal pinned TLS) to the peer's address on that path is answered;
- the connection left from this server's own address on that path, and the
  peer saw it come from that same address (no NAT, no detour through
  NetBird or another interface);
- the best round trip of 5 small probes is at most 5 ms (a LAN, not a
  routed WAN; the best, so a busy moment doesn't count; same subnet or
  routed is both fine, the page shows which);
- a 64 KiB probe gets through within 3 s (jumbo frames set on the servers
  but dropped by the switch stall here; in practice the TLS handshake
  already stalls, its post-quantum key shares being over 1500 bytes, so a
  storage path that doesn't answer with an MTU above 1500 names the
  switch's jumbo frames);
- on the storage network, both ends' interface MTUs are the same.

Each server probes every other one every 30 seconds (and on demand) and
keeps its latest **report**. `netcheck.Status(ctx, src)` collects every
member's report (its own locally, the others' over the peer API,
`GET /cluster/v1/netcheck/report`) and judges them with the same rules
(`Evaluate`, pure). A report older than 2 minutes, or one that can't be
fetched, fails its member. `Result{OK, Reason, PerMember}`: `Reason` is the
first problem in plain words ("c2 can't reach nas on the storage network:
…").

**Signed probes.** The answer to a probe is a statement signed with the
peer's cluster key (domain `hardyos-netcheck/1\n`, distinct from every
other signed statement): the nonce the prober sent, both node ids, the
address the probe came from and arrived at, the receiving interface's MTU
and the SHA-256 of the padding. The prober checks it with the key in the
replicated state. No new port: the probe is a peer API path on 44500.

**Where it blocks.** `ha.Service.Candidates` (the Move dialog) shows live
moves as unavailable with the check's reason; the move handler and the
mover's `live` refuse (`ErrNotLive`), so a drain falls back to an offline
move. `PUT /cluster/workloads/{kind}/{id}/ha` refuses turning HA *on*
(409 `network`); changing or turning off an existing policy is allowed.
The "Make highly available" builder calls `netcheck.Status` too.

**Where it shows.** `GET /api/v1/cluster/netcheck` (administrators;
`?fresh=1` asks every member to probe now, at most every 10 s). Cluster ›
Overview: a "Local network" card with one row per server and a cell per
peer and path (LAN, storage) with RTT, MTU, same subnet or routed and the
reason. A notification (`cluster.netcheck`, link `cluster`) when this
server's own result changes (two checks in a row agree first, so a
restart or one lost probe doesn't notify).

**Not changed:** the HA coordinator's LAN-isolation input (`LANOK`) stays
as it is (a server whose own LAN alone fails); this check is about
topology, not liveness.

## 2. App windows from any server

Today a window for an app on another member opens only through
`POST /nodes/{node}/apps/{id}/open`, and the desktop's App Store and
AppFrame always call this server's `/apps/{id}/open`, so an app window
opened for another server (switcher), or for a cluster app that runs
elsewhere, opens the wrong server or nothing. Per-app hostnames answer only
for this server's own apps.

**Routing** (decision 493). Where an app runs: the cluster's placement for
`app:<id>` (cluster apps; its owner, whatever server was named), else the
server named, else this server. `POST /apps/{id}/open` and
`POST /nodes/{node}/apps/{id}/open` both go there: this server's own window
proxy, or a remote window on the entry server relayed to the owner over the
cluster relay (ALPN `hardyos-relay/1` on 44500). The desktop passes the
window's server (`args.node`) when it opens an app.

**Checks, unchanged in kind:** the owner checks the app's access list on
the window check and on every relayed request (and now every 15 s on a
relayed WebSocket, closing it when access ends); the entry re-applies its
two-factor gate (decision 475) on every window session check and closes
tracked WebSockets; local non-admin accounts don't cross servers; the
relayed-admin allowlist is the API's (windows aren't API paths, so
administrators of other servers open apps as the person they are there).
Relayed window requests skip host routing on the owner (decision 474).

**Per-app hostnames in a cluster** (decision 494). `<app>.<base>` on any
member serves the app wherever it runs: this server's own app first; else
the cluster app's owner; else the one other member that has an app with
that id (from a directory of app windows each member answers,
`GET /cluster/v1/windows`, refreshed every 30 s). Two other members with
the same app and none here: refused with a page naming them (open it from
the desktop). The host-session bounce is the entry's (its desktop host,
its session, its two-factor gate); the access list is the owner's
(`windowcheck` before the code, then every request). Host sessions for a
relayed app are marked remote and are good only while the app still routes
to another member. Names at home stay each server's own (root publishes
only its own apps' names, decision 459); a cluster app's name can point at
any member, which relays. Webmail is never routed elsewhere. Both HTTP and
WebSockets.

The owner's window check answers the app's web path in a header on its
204, so an entry one release older keeps working.

**Fixes found on the way:** the owner rewrites the app's own redirects
(`Location` at 127.0.0.1:<port>) to the window's host; the entry no longer
treats every port-less absolute redirect as the app's own. The window check
answers the app's web path so remote windows open where local ones do.

## Tests

Go unit tests with fakes (`netcheck` over `clustertest.Net`: a cut link,
NAT, slow RTT, MTU mismatch, a missing report, signatures; app windows
between two in-process members: placement routing, hostnames relayed,
access list, WebSockets). The "Cluster (namespaces)" CI job gains
`TestNetcheckNamespaces` (three members in network namespaces with a LAN
bridge and a storage bridge: all good, then the storage network cut for one
member, then jumbo frames on the servers behind a 1500 switch) and
`TestAppWindowAcrossMembers` (a window on member A for an app on member B,
HTTP and WebSocket, over the kernel's TCP in a namespace of its own).
