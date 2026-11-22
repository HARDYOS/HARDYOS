# NetBird standby server (phase 9, build contract)

Branch `phase9/netbird-standby`, decisions 420-429, migration
`0130_netbird_standby.sql`, ports 44620-44622 (`internal/ports`).

Cade's choice (2026-11-21): HardyOS keeps a synced copy of the NetBird
management server that runs on the VPS (`vpn.hardynetworks.net`). Failover is
**manual**: one click, **Take over**, typed confirmation. NetBird has no
multi-master, so there is never more than one server meant to be live, and
nothing switches by itself.

## What the VPS runs (checked 2026-11-21)

NetBird's current self-hosted layout is the **combined server**
(`netbirdio/netbird-server`: management, signal, relay and STUN in one
container, embedded IdP), `netbirdio/dashboard` and Traefik
(`traefik:v3.7.x`, Let's Encrypt by TLS-ALPN, `/letsencrypt/acme.json`).
State: `/var/lib/netbird` (`store.db`, `idp.db`, `events.db`, SQLite by
default), `config.yaml` (with `store.encryptionKey`, `authSecret`,
`auth.sessionCookieEncryptionKey`), `dashboard.env`. The standby supports
exactly this layout with the SQLite store. PostgreSQL stores and the old
split layout (`management.json`, coturn) are refused by the VPS script with
a clear message (NetBird's own migration guide moves an old setup to the
combined one).

## Pieces

1. **The app** `apps/catalog/netbird-standby`: netbird-server 0.83.1,
   dashboard v2.97.0, traefik v3.7.18, all by digest. Installed from Control
   Panel › NetBird Standby (prepare + pull, never `up`), so it is **stopped**
   until a take-over. Host ports 44620 (HTTP), 44621 (HTTPS), 44622/udp
   (STUN) are registered in `internal/ports` as owned by this app id only
   (no other app gets them; this app gets only them). Traefik uses a file
   provider (no Docker socket): root writes its routes for the NetBird
   hostname when it stages a take-over.
2. **Sync** (root, `internal/nbstandby`): hardyd-priv pulls a snapshot over
   SSH (`golang.org/x/crypto/ssh`, already in go.mod) with an ed25519 key it
   generated itself (private half sealed, never leaves root) and the VPS's
   host key pinned (pasted by the administrator). On the VPS a script
   HardyOS generates creates user `hardyos-standby` whose only key has
   `restrict,command="…",from="…"`: the forced command accepts exactly the
   verbs `status`, `snapshot` and (only when installed with
   `--allow-handback`) `fence`, `unfence` and `restore`, each run through
   sudo with that exact argument; a hand-back also needs a one-shot arm made
   on the VPS by a person. `snapshot` writes a tar: `manifest.json`, `config/config.yaml`,
   `config/dashboard.env`, `config/server.env` (only the three NetBird
   secret variables if they're set in the container's environment),
   `data/{store,idp,events}.db` (`sqlite3 .backup`, consistent while it
   runs) and `tls/acme.json`. Root checks every entry (names from that list
   only, regular files, size caps, SHA-256 against the manifest, SQLite
   header, hostname = the configured one) while it seals the stream
   (chunked AES-256-GCM, key `RootKeyFor(keys, "netbird-standby")`) into
   `/var/lib/hardyos/keys/netbird-standby/` (root-only, not in settings
   backups, survives boot environments). Newest 3 kept. hardyd only sees
   time, size, hash, version, peer count, certificate expiry.
3. **Schedule and health** (hardyd, `internal/nbstandby` service + api):
   every 15 minutes by default (5-1440) as job `netbird.standby.sync`;
   history in `nbstandby_syncs`; a failed sync is a warning, no success for
   max(3 intervals, interval + 1 h) is critical (once until it recovers),
   recovery is info. A VPS running a different NetBird version than the
   standby image is shown, and a newer one blocks take-over unless
   acknowledged.
4. **DNS** (root, `priv/dns_ops.go`): `dns.record.set` is registered now.
   The NetBird hostname is usually **not** under the hostnames base
   (`vpn.hardynetworks.net` vs base `home.hardynetworks.net`). Narrowest
   extension: one **standby name**, adopted by `dns.standby.adopt`: it must
   be inside the token's zone (not the apex, no `_`, no wildcard), the
   administrator sees the records that hold it (`dns.standby.preview`) and
   types the name; root records exactly those A/AAAA record ids with their
   original content, TTL and proxied flag (a CNAME or other type there is
   refused). From then `dns.record.set` may set that one name too (A/AAAA
   only, public addresses only) and treats the adopted ids as its own;
   `dns.standby.restore` puts the originals back and deletes records root
   added at that name. Nothing else outside the base becomes reachable.
5. **Take over** (job `netbird.standby.takeover`, typed hostname): stop
   syncing (root mode `takenover`), one last sync if the VPS still answers,
   stage the newest snapshot into the app's data folder (root, app stopped,
   catalog source checked), start the app, open the firewall and point
   HardyOS itself at the local standby (`netbird.standby.network`), set A
   (and AAAA if configured) to HardyOS's public address with TTL 60, then
   watch peers reconnect (NetBird API through the local standby). A failure
   before DNS changed undoes the local steps.
6. **HardyOS's own client**: while taken over, root adds
   `127.0.77.1 <hostname>` to `/etc/hosts` (a marked block) and an nftables
   output DNAT from `127.0.77.1:80/443/3478` to the standby's ports, so the
   NetBird client, hardyd's NetBird API calls and peer checks reach the
   local server without the internet or a router hairpin.
7. **Firewall**: table `inet hardyos_nbstandby` always present while the
   app is installed: closed (drop 44620-44622 from anything but loopback in
   prerouting, before Docker's DNAT) except while taken over. Router port
   forwards are documented (TCP 80→44620, 443→44621, UDP 3478→44622);
   HardyOS can't change the router.
8. **Hand back** (job `netbird.standby.handback`, typed hostname and a
   split-brain acknowledgement): VPS `status` must answer, its NetBird must
   be running and restore must be allowed; stop the standby, push its
   databases with `restore` (the VPS backs its own copy up first, stops
   netbird-server, replaces, starts), restore DNS, close the firewall and
   drop the local override, remove the staged state, resume syncing.
9. **UI**: Control Panel › NetBird Standby: setup (VPS address, user, host
   key, hostname, public address, interval), the VPS script, the DNS name
   adoption, sync status/history, port forwards, Take over / Hand back with
   typed confirmations.

## Tests

Go: snapshot validation (bad names, links, sizes, hash mismatch, hostname),
sealing round trip and tamper, VPS script (forced command verbs, `bash -n`,
shellcheck when present), an in-process SSH server (fake VPS: forced verbs,
pinned host key, wrong key refused), root ops with a fake remote and a fake
apps engine, nft/hosts rendering, DNS adoption and `dns.record.set` scope
with the PR #37 Cloudflare fake, the hardyd service with a fake priv (sync
schedule, stale alert, take-over/hand-back order and rollback), API authz and
confirmations. Web: rules and the page with vitest. No real network, disks
or containers.

## Security review changes (PR #44)

- H1: the public address is root's (`netbird.standby.address`, name typed,
  never while taken over); the standby name moves only during a take-over,
  only to that address; adopting/forgetting needs the Cloudflare token
  pasted again and isn't possible while taken over; the hostname can't move
  off an adopted name; a new VPS address or host key drops the copies.
- H2: hand-back needs a one-shot arm by a person on the VPS, a generation
  id the VPS served, the standby's version not newer than the VPS's,
  SQLite checks as nobody on copies, the same accounts and no new
  owners/admins/tokens unless allowed, and rolls back by itself.
- M1-M6, L1-L10: version gate, sealed hand-back copy, fence/unfence,
  every-record DNS updates without deletes, exclusions and app guard,
  acme.json filtering and Traefik by compose project, restore only of what
  HardyOS set; root-made script and console fingerprint, staged-file
  cleanup, DNS retry with the standby kept stopped, VPS ≠ NetBird name,
  userland-proxy check, a pinned subnet dropped outside a take-over,
  upload cap and backup rotation, stricter public addresses.

## Not covered

NetBird's reverse proxy (published apps on the VPS) isn't part of the
standby: during a take-over, NetBird-only access works and public published
apps wait for the VPS. PostgreSQL stores, the old split layout and
automatic failover are out of scope.
