# NetBird standby server

Your NetBird network has one management server, on the VPS
(`vpn.hardynetworks.net` for Cade). If the VPS goes down, peers keep their
existing tunnels for a while but nothing new can connect, sign in or change.
HardyOS can keep a **stopped copy** of that server and **take over** with one
click: it starts the copy, points the NetBird name at your home connection
in Cloudflare, and peers reconnect to it. When the VPS is healthy again you
**hand back**.

There is no automatic failover. NetBird has no multi-master: two live
management servers with diverging state would confuse peers, so a person
decides when HardyOS takes over and when it gives NetBird back.

Control Panel › **NetBird Standby**, administrators only.

## What you need

- The VPS running NetBird's **current self-hosted layout**: the combined
  `netbirdio/netbird-server` container (management, signal, relay, STUN),
  the dashboard and Traefik, with the **SQLite** store (the quickstart's
  default). The VPS script refuses an older split layout (`management.json`,
  separate signal and coturn; migrate with NetBird's guide first) and a
  PostgreSQL store.
- A **Cloudflare token** saved in Control Panel › Hostnames, for the zone
  the NetBird name is in.
- **Router port forwards** to this server (HardyOS can't change your router):

  | Protocol | Public port | To this server | For |
  | --- | --- | --- | --- |
  | TCP | 80 | 44620 | HTTP (redirects, Let's Encrypt) |
  | TCP | 443 | 44621 | management, signal, relay, dashboard |
  | UDP | 3478 | 44622 | STUN |

  The forwards can stay in place: HardyOS drops traffic to those ports (and
  to the standby's containers) unless it has taken over.
- This server's **public IPv4 address** (and IPv6 if the NetBird name has an
  AAAA record). DNS can point the NetBird name only at this address, so
  changing it needs the name typed, and it can't change during a take-over.
  With a changing home address, update it here before a take-over.
- Docker's userland proxy left on (Debian's default): this server reaches
  its own standby through it during a take-over.

## Setting it up

1. **The VPS and this server.** Enter the NetBird server's name, the VPS's
   SSH address (its public name, or its NetBird address), the public
   address, how often to copy (default every 15 minutes) and the addresses
   HardyOS connects from (its NetBird address by default; the VPS accepts
   the key only from them). Save: HardyOS makes its own SSH key; only the
   system's root helper ever holds its private half.
2. **Set up the VPS.** Show or download the script and run it on the VPS as
   root:

   ```
   bash hardyos-standby.sh                   # HardyOS may only read
   bash hardyos-standby.sh --allow-handback  # and may fence and hand back
   ```

   It adds the user `hardyos-standby` with exactly one key, HardyOS's,
   restricted (`restrict`, `from=`) to a **forced command** that knows five
   verbs: `status`, `snapshot` and, only with `--allow-handback`, `fence`,
   `unfence` and `restore`. Each runs through sudo with exactly that word;
   nothing else can run on the VPS with HardyOS's key. The script prints the
   fingerprint of the key it installed: compare it with
   `sudo hardyctl netbird-standby fingerprint` on this server's console.
   Paste the host key it prints back into step 1 (HardyOS refuses any other
   host key). **Check the VPS** confirms the connection.
3. **Install the standby.** NetBird's own images (pinned by digest), the
   same as on the VPS. It is installed **stopped** and stays stopped.
4. **NetBird's name in Cloudflare.** Usually the NetBird name isn't under
   the Hostnames base (`vpn.hardynetworks.net` vs `home.hardynetworks.net`).
   **Look up** the name, check its records (they must be A/AAAA records
   pointing at the VPS), type the name and paste the Cloudflare token again
   to let HardyOS manage exactly those records. HardyOS remembers what they
   hold, to put them back on hand-back. It can't touch any other name in the
   zone, and it changes this one only during a take-over, only to this
   server's public address.

From then on HardyOS copies the VPS on schedule: the management database,
the embedded sign-in provider's database, activity events, `config.yaml`
(with its encryption key, relay secret and setup keys inside the database)
and Traefik's certificate for the NetBird name (never the Let's Encrypt
account key). The copies are encrypted at rest with a key
only the root helper has, kept in its own folder (not in settings
backups), the newest 3. The page shows the newest copy's age, size, the
VPS's NetBird version and peer count, and the history. A failed copy raises
a warning; no good copy for 3 intervals (at least interval + 1 hour) raises a
critical alert.

## Taking over

**Take over** (type the NetBird name):

1. HardyOS tries one last copy and otherwise uses the newest saved one. If
   the VPS answers, the take-over stops unless you ticked that you mean it.
2. HardyOS **fences** the VPS: it stops its NetBird server (needs
   `--allow-handback`). That must work when the VPS answers; when it's down
   it's tried anyway.
3. The copy goes into the stopped standby, which starts.
4. Its ports open, and this server itself is pointed at the local standby
   (the name resolves to a local address and is forwarded to the standby),
   so HardyOS's own NetBird client keeps working without the VPS or the
   router.
5. The name's A (and AAAA) record is set to this server's public address
   with a 60-second TTL.
6. HardyOS watches peers reconnect (with Remote Access's NetBird token) and
   shows how many are connected.

Peers hold a long-lived gRPC connection to the management server: a lower
TTL alone doesn't move a connected peer, it reconnects (and resolves the
name again) when that connection drops. Fencing the VPS drops them at once;
if the VPS is unreachable they reconnect when their connection times out.

If a step fails before DNS changed, everything is undone (and the VPS
unfenced). The certificate
comes from the VPS's Traefik store; without one, Traefik gets a new one
once the name points here (TCP 443 must be forwarded).

If the VPS runs a newer NetBird than the standby, the page warns, and a
take-over needs an extra tick: the newer database may not open with the
older server. Update HardyOS first when you can.

While taken over:

- Copying stops; settings, the public address, the DNS name, forgetting the
  standby or the Cloudflare token are refused, and the standby's app can't
  be updated, reconfigured, rolled back, restored or removed.
- If the VPS couldn't be fenced and comes back on its own, peers still
  connected to it stay there. **Split brain**: changes made on the VPS in
  that time are lost on hand-back.
- The standby's data isn't in cloud backups, replicas or app snapshots.
- Published apps through NetBird's reverse proxy are not part of the
  standby (that proxy runs on the VPS); access over NetBird itself works.

## Handing back

When the VPS is healthy, first **arm** the hand-back on the VPS, as root:

```
hardyos-netbird-standby-root arm-restore 2h
```

(one hand-back within that time; add `--allow-new-admins` if the take-over
added owners, admins or access tokens on purpose). Then **Hand back** (type
the name, tick that the standby's state replaces the VPS's):

1. HardyOS asks the VPS for its status; it must answer, be armed and run at
   least the standby's NetBird version.
2. The standby stops.
3. Its databases go to the VPS's `restore` verb, which checks them (types,
   checksums, that they descend from a snapshot the VPS served, SQLite
   integrity, run as nobody on copies), refuses other NetBird accounts and
   (unless armed with `--allow-new-admins`) new owners, admins or access
   tokens, prints what's new, keeps a backup of its own databases in
   `/var/lib/hardyos-standby/root/before-handback-<time>` (newest 5), puts
   them in place and starts netbird-server. If the server doesn't stay up,
   it puts its own databases back by itself. HardyOS keeps an encrypted
   copy of what it sent until the next good copy.
4. The name's records go back to exactly what they were (records someone
   changed by hand meanwhile are left alone).
5. The ports close, this server's local override goes, the staged state is
   removed from the app, and copying resumes.

If the VPS refuses, HardyOS stops it again and starts the standby (the page
says plainly if two servers may be running). If DNS can't be put back, the
standby stays stopped and **Hand back** again only finishes.

**Don't send the standby's state** goes back without step 3: the VPS's
server is started again with its own state, and anything changed during
the take-over is lost.

## Security

- HardyOS's SSH key never leaves the root helper; the VPS host key is pinned.
- The VPS accepts the key only for the forced command, from the configured
  addresses, with no shell, port forwarding or terminal; root on the VPS is
  reached only for the exact verbs. A hand-back also needs a person on the
  VPS to arm it, each time.
- Snapshots are checked entry by entry (names from a fixed list, regular
  files, size limits, SQLite headers, checksums, the expected hostname)
  before anything is kept or staged, and encrypted at rest.
- DNS: only the one adopted name (adopting needs the token pasted again),
  only A/AAAA records, only during a take-over, only this server's public
  address kept by the root helper; every other record in Cloudflare is out
  of reach.
- Every change is an administrator's job and in the audit log
  (`netbird.standby.*`).

## Troubleshooting

- **"host key isn't the one saved"**: the VPS was reinstalled, or something
  is in between. Get its key on the VPS (`cat /etc/ssh/ssh_host_ed25519_key.pub`)
  and paste it again.
- **"refused"** from the VPS: run the script again (after a new key, or to
  add `--allow-handback`).
- **"isn't armed"** on hand-back: run `arm-restore` on the VPS (above).
- **Hand back refused for new admins/tokens**: check the summary in the
  error (also in the VPS's log, `journalctl -t hardyos-standby`), then arm
  with `--allow-new-admins`.
- **Peers don't reconnect**: check the router forwards from outside
  (`nc -vz <public ip> 443`), that the name resolves to this server
  (`dig +short vpn.example.net`), and the app's logs in the App Store.
- **The VPS's own logs**: `journalctl -t sudo | grep hardyos` shows each
  verb HardyOS ran.
