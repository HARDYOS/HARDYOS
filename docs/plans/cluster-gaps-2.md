# Cluster gaps 2 (Phase 10): shared folders that move with an HA app, an abandoned app starts again, kept copies of every member, several streaming VMs

Four gaps PR #47 left (docs/plans/make-ha.md). Decisions 500-509. No
migration.

## 1. Apps with shared folders become highly available

**The problem.** An app's shared folders are datasets on its server's own
pool (`<pool>/shares/<id>`), bind-mounted into its containers. A cluster
app runs on any compute server, so a folder on one compute server's pool
can't follow it. The cluster already has *cluster shares*: a shared folder
of the storage server put "in the cluster" (`storage.share`), NFS-exported
to every compute server and mounted at `/mnt/hc/<pool>/shares/<id>`, which
cluster apps resolve by id (`sanclient.ShareResolver`).

**Options considered.** (a) Refuse per folder and offer a separate "move
this shared folder to cluster storage" job: the local app would then use a
folder that is no longer this server's, so local apps would need to bind
cluster shares too (a second resolver, the app settings choosing between
the two, grants on the storage server), and every other local user of the
folder breaks in between. (b) Move the folders **with the app's
conversion**, as part of it: the app is stopped and held anyway, its
folders' users are known, and the conversion's machinery (snapshots,
resumable single-dataset streams, adopt, park, grace period, undo) already
gives every data-safety rule of decisions 480-489. **Chosen: (b)** — it is
the smaller surface and the one where each step already has its rule.

**Flow** (decision 500), inside `cluster.ha.convert` for an app:

- *Checks* (decision 502, refused with the folder named): this server's
  own shared folder, mounted; no other app of this server has it (a folder
  moves with one app only); not the VMs' ISO library; in none of this
  server's backup or replication tasks (take it out first; back it up from
  the storage server afterwards: silently losing backup coverage isn't
  allowed); the storage server has no shared folder with its id or name;
  when its permissions name domain users or groups, both servers share
  files as members of the same domain (same realm: winbind's `rid` ID map
  then gives them the same IDs, so the POSIX ACLs on the files mean the
  same); at most 512 snapshots; the storage pool has room (+10 %). Notes,
  not refusals: web links into it stop working; it is shared on the
  network from the storage server afterwards.
- *Copy while it runs*: each folder snapshotted
  (`hardyos-ha-<conv>s<i>-pre<N>`) and sent like the app's folder into its
  own incoming copy on the storage server (`<pool>/hardyos-ha-incoming/<conv>s<i>/share-<id>`,
  marked `share:<id>`; never the app's), resumable.
- *Stop*: the app is stopped and held (decision 504 below), then each
  folder is **held** (`shares.ha.hold`): file sharing lets go of it first
  (SMB closes it and its open files, NFS stops exporting it, SFTP lets go:
  the share hooks of a delete), then read-only, `canmount=noauto`, marked
  `org.hardyos:ha-hold=<conv>s<i>` and unmounted. A folder still in use
  can't be unmounted: no hold, the app runs again, the conversion fails
  with that reason. A held folder lists as not mounted, so no file service,
  File Manager, backup or app uses it, and its settings can't be changed
  or it deleted.
- *Final*: each folder's final snapshot and increment.
- *Adopt*: the storage server adopts each folder (`ha/adopt`, kind
  `share`) with this server's settings for it (name, description, quota,
  recycle bin, guest, access rules, app grants, services), which travel as
  values and are checked like a person's input before root writes them as
  the dataset's properties (a plain `zfs send` carries none); the dataset
  gets shares.Manager's own properties (`acltype=posixacl`, `xattr=sa`,
  `aclinherit=passthrough`, no devices or setuid; the files' ACLs travel
  in the stream). It is adopted **held** (read-only, unmounted, marked with
  its conversion), so the storage server doesn't share it yet: never two
  copies anyone can write.
- *Park*: each folder first (only while its own conversion holds it;
  refused when written after its final snapshot), then the app's folder;
  any failure puts the parked folders back (still held) and the
  conversion goes back before the park as for the app (app started again
  if it ran, folders let go of, the adopted copies there put aside for an
  hour: never shared, this server's copy is there).
- *Register*: only once every folder's copy here is recorded as parked,
  the storage server lets go of its copy (`ha/share/release`, which root
  does only for the hold that conversion took) and puts it in the cluster
  (`storage.share`); this server waits until it mounts them; then
  `workload.add` and attach as before, and the app's compose file is
  rewritten for each folder's new place (`apps.cluster.adopt`, only that
  folder and paths below it, every folder the app has named) and checked
  again.
- *Start*, *grace*: each parked folder gets the same grace period as the
  app's copy (24 h once the app ran from cluster storage).

**Undo** (decision 503, after the park): the cluster workload is removed
as before; then the storage server's copies of the folders go out of the
cluster and aside **before** this server's come back (never two writable
copies; putting aside deletes nothing): one the storage server shared
(it may have been written there by people) is kept until an administrator
deletes it, and the undo alerts; then this server's folders are put back
(their hold ends, file sharing takes them up again) and checked, then the
app's folder as before. **Abandon** (before the park): adopted folders go
aside for an hour, what was arriving is dropped, holds end, the
conversion's snapshots are removed.

**Make local again** is refused for an app that uses shared folders (asked
of the server running it, peer `ha/app-shares`): they are the storage
server's now, and a server's own app can't use them. Taking them away from
the app first is the way back.

**Root's rules (hacopy kind `share`):** ids are shared folder ids; the
dataset is `<pool>/shares/<id>` on either side, marked `org.hardyos:share=1`,
never cluster storage (`org.hardyos:role=cluster`), nothing below it. A
shared folder is adopted only on the storage server's side, with checked
settings, never over a shared folder whose id or name that server has
(`ShareTaken`). This server's copy is parked only while its conversion
holds it; the storage server's only with a conversion's mark expected and
while no compute server has it exported (`ShareBusy`, the storage
server's NFS exports), and the storage peer API refuses parking one still
in `ClusterShares`, putting one back, or letting go of anything but a
shared folder; every such request needs an administrator's signed
request. Parked folders list as kind `share` among the kept copies.

## 2. An abandoned app starts again (decision 504)

The app's hold (`apps.ha.hold`) now records whether the app ran before the
conversion stopped it (`org.hardyos:ha-hold-running=on`, from the
conversion's record and from root's own look at its containers), on the
dataset, so it outlives hardyd and its record. Ending the hold reports
what it found; **Abandon** starts the app again when the hold it ended
recorded that it ran (it alerts when the start fails). Undo and a
conversion that gives up before the park use the same record (also when
the copy is put back: `ha.unpark` reports the hold it ends). Nothing is
started when there was no hold (the app was let go of already).

## 3. Kept copies of every member (decision 505)

`GET /cluster/kept` merges this server's copies, the storage server's
(through its storage API, as before) and every other non-witness member's
(peer `GET /cluster/v1/ha/kept`, each answering its own; 5 s each, a
silent member is left out), as the failover history is merged. A copy of
another member carries `deleteOn`: the desktop deletes it through that
member's own API (`/api/v1/nodes/<member>/cluster/kept/delete`), so the
holder's own guards apply (its acceptance of other servers'
administrators, typed name, `lastCopy`, root's refusal of a copy without
an expiry). This server's job still deletes only its own and the storage
server's.

## 4. Several published streaming VMs (decision 506)

Moonlight learns every port but the first from Sunshine itself (its
`HttpsPort`, the RTSP URL, the stream ports in the RTSP setup), so a host
port can't be translated to another number in the VM: each published VM's
Sunshine must use its own port numbers. Port sets are registered in
`internal/ports`: 8 slots, 100 apart, slot 0 being Sunshine's standard set
(base 47989); a set is Sunshine's `port` setting and its offsets (HTTPS -5,
web UI +1, video +9, control +10, audio +11, mic +13, RTSP +21). Every
slot's ports are `Reserved` (no app gets one as a host port), and a test
checks that no slot overlaps another, a fixed port, the app proxy or the
migration range.

- Root gives a VM its slot when it is published: its own when no other
  published VM it knows has it, else the lowest free one; a VM set up
  before port sets (its firewall rule covers only 47990) gets slot 0 only.
  The new setup script's firewall rule keeps every slot's web UI port to
  the HardyOS server (`Streaming.AllSlots`).
- hardyd then moves Sunshine in the VM there: finds it (the slot's web
  port, else another slot's; the certificate pinned each time), writes its
  settings back with only `port` changed (Sunshine writes its file from
  what it is given; values with line breaks are refused), restarts it, and
  waits for it on the new web port. A VM that is off gets a warning
  (publish again once it runs).
- Root forwards every published, running VM's own set from its own chosen
  devices to its own address, in one table; never two forwards on one set,
  VM or address (two HA VMs with the same set on one server after a
  failover: neither, with the reason on their panels). 47990 and every
  slot's web UI port are never forwarded. Live moves stay refused while
  published (decision 470).
- The panel shows the address to add in Moonlight: the NetBird address,
  with `:<base>` when it isn't the standard set.

## Security review fixes (decisions 507-509)

- H1 (507): the storage server's copy is received read-only, unmounted and
  held (`zfs receive -o`); one `zfs set` after the rename sets the mark and
  the hold before any settings; root never sets `canmount=on` for a shared
  folder while adopting. An adopt asked again re-holds it unless the
  `org.hardyos:ha-released` mark (set by the storage server's release
  before the hold ends) names this conversion. The storage-side release
  refuses a folder this conversion doesn't hold, unless that mark says it
  released it already. Test: an adopt cut short between the settings and
  the hold, then asked again.
- M1 (508): aside parks with `Since` = the final snapshot and `Expect`;
  root reports the copy changed when this conversion no longer holds it or
  it was written after that snapshot, and refuses an expiry then; the
  conversion keeps it until deleted.
- M2: Undo checks that this server's copies are there first and changes
  nothing otherwise.
- M3: a failed put-back after a failed park stops the conversion at the
  park; Abandon refused while a folder is parked here; this server's parked
  copy and the storage server's kept copy are recorded apart.
- M4: adopt settings are always read fresh from the held folder.
- L1, L2: the folder checks run again before the hold; share paths are
  checked (`shares/<id>`).
- L3 (509): the running state is taken again every attempt; Abandon starts
  the app only when it isn't a cluster workload.
- L4: one lock around choosing and saving a port set; a set an app holds a
  host port of is never given to a VM nor forwarded (the VM panel says so).

## Tests

Go unit tests with fakes: root's share rules (ids, sides, park only held
or marked, adopt held with checked settings, nothing over an existing
folder), shares.HAHold (in use: no hold; changes refused; only its
conversion lets go), the conversion's share checks, the storage server's
copy let go of only after this server's is parked, aside rules, Abandon
starting an app the hold recorded as running (and not otherwise), the
hold record, kept copies merged from peers, the storage peer API's
refusals, port sets, slot choice, rules for several VMs, Sunshine's port
moved with every other setting kept. CI's Cluster (namespaces) job runs
`TestHAShareIntegration` (real ZFS: a held shared folder with ACLs sent,
adopted held with its settings, a late write refused, parked, put back,
the storage copy parked only with its mark); the Game streaming job loads
the rules for two VMs on two port sets and streams to both through
network namespaces (each device reaching only its own VM, no web UI
port).

## Not done

- Moving a shared folder back with "Make local again" (refused instead).
- A failover can bring two published HA VMs with one port set onto one
  server; they aren't forwarded until one is published again (no
  automatic re-slotting: it needs the guest running and its Sunshine
  moved).
