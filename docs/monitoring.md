# Monitoring and alerts

HardyOS watches its disks, pools, UPS, apps, VMs and services, keeps two
years of resource history, and tells people when something needs them: on
the desktop (the bell), in Discord, Slack or Microsoft Teams, and by email.

## Where alerts go (Control Panel › Notifications)

Every alert is an **event**: a kind (`disk.smart`, `pool.capacity`,
`ups.power`, `backup.failed` …), a severity (info, warning, critical), a
title, a body and a link into the desktop. Any package raises one with
`Notify(ctx, notify.Event{…})` (`internal/notify`); backups and replication
emit theirs the same way.

**Channels**

| Channel | Set up with | Notes |
| --- | --- | --- |
| Desktop | always there | The bell in the menu bar, for administrators. Unread count and read state per person; clicking an entry opens what it's about. |
| Discord | a channel webhook URL | Embed in the severity's color; `@everyone` in alert text never pings. |
| Slack | an incoming webhook URL | Header, text and a context line with a link. |
| Microsoft Teams | a Workflows webhook ("Post to a channel when a webhook request is received") | Adaptive Card; old Office 365 connector URLs work too. |
| Other webhook | any public https URL, with **Allow any https host** ticked | JSON: `kind, severity, title, body, link, url, time, server, source`. |
| Email (SMTP) | server, port, encryption, user, password, from, to | Presets: Gmail / Google Workspace (`smtp.gmail.com:587`, an **app password**), Amazon SES's SMTP interface (`email-smtp.<region>.amazonaws.com:587`, SES SMTP credentials), any other server, including the family mail server planned for phase 7. |
| Amazon SES | region, access key ID and secret, from, to | SES API v2 (`SendEmail`) over HTTPS, signed with SigV4. An IAM user allowed only `ses:SendEmail` is enough. |

Each channel has a **Test** button and shows its last delivery (sent, or the
service's error). Secrets (webhook URLs, passwords, the SES secret key) are
sealed with secretbox (purpose `notify`, bound to the channel's row) and
never returned by the API; the list only says which are set.

**Routing.** A table of alert categories (Disks, Pools, UPS, Backups,
Replication, Apps, VMs, Remote access, Domain, System, Everything else) by
channel: for each cell, Off, Everything, Warnings and up, or Critical only.
A category left on *Default* follows "Everything else". The desktop gets
everything; a new channel gets warnings and critical alerts of every kind.

**Noise control**

- *Conditions, not repeats.* The monitor raises a condition (a degraded
  pool, a hot disk) once, updates it quietly while it lasts, raises it again
  only if its severity changes, and sends one "resolved" notice when it
  clears. Thresholds have hysteresis (a pool warning at 80% clears below
  78%; temperatures 3 °C below the limit) and sensor temperatures must hold
  for two checks.
- *Duplicates.* The same alert (kind, severity, title, text) within 30
  minutes is dropped everywhere.
- *Rate limit.* Each channel gets at most 6 alerts an hour about one thing
  (kind + link), critical ones 12; the next one sent says how many were
  held back. Flapping conditions are cut down by this and by the hysteresis.
- *Quiet hours* (optional, e.g. 22:00-07:00): chat and email alerts below
  the chosen severity (critical by default) are held and sent as one summary
  when quiet hours end. The desktop shows everything as it happens.
- Failed deliveries are retried (after 30 s and 2 min) when the failure is
  temporary (network, 429, 5xx, SMTP 4xx). The last 500 deliveries are in
  the delivery log.

**Network safety.** Webhooks must be https. Discord, Slack and Teams
channels accept only their services' hosts. A generic webhook needs the
explicit opt-in. Every connection (webhooks and SES) checks the address it
actually dials, after DNS: loopback, private, link-local, CGNAT (NetBird),
multicast and documentation ranges are refused; redirects aren't followed;
no proxy from the environment is used. Errors never include the URL (it
holds the token). Email is the exception: an SMTP server may be on this
machine or the LAN (the family mail server). STARTTLS is required when
chosen (never a silent fallback); without encryption a password is only
sent to this machine.

Links in messages point to the desktop's address (**Server address for
links**, e.g. `https://nas.example.com`) with `#open=<link>`; the desktop
opens the right app when signed in.

## What's watched

| Check | How often | Alerts |
| --- | --- | --- |
| Pool health | every minute | DEGRADED: warning; FAULTED, UNAVAIL, SUSPENDED: critical; back to ONLINE: resolved |
| Pool device errors | every minute | read/write/checksum errors on any device: warning, listing each device (clears after `zpool clear`) |
| Damaged files | every minute | `errors:` other than "No known data errors": critical |
| Scrub results | every minute | a finished scrub with errors: critical |
| Pool capacity | every minute | 80%: warning, 90%: critical (editable) |
| SMART health | every 10 minutes, without waking sleeping disks | failing (self-assessment failed, attribute below threshold, NVMe critical warning, spare below threshold, last self-test failed): critical; wear (reallocated, pending, uncorrectable, reported-uncorrect, grown defects, NVMe media errors, 90%+ endurance): warning; counts rising since the last reading: warning |
| Disk temperature | every 10 minutes | hard disks 50/55 °C, SSD/NVMe 70/80 °C (editable) |
| Self-tests | while one runs, every 5 minutes | a failed test: critical; a test started by hand: its result |
| Sensors (hwmon) | every minute | above the chip's own max/crit (or 85/95 °C) for two checks |
| UPS | every 10 seconds | on battery: warning; low battery (shutting down) and forced shutdown: critical; power back: info; replace battery, overload: warning; no contact for 30 s: warning |
| Apps | every 30 seconds | stopped or partly stopped without an administrator's stop, update or removal in the last 10 minutes: warning; restarting in two checks in a row: warning; failing health check: warning; Docker not running: critical |
| VMs | every 30 seconds | crashed: critical; running → stopped without a stop, restart or delete job: warning |
| hardyd-priv | every minute | restarted (not at boot): warning; not answering twice: critical |
| NetBird | every minute | joined but disconnected for 3 minutes: warning |
| DC replication | every 10 minutes | `samba-tool drs showrepl` inbound links with failures: warning |
| Publishing | every 5 minutes | a published service whose last sync failed (including certificates NetBird's proxy couldn't get): warning |

What's wrong right now is listed in Resource Monitor › Alerts, in Storage
Manager › Health (pools and disks) and on each pool's page.

## Disk self-tests and scrubs

SMART is read with `smartctl --json` for SATA, SAS and NVMe disks, always
through hardyd-priv's `hw.smart` with the disk's stable path; the periodic
read passes `-n standby` so a sleeping disk stays asleep. Opening a disk's
details in Storage Manager reads it live.

Defaults (Storage Manager › Health): a **short** self-test every 7 days, a
**long** one every 30 days, both only between 01:00 and 06:00 server time.
When a disk is first seen its first tests are spread over the interval, so
disks take turns (four disks: a long test about every week). At most one
test starts per minute, one long test runs at a time, and none starts on a
pool that is scrubbing. Disks can be left out. **Run short test** / **Run
long test** on a disk's details start one now (an audited job).

Pool scrubs keep their per-pool interval (Storage Manager › Schedules,
monthly by default). With **Scrub pools in the same hours** (on), a due
scrub waits for the window, runs one pool at a time and not while a disk of
the pool runs a long test.

## UPS (Control Panel › UPS)

HardyOS uses NUT. Three setups:

- **Connected to this server.** **Find USB UPS** (nut-scanner, or known UPS
  makers in sysfs) fills in the driver and the USB IDs; `usbhid-ups` fits
  most UPSes. **Shut down at** a battery charge and/or a runtime left:
  HardyOS sets the driver's `ignorelb` with `override.battery.charge.low` /
  `override.battery.runtime.low`, so the UPS reports "low battery" at those
  levels and NUT's `upsmon` shuts the server down (`/sbin/shutdown -h +0`).
  The shutdown never depends on hardyd running.
- **Share this UPS with other servers** makes this server a NUT server
  (`MODE=netserver`, upsd listening on port 3493) with an account for the
  other servers (`upsmon secondary`).
- **Connected to another server** (netclient): upsmon watches the UPS on
  the other server and shuts this one down when told, before that server
  shuts down itself.

hardyd-priv writes `/etc/nut/{nut.conf,ups.conf,upsd.conf,upsd.users,upsmon.conf}`
(root:nut, 0640) and starts only what the setup needs; the local upsmon
account's password is made by hardyd-priv on every apply and never leaves
root. hardyd reads the UPS over NUT's network protocol (no sign-in needed to
read) for the page, alerts and history. No UPS yet? The **dummy-ups**
driver replays a file in `/etc/nut` (`ups.status: OB LB` …) to try it.

## Resource history (Resource Monitor)

hardyd samples every 10 seconds and keeps history in
`/var/lib/hardyos/metrics.db`, separate from `hardyd.db` so settings
backups stay small:

| Tier | Resolution | Kept |
| --- | --- | --- |
| 0 | 10 seconds | 1 day |
| 1 | 1 minute | 7 days |
| 2 | 15 minutes | 90 days |
| 3 | 1 hour | 2 years |

Each tier stores chunks of float32 values per series (one row per hour of
10-second values, 1.4 KB), and each coarser tier is the average of the one
below, computed once its bucket is complete. A day of 100 series at 10 s is
2,400 rows (3.5 MB); two years of all tiers for 100 series is about 18 MB.
Queries pick the finest tier still covering the range and average down to
the points asked for.

Series: `cpu.percent`, `mem.used`, `mem.arc`, `mem.total`, `net.rx`,
`net.tx`, `load.1`; `disk.read:<disk>`, `disk.write:<disk>`,
`disk.busy:<disk>` (from /proc/diskstats); `temp:<sensor>` (hwmon, whatever
the hardware has) and `disk.temp:<disk>` (SMART); `pool.used:<pool>`,
`pool.size:<pool>`, `pool.pct:<pool>`; `app.cpu|mem|read|write:<app>`
(from each app's cgroup slice, `hardyos.slice/hardyos-app.slice/hardyos-app-<id>.slice`);
`vm.cpu:<vm>`, `vm.mem:<vm>` (libvirt domstats); `ups.charge|runtime|load|input:<ups>`.

**Adding a source** (a solar inverter, a home battery): implement
`monitor.Source` (`Name`, `Interval`, `Collect` returning points with a
series name, label and unit such as `watts` or `percent`) and call
`Service.AddSource`. Its series appear in the history API at once; the
Resource Monitor shows a card for any series prefix it's given.

## API

| Endpoint | Who | What |
| --- | --- | --- |
| `GET /notifications`, `GET /notifications/unread`, `POST /notifications/{id}/read`, `POST /notifications/read-all` | signed in | The bell |
| `GET/POST /alerts/channels`, `PATCH/DELETE /alerts/channels/{id}`, `POST /alerts/channels/{id}/test` | admin | Channels (secrets write-only) |
| `GET/PUT /alerts/routes`, `GET /alerts/categories` | admin | Routing |
| `GET/PUT /alerts/settings`, `GET /alerts/deliveries` | admin | Quiet hours, limits, delivery log |
| `GET /monitor/series`, `GET /monitor/history?series=cpu.percent,app.cpu:*&range=24h&points=300` | signed in | History |
| `GET /monitor/conditions` | admin | What's wrong now |
| `GET/PUT /monitor/settings` | admin | Thresholds, self-test and scrub window |
| `GET /monitor/disks`, `POST /monitor/disks/{name}/test` | admin | Disk health, self-test now (job `monitor.smart.test`) |
| `GET/PUT /ups`, `GET /ups/detect` | admin | UPS setup (job `ups.apply`), detection |

Changing channels, routing, settings, UPS setup and starting tests are
audited (never with secret values).

## Root operations

| Operation | Arguments | Does |
| --- | --- | --- |
| `hw.smart` | device (a known disk's stable path), noWake | `smartctl --json=c -a [-n standby,0]` |
| `hw.smart.test` | device, test (short, long, abort) | `smartctl -t short|long` / `-X` |
| `ups.detect` | none | `nut-scanner -U -q`, else sysfs |
| `ups.apply` | setup and passwords (validated) | writes /etc/nut, `upsdrvsvcctl resync`, enables and restarts the NUT units it needs |
| `domain.replication` | none | `samba-tool drs showrepl --json` in the DC's namespace |
| `system.ping` | none | now also returns when hardyd-priv started |

The monitor's polling operations are logged at debug level.

## Testing

- `internal/hw`: smartctl JSON samples (SATA, failing SATA, NVMe, failing
  NVMe, SAS, standby) in `testdata/`.
- `internal/monitor`: `zpool status` samples (degraded with errors, data
  errors and a scrub with errors; scrubbing; healthy), condition
  raise/escalate/clear, hysteresis, SMART checks, the self-test schedule
  and its stagger, apps, VMs, services, sensors, the history store (tiers,
  gaps, downsampling, pruning, size).
- `internal/notify`: SigV4 against AWS's published vectors, webhooks via
  httptest (payloads, the address guard, no redirects, no URL in errors),
  SMTP via a local server (STARTTLS, implicit TLS, PLAIN and LOGIN, refusals),
  SES via httptest, routing, dedup, rate limit, quiet hours, retries,
  sealed secrets.
- `internal/ups`: rendered configuration, validation, detection, apply, the
  NUT protocol against a fake upsd, and `TestDummyUPS`, which runs NUT's own
  `dummy-ups` driver and `upsd` (set `HARDYOS_NUT_TEST=1`; needs nut-server).
