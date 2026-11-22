# Plan: mail in cloud backups and replication (phase 9)

Branch `phase9/mail-backup`, decisions 460-469, migration 0110.

## What

The family mail server (decisions 239-249, 303-319, 360-364) becomes an
item of cloud backups (`internal/cloudbackup`, restic) and of replication
between HardyOS servers (`internal/replica`, `internal/replication`). It is
on by default: new backup and replication tasks have it ticked when the
mail server is set up, and migration 0110 adds it to existing whole-server
backup tasks (those with the settings item); the oldest enabled replication
task of each paired server gets it once that server accepts it (see below).

Covered: mailboxes (Maildirs under `<pool>/mail/vmail/<key>`), DKIM keys
(`keys/dkim`), the TLS key, the configuration (domains, mailboxes,
aliases, groups: `mail.RootConfig`, no secrets), Rspamd's learned data
(its Redis dump), Radicale's calendars and contacts, and Roundcube's
preferences database (the `roundcube` app's dataset, as the mail item's
`webmail` part in cloud backups; a ticked app item in replication).

## Consistency

Everything that matters lives on `<pool>/mail`, so its ZFS snapshot is the
consistency point. Before it, root writes `<mail>/.hardyos-backup/`:
`config.json` (the applied `RootConfig`) and `rspamd.rdb` (after
`redis-cli SAVE` on Rspamd's own Redis, whose data lives on the root file
system). Maildir is crash-safe by design (tmp → new/cur renames) and
Dovecot's indexes and uidlists are rewritten by rename and checked on
open, so an atomic snapshot of a running Dovecot is what a power cut
would leave: nothing lost, indexes rebuilt where needed. SQLite (Roundcube)
is crash-safe the same way.

## Restore (root: `mail.Root.RestoreFrom`)

From a staged copy (cloud: restic into a staging dataset; replication: the
replica's snapshot received into `<pool>/mail-restores/<id>`, mounted
read-only in a root-only folder, destroyed after):

- one mailbox: into a new folder `Restored <date>` (subscribed; nothing
  current changes) or overwriting it (its address typed; a ZFS snapshot of
  `<pool>/mail` first);
- one domain: its mailboxes the same way; overwriting also brings its
  DKIM key and its people's calendars back (domain typed);
- calendars and contacts of one person: as new collections "… (restored)"
  or overwriting theirs (address typed);
- everything (`mail` typed): services stopped, safety snapshot, every
  mailbox, calendar, DKIM key and Rspamd's data put back, then the saved
  configuration applied again (services restart). Cloud backups also put
  Roundcube's data back.

Mailboxes are matched by storage key (decision 310), never by address; a
version's mailbox can go into another mailbox only when the administrator
picks it and types that mailbox's address. Every file copied is a regular
file or folder (no links, devices, FIFOs), read without following links,
written with the live owner and fixed modes.

## Security review (PR #39) and what changed

- H1/M1: overwrites build the version's Maildir next to the live one
  (root 0700), then hold that mailbox's mail (Postfix `hold` transport map,
  `retry:`; sessions kicked), take a second snapshot, swap with one
  `renameat2(RENAME_EXCHANGE)`, merge in every message whose base name the
  version lacks, resume delivery in a defer, and keep what was replaced
  root-only for 14 days (`.replaced-<time>`, removed at an apply).
- M2: a domain restore skips mailboxes now at another domain.
- M3: Rspamd's dump never from replicas; from cloud versions only after
  root's RDB reader (no functions or module data), `redis-check-rdb` as
  Redis's user, and Redis starting with it (else the previous dump).
- M4: only Maildir messages (cur, new, keywords); no indexes, uidlist,
  Sieve or other dotfiles.
- M5: a restore of everything starts the mail server again in a defer.
- M6: existing replication tasks get Mail only when the peer's hello lists
  `mail`; then a notification and a one-click "Stop replicating mail";
  older peers make the item skipped, not failed.
- L1-L8: descriptor-based chown/chmod, Nlink on the opened dump, no
  Rspamd restart inside "everything", DKIM change noted, narrow locking,
  stricter rebuild (empty dataset, matching TLS pair), Roundcube note,
  free-space check and display.

## Pieces

- `internal/mail/backup.go`: prepare, contents, restore, rebuild.
- `internal/cloudbackup`: `ItemMail`, `Mail` hook, backup (two parts),
  versions, restore mode `mail`, rebuild, `cloudbackup.mail.contents`.
- `internal/replica`: `KindMail`, prepare hook before the snapshot, never
  browsable, restore into a private staging dataset, `org.hardyos:mail`
  stripped on receive.
- `internal/replication`, `internal/cloudbackups`, `internal/api`: pass the
  mail restore through jobs and audit; a mail item of a server without a
  mail server is skipped, not failed.
- Web: Backup app (task wizard, Restore tab's mail panel), Replication tab.
- Tests: `internal/mail` (temp dirs, fake runner), `internal/cloudbackup`
  (real restic, fake volumes, the real mail root on temp dirs),
  `internal/replica`, `internal/replication`, API, vitest; the mail CI job
  gets a real Dovecot backup → restore round trip.
