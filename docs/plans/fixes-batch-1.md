# Fixes, batch 1 (decisions 510-519)

Four small fixes in one pull request, one commit each.

## 1. App window ports and the replication port (decision 510)

Window ports were allocated "from a base upward": the base was a
parameter, and ports recorded before decision 371 bounded the range could
sit on or past 44400 (replication) and were reused as recorded.

- `internal/ports` gets registered ranges (`ports.Range`, `ports.Ranges`:
  app windows 44300-44399, live migration 49152-49215). A test checks that
  every fixed port and every range is pairwise disjoint (and that the
  checker catches clashes).
- The window proxy always allocates in `ports.AppProxy` (the base is no
  longer an option; tests in the api package set a range of their own).
  `AllocateProxyPort` takes the range and skips fixed ports and other
  ranges.
- On start the proxy forgets recorded ports outside the range
  (`ReleaseStrayProxyPorts`), and never listens on a recorded port
  outside it, so each such app gets a port of the range. The desktop
  always asks `POST /apps/{id}/open` for the URL, so windows keep
  opening; a window reached by a name under the base is sent to the app's
  hostname by the existing redirect (`redirectOld`).
- Apps can't publish a host port inside a registered range.

## 2. IPv6 for cards behind the anti-spoofing filter (decisions 511-513)

libvirt's `clean-traffic` drops all IPv6 (decision 137: filtered cards were
IPv4-only). libvirt's ebtables filters can't express what IPv6 needs, so:

- `hardyos-clean-traffic` (a libvirt filter hardyd-priv defines): exactly
  `clean-traffic` for MAC, IPv4 and ARP, plus "IPv6 passes libvirt".
  Domain XML references it instead of `clean-traffic`.
- `table bridge hardyos_vmguard6` (nftables, root): one chain per filtered
  card (by its tap name), with the card's MAC, the prefixes on-link on its
  network (the server's own routes on the bridge or `<bridge>.<vlan>`), and
  the server's and the routers' addresses as a protected set. Allowed:
  link-local (fe80::/64), addresses in those prefixes (SLAAC, privacy),
  `::` only for DAD and MLD. Dropped: RA, redirect, router renumbering,
  DHCPv6 server/relay replies, NA whose target is protected, NS/NA whose
  first option isn't the card's own link-layer address, VLAN-tagged
  frames.
- Loaded before the VM runs (start, resume of a paused VM, incoming live
  migration); a failure stops the start (fail closed). Seeded again for
  running VMs when hardyd-priv starts; refreshed every 30 s (prefixes
  change) and reloaded only when the text changes.
- Tests: rendering and validation, the sim (filter defined, table loaded,
  spoofing-allowed cards left out, a failed load refuses the start), a
  namespace test in CI's Cluster (namespaces) job that bridges a "VM" and
  another computer and sends crafted frames (SLAAC, privacy, DAD, RA, NA
  spoofing, DHCPv6 server, extension headers), and the KVM job defines the
  filter in the real libvirt.

## 3. SFTP accepts app passwords (decisions 514-516)

- New app-password scope `sftp`.
- sshd's PAM block for domain accounts calls `hardyctl pam-sftp`
  (pam_exec) three times: `app` (with the password on stdin, only when it
  has the shape of an app password), `own` before pam_winbind (is the
  account's own password allowed from this address?) and `after` once
  winbind said yes (checked again). hardyctl talks to hardyd over a
  systemd socket (`/run/hardyos-sftp-auth.sock`, owner hardyd, 0600) and
  hardyd answers only connections from root (SO_PEERCRED).
- hardyd applies WebDAV's rule (decision 445): an app password with the
  scope always works; the account's own password only from home (decision
  441's address rule) and only without two-factor sign-in. Rate limits
  per address and account (the desktop's limiter), audited
  (`sftp.login`); a refused own password counts against the address only.
- SSH keys of local accounts are untouched (the block only runs for
  domain accounts' password sign-ins).

## 4. Revoking other people's app passwords (decision 517)

Users & Groups gets an "App passwords" action per domain account: the
list (name, scopes, created, last used and from where), and Revoke with a
confirmation, through the existing admin API (audited
`auth.app_password.delete`).
