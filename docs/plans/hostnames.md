# Per-app hostnames and a trusted wildcard certificate (phase 9)

Branch `phase9/hostnames`, decisions 450-459, migration `0100_hostnames.sql`.

## Goal

Apps, the office editor, Photos (Immich), webmail (Roundcube) and the sign-in
provider each get their own origin under the base domain, with a publicly
trusted wildcard certificate, so no app shares an origin (or a port of the
desktop's host) with the desktop. Without a Cloudflare token nothing changes:
window proxy ports, the office port and the self-signed certificate stay.

## Pieces

1. **Cloudflare token, root's only** (`internal/cfdns`, `priv/dns_ops.go`).
   The administrator pastes one token limited to Zone › DNS › Edit on the
   zone of the base domain (Control Panel › Hostnames). It goes to a job
   through the in-memory secret box, then to hardyd-priv (`dns.token.set`),
   which verifies it (`/user/tokens/verify`, then the zone holding the base
   must be visible), seals it (AES-256-GCM, a root-only key from
   `RootKeyFor(keys, "dns-cloudflare")`) into `_hardyos-dns.json` in the keys
   folder and never hands it back. `dns.status` answers "set, base, zone,
   last verified". Named DNS operations only:
   - `dns.acme.present` / `dns.acme.cleanup`: TXT exactly
     `_acme-challenge.<base>`; root keeps the ids it made and deletes only
     those.
   - `dns.record.set`: A/AAAA/CNAME for a name strictly under the base (or
     `*.<base>`), only creating or changing records root made. For the
     NetBird take-over later; code and tests now, not registered as an
     operation until then.
   - `dns.token.verify`, `dns.token.clear` (confirmation = the base).
2. **Wildcard certificate** (`internal/hostnames`). hardyd speaks ACME
   (golang.org/x/crypto/acme, already pinned in go.mod) for `*.<base>` with
   DNS-01 through the root ops; key P-256 made by hardyd (it terminates TLS),
   kept 0600 next to the self-signed certificate. Jobs `hostnames.issue`
   (also renewals) and `hostnames.dns`; a loop checks twice a day and renews
   30 days before expiry. `tlscert.Store.GetCertificate` serves it for SNI
   under the base, the self-signed certificate for everything else.
3. **Host routing** on the desktop's own listener (every address: LAN and
   NetBird), only while a valid certificate is installed:
   `<desktop>.<base>` desktop, `sso.<base>` provider only, `files.<base>`
   `/s/` only, `office.<base>` the office origin, `mail.<base>` mail-app
   paths to hardyd and the rest to webmail, `photos.<base>` Immich,
   `<app id>.<base>` any app with a web page, anything else 404.
4. **Sign-in on app hosts**: a bounce through the desktop host
   (`/__hardyos/bind`) that turns the desktop session cookie there into a
   one-time code for exactly the app host it came from, accepted only with
   the state cookie set on that app host. Sessions follow the desktop
   session like window proxy sessions (rechecks, WebSocket closing).
5. **Old addresses**: window proxy ports and the office port reached by a
   name under the base redirect to the hostname; by IP they keep working.
   `/oidc/*` on the desktop host redirects to `sso.<base>`. The desktop
   offers to move to `https://<desktop>.<base>` when that answers.
6. **LAN names**: Control Panel › Hostnames lists the records (each name →
   this server's LAN address) for the router, and, with HardyOS's own domain
   controller, adds them there (`domain.dns.hostnames`, a zone for the base
   or the AD zone when the base is inside it; only records HardyOS made are
   removed).

## Tests

- `cfdns`/`priv`: fake Cloudflare (httptest): verify, zone lookup, TXT
  create/delete of own records only, record.set validation (names outside the
  base, apex, `_` names, wrong content type, records not HardyOS's), token
  never in any result, state file root-only and sealed.
- `hostnames`: a fake ACME server (RFC 8555 subset) that checks the TXT
  record the fake Cloudflare holds before validating; issue, renew window,
  cert store picks by SNI.
- `api`: host routing (each label, unknown → 404, sso never desktop),
  bounce (no desktop session, wrong state cookie, code reuse, code for
  another app, mayUse refused), redirects from old ports, token never
  returned.
- web: Control Panel › Hostnames rules (vitest).

No real network in tests; nothing needs a CI job of its own.

## After the security review (decisions 450-459 amended)

- M1: the wildcard is served only while the hostnames are active and is
  removed when they're turned off; app names under the last known base
  then answer "Hostnames are off" with `Clear-Site-Data`, never the desktop.
- M2: root decides which names go into the DC (HardyOS's own, the
  desktop's, apps with a web page in root's apps state; never wpad, isatap
  or a directory computer/SPN name); Cloudflare zones must be active.
- M3: cookie tossing between app hosts is reduced, not gone: per-host
  learned cookie names, foreign and duplicated names dropped.
- L1-L8: deep names 404, only `_acme-challenge.<base>`, `dns.record.set`
  unregistered, bind codes capped (5 per session and address), DC removal
  deletes HardyOS's zone and works without the token, the apex refused,
  proxy cache keyed on the desktop name, desktop names can't be HardyOS's
  labels, one atomically replaced certificate file.
- Cross-site starts get the Continue page; Photos re-syncs Immich's
  redirect URIs when the hostnames turn on or off; account-owned
  Cloudflare tokens verify at their account's endpoint.
