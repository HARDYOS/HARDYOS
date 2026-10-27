# Remote access: NetBird client, app addresses and HardyOS sign-in (build contract)

Cade's decisions (2026-10-26):

- NetBird stays on the VPS (`vpn.hardynetworks.net`, self-hosted, Ubuntu). HardyOS
  joins it as a **client** (peer). Hosting a NetBird server on HardyOS is a later item.
- Apps get their own names under a base domain chosen in HardyOS's setup
  (e.g. `jellyfin.home.hardynetworks.net`), served by **NetBird's reverse proxy**
  (on the VPS), which also issues the certificates. Cloudflare holds a wildcard
  CNAME `*.<base>` -> the NetBird proxy.
- HardyOS adds and removes these services in NetBird **by itself**, with a NetBird
  access token (service user, Network Admin) pasted into Control Panel.
- Each app (and the desktop itself) is either **NetBird-only** (reachable from
  NetBird peers) or **public** (internet) with sign-in in front.
- At home, devices without NetBird also go through NetBird's proxy (one name and
  certificate everywhere). Port forwarding at home is possible if ever needed.
- **HardyOS is the sign-in provider (OIDC)** for NetBird (its IdP) and for the
  sign-in page in front of public apps, backed by the domain accounts.

Read `docs/architecture.md`, `docs/apps.md` (App windows), decisions 66 and 80
(per-port proxy; cookies not isolated by port), `daemon/internal/api/appproxy.go`,
`daemon/internal/auth/` (domain sign-in), `daemon/internal/network/`.

## 1. NetBird client (part A)

- Package `netbird` (Debian package from NetBird's apt repo, pinned; added to the
  image with its signing key under `os/live/config/archives/` or as a .deb in the
  build, whichever the image already does for third-party repos). Service runs on
  the host; interface `wt0`.
- Root ops (`priv/netbird_ops.go`): `netbird.status`, `netbird.join {managementURL,
  setupKey, hostname}` (setup key via the job secret box and stdin/env, never argv),
  `netbird.leave` (confirm), `netbird.settings`. Status: connected, NetBird IP,
  FQDN, peers count, management URL, problem.
- Control Panel > **Remote Access**: join with management URL (default
  `https://vpn.hardynetworks.net`) + setup key; status; leave.

## 2. Publishing apps through NetBird's proxy (part A)

- Settings (hardyd DB): base domain (e.g. `home.hardynetworks.net`), NetBird API
  URL (default = management URL) and access token (encrypted at rest with the
  existing secret mechanism; never returned by the API), the NetBird proxy
  cluster/domain to use (listed from the API), and a "desktop name" (default
  `nas`).
- Setup check: verifies the token, the base domain is registered and verified in
  NetBird (Reverse Proxy > Custom Domains) and the wildcard CNAME resolves; shows
  the exact Cloudflare record to add when not.
- Services HardyOS manages (tagged/named so it only ever touches its own):
  - the desktop: `<desktop>.<base>` -> NAS peer, hardyd HTTPS port.
  - each app with a web page: `<app id>.<base>` -> NAS peer, the app's **HardyOS app
    gateway** (below), not the container port directly, so HardyOS's per-app
    access rules, frame headers and cookie handling still apply.
  - optional: share links base `files.<base>` for public `/s/...` links.
- Per service: **NetBird-only** (peer groups; needs a proxy cluster with the
  Private capability — detect, otherwise explain) or **Public** with NetBird proxy
  auth = SSO (HardyOS's OIDC, section 3), optionally password/PIN; IP/country
  allow lists left to NetBird's dashboard.
- Lifecycle: app install / reconfigure / remove / rename update NetBird; a sync
  every 10 min repairs drift; failures show on the app and in Remote Access, never
  block the install.
- Look up the real NetBird management API for services/domains/peers/groups
  (`docs.netbird.io` "Public API"; the proxy is beta — read the current docs and
  pin to what exists; write a small typed client with tests against recorded
  responses). If an endpoint we need doesn't exist, report it and fall back to
  showing the exact settings to create by hand.

## 3. App gateway (part A)

- Replaces the per-port app proxy (44300+) for NetBird-published apps: hardyd
  listens on the NetBird interface (wt0 address) on one port (e.g. 8443, HTTPS
  with the desktop cert, or HTTP if NetBird's proxy can't use a self-signed
  upstream — find out; the link is WireGuard-encrypted either way) and routes by
  Host header `<app>.<base>` -> 127.0.0.1:<web port>. Requests only accepted from
  the NetBird proxy peer's address. Keeps: access checks, frame header rewrite,
  WebSocket tracking/revocation, no HardyOS cookies forwarded.
- Sign-in at the gateway: an app host has its own cookie (host-only, Secure,
  SameSite=Lax) set via a redirect round-trip to the desktop
  (`<desktop>.<base>/apps/{id}/signin?return=...`), so each app's sign-in is
  isolated by host. With different hosts per app, cookies are finally isolated
  (decision 80's residual risk goes away for published apps).
- The desktop opens published apps at `https://<app>.<base>` in windows; the
  per-port proxy stays for servers without NetBird publishing.
- LAN fallback: if NetBird isn't set up, everything works as today.

## 4. HardyOS as OIDC provider (part B)

- Issuer `https://<desktop>.<base>/oidc` (or `sso.<base>`, decide and document),
  published through NetBird's proxy as a **public** service (NetBird's
  management on the VPS and browsers must reach it).
- Library: a maintained, well-tested Go OIDC provider (e.g.
  `github.com/zitadel/oidc/v3` op package or `ory/fosite`); no hand-rolled crypto.
  Authorization code + PKCE, refresh tokens, RS256/ES256 keys with rotation,
  discovery and JWKS, consent screen for non-first-party clients, logout.
- Users: domain accounts (password via the existing Kerberos sign-in, same rate
  limits/lockout, admin by SID) and local HardyOS accounts optionally (setting;
  off by default). Claims: sub (stable: objectGUID/SID for domain users), name,
  email, preferred_username, groups (NETBIOS\group names and a `hardyos_admin`
  boolean).
- Clients: Control Panel > **Sign-in (OIDC)**: add a client (name, redirect URIs,
  confidential/public), show the client secret once; a preset for NetBird
  (redirect URIs and the settings to paste into NetBird's IdP config — read
  NetBird's current self-hosted IdP docs: embedded Dex connectors / generic
  OIDC) and for "NetBird reverse proxy SSO".
- Security: exact redirect URI matching, PKCE required for public clients,
  short-lived codes, token revocation, audit sign-ins and client changes,
  CSRF on the sign-in/consent pages, no open redirects.

## 5. Ownership and decisions

| Part | Owns | Decisions |
| --- | --- | --- |
| A NetBird + publishing + gateway | `internal/netbird/`, `internal/publish/`, `priv/netbird_ops.go`, `api/handlers_remote*.go`, `api/appgateway*.go`, web `control-panel/RemoteAccess*.tsx`, App Store window changes | 111-115 |
| B OIDC provider | `internal/oidc/`, `api/handlers_oidc*.go`, web `control-panel/SignIn*.tsx` | 116-119 |
