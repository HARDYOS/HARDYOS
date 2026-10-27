# Remote access

HardyOS reaches the outside world through [NetBird](https://netbird.io):

- **NetBird's VPN.** The server joins your NetBird network as a peer, so your
  laptops and phones with NetBird reach it from anywhere at its NetBird
  address (100.x.y.z), like at home.
- **NetBird's reverse proxy.** HardyOS publishes the desktop and each app
  with a web page at its own address under a domain you choose, like
  `https://nas.home.hardynetworks.net` and
  `https://jellyfin.home.hardynetworks.net`. NetBird's proxy (on your NetBird
  server) makes the certificates and forwards each request to this server
  over the NetBird network, so nothing at home needs a port opened. Each
  address is either **NetBird-only** (only NetBird devices can open it) or
  **public** (anyone on the internet, with a sign-in in front).

Everything is in **Control Panel › Remote Access**; each app's own
publishing is also on its App Store page (**Remote access** tab).

## 1. Join the NetBird network

In NetBird's dashboard (for Cade: `https://vpn.hardynetworks.net`):

1. **Setup Keys › Create Setup Key.** One-off is enough; give it a name
   like "HardyOS". Auto-assigned groups are up to you (they decide which
   NetBird policies apply to the server).
2. Copy the key.

In HardyOS, Control Panel › Remote Access › **Join a NetBird network**:
the NetBird server (already filled in), the setup key and this server's
name in NetBird (`nas` by default). **Join** starts NetBird on the server
and signs it in. The key is used once and isn't kept anywhere.

The card then shows the server's NetBird address, its name in NetBird's
DNS, and how many peers are connected. **Leave** removes HardyOS's
published services from NetBird, signs the server out of NetBird (removing
it from the peer list when NetBird can be reached) and turns NetBird off;
type the NetBird server's name to confirm.

HardyOS starts NetBird with `--disable-client-routes`,
`--disable-server-routes` and `--disable-dns`: routes, exit nodes and DNS
settings in NetBird's dashboard don't apply to this server (it stays a
plain peer and keeps its own resolver), and it never routes for other
peers.

The NetBird client stays joined across HardyOS updates. A settings
restore onto a new install doesn't bring NetBird's identity along: join
again with a new setup key.

## 2. Get NetBird's reverse proxy ready

Publishing needs, on the NetBird side:

- **A NetBird proxy.** Self-hosted NetBird runs it next to the management
  server (NetBird's reverse proxy documentation: the proxy container with
  `NB_PROXY_DOMAIN`, behind Traefik with TLS passthrough). The reverse proxy
  is a beta feature of NetBird.
- **A custom domain** for the apps: Reverse Proxy › Custom Domains › Add
  Domain, for example `home.hardynetworks.net`, with your proxy cluster.
  HardyOS can add it for you (Setup check › **Add to NetBird**).
- **The wildcard DNS record** NetBird checks before it uses the domain. In
  Cloudflare (DNS › Records › Add record):

  | Type | Name | Target | Proxy status | TTL |
  | --- | --- | --- | --- | --- |
  | CNAME | `*.home` (shown in full as `*.home.hardynetworks.net`) | your proxy cluster's address, for example `proxy.hardynetworks.net` | **DNS only** (the grey cloud) | Auto |

  The Setup check shows the exact record for your domain and cluster. Keep
  the proxy status **DNS only**: NetBird's proxy must get the connections
  itself to make the certificates. Then press **Verify** (HardyOS asks
  NetBird to check it). NetBird forgets a domain that isn't verified within
  48 hours; add it again if that happens. If the domain has CAA records,
  they must allow your proxy's certificate authority (Let's Encrypt for a
  self-hosted proxy).
- **An access token** HardyOS uses to manage its services: in NetBird,
  **Team › Service Users › Create Service User** with the role **Network
  Admin**, then **Create Token** on it. Copy the token (`nbp_...`); NetBird
  shows it once.

## 3. Publishing settings

Control Panel › Remote Access › **Publishing**:

- **Base domain**: the custom domain from step 2.
- **Desktop's name**: the desktop is `https://<name>.<base domain>`
  (`nas` by default).
- **New apps are**: NetBird devices only, public with HardyOS sign-in in
  front, or not published. Each app can choose otherwise.
- **NetBird access token**: paste it. It's stored encrypted (sealed with a
  key that isn't in the database, so settings backups never carry it in
  the clear) and is never shown again; paste a new one to replace it, or
  **Remove the token**. After restoring settings onto another server, paste
  it again.
- **NetBird API address**: empty uses the NetBird server the server joined.
  Changing it needs the access token pasted again (the saved token is
  never sent to another address).

Turn on **Publish the desktop and apps** and save. HardyOS adds a
service in NetBird for the desktop and for every app with a web page, and
the **Setup check** says what's missing, if anything: the token, this
server in NetBird's peer list, the domain, the DNS record, whether
NetBird-only services are possible, and whether NetBird uses HardyOS's own
sign-in.

## NetBird-only or public

| | NetBird-only | Public |
| --- | --- | --- |
| Who can open it | NetBird devices in the chosen groups (All by default) | Anyone on the internet |
| Sign-in in front (NetBird's) | None: being a NetBird device in the right group is the sign-in | HardyOS sign-in (SSO), a shared password or PIN, or none |
| HardyOS sign-in (apps) | Yes, unless turned off for the app | Yes, unless turned off for the app |
| Needs | A proxy cluster with the **Private** capability: a NetBird proxy running inside a NetBird client (NetBird's "Bring Your Own Proxy" with the private option). NetBird's shared cloud clusters don't have it | Nothing more |

Choose **NetBird-only** for things only the family's own devices should
reach (the desktop, admin tools); it needs the Private capability above. Choose
**Public** for things people open from devices without NetBird (a TV, a
friend's phone): the sign-in in front keeps strangers out before anything
reaches the server.

- **HardyOS sign-in (SSO)** signs people in with NetBird's identity
  provider. Once HardyOS's own sign-in (Control Panel › Sign-in, OIDC) is
  NetBird's identity provider, that is the family's HardyOS accounts; the
  Setup check says whether it is.
- **Password** (8 characters or more) and **PIN** (4 to 12 digits) are one
  secret for everyone. HardyOS keeps them encrypted and sends them to
  NetBird, which keeps only a hash.
- **None** leaves just the app's own sign-in (and HardyOS's, below).

IP and country rules (Access Control on a service in NetBird's dashboard)
are left to NetBird: HardyOS keeps whatever you set there.

### HardyOS sign-in for apps

Apps also ask for a HardyOS sign-in by default: the first time an app's
address is opened in a browser, it goes to HardyOS's sign-in page at
`https://sso.<base domain>` and back, and only people who may use the app
(App Store › the app › Who can use it) get in. Being signed in there once
is enough for every app (and for NetBird's SSO, when HardyOS is NetBird's
identity provider). How quickly changes reach an app that is already
open (open WebSockets included):

| Change | Open published apps end |
| --- | --- |
| "Who can use it", a HardyOS account turned off, a password reset in HardyOS, **Sign everyone out** of the gateway, local accounts turned off for apps, signing out of HardyOS sign-in | within 30 seconds |
| A domain account turned off, deleted, expired, or its name given to another account, or its password changed on a computer in the domain | at the account's next check with the domain (at most 10 minutes), then within 30 seconds |

Other apps that use HardyOS sign-in (NetBird) find out at their next
token refresh; an access token they already hold lasts its 15 minutes.
Signing out of the desktop doesn't sign out of apps; signing out of
HardyOS sign-in does sign out of every published app. HardyOS sign-in
takes domain accounts; HardyOS's own local accounts only if Control
Panel › Sign-in allows them.

From the internet (`sso.<base domain>` through NetBird's proxy):

- **Wrong passwords slow down, they don't lock out.** After three wrong
  tries the next one waits 1 second, then 2, 4 and so on up to 2 minutes.
  These count apart from sign-ins at home and over NetBird, so a stranger
  typing your name can't lock you out of the desktop (the domain's own
  lockout policy, if it has one, still counts every wrong password).
- **Every failure looks the same**: "Incorrect username or password."
- **Administrators are refused** (with that same answer) unless Control
  Panel › Sign-in › **Administrators can sign in through public SSO** is
  on. Sign in at home or over NetBird instead. A second factor (TOTP) for
  public sign-in is planned.

Apps with phone or TV clients (Jellyfin's apps, sync clients) can't do
that sign-in: turn **Ask for a HardyOS sign-in too** off for them. The
app's own sign-in (and the sign-in in front, if public) then protects it,
and HardyOS's "Who can use it" isn't checked at its address.

Public with **None** in front *and* HardyOS sign-in off leaves only the
app's own sign-in, so it needs an explicit confirmation (a red warning).
Every request reaches the app from this server, so an app that lets
"local" addresses in without a password lets everyone in:

- Sonarr, Radarr, Lidarr, Prowlarr and the other *arr apps: Settings ›
  General › Authentication Required must be **Enabled**, not "Disabled for
  Local Addresses".
- Home Assistant: no `trusted_networks` auth provider covering this
  server's addresses (or Docker's).
- Anything else with an "allow local network without password" or
  "trusted proxies/IPs bypass login" option.

### The desktop

The desktop includes administration (Control Panel, Terminal, storage), so
it is **NetBird-only** by default: open it from devices with NetBird at
`https://<desktop>.<base domain>`. Making it public needs an explicit
confirmation (a red warning in Remote Access); with a password or PIN in
front of it, share links (`/s/...`) and `/oidc` still open without it.
Without a proxy cluster with the Private capability the desktop isn't
published at all (use it at home or at its NetBird address).

### HardyOS sign-in and share links

- `https://sso.<base domain>` is HardyOS's sign-in (Control Panel ›
  Sign-in), always public with nothing in front: NetBird's server and
  everyone signing in must reach it. It serves the sign-in and nothing
  else, and is published only while Sign-in's issuer is exactly
  `https://sso.<base domain>` (the default). With another issuer it is
  taken down, and an issuer with a path on that host is refused.
- `https://files.<base domain>` opens share links (`/s/...`) and nothing
  else, for people without NetBird. It's published while at least one share
  link is active, or always with **Public share links** on; new links show
  their address there (the first one can take a minute to open while NetBird
  gets the certificate).

## Opening published apps

When you use the desktop at its published address
(`https://nas.home.hardynetworks.net`), apps open at their own addresses,
in windows and new tabs alike. At the desktop's home address (its LAN IP or
name) apps open through the window proxy as before. Each app's address is
also on its App Store card.

Each app at its own address keeps its cookies to itself: browsers keep
cookies per host, so the renaming the window proxy does (docs/apps.md, App
windows) isn't needed there.

## At home

Devices at home use the same addresses: they go out to NetBird's proxy and
back over the NetBird network. One name and one certificate everywhere. (A
port forward at home isn't needed, and HardyOS doesn't set one up.)

## How HardyOS keeps NetBird in step

- HardyOS names its services `hardyos-<tag>-desktop`,
  `hardyos-<tag>-files`, `hardyos-<tag>-sso` (HardyOS's own sign-in at `https://sso.<base domain>`,
  always public: NetBird's server and everyone signing in must reach it) and
  `hardyos-<tag>-app-<id>`, where the tag is this server's own. It never
  changes or removes a service without its tag; if another service already
  uses an app's address, the app shows that and stays unpublished.
- Installing, changing, updating, rolling back or removing an app updates
  NetBird a few seconds after the job finishes; a failure shows on the app
  (and in Remote Access) and never fails the install.
- Every 10 minutes HardyOS puts back anything changed on its services in
  NetBird's dashboard (except IP and country rules) and recreates any that
  were deleted. **Update NetBird now** does it at once.
- Turning publishing off, or leaving NetBird, removes HardyOS's services.
  Its custom domain stays in NetBird.

## Security notes

- **Let only NetBird's proxy reach port 44200.** The app gateway takes
  requests from the NetBird network that carry their service's secret
  value, but any peer can knock. In NetBird's dashboard (Access Control ›
  Policies) allow TCP 44200 to this server only from the group your proxy
  runs in, and drop any policy that lets All reach All. NetBird's API
  doesn't name its proxies' peers, so HardyOS can't narrow it down itself.
- **Each service has its own gateway value** (an HMAC of its address under
  the gateway secret), visible in NetBird's dashboard. A value only opens
  its own address. **New gateway secret** (Remote Access › Published)
  replaces every one at once; leaving NetBird or turning publishing off
  does it too. Use it when someone who could read NetBird's services
  shouldn't any more.
- **Client addresses**: the gateway believes `X-Forwarded-For` only on a
  request whose value checked out, and only its right-most entry (the one
  NetBird's proxy appended); everything left of it was written by the
  client. Rate limits and the audit log use that address.
- **The desktop at its NetBird address.** hardyd listens on every
  address, so NetBird peers that policies allow can open the desktop at
  `https://100.x.y.z` like on the LAN, with the desktop's own sign-in. To
  keep the desktop to some devices, restrict TCP 443 to this server in
  NetBird's policies as above.
- **Desktop cookie**: over HTTPS the desktop's session cookie is
  `__Host-hardyos_session`, which no app on a sibling address can set.
  The old `hardyos_session` still works for one release at the desktop's
  LAN address, never at a published one: sign in again there once.

## Troubleshooting

- **Status "Getting a certificate"** for more than a few minutes: the DNS
  record is missing or proxied (orange cloud), or a CAA record blocks the
  proxy's certificate authority.
- **"Waiting for the tunnel"** (`tunnel_not_created`): NetBird's proxy
  can't reach this server over NetBird. Check that the server is connected
  (Remote Access › NetBird) and that NetBird's policies let the proxy reach
  this server on TCP port 44200.
- **"This port only takes requests from NetBird's reverse proxy"**: the
  gateway port was opened directly; use the app's published address.
- **An app called `sso`, `files` or the desktop's name** can't use that
  name under the base domain: HardyOS uses them (the desktop's even while
  the desktop isn't published).
- **"HardyOS sign-in's issuer isn't https://sso.<base domain>"** on the
  sso item: Control Panel › Sign-in has another issuer chosen; empty it to
  follow Remote Access.
- **The token was refused (401) or isn't allowed (403)**: create a new token
  on a service user with the Network Admin role.
- **NetBird-only greyed out**: your proxy cluster has no Private
  capability (see the table above).
