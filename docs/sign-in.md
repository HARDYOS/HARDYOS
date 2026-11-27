# Signing in to other apps with HardyOS (OIDC)

HardyOS is an OpenID Connect provider: apps that support "Sign in with
OpenID Connect" (or "generic OIDC") can let your family sign in with the
same domain accounts they use for the desktop, Windows and the shared
folders. The first such app is NetBird: its dashboard, the NetBird app on
each device, and the sign-in page in front of public apps on NetBird's
reverse proxy.

Everything is set up in **Control Panel > Sign-in (OIDC)** (administrators).

## Who can sign in

- **Domain accounts** (`alice`, `HOME\alice`, `alice@home.example.net`),
  checked by this server's own domain controller exactly like a desktop
  sign-in: the same wrong-password lockout (5 tries in 15 minutes per
  address and per account), the same messages for turned-off, locked or
  expired accounts, and administrators decided by group SID (Domain Admins
  or HardyOS Admins).
- **HardyOS accounts** (local ones such as the recovery administrator) only
  when *HardyOS accounts may sign in to apps* is on. It's off by default:
  the local administrator is for repairs, not for everyday apps.
- An app can be limited to **groups** (`HOME\Family`). People outside them
  see "You can't use …" and the app is told `access_denied`.
- An account turned off (in HardyOS or in the domain), deleted, or whose
  password was changed or reset is signed out of every app: its tokens stop
  working and refreshing them fails.

If you're already signed in in that browser (to an app through HardyOS in
the last 12 hours, or to the desktop when the sign-in page is on the
desktop's own address), HardyOS doesn't ask for the password again (unless
two-factor sign-in needs a code there and that sign-in didn't use one).

## Two-factor sign-in

After the password, HardyOS can ask for a 6-digit code from an
authenticator app (Google Authenticator, Microsoft Authenticator,
1Password, Bitwarden, Aegis…).

- **Administrators must use it.** After their first sign-in that asks, they
  have a grace period (7 days by default; Control Panel › Security, 0-30
  days) shown in Users & Groups and in their account menu. After it, the
  desktop shows nothing but the setup screen until it's done.
- **Everyone else may**, from the account menu › *Two-factor sign-in*.
- **Everyone needs it from outside**: the published desktop, `sso.<base>`
  reached through Remote Access (and so every app that signs in with
  HardyOS from outside, Immich's phone app included) and published apps. A
  desktop session made at home without a code doesn't work through the
  published address. The per-app addresses (Control Panel › Hostnames) are
  reached at home or over NetBird; opening an app there needs a desktop
  session that meets the same rule, and its app session ends with the
  desktop's (two-factor set up, reset, sign-out).
- An app's sign-in through HardyOS (an OIDC app) counts by where the
  browser was when signing in. An app's server refreshing its tokens from a
  container proves nothing about the person, so only an app on the person's
  own device (a public client) is checked by where the refresh comes from.

Setting up shows a QR code and the key to type, and turns on only after the
first code works. You get **10 recovery codes**: each signs you in once if
you lose your phone. Save them (Copy / Download) — they aren't shown again;
*New recovery codes* replaces them.

**From outside without two-factor sign-in** you can't sign in until it's set
up. Set it up at home, or ask an administrator for a **setup code** (Users &
Groups › the shield button): with your password and that code (24 hours,
once) the sign-in page lets you set it up from outside. A password alone
never can: whoever stole it would register their own phone.

**Wrong codes**: they count per place. At home they're one bucket; from outside
each address (each /64 for IPv6) is one. 5 in 15 minutes pause code entry from
that place for 15 minutes, so a stranger can never pause it for you at home,
and recovery codes always work.

Wrong codes from outside also count in a rolling 60-day budget that a right code
doesn't reset. At 20, authenticator codes stop working from outside (at home
they keep working) until you change your password or an administrator resets
two-factor sign-in. Administrators get a notification, and you see a notice in
your account menu, when codes are paused, every 5 wrong codes from outside, and
when they stop. Whoever typed them knows your password, so change it.

A code works once, and only within about a minute and a half of your phone's
clock.

**What counts as outside**: anything through Remote Access, and any address
that isn't this server's own private network (10.x, 172.16-31.x, 192.168.x,
IPv6 unique-local, or a global IPv6 prefix on an interface that isn't the way
to the internet) or NetBird while it's connected. That includes apps' Docker
networks, apps running with the host's network (their connections to the
server's own addresses count as home only when they're HardyOS's own, so an
SSH tunnel to the server counts as outside too), and a server whose own
network is public (a VPS).

**The router's own address counts as outside.** Hairpin NAT (a phone at home
using the public address), a port forward the router masquerades, a VPN or
tunnel on the router, and a server running in a VM behind NAT all make
visitors look like the router, and HardyOS can't tell those apart from the
internet. Control Panel › Security warns when it sees such a request, and
administrators get a notification once. At home, use the server's local
address, and don't forward ports to HardyOS (Remote Access publishes through
NetBird instead).

If the server really is behind NAT and the people at home reach it through
the router (for example from a separate network behind it), an administrator
can turn on *This server is behind NAT: trust the router's address* in Control
Panel › Security (from the server's own network, not through the router), or
as root with `hardyctl trust-router on`. It's off by default, audited, applies
only to that router (its address and hardware address: it lapses if the
router changes), and administrators see a banner while it's on. Even then,
codes from the router have their own limit and count toward the outside
budget, and WebDAV, mail and calendars still need app passwords from it.

**A new server behind NAT**: its first boot shows a one-time setup code for
the administrator on the console login screen. Sign in with the password,
then enter that code to set up your authenticator. Later, root can make a new
one with `hardyctl setup-code <username>`.


**Lost your phone?** Use a recovery code, then *New phone* in the account
menu. No codes left: another administrator uses *Reset two-factor sign-in*
(type the username to confirm). It signs the person out everywhere and ends
every app sign-in; their app passwords are revoked too, unless the tick is
cleared. The only administrator, with no codes: as root on the server's
console, `hardyctl reset-2fa <username>` (add `-keep-app-passwords` to keep
them), then set it up again at the next sign-in from home. Setting up a new
phone yourself also signs out everything else, apps included. After restoring a server from the recovery kit your
authenticator keeps working (the keys come back with it).

### App passwords

Mail apps (IMAP and SMTP), mapped drives (WebDAV), SFTP apps and calendar
apps can't ask for a code, so they use **app passwords**: account menu › *Two-factor
sign-in* › *App passwords* (domain accounts). Each is for one device, can
sign in to the services you tick (files, SFTP, mail, calendars), shows when it was
last used, and can be revoked on its own. The rules:

| | Your own password | An app password |
| --- | --- | --- |
| At home, without two-factor sign-in | works | works |
| At home, with two-factor sign-in | refused | works |
| From outside | refused | works |

App passwords are removed when your domain password changes.

**Not covered**: shared folders over SMB, Windows sign-in, Kerberos and
LDAP check the domain password in Samba itself, and keep doing so. HardyOS
doesn't publish them outside.

**Published apps**: an app with its own sign-in is published only with HardyOS
sign-in in front, which asks for the code from outside. That includes apps
published **NetBird-only**: being a NetBird device used to be enough, and now
HardyOS sign-in is in front of them too (a change in this release). Photos is
the exception, because Immich signs in through HardyOS: only once a Photos sync
has seen, from Immich itself, that sign-in with HardyOS works and Immich's own
passwords are off (Control Panel › Photos, *Sync now*). An app published
without HardyOS sign-in before two-factor sign-in isn't served from outside
until you turn it on in Remote Access.


An app's own session (its cookie, a phone app's token) is the app's. Once
someone signed in through HardyOS, HardyOS can end it only by ending the app
sign-in. It does that when you reset two-factor sign-in, set up a new phone, or
change the password. Phones signed in to Immich before two-factor sign-in
existed sign in once more.

## What apps learn about you

| Claim | Example | Scope |
| --- | --- | --- |
| `sub` | `6f9619ff-8b86-d011-b42d-00c04fc964ff` | always (a domain account's objectGUID: it never changes, not even on a rename) |
| `name` | `Alice Hardy` | `profile` |
| `preferred_username` | `alice` | `profile` |
| `email`, `email_verified` | `alice@example.net`, `true` | `email` (without an address in Domain > Users: `alice@home.example.net`, unverified) |
| `groups` | `["HOME\\Domain Users", "HOME\\Family"]` | `groups` or `profile` |
| `hardyos_admin` | `true` | `groups` or `profile` |
| `hardyos_photos_role`, `hardyos_storage_label` | `admin`, `alice` | `hardyos_photos`, which only the Photos client (Immich, [photos.md](photos.md)) may ask for; with it HardyOS's own accounts without an address get `alice@local.hardyos.invalid` (domain accounts never get a made-up address) |

Apps an administrator adds as "set up by me for this server" (NetBird's
presets) don't ask; any other app shows a consent screen once per person,
and again when it asks for more.

## The issuer address

Apps are configured with HardyOS's **issuer**, shown at the top of the page
with its discovery address (`<issuer>/.well-known/openid-configuration`):

- Once Remote Access has a base domain (for example `home.hardynetworks.net`),
  the issuer is **`https://sso.home.hardynetworks.net`**: a name of its own
  that NetBird's reverse proxy publishes on the internet (NetBird's
  management on the VPS and every browser must reach it). Only the sign-in
  service answers on that name; the desktop can stay NetBird-only.
- Before that, it's the desktop's own address with `/oidc`
  (`https://nas/oidc`), for trying it on the LAN.
- *Change* lets you set it yourself. Apps keep working only with the issuer
  they were set up with, so choose the final one before setting up apps.

## Setting up NetBird

NetBird (self-hosted, with its built-in identity provider, the default for
new installations) adds HardyOS as a **Generic OIDC** identity provider.

1. In HardyOS: **Control Panel > Sign-in (OIDC) > Add app**, choose
   **NetBird**, check NetBird's address (`https://vpn.hardynetworks.net`),
   optionally limit it to groups, and click **Add**.
2. HardyOS shows the **Client ID**, the **Client secret** (only now: copy it)
   and the **Issuer**, and what to paste where in NetBird.
3. In the NetBird dashboard: **Settings > Identity Providers > Add Identity
   Provider > Generic OIDC**:
   - Name: `HardyOS`
   - Client ID: the client ID from step 2
   - Client Secret: the secret from step 2
   - Issuer: the issuer from step 2
4. Click **Save** and keep the window open: NetBird shows a **Redirect URL**
   (`https://vpn.hardynetworks.net/oauth2/callback/…`). Paste it into
   HardyOS's *Redirect URL NetBird shows* field and click **Save the
   redirect URL**. HardyOS accepts only that exact address.
5. To use HardyOS groups in NetBird: **Settings > Groups**, turn on **JWT
   group sync** and set **JWT claim** to `groups`. Groups arrive as
   `HOME\Family`.
6. Sign out of the dashboard and choose **HardyOS** on its sign-in page.

**Public apps on NetBird's reverse proxy**: a service with **SSO** turned on
in its Authentication tab sends people to NetBird's identity provider, where
they choose HardyOS. Nothing else is needed in HardyOS; *distribution groups*
on the service limit it to NetBird groups (synced from HardyOS's in step 5).

### NetBird with HardyOS as its only identity provider

Only if NetBird runs without its built-in identity provider: choose the
preset **NetBird reverse proxy SSO (HardyOS as NetBird's only identity
provider)**. It makes one public client (PKCE, no secret) with NetBird's
dashboard (`/auth`, `/silent-auth`), the NetBird app (`http://localhost:53000`
and `54000`) and the reverse proxy's callback
(`/api/reverse-proxy/callback`), and lists the `setup.env` values
(`NETBIRD_AUTH_OIDC_CONFIGURATION_ENDPOINT`, `NETBIRD_AUTH_CLIENT_ID`,
`NETBIRD_AUTH_AUDIENCE`, scopes `openid profile email offline_access
groups`, …) and the `management.json` `HttpConfig` values (`AuthClientID`,
`AuthCallbackURL`) to set. HardyOS issues JWT access tokens with the client
ID as audience and the groups in them, as NetBird's management expects. It
has no device-code flow and no user-management API, so NetBird can't list
accounts before they first sign in.

## Other apps

**Add app > Another app**: a name, *confidential* (a server that keeps a
secret) or *public* (an app in the browser or on a device: no secret, PKCE
required), its redirect URIs exactly as it sends them (https; plain http only
to `localhost`, for public apps), optional sign-out redirect URIs and groups.
The endpoints are in the discovery document; codes use PKCE (S256), refresh
tokens are rotated on every use (an old one used again signs the person out
of that app), access tokens last 15 minutes, ID tokens an hour, refresh
tokens 14 days of inactivity and 30 days at most.

On an app's row: edit, **new secret** (the old one stops working at once),
**sign everyone out** (every token it holds stops working) and remove.

## Keys and backups

ID and access tokens are signed with RS256 keys. A new key is published a
day before it signs, signs for 30 days, and stays published two days after;
**Rotate now** switches at once. The private keys are encrypted with a key
only the root helper has. Settings backups always hold the apps (with their
secrets as hashes) and the encrypted keys; the key that opens them is only
in backups made *with encryption keys* (password-protected). Restored
without it, HardyOS makes new signing keys by itself and apps pick them up
from the key list (`<issuer>/keys`); nobody has to set anything up again.

## Audit

Sign-ins (`oidc.signin`), consents (`oidc.consent`), sign-outs
(`oidc.signout`), app changes (`oidc.client.*`), revocations and refresh
token reuse (`oidc.token.*`), replayed codes (`oidc.code.replay`), settings
and key rotations are in Control Panel > Security.
