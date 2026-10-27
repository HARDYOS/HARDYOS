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
desktop's own address), HardyOS doesn't ask for the password again.

## What apps learn about you

| Claim | Example | Scope |
| --- | --- | --- |
| `sub` | `6f9619ff-8b86-d011-b42d-00c04fc964ff` | always (a domain account's objectGUID: it never changes, not even on a rename) |
| `name` | `Alice Hardy` | `profile` |
| `preferred_username` | `alice` | `profile` |
| `email`, `email_verified` | `alice@example.net`, `true` | `email` (without an address in Domain > Users: `alice@home.example.net`, unverified) |
| `groups` | `["HOME\\Domain Users", "HOME\\Family"]` | `groups` or `profile` |
| `hardyos_admin` | `true` | `groups` or `profile` |

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
