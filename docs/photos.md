# Photos (Immich)

Phase 7 part C. **Photos** on the desktop is [Immich](https://immich.app),
the catalog app, set up and kept set up by HardyOS: everyone signs in with
their HardyOS account, each person's phone backs up into their own
library, a family folder can be shown to the whole family, photos already
on the server are indexed where they are, and face, object and place
search run on the server (on a graphics card when there is one free).
Settings are in **Control Panel › Photos**; how it's built is in
[architecture.md](architecture.md#photos-immich), the choices in
[decisions.md](decisions.md) (270 onwards; the security review's in 285
onwards).

## Setting it up

1. **Make the shared folders** (Control Panel › Shared Folders):
   - **Photos**, for Immich's own storage. Let only administrators open it
     over the network: it holds everyone's phone backups (each person's
     in a folder of their own, but files are files).
   - optionally **Family Photos**, which everyone in the family may write
     to (over SMB, the File Manager or WebDAV).
   - The folders with photos you already have (Media, a disk copied from
     an old PC...) don't move.
2. **Install Immich** (App Store › Discover). In the shared folders step:
   - *Where Immich keeps photos*: **Photos**.
   - *Existing photos* (and the two *More existing photos*): folders with
     photos you already have, read-only.
   - *Family photos*: **Family Photos**, read-only.
3. **Publish it** for phones: Control Panel › Photos › **Phone backup from
   anywhere** (needs Remote Access with a base domain,
   [remote-access.md](remote-access.md)).
4. **Control Panel › Photos**: choose whose library each existing folder
   joins, turn the family library on and say who's in the family. **Save
   and apply.**
5. **Phones**: install the Immich app, enter the HTTPS address Control
   Panel › Photos shows (`https://immich.<base domain>`), tap **Sign in
   with HardyOS**, confirm on HardyOS's page, and turn on backup.

Immich listens only on the server itself (`127.0.0.1`, port 2283 by
default): people reach it through HardyOS, in the desktop's **Photos**
window (the window proxy) or at its published address (the app gateway).
Those are also where HardyOS keeps a few requests away from Immich (see
[Accounts](#accounts)). There is no `http://<server>:2283` any more; phones
use the HTTPS address, at home too.

Photos applies everything in a job (`photos.sync`, in the job list and the
audit log as HardyOS's own). It runs again by itself after Immich is
installed, updated or reconfigured, when publishing or the domain
changes, when a VM stops (a GPU may be back), right after a HardyOS
account or Immich's "Who can use it" changes, when the five-minute check
sees accounts, roles or groups change or someone new signs in to Immich,
and every six hours. Until HardyOS has made Immich's administrator (a
fresh install) it tries again every five minutes.

## Signing in

With **Sign in with HardyOS** on (the default), HardyOS registers a sign-in
client for Immich with its own provider (Control Panel › Sign-in lists it
as *Photos (Immich)*, kept by Photos) and configures Immich's OAuth
through Immich's API:

| Immich setting | Value |
| --- | --- |
| Issuer | `https://sso.<base domain>` |
| Client | HardyOS's client id and secret (the secret sealed in hardyd's database, never shown) |
| Scope | `openid email profile hardyos_photos` (only this client may ask for `hardyos_photos`) |
| Auto register | on (HardyOS has normally made the account already, see below) |
| Auto launch | off by default (Control Panel › Photos) |
| Role claim | `hardyos_photos_role`: HardyOS administrators are Immich administrators, everyone else ordinary users |
| Storage label claim | `hardyos_storage_label`: the person's HardyOS name, so their files are in `library/<name>/` (`admin`, `family`, `user`, `hardyos…` and `unlinked…` get a `u-` in front) |
| Default storage quota | Control Panel › Photos (none by default) |
| Mobile redirect override | `https://immich.<base>/api/oauth/mobile-redirect` |
| Password login | off (on again with **Also allow Immich passwords**) |

- **Who may sign in** is the app's App Store list (App Store › Immich ›
  Who can use it): HardyOS refuses anyone else at its sign-in page, before
  Immich hears of them, and at every token refresh.
- **Why `sso.<base>`**: Immich's server talks to the provider itself and
  checks its certificate. The desktop's own certificate is self-signed;
  NetBird's proxy serves `sso.<base>` with a real one. Without a base
  domain, Immich keeps its own passwords and Control Panel › Photos says
  why. Immich's server reaches `sso.<base>` through the internet.
- **E-mail addresses**: Immich tells people apart by address. HardyOS's
  own accounts without one get `<name>@local.hardyos.invalid` (only for
  Immich). Domain accounts get their address or their user principal
  name; a domain account with neither can't use Immich (HardyOS never
  makes one up for it). Two HardyOS accounts with the same address: neither
  gets an Immich account until one is changed.
- **Immich's administrator**: HardyOS makes Immich's first administrator
  itself (`admin@service.hardyos.invalid`, a random password sealed in
  hardyd's database) right after the install, before anything else, and an
  API key for it with only what Photos needs (settings, accounts,
  libraries). Nobody signs in as it. Immich's own first sign-up page is
  refused by HardyOS's proxies, and Immich listens only on the server, so
  nobody else can get there first; if an Immich HardyOS installed with new
  data has another administrator anyway, Photos stops, says so in Control
  Panel › Photos and sends a critical alert (`security.photos`).
- **Immich set up before Photos** (installed in an earlier HardyOS with
  data kept, its administrator already made): Control Panel › Photos asks
  for an API key of that administrator (Immich › Account Settings › API
  Keys, all permissions). HardyOS leaves that administrator's account as
  it is.
- **The phone app's sign-in is always confirmed**: when a sign-in goes to
  Immich's mobile redirect, HardyOS's page asks "Continue to Photos
  (Immich)?" even if the browser is already signed in, so a link someone
  sends can't sign a phone in silently.
- From the internet, HardyOS's own rules apply: wrong passwords slow down;
  **administrators are refused** unless Control Panel › Sign-in ›
  *Administrators can sign in through public SSO* is on.

### Accounts

Immich links a first sign-in to the account that has the same e-mail
address, and lets people change their own address and unlink their
sign-in. Left alone, someone could take an address a HardyOS account will
sign in with and get that person's sign-in. So, while sign-in with
HardyOS is on:

- **Every person who may use Immich has an account before their first
  sign-in**, made by HardyOS with their address (and a random password
  nobody knows). HardyOS records it for that person only (by their sign-in
  subject) and finds accounts by subject, never by address.
- **No other account may hold a HardyOS address**: an Immich account
  HardyOS didn't make and nobody signed in to with HardyOS that has the
  address of a HardyOS account (or any `…hardyos.invalid` address) is
  renamed to `unlinked-<id>@hardyos.invalid` and flagged in Control Panel
  › Photos (and the audit log).
- **Addresses come back**: a signed-in account's address is set back to
  its person's HardyOS one at every sync.
- **HardyOS's proxies refuse** changing one's own address or password in
  Immich (`PUT /api/users/me` with `email` or `password`) and unlinking
  the HardyOS sign-in (`POST /api/oauth/unlink`).
- **Losing Photos loses Immich**: the Immich account of someone whose
  HardyOS account is deleted, turned off, or no longer on "Who can use
  it" is suspended: its address moved aside, its password made random,
  administrator rights removed, then soft-deleted in Immich, which ends
  its sessions and API keys. Nothing in it is deleted: when the person may
  use Photos again, HardyOS restores it (address and all). Immich deletes
  soft-deleted accounts for good after its own delay (Administration ›
  Settings › User Settings); Photos makes that at least 30 days (Immich's
  default is 7) and never shortens it. Make it longer if people lose
  access for longer and should get their photos back.
- **Administrators follow HardyOS**: Immich's administrators are exactly
  HardyOS's (checked at every sync, not only at sign-in).
- **Passwords**: while Immich's own passwords are off, every person's
  Immich password is replaced with a random one at every sync.

All of these changes are in the audit log as HardyOS's own
(`photos.account.*`, `photos.family.*`).

### In a desktop window

**Photos** opens Immich in a window (through the window proxy at home, at
its published address when the desktop is used through Remote Access).
HardyOS's sign-in page refuses to be shown inside another page (it would
make tricking people into signing in easy), so the first sign-in happens
in a tab of its own: the window's **Sign in** button. After that the
window has Immich's session too. The desktop's address with the window
proxy's port (`https://<server name>:<port>`) is one of the client's
redirect addresses; at another address (an IP address), use the published
one or Immich's own tab.

## Phones

The Immich app talks to Immich's API with Immich's own tokens, so nothing
may ask for another sign-in in front of it: HardyOS's gateway sign-in
(**Ask for a HardyOS sign-in too**) answers the app's requests with a
redirect to a web page, and NetBird's SSO in front does the same. Photos
therefore publishes Immich (button **Phone backup from anywhere**) as:

- **public**, **None** in front, **HardyOS sign-in off**: Immich's own
  sign-in, which is HardyOS's through OAuth, protects it. Anyone on the
  internet reaches Immich's sign-in page and API (through the app gateway,
  which still refuses the requests listed under Accounts).
- or **NetBird only** (Control Panel › Remote Access), with HardyOS sign-in
  off: phones need the NetBird app too, and nothing is on the internet.

Phones always use that HTTPS address, at home too.

Signing in from the phone: the app asks Immich to start an OAuth sign-in
for `app.immich:///oauth-callback`; Immich replaces that with
`https://immich.<base>/api/oauth/mobile-redirect` (HardyOS's provider
takes https redirect addresses only, matched exactly), the phone's browser
signs in at `sso.<base>` and confirms, and Immich's mobile redirect hands
the code back to the app. Control Panel › Photos shows when Immich is
published in a way the app can't use.

## Libraries

- **Each person's own**: phone backups and uploads. Immich keeps them in
  the Photos shared folder, under `library/<HardyOS name>/<year>/...`
  (Immich's storage template, turned on by Photos), next to thumbnails,
  converted videos and Immich's database backups. In Immich only the
  owner sees them (and whoever they share with), and Immich's
  administrators (below).
- **Existing photos**: each folder listed in Control Panel › Photos becomes
  an Immich *external library* owned by one person, who must be allowed to
  use Photos. Immich reads it where it is (mounted read-only: it can't
  change, move or delete anything) and looks for new and removed files
  every few hours (6 by default) and, if asked, as they change. Removing
  the folder from the list removes the library from Immich; the files
  stay. A library belongs to the person, not the account row: when a
  HardyOS account turns out to be someone else's (a domain name given to
  a new directory object), the old library goes and the new person gets a
  new one.
- **The family library**: Immich's external libraries belong to one
  account, and Immich has no shared libraries. HardyOS makes an Immich
  account of its own, **Family Photos** (`family@service.hardyos.invalid`,
  password sealed, never signed in to by people, always the account whose
  id HardyOS recorded), gives it an external library on the *Family
  photos* folder, and shares that account with each family member as an
  Immich **partner**. Members see it under Sharing › Partners and can show
  it on their timeline (Immich asks each person; HardyOS can't turn that
  on for them). Family members are the people in the list in Control
  Panel › Photos (users, domain users, domain groups) who may also use
  Immich, or everyone who may use Immich when the list is empty; they're
  removed when they leave the list; partners someone added in Immich by
  hand stay.

### Links out of a shared folder

Immich's crawler follows symbolic links, and inside Immich's container a
link resolves against the container's own folders: a link in an
existing-photos folder pointing at `/data/library/alice` would put Alice's
phone backups into someone else's library. So before every sync HardyOS
looks through each shared folder a library uses (a named root operation,
`shares.links`, never following links itself) for links whose target is
absolute, missing, or outside the folder, and:

- excludes each from the libraries on that folder (Immich's exclusion
  patterns), or
- doesn't make (and removes) the library when there are more than 200,
  when the folder is too big to check within ten minutes (5 million
  entries), or when it couldn't be checked, saying why in Control Panel ›
  Photos.

Over SFTP, links can't be made at all (`internal-sftp -P symlink,hardlink`);
over SMB neither (`unix extensions = no`). NFS clients and other apps
that may write to the folder can make them; HardyOS catches those at the
next sync (a link made between two syncs is followed by Immich's own scan
until then: give apps write access to existing-photos folders only when
you trust them).

### Who sees what

- A person's phone backups: them, and Immich's administrators (HardyOS's
  administrators). Immich doesn't show administrators other people's
  photos, but an administrator can: make an external library of any
  folder in Immich's container, including the Photos folder's
  `library/<name>/`; change people's settings. At the file level, anyone
  who can open the Photos shared folder can read everything in it, so keep
  it administrators-only.
- An existing-photos library: its owner in Immich, and administrators. The
  folder itself is as private as its shared folder is.
- Family photos: every family member (as partners of the family account).

## Face, object and place search

Immich's machine learning always runs on the processor
(`immich-machine-learning`). When the server has a graphics card Docker
apps can use, Photos also turns on Immich's accelerated service for it
(amd64 servers only):

| GPU (driver) | Service | Image |
| --- | --- | --- |
| NVIDIA (`nvidia`, with the container toolkit) | `immich-machine-learning-cuda` | `-cuda` |
| Intel (`i915`, `xe`) | `immich-machine-learning-openvino` | `-openvino` |
| AMD (`amdgpu`, `/dev/kfd`) | `immich-machine-learning-rocm` | `-rocm` |

Immich is given both addresses, the accelerated one first; it switches to
the processor by itself whenever the first doesn't answer. **Automatic**
prefers a card no VM uses or is set up to take, then NVIDIA, Intel, AMD.
A card lent to a VM (Virtual Machines, GPU passthrough) leaves the
accelerated service without its device: Immich uses the processor, and
when the VM stops and the card is back with the server, Photos starts the
service again (after the VM job, or within five minutes). The service's
image (several GB) is downloaded only when it's turned on. Video
conversion keeps using the graphics chip through the server container
(Immich › Administration › Video Transcoding). AMD's compute device
(`/dev/kfd`) is its own permission in the package (`rocm`, grant
`gpu.rocm`), apart from the graphics card (`gpu`).

Places (reverse geocoding) run in Immich itself; maps load tiles from
Immich's tile server.

## Backups

- **Immich's database** is in the app's dataset (`<pool>/apps/immich`).
  Right before a cloud backup of the app takes its snapshot, HardyOS runs
  the package's backup dump: `pg_dump` in the database container, as the
  app's user, into `db-dump/immich.dump` in the app's folder (at most 30
  minutes; a failed dump is a warning on the backup, which goes on). The
  version then holds a consistent dump next to the database files (which
  a ZFS snapshot holds crash-consistent, like after a power cut). Photos
  also keeps Immich's own nightly dump on (02:00, the last 14, in
  `backups/` of the Photos shared folder), the copy Immich's own restore
  uses.
- **Photos and videos** are in the Photos shared folder: back that folder
  up (replication or cloud backups of shared folders) as well as the app.
  Existing photos and the family folder are backed up as the shared
  folders they are.
- Local app snapshots (before updates) and replication don't run the
  dump; they rely on the crash-consistent copy and Immich's nightly dump.

## API

| Call | Who | What |
| --- | --- | --- |
| `GET /photos` | signed in | Installed, may this person open it, SSO on, published address |
| `GET /photos/settings` | admin | Settings, the last sync's status, the app's shared folders |
| `PUT /photos/settings` | admin | Save and apply (job `photos.settings`) |
| `POST /photos/sync` | admin | Apply now (job `photos.sync`) |
| `POST /photos/link` | admin | Link an Immich set up before Photos with an administrator's API key (job `photos.link`; the key only in memory, then sealed) |

## Troubleshooting

- **"Immich can't reach HardyOS's sign-in"**: Immich's server must resolve
  and reach `https://sso.<base>` (through the internet). Check Remote
  Access › Check setup; `sso` must be published.
- **The phone app shows a web page instead of signing in**: Immich is
  published with a sign-in in front; use **Phone backup from anywhere**.
- **Someone can't sign in**: they aren't in App Store › Immich › Who can
  use it, they're an administrator signing in from the internet, or
  they're a domain account without an e-mail address.
- **An account is flagged "renamed"**: it held a HardyOS person's address
  without being theirs. Check who made it (Immich › Administration ›
  Users) and delete it if nobody should have it.
- **An existing-photos library shows a problem**: Immich wasn't given that
  shared folder (App Store › Immich › Settings), its owner's account is
  gone or may not use Photos, or the folder has links leading out of it.
- **"Immich was set up before Photos"**: link it with an API key.
- **"Immich got an administrator HardyOS didn't make"**: on an Immich
  HardyOS installed fresh, that's someone else's doing. Remove Immich with
  its data and install it again (or link it, if you made it yourself).
