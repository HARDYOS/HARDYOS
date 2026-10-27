# Photos (Immich)

Phase 7 part C. **Photos** on the desktop is [Immich](https://immich.app),
the catalog app, set up and kept set up by HardyOS: everyone signs in with
their HardyOS account, each person's phone backs up into their own
library, a family folder can be shown to the whole family, photos already
on the server are indexed where they are, and face, object and place
search run on the server (on a graphics card when there is one free).
Settings are in **Control Panel › Photos**; how it's built is in
[architecture.md](architecture.md#photos-immich), the choices in
[decisions.md](decisions.md) (270 onwards).

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
3. **Publish it** if phones should back up away from home: Control Panel ›
   Photos › **Phone backup from anywhere** (needs Remote Access with a
   base domain, [remote-access.md](remote-access.md)).
4. **Control Panel › Photos**: choose whose library each existing folder
   joins, turn the family library on and say who's in the family. **Save
   and apply.**
5. **Phones**: install the Immich app, enter the server address Control
   Panel › Photos shows (`https://immich.<base domain>` when published,
   `http://<server>:2283` at home), tap **Sign in with HardyOS**, and turn
   on backup.

Photos applies everything in a job (`photos.sync`, in the job list and the
audit log as HardyOS's own). It runs again by itself after Immich is
installed, updated or reconfigured, when publishing changes, when a VM
stops (a GPU may be back), when someone new signs in to Immich, and every
six hours.

## Signing in

With **Sign in with HardyOS** on (the default), HardyOS registers a sign-in
client for Immich with its own provider (Control Panel › Sign-in lists it
as *Photos (Immich)*, kept by Photos) and configures Immich's OAuth
through Immich's API:

| Immich setting | Value |
| --- | --- |
| Issuer | `https://sso.<base domain>` |
| Client | HardyOS's client id and secret (the secret sealed in hardyd's database, never shown) |
| Scope | `openid email profile hardyos_photos` |
| Auto register | on: a person's Immich account is made at their first sign-in |
| Auto launch | off by default (Control Panel › Photos) |
| Role claim | `hardyos_photos_role`: HardyOS administrators are Immich administrators, everyone else ordinary users, checked at every sign-in |
| Storage label claim | `hardyos_storage_label`: the person's HardyOS name, so their files are in `library/<name>/` |
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
- **People without an e-mail address** (HardyOS accounts with none set, in
  Users) get `<name>@hardyos.invalid`, which only tells them apart in
  Immich. Domain accounts get their address or their user principal name.
- **Accounts made ahead**: a person who has a library of existing photos
  gets their Immich account from HardyOS before they ever sign in (a random
  password nobody knows); their first sign-in with HardyOS links it by
  e-mail address.
- **Immich's administrator**: HardyOS makes Immich's first administrator
  itself (`hardyos-admin@hardyos.invalid`, a random password sealed in
  hardyd's database) and an API key for it with only what Photos needs
  (settings, accounts, libraries). Nobody signs in as it.
- **Immich set up before Photos** (installed in an earlier HardyOS, its
  administrator already made): Control Panel › Photos asks for an API key
  of that administrator (Immich › Account Settings › API Keys, all
  permissions). Existing accounts are linked by e-mail address the first
  time each person signs in with HardyOS; an account whose address
  differs from the person's HardyOS one can be linked from Immich's
  Account Settings › OAuth.
- From the internet, HardyOS's own rules apply: wrong passwords slow down;
  **administrators are refused** unless Control Panel › Sign-in ›
  *Administrators can sign in through public SSO* is on.

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

## Phones from anywhere

The Immich app talks to Immich's API with Immich's own tokens, so nothing
may ask for another sign-in in front of it: HardyOS's gateway sign-in
(**Ask for a HardyOS sign-in too**) answers the app's requests with a
redirect to a web page, and NetBird's SSO in front does the same. Photos
therefore publishes Immich (button **Phone backup from anywhere**) as:

- **public**, **None** in front, **HardyOS sign-in off**: Immich's own
  sign-in, which is HardyOS's through OAuth, protects it. Anyone on the
  internet reaches Immich's sign-in page and API.
- or **NetBird only** (Control Panel › Remote Access), with HardyOS sign-in
  off: phones need the NetBird app too, and nothing is on the internet.

Signing in from the phone: the app asks Immich to start an OAuth sign-in
for `app.immich:///oauth-callback`; Immich replaces that with
`https://immich.<base>/api/oauth/mobile-redirect` (HardyOS's provider
takes https redirect addresses only, matched exactly), the phone's browser
signs in at `sso.<base>`, and Immich's mobile redirect hands the code back
to the app. Control Panel › Photos shows when Immich is published in a way
the app can't use.

## Libraries

- **Each person's own**: phone backups and uploads. Immich keeps them in
  the Photos shared folder, under `library/<HardyOS name>/<year>/...`
  (Immich's storage template, turned on by Photos), next to thumbnails,
  converted videos and Immich's database backups. In Immich only the
  owner sees them (and whoever they share with).
- **Existing photos**: each folder listed in Control Panel › Photos becomes
  an Immich *external library* owned by one person. Immich reads it where
  it is (mounted read-only: it can't change, move or delete anything) and
  looks for new and removed files every few hours (6 by default) and,
  if asked, as they change. Removing the folder from the list removes the
  library from Immich; the files stay.
- **The family library**: Immich's external libraries belong to one
  account, and Immich has no shared libraries. HardyOS makes an Immich
  account of its own, **Family Photos** (`hardyos-family@hardyos.invalid`,
  password sealed, never signed in to by people), gives it an external
  library on the *Family photos* folder, and shares that account with each
  family member as an Immich **partner**. Members see it under Sharing ›
  Partners and can show it on their timeline (Immich asks each person;
  HardyOS can't turn that on for them). Family members are the people in
  the list in Control Panel › Photos (users, domain users, domain groups)
  who may also use Immich, or everyone who may use Immich when the list is
  empty. People are added once they've signed in to Immich with HardyOS
  (HardyOS checks their HardyOS account behind the sign-in), and removed
  when they leave the list; partners someone added in Immich by hand stay.

### Who sees what

- A person's phone backups: only them in Immich (Immich's model:
  administrators manage accounts, they don't browse others' photos). At
  the file level, anyone who can open the Photos shared folder can read
  everything in it, so keep it administrators-only.
- An existing-photos library: its owner in Immich. The folder itself is as
  private as its shared folder is.
- Family photos: every family member (as partners of the family account).
- Immich administrators (HardyOS administrators) can make external
  libraries of any folder Immich was given, so they can see existing
  photos and the family folder, but not phone backups.

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
(Immich › Administration › Video Transcoding).

Places (reverse geocoding) run in Immich itself; maps load tiles from
Immich's tile server.

## Backups

- **Immich's database** is in the app's dataset (`<pool>/apps/immich`);
  ZFS snapshots of it are atomic, so a snapshot (app update snapshots,
  replication, cloud backups of the app) holds a database PostgreSQL
  recovers like after a power cut. On top of that, Photos keeps Immich's
  own nightly database dump on (02:00, the last 14, in
  `backups/` of the Photos shared folder), the copy Immich's own restore
  uses.
- **Photos and videos** are in the Photos shared folder: back that folder
  up (replication or cloud backups of shared folders) as well as the app.
  Existing photos and the family folder are backed up as the shared
  folders they are.
- Phase 6 app backups don't run commands before a backup yet; a
  `pg_dump` in the database container right before each app backup (a
  named root operation, `apps.dump`) is a follow-up. Until then the dump
  can be up to a day old, and the snapshot copy is crash-consistent.

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
  use it, or they're an administrator signing in from the internet.
- **An existing-photos library shows a problem**: Immich wasn't given that
  shared folder (App Store › Immich › Settings), or its owner's account is
  gone.
- **"Immich was set up before Photos"**: link it with an API key.
