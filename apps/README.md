# HardyOS app catalog

Each folder in `catalog/` is one `.hardyapp` package (`hardyapp.json`,
`compose.yaml`, `icon.svg`) shipped in the App Store's Discover section.
(This file lives here rather than in `catalog/` because the catalog test
packs every entry of that folder.) `make build-apps` packs them; `hardyctl app-check apps/catalog/<id>` checks one. The format and
the rules a compose file must follow are in [docs/apps.md](../docs/apps.md);
shared folders, `HARDY_UID` and the `gpu`/`hostNetwork` permissions are in
[docs/plans/app-store-v2.md](../docs/plans/app-store-v2.md).

## Conventions

- **Pinned images.** Every image tag is pinned in `compose.yaml` (Immich's
  database and cache images by digest too, as Immich ships them). The package
  `version` is the upstream app's version; a package-only fix appends a
  number (`12.3` -> `12.3.0.1`). There are no `*_TAG` settings: settings keep
  their saved value on update, so a tag setting would keep the old version
  forever (decision 70). KinCast and Apex RMM keep their `latest` tag setting
  because their images publish only `latest`.
- **Own user.** Apps run as `${HARDY_UID}:${HARDY_GID}`: `user:` for images
  that support it, `PUID`/`PGID` (LinuxServer.io), `PLEX_UID`/`PLEX_GID`
  (Plex) or `USERMAP_UID`/`USERMAP_GID` (Paperless) for images that start as
  root and drop to that user. Folders without an `owner` belong to the app's
  user. Exceptions are listed per app.
- **Data** lives under `${HARDY_APP_DATA}`; libraries come from shared
  folders through `${HARDY_SHARE_<NAME>}`. Read-only shares are also bound
  `:ro` in the compose file.
- **Same paths in every media app** (decision 71): the Media library is
  `/media` and Downloads is `/downloads` inside Jellyfin, Plex, Sonarr,
  Radarr, Bazarr and qBittorrent, so no "remote path mapping" is needed.
  Apps reach each other through the server: `host.docker.internal` (set with
  `extra_hosts: host-gateway`) or the server's address, plus the other app's
  port.
- **Secrets** (database passwords, signing keys) use `"generate": "secret"`.
  Passwords a person must know (Paperless admin, Vaultwarden admin page,
  Plex claim code) are `password` settings.
- **Icons** are original: a rounded square in a HardyOS gradient (hue by
  category) with a generic glyph. Never use a project's own logo or wordmark.

## Apps

| App | Image | Shared folders | Permissions | Why |
| --- | --- | --- | --- | --- |
| Jellyfin | `jellyfin/jellyfin:12.3` | MEDIA read (`/media`) | gpu | Plays the library, never changes it; GPU for hardware transcoding (`/dev/dri`, NVIDIA) |
| Plex Media Server | `plexinc/pms-docker:1.43.5.11079-b3b13e506` | MEDIA read (`/media`) | gpu | As Jellyfin. Bridge networking with `ADVERTISE_IP`, so it needs the claim code (password setting) to link to the Plex account |
| Immich | `immich-app/immich-server` + `immich-machine-learning:v3.3.5`, `immich-app/postgres:14-vectorchord0.4.3-pgvectors0.2.0`, `valkey:9` | PHOTOS write (`/data`), EXISTING read (`/mnt/existing`, optional external library) | gpu | Immich owns its upload folder (originals, thumbnails, encoded video, DB backups); existing photos are only read. GPU for video transcoding; machine learning runs on the CPU |
| Home Assistant | `home-assistant/home-assistant:2026.10.4` | none | hostNetwork | Device discovery (mDNS, SSDP, broadcasts) needs the server's network; port 8123 fixed. Runs as root (the image doesn't support another user) |
| AdGuard Home | `adguard/adguardhome:v0.107.79` | none | hostNetwork | DNS on port 53 of the server's address and real client addresses in its logs. `--web-addr` pins the admin site to the WEB port. The DC has its own address (macvlan), so no clash on 53 |
| Vaultwarden | `vaultwarden/server:1.37.4` | none | none | Self-contained; listens on 8080 inside so it can run unprivileged. Admin page only with a password setting |
| Paperless-ngx | `paperless-ngx/paperless-ngx:3.3.4`, `postgres:18`, `valkey:9-alpine` | DOCUMENTS write (archive), CONSUME write (inbox; files are removed after import) | none | Documents should live in a shared folder that's backed up; the inbox must be writable so consumed files can be deleted |
| Sonarr | `linuxserver/sonarr:4.0.20` | MEDIA write, DOWNLOADS write | none | Moves and renames finished episodes from Downloads into Media |
| Radarr | `linuxserver/radarr:6.4.4` | MEDIA write, DOWNLOADS write | none | As Sonarr, for movies |
| Prowlarr | `linuxserver/prowlarr:2.6.5` | none | none | Only talks to indexers, Sonarr and Radarr |
| qBittorrent | `linuxserver/qbittorrent:5.3.0` | DOWNLOADS write (`/downloads`) | none | Saves downloads. Listens on the published torrent port number inside the container (`TORRENTING_PORT`) |
| Bazarr | `linuxserver/bazarr:1.6.2` | MEDIA write | none | Saves subtitle files next to the videos |
| Seerr (id `jellyseerr`) | `seerr-team/seerr:v3.5.1` | none | none | Jellyseerr merged into Seerr; the id stays `jellyseerr`. Runs as the image's own user 1000 (its config folder is owned by 1000) because other users aren't documented |
| KinCast | `hardynetworks/kintube:${KINCAST_TAG}` | none | none | Unchanged |
| Apex RMM | `hardynetworks/apex-rmm:${APEX_TAG}`, `rustdesk-server:1.1.16` | none | none | RustDesk server pinned (was `latest`) |

All images publish amd64 and arm64.

## Known limits

Things these apps would like that a package can't say yet:

- **AdGuard Home's port 53** can't be declared (manifest ports are
  1024-65535), so the install can't check it's free. It's described in the
  app's text instead.
- **GPU group.** Apps that run as their own user need the host's `render`
  group (`group_add`) to open `/dev/dri/renderD*`, and its number differs per
  server. The engine should add it when it keeps `/dev/dri` for a `gpu` app.
- **Hardware-specific images.** Immich's accelerated machine learning is a
  different image (`-cuda`, `-openvino`), which a package can't pick per
  server; it runs on the CPU.
- **USB sticks and Bluetooth** for Home Assistant: devices are fixed in the
  manifest (and must exist), and Bluetooth needs the host's D-Bus socket.
- **A TCP and UDP port pair** (qBittorrent) can't be tied to the same number.
- **The app's own public address.** Apps that check the browser's origin
  (Paperless-ngx's sign-in, Vaultwarden's `DOMAIN`, Seerr) only know
  `http://HARDY_HOST:port`, not the desktop's HTTPS proxy address.
- **Hardlinks** between Downloads and Media: they're separate shared folders
  (and separate mounts), so Sonarr and Radarr copy finished downloads instead
  of hardlinking them.
