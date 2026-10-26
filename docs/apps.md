# One-click apps (.hardyapp)

HardyOS installs Docker apps from `.hardyapp` packages: a small file that
describes an app and how to run it. Apps that ship with HardyOS are in the
App Store's **Discover** section; anyone with an administrator account can
also upload a package (App Store › Upload a package).

## What's in a package

A `.hardyapp` is a gzipped tar with these files at the top level:

| File | Required | What it is |
| --- | --- | --- |
| `hardyapp.json` | yes | The manifest: name, version, ports, settings, folders, permissions |
| `compose.yaml` | yes | A Docker Compose file using the variables HardyOS provides |
| `icon.svg` or `icon.png` | yes | The icon named in the manifest (at most 128 KB) |
| `README.md`, `LICENSE` | no | Kept with the package, not used |

Limits: 512 KB compressed, 2 MB unpacked, regular files only.

Build one with `hardyctl app-pack <folder>` (or `make build-apps` for the
catalog in `apps/catalog/`) and check it with `hardyctl app-check`.

## The manifest

```json
{
  "format": 1,
  "id": "kincast",
  "name": "KinCast",
  "version": "1.0.0",
  "summary": "Your family's private YouTube.",
  "description": "Longer text for the install dialog.",
  "publisher": "Hardy Networks",
  "website": "https://github.com/hardynetworks/kintube",
  "icon": "icon.svg",
  "arch": ["amd64", "arm64"],
  "minMemoryMB": 2048,
  "web": { "port": "WEB", "path": "/", "scheme": "http" },
  "ports": [
    { "name": "WEB", "label": "Website", "default": 8095 },
    { "name": "RTMP", "label": "Live streaming", "default": 1935, "protocol": "tcp" }
  ],
  "settings": [
    { "env": "SESSION_SECRET", "generate": "secret" },
    { "env": "MAX_UPLOAD_GB", "label": "Largest upload (GB)", "type": "number", "default": "20", "required": true },
    { "env": "X264_PRESET", "label": "Processing speed", "type": "select", "options": ["veryfast", "fast"], "default": "veryfast" }
  ],
  "folders": [
    { "path": "postgres", "mode": "0700" },
    { "path": "media", "owner": "1000:1000", "mode": "0755" }
  ],
  "permissions": { "capabilities": [], "devices": [] }
}
```

- **id**: 2–32 lowercase letters, digits and dashes. It names the app's
  dataset (`<pool>/apps/<id>`) and Compose project (`hardyos-<id>`).
- **version**: compared number by number (`1.10.0` is newer than `1.9.2`); a
  catalog version newer than the installed one shows as an update.
- **ports**: every host port the app publishes, 1024–65535. The install
  dialog offers the default, or the next free port if it's taken. The
  compose file must publish exactly these, through `${HARDY_PORT_<NAME>}`.
- **web**: which port is the app's web page, for the **Open** button.
- **settings**: become environment variables for the compose file. Types are
  `text`, `number`, `boolean` (`"true"`/`"false"`), `select` and `password`.
  `"generate": "secret"` makes a random 64-character password at the first
  install and keeps it across updates and reinstalls; it's never shown.
  Values can't contain single quotes or line breaks. Names starting with `HARDY_`
  belong to HardyOS.
- **folders**: created under the data folder before the app starts, with
  the owner (`uid:gid`) and mode the containers need.
- **permissions**: capabilities and devices the app needs beyond a plain
  container, shown to the person installing it. Only the allowlist in
  `daemon/internal/apps/policy.go` is available: for example `NET_ADMIN`,
  `/dev/net/tun`, `/dev/dri` and USB serial sticks. Never `SYS_ADMIN` or
  similar.

## Variables HardyOS provides

| Variable | Value |
| --- | --- |
| `HARDY_APP_ID` | The app's id |
| `HARDY_APP_DATA` | The app's data folder: put every bind mount under it |
| `HARDY_HOST` | The server's name or address as the installer reached it |
| `HARDY_TZ` | The server's time zone |
| `HARDY_PORT_<NAME>` | The host port chosen for each manifest port |

## What the compose file may do

HardyOS runs `docker compose config` and checks the result (with includes,
`extends` and env files already applied), so what's checked is exactly what
runs. Anything not allowed is refused:

- No `privileged`, no `network_mode`, `pid`, `ipc`, `uts` or `cgroup` set to
  `host`, no joining containers or networks outside the app.
- Bind mounts only inside `${HARDY_APP_DATA}`, with private propagation. No
  named volumes (data goes in folders HardyOS can snapshot); anonymous
  volumes and tmpfs are fine.
- Published ports only as declared in the manifest.
- Capabilities and devices only as declared in the manifest's permissions.
- `security_opt` only `no-new-privileges`; sysctls only `net.*`; logging
  only `json-file`, `local`, `journald` or `none`; bridge networks only.
- No `build`, `container_name`, `secrets`, `configs`, GPU reservations or
  privileged lifecycle hooks.

HardyOS sets `restart: unless-stopped` (unless the app chose another policy)
and the labels `org.hardyos.app` and `org.hardyos.app.version` on every
container. Before every start it resolves each bind mount's real path, so a
container can't swap a folder for a link to somewhere else.

## Where things live

The first install asks which pool apps go on. HardyOS then creates:

- `<pool>/docker`: Docker's data (images and containers), not
  auto-snapshotted. Docker is off at boot and started by `hardyd-priv` once
  the pool is mounted, so boot environments never hold app data.
- `<pool>/apps/<id>`: one dataset per app. `data/` is `HARDY_APP_DATA`;
  `.hardyos/` (root only) holds the manifest, compose file, the resolved
  and checked compose file that actually runs, `app.env` with the settings
  and passwords, and `state.json`.

Removing an app keeps its dataset unless "Also delete its data" is ticked.
Installing it again picks the data and passwords back up.

## How installing works

1. `POST /apps/plan`: hardyd reads the package and asks `hardyd-priv` for
   free ports.
2. `POST /apps/install` starts an `apps.install` job. Password settings go
   to the job through an in-memory reference, not its parameters.
3. The job calls `hardyd-priv` to prepare the app (dataset, files, compose
   check), pull each image (retrying; if a registry is unreachable and the
   image is already on the server, that copy is used), and start it.

Every step is a named operation in `hardyd-priv` (`apps.prepare`,
`apps.pull`, `apps.up`, ...) with checked arguments. There is no way to run
an arbitrary compose file or command.

## Screens

![My apps](images/app-store/my-apps.png)
![Installing an app](images/app-store/install.png)
