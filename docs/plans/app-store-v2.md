# App Store v2 and shared folders: build contract

This is the agreed design for finishing the App Store and adding shared
folders. Several people (agents) build it in parallel, so it fixes the names,
types and operations each part relies on. If a part needs to change something
here, say so in its summary rather than silently diverging.

Cade's decisions (2026-10-26) this implements:

- Shared folders come first (Media with Movies/TV/Music/Photos, Backups; home
  folders per user arrive with file sharing). File sharing later adds SMB, NFS,
  Time Machine, SFTP/WebDAV on top of the same shared folders.
- Apps: one-click install, settings changeable afterwards; pick which shared
  folders each app gets; admins install and choose who can use each app;
  updates only when an admin clicks Update, with a snapshot first and a way
  back; apps open as windows in the desktop; stop/start, logs, resource limits;
  uninstall keeps data; app settings go into settings backups.
- Catalog apps may use the GPU or the host network, clearly labelled.
  Uploaded packages, imported catalogs and custom Compose apps are sandboxed;
  an admin can loosen one app at a time (tick each extra permission, red
  warning, audited).
- Domain accounts can sign in to the desktop. App access is by HardyOS
  accounts, domain users and domain groups.
- First catalog: Jellyfin, Plex, Immich, Home Assistant, AdGuard Home,
  Vaultwarden, Paperless-ngx, Sonarr, Radarr, Prowlarr, qBittorrent, Bazarr,
  Jellyseerr, plus the existing KinCast and Apex RMM (PR #18).

## 1. Shared folders (`daemon/internal/shares`, runs in hardyd-priv)

A shared folder is a ZFS dataset `<pool>/shares/<id>` mounted at
`/mnt/<pool>/shares/<id>` (pools mount at `/mnt/<pool>`, `zfs.MountRoot`).

- `id`: 1-32 chars `^[a-z0-9][a-z0-9-]*$` (dataset-safe, derived from the name:
  "Media" -> `media`). Unique across pools.
- `name`: what people see, 1-40 chars, letters, digits, spaces, `.-_()'&`.
- Configuration lives on the dataset as ZFS user properties, so it travels
  with the pool (import on a reinstalled server keeps it):
  `org.hardyos:share=1`, `org.hardyos:name`, `org.hardyos:description`,
  `org.hardyos:access` (JSON array of rules), `org.hardyos:apps` (JSON, see
  below), `org.hardyos:recycle` (`on`/`off`), `org.hardyos:guest` (`on`/`off`).
- Dataset properties at creation: `acltype=posixacl`, `xattr=sa`,
  `aclinherit=passthrough`, `compression=lz4` (inherit if the pool sets one).
  Quota = ZFS `quota` (0 = none). Snapshots use the existing snapshot code
  where present; schedule is file sharing's job, not this one.
- Access rules (stored now, enforced on disk by POSIX ACLs; SMB enforcement
  arrives with file sharing): `{"kind":"user"|"group"|"everyone","name":"HOME\\alice","level":"read"|"write"|"none"}`.
  Domain principals are written `NETBIOS\name`. Domain users/groups can't be
  turned into ACL entries until the NAS resolves domain IDs (winbind, file
  sharing phase), so for now rules are stored and shown, and only app grants
  become ACL entries.
- App grants: each installed app has its own Linux user ID (see 2.2). Giving
  an app a shared folder adds `u:<uid>:rwX` (write) or `u:<uid>:r-X` (read)
  as both access and default ACL on the share root, and applies it
  recursively in the background (large libraries: don't block the request).
  `org.hardyos:apps` records `[{"app":"jellyfin","uid":30001,"level":"read"}]`
  so grants can be removed exactly.
- Starter set (one call, each optional): `media` "Media" with subfolders
  Movies, TV, Music, Photos; `backups` "Backups". Created on a chosen pool.
- Deleting a shared folder destroys the dataset: requires
  `confirm` = the folder's name, refused while an app uses it (names the apps).

Go API (implemented by the shares agent; the apps agent calls it through the
interface in `apps/contract.go`):

```go
type Manager struct{ Runner sysexec.Runner; Log *slog.Logger; Root string }
func (m *Manager) List(ctx) ([]Share, error)
func (m *Manager) Create(ctx, NewShare) (*Share, error)
func (m *Manager) Update(ctx, ShareUpdate) (*Share, error)
func (m *Manager) Delete(ctx, id, confirm string) error
func (m *Manager) CreateStarter(ctx, StarterArgs) ([]Share, error)
func (m *Manager) Folders(ctx, id, sub string) ([]string, error)   // subfolders, for pickers
// For apps:
func (m *Manager) Resolve(ctx, id, sub string) (hostPath string, err error) // real path, no symlinks, inside the share
func (m *Manager) GrantApp(ctx, id, app string, uid int, write bool) error
func (m *Manager) RevokeApp(ctx, app string) error                  // every share
```

Root operations (`priv/shares_ops.go`): `shares.list`, `shares.create`,
`shares.update`, `shares.delete`, `shares.starter`, `shares.folders`.
API (hardyd, admin only for changes, any signed-in user may list):
`GET/POST /shares`, `GET/PATCH/DELETE /shares/{id}`, `POST /shares/starter`,
`GET /shares/{id}/folders?path=`. Create/update/delete/starter are jobs
(`shares.create` etc.) and audited. Web: Control Panel > Shared Folders
(list, create, edit access + quota + recycle bin flag, delete with name
confirmation, starter-set card when there are none). Settings backups include
nothing extra (config is on the datasets).

## 2. Apps engine (`daemon/internal/apps`, hardyd-priv)

### 2.1 Manifest additions (format stays 1; all optional)

```json
"shares": [
  { "name": "MEDIA", "label": "Media library", "help": "Where your movies and shows are",
    "access": "read", "suggest": "media", "required": false }
],
"permissions": { "capabilities": [], "devices": [], "hostNetwork": false, "gpu": false }
```

- `shares[].name` `^[A-Z][A-Z0-9_]{0,23}$`; compose uses `${HARDY_SHARE_<NAME>}`
  as a bind source. The install dialog offers every shared folder; apps get
  whole shared folders only (no subfolder: `ShareChoice.path` must be `""`,
  decision 76), and `HARDY_SHARE_<NAME>` is the share's root. `suggest`
  preselects a share id if it exists. When none
  is chosen and it's not required, `HARDY_SHARE_<NAME>` points to an empty
  folder `${HARDY_APP_DATA}/.unshared/<name>`. `access` is the most the app
  gets; the admin may lower write to read.
- Policy: a bind source must be inside the data folder or be exactly the
  root of a share chosen for a declared share (not a folder in it; read
  grants force `read_only: true`), and no bind source may be inside another
  bind source of the same app across its services (decision 76).
- `hostNetwork`: allows `network_mode: host` on services. Declared ports are
  then fixed (no remapping); the install checks they're free.
- `gpu`: allows `/dev/dri` (render nodes) and NVIDIA device reservations
  (`deploy.resources.reservations.devices` with driver `nvidia`, capabilities
  `[gpu]`) — only if the server has that hardware (detect `/dev/dri/renderD*`,
  `/dev/nvidia0` at runtime; otherwise the reservation is dropped with a
  warning, never fail the install for lack of a GPU).

### 2.2 Variables added

`HARDY_UID`, `HARDY_GID`: the app's own user and group ID, allocated at first
install from 30000-30999 (lowest free, never reused while the app's data is
kept), stored in state. Catalog apps run their processes as it (`PUID`/`PGID`
or `user:`). Folders without an explicit owner default to it.
`HARDY_SHARE_<NAME>`: as above.

### 2.3 Sources and trust

`Source` = `catalog` (shipped with HardyOS), `upload`, `imported` (from an
imported catalog; `SourceName` = the catalog's name), `custom` (made from a
pasted Compose file). hardyd-priv decides `catalog` itself: only a package
whose SHA-256 matches a file in the shipped catalog folder (or the package it
verified at install, `catalogSHA256` in state) is a catalog app; the source
hardyd sends is a label for the others, and `catalog`/empty from hardyd
becomes `upload` (decision 75). Only `catalog` apps get `hostNetwork`, `gpu`, devices
and non-basic capabilities by declaring them. For other sources each of these
is refused unless listed in the request's `grants` (strings:
`hostNetwork`, `gpu`, `device:/dev/...`, `cap:NET_ADMIN`). Grants are stored
in state and shown on the app. hardyd only forwards grants from an admin who
ticked them, and audits them.

### 2.4 Limits

`Limits{MemoryMB int, CPUs float64}` (0 = none) for the whole app. Applied with
a systemd slice `hardyos-app-<id>.slice` (MemoryMax, CPUQuota) written under
`/run/systemd/system` (re-written at start) and `cgroup_parent` injected into
every service of the resolved file after the policy check.

### 2.5 Operations (all in `priv/apps_ops.go`)

Existing: `apps.status/ports/prepare/services/pull/up/start/stop/restart/logs/remove`.
`PrepareArgs` gains `Source`, `SourceName`, `Shares map[string]ShareChoice`,
`Grants []string`, `Limits *Limits`. New:

- `apps.reconfigure` `ReconfigureArgs{ID, Ports, Settings, Shares, Grants, Limits}`:
  like prepare with the installed package; the job then runs `apps.up`.
  Omitted fields keep current values; password settings left empty keep theirs.
- `apps.snapshot` `{id, reason}` -> `{snapshot}`: `zfs snapshot <pool>/apps/<id>@hardyos-<reason>-<UTC yyyymmdd-hhmmss>`;
  keeps the newest 3 `hardyos-update-*` snapshots, deletes older.
- `apps.snapshots` `{id}` -> `[{name, created, version}]` (version from a
  `org.hardyos:app-version` user property set on the snapshot).
- `apps.rollback` `{id, snapshot, confirm}`: stops the app, `zfs rollback -r`,
  starts it with the package and settings inside the snapshot, but with only
  the grants and shared folders it has both in the snapshot and now
  (decision 77); if the checks then fail, the app stays stopped, marked
  `blocked`, until an admin reconfigures it.
  `confirm` = app name.
- `apps.config` `{id}` -> current settings (passwords masked as `""` with
  `set: true`), ports, shares, grants, limits, uid, source — for the settings
  screen.

The `App` view gains: `source`, `sourceName`, `uid`, `shares`
(`[{name,label,share,path,access}]`, `path` always `""`), `grants`, `limits`,
`permissions` (plain-words list from `DescribePermissions`) and `blocked`
(omitted unless a rollback left the app needing a permission).

Update flow (hardyd job `apps.update`): `apps.snapshot reason=update` ->
`apps.prepare` (new package) -> pulls -> `apps.up`. If any step after the
snapshot fails, the job ends with the snapshot name so the UI offers
Roll back.

## 3. hardyd API and web (`daemon/internal/api`, `web/apps/shell`)

- `GET /apps` (existing) filtered for non-admins to apps they may use.
- App access: stored in hardyd's own database (not root state): table
  `app_access(app_id, kind, name)`; empty = everyone. `GET/PUT /apps/{id}/access`.
  Principals: HardyOS users (`alice`), domain users (`HOME\alice`), domain
  groups (`HOME\Family`), `everyone`.
- `GET /apps/{id}/config`, `PATCH /apps/{id}/config` (job `apps.reconfigure`),
  `POST /apps/{id}/update` (job), `GET /apps/{id}/snapshots`,
  `POST /apps/{id}/rollback` (job, confirm).
- Install dialog: shares step (pick a shared folder per declared share, no
  subfolder, show read/write), permissions step (labels for catalog
  apps; for non-catalog apps, unticked checkboxes with a red warning),
  limits (advanced), who can use it.
- Imported catalogs: `GET/POST/DELETE /apps/catalogs` (admin). A catalog is
  an https URL to `index.json`: `{"name","apps":[{"id","name","version","summary","url","sha256","icon"}]}`;
  hardyd fetches index and packages (size limits, sha256 must match), never
  hardyd-priv. Shown in Discover under the catalog's name with a
  "Third-party" label. Imported package refs carry the catalog's id
  (`catalogId`), which must list that sha; the install records it and
  updates follow it. Fetches refuse this server's own networks unless the
  catalog is marked "On my network" (decision 82).
- Custom app: App Store > Create an app: name, id, pasted compose YAML, the
  web port and other published ports, data folders; hardyd builds a
  `.hardyapp` (source `custom`) and runs the normal install.
- Opening apps as windows: the desktop is HTTPS, so an http app can't be
  framed directly. hardyd runs an HTTPS proxy per installed app with a web
  page: listen on `44300 + n` (allocated, stored in hardyd's database),
  same certificate as the desktop, proxies to `127.0.0.1:<webport>` including
  WebSockets, and removes `X-Frame-Options` / `frame-ancestors` so the
  desktop origin may frame it. Sign-in to HardyOS is required for the proxy:
  the desktop's session cookie must never reach an app, so a short-lived
  token in the first URL is swapped for a per-app proxy cookie. Ports do
  **not** isolate apps: browsers keep cookies per host, not per port, and
  SameSite treats every port of a host as the same site, so the desktop and
  every app share one cookie jar and are same-site to each other. Until
  per-app subdomains (with the reverse proxy) replace the ports, the proxy
  renames each app's cookies to `a_<app id>_<name>` and forwards only that
  app's, refuses cross-app requests (other Origin on changes and
  WebSockets, same-site non-navigations), and binds every proxy session to
  the desktop session cookie (decisions 80-82; residual risks in
  `docs/apps.md`). The desktop opens the app in a sandboxed window (iframe,
  no top navigation) with "Open in new tab".
- Settings backups: hardyd's backup includes app access, catalogs, proxy
  ports; root's apps state is on the pool already.

## 4. Desktop sign-in with domain accounts (`daemon/internal/auth`)

- If this server has a domain (DC status provisioned, or later joined as a
  member), the sign-in page accepts `alice`, `HOME\alice` or
  `alice@home.example.net`. Local HardyOS accounts win on a name clash
  without a domain prefix.
- Password check: Kerberos AS exchange against the domain's DCs
  (`github.com/jcmturner/gokrb5/v8`, pure Go, runs in hardyd), DCs from the
  domain status. Groups: via a hardyd-priv op `domain.user_groups {username}`
  using the existing directory helper.
- Role: admin if in `Domain Admins` or `HardyOS Admins` (created on demand
  in the domain by an admin action, not automatically); otherwise user.
  Disabled/locked domain accounts can't sign in. Group membership refreshed
  at each sign-in and at most every 10 minutes during a session.
- Sessions record `source=domain` and the principal `HOME\alice`.

## 5. Ownership (who edits what) and decision numbers

| Part | Owns | Decisions |
| --- | --- | --- |
| Shared folders | `internal/shares/`, `priv/shares_ops.go`, API `handlers_shares.go`, web `control-panel/SharedFolders*.tsx` | 55-59 |
| Apps engine | `internal/apps/` (not `contract.go` types' names), `priv/apps_ops.go` | 60-64, 75-77 (security review) |
| Apps API + web | `api/handlers_apps*.go`, `api/appproxy*.go`, `internal/appstore/`, `web/apps/shell/src/apps/store/` | 65-69, 80-82 (security review) |
| Catalog | `apps/catalog/*` | 70-71 |
| Domain sign-in | `internal/auth/` (domain parts), `priv/domain_ops.go` (one op), login UI | 72-74 |

Shared files everyone may append to: `api/openapi.yaml` (add your own paths and
schemas only, keep them in one block per part), `docs/decisions.md` (your
numbers only), `docs/architecture.md` (your own section), `.github/workflows/ci.yml`
(new jobs only), `cmd/*/main.go` (wiring lines only). Don't commit
`schema.gen.ts`/`index.ts` changes from other parts; regenerate with `make gen`.
