-- App Store v2 (docs/plans/app-store-v2.md section 3). These live in hardyd's
-- database, so settings backups carry them.

-- Who may use each installed app. No rows for an app = everyone signed in.
-- kind: user (HardyOS "alice" or domain "HOME\alice"), group ("HOME\Family"),
-- everyone (name '').
CREATE TABLE app_access (
    app_id TEXT NOT NULL,
    kind   TEXT NOT NULL CHECK (kind IN ('user', 'group', 'everyone')),
    name   TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (app_id, kind, name)
);

-- Imported (third-party) app catalogs: an https URL to an index.json.
CREATE TABLE app_catalogs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    url        TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL UNIQUE,
    added_at   TEXT NOT NULL,
    added_by   TEXT NOT NULL DEFAULT '',
    fetched_at TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    index_json TEXT NOT NULL DEFAULT '{}'
);

-- The HTTPS port of each app's window proxy (44300 + n).
CREATE TABLE app_proxy_ports (
    app_id TEXT PRIMARY KEY,
    port   INTEGER NOT NULL UNIQUE CHECK (port BETWEEN 1024 AND 65535)
);
