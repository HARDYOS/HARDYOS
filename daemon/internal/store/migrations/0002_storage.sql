-- Automatic snapshots per dataset.
CREATE TABLE snapshot_policies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset     TEXT NOT NULL,
    frequency   TEXT NOT NULL CHECK (frequency IN ('hourly', 'daily', 'weekly', 'monthly')),
    keep        INTEGER NOT NULL CHECK (keep BETWEEN 1 AND 1000),
    recursive   INTEGER NOT NULL DEFAULT 1,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_run_at TEXT,
    last_error  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    UNIQUE (dataset, frequency)
);

-- Scrub schedule per pool.
CREATE TABLE scrub_policies (
    pool            TEXT PRIMARY KEY,
    interval_days   INTEGER NOT NULL DEFAULT 30 CHECK (interval_days BETWEEN 1 AND 365),
    enabled         INTEGER NOT NULL DEFAULT 1,
    last_started_at TEXT,
    last_error      TEXT NOT NULL DEFAULT ''
);

-- Last known health per disk, to notify only when it changes.
CREATE TABLE disk_health (
    by_id        TEXT PRIMARY KEY,
    health       TEXT NOT NULL,
    reasons      TEXT NOT NULL DEFAULT '[]',
    temperature  INTEGER,
    checked_at   TEXT NOT NULL
);

-- Notification center.
CREATE TABLE notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT NOT NULL,
    level      TEXT NOT NULL CHECK (level IN ('info', 'success', 'warning', 'error')),
    title      TEXT NOT NULL,
    body       TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL DEFAULT '',
    admin_only INTEGER NOT NULL DEFAULT 1,
    read_at    TEXT
);
CREATE INDEX notifications_at ON notifications(at);
