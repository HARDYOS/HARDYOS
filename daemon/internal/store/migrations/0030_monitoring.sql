-- Phase 6 part C: monitoring and alerts (docs/monitoring.md).

-- Notifications carry the event's kind and a desktop link, and each person
-- has their own read state (notifications.read_at is no longer written).
ALTER TABLE notifications ADD COLUMN kind TEXT NOT NULL DEFAULT '';
ALTER TABLE notifications ADD COLUMN link TEXT NOT NULL DEFAULT '';
CREATE TABLE notification_reads (
    notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    read_at         TEXT NOT NULL,
    PRIMARY KEY (notification_id, user_id)
);

-- Where alerts go. config is JSON without secrets; secrets is a sealed JSON
-- object (secretbox, purpose "notify", bound to the row id). The desktop is
-- a channel too and can't be deleted.
CREATE TABLE notify_channels (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT NOT NULL CHECK (type IN ('desktop', 'discord', 'slack', 'teams', 'webhook', 'smtp', 'ses')),
    name       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    config     TEXT NOT NULL DEFAULT '{}',
    secrets    BLOB,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_at    TEXT,
    last_ok    INTEGER,
    last_error TEXT NOT NULL DEFAULT ''
);
INSERT INTO notify_channels (type, name, enabled, config, created_at, updated_at)
    VALUES ('desktop', 'Desktop', 1, '{}', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- Routing: for a category of alerts ("disk", "pool", ... or "*" for the
-- rest), the lowest severity each channel gets.
CREATE TABLE notify_routes (
    category     TEXT NOT NULL,
    channel_id   INTEGER NOT NULL REFERENCES notify_channels(id) ON DELETE CASCADE,
    min_severity TEXT NOT NULL CHECK (min_severity IN ('info', 'warning', 'critical')),
    PRIMARY KEY (category, channel_id)
);
INSERT INTO notify_routes (category, channel_id, min_severity)
    SELECT '*', id, 'info' FROM notify_channels WHERE type = 'desktop';

-- What was sent where, for Control Panel's delivery log (newest 500 kept).
CREATE TABLE notify_deliveries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT NOT NULL,
    channel_id INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    title      TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('sent', 'failed', 'held', 'suppressed')),
    detail     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX notify_deliveries_at ON notify_deliveries(at);

-- Alerts held during quiet hours, sent as one summary when they end.
CREATE TABLE notify_deferred (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id INTEGER NOT NULL REFERENCES notify_channels(id) ON DELETE CASCADE,
    at         TEXT NOT NULL,
    kind       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL DEFAULT '',
    link       TEXT NOT NULL DEFAULT ''
);

-- Conditions the monitor currently sees (a degraded pool, a hot disk, a UPS
-- on battery): raised once, cleared once, kept across restarts.
CREATE TABLE monitor_conditions (
    key        TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL DEFAULT '',
    link       TEXT NOT NULL DEFAULT '',
    since      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- SMART self-tests per disk: when each kind is next due (first dates are
-- spread out so disks take turns), when each last ran, what is running
-- and how the last one ended.
CREATE TABLE smart_tests (
    by_id         TEXT PRIMARY KEY,
    next_short_at TEXT NOT NULL,
    next_long_at  TEXT NOT NULL,
    last_short_at TEXT,
    last_long_at  TEXT,
    running       TEXT NOT NULL DEFAULT '' CHECK (running IN ('', 'short', 'long')),
    running_since TEXT,
    manual        INTEGER NOT NULL DEFAULT 0,
    last_type     TEXT NOT NULL DEFAULT '',
    last_result   TEXT NOT NULL DEFAULT '',
    last_passed   INTEGER,
    last_done_at  TEXT
);
