-- Versioned cloud backups (internal/cloudbackups, docs/backup.md): the
-- backup tasks an administrator set up, what each run did, and per
-- destination maintenance settings. The destinations themselves and their
-- credentials are hardyd-priv's (sealed in its own state directory); only
-- their ids appear here. Numbered 0016 to leave room for parallel work.

CREATE TABLE backup_tasks (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    target     TEXT NOT NULL,              -- destination id (hardyd-priv's)
    items      TEXT NOT NULL DEFAULT '[]', -- JSON [{kind, id}]
    schedule   TEXT NOT NULL DEFAULT '{}', -- JSON
    retention  TEXT NOT NULL DEFAULT '{}', -- JSON {daily, weekly, monthly}
    enabled    INTEGER NOT NULL DEFAULT 1,
    last_slot  TEXT NOT NULL DEFAULT '',   -- the last scheduled slot handled
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE backup_runs (
    id          TEXT PRIMARY KEY,           -- run id (a version's tag for backups)
    task_id     TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL,              -- backup, restore, prune, check, rebuild
    target      TEXT NOT NULL,
    job_id      TEXT NOT NULL DEFAULT '',
    trigger     TEXT NOT NULL DEFAULT '',   -- schedule, manual
    state       TEXT NOT NULL,              -- running, succeeded, partial, failed, cancelled, missed
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    files       INTEGER NOT NULL DEFAULT 0,
    bytes       INTEGER NOT NULL DEFAULT 0,
    added       INTEGER NOT NULL DEFAULT 0,
    detail      TEXT NOT NULL DEFAULT '{}', -- JSON result from hardyd-priv
    error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX backup_runs_task ON backup_runs(task_id, started_at);
CREATE INDEX backup_runs_started ON backup_runs(started_at);

CREATE TABLE backup_target_settings (
    target            TEXT PRIMARY KEY,
    maintenance       TEXT NOT NULL DEFAULT '{}', -- JSON {weekday, time, checkPercent}
    last_slot         TEXT NOT NULL DEFAULT '',
    kit_downloaded_at TEXT
);
