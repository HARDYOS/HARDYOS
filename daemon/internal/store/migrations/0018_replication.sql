-- Replication between HardyOS servers (internal/replication, phase 6
-- part B). A source server keeps targets (servers it sends to) and tasks;
-- a receiving server keeps sources (servers allowed to send to it) and at
-- most one pairing code. Pinned keys and the pairing code are sealed with
-- a key from hardyd-priv (internal/secretbox, purpose "replication"), so
-- editing the database alone can't make this server trust another key.

CREATE TABLE repl_targets (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,          -- the receiving server's name
    address     TEXT NOT NULL,          -- host or host:port
    pin_sealed  BLOB NOT NULL,          -- SHA-256 of its public key
    source_id   TEXT NOT NULL,          -- this server's id over there
    created_at  TEXT NOT NULL
);

CREATE TABLE repl_tasks (
    id               TEXT PRIMARY KEY,  -- also in snapshot names
    name             TEXT NOT NULL,
    target_id        TEXT NOT NULL REFERENCES repl_targets(id),
    items            TEXT NOT NULL DEFAULT '[]',   -- JSON [{kind, id}]
    interval_minutes INTEGER NOT NULL,
    bwlimit_kbps     INTEGER NOT NULL DEFAULT 0,   -- 0 = unlimited
    keep_local       INTEGER NOT NULL DEFAULT 3,
    keep_remote      INTEGER NOT NULL DEFAULT 14,
    enabled          INTEGER NOT NULL DEFAULT 1,
    last_run_at      TEXT,
    last_success_at  TEXT,
    last_error       TEXT NOT NULL DEFAULT '',
    last_bytes       INTEGER NOT NULL DEFAULT 0,
    alert            TEXT NOT NULL DEFAULT '',     -- '', 'failed', 'stale': what was last notified
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE TABLE repl_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id     TEXT NOT NULL,
    job_id      TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL DEFAULT 'replicate',  -- replicate, restore
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    state       TEXT NOT NULL,                       -- running, succeeded, failed, cancelled
    bytes       INTEGER NOT NULL DEFAULT 0,
    message     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX repl_runs_task ON repl_runs(task_id, id);

CREATE TABLE repl_sources (
    id           TEXT PRIMARY KEY,      -- <pool>/replicas/<id>
    name         TEXT NOT NULL,         -- the sending server's name
    pin_sealed   BLOB NOT NULL,
    pool         TEXT NOT NULL,
    quota_bytes  INTEGER NOT NULL DEFAULT 0,
    min_keep     INTEGER NOT NULL DEFAULT 3,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT
);

CREATE TABLE repl_source_items (
    source_id    TEXT NOT NULL REFERENCES repl_sources(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,
    item_id      TEXT NOT NULL,
    name         TEXT NOT NULL,
    pool         TEXT NOT NULL DEFAULT '',  -- where it lives on the source
    task_id      TEXT NOT NULL DEFAULT '',
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (source_id, kind, item_id)
);

CREATE TABLE repl_pairing (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    code_sealed  BLOB NOT NULL,
    pool         TEXT NOT NULL,
    quota_bytes  INTEGER NOT NULL DEFAULT 0,
    min_keep     INTEGER NOT NULL DEFAULT 3,
    failures     INTEGER NOT NULL DEFAULT 0,
    expires_at   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
