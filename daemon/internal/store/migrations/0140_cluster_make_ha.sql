-- Phase 10: "Make highly available" and "Make local again"
-- (docs/plans/make-ha.md, decisions 480-489). A conversion is a job on the
-- compute server that runs it; this row keeps where it got to, so a failed
-- or interrupted one resumes (or is undone or abandoned) from there. Parked
-- copies keep their own expiry as a ZFS property, on the server that holds
-- them; failovers are recorded by the leader that coordinated them.
CREATE TABLE cluster_conversions (
    id           TEXT PRIMARY KEY,
    direction    TEXT NOT NULL,             -- 'ha' or 'local'
    kind         TEXT NOT NULL,             -- 'vm' or 'app'
    workload     TEXT NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    storage_pool TEXT NOT NULL DEFAULT '',
    local_pool   TEXT NOT NULL DEFAULT '',
    phase        TEXT NOT NULL,
    state        TEXT NOT NULL,             -- 'running', 'done', 'failed', 'undone', 'abandoned'
    problem      TEXT NOT NULL DEFAULT '',
    job_id       TEXT NOT NULL DEFAULT '',
    was_running  INTEGER NOT NULL DEFAULT 0,
    options      TEXT NOT NULL DEFAULT '{}',
    bytes_done   INTEGER NOT NULL DEFAULT 0,
    bytes_total  INTEGER NOT NULL DEFAULT 0,
    actor        TEXT NOT NULL DEFAULT '',
    started_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    finished_at  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX cluster_conversions_workload ON cluster_conversions (kind, workload);

CREATE TABLE cluster_failovers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    at          TEXT NOT NULL,
    kind        TEXT NOT NULL,              -- 'vm' or 'app'
    workload    TEXT NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    from_node   TEXT NOT NULL DEFAULT '',
    to_node     TEXT NOT NULL DEFAULT '',
    outcome     TEXT NOT NULL,              -- 'restarted', 'pending', 'failed'
    problem     TEXT NOT NULL DEFAULT '',
    priority    INTEGER NOT NULL DEFAULT 0,
    coordinator TEXT NOT NULL DEFAULT ''
);
CREATE INDEX cluster_failovers_at ON cluster_failovers (at);
