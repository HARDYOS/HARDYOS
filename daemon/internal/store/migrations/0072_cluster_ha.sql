-- Phase 8 part C: placement, moves, HA and fencing (docs/plans/cluster.md
-- sections 6.3-7). Placements, grants, fences and HA policies are in the
-- cluster's replicated state, not here; this server keeps only the history
-- of the moves started on it (each also a job and audited).
CREATE TABLE cluster_moves (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      TEXT NOT NULL,
    kind        TEXT NOT NULL,           -- vm or app
    workload    TEXT NOT NULL,
    from_node   TEXT NOT NULL DEFAULT '',
    to_node     TEXT NOT NULL DEFAULT '',
    mode        TEXT NOT NULL,           -- offline or live
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    downtime_ms INTEGER NOT NULL DEFAULT 0,
    ok          INTEGER NOT NULL DEFAULT 0,
    problem     TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX cluster_moves_workload ON cluster_moves (kind, workload);
