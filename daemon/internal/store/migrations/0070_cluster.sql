-- Cluster core (internal/cluster, phase 8 part A; docs/plans/cluster.md).
-- The replicated state lives in Raft's own files under
-- /var/lib/hardyos/cluster; this database keeps only what is this
-- server's: the membership and sequence number (settings "cluster.info",
-- "cluster.seq"), the sealed cluster identity (settings
-- "cluster.identity", secretbox purpose "cluster") and the open join codes.
-- A join code is sealed (purpose "cluster", bound to its row id), so
-- reading the database alone doesn't let anyone join.

CREATE TABLE cluster_join_codes (
    id          TEXT PRIMARY KEY,
    code_sealed BLOB NOT NULL,
    role        TEXT NOT NULL CHECK (role IN ('compute', 'storage', 'witness')),
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    failures    INTEGER NOT NULL DEFAULT 0
);
