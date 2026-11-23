-- Phase 9: the NetBird standby server (docs/netbird-standby.md, decisions
-- 420-429). The VPS connection, root's SSH key and the snapshots themselves
-- are hardyd-priv's (keys/netbird-standby); hardyd keeps only its schedule
-- and public-address settings (settings rows nbstandby.*) and this history
-- of sync attempts, which Control Panel › NetBird Standby shows.
CREATE TABLE nbstandby_syncs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    ok          INTEGER NOT NULL,
    auto        INTEGER NOT NULL DEFAULT 0,
    bytes       INTEGER NOT NULL DEFAULT 0,
    sha256      TEXT NOT NULL DEFAULT '',
    version     TEXT NOT NULL DEFAULT '',
    peers       INTEGER NOT NULL DEFAULT 0,
    error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX nbstandby_syncs_started ON nbstandby_syncs (started_at);
