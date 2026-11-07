-- Phase 8 part B: cluster storage (docs/plans/cluster.md sections 5 and 6.1).
-- Nothing here is cluster state (that is the replicated log); these are
-- this server's own settings and secrets.

-- This server's storage network, as the wizard set it up (one row, id 1):
-- kind dedicated | vlan | lan, the port or bond, the VLAN id, the address
-- with its prefix and the MTU (0 = 1500).
CREATE TABLE cluster_storage_net (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    kind       TEXT NOT NULL,
    iface      TEXT NOT NULL,
    vlan       INTEGER NOT NULL DEFAULT 0,
    address    TEXT NOT NULL,
    mtu        INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

-- A compute node's own CHAP secrets for its target on the storage node,
-- sealed (secretbox purpose "cluster", bound to the row). The storage
-- node keeps its copy in root's own file, never in this database.
CREATE TABLE cluster_storage_chap (
    node       TEXT PRIMARY KEY,
    sealed     BLOB NOT NULL,
    updated_at TEXT NOT NULL
);

-- Storage mode overrides an administrator chose for apps before or after
-- they joined the cluster (app id -> nfs | block, with the file system);
-- an app without a row gets its catalog default.
CREATE TABLE cluster_app_storage_mode (
    app        TEXT PRIMARY KEY,
    mode       TEXT NOT NULL CHECK (mode IN ('nfs', 'block')),
    fs         TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
