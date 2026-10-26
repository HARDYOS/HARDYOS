-- App Store security review (decisions 80-82).

-- An imported catalog may be fetched from this server's own networks
-- (loopback, private, link-local, CGNAT, unique-local addresses) only when
-- an administrator ticked "On my network" for it.
ALTER TABLE app_catalogs ADD COLUMN local_network INTEGER NOT NULL DEFAULT 0;

-- Where each installed app came from, as hardyd installed it: the source,
-- and for imported apps the catalog's id (names can be reused after a
-- catalog is removed) and name. Updates follow catalog_id; installing the
-- same app id from another source or catalog needs replaceSource.
CREATE TABLE app_origins (
    app_id       TEXT PRIMARY KEY,
    source       TEXT NOT NULL,
    catalog_id   INTEGER NOT NULL DEFAULT 0,
    catalog_name TEXT NOT NULL DEFAULT '',
    ref          TEXT NOT NULL DEFAULT ''
);
