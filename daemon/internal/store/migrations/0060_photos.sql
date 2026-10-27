-- Phase 7 part C: Photos (Immich set up by HardyOS, docs/photos.md).
-- Settings, status and the sealed Immich service account and OIDC client
-- secret are rows of `settings` (photos.*). These tables remember what
-- HardyOS made or changed in Immich, so it only ever changes or removes its
-- own.

-- External libraries HardyOS keeps in Immich: one per personal library of
-- existing photos (key user:<users.id>:<share>:<folder>) and the family
-- library (key family). subject is the owner's sign-in subject when the
-- library was made: a HardyOS account that now belongs to another person
-- (another directory object) gets a new library, never the old one.
CREATE TABLE photos_libraries (
    key         TEXT PRIMARY KEY,
    immich_id   TEXT NOT NULL,
    owner_id    TEXT NOT NULL,
    import_path TEXT NOT NULL,
    subject     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

-- Immich accounts of people HardyOS looks after: made by HardyOS ahead of
-- the person's first sign-in (made = 1, for that subject only), and those
-- it soft-deleted because their HardyOS account may no longer use Photos
-- (suspended = 1; restored when it may again).
CREATE TABLE photos_accounts (
    immich_id  TEXT PRIMARY KEY,
    subject    TEXT NOT NULL,
    made       INTEGER NOT NULL DEFAULT 0,
    suspended  INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

-- Immich accounts the family account shares with as a partner because
-- HardyOS added them (partners someone added in Immich are left alone).
CREATE TABLE photos_partners (
    immich_user_id TEXT PRIMARY KEY,
    created_at     TEXT NOT NULL
);
