-- Phase 7 part C: Photos (Immich set up by HardyOS, docs/photos.md).
-- Settings, status and the sealed Immich service account and OIDC client
-- secret are rows of `settings` (photos.*). These tables remember what
-- HardyOS made in Immich, so it only ever changes or removes its own.

-- External libraries HardyOS keeps in Immich: one per personal library of
-- existing photos (key user:<users.id>:<share>:<folder>) and the family
-- library (key family).
CREATE TABLE photos_libraries (
    key         TEXT PRIMARY KEY,
    immich_id   TEXT NOT NULL,
    owner_id    TEXT NOT NULL,
    import_path TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

-- Immich accounts the family account shares with as a partner because
-- HardyOS added them (partners someone added in Immich are left alone).
CREATE TABLE photos_partners (
    immich_user_id TEXT PRIMARY KEY,
    created_at     TEXT NOT NULL
);
