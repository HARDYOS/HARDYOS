-- Web share links (docs/plans/file-sharing.md section 4, decisions 96-98).
--
-- A link points at one file or folder in a shared folder (or a person's
-- Home, share '~home'). Only the SHA-256 of its token is stored: the token
-- itself is shown once, when the link is made. Files are read as the person
-- who made the link (created_by), re-checked on every use, so deleting or
-- disabling that account, or taking away their access, stops the link.
CREATE TABLE share_links (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash     TEXT NOT NULL UNIQUE,
    share          TEXT NOT NULL,
    path           TEXT NOT NULL DEFAULT '',
    is_dir         INTEGER NOT NULL DEFAULT 0,
    created_by     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_by_name TEXT NOT NULL DEFAULT '',
    created_at     TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    password_hash  TEXT NOT NULL DEFAULT '',
    allow_upload   INTEGER NOT NULL DEFAULT 0,
    max_downloads  INTEGER NOT NULL DEFAULT 0 CHECK (max_downloads >= 0),
    download_count INTEGER NOT NULL DEFAULT 0,
    last_used_at   TEXT NOT NULL DEFAULT '',
    revoked        INTEGER NOT NULL DEFAULT 0,
    revoked_at     TEXT NOT NULL DEFAULT '',
    CHECK (allow_upload = 0 OR is_dir = 1)
);
CREATE INDEX share_links_created_by ON share_links (created_by);
