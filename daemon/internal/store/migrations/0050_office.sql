-- Office (phase 7 part B, docs/office.md, decisions 250-262).
--
-- An editing session is one version of one file open in the Document
-- Server under a document key. Everyone who opens the file while it is open
-- joins the same session (co-editing); each opening is a participant, whose
-- id is the user id the Document Server reports back in callbacks, so a
-- save is written as exactly the person (or share link) behind it.
CREATE TABLE office_sessions (
    doc_key       TEXT PRIMARY KEY,
    share         TEXT NOT NULL,
    path          TEXT NOT NULL,
    file_type     TEXT NOT NULL,
    -- The version on disk the session expects: what it was opened from, then
    -- what the last save wrote. A different file there means someone changed
    -- it outside the editor, and a save goes next to it instead.
    base_modified TEXT NOT NULL,
    base_size     INTEGER NOT NULL,
    state         TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closed', 'error')),
    error         TEXT NOT NULL DEFAULT '',
    -- Participant ids the Document Server last said are in the document.
    active        TEXT NOT NULL DEFAULT '[]',
    saves         INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE UNIQUE INDEX office_sessions_open ON office_sessions (share, path) WHERE state = 'open';

CREATE TABLE office_participants (
    id         TEXT PRIMARY KEY,
    doc_key    TEXT NOT NULL REFERENCES office_sessions(doc_key) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('user', 'link')),
    user_id    INTEGER NOT NULL DEFAULT 0,
    link_id    INTEGER NOT NULL DEFAULT 0,
    name       TEXT NOT NULL DEFAULT '',
    mode       TEXT NOT NULL CHECK (mode IN ('edit', 'view')),
    created_at TEXT NOT NULL
);
CREATE INDEX office_participants_key ON office_participants (doc_key);

-- Callbacks already acted on (status, download URL), so a replayed save
-- is never written twice.
CREATE TABLE office_callbacks (
    doc_key     TEXT NOT NULL REFERENCES office_sessions(doc_key) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    status      INTEGER NOT NULL,
    at          TEXT NOT NULL,
    PRIMARY KEY (doc_key, fingerprint)
);

-- Share links can grant editing in the browser (decision 256).
ALTER TABLE share_links ADD COLUMN access TEXT NOT NULL DEFAULT 'view' CHECK (access IN ('view', 'edit'));
