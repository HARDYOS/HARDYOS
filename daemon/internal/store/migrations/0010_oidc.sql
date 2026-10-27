-- HardyOS as an OpenID Connect provider (internal/oidc): the apps that may
-- sign people in with their HardyOS accounts (NetBird first), the keys ID
-- tokens are signed with, and the short-lived state of each sign-in.
-- Secrets are never stored in the clear: client secrets and tokens as
-- SHA-256 (they're 256-bit random values), private keys sealed with a key
-- from hardyd-priv (internal/secretbox), so the database and its backups
-- don't hold anything that signs or opens a session.

CREATE TABLE oidc_clients (
    id               TEXT PRIMARY KEY,           -- client_id
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL CHECK (kind IN ('confidential', 'public')),
    secret_hash      TEXT NOT NULL DEFAULT '',   -- SHA-256 hex; '' for public clients
    redirect_uris    TEXT NOT NULL DEFAULT '[]', -- JSON, matched exactly
    post_logout_uris TEXT NOT NULL DEFAULT '[]',
    allowed_groups   TEXT NOT NULL DEFAULT '[]', -- NETBIOS\group; [] = everyone
    first_party      INTEGER NOT NULL DEFAULT 0, -- 1: no consent screen
    preset           TEXT NOT NULL DEFAULT '',
    managed_by       TEXT NOT NULL DEFAULT '',   -- '' = made by an administrator
    disabled         INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);
CREATE UNIQUE INDEX oidc_clients_managed ON oidc_clients(managed_by) WHERE managed_by != '';

-- Signing keys: 'next' is published in the JWKS before it signs anything,
-- 'active' signs, 'retired' stays published until expires_at.
CREATE TABLE oidc_keys (
    id           TEXT PRIMARY KEY,               -- kid
    alg          TEXT NOT NULL,
    private_seal BLOB NOT NULL,                  -- PKCS#8, sealed (secretbox, AAD = kid)
    public_jwk   TEXT NOT NULL,
    state        TEXT NOT NULL CHECK (state IN ('next', 'active', 'retired')),
    created_at   TEXT NOT NULL,
    activated_at TEXT,
    retired_at   TEXT,
    expires_at   TEXT
);

-- People's stable subjects: a domain account's objectGUID, a random value
-- for a local account.
CREATE TABLE oidc_subjects (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    sub     TEXT NOT NULL UNIQUE,
    guid    TEXT NOT NULL DEFAULT ''
);

-- A sign-in in progress (10 minutes), then its code (60 seconds). Rows of
-- used codes are kept until they expire, so a replayed code is recognised
-- and the tokens it gave are revoked.
CREATE TABLE oidc_auth_requests (
    id            TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    request       TEXT NOT NULL,                 -- JSON (internal/oidc authRequest)
    browser_hash  TEXT NOT NULL DEFAULT '',      -- the browser it was first opened in
    user_id       INTEGER REFERENCES users(id) ON DELETE CASCADE,
    done          INTEGER NOT NULL DEFAULT 0,
    code_hash     TEXT UNIQUE,
    code_at       TEXT,
    consumed_at   TEXT,
    replayed      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL
);
CREATE INDEX oidc_auth_requests_expires ON oidc_auth_requests(expires_at);

-- What a sign-in gave a client: the access tokens and the refresh token
-- family (rotated on every use; a reused one revokes the grant).
CREATE TABLE oidc_grants (
    id          TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject     TEXT NOT NULL,
    scopes      TEXT NOT NULL DEFAULT '[]',
    auth_time   TEXT NOT NULL,
    amr         TEXT NOT NULL DEFAULT '[]',
    code_hash   TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,                   -- the refresh family's absolute end
    revoked_at  TEXT
);
CREATE INDEX oidc_grants_user ON oidc_grants(user_id, client_id);
CREATE INDEX oidc_grants_code ON oidc_grants(code_hash);

CREATE TABLE oidc_refresh_tokens (
    hash       TEXT PRIMARY KEY,
    grant_id   TEXT NOT NULL REFERENCES oidc_grants(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT
);
CREATE INDEX oidc_refresh_tokens_grant ON oidc_refresh_tokens(grant_id);

CREATE TABLE oidc_access_tokens (
    id         TEXT PRIMARY KEY,                 -- the JWT's jti
    grant_id   TEXT NOT NULL REFERENCES oidc_grants(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX oidc_access_tokens_grant ON oidc_access_tokens(grant_id);

-- What a person allowed a (third-party) client to see.
CREATE TABLE oidc_consents (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL REFERENCES oidc_clients(id) ON DELETE CASCADE,
    scopes     TEXT NOT NULL DEFAULT '[]',
    granted_at TEXT NOT NULL,
    PRIMARY KEY (user_id, client_id)
);

-- The provider's own sign-in session in a browser (12 hours at most).
CREATE TABLE oidc_browser_sessions (
    id_hash    TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_time  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip         TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT ''
);
CREATE INDEX oidc_browser_sessions_user ON oidc_browser_sessions(user_id);
