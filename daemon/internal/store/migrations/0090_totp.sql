-- Two-factor sign-in (decisions 440-449, docs/plans/totp.md).

-- An account's authenticator. secret and pending_secret are sealed with
-- secretbox (purpose "totp", bound to the user id); last_step is the last
-- time step accepted (codes for it or earlier are refused); failures counts
-- wrong authenticator codes in a row. grace_until is an administrator's
-- deadline to enroll; setup_code_* a one-time code an administrator issued
-- for enrolling from outside (SHA-256 only).
CREATE TABLE user_totp (
    user_id            INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret             BLOB,
    enabled_at         TEXT,
    pending_secret     BLOB,
    pending_at         TEXT,
    last_step          INTEGER NOT NULL DEFAULT 0,
    failures           INTEGER NOT NULL DEFAULT 0,
    grace_until        TEXT,
    setup_code_hash    TEXT,
    setup_code_expires TEXT,
    updated_at         TEXT NOT NULL
);

-- Single-use recovery codes (SHA-256 of the normalized code).
CREATE TABLE user_recovery_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX user_recovery_codes_user ON user_recovery_codes(user_id);

-- Per-device app passwords for services that can't ask for a code (WebDAV,
-- mail, calendars). Only the SHA-256 of the password is kept.
CREATE TABLE app_passwords (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    scopes       TEXT NOT NULL DEFAULT '[]',
    hash         TEXT NOT NULL UNIQUE,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    last_used_ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX app_passwords_user ON app_passwords(user_id);

-- Whether a session was signed in with a second factor.
ALTER TABLE sessions ADD COLUMN mfa INTEGER NOT NULL DEFAULT 0;
ALTER TABLE oidc_browser_sessions ADD COLUMN mfa INTEGER NOT NULL DEFAULT 0;
