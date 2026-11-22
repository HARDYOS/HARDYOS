-- Phase 9: per-app hostnames under the base domain with a Let's Encrypt
-- wildcard certificate (docs/plans/hostnames.md, decisions 450-459).
-- Settings (on/off, contact address, staging) and the sealed ACME account
-- key are rows of `settings` (hostnames.*). The Cloudflare token is never in
-- this database: hardyd-priv keeps it (decision 451).

-- Every certificate HardyOS was issued (and every failed attempt), newest
-- last: what Control Panel › Hostnames shows as "last renewed" and why the
-- last try failed. The certificate itself is a file next to the desktop's
-- self-signed one.
CREATE TABLE hostname_certs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    names      TEXT NOT NULL,
    serial     TEXT NOT NULL DEFAULT '',
    not_before TEXT NOT NULL DEFAULT '',
    not_after  TEXT NOT NULL DEFAULT '',
    issuer     TEXT NOT NULL DEFAULT '',
    error      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
