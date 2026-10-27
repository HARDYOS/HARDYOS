-- Remote access: publishing the desktop and apps through NetBird's reverse
-- proxy (docs/remote-access.md, decisions 111-115).
--
-- The publishing settings (base domain, NetBird API address, desktop name)
-- are in settings ('remote.publish'); the access token and the gateway's
-- shared secret are in settings too, sealed with hardyd's secret key
-- (internal/publish: AES-256-GCM, key file outside the database), so
-- settings backups never carry them in the clear.
--
-- remote_services has one row per published thing: key 'desktop' or
-- 'app:<id>'. mode: '' (follow the default for new apps), off, netbird,
-- public; auth (public only): sso, password, pin, none; groups: NetBird
-- group IDs (NetBird-only: who may reach it; SSO: who may sign in);
-- hardyos_signin: the app gateway asks for a HardyOS sign-in (apps only);
-- secret: a sealed password or PIN. The rest is what the last sync saw:
-- NetBird's service id, its domain and status, an error, and a hash of the
-- service HardyOS last sent.
CREATE TABLE remote_services (
    key            TEXT PRIMARY KEY,
    mode           TEXT NOT NULL DEFAULT '' CHECK (mode IN ('', 'off', 'netbird', 'public')),
    auth           TEXT NOT NULL DEFAULT '' CHECK (auth IN ('', 'sso', 'password', 'pin', 'none')),
    groups         TEXT NOT NULL DEFAULT '[]',
    hardyos_signin INTEGER NOT NULL DEFAULT 1,
    secret         TEXT NOT NULL DEFAULT '',
    service_id     TEXT NOT NULL DEFAULT '',
    domain         TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT '',
    error          TEXT NOT NULL DEFAULT '',
    applied        TEXT NOT NULL DEFAULT '',
    synced_at      TEXT NOT NULL DEFAULT ''
);
