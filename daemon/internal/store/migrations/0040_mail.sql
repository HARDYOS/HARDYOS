-- Phase 7 part A: the family mail server (docs/mail.md). Numbers 0040-0049
-- are this part's; settings (JSON) and sealed secrets live in `settings`
-- under mail.* keys.

-- Mail domains. dkim_public is the public half of root's key (base64 DER);
-- ses_dkim the Easy DKIM tokens SES gave; last_check the last DNS check
-- (JSON) with its time.
CREATE TABLE mail_domains (
    name          TEXT PRIMARY KEY,
    selector      TEXT NOT NULL,
    dkim_public   TEXT NOT NULL DEFAULT '',
    dmarc_policy  TEXT NOT NULL DEFAULT 'quarantine' CHECK (dmarc_policy IN ('none', 'quarantine', 'reject')),
    mta_sts       TEXT NOT NULL DEFAULT 'off' CHECK (mta_sts IN ('off', 'testing', 'enforce')),
    mta_sts_id    TEXT NOT NULL DEFAULT '',
    cloudflare    INTEGER NOT NULL DEFAULT 0,
    ses_dkim      TEXT NOT NULL DEFAULT '[]',
    ses_status    TEXT NOT NULL DEFAULT '',
    ses_mail_from INTEGER NOT NULL DEFAULT 0,
    last_check    TEXT NOT NULL DEFAULT '',
    checked_at    TEXT,
    created_at    TEXT NOT NULL
);

-- One mailbox per domain account (account = sAMAccountName, lower case),
-- made automatically. account_state follows the domain: a turned-off or
-- deleted account can't sign in to mail; deleting the mailbox itself
-- (and its messages) is a separate, confirmed step. aliases is a JSON list.
CREATE TABLE mail_mailboxes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    account       TEXT NOT NULL UNIQUE,
    address       TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL DEFAULT '',
    aliases       TEXT NOT NULL DEFAULT '[]',
    quota_mb      INTEGER NOT NULL DEFAULT 0,
    enabled       INTEGER NOT NULL DEFAULT 1,
    account_state TEXT NOT NULL DEFAULT 'active' CHECK (account_state IN ('active', 'disabled', 'deleted')),
    custom_address INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- Addresses that deliver to several mailboxes (family@). targets is a JSON
-- list of mailbox addresses.
CREATE TABLE mail_groups (
    address    TEXT PRIMARY KEY,
    targets    TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);
