-- Domain accounts that signed in to the desktop. A domain user gets a row in
-- users the first time they sign in (username = principal, HOME\alice), so
-- jobs, audit entries and sessions can point at them like at local accounts.
-- Their password stays in the domain (password_hash is empty and never
-- checked); role and groups come from the domain at each sign-in and at
-- most every 10 minutes during a session.
ALTER TABLE users ADD COLUMN source TEXT NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'domain'));
ALTER TABLE users ADD COLUMN groups TEXT NOT NULL DEFAULT '[]';
ALTER TABLE users ADD COLUMN groups_checked_at TEXT;

-- Which kind of account a session belongs to, and its principal.
ALTER TABLE sessions ADD COLUMN source TEXT NOT NULL DEFAULT 'local';
ALTER TABLE sessions ADD COLUMN principal TEXT NOT NULL DEFAULT '';
