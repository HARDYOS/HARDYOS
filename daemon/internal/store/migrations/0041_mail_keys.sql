-- Mail security review (decision 310). storage_key names a mailbox on disk
-- for good (vmail/<key>, Radicale); account_guid and account_sid tie it to
-- the domain account itself, so an account deleted and made again under
-- the same name doesn't get the old one's mail. A mailbox whose account is
-- gone for good has account "@<id>". deleting: taken off the server, its
-- files being deleted (the row goes last).
ALTER TABLE mail_mailboxes ADD COLUMN storage_key TEXT NOT NULL DEFAULT '';
ALTER TABLE mail_mailboxes ADD COLUMN account_guid TEXT NOT NULL DEFAULT '';
ALTER TABLE mail_mailboxes ADD COLUMN account_sid TEXT NOT NULL DEFAULT '';
ALTER TABLE mail_mailboxes ADD COLUMN deleting INTEGER NOT NULL DEFAULT 0;
-- legacy_layout: made before decision 310, so its mail may still be under
-- its address; only such a mailbox takes that folder on the next apply
-- (decision 318), then hardyd clears the flag.
ALTER TABLE mail_mailboxes ADD COLUMN legacy_layout INTEGER NOT NULL DEFAULT 0;
UPDATE mail_mailboxes SET legacy_layout = 1;
-- Existing mailboxes get a key now; hardyd-priv moves their folders to it
-- on the next apply.
UPDATE mail_mailboxes SET storage_key = lower(hex(randomblob(12))) WHERE storage_key = '';
CREATE UNIQUE INDEX mail_mailboxes_storage_key ON mail_mailboxes (storage_key);
