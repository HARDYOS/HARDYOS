-- Share link limits (decisions 103-104).
--
-- max_upload_bytes: how much an upload link may take in, in all;
-- uploaded_bytes: how much it has (bytes of uploads in progress are
-- reserved here as they arrive and given back if the upload fails).
-- max_zip_bytes: the most one "download all" zip of a folder link holds.
ALTER TABLE share_links ADD COLUMN max_upload_bytes INTEGER NOT NULL DEFAULT 10000000000 CHECK (max_upload_bytes >= 0);
ALTER TABLE share_links ADD COLUMN uploaded_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE share_links ADD COLUMN max_zip_bytes INTEGER NOT NULL DEFAULT 20000000000 CHECK (max_zip_bytes >= 0);
