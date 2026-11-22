-- Phase 9: game streaming (decisions 400-409, docs/plans/streaming.md).
-- The Sunshine web UI account HardyOS made in a gaming VM. The password is
-- sealed (secretbox, purpose vm-streaming, bound to the VM's name) and
-- never stored in the clear, in job parameters or in logs. revealed_at is
-- the last time an administrator looked at it.
CREATE TABLE vm_streaming (
    vm_id           TEXT PRIMARY KEY,
    sunshine_user   TEXT NOT NULL,
    password_sealed BLOB NOT NULL,
    created_at      TEXT NOT NULL,
    revealed_at     TEXT NOT NULL DEFAULT ''
);
