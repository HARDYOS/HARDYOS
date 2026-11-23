-- Mail in cloud backups and replication, on by default (decisions 460,
-- 469). Whole-server backup tasks (those with the settings item) back the
-- mail server up too; a server without a mail server skips the item
-- without a failure. Administrators untick Mail in the task to stop it.

UPDATE backup_tasks
SET items = json_insert(items, '$[#]', json('{"kind":"mail"}'))
WHERE json_valid(items)
  AND json_array_length(items) < 256
  AND EXISTS (SELECT 1 FROM json_each(backup_tasks.items) WHERE json_extract(value, '$.kind') = 'system')
  AND NOT EXISTS (SELECT 1 FROM json_each(backup_tasks.items) WHERE json_extract(value, '$.kind') = 'mail');

-- Replication sends the mail (and its DKIM keys) to another server, so an
-- existing task gets it only later and visibly: the oldest enabled task to
-- each paired server is marked 'pending'; hardyd adds Mail to it once that
-- server says it accepts mail replicas (and this one has a mail server),
-- marks it 'added' and tells the administrators, who can turn it off with
-- one click. Any change to the task clears 'added'.
ALTER TABLE repl_tasks ADD COLUMN mail_auto TEXT NOT NULL DEFAULT '';

UPDATE repl_tasks
SET mail_auto = 'pending'
WHERE enabled = 1
  AND rowid IN (
    SELECT (SELECT t2.rowid FROM repl_tasks t2 WHERE t2.target_id = t.target_id AND t2.enabled = 1 ORDER BY t2.created_at, t2.rowid LIMIT 1)
    FROM repl_tasks t GROUP BY t.target_id)
  AND NOT EXISTS (
    SELECT 1 FROM repl_tasks t3, json_each(t3.items)
    WHERE t3.target_id = repl_tasks.target_id AND json_extract(value, '$.kind') = 'mail');
