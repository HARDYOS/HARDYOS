-- Mail in cloud backups and replication, on by default (decision 460).
-- Whole-server backup tasks (those with the settings item) back the mail
-- server up too, and the oldest replication task to each paired server
-- copies it. A server without a mail server skips the item without a
-- failure, so this is harmless where mail isn't set up. Administrators
-- untick Mail in the task to stop it.

UPDATE backup_tasks
SET items = json_insert(items, '$[#]', json('{"kind":"mail"}'))
WHERE json_valid(items)
  AND json_array_length(items) < 256
  AND EXISTS (SELECT 1 FROM json_each(backup_tasks.items) WHERE json_extract(value, '$.kind') = 'system')
  AND NOT EXISTS (SELECT 1 FROM json_each(backup_tasks.items) WHERE json_extract(value, '$.kind') = 'mail');

UPDATE repl_tasks
SET items = json_insert(items, '$[#]', json('{"kind":"mail","id":"mail"}'))
WHERE json_valid(items)
  AND json_array_length(items) < 100
  AND rowid IN (
    SELECT (SELECT t2.rowid FROM repl_tasks t2 WHERE t2.target_id = t.target_id ORDER BY t2.created_at, t2.rowid LIMIT 1)
    FROM repl_tasks t GROUP BY t.target_id)
  AND NOT EXISTS (
    SELECT 1 FROM repl_tasks t3, json_each(t3.items)
    WHERE t3.target_id = repl_tasks.target_id AND json_extract(value, '$.kind') = 'mail');
