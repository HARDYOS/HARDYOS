package store

import (
	"context"
	"path/filepath"
	"testing"
)

// Migration 0110 (decisions 460, 469): mail goes into whole-server backup
// tasks at once; the oldest enabled replication task of each paired server
// is only marked to get it later (when that server accepts mail).
func TestMigrationMailOnByDefault(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "hardyd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := "2026-11-01T00:00:00Z"
	later := "2026-11-02T00:00:00Z"
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO backup_tasks (id, name, target, items, created_at, updated_at) VALUES (?, ?, 't1', ?, ?, ?)`, []any{"whole", "Whole", `[{"kind":"share","id":"media"},{"kind":"system"}]`, now, now}},
		{`INSERT INTO backup_tasks (id, name, target, items, created_at, updated_at) VALUES (?, ?, 't1', ?, ?, ?)`, []any{"photos", "Photos", `[{"kind":"share","id":"photos"}]`, now, now}},
		{`INSERT INTO backup_tasks (id, name, target, items, created_at, updated_at) VALUES (?, ?, 't1', ?, ?, ?)`, []any{"has", "Has", `[{"kind":"system"},{"kind":"mail"}]`, now, now}},
		{`INSERT INTO repl_targets (id, name, address, pin_sealed, source_id, created_at) VALUES ('b', 'B', 'b:44400', x'00', 'srcid1', ?)`, []any{now}},
		{`INSERT INTO repl_targets (id, name, address, pin_sealed, source_id, created_at) VALUES ('c', 'C', 'c:44400', x'00', 'srcid2', ?)`, []any{now}},
		{`INSERT INTO repl_tasks (id, name, target_id, items, interval_minutes, created_at, updated_at) VALUES ('old111', 'Old', 'b', ?, 60, ?, ?)`, []any{`[{"kind":"share","id":"media"}]`, now, now}},
		{`INSERT INTO repl_tasks (id, name, target_id, items, interval_minutes, created_at, updated_at) VALUES ('new111', 'New', 'b', ?, 60, ?, ?)`, []any{`[{"kind":"vm","id":"web"}]`, later, later}},
		{`INSERT INTO repl_tasks (id, name, target_id, items, interval_minutes, created_at, updated_at) VALUES ('cmail1', 'C1', 'c', ?, 60, ?, ?)`, []any{`[{"kind":"vm","id":"x"}]`, now, now}},
		{`INSERT INTO repl_tasks (id, name, target_id, items, interval_minutes, created_at, updated_at) VALUES ('cmail2', 'C2', 'c', ?, 60, ?, ?)`, []any{`[{"kind":"mail","id":"mail"}]`, later, later}},
		{`INSERT INTO repl_tasks (id, name, target_id, items, interval_minutes, enabled, created_at, updated_at) VALUES ('off111', 'Off', 'b', '[]', 60, 0, '2026-10-01T00:00:00Z', ?)`, []any{now}},
		// As before 0110.
		{`ALTER TABLE repl_tasks DROP COLUMN mail_auto`, nil},
		{`DELETE FROM schema_migrations WHERE version = 110`, nil},
	} {
		if _, err := db.ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", q.sql, err)
		}
	}
	for i := 0; i < 1; i++ {
		if err := db.migrate(ctx); err != nil {
			t.Fatal(err)
		}
		items := func(table, id string) string {
			var s string
			if err := db.QueryRowContext(ctx, `SELECT items FROM `+table+` WHERE id = ?`, id).Scan(&s); err != nil {
				t.Fatal(err)
			}
			return s
		}
		for _, c := range []struct{ table, id, want string }{
			{"backup_tasks", "whole", `[{"kind":"share","id":"media"},{"kind":"system"},{"kind":"mail"}]`},
			{"backup_tasks", "photos", `[{"kind":"share","id":"photos"}]`},
			{"backup_tasks", "has", `[{"kind":"system"},{"kind":"mail"}]`},
			{"repl_tasks", "old111", `[{"kind":"share","id":"media"}]`},
			{"repl_tasks", "new111", `[{"kind":"vm","id":"web"}]`},
			{"repl_tasks", "cmail1", `[{"kind":"vm","id":"x"}]`},
			{"repl_tasks", "cmail2", `[{"kind":"mail","id":"mail"}]`},
		} {
			if got := items(c.table, c.id); got != c.want {
				t.Errorf("run %d: %s %s: %s, want %s", i, c.table, c.id, got, c.want)
			}
		}
		for id, want := range map[string]string{"old111": "pending", "new111": "", "off111": "", "cmail1": "", "cmail2": ""} {
			var got string
			if err := db.QueryRowContext(ctx, `SELECT mail_auto FROM repl_tasks WHERE id = ?`, id).Scan(&got); err != nil || got != want {
				t.Errorf("%s: mail_auto %q (%v), want %q", id, got, err, want)
			}
		}
	}
}
