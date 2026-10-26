package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
)

// Snapshot writes a consistent copy of the database to path (which must not
// exist), while the database stays in use.
func (db *DB) Snapshot(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	_, err := db.ExecContext(ctx, `VACUUM INTO ?`, path)
	return err
}

// SchemaVersion is the newest migration this build knows.
func SchemaVersion() int {
	migs, err := loadMigrations()
	if err != nil || len(migs) == 0 {
		return 0
	}
	return migs[len(migs)-1].version
}

// DBInfo describes a database file without opening it for use.
type DBInfo struct {
	Schema int
	Users  int
}

// Inspect reads the migration level and user count of a database file,
// read-only and without migrating it. It fails for anything that isn't a
// HardyOS database.
func Inspect(ctx context.Context, path string) (*DBInfo, error) {
	sqlDB, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	defer sqlDB.Close()
	var info DBInfo
	if err := sqlDB.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&info.Schema); err != nil {
		return nil, errors.New("not a HardyOS database")
	}
	if err := sqlDB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&info.Users); err != nil {
		return nil, errors.New("not a HardyOS database")
	}
	return &info, nil
}
