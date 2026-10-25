package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestOpenMigratesAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "hardyd.db")

	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no migrations recorded")
	}
	db.Close()

	db, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db.Close()
	var n2 int
	_ = db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n2)
	if n2 != n {
		t.Fatalf("migrations reapplied: %d then %d", n, n2)
	}
}

func TestSettings(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.GetSetting(ctx, "hostname"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if err := db.SetSetting(ctx, "hostname", "nas-01"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting(ctx, "hostname", "nas-02"); err != nil {
		t.Fatal(err)
	}
	v, err := db.GetSetting(ctx, "hostname")
	if err != nil || v != "nas-02" {
		t.Fatalf("got %q, %v", v, err)
	}
}
