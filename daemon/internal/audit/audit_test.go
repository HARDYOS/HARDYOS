package audit

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/events"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func TestRecordAndList(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	b := events.NewBroker()
	sub := b.Subscribe(1, true, 8)
	log := &Log{DB: db, Events: b}

	id := int64(1)
	for _, a := range []string{"auth.login", "user.create", "user.delete", "storage.pool.create"} {
		if err := log.Record(ctx, Entry{ActorID: &id, Actor: "cade", Action: a, Outcome: Success}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := log.List(ctx, Query{})
	if err != nil || len(all) != 4 || all[0].Action != "storage.pool.create" {
		t.Fatalf("list all: %v %v", all, err)
	}
	users, _ := log.List(ctx, Query{Action: "user."})
	if len(users) != 2 {
		t.Fatalf("prefix filter got %d", len(users))
	}
	page, _ := log.List(ctx, Query{Limit: 2, Before: all[1].ID})
	if len(page) != 2 || page[0].ID != all[2].ID {
		t.Fatalf("paging got %v", page)
	}
	if len(sub.C) != 4 {
		t.Fatalf("published %d events, want 4", len(sub.C))
	}
}
