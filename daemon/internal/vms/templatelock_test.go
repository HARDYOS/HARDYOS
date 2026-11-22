package vms

import (
	"context"
	"strings"
	"testing"
)

// L7: a template can't be deleted while a VM is copied from it.
func TestTemplateDeleteWaitsForClones(t *testing.T) {
	e := newEnv(t)
	unlock, ok := e.m.tryLock(templateLock("base"))
	if !ok {
		t.Fatal("no lock")
	}
	if err := e.m.DeleteTemplate(context.Background(), DeleteTemplateArgs{ID: "base", Confirm: "base"}); err == nil || !strings.Contains(err.Error(), "right now") {
		t.Fatalf("delete while busy: %v", err)
	}
	unlock()
	again, ok := e.m.tryLock(templateLock("base"))
	if !ok {
		t.Fatal("the lock wasn't given back")
	}
	again()
}
