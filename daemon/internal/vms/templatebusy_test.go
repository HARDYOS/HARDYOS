package vms

import (
	"context"
	"fmt"
	"testing"
)

// Once a template or clone task says it's done, its locks are free: what
// a person (or a job) does next, like deleting the template or starting
// the VM, never finds them still held.
func TestTemplateLocksFreeWhenTaskDone(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	e.fakeSendRecv()
	// At the moment a task becomes done, its locks must already be free
	// (checked inside finish, so the order is what's tested, not timing).
	var held []string
	e.m.tasks.onFinish = func(x Task) {
		names := []string{x.VM}
		if x.Kind == "template" || x.Kind == "clone" {
			names = append(names, templateLock(x.File)) // File is the template's id
		}
		for _, n := range names {
			if unlock, ok := e.m.tryLock(n); ok {
				unlock()
			} else {
				held = append(held, x.Kind+":"+n)
			}
		}
	}
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	task, err := e.m.MakeTemplate(ctx, MakeTemplateArgs{VM: "web", ID: "base", Name: "Base"})
	if err != nil {
		t.Fatal(err)
	}
	if d := waitDone(t, e.m, task.ID); d.Error != "" {
		t.Fatalf("template = %+v", d)
	}
	for _, name := range []string{"web", templateLock("base")} {
		unlock, ok := e.m.tryLock(name)
		if !ok {
			t.Fatalf("%s still locked after the template task finished", name)
		}
		unlock()
	}
	l, err := e.m.UserTemplates(ctx)
	if err != nil || len(l) != 1 {
		t.Fatalf("templates = %+v %v", l, err)
	}
	for i := 0; i < 20; i++ {
		s := l[0].Spec
		s.ID, s.Name, s.Pool = fmt.Sprintf("copy%d", i), fmt.Sprintf("Copy %d", i), "tank"
		s.Disks[0].Clone = &Clone{Template: "base"}
		if _, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "longenough"}); err != nil {
			t.Fatal(err)
		}
		ct, err := e.m.StartClone(ctx, ImportArgs{ID: s.ID, Disk: "disk0"})
		if err != nil {
			t.Fatal(err)
		}
		if d := waitDone(t, e.m, ct.ID); d.Error != "" {
			t.Fatalf("clone = %+v", d)
		}
		for _, name := range []string{s.ID, templateLock("base")} {
			unlock, ok := e.m.tryLock(name)
			if !ok {
				t.Fatalf("round %d: %s still locked after the clone finished", i, name)
			}
			unlock()
		}
	}
	if err := e.m.DeleteTemplate(ctx, DeleteTemplateArgs{ID: "base", Confirm: "Base"}); err != nil {
		t.Fatalf("delete right after the clones: %v", err)
	}
	if len(held) > 0 {
		t.Fatalf("locks still held when tasks were marked done: %v", held)
	}
}
