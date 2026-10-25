package events

import "testing"

func TestVisibility(t *testing.T) {
	b := NewBroker()
	admin := b.Subscribe(1, true, 8)
	alice := b.Subscribe(2, false, 8)
	bob := b.Subscribe(3, false, 8)

	b.Publish(Event{Type: "public"})
	b.Publish(Event{Type: "admin-only", Admin: true})
	b.Publish(Event{Type: "for-alice", User: 2})

	got := func(s *Subscriber) []string {
		var out []string
		for {
			select {
			case e := <-s.C:
				out = append(out, e.Type)
			default:
				return out
			}
		}
	}
	if g := got(admin); len(g) != 3 {
		t.Errorf("admin got %v, want all 3", g)
	}
	if g := got(alice); len(g) != 2 || g[1] != "for-alice" {
		t.Errorf("alice got %v", g)
	}
	if g := got(bob); len(g) != 1 || g[0] != "public" {
		t.Errorf("bob got %v", g)
	}
}

func TestSlowSubscriberDoesNotBlock(t *testing.T) {
	b := NewBroker()
	s := b.Subscribe(1, false, 2)
	for i := 0; i < 10; i++ {
		b.Publish(Event{Type: "x"})
	}
	if s.Dropped.Load() != 8 {
		t.Fatalf("dropped = %d, want 8", s.Dropped.Load())
	}
	b.Unsubscribe(s)
	b.Unsubscribe(s) // idempotent
	if b.Count() != 0 {
		t.Fatal("subscriber not removed")
	}
}
