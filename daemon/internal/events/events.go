// Package events is an in-process publish/subscribe broker. hardyd publishes
// job progress, notifications and state changes; WebSocket clients subscribe.
package events

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

// Event is one message delivered to subscribers.
type Event struct {
	ID    uint64          `json:"id"`
	Type  string          `json:"type"`
	Time  time.Time       `json:"time"`
	Data  json.RawMessage `json:"data,omitempty"`
	Admin bool            `json:"-"` // only delivered to admin subscribers
	User  int64           `json:"-"` // when non-zero, only delivered to this user (and admins)
}

// Well-known event types.
const (
	TypeJobUpdated   = "job.updated"
	TypeNotification = "notification"
	TypeAudit        = "audit.created"
)

// Subscriber receives events on C. If it falls behind by more than its buffer,
// events are dropped for it and Dropped is incremented.
type Subscriber struct {
	C       <-chan Event
	c       chan Event
	userID  int64
	admin   bool
	Dropped atomic.Uint64
}

// Broker fans events out to subscribers.
type Broker struct {
	mu     sync.RWMutex
	subs   map[*Subscriber]struct{}
	nextID atomic.Uint64
}

// NewBroker returns an empty broker.
func NewBroker() *Broker { return &Broker{subs: map[*Subscriber]struct{}{}} }

// Subscribe registers a subscriber for userID; admins also see admin-only events.
func (b *Broker) Subscribe(userID int64, admin bool, buffer int) *Subscriber {
	if buffer <= 0 {
		buffer = 64
	}
	c := make(chan Event, buffer)
	s := &Subscriber{C: c, c: c, userID: userID, admin: admin}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()
	return s
}

// Unsubscribe removes s and closes its channel.
func (b *Broker) Unsubscribe(s *Subscriber) {
	b.mu.Lock()
	if _, ok := b.subs[s]; ok {
		delete(b.subs, s)
		close(s.c)
	}
	b.mu.Unlock()
}

// Publish sends an event to every subscriber allowed to see it. It never blocks.
func (b *Broker) Publish(e Event) Event {
	e.ID = b.nextID.Add(1)
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subs {
		if e.Admin && !s.admin {
			continue
		}
		if e.User != 0 && e.User != s.userID && !s.admin {
			continue
		}
		select {
		case s.c <- e:
		default:
			s.Dropped.Add(1)
		}
	}
	return e
}

// PublishJSON marshals data and publishes it with the given type.
func (b *Broker) PublishJSON(typ string, data any, adminOnly bool, userID int64) {
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	b.Publish(Event{Type: typ, Data: raw, Admin: adminOnly, User: userID})
}

// Count returns the number of active subscribers.
func (b *Broker) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}
