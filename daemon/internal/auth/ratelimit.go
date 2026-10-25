package auth

import (
	"sync"
	"time"
)

// LoginLimiter throttles failed sign-ins per key (an IP address or a username).
// After MaxFailures failures within Window, the key is locked for Lockout.
type LoginLimiter struct {
	MaxFailures int
	Window      time.Duration
	Lockout     time.Duration

	mu      sync.Mutex
	entries map[string]*limitEntry
	now     func() time.Time
}

type limitEntry struct {
	failures    []time.Time
	lockedUntil time.Time
}

// NewLoginLimiter returns a limiter with HardyOS defaults: 5 failures in 15
// minutes locks the key for 15 minutes.
func NewLoginLimiter() *LoginLimiter {
	return &LoginLimiter{MaxFailures: 5, Window: 15 * time.Minute, Lockout: 15 * time.Minute}
}

func (l *LoginLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// Allowed reports whether key may attempt a sign-in, and if not, for how long it is locked.
func (l *LoginLimiter) Allowed(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		return true, 0
	}
	if now := l.clock(); now.Before(e.lockedUntil) {
		return false, e.lockedUntil.Sub(now)
	}
	return true, 0
}

// Fail records a failed attempt for key.
func (l *LoginLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = map[string]*limitEntry{}
	}
	now := l.clock()
	e := l.entries[key]
	if e == nil {
		e = &limitEntry{}
		l.entries[key] = e
	}
	cutoff := now.Add(-l.Window)
	kept := e.failures[:0]
	for _, t := range e.failures {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	e.failures = append(kept, now)
	if len(e.failures) >= l.MaxFailures {
		e.lockedUntil = now.Add(l.Lockout)
		e.failures = nil
	}
	// Bound memory: drop entries that are idle and unlocked.
	if len(l.entries) > 10000 {
		for k, v := range l.entries {
			if len(v.failures) == 0 && now.After(v.lockedUntil) {
				delete(l.entries, k)
			}
		}
	}
}

// Succeed clears the failure history for key.
func (l *LoginLimiter) Succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
