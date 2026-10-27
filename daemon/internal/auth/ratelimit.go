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

// DelayLimiter slows failed sign-ins down instead of locking a key out: the
// first Free failures within Window cost nothing, each one after that
// doubles the wait before the next attempt (1 s, 2 s, 4 s, ...) up to
// MaxDelay. It is for sign-ins from the internet (HardyOS sign-in through
// the app gateway), where a hard lockout would let any stranger lock a
// family member out by typing their name: the attacker gets a few guesses
// an hour, the person still gets in after a short wait.
type DelayLimiter struct {
	Free     int
	MaxDelay time.Duration
	Window   time.Duration

	mu      sync.Mutex
	entries map[string]*delayEntry
	now     func() time.Time
}

type delayEntry struct {
	failures int
	last     time.Time
	next     time.Time
}

// NewDelayLimiter returns a limiter with HardyOS's defaults: 3 free
// failures, then 1 s doubling up to 2 minutes; a key forgets its failures
// an hour after the last one.
func NewDelayLimiter() *DelayLimiter {
	return &DelayLimiter{Free: 3, MaxDelay: 2 * time.Minute, Window: time.Hour}
}

func (l *DelayLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// Allowed reports whether key may try now, and if not, how long to wait.
func (l *DelayLimiter) Allowed(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		return true, 0
	}
	if now := l.clock(); now.Before(e.next) {
		return false, e.next.Sub(now)
	}
	return true, 0
}

// Fail records a failed attempt for key.
func (l *DelayLimiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = map[string]*delayEntry{}
	}
	now := l.clock()
	e := l.entries[key]
	if e == nil || now.Sub(e.last) > l.Window {
		e = &delayEntry{}
		l.entries[key] = e
	}
	e.failures++
	e.last = now
	if over := e.failures - l.Free; over > 0 {
		d := time.Second
		for i := 1; i < over && d < l.MaxDelay; i++ {
			d *= 2
		}
		if d > l.MaxDelay {
			d = l.MaxDelay
		}
		e.next = now.Add(d)
	}
	if len(l.entries) > 10000 {
		for k, v := range l.entries {
			if now.Sub(v.last) > l.Window {
				delete(l.entries, k)
			}
		}
	}
}

// Succeed clears the failures for key.
func (l *DelayLimiter) Succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
