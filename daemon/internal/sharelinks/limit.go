package sharelinks

import (
	"sync"
	"time"
)

// RateLimiter allows at most Max requests per key in each Window (a fixed
// window per key, which is plenty to stop scraping and token guessing).
type RateLimiter struct {
	Max    int
	Window time.Duration
	Now    func() time.Time // tests

	mu   sync.Mutex
	keys map[string]*window
}

type window struct {
	start time.Time
	n     int
}

// NewRateLimiter returns a limiter of max requests per window.
func NewRateLimiter(max int, per time.Duration) *RateLimiter {
	return &RateLimiter{Max: max, Window: per}
}

// Allow counts a request for key and reports whether it may go ahead.
func (l *RateLimiter) Allow(key string) bool {
	now := time.Now()
	if l.Now != nil {
		now = l.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.keys == nil {
		l.keys = map[string]*window{}
	}
	w := l.keys[key]
	if w == nil || now.Sub(w.start) >= l.Window {
		if len(l.keys) > 20000 {
			for k, v := range l.keys {
				if now.Sub(v.start) >= l.Window {
					delete(l.keys, k)
				}
			}
		}
		w = &window{start: now}
		l.keys[key] = w
	}
	w.n++
	return w.n <= l.Max
}
