package cloudbackup

import (
	"context"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/fileworker"
)

// Limits on what restores can cost (decision 231). Every restore unpacks
// into a staging dataset with a quota (the version's size plus headroom,
// refused when the pool hasn't that much free); a person restores chosen
// files only, at most MaxUserBytes, one restore at a time; listing a
// version's folders is cached and at most a few restic processes list at
// once, a person at most two.

// MaxUserBytes caps a person's own restore.
const MaxUserBytes int64 = 20 << 30

// Concurrency.
const (
	maxBrowse           = 4 // restic ls at once, everyone
	maxPersonBrowse     = 2 // per person
	maxPersonRestores   = 3 // people's restores at once, everyone
	browseCacheLifetime = 2 * time.Minute
	browseCacheEntries  = 256
)

// stagingQuota is how much a version may take unpacked: its size, 4 KiB
// per file and 10% plus 256 MiB for metadata.
func stagingQuota(s *Snapshot) int64 {
	var size, files int64
	if s.Summary != nil {
		size, files = s.Summary.TotalBytes, s.Summary.TotalFiles
	}
	return size + size/10 + files*4096 + 256<<20
}

type limits struct {
	mu        sync.Mutex
	browse    chan struct{}
	browsing  map[string]int
	restoring map[string]bool
	people    int
	cache     map[string]browseCached
}

type browseCached struct {
	at      time.Time
	entries []Entry
}

func (l *limits) init() {
	if l.browse == nil {
		l.browse = make(chan struct{}, maxBrowse)
		l.browsing = map[string]int{}
		l.restoring = map[string]bool{}
		l.cache = map[string]browseCached{}
	}
}

func whoKey(w *fileworker.Who) string {
	if w == nil {
		return ""
	}
	return w.Principal
}

// startBrowse takes a listing slot (waiting for one), refusing a person
// who already has maxPersonBrowse running.
func (r *Root) startBrowse(ctx context.Context, who *fileworker.Who) (func(), error) {
	l := &r.lim
	l.mu.Lock()
	l.init()
	k := whoKey(who)
	if k != "" && l.browsing[k] >= maxPersonBrowse {
		l.mu.Unlock()
		return nil, problemf("you're already looking through backups; try again in a moment")
	}
	l.browsing[k]++
	sem := l.browse
	l.mu.Unlock()
	done := func() {
		l.mu.Lock()
		l.browsing[k]--
		l.mu.Unlock()
	}
	select {
	case sem <- struct{}{}:
		return func() { <-sem; done() }, nil
	case <-ctx.Done():
		done()
		return nil, ctx.Err()
	}
}

func (r *Root) cachedBrowse(key string) ([]Entry, bool) {
	l := &r.lim
	l.mu.Lock()
	defer l.mu.Unlock()
	l.init()
	c, ok := l.cache[key]
	if !ok || time.Since(c.at) > browseCacheLifetime {
		return nil, false
	}
	return c.entries, true
}

func (r *Root) cacheBrowse(key string, e []Entry) {
	l := &r.lim
	l.mu.Lock()
	defer l.mu.Unlock()
	l.init()
	if len(l.cache) >= browseCacheEntries {
		for k, c := range l.cache {
			if time.Since(c.at) > browseCacheLifetime || len(l.cache) >= browseCacheEntries {
				delete(l.cache, k)
			}
		}
	}
	l.cache[key] = browseCached{at: time.Now(), entries: e}
}

// startPersonRestore lets a person have one restore running, and people
// at most maxPersonRestores.
func (r *Root) startPersonRestore(who *fileworker.Who) (func(), error) {
	l := &r.lim
	l.mu.Lock()
	defer l.mu.Unlock()
	l.init()
	k := whoKey(who)
	if l.restoring[k] {
		return nil, problemf("one of your restores is still running; wait for it to finish")
	}
	if l.people >= maxPersonRestores {
		return nil, problemf("the server is busy with other people's restores; try again in a few minutes")
	}
	l.restoring[k] = true
	l.people++
	return func() {
		l.mu.Lock()
		delete(l.restoring, k)
		l.people--
		l.mu.Unlock()
	}, nil
}
