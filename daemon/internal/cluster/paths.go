package cluster

import (
	"context"
	"slices"
	"sync"
	"time"
)

// Paths (docs/plans/cluster.md 2.4, decisions 321 and 332): control
// traffic to a member goes over the LAN first, the storage network second
// and NetBird last. Every path both ends have is probed each interval; the
// path in use is left after DownAfter missed probes in a row, and a better
// path is taken back after UpAfter good probes in a row. The witness has
// only NetBird. Raft addresses are node ids, so Raft never sees a switch:
// connections on the old path are closed and redialled on the new one.

// PathOrder is the preference order of control paths.
var PathOrder = []Path{PathLAN, PathStorage, PathNetBird}

// PathTimings tune probing.
type PathTimings struct {
	Interval  time.Duration // between probes (1 s)
	Timeout   time.Duration // one probe (800 ms)
	DownAfter int           // missed probes before leaving the path in use (3)
	UpAfter   int           // good probes before going back to a better path (10)
}

// DefaultPathTimings are the plan's values.
var DefaultPathTimings = PathTimings{Interval: time.Second, Timeout: 800 * time.Millisecond, DownAfter: 3, UpAfter: 10}

// PathProbe is one path's live state.
type PathProbe struct {
	Path   Path          `json:"path"`
	Up     bool          `json:"up"`
	RTT    time.Duration `json:"rtt"`
	Good   int           `json:"good"`
	Missed int           `json:"missed"`
}

// PeerPath is this node's view of one peer.
type PeerPath struct {
	Node    NodeID        `json:"node"`
	Current Path          `json:"current"`
	RTT     time.Duration `json:"rtt"`
	Probes  []PathProbe   `json:"probes"`
	Changed time.Time     `json:"changed"`
}

// selector is the pure path choice for one peer.
type selector struct {
	avail   []Path // paths both ends have, in preference order
	cur     Path
	probes  map[Path]*PathProbe
	changed time.Time
}

func newSelector(avail []Path) *selector {
	s := &selector{avail: avail, cur: PathNone, probes: map[Path]*PathProbe{}}
	for _, p := range avail {
		s.probes[p] = &PathProbe{Path: p}
	}
	return s
}

func (s *selector) setAvail(avail []Path) {
	s.avail = avail
	for _, p := range avail {
		if s.probes[p] == nil {
			s.probes[p] = &PathProbe{Path: p}
		}
	}
	for p := range s.probes {
		if !slices.Contains(avail, p) {
			delete(s.probes, p)
		}
	}
	if s.cur != PathNone && !slices.Contains(avail, s.cur) {
		s.cur = PathNone
	}
}

// observe records a probe and returns the new current path if it changed.
func (s *selector) observe(p Path, ok bool, rtt time.Duration, t PathTimings, now time.Time) (Path, bool) {
	pr := s.probes[p]
	if pr == nil {
		return s.cur, false
	}
	if ok {
		pr.Good++
		pr.Missed = 0
		pr.Up = true
		pr.RTT = rtt
	} else {
		pr.Missed++
		pr.Good = 0
		if pr.Missed >= t.DownAfter {
			pr.Up = false
		}
	}
	old := s.cur
	switch {
	case s.cur == PathNone:
		// Nothing in use yet: the best path that answers.
		for _, q := range s.avail {
			if s.probes[q].Good > 0 {
				s.cur = q
				break
			}
		}
	case s.probes[s.cur].Missed >= t.DownAfter:
		// The path in use failed: the best other path that answers now.
		s.cur = PathNone
		for _, q := range s.avail {
			if s.probes[q].Good > 0 && s.probes[q].Missed == 0 {
				s.cur = q
				break
			}
		}
	default:
		// A better path that has been good long enough.
		for _, q := range s.avail {
			if q == s.cur {
				break
			}
			if s.probes[q].Good >= t.UpAfter {
				s.cur = q
				break
			}
		}
	}
	if s.cur != old {
		s.changed = now
		return s.cur, true
	}
	return s.cur, false
}

// Paths keeps the path in use for every peer.
type Paths struct {
	Timings PathTimings
	// Self is this node's addresses; Peers the members to probe.
	Self  func() Addresses
	Peers func() []Node
	// Probe sends one probe to a peer over a path.
	Probe func(ctx context.Context, n Node, p Path) (time.Duration, error)
	// OnSwitch is told when a peer's path changes.
	OnSwitch func(id NodeID, from, to Path)
	Now      func() time.Time

	mu  sync.Mutex
	sel map[NodeID]*selector
}

func (ps *Paths) now() time.Time {
	if ps.Now != nil {
		return ps.Now()
	}
	return time.Now()
}

func (ps *Paths) timings() PathTimings {
	t := ps.Timings
	if t.Interval == 0 {
		t = DefaultPathTimings
	}
	if t.DownAfter == 0 {
		t.DownAfter = DefaultPathTimings.DownAfter
	}
	if t.UpAfter == 0 {
		t.UpAfter = DefaultPathTimings.UpAfter
	}
	if t.Timeout == 0 {
		t.Timeout = t.Interval * 4 / 5
	}
	return t
}

// Available lists the paths two members share, in preference order. The
// witness is reached over NetBird only.
func Available(self, peer Addresses, selfRole, peerRole Role) []Path {
	var out []Path
	for _, p := range PathOrder {
		if (selfRole == RoleWitness || peerRole == RoleWitness) && p != PathNetBird {
			continue
		}
		if pathAddr(self, p).IsValid() && pathAddr(peer, p).IsValid() {
			out = append(out, p)
		}
	}
	return out
}

func (ps *Paths) selfAddrs() Addresses {
	if ps.Self == nil {
		return Addresses{}
	}
	return ps.Self()
}

// DialOrder is the order to try a peer's paths in: the one in use first,
// then the others by preference.
func (ps *Paths) DialOrder(id NodeID) []Path {
	if ps == nil {
		return PathOrder
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	s := ps.sel[id]
	if s == nil {
		return PathOrder
	}
	var out []Path
	if s.cur != PathNone {
		out = append(out, s.cur)
	}
	for _, p := range s.avail {
		if p != s.cur {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return PathOrder
	}
	return out
}

// Current is the path in use to a peer.
func (ps *Paths) Current(id NodeID) Path {
	if ps == nil {
		return PathNone
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if s := ps.sel[id]; s != nil {
		return s.cur
	}
	return PathNone
}

// Status is the view of every peer.
func (ps *Paths) Status() []PeerPath {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	out := []PeerPath{}
	for id, s := range ps.sel {
		pp := PeerPath{Node: id, Current: s.cur, Changed: s.changed, Probes: []PathProbe{}}
		for _, p := range s.avail {
			pr := *s.probes[p]
			pp.Probes = append(pp.Probes, pr)
			if p == s.cur {
				pp.RTT = pr.RTT
			}
		}
		out = append(out, pp)
	}
	slices.SortFunc(out, func(a, b PeerPath) int {
		if a.Node < b.Node {
			return -1
		}
		if a.Node > b.Node {
			return 1
		}
		return 0
	})
	return out
}

// Observe feeds one probe result in (the prober's, or a test's).
func (ps *Paths) Observe(n Node, selfRole Role, p Path, ok bool, rtt time.Duration) {
	ps.mu.Lock()
	if ps.sel == nil {
		ps.sel = map[NodeID]*selector{}
	}
	avail := Available(ps.selfAddrs(), n.Addresses, selfRole, n.Role)
	s := ps.sel[n.ID]
	if s == nil {
		s = newSelector(avail)
		ps.sel[n.ID] = s
	} else {
		s.setAvail(avail)
	}
	old := s.cur
	cur, changed := s.observe(p, ok, rtt, ps.timings(), ps.now())
	ps.mu.Unlock()
	if changed && ps.OnSwitch != nil {
		ps.OnSwitch(n.ID, old, cur)
	}
}

// Run probes every peer on every shared path each interval until ctx ends.
func (ps *Paths) Run(ctx context.Context, self NodeID, selfRole Role) {
	t := ps.timings()
	tick := time.NewTicker(t.Interval)
	defer tick.Stop()
	for {
		ps.round(ctx, self, selfRole, t)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (ps *Paths) round(ctx context.Context, self NodeID, selfRole Role, t PathTimings) {
	peers := ps.Peers()
	present := map[NodeID]bool{}
	var wg sync.WaitGroup
	for _, n := range peers {
		if n.ID == self {
			continue
		}
		present[n.ID] = true
		for _, p := range Available(ps.selfAddrs(), n.Addresses, selfRole, n.Role) {
			wg.Add(1)
			go func(n Node, p Path) {
				defer wg.Done()
				pctx, cancel := context.WithTimeout(ctx, t.Timeout)
				rtt, err := ps.Probe(pctx, n, p)
				cancel()
				if ctx.Err() != nil {
					return
				}
				ps.Observe(n, selfRole, p, err == nil, rtt)
			}(n, p)
		}
	}
	wg.Wait()
	ps.mu.Lock()
	for id := range ps.sel {
		if !present[id] {
			delete(ps.sel, id)
		}
	}
	ps.mu.Unlock()
}
