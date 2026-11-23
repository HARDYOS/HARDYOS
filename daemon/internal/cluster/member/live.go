package member

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Live is the cluster core as parts B and C use it: cluster.Membership,
// cluster.PeerClient and cluster.PeerMux over whatever core the Service
// runs now. The Service replaces its core when this server leaves a
// cluster (a new key, a new state machine), so the parts never hold a core
// themselves: appliers and peer handlers registered here are added to
// every core before it starts (Service.Configure, so before the log is
// replayed), and every other call goes to the current core.
type Live struct {
	svc *Service

	mu       sync.Mutex
	appliers []cluster.Applier
	handlers []liveHandler
	progress map[*cluster.Core]*liveProgress
	migrate  func(conn *tls.Conn, from cluster.Node)
	changed  chan struct{} // closed when the core is replaced
}

type liveHandler struct {
	pattern string
	h       http.Handler
	fenced  bool
}

var (
	_ cluster.Membership = (*Live)(nil)
	_ cluster.PeerClient = (*Live)(nil)
	_ cluster.PeerMux    = (*Live)(nil)
)

// Live returns the service's live view; call before Init so that every
// core gets what the parts register. One per Service.
func (s *Service) Live() *Live {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live != nil {
		return s.live
	}
	l := &Live{svc: s, changed: make(chan struct{})}
	s.live = l
	s.Configure = append(s.Configure, l.configure)
	if s.core != nil { // Init ran already: catch up with the current core
		l.configureLocked(s.core)
	}
	return l
}

// configure is the Service.Configure hook for a new core.
func (l *Live) configure(c *cluster.Core) { l.configureLocked(c) }

func (l *Live) configureLocked(c *cluster.Core) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.syncLocked(c)
	if l.migrate != nil {
		c.SetMigrate(l.migrate) // before the core starts
	}
	close(l.changed)
	l.changed = make(chan struct{})
}

// liveProgress is how much of the registrations a core has (a pattern
// registered twice would make its mux panic).
type liveProgress struct{ appliers, handlers int }

func (l *Live) syncLocked(c *cluster.Core) {
	if c == nil {
		return
	}
	p := l.progress[c]
	if p == nil {
		if l.progress == nil {
			l.progress = map[*cluster.Core]*liveProgress{}
		}
		p = &liveProgress{}
		l.progress[c] = p
	}
	for ; p.appliers < len(l.appliers); p.appliers++ {
		c.Register(l.appliers[p.appliers])
	}
	mux := c.Mux()
	for ; p.handlers < len(l.handlers); p.handlers++ {
		h := l.handlers[p.handlers]
		if h.fenced {
			mux.AllowFenced(h.pattern, h.h)
		} else {
			mux.Handle(h.pattern, h.h)
		}
	}
}

// sync brings the current core up to date (never under s.mu: Core takes it).
func (l *Live) sync() {
	c := l.svc.Core()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.syncLocked(c)
}

// Core is the current core (nil before Init).
func (l *Live) Core() *cluster.Core { return l.svc.Core() }

func (l *Live) core() (*cluster.Core, error) {
	c := l.svc.Core()
	if c == nil {
		return nil, cluster.ErrNotMember
	}
	return c, nil
}

// ---- cluster.Membership ---------------------------------------------------------

// Self implements cluster.Membership.
func (l *Live) Self() (cluster.Node, error) {
	c, err := l.core()
	if err != nil {
		return cluster.Node{}, err
	}
	return c.Self()
}

// State implements cluster.Membership (the current core's machine).
func (l *Live) State() cluster.State {
	if c := l.svc.Core(); c != nil {
		return c.State()
	}
	return emptyState{}
}

// Leader implements cluster.Membership.
func (l *Live) Leader() (cluster.NodeID, bool) {
	if c := l.svc.Core(); c != nil {
		return c.Leader()
	}
	return "", false
}

// Quorate implements cluster.Membership.
func (l *Live) Quorate() (bool, time.Time) {
	if c := l.svc.Core(); c != nil {
		return c.Quorate()
	}
	return false, time.Time{}
}

// LeaseStatement implements fence.LeaseSource: the leader's latest signed
// answer to this node's heartbeat, which root checks before each pet.
func (l *Live) LeaseStatement() ([]byte, bool) {
	if c := l.svc.Core(); c != nil {
		return c.LeaseStatement()
	}
	return nil, false
}

// Health implements cluster.Membership.
func (l *Live) Health(ctx context.Context) ([]cluster.Health, error) {
	c, err := l.core()
	if err != nil {
		return nil, err
	}
	return c.Health(ctx)
}

// Propose implements cluster.Membership.
func (l *Live) Propose(ctx context.Context, t cluster.CommandType, body any, actor cluster.Actor) (uint64, error) {
	c, err := l.core()
	if err != nil {
		return 0, err
	}
	return c.Propose(ctx, t, body, actor)
}

// WaitApplied implements cluster.Membership.
func (l *Live) WaitApplied(ctx context.Context, index uint64) error {
	c, err := l.core()
	if err != nil {
		return err
	}
	return c.WaitApplied(ctx, index)
}

// Subscribe implements cluster.Membership. It follows core replacements:
// when the core changes it subscribes to the new one and sends an empty
// event (with the new index), so subscribers re-read the state.
func (l *Live) Subscribe(ctx context.Context) <-chan cluster.Event {
	out := make(chan cluster.Event, 64)
	go func() {
		defer close(out)
		for {
			l.mu.Lock()
			changed := l.changed
			l.mu.Unlock()
			c := l.svc.Core()
			sctx, cancel := context.WithCancel(ctx)
			var in <-chan cluster.Event
			if c != nil {
				in = c.Subscribe(sctx)
			}
		forward:
			for {
				select {
				case <-ctx.Done():
					cancel()
					return
				case <-changed:
					break forward
				case e, ok := <-in:
					if !ok {
						in = nil
						continue
					}
					select {
					case out <- e:
					case <-ctx.Done():
						cancel()
						return
					}
				}
			}
			cancel()
			var idx uint64
			if c := l.svc.Core(); c != nil {
				idx = c.State().Index()
			}
			select {
			case out <- cluster.Event{Index: idx}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

// Register implements cluster.Membership: the applier is added to the
// current core and to every later one.
func (l *Live) Register(a cluster.Applier) {
	l.mu.Lock()
	l.appliers = append(l.appliers, a)
	l.mu.Unlock()
	l.sync()
}

// ---- cluster.PeerClient -----------------------------------------------------------

// Call implements cluster.PeerClient.
func (l *Live) Call(ctx context.Context, node cluster.NodeID, method, path string, in, out any) error {
	c, err := l.core()
	if err != nil {
		return err
	}
	return c.Peers().Call(ctx, node, method, path, in, out)
}

// Do implements cluster.PeerClient.
func (l *Live) Do(ctx context.Context, node cluster.NodeID, r *http.Request) (*http.Response, error) {
	c, err := l.core()
	if err != nil {
		return nil, err
	}
	return c.Peers().Do(ctx, node, r)
}

// ---- cluster.PeerMux ----------------------------------------------------------------

// Handle implements cluster.PeerMux.
func (l *Live) Handle(pattern string, h http.Handler) { l.add(liveHandler{pattern: pattern, h: h}) }

// AllowFenced implements cluster.PeerMux.
func (l *Live) AllowFenced(pattern string, h http.Handler) {
	l.add(liveHandler{pattern: pattern, h: h, fenced: true})
}

func (l *Live) add(h liveHandler) {
	l.mu.Lock()
	l.handlers = append(l.handlers, h)
	l.mu.Unlock()
	l.sync()
}

// Caller implements cluster.PeerMux (the caller is set on the request by
// whichever core's mux served it).
func (l *Live) Caller(r *http.Request) (cluster.Node, bool) {
	c := l.svc.Core()
	if c == nil {
		return cluster.Node{}, false
	}
	return c.Mux().Caller(r)
}

// emptyState is the state outside a cluster.
type emptyState struct{}

func (emptyState) Snapshot() *cluster.Snapshot {
	return &cluster.Snapshot{Nodes: map[cluster.NodeID]*cluster.Node{}, Placements: map[cluster.WorkloadRef]*cluster.Placement{},
		Grants: map[cluster.WorkloadRef]*cluster.Grant{}, Fences: map[cluster.NodeID]*cluster.Fence{}, Seq: map[cluster.NodeID]uint64{}}
}
func (emptyState) Node(cluster.NodeID) (*cluster.Node, bool)                { return nil, false }
func (emptyState) Placement(cluster.WorkloadRef) (*cluster.Placement, bool) { return nil, false }
func (emptyState) Grant(cluster.WorkloadRef) (*cluster.Grant, bool)         { return nil, false }
func (emptyState) Index() uint64                                            { return 0 }

// SetMigrate sets part C's live migration hook (the cluster port's
// hardyos-migrate/1) on every core. Call before Init.
func (l *Live) SetMigrate(f func(conn *tls.Conn, from cluster.Node)) {
	l.mu.Lock()
	l.migrate = f
	l.mu.Unlock()
}

// DialMigrate dials a member's hardyos-migrate/1 on the current path (LAN,
// then the storage network; never NetBird).
func (l *Live) DialMigrate(ctx context.Context, node cluster.NodeID) (net.Conn, error) {
	c, err := l.core()
	if err != nil {
		return nil, err
	}
	conn, _, err := c.Transport().DialNode(ctx, node, cluster.ALPNMigrate)
	return conn, err
}
