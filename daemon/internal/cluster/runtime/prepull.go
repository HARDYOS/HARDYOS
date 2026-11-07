package runtime

import (
	"context"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

// ImageSource says which images a cluster app uses (asked of the node that
// runs it: its resolved compose file).
type ImageSource interface {
	Images(ctx context.Context, owner cluster.NodeID, app string) ([]string, error)
}

// Images is this node's image store.
type Images interface {
	Have(ctx context.Context, images []string) ([]string, error)
	// Pull returns the images that failed, with why.
	Pull(ctx context.Context, images []string) (map[string]string, error)
}

// PrepullStatus is one HA app's images on this node.
type PrepullStatus struct {
	App     string            `json:"app"`
	Images  []string          `json:"images"`
	Missing []string          `json:"missing"`
	Failed  map[string]string `json:"failed,omitempty"`
	Checked time.Time         `json:"checked"`
}

// Prepuller keeps every HA app's images on this node when this node could
// take the app over (decision 355): an HA app then fails over without the
// internet. Images are refreshed when the app's image list changes (an
// update) and checked again every Interval.
type Prepuller struct {
	Cluster Cluster
	Source  ImageSource
	Images  Images
	// Interval between full checks (default 15 minutes).
	Interval time.Duration
	Now      func() time.Time
	Log      *slog.Logger

	mu     sync.Mutex
	status map[string]*PrepullStatus
	known  map[string][]string // app -> last image list
}

func (p *Prepuller) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Prepuller) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}

// Status lists the HA apps' images on this node.
func (p *Prepuller) Status() []PrepullStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]PrepullStatus, 0, len(p.status))
	for _, s := range p.status {
		c := *s
		c.Images = slices.Clone(s.Images)
		c.Missing = slices.Clone(s.Missing)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].App < out[j].App })
	return out
}

// Run checks on every state change (at most every 30 s) and every
// Interval.
func (p *Prepuller) Run(ctx context.Context, events <-chan cluster.Event) error {
	iv := p.Interval
	if iv <= 0 {
		iv = 15 * time.Minute
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	var last time.Time
	for {
		if p.now().Sub(last) >= 30*time.Second {
			p.Step(ctx, false)
			last = p.now()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			p.Step(ctx, true)
			last = p.now()
		case <-events:
		}
	}
}

// Step makes sure this node has the images of every HA app it could take
// over. full checks every app, otherwise only apps whose list changed.
func (p *Prepuller) Step(ctx context.Context, full bool) {
	self, err := p.Cluster.Self()
	if err != nil || self.Role != cluster.RoleCompute {
		return
	}
	s := p.Cluster.State().Snapshot()
	if ok, _ := state.HAEligible(s, self.ID); !ok {
		p.mu.Lock()
		p.status = map[string]*PrepullStatus{}
		p.mu.Unlock()
		return
	}
	wanted := map[string]bool{}
	for _, pl := range state.SortedPlacements(s) {
		if pl.Workload.Kind != cluster.KindApp || !pl.HA.Enabled || pl.Owner == "" {
			continue
		}
		if pl.HA.Restricted && !slices.Contains(pl.HA.Preferred, self.ID) {
			continue
		}
		wanted[pl.Workload.ID] = true
		imgs, err := p.Source.Images(ctx, pl.Owner, pl.Workload.ID)
		if err != nil {
			p.log().Debug("cluster: an HA app's images", "app", pl.Workload.ID, "err", err)
			p.mu.Lock()
			imgs = slices.Clone(p.known[pl.Workload.ID])
			p.mu.Unlock()
			if len(imgs) == 0 {
				continue
			}
		}
		slices.Sort(imgs)
		p.mu.Lock()
		if p.known == nil {
			p.known = map[string][]string{}
			p.status = map[string]*PrepullStatus{}
		}
		changed := !slices.Equal(p.known[pl.Workload.ID], imgs)
		p.known[pl.Workload.ID] = imgs
		p.mu.Unlock()
		if !changed && !full {
			continue
		}
		p.ensure(ctx, pl.Workload.ID, imgs)
	}
	p.mu.Lock()
	for app := range p.status {
		if !wanted[app] {
			delete(p.status, app)
			delete(p.known, app)
		}
	}
	p.mu.Unlock()
}

func (p *Prepuller) ensure(ctx context.Context, app string, imgs []string) {
	st := &PrepullStatus{App: app, Images: imgs, Missing: []string{}, Checked: p.now()}
	have, err := p.Images.Have(ctx, imgs)
	if err != nil {
		st.Failed = map[string]string{"*": err.Error()}
		st.Missing = imgs
		p.set(st)
		return
	}
	var missing []string
	for _, img := range imgs {
		if !slices.Contains(have, img) {
			missing = append(missing, img)
		}
	}
	if len(missing) > 0 {
		failed, err := p.Images.Pull(ctx, missing)
		if err != nil {
			failed = map[string]string{"*": err.Error()}
		}
		st.Failed = failed
		for _, img := range missing {
			if _, bad := failed[img]; bad || err != nil {
				st.Missing = append(st.Missing, img)
			}
		}
		if len(st.Missing) == 0 {
			p.log().Info("cluster: HA app images ready for failover", "app", app, "pulled", len(missing))
		}
	}
	p.set(st)
}

func (p *Prepuller) set(st *PrepullStatus) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.status == nil {
		p.status = map[string]*PrepullStatus{}
	}
	p.status[st.App] = st
}
