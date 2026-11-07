// Package runtime runs cluster workloads on this node through hardyd-priv
// (docs/plans/cluster.md sections 6 and 7): the VM and app runtimes, the
// watchdog and self-fence clients the fence agent uses, the reconciler
// that keeps what runs here in line with the replicated placements, and
// the pre-puller that keeps HA apps' images on every eligible node.
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// Priv is the part of priv.Client the runtimes use.
type Priv interface {
	Call(ctx context.Context, op string, args, out any) error
	CallFile(ctx context.Context, op string, args, out any) (*os.File, error)
}

var _ Priv = (*priv.Client)(nil)

// ---- watchdog ----------------------------------------------------------------------

// PrivWatchdog is cluster.Watchdog over hardyd-priv's watchdog operations.
type PrivWatchdog struct{ Priv Priv }

var _ cluster.Watchdog = PrivWatchdog{}

func short(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 5*time.Second)
}

// Arm implements cluster.Watchdog.
func (w PrivWatchdog) Arm(ctx context.Context, timeout time.Duration) (string, error) {
	ctx, cancel := short(ctx)
	defer cancel()
	var res priv.WatchdogArmResult
	err := w.Priv.Call(ctx, priv.OpClusterWatchdogArm, priv.WatchdogArmArgs{TimeoutSec: int((timeout + time.Second - 1) / time.Second)}, &res)
	return res.Kind, err
}

// Pet implements cluster.Watchdog.
func (w PrivWatchdog) Pet(ctx context.Context, validFor time.Duration) error {
	ctx, cancel := short(ctx)
	defer cancel()
	return w.Priv.Call(ctx, priv.OpClusterWatchdogPet, priv.WatchdogPetArgs{ValidForMs: validFor.Milliseconds()}, nil)
}

// Disarm implements cluster.Watchdog.
func (w PrivWatchdog) Disarm(ctx context.Context) error {
	ctx, cancel := short(ctx)
	defer cancel()
	return w.Priv.Call(ctx, priv.OpClusterWatchdogDisarm, nil, nil)
}

// Expire implements cluster.Watchdog.
func (w PrivWatchdog) Expire(ctx context.Context) error {
	ctx, cancel := short(ctx)
	defer cancel()
	return w.Priv.Call(ctx, priv.OpClusterWatchdogExpire, nil, nil)
}

// ---- self-fencing --------------------------------------------------------------------

// SelfFencer kills HA workloads through hardyd-priv and then detaches their
// storage (fence.SelfFencer).
type SelfFencer struct {
	Priv     Priv
	Attacher cluster.StorageAttacher
	Log      *slog.Logger
}

// SelfFence stops ws by force; nil only when every one stopped.
func (f SelfFencer) SelfFence(ctx context.Context, epoch uint64, ws []cluster.WorkloadRef) error {
	if len(ws) == 0 {
		return nil
	}
	a := priv.SelfFenceArgs{Epoch: epoch, VMs: []string{}, Apps: []string{}}
	for _, w := range ws {
		if w.Kind == cluster.KindVM {
			a.VMs = append(a.VMs, w.ID)
		} else {
			a.Apps = append(a.Apps, w.ID)
		}
	}
	if err := f.Priv.Call(ctx, priv.OpClusterSelfFence, a, nil); err != nil {
		return err
	}
	if f.Attacher != nil {
		for _, w := range ws {
			if err := f.Attacher.Detach(ctx, w, true); err != nil && f.Log != nil {
				f.Log.Warn("fence: detaching after the self-fence", "workload", w.ID, "err", err)
			}
		}
	}
	return nil
}

// ---- VMs -------------------------------------------------------------------------------

// VMRuntime is cluster.Runtime for VMs.
type VMRuntime struct {
	Priv Priv
	// HostModel is this node's CPU model (for host-passthrough VMs).
	HostModel func() string
	// GracefulTimeout bounds a graceful stop before it is forced
	// (default 3 minutes).
	GracefulTimeout time.Duration
	// Poll is how often a stop is checked (default 2 s).
	Poll time.Duration
}

var _ cluster.Runtime = (*VMRuntime)(nil)

// Kind implements cluster.Runtime.
func (r *VMRuntime) Kind() cluster.WorkloadKind { return cluster.KindVM }

// Requirements implements cluster.Runtime.
func (r *VMRuntime) Requirements(ctx context.Context, w cluster.WorkloadRef) (*cluster.Requirements, error) {
	var v vms.VM
	if err := r.Priv.Call(ctx, priv.OpVMsGet, priv.VMRef{ID: w.ID}, &v); err != nil {
		return nil, err
	}
	var caps vms.Capabilities
	_ = r.Priv.Call(ctx, priv.OpVMsCapabilities, nil, &caps)
	return VMRequirements(&v.Spec, caps.Bridge, r.hostModel()), nil
}

func (r *VMRuntime) hostModel() string {
	if r.HostModel != nil {
		return r.HostModel()
	}
	return ""
}

// VMRequirements is what a VM needs from a node.
func VMRequirements(s *vms.Spec, bridge, hostModel string) *cluster.Requirements {
	req := &cluster.Requirements{MemoryMB: s.Memory.MB, CPUs: s.CPU.VCPUs(), KVM: true}
	if s.CPUModel == "" {
		// host-passthrough: only a server with the same CPU.
		req.CPUModel = hostModel
	}
	if s.NeedsBridge() {
		if bridge == "" {
			bridge = "br0"
		}
		vlans := []int{}
		for _, n := range s.NICs {
			if n.Mode == vms.NICVLAN {
				vlans = append(vlans, n.VLAN)
			}
		}
		req.Bridges = map[string][]int{bridge: vlans}
	}
	for _, d := range s.Devices {
		req.Devices = append(req.Devices, d.Kind+":"+d.ID)
	}
	return req
}

// Start implements cluster.Runtime.
func (r *VMRuntime) Start(ctx context.Context, w cluster.WorkloadRef, a *cluster.Attachment) error {
	if a == nil || a.Generation == 0 {
		return cluster.ErrStorageUnavailable
	}
	return r.Priv.Call(ctx, priv.OpVMsClusterStart, vms.ClusterStartArgs{ID: w.ID, Generation: a.Generation}, nil)
}

// Stop implements cluster.Runtime: graceful waits up to GracefulTimeout,
// then forces.
func (r *VMRuntime) Stop(ctx context.Context, w cluster.WorkloadRef, mode cluster.StopMode) error {
	force := mode == cluster.StopForce
	if err := r.Priv.Call(ctx, priv.OpVMsClusterStop, vms.ClusterStopArgs{ID: w.ID, Force: force, Undefine: force}, nil); err != nil {
		return err
	}
	if force {
		return nil
	}
	return waitStopped(ctx, r, w, r.GracefulTimeout, r.Poll, func(ctx context.Context) error {
		return r.Priv.Call(ctx, priv.OpVMsClusterStop, vms.ClusterStopArgs{ID: w.ID, Force: true}, nil)
	})
}

// Status implements cluster.Runtime.
func (r *VMRuntime) Status(ctx context.Context) ([]cluster.WorkloadStatus, error) {
	var l []vms.ClusterVM
	if err := r.Priv.Call(ctx, priv.OpVMsClusterStatus, nil, &l); err != nil {
		return nil, err
	}
	out := make([]cluster.WorkloadStatus, 0, len(l))
	for _, v := range l {
		st := cluster.WorkloadStatus{Workload: cluster.WorkloadRef{Kind: cluster.KindVM, ID: v.ID}, Generation: v.Generation,
			Running: v.State == "running", Paused: v.State == "paused"}
		if !v.Attached {
			st.Problem = "its storage isn't attached here"
		}
		out = append(out, st)
	}
	return out, nil
}

// ---- apps ------------------------------------------------------------------------------

// AppRuntime is cluster.Runtime for apps.
type AppRuntime struct {
	Priv            Priv
	GracefulTimeout time.Duration
	Poll            time.Duration
}

var _ cluster.Runtime = (*AppRuntime)(nil)

// Kind implements cluster.Runtime.
func (r *AppRuntime) Kind() cluster.WorkloadKind { return cluster.KindApp }

// Requirements implements cluster.Runtime: the images (memory limits are
// the app's own and not committed ahead).
func (r *AppRuntime) Requirements(ctx context.Context, w cluster.WorkloadRef) (*cluster.Requirements, error) {
	var res priv.ImagesResult
	if err := r.Priv.Call(ctx, priv.OpAppsClusterImages, priv.AppRef{ID: w.ID}, &res); err != nil {
		return nil, err
	}
	return &cluster.Requirements{Images: res.Images}, nil
}

// Start implements cluster.Runtime.
func (r *AppRuntime) Start(ctx context.Context, w cluster.WorkloadRef, a *cluster.Attachment) error {
	if a == nil || a.Generation == 0 {
		return cluster.ErrStorageUnavailable
	}
	return r.Priv.Call(ctx, priv.OpAppsClusterStart, apps.ClusterStartArgs{ID: w.ID, Generation: a.Generation}, nil)
}

// Stop implements cluster.Runtime.
func (r *AppRuntime) Stop(ctx context.Context, w cluster.WorkloadRef, mode cluster.StopMode) error {
	force := mode == cluster.StopForce
	if err := r.Priv.Call(ctx, priv.OpAppsClusterStop, apps.ClusterStopArgs{ID: w.ID, Force: force}, nil); err != nil {
		return err
	}
	if force {
		return nil
	}
	return waitStopped(ctx, r, w, r.GracefulTimeout, r.Poll, func(ctx context.Context) error {
		return r.Priv.Call(ctx, priv.OpAppsClusterStop, apps.ClusterStopArgs{ID: w.ID, Force: true}, nil)
	})
}

// Status implements cluster.Runtime.
func (r *AppRuntime) Status(ctx context.Context) ([]cluster.WorkloadStatus, error) {
	var l []apps.ClusterApp
	if err := r.Priv.Call(ctx, priv.OpAppsClusterStatus, nil, &l); err != nil {
		return nil, err
	}
	out := make([]cluster.WorkloadStatus, 0, len(l))
	for _, a := range l {
		st := cluster.WorkloadStatus{Workload: cluster.WorkloadRef{Kind: cluster.KindApp, ID: a.ID}, Generation: a.Generation, Running: a.Running}
		if !a.Attached {
			st.Problem = "its storage isn't attached here"
		}
		out = append(out, st)
	}
	return out, nil
}

// waitStopped polls a runtime until w no longer runs, forcing it after
// limit.
func waitStopped(ctx context.Context, rt cluster.Runtime, w cluster.WorkloadRef, limit, poll time.Duration, force func(context.Context) error) error {
	if limit <= 0 {
		limit = 3 * time.Minute
	}
	if poll <= 0 {
		poll = 2 * time.Second
	}
	deadline := time.Now().Add(limit)
	for {
		l, err := rt.Status(ctx)
		if err != nil {
			return err
		}
		running := false
		for _, s := range l {
			if s.Workload == w && (s.Running || s.Paused) {
				running = true
			}
		}
		if !running {
			return nil
		}
		if time.Now().After(deadline) {
			if err := force(ctx); err != nil {
				return fmt.Errorf("it didn't stop within %s and couldn't be forced: %w", limit, err)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// ---- images ----------------------------------------------------------------------------

// PrivImages is the local image store over hardyd-priv (Puller).
type PrivImages struct{ Priv Priv }

// Have lists which images are here.
func (p PrivImages) Have(ctx context.Context, images []string) ([]string, error) {
	var res priv.ImagesResult
	err := p.Priv.Call(ctx, priv.OpAppsHaveImages, apps.PrepullArgs{Images: images}, &res)
	return res.Images, err
}

// Pull downloads images; failed ones come back with their errors.
func (p PrivImages) Pull(ctx context.Context, images []string) (map[string]string, error) {
	var res apps.PrepullResult
	if err := p.Priv.Call(ctx, priv.OpAppsPrepull, apps.PrepullArgs{Images: images}, &res); err != nil {
		return nil, err
	}
	return res.Failed, nil
}

// ErrNoRuntime: no runtime for a workload's kind.
var ErrNoRuntime = errors.New("this server can't run that kind of workload")
