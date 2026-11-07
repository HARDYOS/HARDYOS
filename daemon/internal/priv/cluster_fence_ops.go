package priv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cluster/fence"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// Cluster fencing operations (Phase 8 part C, docs/plans/cluster.md
// section 7.2). Root owns the watchdog: it pets it itself, but only while
// the deadline hardyd last gave is ahead (cluster.watchdog.pet). hardyd
// never gets the device.
const (
	OpClusterWatchdogStatus = "cluster.watchdog.status"
	OpClusterWatchdogArm    = "cluster.watchdog.arm"
	OpClusterWatchdogPet    = "cluster.watchdog.pet"
	OpClusterWatchdogDisarm = "cluster.watchdog.disarm"
	OpClusterWatchdogExpire = "cluster.watchdog.expire"
	OpClusterSelfFence      = "cluster.selffence"
)

// WatchdogArmArgs arms the watchdog with a timeout (5-60 s).
type WatchdogArmArgs struct {
	TimeoutSec int `json:"timeoutSec"`
}

// WatchdogArmResult says which watchdog was armed.
type WatchdogArmResult struct {
	Kind string `json:"kind"`
}

// WatchdogPetArgs lets root pet for ValidForMs more (at most 2 minutes).
type WatchdogPetArgs struct {
	ValidForMs int64 `json:"validForMs"`
}

// SelfFenceArgs stops cluster workloads by force: the HA workloads of a
// node that lost quorum or was declared dead or isolated.
type SelfFenceArgs struct {
	Epoch uint64   `json:"epoch"`
	VMs   []string `json:"vms"`
	Apps  []string `json:"apps"`
}

// SelfFenceResult lists what couldn't be stopped.
type SelfFenceResult struct {
	Stopped []string          `json:"stopped"`
	Failed  map[string]string `json:"failed"`
}

// MaxSelfFence bounds one self-fence request.
const MaxSelfFence = 256

// RegisterClusterFence adds the fencing operations. vmm and am may be nil
// (no VMs or apps on this build).
func RegisterClusterFence(s *Server, f *fence.Feeder, vmm *vms.Manager, am *apps.Manager) {
	s.Handle(OpClusterWatchdogStatus, func(context.Context, json.RawMessage) (any, error) {
		return f.Status(), nil
	})
	s.Handle(OpClusterWatchdogArm, typed(func(_ context.Context, a WatchdogArmArgs) (any, error) {
		kind, err := f.Arm(time.Duration(a.TimeoutSec) * time.Second)
		if errors.Is(err, fence.ErrNoWatchdog) {
			return nil, Errorf(CodeBadArgs, "%v", err)
		}
		if err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		return WatchdogArmResult{Kind: kind}, nil
	}))
	s.Handle(OpClusterWatchdogPet, typed(func(_ context.Context, a WatchdogPetArgs) (any, error) {
		if a.ValidForMs <= 0 || a.ValidForMs > (2*time.Minute).Milliseconds() {
			return nil, Errorf(CodeBadArgs, "a pet is valid for 1 ms to 2 minutes")
		}
		if err := f.Pet(time.Duration(a.ValidForMs) * time.Millisecond); err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		return map[string]bool{"ok": true}, nil
	}))
	s.Handle(OpClusterWatchdogExpire, func(context.Context, json.RawMessage) (any, error) {
		f.Expire()
		return map[string]bool{"ok": true}, nil
	})
	s.Handle(OpClusterWatchdogDisarm, func(context.Context, json.RawMessage) (any, error) {
		if err := f.Disarm(); err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		return map[string]bool{"ok": true}, nil
	})
	s.Handle(OpClusterSelfFence, typed(func(ctx context.Context, a SelfFenceArgs) (any, error) {
		if len(a.VMs)+len(a.Apps) > MaxSelfFence {
			return nil, Errorf(CodeBadArgs, "too many workloads")
		}
		for _, id := range a.VMs {
			if vms.ValidID(id) != nil {
				return nil, Errorf(CodeBadArgs, "%q isn't a VM id", id)
			}
		}
		for _, id := range a.Apps {
			if apps.ValidID(id) != nil {
				return nil, Errorf(CodeBadArgs, "%q isn't an app id", id)
			}
		}
		res := SelfFenceResult{Stopped: []string{}, Failed: map[string]string{}}
		for _, id := range a.VMs {
			if vmm == nil {
				res.Failed["vm:"+id] = "this server has no VM engine"
				continue
			}
			if _, err := vmm.ClusterStop(ctx, vms.ClusterStopArgs{ID: id, Force: true, Undefine: true}); err != nil {
				res.Failed["vm:"+id] = err.Error()
				continue
			}
			res.Stopped = append(res.Stopped, "vm:"+id)
		}
		for _, id := range a.Apps {
			if am == nil {
				res.Failed["app:"+id] = "this server has no app engine"
				continue
			}
			if err := am.ClusterStop(ctx, apps.ClusterStopArgs{ID: id, Force: true}); err != nil {
				res.Failed["app:"+id] = err.Error()
				continue
			}
			res.Stopped = append(res.Stopped, "app:"+id)
		}
		if len(res.Failed) > 0 {
			var b strings.Builder
			for k, v := range res.Failed {
				fmt.Fprintf(&b, "%s: %s; ", k, v)
			}
			return nil, Errorf(CodeFailed, "self-fence epoch %d: not everything stopped: %s", a.Epoch, strings.TrimSuffix(b.String(), "; "))
		}
		return res, nil
	}))
}
