package priv

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/ups"
)

// Monitoring operation names (docs/monitoring.md). SMART reads and tests
// take a device that must be the stable path (ByID) of a disk hw.disks
// lists right now: never an arbitrary node.
const (
	OpHWSmartTest = "hw.smart.test"
	OpUPSDetect   = "ups.detect"
	OpUPSApply    = "ups.apply"
)

// SmartTestArgs starts a self-test: Test is short, long or abort.
type SmartTestArgs struct {
	Device string `json:"device"`
	Test   string `json:"test"`
}

// knownDisk checks that device is the stable path of a disk this server
// has now (by-id, or the kernel path for a disk without one) and returns it.
func knownDisk(ctx context.Context, env StorageEnv, device string) (*hw.Disk, error) {
	if !hw.ValidDevicePath(device) {
		return nil, Errorf(CodeBadArgs, "invalid device %q", device)
	}
	disks, err := hw.ListDisks(ctx, env.Runner, env.Root)
	if err != nil {
		return nil, err
	}
	for i := range disks {
		if disks[i].ByID == device {
			return &disks[i], nil
		}
	}
	return nil, Errorf(CodeBadArgs, "%s isn't one of this server's disks", device)
}

// MonitorEnv is what monitoring operations need.
type MonitorEnv struct {
	Storage StorageEnv
	UPS     *ups.Root
}

// RegisterMonitor adds SMART self-tests and the UPS operations.
func RegisterMonitor(s *Server, env MonitorEnv) {
	s.Handle(OpHWSmartTest, typed(func(ctx context.Context, a SmartTestArgs) (any, error) {
		switch a.Test {
		case hw.TestShort, hw.TestLong, hw.TestAbort:
		default:
			return nil, Errorf(CodeBadArgs, "test must be short, long or abort")
		}
		d, err := knownDisk(ctx, env.Storage, a.Device)
		if err != nil {
			return nil, err
		}
		if err := hw.StartSelfTest(ctx, env.Storage.Runner, d.ByID, a.Test); err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		return map[string]string{"device": d.ByID, "test": a.Test, "startedAt": time.Now().UTC().Format(time.RFC3339)}, nil
	}))
	if env.UPS != nil {
		s.Handle(OpUPSDetect, func(ctx context.Context, _ json.RawMessage) (any, error) {
			return env.UPS.Detect(ctx), nil
		})
		s.Handle(OpUPSApply, typed(func(ctx context.Context, a ups.ApplyArgs) (any, error) {
			res, err := env.UPS.Apply(ctx, a)
			var ve *ups.ValidationError
			if errors.As(err, &ve) {
				return nil, Errorf(CodeBadArgs, "%v", err)
			}
			return res, err
		}))
	}
}

// monitorQuietOps are read-only operations hardyd's monitor calls every few
// seconds; they're logged at debug level so the journal isn't flooded.
var monitorQuietOps = []string{OpPing, OpHWSmart, OpHWDisks, OpPools, OpPoolStatus, "vms.list", "apps.status", "netbird.status", "domain.status", "domain.replication"}

// QuietMonitoringOps marks the monitor's polling operations as quiet.
func QuietMonitoringOps(s *Server) {
	if s.QuietOps == nil {
		s.QuietOps = map[string]bool{}
	}
	for _, op := range monitorQuietOps {
		s.QuietOps[op] = true
	}
}
