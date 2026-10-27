package priv

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/devices"
	"github.com/hardyos/hardyos/daemon/internal/gpu"
)

// Device and GPU driver operations. Each takes named, validated arguments;
// lending devices to a VM (Prepare/Release) isn't an operation of its own:
// the VM engine calls devices.Manager inside hardyd-priv when a VM starts
// and stops.
const (
	OpDevicesInventory   = "devices.inventory"
	OpDevicesCheck       = "devices.check"
	OpDevicesIOMMUEnable = "devices.iommu.enable"
	OpDevicesReconcile   = "devices.reconcile"
	OpDevicesSRIOV       = "devices.sriov"
	OpDevicesSliceRemove = "devices.slice.remove"

	OpGPUStatus        = "gpu.status"
	OpGPULicence       = "gpu.licence"
	OpGPUTask          = "gpu.task"
	OpGPUNvidiaPrepare = "gpu.nvidia.prepare"
	OpGPUNvidiaInstall = "gpu.nvidia.install"
	OpGPUNvidiaRemove  = "gpu.nvidia.remove"
	OpGPUVGPUInstall   = "gpu.vgpu.install"
	OpGPUVGPURemove    = "gpu.vgpu.remove"
)

// DevicesCheckArgs asks whether devices can go to a VM.
type DevicesCheckArgs struct {
	VM      string           `json:"vm"`
	Devices []devices.Device `json:"devices"`
}

// DevicesCheckResult lists every problem (none: OK).
type DevicesCheckResult struct {
	OK       bool             `json:"ok"`
	Problems devices.Problems `json:"problems"`
}

// SRIOVArgs turns a GPU's virtual functions on (VFs > 0) or off.
type SRIOVArgs struct {
	Address string `json:"address"`
	VFs     int    `json:"vfs"`
}

// SliceArgs names a vGPU slice (mdev UUID or virtual function address).
type SliceArgs struct {
	ID string `json:"id"`
}

// ConfirmArgs confirms a removal.
type ConfirmArgs struct {
	Confirm bool `json:"confirm"`
}

// LicenceResult is NVIDIA's licence text from the packages.
type LicenceResult struct {
	Text    string       `json:"text"`
	Licence *gpu.Licence `json:"licence"`
}

// TaskResult wraps the current GPU driver task (nil: none).
type TaskResult struct {
	Task *gpu.Task `json:"task"`
}

// RegisterDevices adds the device and GPU driver operations.
func RegisterDevices(s *Server, h *devices.Host, g *gpu.Manager) {
	s.Handle(OpDevicesInventory, func(ctx context.Context, _ json.RawMessage) (any, error) {
		inv, err := h.Inventory(ctx)
		return inv, failed(err)
	})
	s.Handle(OpDevicesCheck, typed(func(ctx context.Context, a DevicesCheckArgs) (any, error) {
		if len(a.Devices) > 64 {
			return nil, Errorf(CodeBadArgs, "at most 64 devices per VM")
		}
		err := h.Check(ctx, a.VM, a.Devices)
		var p devices.Problems
		if errors.As(err, &p) {
			return DevicesCheckResult{Problems: p}, nil
		}
		if err != nil {
			return nil, failed(err)
		}
		return DevicesCheckResult{OK: true, Problems: devices.Problems{}}, nil
	}))
	s.Handle(OpDevicesIOMMUEnable, func(ctx context.Context, _ json.RawMessage) (any, error) {
		r, err := h.EnableIOMMU(ctx)
		return r, failed(err)
	})
	s.Handle(OpDevicesReconcile, func(ctx context.Context, _ json.RawMessage) (any, error) {
		if err := h.Reconcile(ctx); err != nil {
			return nil, failed(err)
		}
		return map[string]bool{"ok": true}, nil
	})
	s.Handle(OpDevicesSRIOV, typed(func(ctx context.Context, a SRIOVArgs) (any, error) {
		if !devices.ValidPCIAddress(a.Address) || a.VFs < 0 || a.VFs > 64 {
			return nil, Errorf(CodeBadArgs, "invalid address or count")
		}
		if err := h.SetVFs(ctx, a.Address, a.VFs); err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		return map[string]bool{"ok": true}, nil
	}))
	s.Handle(OpDevicesSliceRemove, typed(func(ctx context.Context, a SliceArgs) (any, error) {
		if err := h.RemoveSlice(ctx, a.ID); err != nil {
			return nil, Errorf(CodeFailed, "%v", err)
		}
		return map[string]bool{"ok": true}, nil
	}))

	s.Handle(OpGPUStatus, func(ctx context.Context, _ json.RawMessage) (any, error) {
		st, err := g.Status(ctx)
		return st, failed(err)
	})
	s.Handle(OpGPULicence, func(ctx context.Context, _ json.RawMessage) (any, error) {
		text, lic, err := g.LicenceText()
		if err != nil {
			return nil, Errorf(CodeBadArgs, "%v", err)
		}
		return LicenceResult{Text: text, Licence: lic}, nil
	})
	s.Handle(OpGPUTask, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return TaskResult{Task: g.Task()}, nil
	})
	s.Handle(OpGPUNvidiaPrepare, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return taskStarted(g.PrepareNvidia())
	})
	s.Handle(OpGPUNvidiaInstall, typed(func(ctx context.Context, a gpu.InstallArgs) (any, error) {
		return taskStarted(g.InstallNvidia(a))
	}))
	s.Handle(OpGPUNvidiaRemove, typed(func(ctx context.Context, a ConfirmArgs) (any, error) {
		if !a.Confirm {
			return nil, Errorf(CodeBadArgs, "confirm must be true")
		}
		return taskStarted(g.RemoveNvidia())
	}))
	s.Handle(OpGPUVGPUInstall, typed(func(ctx context.Context, a gpu.VGPUArgs) (any, error) {
		return taskStarted(g.InstallVGPU(a))
	}))
	s.Handle(OpGPUVGPURemove, typed(func(ctx context.Context, a ConfirmArgs) (any, error) {
		if !a.Confirm {
			return nil, Errorf(CodeBadArgs, "confirm must be true")
		}
		return taskStarted(g.RemoveVGPU())
	}))
}

func taskStarted(t *gpu.Task, err error) (any, error) {
	if errors.Is(err, gpu.ErrBusy) {
		return nil, Errorf(CodeFailed, "%v", err)
	}
	if err != nil {
		return nil, Errorf(CodeBadArgs, "%v", err)
	}
	return TaskResult{Task: t}, nil
}

func failed(err error) error {
	if err == nil {
		return nil
	}
	return Errorf(CodeFailed, "%v", err)
}
