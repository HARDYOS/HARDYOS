package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/devices"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// Devices for VMs: inventory, IOMMU, vGPU slices (this file) and the GPU
// drivers (handlers_devices_gpu.go). Admins only; every change is a job and
// is audited.

// Device job kinds.
const (
	JobKindDevicesIOMMU       = "devices.iommu.enable"
	JobKindDevicesReconcile   = "devices.reconcile"
	JobKindDevicesSRIOV       = "devices.sriov"
	JobKindDevicesSliceRemove = "devices.slice.remove"
)

func registerDeviceJobs(m *jobs.Manager, pc *priv.Client) {
	lock := func(json.RawMessage) string { return "devices" }
	call := func(op string, msg string, params func(*jobs.Context) (any, error), out func() any) jobs.RunFunc {
		return func(jc *jobs.Context) (any, error) {
			a, err := params(jc)
			if err != nil {
				return nil, err
			}
			jc.Progress(10, msg)
			ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
			defer cancel()
			res := out()
			if err := pc.Call(ctx, op, a, res); err != nil {
				return nil, err
			}
			return res, nil
		}
	}
	none := func(*jobs.Context) (any, error) { return nil, nil }
	anyOut := func() any { return &map[string]any{} }
	m.Register(jobs.Kind{Name: JobKindDevicesIOMMU, AdminOnly: true, LockKey: func(json.RawMessage) string { return "boot-disks" },
		Run: call(priv.OpDevicesIOMMUEnable, "Adding the IOMMU settings to every boot disk", none, func() any { return &devices.IOMMUResult{} })})
	m.Register(jobs.Kind{Name: JobKindDevicesReconcile, AdminOnly: true, LockKey: lock,
		Run: call(priv.OpDevicesReconcile, "Giving back devices of VMs that aren't running", none, anyOut)})
	m.Register(jobs.Kind{Name: JobKindDevicesSRIOV, AdminOnly: true, LockKey: lock,
		Run: call(priv.OpDevicesSRIOV, "Changing the GPU's virtual functions", func(jc *jobs.Context) (any, error) {
			var a priv.SRIOVArgs
			return a, jc.Params(&a)
		}, anyOut)})
	m.Register(jobs.Kind{Name: JobKindDevicesSliceRemove, AdminOnly: true, LockKey: lock,
		Run: call(priv.OpDevicesSliceRemove, "Removing the vGPU slice", func(jc *jobs.Context) (any, error) {
			var a priv.SliceArgs
			return a, jc.Params(&a)
		}, anyOut)})
	registerGPUJobs(m, pc)
}

func (s *Server) deviceRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/devices", s.admin(s.handleDevices))
	m.Handle("POST /api/v1/devices/check", s.admin(s.handleDevicesCheck))
	m.Handle("POST /api/v1/devices/iommu/enable", s.admin(s.handleIOMMUEnable))
	m.Handle("POST /api/v1/devices/reconcile", s.admin(s.handleDevicesReconcile))
	m.Handle("POST /api/v1/devices/gpus/{address}/sriov", s.admin(s.handleGPUSRIOV))
	m.Handle("POST /api/v1/devices/slices/{id}/remove", s.admin(s.handleSliceRemove))
	s.gpuRoutes()
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var inv devices.Inventory
	if err := s.cfg.Priv.Call(r.Context(), priv.OpDevicesInventory, nil, &inv); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

// handleDevicesCheck checks devices for a VM (the wizard calls it as the
// admin picks devices). It changes nothing.
func (s *Server) handleDevicesCheck(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var a priv.DevicesCheckArgs
	if !decodeJSON(w, r, &a) {
		return
	}
	if a.Devices == nil {
		a.Devices = []devices.Device{}
	}
	var res priv.DevicesCheckResult
	if err := s.cfg.Priv.Call(r.Context(), priv.OpDevicesCheck, a, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	if res.Problems == nil {
		res.Problems = devices.Problems{}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleIOMMUEnable(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.submit(w, r, u, JobKindDevicesIOMMU, "Turn on IOMMU", map[string]any{}, "devices.iommu.enable", "boot", nil)
}

func (s *Server) handleDevicesReconcile(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.submit(w, r, u, JobKindDevicesReconcile, "Give back devices of stopped VMs", map[string]any{}, "devices.reconcile", "", nil)
}

type sriovRequest struct {
	VFs int `json:"vfs"`
}

func (s *Server) handleGPUSRIOV(w http.ResponseWriter, r *http.Request, u *auth.User) {
	addr := r.PathValue("address")
	if !devices.ValidPCIAddress(addr) {
		writeError(w, http.StatusBadRequest, "invalid", "invalid PCI address")
		return
	}
	var req sriovRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.VFs < 0 || req.VFs > 64 {
		writeError(w, http.StatusBadRequest, "invalid", "vfs must be 0 to 64")
		return
	}
	title := "Turn on vGPU slices"
	if req.VFs == 0 {
		title = "Turn off vGPU slices"
	}
	s.submit(w, r, u, JobKindDevicesSRIOV, title, priv.SRIOVArgs{Address: addr, VFs: req.VFs}, "devices.sriov", fmt.Sprintf("%s vfs=%d", addr, req.VFs), nil)
}

var sliceIDRE = regexp.MustCompile(`^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])$`)

func (s *Server) handleSliceRemove(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id := r.PathValue("id")
	if !sliceIDRE.MatchString(id) {
		writeError(w, http.StatusBadRequest, "invalid", "invalid vGPU slice id")
		return
	}
	s.submit(w, r, u, JobKindDevicesSliceRemove, "Remove a vGPU slice", priv.SliceArgs{ID: id}, "devices.slice.remove", id, nil)
}
