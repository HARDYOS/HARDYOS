package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// VM polish (phase 9, decisions 410-419): the verified image catalog, saved
// templates, snapshot schedules and USB hot-plug. Administrators only;
// every change is a job and audited.

// More VM job kinds.
const (
	JobKindVMTemplateCreate = "vms.usertemplates.create"
	JobKindVMTemplateDelete = "vms.usertemplates.delete"
	JobKindVMSchedule       = "vms.schedule.set"
	JobKindVMUSBAttach      = "vms.usb.attach"
	JobKindVMUSBDetach      = "vms.usb.detach"
)

func (s *Server) vmPolishRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/vms/catalog", s.admin(s.handleVMCatalog))
	m.Handle("GET /api/v1/vms/usertemplates", s.admin(s.handleVMUserTemplates))
	m.Handle("DELETE /api/v1/vms/usertemplates/{tid}", s.admin(s.handleVMUserTemplateDelete))
	m.Handle("POST /api/v1/vms/{id}/template", s.admin(s.handleVMMakeTemplate))
	m.Handle("PUT /api/v1/vms/{id}/schedule", s.admin(s.handleVMSchedule))
	m.Handle("POST /api/v1/vms/{id}/usb", s.admin(s.handleVMUSBAttach))
	m.Handle("POST /api/v1/vms/{id}/usb/detach", s.admin(s.handleVMUSBDetach))
}

func (s *Server) handleVMCatalog(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var res priv.VMCatalogResult
	if err := s.vmCall(r, priv.OpVMsCatalogList, nil, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res.Images)
}

func (s *Server) handleVMUserTemplates(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var res priv.VMUserTemplatesResult
	if err := s.vmCall(r, priv.OpVMsUserTemplates, nil, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res.Templates)
}

var templateIDRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)

// VMMakeTemplateRequest saves a stopped VM as a template.
type VMMakeTemplateRequest struct {
	TemplateID  string `json:"templateId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (s *Server) handleVMMakeTemplate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req VMMakeTemplateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	v, ok := s.getVM(w, r)
	if !ok {
		return
	}
	if !templateIDRE.MatchString(req.TemplateID) || strings.TrimSpace(req.Name) == "" || len(req.Name) > 64 {
		writeError(w, http.StatusBadRequest, "invalid", "give the template a short name (2-32 lowercase letters, digits and dashes) and a display name")
		return
	}
	if v.State != "stopped" && v.State != "crashed" {
		writeError(w, http.StatusConflict, "running", "shut the VM down before making a template from it")
		return
	}
	s.submit(w, r, u, JobKindVMTemplateCreate, "Make template "+req.Name+" from "+v.Name,
		vms.MakeTemplateArgs{VM: v.ID, ID: req.TemplateID, Name: req.Name, Description: req.Description},
		"vms.usertemplates.create", v.ID+" -> "+req.TemplateID, nil)
}

// VMTemplateDeleteRequest deletes a saved template; Confirm is its name.
type VMTemplateDeleteRequest struct {
	Confirm string `json:"confirm"`
}

func (s *Server) handleVMUserTemplateDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req VMTemplateDeleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	tid := r.PathValue("tid")
	if !templateIDRE.MatchString(tid) {
		writeError(w, http.StatusNotFound, "not_found", "there's no such template")
		return
	}
	if strings.TrimSpace(req.Confirm) == "" {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the template's name to confirm")
		return
	}
	s.submit(w, r, u, JobKindVMTemplateDelete, "Delete template "+tid, vms.DeleteTemplateArgs{ID: tid, Confirm: req.Confirm},
		"vms.usertemplates.delete", tid, nil)
}

// VMScheduleRequest sets a VM's snapshot schedule (all zero: off).
type VMScheduleRequest struct {
	Schedule vms.Schedule `json:"schedule"`
	// Confirm is the VM's name, needed when the counts delete automatic
	// snapshots there are now.
	Confirm string `json:"confirm,omitempty"`
}

func (s *Server) handleVMSchedule(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req VMScheduleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	v, ok := s.getVM(w, r)
	if !ok {
		return
	}
	sc := req.Schedule
	if sc.Hourly < 0 || sc.Daily < 0 || sc.Weekly < 0 || sc.Monthly < 0 ||
		sc.Hourly > vms.MaxHourly || sc.Daily > vms.MaxDaily || sc.Weekly > vms.MaxWeekly || sc.Monthly > vms.MaxMonthly {
		writeError(w, http.StatusBadRequest, "invalid", fmt.Sprintf("keep at most %d hourly, %d daily, %d weekly and %d monthly snapshots", vms.MaxHourly, vms.MaxDaily, vms.MaxWeekly, vms.MaxMonthly))
		return
	}
	// A quick answer here; hardyd-priv checks it again.
	var snaps priv.VMSnapshotsResult
	if err := s.vmCall(r, priv.OpVMsSnapshots, priv.VMRef{ID: v.ID}, &snaps); err != nil {
		s.writePrivError(w, err)
		return
	}
	pruned := len(vms.SchedulePrunes(snaps.Snapshots, &sc))
	if pruned > 0 && !vms.Confirms(req.Confirm, &v.Spec) {
		writeError(w, http.StatusBadRequest, "confirm_required",
			fmt.Sprintf("these counts delete %d automatic snapshots %s has now; type the VM's name (%s) to confirm", pruned, v.Name, v.Name))
		return
	}
	s.submit(w, r, u, JobKindVMSchedule, "Snapshot schedule of "+v.Name, vms.SetScheduleArgs{ID: v.ID, Schedule: &sc, Confirm: req.Confirm},
		"vms.schedule.set", fmt.Sprintf("%s hourly=%d daily=%d weekly=%d monthly=%d prunes=%d", v.ID, sc.Hourly, sc.Daily, sc.Weekly, sc.Monthly, pruned), nil)
}

var (
	usbIDRE     = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{4}$`)
	catalogIDRE = regexp.MustCompile(`^[a-z][a-z0-9.-]{1,31}$`)
)

// VMUSBRequest plugs a USB device in or out of a running VM.
type VMUSBRequest struct {
	Device  string `json:"device"`
	Persist bool   `json:"persist"`
	// AllowInput confirms giving a keyboard or mouse to the VM.
	AllowInput bool `json:"allowInput,omitempty"`
}

func (s *Server) vmUSB(w http.ResponseWriter, r *http.Request, u *auth.User, kind, verb string) {
	var req VMUSBRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	v, ok := s.getVM(w, r)
	if !ok {
		return
	}
	req.Device = strings.ToLower(strings.TrimSpace(req.Device))
	if !usbIDRE.MatchString(req.Device) {
		writeError(w, http.StatusBadRequest, "invalid", "the USB device must be vendor:product, like 046d:c52b")
		return
	}
	if v.State != "running" {
		writeError(w, http.StatusConflict, "not_running", "the VM isn't running; change its USB devices in Hardware")
		return
	}
	s.submit(w, r, u, kind, verb+" USB "+req.Device+" ("+v.Name+")", vms.USBArgs{ID: v.ID, Device: req.Device, Persist: req.Persist, AllowInput: req.AllowInput},
		kind, fmt.Sprintf("%s %s persist=%t allowInput=%t", v.ID, req.Device, req.Persist, req.AllowInput), nil)
}

func (s *Server) handleVMUSBAttach(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.vmUSB(w, r, u, JobKindVMUSBAttach, "Plug in")
}

func (s *Server) handleVMUSBDetach(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.vmUSB(w, r, u, JobKindVMUSBDetach, "Unplug")
}

func registerVMPolishJobs(m *jobs.Manager, pc *priv.Client) {
	reg := func(name string, lock func(json.RawMessage) string, run jobs.RunFunc) {
		m.Register(jobs.Kind{Name: name, AdminOnly: true, Run: run, LockKey: lock})
	}
	vmKey := vmLock

	reg(JobKindVMTemplateCreate, func(raw json.RawMessage) string {
		var a vms.MakeTemplateArgs
		_ = json.Unmarshal(raw, &a)
		return "vm:" + a.VM
	}, func(jc *jobs.Context) (any, error) {
		var p vms.MakeTemplateArgs
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(2, "Copying "+p.VM+" into the template "+p.Name)
		var res priv.VMTaskResult
		if err := call(jc, pc, time.Minute, priv.OpVMsUserTemplateCreate, p, &res); err != nil {
			return nil, err
		}
		if err := followVMTask(jc, pc, res.Task, 2, 100); err != nil {
			return nil, err
		}
		return map[string]string{"template": p.ID}, nil
	})
	reg(JobKindVMTemplateDelete, nil, func(jc *jobs.Context) (any, error) {
		var p vms.DeleteTemplateArgs
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		return map[string]bool{"deleted": true}, call(jc, pc, 10*time.Minute, priv.OpVMsUserTemplateDelete, p, nil)
	})
	reg(JobKindVMSchedule, vmKey, func(jc *jobs.Context) (any, error) {
		var p vms.SetScheduleArgs
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		var v vms.VM
		if err := call(jc, pc, time.Minute, priv.OpVMsScheduleSet, p, &v); err != nil {
			return nil, err
		}
		return VMJobResult{VM: &v, Warnings: []string{}}, nil
	})
	for _, k := range []struct{ kind, op string }{{JobKindVMUSBAttach, priv.OpVMsUSBAttach}, {JobKindVMUSBDetach, priv.OpVMsUSBDetach}} {
		op := k.op
		reg(k.kind, vmKey, func(jc *jobs.Context) (any, error) {
			var p vms.USBArgs
			if err := jc.Params(&p); err != nil {
				return nil, err
			}
			var v vms.VM
			if err := call(jc, pc, 2*time.Minute, op, p, &v); err != nil {
				return nil, err
			}
			return VMJobResult{VM: &v, Warnings: []string{}}, nil
		})
	}
}
