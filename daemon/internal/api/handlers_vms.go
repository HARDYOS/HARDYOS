package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// Virtual machines (docs/vms.md). Every change runs as a job and is audited;
// reading goes straight to hardyd-priv. Administrators only: a VM is a
// computer on the home network.

func (s *Server) vmRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/vms", s.admin(s.handleVMs))
	m.Handle("POST /api/v1/vms", s.admin(s.handleVMCreate))
	m.Handle("GET /api/v1/vms/templates", s.admin(s.handleVMTemplates))
	m.Handle("GET /api/v1/vms/capabilities", s.admin(s.handleVMCapabilities))
	m.Handle("POST /api/v1/vms/bridge", s.admin(s.handleVMBridge))
	m.Handle("POST /api/v1/vms/kept/delete", s.admin(s.handleVMKeptDelete))
	m.Handle("GET /api/v1/vms/isos", s.admin(s.handleVMLibrary))
	m.Handle("POST /api/v1/vms/isos/download", s.admin(s.handleVMDownload))
	m.Handle("DELETE /api/v1/vms/isos/{name}", s.admin(s.handleVMFileDelete))
	m.Handle("GET /api/v1/vms/{id}", s.admin(s.handleVM))
	m.Handle("PUT /api/v1/vms/{id}", s.admin(s.handleVMUpdate))
	m.Handle("DELETE /api/v1/vms/{id}", s.admin(s.handleVMDelete))
	m.Handle("POST /api/v1/vms/{id}/{action}", s.admin(s.handleVMAction))
	m.Handle("GET /api/v1/vms/{id}/logs", s.admin(s.handleVMLogs))
	m.Handle("GET /api/v1/vms/{id}/snapshots", s.admin(s.handleVMSnapshots))
	m.Handle("POST /api/v1/vms/{id}/snapshots", s.admin(s.handleVMSnapshot))
	m.Handle("DELETE /api/v1/vms/{id}/snapshots/{name}", s.admin(s.handleVMSnapshotDelete))
	m.Handle("POST /api/v1/vms/{id}/rollback", s.admin(s.handleVMRollback))
	m.Handle("POST /api/v1/vms/{id}/console", s.admin(s.handleVMConsole))
	m.Handle("GET /api/v1/vms/{id}/console/ws", s.admin(s.handleVMConsoleWS))
}

func (s *Server) vmCall(r *http.Request, op string, args, out any) error {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	return s.cfg.Priv.Call(ctx, op, args, out)
}

func (s *Server) handleVMs(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var o vms.Overview
	if err := s.vmCall(r, priv.OpVMsList, nil, &o); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, o)
}

func (s *Server) handleVMTemplates(w http.ResponseWriter, _ *http.Request, _ *auth.User) {
	writeJSON(w, http.StatusOK, vms.Templates)
}

func (s *Server) handleVMCapabilities(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var c vms.Capabilities
	if err := s.vmCall(r, priv.OpVMsCapabilities, nil, &c); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// vmID reads the {id} path value; a malformed one is simply not found.
func vmID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if vms.ValidID(id) != nil {
		writeError(w, http.StatusNotFound, "not_found", "there's no virtual machine called "+strconv.Quote(id))
		return "", false
	}
	return id, true
}

func (s *Server) getVM(w http.ResponseWriter, r *http.Request) (*vms.VM, bool) {
	id, ok := vmID(w, r)
	if !ok {
		return nil, false
	}
	var v vms.VM
	if err := s.vmCall(r, priv.OpVMsGet, priv.VMRef{ID: id}, &v); err != nil {
		var pe *priv.Error
		if errors.As(err, &pe) && pe.Code == priv.CodeBadArgs {
			writeError(w, http.StatusNotFound, "not_found", pe.Message)
			return nil, false
		}
		s.writePrivError(w, err)
		return nil, false
	}
	return &v, true
}

func (s *Server) handleVM(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	if v, ok := s.getVM(w, r); ok {
		writeJSON(w, http.StatusOK, v)
	}
}

// VMCreateRequest makes a VM. Downloads (an installer or disk image by
// link) go into the ISO library first; Password is the cloud-init user's
// and never stored by hardyd.
type VMCreateRequest struct {
	Spec      vms.Spec           `json:"spec"`
	Password  string             `json:"password,omitempty"`
	Start     bool               `json:"start"`
	Downloads []vms.DownloadArgs `json:"downloads,omitempty"`
	// AllowOvercommit: the disks may be bigger than the pool's free space.
	AllowOvercommit bool `json:"allowOvercommit,omitempty"`
}

// checkSpec gives quick answers to obvious mistakes; hardyd-priv checks
// everything again against the server.
func checkSpec(w http.ResponseWriter, sp *vms.Spec) bool {
	s := *sp
	s.Normalize()
	if err := s.Validate(vms.Host{Arch: vmArch()}); err != nil {
		var p vms.Problems
		if errors.As(err, &p) {
			msg := p[0]
			if len(p) > 1 {
				msg = fmt.Sprintf("%s (and %d more)", p[0], len(p)-1)
			}
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Code: "invalid", Message: msg, Details: p})
			return false
		}
	}
	return true
}

// vmArch is used for hardyd's quick checks; hardyd-priv's are the ones
// that count. (Secure Boot and TPM availability are only known as root.)
func vmArch() vms.ArchInfo {
	a, _ := vms.HostArch()
	return a
}

func (s *Server) handleVMCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req VMCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !checkSpecLoose(w, &req.Spec) {
		return
	}
	if len(req.Downloads) > 4 {
		writeError(w, http.StatusBadRequest, "invalid", "at most 4 downloads")
		return
	}
	p := vmCreateParams{Spec: req.Spec, Start: req.Start, Downloads: req.Downloads, AllowOvercommit: req.AllowOvercommit}
	if req.Password != "" {
		p.PasswordRef = jobSecrets.put(req.Password)
	}
	name := req.Spec.Name
	if name == "" {
		name = req.Spec.ID
	}
	s.submit(w, r, u, JobKindVMCreate, "Create "+name, p, "vms.create", req.Spec.ID+" template="+req.Spec.Template, nil)
}

// checkSpecLoose checks a new VM, leaving out what only root knows
// (firmware, TPM) and what the job fills in (MACs, files to download).
func checkSpecLoose(w http.ResponseWriter, sp *vms.Spec) bool {
	s := *sp
	s.Firmware.SecureBoot, s.Firmware.TPM = false, false
	if sp.CloudInit != nil {
		ci := *sp.CloudInit
		ci.PasswordHash = "$6$x$" + strings.Repeat("a", 86) // a password may follow
		s.CloudInit = &ci
	}
	return checkSpec(w, &s)
}

// VMUpdateRequest changes a VM. Removing disks needs the VM's name typed
// in Confirm.
type VMUpdateRequest struct {
	Spec            vms.Spec `json:"spec"`
	Password        string   `json:"password,omitempty"`
	RemoveDisks     []string `json:"removeDisks,omitempty"`
	Confirm         string   `json:"confirm,omitempty"`
	AllowOvercommit bool     `json:"allowOvercommit,omitempty"`
}

func (s *Server) handleVMUpdate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	v, ok := s.getVM(w, r)
	if !ok {
		return
	}
	var req VMUpdateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Spec.ID = v.ID
	if !checkSpecLoose(w, &req.Spec) {
		return
	}
	if len(req.RemoveDisks) > 0 && !vms.Confirms(req.Confirm, &v.Spec) {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the VM's name ("+v.Name+") to confirm deleting "+strings.Join(req.RemoveDisks, ", "))
		return
	}
	p := vmUpdateParams{UpdateArgs: vms.UpdateArgs{Spec: req.Spec, RemoveDisks: req.RemoveDisks, Confirm: req.Confirm, AllowOvercommit: req.AllowOvercommit}}
	if req.Password != "" {
		p.PasswordRef = jobSecrets.put(req.Password)
	}
	detail := v.ID
	if len(req.RemoveDisks) > 0 {
		detail += " remove=" + strings.Join(req.RemoveDisks, ",")
	}
	s.submit(w, r, u, JobKindVMUpdate, "Change "+v.Name, p, "vms.update", detail, nil)
}

var vmActions = map[string]struct {
	kind, title string
}{
	"start":      {JobKindVMStart, "Start"},
	"stop":       {JobKindVMStop, "Shut down"},
	"force-stop": {JobKindVMForceStop, "Turn off"},
	"restart":    {JobKindVMRestart, "Restart"},
	"reset":      {JobKindVMReset, "Reset"},
}

func (s *Server) handleVMAction(w http.ResponseWriter, r *http.Request, u *auth.User) {
	a, known := vmActions[r.PathValue("action")]
	if !known {
		writeError(w, http.StatusNotFound, "not_found", "no such API endpoint")
		return
	}
	v, ok := s.getVM(w, r)
	if !ok {
		return
	}
	s.submit(w, r, u, a.kind, a.title+" "+v.Name, priv.VMRef{ID: v.ID}, "vms."+r.PathValue("action"), v.ID, nil)
}

// VMDeleteRequest deletes a VM.
type VMDeleteRequest struct {
	Confirm   string `json:"confirm"`
	KeepDisks bool   `json:"keepDisks"`
}

func (s *Server) handleVMDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req VMDeleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	v, ok := s.getVM(w, r)
	if !ok {
		return
	}
	if !vms.Confirms(req.Confirm, &v.Spec) {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the VM's name ("+v.Name+") to confirm")
		return
	}
	if v.State == "running" || v.State == "paused" {
		writeError(w, http.StatusConflict, "running", "turn the VM off before deleting it")
		return
	}
	title := "Delete " + v.Name
	if req.KeepDisks {
		title += " (keep its disks)"
	}
	s.submit(w, r, u, JobKindVMDelete, title, vms.DeleteArgs{ID: v.ID, Confirm: req.Confirm, KeepDisks: req.KeepDisks},
		"vms.delete", fmt.Sprintf("%s keepDisks=%t", v.ID, req.KeepDisks), nil)
}

func (s *Server) handleVMKeptDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req vms.DeleteKeptArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	if !strings.Contains(req.Dataset, "/vms/") || strings.TrimSpace(req.Confirm) == "" {
		writeError(w, http.StatusBadRequest, "confirm_required", "name the kept disks and type the deleted VM's name")
		return
	}
	s.submit(w, r, u, JobKindVMKeptDelete, "Delete kept disks "+req.Dataset, req, "vms.kept.delete", req.Dataset, nil)
}

func (s *Server) handleVMLogs(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	id, ok := vmID(w, r)
	if !ok {
		return
	}
	lines := 300
	if v := r.URL.Query().Get("lines"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 5000 {
			writeError(w, http.StatusBadRequest, "invalid", "lines must be from 1 to 5000")
			return
		}
		lines = n
	}
	var res priv.VMLogsResult
	if err := s.vmCall(r, priv.OpVMsLogs, priv.VMLogsArgs{ID: id, Lines: lines}, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleVMSnapshots(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	id, ok := vmID(w, r)
	if !ok {
		return
	}
	var res priv.VMSnapshotsResult
	if err := s.vmCall(r, priv.OpVMsSnapshots, priv.VMRef{ID: id}, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res.Snapshots)
}

// VMSnapshotRequest takes a snapshot.
type VMSnapshotRequest struct {
	Label string `json:"label"`
}

func (s *Server) handleVMSnapshot(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req VMSnapshotRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	v, ok := s.getVM(w, r)
	if !ok {
		return
	}
	if len(req.Label) > 80 || strings.ContainsAny(req.Label, "\n\r\x00") {
		writeError(w, http.StatusBadRequest, "invalid", "the description must be at most 80 characters on one line")
		return
	}
	s.submit(w, r, u, JobKindVMSnapshot, "Snapshot of "+v.Name, vms.SnapshotArgs{ID: v.ID, Label: req.Label}, "vms.snapshot", v.ID, nil)
}

// VMSnapshotDeleteRequest deletes a snapshot; Confirm is the VM's name.
type VMSnapshotDeleteRequest struct {
	Confirm string `json:"confirm"`
}

func (s *Server) handleVMSnapshotDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req VMSnapshotDeleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	v, ok := s.getVM(w, r)
	if !ok {
		return
	}
	if !vms.Confirms(req.Confirm, &v.Spec) {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the VM's name ("+v.Name+") to confirm")
		return
	}
	name := r.PathValue("name")
	s.submit(w, r, u, JobKindVMSnapshotDelete, "Delete snapshot "+name+" of "+v.Name, vms.DeleteSnapshotArgs{ID: v.ID, Snapshot: name, Confirm: req.Confirm},
		"vms.snapshot.delete", v.ID+"@"+name, nil)
}

// VMRollbackRequest goes back to a snapshot.
type VMRollbackRequest struct {
	Snapshot string `json:"snapshot"`
	Confirm  string `json:"confirm"`
}

func (s *Server) handleVMRollback(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req VMRollbackRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	v, ok := s.getVM(w, r)
	if !ok {
		return
	}
	if !vms.Confirms(req.Confirm, &v.Spec) {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the VM's name ("+v.Name+") to confirm")
		return
	}
	s.submit(w, r, u, JobKindVMRollback, "Put "+v.Name+" back to "+req.Snapshot, vms.RollbackArgs{ID: v.ID, Snapshot: req.Snapshot, Confirm: req.Confirm},
		"vms.rollback", v.ID+"@"+req.Snapshot, nil)
}

func (s *Server) handleVMLibrary(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var l vms.LibraryView
	if err := s.vmCall(r, priv.OpVMsISOList, nil, &l); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (s *Server) handleVMDownload(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req vms.DownloadArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	if !strings.HasPrefix(strings.TrimSpace(req.URL), "https://") {
		writeError(w, http.StatusBadRequest, "invalid", "the link must be an https:// address")
		return
	}
	title := "Download " + req.Name
	if req.Name == "" {
		title = "Download " + lastSegment(req.URL)
	}
	s.submit(w, r, u, JobKindVMDownload, title, req, "vms.iso.download", req.URL, nil)
}

func lastSegment(u string) string {
	u, _, _ = strings.Cut(u, "?")
	if i := strings.LastIndexByte(u, '/'); i >= 0 && i < len(u)-1 {
		return u[i+1:]
	}
	return "a file"
}

func (s *Server) handleVMFileDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	name := r.PathValue("name")
	if vms.ValidFile(name) != nil {
		writeError(w, http.StatusNotFound, "not_found", "there's no such file in the ISO library")
		return
	}
	s.submit(w, r, u, JobKindVMFileDelete, "Delete "+name, vms.DeleteFileArgs{Name: name}, "vms.iso.delete", name, nil)
}

func (s *Server) handleVMBridge(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.submit(w, r, u, JobKindVMBridge, "Set up the network bridge for VMs", struct{}{}, "vms.bridge", "br0", nil)
}
