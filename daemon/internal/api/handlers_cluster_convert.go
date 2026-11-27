package api

// "Make highly available" and "Make local again" (docs/plans/make-ha.md,
// decisions 480-489): checks, the conversion jobs, conversions in
// progress, kept copies and an HA VM's template on the storage server.
// Every change is a job (and audited) with a typed confirmation.
//
// Administrators of other members may use these (decision 488): they are
// the cluster workloads area of decision 368's allowlist, which already
// moves, stops and destroys cluster storage, and each server can turn
// another server's administrators off (Cluster › Servers).

import (
	"errors"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/convert"
	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
	"github.com/hardyos/hardyos/daemon/internal/cluster/storagesvc"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

type convertState struct {
	conv    *convert.Converter
	storage *storagesvc.Service
}

// clusterConvert is the converter for jobs that run without the Server
// (the VM schedule and streaming jobs' approvals don't need it).
var clusterConvert atomic.Pointer[convert.Converter]

// ClusterConvertRoutes registers the conversion endpoints.
func (s *Server) ClusterConvertRoutes(c *convert.Converter, st *storagesvc.Service) {
	if c == nil || s.cfg.Jobs == nil {
		return
	}
	s.convert = convertState{conv: c, storage: st}
	clusterConvert.Store(c)
	m := s.mux
	m.Handle("GET /api/v1/cluster/convert/{kind}/{id}", s.admin(s.handleConvertCheck))
	m.Handle("POST /api/v1/cluster/convert/{kind}/{id}", s.admin(s.handleConvertToHA))
	m.Handle("POST /api/v1/cluster/workloads/{kind}/{id}/local", s.admin(s.handleConvertToLocal))
	m.Handle("GET /api/v1/cluster/conversions", s.admin(s.handleConversions))
	m.Handle("POST /api/v1/cluster/conversions/{conv}/undo", s.admin(s.handleConversionUndo))
	m.Handle("POST /api/v1/cluster/conversions/{conv}/abandon", s.admin(s.handleConversionAbandon))
	m.Handle("GET /api/v1/cluster/kept", s.admin(s.handleKept))
	m.Handle("POST /api/v1/cluster/kept/delete", s.admin(s.handleKeptDelete))
	m.Handle("POST /api/v1/cluster/workloads/vm/{id}/template", s.admin(s.handleClusterVMTemplate))
}

func (s *Server) converter(w http.ResponseWriter) (*convert.Converter, bool) {
	c := s.convert.conv
	if c == nil || !c.Member() {
		writeError(w, http.StatusConflict, "not_member", "this server isn't in a cluster")
		return nil, false
	}
	if !s.jobsReady(w) {
		return nil, false
	}
	return c, true
}

func (s *Server) convertActor(u *auth.User) cluster.Actor {
	a := cluster.Actor{Kind: "local", Name: u.Principal}
	if u.Source == auth.SourceDomain {
		a.Kind = "domain"
	}
	if c := s.convert.conv; c != nil && c.Cluster != nil {
		if n, err := c.Cluster.Self(); err == nil {
			a.Via = n.ID
		}
	}
	return a
}

func writeConvertError(s *Server, w http.ResponseWriter, err error) {
	var ref *convert.Refused
	switch {
	case errors.As(err, &ref):
		writeError(w, http.StatusConflict, "refused", err.Error())
	case errors.Is(err, convert.ErrNotMember):
		writeError(w, http.StatusConflict, "not_member", "this server isn't in a cluster")
	case errors.Is(err, cluster.ErrNoQuorum):
		writeError(w, http.StatusConflict, "no_quorum", err.Error())
	case strings.HasPrefix(err.Error(), "type the name"):
		writeError(w, http.StatusBadRequest, "confirm_required", "type the name to confirm")
	default:
		writeError(w, http.StatusConflict, "refused", err.Error())
	}
}

func (s *Server) handleConvertCheck(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	ref, ok := workloadRef(r)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such workload")
		return
	}
	c, ok := s.converter(w)
	if !ok {
		return
	}
	rd, err := c.Check(r.Context(), ref, r.URL.Query().Get("cpu"))
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rd)
}

// ConvertRequest makes a workload highly available. Confirm is its name.
type ConvertRequest struct {
	Priority int    `json:"priority,omitempty"`
	CPU      string `json:"cpu,omitempty"`
	Confirm  string `json:"confirm"`
}

func (s *Server) handleConvertToHA(w http.ResponseWriter, r *http.Request, u *auth.User) {
	ref, ok := workloadRef(r)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such workload")
		return
	}
	var req ConvertRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Priority < 0 || req.Priority > 100 {
		writeError(w, http.StatusBadRequest, "invalid", "priority is 1-100")
		return
	}
	if req.CPU != "" && req.CPU != convert.CPUBaseline && req.CPU != convert.CPUKeep {
		writeError(w, http.StatusBadRequest, "invalid", "cpu is baseline or keep")
		return
	}
	c, ok := s.converter(w)
	if !ok {
		return
	}
	id := u.ID
	j, err := c.StartToHA(r.Context(), convert.ToHAParams{Workload: ref, Priority: req.Priority, CPU: req.CPU, Actor: s.convertActor(u)}, req.Confirm, &id)
	if err != nil {
		writeConvertError(s, w, err)
		return
	}
	s.record(r, u, "cluster.ha.convert", string(ref.Kind)+":"+ref.ID, "success", "job "+j.ID)
	writeJSON(w, http.StatusAccepted, JobAccepted{Job: j, Warnings: []string{}})
}

// ToLocalRequest makes a cluster workload local again on this server.
type ToLocalRequest struct {
	Pool    string `json:"pool,omitempty"`
	Confirm string `json:"confirm"`
}

func (s *Server) handleConvertToLocal(w http.ResponseWriter, r *http.Request, u *auth.User) {
	ref, ok := workloadRef(r)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no such workload")
		return
	}
	var req ToLocalRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.converter(w)
	if !ok {
		return
	}
	id := u.ID
	j, err := c.StartToLocal(r.Context(), convert.ToLocalParams{Workload: ref, Pool: req.Pool, Actor: s.convertActor(u)}, req.Confirm, &id)
	if err != nil {
		writeConvertError(s, w, err)
		return
	}
	s.record(r, u, "cluster.ha.local", string(ref.Kind)+":"+ref.ID, "success", "job "+j.ID)
	writeJSON(w, http.StatusAccepted, JobAccepted{Job: j, Warnings: []string{}})
}

func (s *Server) handleConversions(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	c := s.convert.conv
	if c == nil {
		writeJSON(w, http.StatusOK, []convert.Record{})
		return
	}
	l, err := c.List(r.Context(), 50)
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (s *Server) handleConversionUndo(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req ConfirmRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.converter(w)
	if !ok {
		return
	}
	id := u.ID
	j, err := c.StartUndo(r.Context(), convert.UndoParams{Conv: r.PathValue("conv"), Actor: s.convertActor(u)}, req.Confirm, &id)
	if err != nil {
		writeConvertError(s, w, err)
		return
	}
	s.record(r, u, "cluster.ha.undo", r.PathValue("conv"), "success", "job "+j.ID)
	writeJSON(w, http.StatusAccepted, JobAccepted{Job: j, Warnings: []string{}})
}

func (s *Server) handleConversionAbandon(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req ConfirmRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	c, ok := s.converter(w)
	if !ok {
		return
	}
	id := u.ID
	j, err := c.StartAbandon(r.Context(), convert.AbandonParams{Conv: r.PathValue("conv"), Actor: s.convertActor(u)}, req.Confirm, &id)
	if err != nil {
		writeConvertError(s, w, err)
		return
	}
	s.record(r, u, "cluster.ha.abandon", r.PathValue("conv"), "success", "job "+j.ID)
	writeJSON(w, http.StatusAccepted, JobAccepted{Job: j, Warnings: []string{}})
}

func (s *Server) handleKept(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	c := s.convert.conv
	if c == nil || !c.Member() {
		writeJSON(w, http.StatusOK, []convert.KeptCopy{})
		return
	}
	l, err := c.Kept(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

// KeptDeleteRequest deletes a kept copy now. Confirm is the workload's id.
type KeptDeleteRequest struct {
	Node    cluster.NodeID `json:"node"`
	Pool    string         `json:"pool"`
	Name    string         `json:"name"`
	Confirm string         `json:"confirm"`
	// LastCopy confirms deleting a copy without an expiry (its workload
	// hasn't run from its other copy: it may be the only good one).
	LastCopy bool `json:"lastCopy,omitempty"`
}

func (s *Server) handleKeptDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req KeptDeleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Pool == "" || req.Name == "" || req.Node == "" {
		writeError(w, http.StatusBadRequest, "invalid", "name the kept copy")
		return
	}
	parts := strings.Split(req.Name, "-")
	if len(parts) < 3 || req.Confirm == "" || req.Confirm != strings.Join(parts[1:len(parts)-1], "-") {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the workload's name to delete its kept copy")
		return
	}
	c, ok := s.converter(w)
	if !ok {
		return
	}
	if !req.LastCopy {
		// Root refuses too; this says so before a job is queued.
		if l, err := c.Kept(r.Context()); err == nil {
			for _, k := range l {
				if k.Node == req.Node && k.Pool == req.Pool && k.Name == req.Name && k.KeepUntil.IsZero() {
					writeError(w, http.StatusConflict, "last_copy", hacopy.ErrLastCopy.Error())
					return
				}
			}
		}
	}
	s.submit(w, r, u, convert.JobParkedDrop, "Delete the kept copy "+req.Name,
		convert.DropParams{Node: req.Node, Pool: req.Pool, Name: req.Name, Confirm: req.Confirm, LastCopy: req.LastCopy, Actor: s.convertActor(u)},
		"cluster.ha.parked.delete", string(req.Node)+":"+req.Pool+"/"+req.Name, nil)
}

// ClusterTemplateRequest saves an HA VM as a template on the storage
// server (this server).
type ClusterTemplateRequest struct {
	TemplateID  string `json:"templateId"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (s *Server) handleClusterVMTemplate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req ClusterTemplateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	if vms.ValidID(id) != nil || !templateIDRE.MatchString(req.TemplateID) || strings.TrimSpace(req.Name) == "" || len(req.Name) > 64 {
		writeError(w, http.StatusBadRequest, "invalid", "give the template a short name (2-32 lowercase letters, digits and dashes) and a display name")
		return
	}
	c, ok := s.converter(w)
	if !ok {
		return
	}
	self, err := c.Cluster.Self()
	if err != nil || self.Role != cluster.RoleStorage {
		writeError(w, http.StatusConflict, "not_storage", "an HA VM's template is made on the storage server, which holds its disks")
		return
	}
	p, ok := c.Cluster.State().Placement(cluster.WorkloadRef{Kind: cluster.KindVM, ID: id})
	if !ok || p == nil {
		writeError(w, http.StatusNotFound, "not_found", "that isn't a cluster VM")
		return
	}
	if p.State != cluster.PlacementStopped || p.Requested != cluster.RequestStopped {
		writeError(w, http.StatusConflict, "running", "stop the VM in the cluster before making a template from it")
		return
	}
	s.submit(w, r, u, JobKindVMTemplateCreate, "Make template "+req.Name+" from "+p.Name,
		vms.MakeTemplateArgs{VM: id, ID: req.TemplateID, Name: req.Name, Description: req.Description, ClusterPool: p.Storage.Pool},
		"vms.usertemplates.create", id+" -> "+req.TemplateID+" (cluster)", nil)
}
