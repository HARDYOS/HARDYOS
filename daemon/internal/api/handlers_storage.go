package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/storage"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

func (s *Server) storageRoutes() {
	if s.cfg.Storage == nil {
		return
	}
	m := s.mux
	m.Handle("GET /api/v1/hardware", s.admin(s.handleHardware))
	m.Handle("GET /api/v1/hardware/disks/{name}/smart", s.admin(s.handleDiskSMART))
	m.Handle("GET /api/v1/hardware/disk-health", s.admin(s.handleDiskHealth))

	m.Handle("GET /api/v1/storage/pools", s.admin(s.handleListPools))
	m.Handle("POST /api/v1/storage/pools", s.admin(s.handleCreatePool))
	m.Handle("GET /api/v1/storage/recommendation", s.admin(s.handleRecommend))
	m.Handle("GET /api/v1/storage/importable", s.admin(s.handleImportable))
	m.Handle("POST /api/v1/storage/import", s.admin(s.handleImport))
	m.Handle("GET /api/v1/storage/pools/{pool}", s.admin(s.handlePoolStatus))
	m.Handle("DELETE /api/v1/storage/pools/{pool}", s.admin(s.handleDestroyPool))
	m.Handle("POST /api/v1/storage/pools/{pool}/vdevs", s.admin(s.handleAddVdevs))
	m.Handle("POST /api/v1/storage/pools/{pool}/attach", s.admin(s.handleAttach))
	m.Handle("POST /api/v1/storage/pools/{pool}/replace", s.admin(s.handleReplace))
	m.Handle("POST /api/v1/storage/pools/{pool}/device", s.admin(s.handleDeviceAction))
	m.Handle("POST /api/v1/storage/pools/{pool}/scrub", s.admin(s.handleScrub))
	m.Handle("POST /api/v1/storage/pools/{pool}/clear", s.admin(s.handleClear))
	m.Handle("POST /api/v1/storage/pools/{pool}/export", s.admin(s.handleExport))

	m.Handle("GET /api/v1/storage/datasets", s.admin(s.handleListDatasets))
	m.Handle("POST /api/v1/storage/datasets", s.admin(s.handleCreateDataset))
	m.Handle("PATCH /api/v1/storage/datasets", s.admin(s.handleUpdateDataset))
	m.Handle("DELETE /api/v1/storage/datasets", s.admin(s.handleDestroyDataset))

	m.Handle("GET /api/v1/storage/snapshots", s.admin(s.handleListSnapshots))
	m.Handle("POST /api/v1/storage/snapshots", s.admin(s.handleCreateSnapshot))
	m.Handle("DELETE /api/v1/storage/snapshots", s.admin(s.handleDestroySnapshot))
	m.Handle("POST /api/v1/storage/snapshots/rollback", s.admin(s.handleRollback))

	m.Handle("GET /api/v1/storage/snapshot-policies", s.admin(s.handleListSnapPolicies))
	m.Handle("POST /api/v1/storage/snapshot-policies", s.admin(s.handleSaveSnapPolicy))
	m.Handle("DELETE /api/v1/storage/snapshot-policies/{id}", s.admin(s.handleDeleteSnapPolicy))
	m.Handle("GET /api/v1/storage/scrub-policies", s.admin(s.handleListScrubPolicies))
	m.Handle("POST /api/v1/storage/scrub-policies", s.admin(s.handleSaveScrubPolicy))
}

// writePrivError maps root-helper errors to HTTP responses.
func (s *Server) writePrivError(w http.ResponseWriter, err error) {
	var pe *priv.Error
	if errors.As(err, &pe) {
		switch pe.Code {
		case priv.CodeBadArgs, priv.CodeBadRequest:
			writeError(w, http.StatusBadRequest, "invalid", pe.Message)
		case priv.CodeForbidden:
			writeError(w, http.StatusConflict, "refused", pe.Message)
		case priv.CodeUnavailable:
			writeError(w, http.StatusServiceUnavailable, "priv_unavailable", "the root helper isn't running: "+pe.Message)
		default:
			writeError(w, http.StatusUnprocessableEntity, "operation_failed", pe.Message)
		}
		return
	}
	internalError(s, w, err)
}

func (s *Server) privCall(w http.ResponseWriter, r *http.Request, op string, args, out any) bool {
	if err := s.cfg.Storage.Priv.Call(r.Context(), op, args, out); err != nil {
		s.writePrivError(w, err)
		return false
	}
	return true
}

func (s *Server) handleHardware(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	h, err := s.cfg.Storage.Hardware(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) handleDiskSMART(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var disks []hw.Disk
	if !s.privCall(w, r, priv.OpHWDisks, nil, &disks) {
		return
	}
	name := r.PathValue("name")
	for _, d := range disks {
		if d.Name != name {
			continue
		}
		dev := d.ByID
		if !hw.ValidDevicePath(dev) {
			dev = d.Path
		}
		var sm hw.SMART
		if s.privCall(w, r, priv.OpHWSmart, priv.DeviceArgs{Device: dev}, &sm) {
			writeJSON(w, http.StatusOK, sm)
		}
		return
	}
	writeError(w, http.StatusNotFound, "not_found", "no disk named "+name)
}

func (s *Server) handleDiskHealth(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	h, err := s.cfg.Storage.DiskHealthAll(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (s *Server) handleListPools(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var pools []zfs.Pool
	if s.privCall(w, r, priv.OpPools, nil, &pools) {
		writeJSON(w, http.StatusOK, pools)
	}
}

func (s *Server) handlePoolStatus(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var st zfs.Status
	if s.privCall(w, r, priv.OpPoolStatus, priv.PoolArgs{Pool: r.PathValue("pool")}, &st) {
		writeJSON(w, http.StatusOK, st)
	}
}

func (s *Server) handleRecommend(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "tank"
	}
	rec, err := s.cfg.Storage.Recommend(r.Context(), name)
	if err != nil {
		var pe *priv.Error
		if errors.As(err, &pe) {
			s.writePrivError(w, err)
			return
		}
		writeError(w, http.StatusUnprocessableEntity, "no_recommendation", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleImportable(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var list []zfs.ImportablePool
	if s.privCall(w, r, priv.OpPoolImportable, nil, &list) {
		writeJSON(w, http.StatusOK, list)
	}
}

// JobAccepted is returned when an operation runs as a background job.
type JobAccepted struct {
	Job      any      `json:"job"`
	Warnings []string `json:"warnings"`
}

type createPoolRequest struct {
	Spec        zfs.PoolSpec `json:"spec"`
	ConfirmWipe bool         `json:"confirmWipe"`
}

func (s *Server) handleCreatePool(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req createPoolRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Spec.Validate(true); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if !req.ConfirmWipe {
		writeError(w, http.StatusBadRequest, "confirm_required", "confirmWipe must be true: every selected disk will be erased")
		return
	}
	s.submit(w, r, u, storage.KindPoolCreate, "Create pool "+req.Spec.Name, storage.CreatePoolParams{Spec: req.Spec},
		"storage.pool.create", req.Spec.Name, req.Spec.Warnings())
}

type addVdevsRequest struct {
	Spec        zfs.PoolSpec `json:"spec"`
	ConfirmWipe bool         `json:"confirmWipe"`
}

func (s *Server) handleAddVdevs(w http.ResponseWriter, r *http.Request, u *auth.User) {
	pool := r.PathValue("pool")
	var req addVdevsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Spec.Validate(false); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if !req.ConfirmWipe {
		writeError(w, http.StatusBadRequest, "confirm_required", "confirmWipe must be true: the new disks will be erased")
		return
	}
	s.submit(w, r, u, storage.KindPoolAdd, "Add disks to "+pool, storage.AddParams{Pool: pool, Spec: req.Spec},
		"storage.pool.add", pool, req.Spec.Warnings())
}

type attachRequest struct {
	Target      string `json:"target"`
	Disk        string `json:"disk"`
	ConfirmWipe bool   `json:"confirmWipe"`
}

func (s *Server) handleAttach(w http.ResponseWriter, r *http.Request, u *auth.User) {
	pool := r.PathValue("pool")
	var req attachRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := zfs.ValidDiskPath(req.Disk); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if err := zfs.ValidVdevRef(req.Target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if !req.ConfirmWipe {
		writeError(w, http.StatusBadRequest, "confirm_required", "confirmWipe must be true: the new disk will be erased")
		return
	}
	s.submit(w, r, u, storage.KindPoolAttach, "Expand "+req.Target+" in "+pool,
		storage.AttachParams{Pool: pool, Target: req.Target, Disk: req.Disk}, "storage.pool.attach", pool+" "+req.Target, nil)
}

type replaceRequest struct {
	Old         string `json:"old"`
	Disk        string `json:"disk"`
	ConfirmWipe bool   `json:"confirmWipe"`
}

func (s *Server) handleReplace(w http.ResponseWriter, r *http.Request, u *auth.User) {
	pool := r.PathValue("pool")
	var req replaceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := zfs.ValidDiskPath(req.Disk); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if err := zfs.ValidVdevRef(req.Old); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if !req.ConfirmWipe {
		writeError(w, http.StatusBadRequest, "confirm_required", "confirmWipe must be true: the new disk will be erased")
		return
	}
	s.submit(w, r, u, storage.KindPoolReplace, "Replace a disk in "+pool,
		storage.ReplaceParams{Pool: pool, Old: req.Old, Disk: req.Disk}, "storage.pool.replace", pool+" "+req.Old, nil)
}

func (s *Server) submit(w http.ResponseWriter, r *http.Request, u *auth.User, kind, title string, params any, action, target string, warnings []string) {
	if !s.jobsReady(w) {
		return
	}
	id := u.ID
	j, err := s.cfg.Jobs.Submit(r.Context(), kind, title, params, &id)
	if err != nil {
		internalError(s, w, err)
		return
	}
	s.record(r, u, action, target, audit.Success, "job "+j.ID)
	if warnings == nil {
		warnings = []string{}
	}
	writeJSON(w, http.StatusAccepted, JobAccepted{Job: j, Warnings: warnings})
}

type deviceActionRequest struct {
	Action string `json:"action"` // online, offline, remove
	Device string `json:"device"`
}

func (s *Server) handleDeviceAction(w http.ResponseWriter, r *http.Request, u *auth.User) {
	pool := r.PathValue("pool")
	var req deviceActionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	op := map[string]string{"online": priv.OpPoolOnline, "offline": priv.OpPoolOffline, "remove": priv.OpPoolRemove}[req.Action]
	if op == "" {
		writeError(w, http.StatusBadRequest, "invalid", "action must be online, offline or remove")
		return
	}
	var st zfs.Status
	if s.privCall(w, r, op, priv.PoolDeviceArgs{Pool: pool, Device: req.Device}, &st) {
		s.record(r, u, "storage.device."+req.Action, pool+" "+req.Device, audit.Success, "")
		writeJSON(w, http.StatusOK, st)
	}
}

type scrubRequest struct {
	Action string `json:"action"`
}

func (s *Server) handleScrub(w http.ResponseWriter, r *http.Request, u *auth.User) {
	pool := r.PathValue("pool")
	var req scrubRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var st zfs.Status
	if s.privCall(w, r, priv.OpPoolScrub, priv.PoolScrubArgs{Pool: pool, Action: req.Action}, &st) {
		s.record(r, u, "storage.scrub."+orDefault(req.Action, "start"), pool, audit.Success, "")
		writeJSON(w, http.StatusOK, st)
	}
}

func (s *Server) handleClear(w http.ResponseWriter, r *http.Request, u *auth.User) {
	pool := r.PathValue("pool")
	var st zfs.Status
	if s.privCall(w, r, priv.OpPoolClear, priv.PoolArgs{Pool: pool}, &st) {
		s.record(r, u, "storage.pool.clear", pool, audit.Success, "")
		writeJSON(w, http.StatusOK, st)
	}
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, u *auth.User) {
	pool := r.PathValue("pool")
	if s.privCall(w, r, priv.OpPoolExport, priv.PoolArgs{Pool: pool}, nil) {
		s.record(r, u, "storage.pool.export", pool, audit.Success, "")
		w.WriteHeader(http.StatusNoContent)
	}
}

type importRequest struct {
	Pool  string `json:"pool"`
	Force bool   `json:"force"`
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req importRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	var pools []zfs.Pool
	if s.privCall(w, r, priv.OpPoolImport, priv.PoolImportArgs{Pool: req.Pool, Force: req.Force}, &pools) {
		s.record(r, u, "storage.pool.import", req.Pool, audit.Success, "")
		writeJSON(w, http.StatusOK, pools)
	}
}

type destroyPoolRequest struct {
	ConfirmName string `json:"confirmName"`
}

func (s *Server) handleDestroyPool(w http.ResponseWriter, r *http.Request, u *auth.User) {
	pool := r.PathValue("pool")
	var req destroyPoolRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if s.privCall(w, r, priv.OpPoolDestroy, priv.PoolDestroyArgs{Pool: pool, ConfirmName: req.ConfirmName}, nil) {
		s.record(r, u, "storage.pool.destroy", pool, audit.Success, "")
		w.WriteHeader(http.StatusNoContent)
	} else {
		s.record(r, u, "storage.pool.destroy", pool, audit.Failure, "")
	}
}

func (s *Server) handleListDatasets(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var list []zfs.Dataset
	if s.privCall(w, r, priv.OpDatasets, priv.DatasetListArgs{Root: r.URL.Query().Get("root")}, &list) {
		writeJSON(w, http.StatusOK, list)
	}
}

func (s *Server) handleCreateDataset(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req priv.DatasetCreateArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	var list []zfs.Dataset
	if s.privCall(w, r, priv.OpDatasetCreate, req, &list) {
		s.record(r, u, "storage.dataset.create", req.Name, audit.Success, "")
		writeJSON(w, http.StatusCreated, list)
	}
}

func (s *Server) handleUpdateDataset(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req priv.DatasetSetArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	var list []zfs.Dataset
	if s.privCall(w, r, priv.OpDatasetSet, req, &list) {
		s.record(r, u, "storage.dataset.update", req.Name, audit.Success, "")
		writeJSON(w, http.StatusOK, list)
	}
}

func (s *Server) handleDestroyDataset(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req priv.DatasetDestroyArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	if s.privCall(w, r, priv.OpDatasetDestroy, req, nil) {
		s.record(r, u, "storage.dataset.destroy", req.Name, audit.Success, "")
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleListSnapshots(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var list []zfs.Snapshot
	if s.privCall(w, r, priv.OpSnapshots, priv.DatasetListArgs{Root: r.URL.Query().Get("root")}, &list) {
		writeJSON(w, http.StatusOK, list)
	}
}

func (s *Server) handleCreateSnapshot(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req priv.SnapshotCreateArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	if s.privCall(w, r, priv.OpSnapshotCreate, req, nil) {
		s.record(r, u, "storage.snapshot.create", req.Dataset+"@"+req.Label, audit.Success, "")
		w.WriteHeader(http.StatusCreated)
	}
}

func (s *Server) handleDestroySnapshot(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req priv.SnapshotArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	if s.privCall(w, r, priv.OpSnapshotDestroy, req, nil) {
		s.record(r, u, "storage.snapshot.destroy", req.Name, audit.Success, "")
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req priv.SnapshotRollbackArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	if s.privCall(w, r, priv.OpSnapshotRollback, req, nil) {
		s.record(r, u, "storage.snapshot.rollback", req.Name, audit.Success, "")
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleListSnapPolicies(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	list, err := s.cfg.Storage.ListSnapshotPolicies(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleSaveSnapPolicy(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var p storage.SnapshotPolicy
	if !decodeJSON(w, r, &p) {
		return
	}
	saved, err := s.cfg.Storage.SaveSnapshotPolicy(r.Context(), p)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "no such policy")
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	s.record(r, u, "storage.snapshot_policy.save", saved.Dataset+" "+saved.Frequency, audit.Success, "")
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDeleteSnapPolicy(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.cfg.Storage.DeleteSnapshotPolicy(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "no such policy")
			return
		}
		internalError(s, w, err)
		return
	}
	s.record(r, u, "storage.snapshot_policy.delete", strconv.FormatInt(id, 10), audit.Success, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListScrubPolicies(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	list, err := s.cfg.Storage.ListScrubPolicies(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleSaveScrubPolicy(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var p storage.ScrubPolicy
	if !decodeJSON(w, r, &p) {
		return
	}
	saved, err := s.cfg.Storage.SaveScrubPolicy(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	s.record(r, u, "storage.scrub_policy.save", saved.Pool, audit.Success, "")
	writeJSON(w, http.StatusOK, saved)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
