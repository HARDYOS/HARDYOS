package api

import (
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/backup"
	"github.com/hardyos/hardyos/daemon/internal/backups"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

func (s *Server) backupRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/system/backups", s.admin(s.handleBackupStatus))
	m.Handle("PUT /api/v1/system/backups/settings", s.admin(s.handleBackupSettings))
	m.Handle("POST /api/v1/system/backups/run", s.admin(s.handleBackupRun))
	m.Handle("POST /api/v1/system/backups/download", s.admin(s.handleBackupPrepareDownload))
	m.Handle("GET /api/v1/system/backups/files/{name}", s.admin(s.handleBackupFile))
	m.Handle("POST /api/v1/system/backups/upload", s.admin(s.handleBackupUpload))
	m.Handle("POST /api/v1/system/backups/restore", s.admin(s.handleBackupRestore))
	m.Handle("POST /api/v1/system/backups/restore/cancel", s.admin(s.handleBackupRestoreCancel))
}

func (s *Server) handleBackupStatus(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	st, err := s.cfg.Backups.Status(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleBackupSettings(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var st backups.Settings
	if !decodeJSON(w, r, &st) {
		return
	}
	if err := s.cfg.Backups.SaveSettings(r.Context(), st); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	s.record(r, u, "system.backup.settings", "nightly="+strconv.FormatBool(st.Nightly), audit.Success, "")
	writeJSON(w, http.StatusOK, s.cfg.Backups.LoadSettings(r.Context()))
}

type backupRunRequest struct {
	Pool string `json:"pool"`
}

func (s *Server) handleBackupRun(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req backupRunRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	s.submit(w, r, u, backups.JobCreate, "Back up settings", map[string]string{"pool": req.Pool, "note": "manual"}, "system.backup.create", req.Pool, nil)
}

type backupDownloadRequest struct {
	Password string `json:"password"`
	Secrets  bool   `json:"secrets"`
}

// handleBackupPrepareDownload makes a password-protected backup right away
// (not as a job: job parameters are kept, and this one has a password).
func (s *Server) handleBackupPrepareDownload(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req backupDownloadRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	d, err := s.cfg.Backups.PrepareDownload(r.Context(), req.Password, req.Secrets)
	if err != nil {
		s.record(r, u, "system.backup.download", "", audit.Failure, err.Error())
		s.writeBackupError(w, err)
		return
	}
	detail := "settings"
	if req.Secrets {
		detail = "settings and encryption keys"
	}
	s.record(r, u, "system.backup.download", d.File, audit.Success, detail)
	writeJSON(w, http.StatusOK, d)
}

var saveAsRE = regexp.MustCompile(`^hardyos-settings-[A-Za-z0-9.-]{1,80}-[0-9]{8}-[0-9]{6}\.hbak$`)

func (s *Server) handleBackupFile(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	f, err := s.cfg.Backups.OpenDownload(r.PathValue("name"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "that download has expired; make a new one")
		return
	}
	defer f.Close()
	as := r.URL.Query().Get("as")
	if !saveAsRE.MatchString(as) {
		as = "hardyos-settings.hbak"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+as+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.Copy(w, f)
}

func (s *Server) handleBackupUpload(w http.ResponseWriter, r *http.Request, u *auth.User) {
	r.Body = http.MaxBytesReader(w, r.Body, backup.MaxBytes)
	name, err := s.cfg.Backups.SaveUpload(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "the file is too large to be a settings backup")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"upload": name})
}

// handleBackupRestore checks a backup and stages it for the next restart.
func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req backups.RestoreSource
	if !decodeJSON(w, r, &req) {
		return
	}
	target := req.Upload
	if req.Pool != "" {
		target = req.Pool + "/" + req.Name
	}
	st, err := s.cfg.Backups.Stage(r.Context(), req)
	if err != nil {
		s.record(r, u, "system.backup.restore", target, audit.Failure, err.Error())
		s.writeBackupError(w, err)
		return
	}
	s.record(r, u, "system.backup.restore", target, audit.Success, "applies at the next restart")
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleBackupRestoreCancel(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if err := s.cfg.Backups.Unstage(r.Context()); err != nil {
		s.writePrivError(w, err)
		return
	}
	s.record(r, u, "system.backup.restore.cancel", "", audit.Success, "")
	w.WriteHeader(http.StatusNoContent)
}

// writeBackupError: root-helper errors as usual; everything else (wrong
// password, damaged file, made by a newer HardyOS) is the request's problem.
func (s *Server) writeBackupError(w http.ResponseWriter, err error) {
	var pe *priv.Error
	if errors.As(err, &pe) {
		s.writePrivError(w, err)
		return
	}
	writeError(w, http.StatusBadRequest, "invalid", err.Error())
}
