package api

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/updates"
)

func (s *Server) updateRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/system/updates", s.admin(s.handleUpdateStatus))
	m.Handle("POST /api/v1/system/updates/upload", s.admin(s.handleUpdateUpload))
	m.Handle("POST /api/v1/system/updates/download", s.admin(s.handleUpdateDownload))
	m.Handle("POST /api/v1/system/versions/{name}/activate", s.admin(s.handleVersionActivate))
	m.Handle("POST /api/v1/system/versions/{name}/delete", s.admin(s.handleVersionDelete))
	m.Handle("POST /api/v1/system/reboot", s.admin(s.handleReboot))
	m.Handle("GET /api/v1/system/updates/check", s.admin(s.handleUpdateCheckState))
	m.Handle("POST /api/v1/system/updates/check", s.admin(s.handleUpdateCheckNow))
	m.Handle("PUT /api/v1/system/updates/check", s.admin(s.handleUpdateCheckSettings))
	m.Handle("POST /api/v1/system/updates/install-available", s.admin(s.handleInstallAvailable))
}

func (s *Server) handleUpdateCheckState(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	writeJSON(w, http.StatusOK, s.cfg.Updates.CheckState(r.Context()))
}

// handleUpdateCheckNow asks GitHub right away. A failed check (no internet)
// isn't an API error: the state carries the reason.
func (s *Server) handleUpdateCheckNow(w http.ResponseWriter, r *http.Request, u *auth.User) {
	st, err := s.cfg.Updates.CheckNow(r.Context())
	if err != nil {
		s.record(r, u, "system.update.check", "", audit.Failure, err.Error())
	} else {
		s.record(r, u, "system.update.check", "", audit.Success, "")
	}
	writeJSON(w, http.StatusOK, st)
}

type checkSettingsRequest struct {
	AutoCheck bool `json:"autoCheck"`
}

func (s *Server) handleUpdateCheckSettings(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req checkSettingsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := s.cfg.Updates.SetAutoCheck(r.Context(), req.AutoCheck); err != nil {
		internalError(s, w, err)
		return
	}
	s.record(r, u, "system.update.autocheck", fmt.Sprint(req.AutoCheck), audit.Success, "")
	writeJSON(w, http.StatusOK, s.cfg.Updates.CheckState(r.Context()))
}

// handleInstallAvailable downloads and installs the version the last check
// found. The file's signature is checked like any other update.
func (s *Server) handleInstallAvailable(w http.ResponseWriter, r *http.Request, u *auth.User) {
	url, ver, err := s.cfg.Updates.AvailableURL(r.Context())
	if err != nil {
		writeError(w, http.StatusConflict, "nothing_available", err.Error())
		return
	}
	s.submit(w, r, u, updates.JobDownload, "Download and install HardyOS "+ver, map[string]string{"url": url}, "system.update", url, nil)
}

func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	st, err := s.cfg.Updates.Status(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// handleUpdateUpload takes the update file as the raw request body.
func (s *Server) handleUpdateUpload(w http.ResponseWriter, r *http.Request, u *auth.User) {
	r.Body = http.MaxBytesReader(w, r.Body, updates.MaxBundleBytes)
	path, err := s.cfg.Updates.Save(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) || errors.Is(err, updates.ErrTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "the update file is too large")
			return
		}
		s.record(r, u, "system.update.upload", "", audit.Failure, err.Error())
		writeError(w, http.StatusBadRequest, "upload_failed", "the upload didn't finish: "+err.Error())
		return
	}
	s.submit(w, r, u, updates.JobInstall, "Install update", map[string]string{"path": path}, "system.update", "upload", nil)
}

type downloadRequest struct {
	URL string `json:"url"`
}

func (s *Server) handleUpdateDownload(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req downloadRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := updates.ValidateURL(req.URL); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	s.submit(w, r, u, updates.JobDownload, "Download and install update", map[string]string{"url": req.URL}, "system.update", req.URL, nil)
}

var versionPathRE = regexp.MustCompile(`^hardyos-[A-Za-z0-9._-]{1,110}$`)

func versionName(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("name")
	if !versionPathRE.MatchString(name) {
		writeError(w, http.StatusBadRequest, "invalid", "invalid version name")
		return "", false
	}
	return name, true
}

type activateRequest struct {
	RestoreSettings bool `json:"restoreSettings"`
}

func (s *Server) handleVersionActivate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	name, ok := versionName(w, r)
	if !ok {
		return
	}
	var req activateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	s.submit(w, r, u, updates.JobActivate, "Switch to "+name, updates.VersionParams{Name: name, RestoreSettings: req.RestoreSettings}, "system.version.activate", name, nil)
}

type deleteVersionRequest struct {
	ConfirmName string `json:"confirmName"`
}

func (s *Server) handleVersionDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	name, ok := versionName(w, r)
	if !ok {
		return
	}
	var req deleteVersionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.ConfirmName != name {
		writeError(w, http.StatusBadRequest, "invalid", "confirmName must repeat the version name exactly")
		return
	}
	s.submit(w, r, u, updates.JobDelete, "Remove "+name, updates.VersionParams{Name: name, ConfirmName: req.ConfirmName}, "system.version.delete", name, nil)
}

func (s *Server) handleReboot(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if err := s.cfg.Priv.Call(r.Context(), priv.OpSystemReboot, nil, nil); err != nil {
		s.record(r, u, "system.reboot", "", audit.Failure, err.Error())
		s.writePrivError(w, err)
		return
	}
	s.record(r, u, "system.reboot", "", audit.Success, "")
	writeJSON(w, http.StatusAccepted, map[string]bool{"rebooting": true})
}
