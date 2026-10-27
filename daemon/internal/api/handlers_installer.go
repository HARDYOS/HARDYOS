package api

import (
	"errors"
	"github.com/hardyos/hardyos/daemon/internal/cloudbackup"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/hw"
	"github.com/hardyos/hardyos/daemon/internal/install"
	"github.com/hardyos/hardyos/daemon/internal/installer"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/version"
)

// InstallerCookie holds the installer session on the live ISO.
const InstallerCookie = "hardyos_installer"

// InstallerStatus is returned by GET /api/v1/installer.
type InstallerStatus struct {
	Active   bool      `json:"active"`   // this is the live installer
	Unlocked bool      `json:"unlocked"` // the browser entered the console code
	Version  string    `json:"version,omitempty"`
	Job      *jobs.Job `json:"job,omitempty"` // current or last install
}

// installerRoutes replaces the whole API on the live installer.
func (s *Server) installerRoutes() {
	m := s.mux
	m.HandleFunc("GET /api/v1/installer", s.handleInstallerStatus)
	m.HandleFunc("POST /api/v1/installer/unlock", s.handleInstallerUnlock)
	m.Handle("GET /api/v1/installer/hardware", s.installerAuthed(s.handleInstallerHardware))
	m.Handle("POST /api/v1/installer/check", s.installerAuthed(s.handleInstallerCheck))
	m.Handle("POST /api/v1/installer/install", s.installerAuthed(s.handleInstallerInstall))
	m.Handle("POST /api/v1/installer/reboot", s.installerAuthed(s.handleInstallerReboot))
	m.Handle("POST /api/v1/installer/cloud/probe", s.installerAuthed(s.handleInstallerCloudProbe))
	// The desktop's first request; answer it so the UI knows where it is.
	m.HandleFunc("GET /api/v1/setup", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusConflict, "installer", "this is the HardyOS installer")
	})
}

func (s *Server) installerUnlocked(r *http.Request) bool {
	c, err := r.Cookie(InstallerCookie)
	return err == nil && s.cfg.Installer.Valid(c.Value)
}

func (s *Server) installerAuthed(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.installerUnlocked(r) {
			writeError(w, http.StatusUnauthorized, "locked", "enter the code shown on the server's screen")
			return
		}
		h(w, r)
	})
}

func (s *Server) handleInstallerStatus(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Installer == nil {
		writeJSON(w, http.StatusOK, InstallerStatus{Active: false})
		return
	}
	st := InstallerStatus{Active: true, Unlocked: s.installerUnlocked(r)}
	if st.Unlocked {
		st.Version = version.Version
		st.Job = s.cfg.Installer.Job(r.Context())
	}
	writeJSON(w, http.StatusOK, st)
}

type unlockRequest struct {
	Code string `json:"code"`
}

func (s *Server) handleInstallerUnlock(w http.ResponseWriter, r *http.Request) {
	var req unlockRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	token, err := s.cfg.Installer.Unlock(s.clientIP(r), req.Code)
	switch {
	case errors.Is(err, installer.ErrRateLimited):
		writeError(w, http.StatusTooManyRequests, "rate_limited", err.Error())
		return
	case errors.Is(err, installer.ErrBadCode):
		writeError(w, http.StatusUnauthorized, "bad_code", err.Error())
		return
	case errors.Is(err, installer.ErrNoCode):
		writeError(w, http.StatusServiceUnavailable, "not_ready", err.Error())
		return
	case err != nil:
		internalError(s, w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: InstallerCookie, Value: token, Path: "/", MaxAge: int(installer.SessionLifetime.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil || !s.cfg.Insecure, SameSite: http.SameSiteStrictMode,
	})
	s.log.Info("installer unlocked", "ip", s.clientIP(r))
	writeJSON(w, http.StatusOK, InstallerStatus{Active: true, Unlocked: true, Version: version.Version})
}

// InstallerNIC is a network interface with its current addresses.
type InstallerNIC struct {
	hw.NIC
	Addresses []string `json:"addresses"`
}

// InstallerHardware is returned by GET /api/v1/installer/hardware.
type InstallerHardware struct {
	Disks    []hw.Disk      `json:"disks"`
	NICs     []InstallerNIC `json:"nics"`
	MemBytes uint64         `json:"memBytes"`
	CPU      string         `json:"cpu"`
	Virtual  bool           `json:"virtual"`
	Hostname string         `json:"hostname"`
}

func (s *Server) handleInstallerHardware(w http.ResponseWriter, r *http.Request) {
	var disks []hw.Disk
	if err := s.cfg.Priv.Call(r.Context(), priv.OpHWDisks, nil, &disks); err != nil {
		s.writePrivError(w, err)
		return
	}
	var sys hw.System
	if err := s.cfg.Priv.Call(r.Context(), priv.OpHWSystem, nil, &sys); err != nil {
		s.writePrivError(w, err)
		return
	}
	out := InstallerHardware{Disks: disks, NICs: []InstallerNIC{}, MemBytes: sys.Memory.TotalBytes, CPU: sys.CPU.Model, Virtual: sys.Virtual}
	out.Hostname, _ = os.Hostname()
	for _, n := range sys.NICs {
		nic := InstallerNIC{NIC: n, Addresses: []string{}}
		if iface, err := net.InterfaceByName(n.Name); err == nil {
			if addrs, err := iface.Addrs(); err == nil {
				for _, a := range addrs {
					if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLinkLocalUnicast() {
						nic.Addresses = append(nic.Addresses, ipn.String())
					}
				}
			}
		}
		out.NICs = append(out.NICs, nic)
	}
	writeJSON(w, http.StatusOK, out)
}

type installerCheckRequest struct {
	Plan install.Plan `json:"plan"`
}

func (s *Server) handleInstallerCheck(w http.ResponseWriter, r *http.Request) {
	var req installerCheckRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.Plan.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	info, err := s.cfg.Installer.Check(r.Context(), req.Plan)
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleInstallerInstall(w http.ResponseWriter, r *http.Request) {
	var req installer.StartRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	j, err := s.cfg.Installer.Start(r.Context(), req)
	var pe *priv.Error
	switch {
	case err == nil:
		s.log.Info("install started", "ip", s.clientIP(r), "disks", strings.Join(req.Plan.Disks, ","), "job", j.ID)
		writeJSON(w, http.StatusAccepted, j)
	case errors.As(err, &pe):
		s.writePrivError(w, err)
	case isErr(err, installer.ErrBusy, installer.ErrAlreadyDone):
		writeError(w, http.StatusConflict, "busy", err.Error())
	case isErr(err, auth.ErrInvalidName, auth.ErrWeakPassword, auth.ErrPasswordTooLong):
		writeError(w, http.StatusBadRequest, "invalid_admin", err.Error())
	default:
		// Plan validation and confirmation errors are the person's to fix.
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
	}
}

// handleInstallerCloudProbe opens a cloud backup from its recovery kit
// (and the bucket's keys) and lists the versions to restore from.
func (s *Server) handleInstallerCloudProbe(w http.ResponseWriter, r *http.Request) {
	var req cloudbackup.ProbeArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Run = ""
	v, err := s.cfg.Installer.Probe(r.Context(), req)
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": v})
}

func (s *Server) handleInstallerReboot(w http.ResponseWriter, r *http.Request) {
	if err := s.cfg.Installer.Reboot(r.Context()); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"rebooting": true})
}
