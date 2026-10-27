package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/gpu"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// GPU driver job kinds. They start a task in hardyd-priv and follow it.
const (
	JobKindNvidiaPrepare = "devices.nvidia.prepare"
	JobKindNvidiaInstall = "devices.nvidia.install"
	JobKindNvidiaRemove  = "devices.nvidia.remove"
	JobKindVGPUInstall   = "devices.vgpu.install"
	JobKindVGPURemove    = "devices.vgpu.remove"
)

var (
	sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	uploadIDRE  = regexp.MustCompile(`^upload-[0-9a-f]{16}\.run$`)
)

// gpuPollInterval is how often a job asks hardyd-priv about its task.
var gpuPollInterval = 2 * time.Second

func registerGPUJobs(m *jobs.Manager, pc *priv.Client) {
	lock := func(json.RawMessage) string { return "gpu-drivers" }
	follow := func(op string, params func(*jobs.Context) (any, error)) jobs.RunFunc {
		return func(jc *jobs.Context) (any, error) {
			a, err := params(jc)
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(jc, time.Minute)
			var started priv.TaskResult
			err = pc.Call(ctx, op, a, &started)
			cancel()
			if err != nil {
				return nil, err
			}
			if started.Task == nil {
				return nil, errors.New("the driver task didn't start")
			}
			return followTask(jc, pc, started.Task.ID)
		}
	}
	none := func(*jobs.Context) (any, error) { return nil, nil }
	m.Register(jobs.Kind{Name: JobKindNvidiaPrepare, AdminOnly: true, LockKey: lock, Run: follow(priv.OpGPUNvidiaPrepare, none)})
	m.Register(jobs.Kind{Name: JobKindNvidiaInstall, AdminOnly: true, LockKey: lock, Run: follow(priv.OpGPUNvidiaInstall, func(jc *jobs.Context) (any, error) {
		var a gpu.InstallArgs
		return a, jc.Params(&a)
	})})
	m.Register(jobs.Kind{Name: JobKindNvidiaRemove, AdminOnly: true, LockKey: lock, Run: follow(priv.OpGPUNvidiaRemove, func(*jobs.Context) (any, error) {
		return priv.ConfirmArgs{Confirm: true}, nil
	})})
	m.Register(jobs.Kind{Name: JobKindVGPUInstall, AdminOnly: true, LockKey: lock, Run: follow(priv.OpGPUVGPUInstall, func(jc *jobs.Context) (any, error) {
		var a gpu.VGPUArgs
		return a, jc.Params(&a)
	})})
	m.Register(jobs.Kind{Name: JobKindVGPURemove, AdminOnly: true, LockKey: lock, Run: follow(priv.OpGPUVGPURemove, func(*jobs.Context) (any, error) {
		return priv.ConfirmArgs{Confirm: true}, nil
	})})
}

// followTask reports a hardyd-priv task's steps as job progress until it
// ends. Cancelling the job stops following; the task itself (apt, DKMS)
// is never cut off half way.
func followTask(jc *jobs.Context, pc *priv.Client, id string) (any, error) {
	last := ""
	for {
		select {
		case <-jc.Done():
			return nil, errors.New("stopped following the driver task; it keeps running and its log is in Devices > NVIDIA setup")
		case <-time.After(gpuPollInterval):
		}
		ctx, cancel := context.WithTimeout(jc, 30*time.Second)
		var res priv.TaskResult
		err := pc.Call(ctx, priv.OpGPUTask, nil, &res)
		cancel()
		if err != nil {
			continue // hardyd-priv restarting: try again
		}
		t := res.Task
		if t == nil || t.ID != id {
			return nil, errors.New("the driver task was interrupted (the root helper restarted); start it again")
		}
		if t.Step != last || t.State != gpu.TaskRunning {
			jc.Progress(float64(t.Progress), t.Step)
			last = t.Step
		}
		switch t.State {
		case gpu.TaskSucceeded:
			return t.Result, nil
		case gpu.TaskFailed:
			return nil, errors.New(t.Error)
		}
	}
}

func (s *Server) gpuRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/devices/nvidia", s.admin(s.handleNvidiaStatus))
	m.Handle("GET /api/v1/devices/nvidia/licence", s.admin(s.handleNvidiaLicence))
	m.Handle("POST /api/v1/devices/nvidia/prepare", s.admin(s.handleNvidiaPrepare))
	m.Handle("POST /api/v1/devices/nvidia/install", s.admin(s.handleNvidiaInstall))
	m.Handle("POST /api/v1/devices/nvidia/remove", s.admin(s.handleNvidiaRemove))
	m.Handle("GET /api/v1/devices/gpu-task", s.admin(s.handleGPUTask))
	m.Handle("POST /api/v1/devices/vgpu-driver/upload", s.admin(s.handleVGPUUpload))
	m.Handle("POST /api/v1/devices/vgpu-driver/install", s.admin(s.handleVGPUInstall))
	m.Handle("POST /api/v1/devices/vgpu-driver/remove", s.admin(s.handleVGPURemove))
}

func (s *Server) handleNvidiaStatus(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var st gpu.Status
	if err := s.cfg.Priv.Call(r.Context(), priv.OpGPUStatus, nil, &st); err != nil {
		s.writePrivError(w, err)
		return
	}
	if st.Packages == nil {
		st.Packages = []string{}
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleNvidiaLicence(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var res priv.LicenceResult
	if err := s.cfg.Priv.Call(r.Context(), priv.OpGPULicence, nil, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleGPUTask(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var res priv.TaskResult
	if err := s.cfg.Priv.Call(r.Context(), priv.OpGPUTask, nil, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleNvidiaPrepare(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.submit(w, r, u, JobKindNvidiaPrepare, "Get the NVIDIA driver and its licence", map[string]any{}, "devices.nvidia.prepare", "", nil)
}

// NvidiaInstallRequest agrees to NVIDIA's licence and installs the driver.
type NvidiaInstallRequest struct {
	// LicenceSHA256 is the hash of the licence text shown.
	LicenceSHA256 string `json:"licenceSha256"`
	// Accept must be true: the admin agrees to NVIDIA's licence.
	Accept bool `json:"accept"`
}

func (s *Server) handleNvidiaInstall(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req NvidiaInstallRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !req.Accept {
		writeError(w, http.StatusBadRequest, "invalid", "accept must be true: the driver is only installed once NVIDIA's licence is agreed to")
		return
	}
	if !sha256HexRE.MatchString(req.LicenceSHA256) {
		writeError(w, http.StatusBadRequest, "invalid", "licenceSha256 must be the licence text's SHA-256")
		return
	}
	// The agreement itself is audited apart from the job.
	s.record(r, u, "devices.nvidia.licence.accept", req.LicenceSHA256, audit.Success, "NVIDIA driver licence agreed to")
	s.submit(w, r, u, JobKindNvidiaInstall, "Install the NVIDIA driver", gpu.InstallArgs{LicenceSHA256: req.LicenceSHA256, By: u.Username}, "devices.nvidia.install", req.LicenceSHA256, nil)
}

type confirmRequest struct {
	Confirm bool `json:"confirm"`
}

func (s *Server) handleNvidiaRemove(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req confirmRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, "invalid", "confirm must be true")
		return
	}
	s.submit(w, r, u, JobKindNvidiaRemove, "Remove the NVIDIA driver", map[string]any{}, "devices.nvidia.remove", "", nil)
}

// VGPUUpload is a saved vGPU driver file waiting to be installed.
type VGPUUpload struct {
	Upload   string `json:"upload"` // upload-<hex>.run
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	FileName string `json:"fileName"`
	Version  string `json:"version"`
}

func (s *Server) gpuUploadDir() string {
	if s.cfg.GPUUploadDir != "" {
		return s.cfg.GPUUploadDir
	}
	return gpu.UploadDir
}

// handleVGPUUpload takes NVIDIA's vGPU host driver file as the raw body
// (its name in X-HardyOS-Filename), saves it and returns its SHA-256.
func (s *Server) handleVGPUUpload(w http.ResponseWriter, r *http.Request, u *auth.User) {
	name := r.Header.Get("X-HardyOS-Filename")
	version, err := gpu.CheckVGPUFileName(name, runtime.GOARCH)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	dir := s.gpuUploadDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		internalError(s, w, err)
		return
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	id := "upload-" + hex.EncodeToString(b) + ".run"
	path := filepath.Join(dir, id)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		internalError(s, w, err)
		return
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r.Body, gpu.MaxDriverBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > gpu.MaxDriverBytes {
		_ = os.Remove(path)
		writeError(w, http.StatusRequestEntityTooLarge, "too_large", "the driver file is too large")
		return
	}
	if err != nil {
		_ = os.Remove(path)
		s.record(r, u, "devices.vgpu.upload", name, audit.Failure, err.Error())
		writeError(w, http.StatusBadRequest, "upload_failed", "the upload didn't finish: "+err.Error())
		return
	}
	res := VGPUUpload{Upload: id, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n, FileName: name, Version: version}
	s.record(r, u, "devices.vgpu.upload", name, audit.Success, "sha256 "+res.SHA256)
	writeJSON(w, http.StatusOK, res)
}

// VGPUInstallRequest installs an uploaded vGPU host driver.
type VGPUInstallRequest struct {
	Upload   string `json:"upload"`
	SHA256   string `json:"sha256"`
	FileName string `json:"fileName"`
	// Accept: the admin has NVIDIA's vGPU licence and agrees to the
	// licence in NVIDIA's installer.
	Accept bool `json:"accept"`
	// ReplaceDriver: remove Debian's NVIDIA driver first.
	ReplaceDriver bool `json:"replaceDriver"`
}

func (s *Server) handleVGPUInstall(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req VGPUInstallRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !req.Accept {
		writeError(w, http.StatusBadRequest, "invalid", "accept must be true: NVIDIA's vGPU software needs your own licence from NVIDIA")
		return
	}
	if !uploadIDRE.MatchString(req.Upload) || !sha256HexRE.MatchString(req.SHA256) {
		writeError(w, http.StatusBadRequest, "invalid", "upload and sha256 come from the upload")
		return
	}
	if _, err := os.Stat(filepath.Join(s.gpuUploadDir(), req.Upload)); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", "that upload isn't there any more; upload the file again")
		return
	}
	args := gpu.VGPUArgs{Upload: gpu.UploadDir + "/" + req.Upload, SHA256: req.SHA256, FileName: req.FileName, By: u.Username, ReplaceDriver: req.ReplaceDriver}
	s.record(r, u, "devices.vgpu.licence.accept", req.FileName, audit.Success, "sha256 "+req.SHA256)
	s.submit(w, r, u, JobKindVGPUInstall, "Install NVIDIA's vGPU host driver", args, "devices.vgpu.install", fmt.Sprintf("%s sha256 %s", req.FileName, req.SHA256), nil)
}

func (s *Server) handleVGPURemove(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req confirmRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, "invalid", "confirm must be true")
		return
	}
	s.submit(w, r, u, JobKindVGPURemove, "Remove NVIDIA's vGPU host driver", map[string]any{}, "devices.vgpu.remove", "", nil)
}
