// Package installer is hardyd's side of the web installer: it checks the
// one-time code shown on the server's console, keeps installer sessions, and
// runs the install as a job that drives hardyd-priv's install steps.
//
// It also holds ApplySeed, which creates the first administrator on an
// installed system's first boot from what the installer recorded.
package installer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/install"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// JobKind is the install job.
const JobKind = "system.install"

// SessionLifetime bounds an installer session.
const SessionLifetime = 12 * time.Hour

// Errors returned to the API.
var (
	ErrBadCode      = errors.New("that code doesn't match the one on the server's screen")
	ErrRateLimited  = errors.New("too many attempts; wait a minute and try again")
	ErrBusy         = errors.New("an install is already running")
	ErrAlreadyDone  = errors.New("HardyOS is already installed; restart the server")
	ErrNoCode       = errors.New("the installer isn't ready yet; try again in a few seconds")
	ErrConfirmation = errors.New("confirm that the boot disks will be erased")
)

// Service is the installer state inside hardyd.
type Service struct {
	Priv    *priv.Client
	Jobs    *jobs.Manager
	Limiter *auth.LoginLimiter
	// Root prefixes install.CodeFile ("/" for real).
	Root string

	mu       sync.Mutex
	sessions map[string]time.Time // sha256(token) -> expiry
	jobID    string
}

// Unlock checks a typed code and returns a new session token.
func (s *Service) Unlock(clientKey, typed string) (string, error) {
	if ok, _ := s.Limiter.Allowed("installer:" + clientKey); !ok {
		return "", ErrRateLimited
	}
	real, err := os.ReadFile(filepath.Join(s.root(), install.CodeFile))
	if err != nil {
		return "", ErrNoCode
	}
	if !install.CodesMatch(typed, strings.TrimSpace(string(real))) {
		s.Limiter.Fail("installer:" + clientKey)
		return "", ErrBadCode
	}
	s.Limiter.Succeed("installer:" + clientKey)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = map[string]time.Time{}
	}
	now := time.Now()
	for k, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, k)
		}
	}
	s.sessions[hashToken(token)] = now.Add(SessionLifetime)
	return token, nil
}

// Valid reports whether token is a live installer session.
func (s *Service) Valid(token string) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[hashToken(token)]
	return ok && time.Now().Before(exp)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func (s *Service) root() string {
	if s.Root == "" {
		return "/"
	}
	return s.Root
}

// stepTimeout bounds each install step (copying from a slow USB stick).
const stepTimeout = 40 * time.Minute

// Check validates a plan against the hardware.
func (s *Service) Check(ctx context.Context, plan install.Plan) (*priv.InstallInfo, error) {
	var info priv.InstallInfo
	if err := s.Priv.Call(ctx, priv.OpInstallCheck, priv.InstallArgs{Plan: plan}, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Admin is the first administrator typed into the installer.
type Admin struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Password    string `json:"password"`
}

// StartRequest starts an install.
type StartRequest struct {
	Plan        install.Plan `json:"plan"`
	Admin       Admin        `json:"admin"`
	ConfirmWipe bool         `json:"confirmWipe"`
}

type jobParams struct {
	Plan install.Plan `json:"plan"`
	Seed install.Seed `json:"seed"`
}

// Start validates the request and submits the install job.
func (s *Service) Start(ctx context.Context, req StartRequest) (*jobs.Job, error) {
	if !req.ConfirmWipe {
		return nil, ErrConfirmation
	}
	if err := req.Plan.Validate(); err != nil {
		return nil, err
	}
	name, err := auth.NormalizeUsername(req.Admin.Username)
	if err != nil {
		return nil, err
	}
	if err := auth.ValidatePassword(req.Admin.Password); err != nil {
		return nil, err
	}
	hash, err := auth.HashPassword(req.Admin.Password)
	if err != nil {
		return nil, err
	}
	seed := install.Seed{Username: name, DisplayName: strings.TrimSpace(req.Admin.DisplayName), PasswordHash: hash}
	if err := seed.Validate(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jobID != "" {
		if j, err := s.Jobs.Get(ctx, s.jobID); err == nil {
			switch {
			case !j.State.Done():
				return nil, ErrBusy
			case j.State == jobs.Succeeded:
				return nil, ErrAlreadyDone
			}
		}
	}
	// Fail fast on disk problems instead of inside the job.
	if _, err := s.Check(ctx, req.Plan); err != nil {
		return nil, err
	}
	j, err := s.Jobs.Submit(ctx, JobKind, "Install HardyOS", jobParams{Plan: req.Plan, Seed: seed}, nil)
	if err != nil {
		return nil, err
	}
	s.jobID = j.ID
	return j, nil
}

// Job returns the current or last install job, if any.
func (s *Service) Job(ctx context.Context) *jobs.Job {
	s.mu.Lock()
	id := s.jobID
	s.mu.Unlock()
	if id == "" {
		return nil
	}
	j, err := s.Jobs.Get(ctx, id)
	if err != nil {
		return nil
	}
	return j
}

// Reboot restarts the server (into the new system once installed).
func (s *Service) Reboot(ctx context.Context) error {
	return s.Priv.Call(ctx, priv.OpSystemReboot, nil, nil)
}

// RegisterJobs adds the install job kind.
func (s *Service) RegisterJobs(m *jobs.Manager) {
	m.Register(jobs.Kind{
		Name:    JobKind,
		LockKey: func(json.RawMessage) string { return "install" },
		Run:     s.run,
	})
}

type step struct {
	pct  float64
	msg  string
	op   string
	args any
}

func (s *Service) run(jc *jobs.Context) (any, error) {
	var p jobParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	steps := []step{
		{2, "Checking the boot disks", priv.OpInstallCheck, priv.InstallArgs{Plan: p.Plan}},
		{5, "Erasing and partitioning the boot disks", priv.OpInstallPartition, priv.InstallArgs{Plan: p.Plan, ConfirmWipe: true}},
		{15, "Creating the boot pool", priv.OpInstallPool, priv.InstallArgs{Plan: p.Plan}},
		{20, "Copying HardyOS onto the boot disks", priv.OpInstallSystem, nil},
		{70, "Applying your settings and preparing the first boot", priv.OpInstallConfigure, priv.InstallArgs{Plan: p.Plan, Seed: &p.Seed}},
		{88, "Installing the boot loader", priv.OpInstallBoot, priv.InstallArgs{Plan: p.Plan}},
		{97, "Finishing up", priv.OpInstallFinish, nil},
	}
	for _, st := range steps {
		jc.Progress(st.pct, st.msg)
		ctx, cancel := context.WithTimeout(jc, stepTimeout)
		err := s.Priv.Call(ctx, st.op, st.args, nil)
		cancel()
		if err != nil {
			// Leave the disks unmounted so another attempt can start cleanly.
			_ = s.Priv.Call(context.WithoutCancel(jc), priv.OpInstallReset, nil, nil)
			return nil, fmt.Errorf("%s: %w", strings.ToLower(st.msg[:1])+st.msg[1:], err)
		}
	}
	jc.Progress(100, "HardyOS is installed")
	return map[string]any{"hostname": p.Plan.Hostname, "disks": p.Plan.Disks}, nil
}

// ApplySeed creates the first administrator recorded by the installer, then
// removes the seed. It does nothing when there is no seed or when accounts
// already exist.
func ApplySeed(ctx context.Context, users *auth.Users, path string) (*auth.User, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var seed install.Seed
	if err := json.Unmarshal(b, &seed); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := seed.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	n, err := users.Count(ctx)
	if err != nil {
		return nil, err
	}
	var u *auth.User
	if n == 0 {
		u, err = users.CreateHashed(ctx, auth.NewUser{
			Username: seed.Username, DisplayName: seed.DisplayName, Role: auth.RoleAdmin, BreakGlass: true,
		}, seed.PasswordHash)
		if err != nil {
			return nil, err
		}
	}
	if err := os.Remove(path); err != nil {
		return u, err
	}
	return u, nil
}
