package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/ports"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/streaming"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// Game streaming in a VM (decisions 400-409, docs/plans/streaming.md):
// the Streaming panel's status, revealing the Sunshine account (password
// asked again, audited), pairing and unpairing Moonlight devices and
// publishing the streaming ports to NetBird peers. Administrators only;
// every change is a job (audited). hardyd talks to Sunshine in the VM
// itself, at the address root verified, with the certificate root made
// pinned (streaming.Client); root forwards the ports.

// Game streaming job kinds.
const (
	JobKindVMStreamPair   = "vms.streaming.pair"
	JobKindVMStreamUnpair = "vms.streaming.unpair"
	JobKindVMStreamRemote = "vms.streaming.publish"
)

type vmStreaming struct {
	accounts *streaming.Store
	client   *streaming.Client
}

func (s *Server) newVMStreaming() {
	if s.cfg.DB == nil {
		return
	}
	keys := s.cfg.Secrets
	if keys == nil {
		keys = secretbox.NewStaticSource()
	}
	c := s.cfg.StreamingClient
	if c == nil {
		c = &streaming.Client{}
	}
	s.stream = &vmStreaming{accounts: &streaming.Store{DB: s.cfg.DB, Keys: keys}, client: c}
	if s.cfg.Jobs != nil && s.cfg.Priv != nil {
		s.registerVMStreamingJobs(s.cfg.Jobs, s.cfg.Priv)
	}
}

func (s *Server) vmStreamingRoutes() {
	if s.stream == nil {
		return
	}
	m := s.mux
	m.Handle("GET /api/v1/vms/{id}/streaming", s.admin(s.handleVMStreaming))
	m.Handle("POST /api/v1/vms/{id}/streaming/reveal", s.admin(s.handleVMStreamingReveal))
	m.Handle("POST /api/v1/vms/{id}/streaming/pair", s.admin(s.handleVMStreamingPair))
	m.Handle("POST /api/v1/vms/{id}/streaming/unpair", s.admin(s.handleVMStreamingUnpair))
	m.Handle("PUT /api/v1/vms/{id}/streaming/remote", s.admin(s.handleVMStreamingRemote))
}

// VMStreamingStatus is the Streaming panel.
type VMStreamingStatus struct {
	// SetUp: HardyOS installed and set up Sunshine in this VM. Without it
	// the panel only gives the steps to do it by hand.
	SetUp bool `json:"setUp"`
	// InstallPending: Windows (and so Sunshine) isn't installed yet.
	InstallPending bool `json:"installPending"`
	Running        bool `json:"running"`
	HasGPU         bool `json:"hasGPU"`
	// Address is the VM's address on the home network (Moonlight finds
	// it there by itself, or add it by this address).
	Address string `json:"address"`
	// Reachable: Sunshine answered with its pinned certificate.
	Reachable bool   `json:"reachable"`
	Problem   string `json:"problem,omitempty"`
	// User is the Sunshine web UI account; AccountKept: HardyOS has its
	// password (Reveal shows it); RevealedAt the last time it was shown.
	User        string               `json:"user"`
	AccountKept bool                 `json:"accountKept"`
	RevealedAt  string               `json:"revealedAt,omitempty"`
	Devices     []streaming.Device   `json:"devices"`
	Waiting     []VMStreamingWaiting `json:"waiting"`
	Remote      bool                 `json:"remote"`
	Forwarding  bool                 `json:"forwarding"`
	NetBird     string               `json:"netbirdAddress,omitempty"`
	Ports       VMStreamingPortsInfo `json:"ports"`
	// Peers are the NetBird devices streaming is forwarded from (none
	// until chosen); NetBirdPeers what this server sees, to choose from.
	Peers         []string            `json:"peers"`
	NetBirdPeers  []VMStreamingNBPeer `json:"netbirdPeers"`
	NetBirdKernel bool                `json:"netbirdKernel"`
	// BridgeAddress is this server's home network address: what Sunshine
	// sees as the client for every device forwarded from NetBird.
	BridgeAddress string `json:"bridgeAddress,omitempty"`
}

// VMStreamingWaiting is a Moonlight device waiting for its PIN.
type VMStreamingWaiting struct {
	streaming.Pending
	// ViaNetBird: it reached Sunshine through the NetBird forwarding
	// (Sunshine sees this server's address), so HardyOS can't tell which
	// device it is; pair at home instead, or confirm.
	ViaNetBird bool `json:"viaNetBird"`
}

// VMStreamingNBPeer is a NetBird device streaming can be published to.
type VMStreamingNBPeer struct {
	vms.NetBirdPeer
	// Proxy: NetBird's reverse proxy came from this address; it can't be
	// chosen.
	Proxy bool `json:"proxy"`
}

// VMStreamingPortsInfo lists what's forwarded over NetBird.
type VMStreamingPortsInfo struct {
	TCP []int `json:"tcp"`
	UDP []int `json:"udp"`
}

// streamTarget is the VM's Sunshine: root's verified address and pin,
// hardyd's sealed account.
func (s *Server) streamTarget(ctx context.Context, id string) (*streaming.Target, *vms.StreamingInfo, error) {
	var info vms.StreamingInfo
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := s.cfg.Priv.Call(cctx, priv.OpVMsStreamingInfo, priv.VMRef{ID: id}, &info); err != nil {
		return nil, nil, err
	}
	if info.Address == "" {
		msg := info.Problem
		if msg == "" {
			msg = "the VM's address isn't known yet"
		}
		return nil, &info, errors.New(msg)
	}
	acct, err := s.stream.accounts.Get(ctx, id)
	if err != nil {
		if errors.Is(err, secretbox.ErrOpen) {
			return nil, &info, errors.New("the Sunshine account can't be opened on this server (restored from another?)")
		}
		return nil, &info, err
	}
	return &streaming.Target{Address: info.Address, CertSHA256: info.CertSHA256, User: acct.User, Password: acct.Password}, &info, nil
}

func (s *Server) handleVMStreaming(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	v, ok := s.getVM(w, r)
	if !ok {
		return
	}
	st := VMStreamingStatus{
		SetUp: v.StreamingSetUp(), InstallPending: v.InstallPending(), Running: v.State == "running", HasGPU: v.HasGPU(),
		Devices: []streaming.Device{}, Waiting: []VMStreamingWaiting{}, Peers: []string{}, NetBirdPeers: []VMStreamingNBPeer{},
		Ports: VMStreamingPortsInfo{TCP: vmsPortsTCP(), UDP: vmsPortsUDP()},
	}
	if !st.SetUp {
		writeJSON(w, http.StatusOK, st)
		return
	}
	st.User = v.Streaming.User
	st.Remote = v.Streaming.Remote
	st.AccountKept, st.RevealedAt = s.stream.accounts.Has(r.Context(), v.ID)
	t, info, err := s.streamTarget(r.Context(), v.ID)
	if info != nil {
		st.Address, st.Forwarding, st.NetBird = info.Address, info.Forwarding, info.NetBirdAddress
		st.Peers, st.NetBirdKernel, st.BridgeAddress = append(st.Peers, info.Peers...), info.NetBirdKernel, info.BridgeAddress
		proxies := s.remote.knownProxies()
		for _, p := range info.NetBirdPeers {
			st.NetBirdPeers = append(st.NetBirdPeers, VMStreamingNBPeer{NetBirdPeer: p, Proxy: proxies[p.IP]})
		}
	}
	if err != nil {
		st.Problem = err.Error()
		writeJSON(w, http.StatusOK, st)
		return
	}
	devs, err := s.stream.client.Devices(r.Context(), *t)
	if err != nil {
		st.Problem = err.Error()
		if st.InstallPending {
			st.Problem = "Windows and Sunshine are still being installed; watch the VM's screen"
		}
		writeJSON(w, http.StatusOK, st)
		return
	}
	st.Reachable, st.Devices = true, devs
	if waiting, err := s.stream.client.Waiting(r.Context(), *t); err == nil {
		for _, w := range waiting {
			st.Waiting = append(st.Waiting, VMStreamingWaiting{Pending: w, ViaNetBird: info != nil && viaNetBird(w, info.BridgeAddress)})
		}
	}
	if info != nil && info.Problem != "" {
		st.Problem = info.Problem
	}
	writeJSON(w, http.StatusOK, st)
}

// VMStreamingRevealRequest asks for the Sunshine account; the
// administrator's own password is checked again.
type VMStreamingRevealRequest struct {
	Password string `json:"password"`
}

// VMStreamingAccount is the Sunshine web UI account.
type VMStreamingAccount struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

func (s *Server) handleVMStreamingReveal(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req VMStreamingRevealRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	v, ok := s.getVM(w, r)
	if !ok {
		return
	}
	if !v.StreamingSetUp() {
		writeError(w, http.StatusNotFound, "not_found", "HardyOS didn't set up game streaming in this VM")
		return
	}
	key := "streamreveal:" + strconv.FormatInt(u.ID, 10)
	if s.cfg.Limiter != nil {
		if ok, wait := s.cfg.Limiter.Allowed(key); !ok {
			s.record(r, u, "vms.streaming.reveal", v.ID, audit.Denied, "rate limited")
			writeError(w, http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("too many wrong passwords; try again in %d minutes", int(wait.Minutes())+1))
			return
		}
	}
	if err := s.signin.Verify(r.Context(), u, req.Password); err != nil {
		if errors.Is(err, auth.ErrDomainUnavailable) || errors.Is(err, auth.ErrClockSkew) {
			writeError(w, http.StatusServiceUnavailable, "domain_unavailable", err.Error())
			return
		}
		if errors.Is(err, auth.ErrBadCredentials) || errors.Is(err, auth.ErrAccountRevoked) ||
			errors.Is(err, auth.ErrPasswordExpired) || errors.Is(err, auth.ErrAccountGone) {
			if s.cfg.Limiter != nil {
				s.cfg.Limiter.Fail(key)
			}
			s.record(r, u, "vms.streaming.reveal", v.ID, audit.Failure, "wrong password")
			writeError(w, http.StatusUnauthorized, "bad_credentials", "that password isn't right")
			return
		}
		internalError(s, w, err)
		return
	}
	if s.cfg.Limiter != nil {
		s.cfg.Limiter.Succeed(key)
	}
	acct, err := s.stream.accounts.Get(r.Context(), v.ID)
	if err != nil {
		s.record(r, u, "vms.streaming.reveal", v.ID, audit.Failure, "no account")
		if errors.Is(err, streaming.ErrNoAccount) || errors.Is(err, secretbox.ErrOpen) {
			writeError(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		internalError(s, w, err)
		return
	}
	_ = s.stream.accounts.Revealed(r.Context(), v.ID)
	s.record(r, u, "vms.streaming.reveal", v.ID, audit.Success, "Sunshine account shown")
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, VMStreamingAccount{User: acct.User, Password: acct.Password})
}

// viaNetBird: Sunshine saw the pairing come from this server's own home
// network address, which is what the NetBird forwarding's masquerade looks
// like (decision 406).
func viaNetBird(p streaming.Pending, bridge string) bool {
	return bridge != "" && strings.TrimPrefix(p.Address, "::ffff:") == bridge
}

// VMStreamingPairRequest gives Sunshine a waiting Moonlight device's PIN.
// ConfirmRemote is needed for a device that came through NetBird.
type VMStreamingPairRequest struct {
	PairingID     string `json:"pairingId"`
	PIN           string `json:"pin"`
	Name          string `json:"name"`
	ConfirmRemote bool   `json:"confirmRemote,omitempty"`
}

type vmStreamPairParams struct {
	ID            string `json:"id"`
	PairingID     string `json:"pairingId"`
	Name          string `json:"name"`
	ConfirmRemote bool   `json:"confirmRemote,omitempty"`
	// PINRef: the PIN waits in jobSecrets (job parameters are history).
	PINRef string `json:"pinRef"`
}

func (s *Server) streamingVM(w http.ResponseWriter, r *http.Request) (*vms.VM, bool) {
	v, ok := s.getVM(w, r)
	if !ok {
		return nil, false
	}
	if !v.StreamingSetUp() {
		writeError(w, http.StatusConflict, "not_set_up", "HardyOS didn't set up game streaming in this VM")
		return nil, false
	}
	return v, true
}

func (s *Server) handleVMStreamingPair(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req VMStreamingPairRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if err := streaming.ValidPairing(req.PairingID, req.PIN, req.Name); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	v, ok := s.streamingVM(w, r)
	if !ok {
		return
	}
	p := vmStreamPairParams{ID: v.ID, PairingID: req.PairingID, Name: req.Name, ConfirmRemote: req.ConfirmRemote, PINRef: jobSecrets.put(req.PIN)}
	s.submit(w, r, u, JobKindVMStreamPair, "Pair "+req.Name+" with "+v.Name, p, "vms.streaming.pair", v.ID+" device="+req.Name, nil)
}

// VMStreamingUnpairRequest removes a paired device.
type VMStreamingUnpairRequest struct {
	UUID string `json:"uuid"`
}

type vmStreamUnpairParams struct {
	ID   string `json:"id"`
	UUID string `json:"uuid"`
}

func (s *Server) handleVMStreamingUnpair(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req VMStreamingUnpairRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !streaming.ValidClientID(req.UUID) {
		writeError(w, http.StatusBadRequest, "invalid", "that isn't a paired device")
		return
	}
	v, ok := s.streamingVM(w, r)
	if !ok {
		return
	}
	s.submit(w, r, u, JobKindVMStreamUnpair, "Unpair a device from "+v.Name, vmStreamUnpairParams{ID: v.ID, UUID: req.UUID}, "vms.streaming.unpair", v.ID+" device="+req.UUID, nil)
}

// VMStreamingRemoteRequest publishes (or stops publishing) the streaming
// ports to the chosen NetBird devices (their addresses).
type VMStreamingRemoteRequest struct {
	Enabled bool     `json:"enabled"`
	Peers   []string `json:"peers,omitempty"`
}

func (s *Server) handleVMStreamingRemote(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req VMStreamingRemoteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	v, ok := s.streamingVM(w, r)
	if !ok {
		return
	}
	title := "Stop streaming " + v.Name + " to NetBird devices"
	peers := []string{}
	if req.Enabled {
		title = "Stream " + v.Name + " to NetBird devices"
		if len(req.Peers) == 0 || len(req.Peers) > vms.MaxStreamPeers {
			writeError(w, http.StatusBadRequest, "invalid", fmt.Sprintf("choose 1 to %d NetBird devices to stream to", vms.MaxStreamPeers))
			return
		}
		proxies := s.remote.knownProxies()
		for _, p := range req.Peers {
			a, err := netip.ParseAddr(p)
			if err != nil || !a.Is4() || a.String() != p {
				writeError(w, http.StatusBadRequest, "invalid", fmt.Sprintf("%q isn't a NetBird device's address", p))
				return
			}
			if proxies[p] {
				writeError(w, http.StatusBadRequest, "invalid", p+" is NetBird's reverse proxy; game streaming is never forwarded to it")
				return
			}
		}
		peers = req.Peers
	}
	s.submit(w, r, u, JobKindVMStreamRemote, title, vms.StreamingPublishArgs{ID: v.ID, Enabled: req.Enabled, Peers: peers}, "vms.streaming.publish",
		fmt.Sprintf("%s enabled=%t devices=%s", v.ID, req.Enabled, strings.Join(peers, ",")), nil)
}

func (s *Server) registerVMStreamingJobs(m *jobs.Manager, pc *priv.Client) {
	acct := s.stream.accounts
	// Creating and deleting VMs keep and forget Sunshine accounts.
	m.Register(jobs.Kind{Name: JobKindVMCreate, AdminOnly: true, LockKey: vmLock, Run: vmCreateJob(pc, acct)})
	m.Register(jobs.Kind{Name: JobKindVMDelete, AdminOnly: true, LockKey: vmLock, Run: vmDeleteJob(pc, acct)})

	target := func(jc *jobs.Context, id string) (*streaming.Target, error) {
		t, _, err := s.streamTarget(jc, id)
		return t, err
	}
	m.Register(jobs.Kind{Name: JobKindVMStreamPair, AdminOnly: true, LockKey: vmLock, Run: func(jc *jobs.Context) (any, error) {
		var p vmStreamPairParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		pin, ok := jobSecrets.take(p.PINRef)
		if !ok {
			return nil, errors.New("the PIN was lost (HardyOS restarted); enter it again")
		}
		jc.Progress(20, "Reaching Sunshine in the VM")
		t, info, err := s.streamTarget(jc, p.ID)
		if err != nil {
			return nil, err
		}
		// Exactly one device may be waiting, and it must be the one the
		// administrator saw (decision 406): a second device knocking at
		// the same moment could otherwise take the PIN.
		waiting, err := s.stream.client.Waiting(jc, *t)
		if err != nil {
			return nil, err
		}
		if len(waiting) != 1 || waiting[0].ID != p.PairingID {
			return nil, fmt.Errorf("%d devices are waiting to pair; pair one at a time (cancel the others in Moonlight and try again)", len(waiting))
		}
		if info != nil && viaNetBird(waiting[0], info.BridgeAddress) && !p.ConfirmRemote {
			return nil, errors.New("this device came through NetBird, so HardyOS can't tell which device it is; pair it at home, or confirm that it's yours")
		}
		jc.Progress(60, "Giving Sunshine the PIN")
		if err := s.stream.client.Pair(jc, *t, p.PairingID, pin, p.Name); err != nil {
			return nil, err
		}
		return map[string]any{"paired": true, "name": p.Name}, nil
	}})
	m.Register(jobs.Kind{Name: JobKindVMStreamUnpair, AdminOnly: true, LockKey: vmLock, Run: func(jc *jobs.Context) (any, error) {
		var p vmStreamUnpairParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		t, err := target(jc, p.ID)
		if err != nil {
			return nil, err
		}
		if err := s.stream.client.Unpair(jc, *t, p.UUID); err != nil {
			return nil, err
		}
		return map[string]any{"unpaired": true}, nil
	}})
	m.Register(jobs.Kind{Name: JobKindVMStreamRemote, AdminOnly: true, LockKey: vmLock, Run: func(jc *jobs.Context) (any, error) {
		var p vms.StreamingPublishArgs
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(30, "Setting up forwarding")
		var v vms.VM
		if err := call(jc, pc, time.Minute, priv.OpVMsStreamingPublish, p, &v); err != nil {
			return nil, err
		}
		return VMJobResult{VM: &v, Warnings: []string{}}, nil
	}})
}

func vmsPortsTCP() []int { return append([]int(nil), ports.SunshineTCP...) }
func vmsPortsUDP() []int { return append([]int(nil), ports.SunshineUDP...) }
