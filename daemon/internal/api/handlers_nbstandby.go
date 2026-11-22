package api

// Control Panel › NetBird Standby (docs/netbird-standby.md, decisions
// 420-429): a stopped copy of the VPS's NetBird server that HardyOS keeps in
// sync and can take over by hand. Every change is an administrator's job,
// audited; root holds the VPS key and the copies.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cfdns"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/nbstandby"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/ports"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// NetBird standby job kinds.
const (
	JobKindNBStandbySettings = "netbird.standby.settings"
	JobKindNBStandbyInstall  = "netbird.standby.install"
	JobKindNBStandbySync     = "netbird.standby.sync"
	JobKindNBStandbyDNS      = "netbird.standby.dns"
	JobKindNBStandbyTakeover = "netbird.standby.takeover"
	JobKindNBStandbyHandback = "netbird.standby.handback"
	JobKindNBStandbyForget   = "netbird.standby.forget"
)

// NBStandbyStatus is Control Panel › NetBird Standby.
type NBStandbyStatus struct {
	// Connection is root's side (nil when hardyd-priv didn't answer).
	Connection     *nbstandby.Status         `json:"connection"`
	Problem        string                    `json:"problem,omitempty"`
	Settings       nbstandby.Settings        `json:"settings"`
	Health         nbstandby.Health          `json:"health"`
	History        []nbstandby.SyncRow       `json:"history"`
	App            NBStandbyApp              `json:"app"`
	DNS            NBStandbyDNS              `json:"dns"`
	Takeover       *nbstandby.TakeoverRecord `json:"takeover"`
	StandbyVersion string                    `json:"standbyVersion"`
	VersionNote    string                    `json:"versionNote,omitempty"`
	VersionNewer   bool                      `json:"versionNewer"`
	PortForwards   []NBPortForward           `json:"portForwards"`
	// Client is this server's own NetBird client.
	ClientConnected bool   `json:"clientConnected"`
	ClientIP        string `json:"clientIp"`
	ManagementURL   string `json:"managementUrl"`
}

// NBStandbyApp is the netbird-standby app.
type NBStandbyApp struct {
	Installed bool   `json:"installed"`
	State     string `json:"state"`
	Version   string `json:"version"`
}

// NBStandbyDNS is the standby's name in Cloudflare.
type NBStandbyDNS struct {
	TokenSet bool              `json:"tokenSet"`
	Base     string            `json:"base"`
	Zone     string            `json:"zone"`
	Name     string            `json:"name"`
	Adopted  []priv.DNSAdopted `json:"adopted"`
	// InBase: the NetBird hostname is under the hostnames base (else it
	// needs the standby name extension, decision 424).
	InBase bool `json:"inBase"`
	InZone bool `json:"inZone"`
	// Bound is what the token allowed when the name was adopted (decision
	// 424): the name, this server's addresses and the VPS. NeedsRebind:
	// the current ones differ, so a take-over refuses until the token is
	// pasted again (or hardyctl netbird-standby rebind on the console).
	Bound       *nbstandby.Binding `json:"bound,omitempty"`
	NeedsRebind bool               `json:"needsRebind"`
}

// NBPortForward is one router port forward the standby needs.
type NBPortForward struct {
	Protocol string `json:"protocol"`
	Public   int    `json:"public"`
	Internal int    `json:"internal"`
	Purpose  string `json:"purpose"`
}

func nbPortForwards() []NBPortForward {
	return []NBPortForward{
		{Protocol: "TCP", Public: ports.HTTP, Internal: ports.NetBirdStandbyHTTP, Purpose: "HTTP (redirects; Let's Encrypt)"},
		{Protocol: "TCP", Public: ports.HTTPS, Internal: ports.NetBirdStandbyHTTPS, Purpose: "Management, signal, relay, dashboard (HTTPS and gRPC)"},
		{Protocol: "UDP", Public: ports.NetBirdSTUN, Internal: ports.NetBirdStandbySTUN, Purpose: "STUN"},
	}
}

// nbsRuntime is the loop's memory: when it last started a sync.
type nbsRuntime struct {
	mu        sync.Mutex
	submitted time.Time
}

var nbsLoop nbsRuntime

func (s *Server) nbs() *nbstandby.Service {
	return &nbstandby.Service{DB: s.cfg.DB, Notify: func(ctx context.Context, level, title, body string) {
		if s.cfg.Notify == nil {
			return
		}
		lv := notify.Info
		switch level {
		case "warning":
			lv = notify.Warning
		case "error":
			lv = notify.Error
		}
		_ = s.cfg.Notify.Send(ctx, notify.Notification{Level: lv, Title: title, Body: body, Source: "netbird-standby", AdminOnly: true,
			Kind: "netbird.standby", Link: "control-panel/netbird-standby"})
	}}
}

func (s *Server) nbStandbyRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/netbird-standby", s.admin(s.handleNBStandby))
	m.Handle("PUT /api/v1/netbird-standby/settings", s.admin(s.handleNBStandbySettings))
	m.Handle("GET /api/v1/netbird-standby/script", s.admin(s.handleNBStandbyScript))
	m.Handle("GET /api/v1/netbird-standby/vps", s.admin(s.handleNBStandbyVPS))
	m.Handle("POST /api/v1/netbird-standby/install", s.admin(s.handleNBStandbyInstall))
	m.Handle("POST /api/v1/netbird-standby/sync", s.admin(s.handleNBStandbySync))
	m.Handle("GET /api/v1/netbird-standby/dns", s.admin(s.handleNBStandbyDNSPreview))
	m.Handle("POST /api/v1/netbird-standby/dns", s.admin(s.handleNBStandbyDNSAdopt))
	m.Handle("DELETE /api/v1/netbird-standby/dns", s.admin(s.handleNBStandbyDNSForget))
	m.Handle("POST /api/v1/netbird-standby/dns/rebind", s.admin(s.handleNBStandbyDNSRebind))
	m.Handle("POST /api/v1/netbird-standby/takeover", s.admin(s.handleNBStandbyTakeover))
	m.Handle("POST /api/v1/netbird-standby/handback", s.admin(s.handleNBStandbyHandback))
	m.Handle("DELETE /api/v1/netbird-standby", s.admin(s.handleNBStandbyForget))
	if s.cfg.Jobs != nil {
		s.registerNBStandbyJobs(s.cfg.Jobs)
	}
}

func (s *Server) nbsReady(w http.ResponseWriter) bool {
	if s.cfg.Priv == nil || s.cfg.DB == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "the NetBird standby isn't available on this server")
		return false
	}
	return true
}

func (s *Server) nbsRootStatus(ctx context.Context) (*nbstandby.Status, error) {
	var st nbstandby.Status
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := s.cfg.Priv.Call(ctx, priv.OpNBStandbyStatus, nil, &st); err != nil {
		return nil, err
	}
	if st.Snapshots == nil {
		st.Snapshots = []nbstandby.SnapshotRecord{}
	}
	return &st, nil
}

func (s *Server) nbsDNS(ctx context.Context, host string) (NBStandbyDNS, *priv.DNSStatus) {
	out := NBStandbyDNS{Adopted: []priv.DNSAdopted{}}
	var st priv.DNSStatus
	if err := s.cfg.Priv.Call(ctx, priv.OpDNSStatus, nil, &st); err != nil {
		return out, nil
	}
	out.TokenSet, out.Base, out.Zone = st.Set, st.Base, st.Zone
	if st.Standby != nil {
		out.Name, out.Adopted = st.Standby.Name, st.Standby.Adopted
		b := st.Standby.Bound
		out.Bound = &b
	}
	if host != "" && st.Set {
		out.InBase = cfdns.Under(host, st.Base, false)
		out.InZone = cfdns.Under(host, st.Zone, false)
	}
	return out, &st
}

func (s *Server) handleNBStandby(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	if !s.nbsReady(w) {
		return
	}
	ctx := r.Context()
	svc := s.nbs()
	out := NBStandbyStatus{History: []nbstandby.SyncRow{}, StandbyVersion: nbstandby.StandbyVersion, PortForwards: nbPortForwards()}
	set, err := svc.Settings(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	out.Settings = set
	st, err := s.nbsRootStatus(ctx)
	if err != nil {
		out.Problem = "hardyd-priv didn't answer: " + err.Error()
	} else {
		out.Connection = st
		// The addresses DNS may point at are root's, not hardyd's.
		out.Settings.PublicIPv4, out.Settings.PublicIPv6 = st.PublicIPv4, st.PublicIPv6
		if st.From != nil {
			out.Settings.ConnectFrom = st.From
		}
		if len(st.Snapshots) > 0 {
			out.VersionNote, out.VersionNewer = nbstandby.VersionNote(st.Snapshots[0].Info.Version)
		}
	}
	out.Health = nbstandby.HealthOf(st, set, time.Now())
	if h, err := svc.History(ctx, 20); err == nil {
		out.History = h
	}
	out.Takeover, _ = svc.Takeover(ctx)
	host := ""
	if st != nil {
		host = st.Hostname
	}
	out.DNS, _ = s.nbsDNS(ctx, host)
	if st != nil && out.DNS.Bound != nil {
		cur := nbstandby.Binding{Host: st.Hostname, IPv4: st.PublicIPv4, IPv6: st.PublicIPv6,
			VPSHost: st.VPSHost, VPSPort: st.VPSPort, HostKeyFP: st.HostKeyFP}
		out.DNS.NeedsRebind = *out.DNS.Bound != cur
	}
	if o, err := s.appsStatus(ctx); err == nil {
		if a := findApp(o, ports.NetBirdStandbyApp); a != nil {
			out.App = NBStandbyApp{Installed: true, State: a.State, Version: a.Version}
		}
	}
	if _, nb, _ := remoteInputs(ctx, s.cfg.Priv, s.cfg.DB); nb != nil {
		out.ClientConnected, out.ClientIP, out.ManagementURL = nb.Connected, nb.IP, nb.ManagementURL
	}
	writeJSON(w, http.StatusOK, out)
}

// NBStandbySettingsRequest saves the connection (root) and the schedule and
// addresses (hardyd).
type NBStandbySettingsRequest struct {
	VPSHost  string             `json:"vpsHost"`
	VPSPort  int                `json:"vpsPort"`
	VPSUser  string             `json:"vpsUser"`
	HostKey  string             `json:"hostKey"`
	Hostname string             `json:"hostname"`
	NewKey   bool               `json:"newKey"`
	Settings nbstandby.Settings `json:"settings"`
	// AddressConfirm is the NetBird name, typed, when the public address
	// changes (root refuses the change otherwise).
	AddressConfirm string `json:"addressConfirm"`
}

func (s *Server) handleNBStandbySettings(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.nbsReady(w) {
		return
	}
	var req NBStandbySettingsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Hostname), "."))
	req.VPSHost = strings.ToLower(strings.TrimSpace(req.VPSHost))
	if !nbstandby.ValidHostname(req.Hostname) {
		writeError(w, http.StatusBadRequest, "invalid", "the NetBird server's name must be a host name like vpn.example.net")
		return
	}
	if !nbstandby.ValidVPSHost(req.VPSHost) {
		writeError(w, http.StatusBadRequest, "invalid", "the VPS address must be a host name or an IP address")
		return
	}
	if req.VPSUser != "" && !nbstandby.ValidVPSUser(req.VPSUser) {
		writeError(w, http.StatusBadRequest, "invalid", "the VPS user isn't a valid user name")
		return
	}
	if _, err := nbstandby.ParseHostKey(req.HostKey); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if err := req.Settings.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if req.VPSHost == req.Hostname {
		writeError(w, http.StatusBadRequest, "invalid", "the VPS's SSH address can't be the NetBird name itself (it points here during a take-over)")
		return
	}
	if st, err := s.nbsRootStatus(r.Context()); err == nil && (st.PublicIPv4 != req.Settings.PublicIPv4 || st.PublicIPv6 != req.Settings.PublicIPv6) &&
		strings.ToLower(strings.TrimSpace(req.AddressConfirm)) != req.Hostname {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the NetBird server's name to change this server's public address")
		return
	}
	target := req.Hostname + " vps=" + req.VPSHost
	if req.NewKey {
		target += " new key"
	}
	s.submit(w, r, u, JobKindNBStandbySettings, "Save the NetBird standby's settings", req, "netbird.standby.settings", target, nil)
}

// NBStandbyScript is the VPS script.
type NBStandbyScript struct {
	Script   string `json:"script"`
	FileName string `json:"fileName"`
	// Fingerprint of HardyOS's key, to compare with what the VPS script
	// prints and with 'hardyctl netbird-standby fingerprint' on the console.
	Fingerprint string `json:"fingerprint"`
}

func (s *Server) handleNBStandbyScript(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	if !s.nbsReady(w) {
		return
	}
	// Root makes the script from its own key, name and from= addresses.
	var sc nbstandby.ScriptResult
	if err := s.cfg.Priv.Call(r.Context(), priv.OpNBStandbyScript, nil, &sc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", privMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, NBStandbyScript{Script: sc.Script, FileName: "hardyos-standby.sh", Fingerprint: sc.Fingerprint})
}

func (s *Server) handleNBStandbyVPS(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	if !s.nbsReady(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	var vs nbstandby.VPSStatus
	if err := s.cfg.Priv.Call(ctx, priv.OpNBStandbyVPS, nil, &vs); err != nil {
		writeError(w, http.StatusBadGateway, "vps_unreachable", privMessage(err))
		return
	}
	writeJSON(w, http.StatusOK, vs)
}

func privMessage(err error) string {
	var pe *priv.Error
	if errors.As(err, &pe) {
		return pe.Message
	}
	return err.Error()
}

// NBStandbyInstallRequest installs the stopped standby app.
type NBStandbyInstallRequest struct {
	Pool string `json:"pool"`
}

func (s *Server) handleNBStandbyInstall(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.nbsReady(w) {
		return
	}
	var req NBStandbyInstallRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	st, err := s.nbsRootStatus(r.Context())
	if err != nil || st.Hostname == "" {
		writeError(w, http.StatusBadRequest, "invalid", "save the standby's settings first")
		return
	}
	if st.Mode == nbstandby.ModeTakenOver {
		writeError(w, http.StatusConflict, "taken_over", "HardyOS has taken over: hand back first")
		return
	}
	s.submit(w, r, u, JobKindNBStandbyInstall, "Install the NetBird standby (stopped)", req, "netbird.standby.install", st.Hostname, nil)
}

type nbsSyncParams struct {
	Auto bool `json:"auto,omitempty"`
}

func (s *Server) handleNBStandbySync(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.nbsReady(w) {
		return
	}
	st, err := s.nbsRootStatus(r.Context())
	if err != nil || !st.Configured {
		writeError(w, http.StatusBadRequest, "invalid", "set up the VPS connection first")
		return
	}
	if st.Mode == nbstandby.ModeTakenOver {
		writeError(w, http.StatusConflict, "taken_over", "HardyOS has taken over: there is nothing to sync until hand-back")
		return
	}
	s.submit(w, r, u, JobKindNBStandbySync, "Copy the VPS's NetBird server", nbsSyncParams{}, "netbird.standby.sync", st.Hostname, nil)
}

func (s *Server) handleNBStandbyDNSPreview(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	if !s.nbsReady(w) {
		return
	}
	name := cfdns.Normalize(r.URL.Query().Get("name"))
	if !cfdns.ValidDomain(name) {
		writeError(w, http.StatusBadRequest, "invalid", "give the NetBird server's name")
		return
	}
	var pv priv.DNSStandbyPreview
	if err := s.cfg.Priv.Call(r.Context(), priv.OpDNSStandbyPreview, priv.DNSStandbyNameArgs{Name: name}, &pv); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", privMessage(err))
		return
	}
	if pv.Records == nil {
		pv.Records = []priv.DNSAdopted{}
	}
	writeJSON(w, http.StatusOK, pv)
}

type nbsDNSParams struct {
	Action   string   `json:"action"` // adopt, forget
	Name     string   `json:"name"`
	Confirm  string   `json:"confirm"`
	IDs      []string `json:"ids,omitempty"`
	TokenRef string   `json:"tokenRef,omitempty"`
}

// NBStandbyDNSRequest adopts the name's records (confirm = the name, token
// = the Cloudflare token pasted again).
type NBStandbyDNSRequest struct {
	Name    string   `json:"name"`
	Confirm string   `json:"confirm"`
	IDs     []string `json:"ids"`
	Token   string   `json:"token"`
}

// NBStandbyDNSForgetRequest stops managing the name.
type NBStandbyDNSForgetRequest struct {
	Confirm string `json:"confirm"`
	Token   string `json:"token"`
}

func validTokenShape(tok string) bool {
	t := strings.TrimSpace(tok)
	return len(t) >= 20 && len(t) <= 200 && !strings.ContainsAny(t, " \r\n\t\"'")
}

func (s *Server) handleNBStandbyDNSAdopt(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.nbsReady(w) {
		return
	}
	var req NBStandbyDNSRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	name := cfdns.Normalize(req.Name)
	st, err := s.nbsRootStatus(r.Context())
	if err != nil || st.Hostname == "" || name != st.Hostname {
		writeError(w, http.StatusBadRequest, "invalid", "the name must be the NetBird server's name saved in the standby's settings")
		return
	}
	if cfdns.Normalize(req.Confirm) != name {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the name to let HardyOS change its records")
		return
	}
	if len(req.IDs) == 0 || len(req.IDs) > 8 {
		writeError(w, http.StatusBadRequest, "invalid", "choose the records you saw")
		return
	}
	for _, id := range req.IDs {
		if !cfdns.RecordIDOK(id) {
			writeError(w, http.StatusBadRequest, "invalid", "bad record id")
			return
		}
	}
	if !validTokenShape(req.Token) {
		writeError(w, http.StatusBadRequest, "token_required", "paste the Cloudflare token again (the one saved in Control Panel › Hostnames)")
		return
	}
	s.submit(w, r, u, JobKindNBStandbyDNS, "Let HardyOS manage "+name+" in Cloudflare",
		nbsDNSParams{Action: "adopt", Name: name, Confirm: name, IDs: req.IDs, TokenRef: jobSecrets.put(strings.TrimSpace(req.Token))},
		"netbird.standby.dns.adopt", name, nil)
}

// NBStandbyConfirm carries a typed confirmation.
type NBStandbyConfirm struct {
	Confirm string `json:"confirm"`
}

func (s *Server) handleNBStandbyDNSForget(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.nbsReady(w) {
		return
	}
	var req NBStandbyDNSForgetRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if st, err := s.nbsRootStatus(r.Context()); err == nil && st.Mode == nbstandby.ModeTakenOver {
		writeError(w, http.StatusConflict, "taken_over", "HardyOS has taken over: hand back first")
		return
	}
	d, _ := s.nbsDNS(r.Context(), "")
	if d.Name == "" || cfdns.Normalize(req.Confirm) != d.Name {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the name to stop HardyOS managing it")
		return
	}
	if !validTokenShape(req.Token) {
		writeError(w, http.StatusBadRequest, "token_required", "paste the Cloudflare token again (the one saved in Control Panel › Hostnames)")
		return
	}
	s.submit(w, r, u, JobKindNBStandbyDNS, "Stop managing "+d.Name+" in Cloudflare",
		nbsDNSParams{Action: "forget", Name: d.Name, Confirm: d.Name, TokenRef: jobSecrets.put(strings.TrimSpace(req.Token))},
		"netbird.standby.dns.forget", d.Name, nil)
}

// NBStandbyDNSRebindRequest confirms the standby's current addresses and
// VPS for the adopted name with the Cloudflare token pasted again.
type NBStandbyDNSRebindRequest struct {
	Token string `json:"token"`
}

func (s *Server) handleNBStandbyDNSRebind(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.nbsReady(w) {
		return
	}
	var req NBStandbyDNSRebindRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if st, err := s.nbsRootStatus(r.Context()); err == nil && st.Mode == nbstandby.ModeTakenOver {
		writeError(w, http.StatusConflict, "taken_over", "HardyOS has taken over: hand back first")
		return
	}
	d, _ := s.nbsDNS(r.Context(), "")
	if d.Name == "" {
		writeError(w, http.StatusBadRequest, "no_name", "HardyOS doesn't manage a standby name")
		return
	}
	if !validTokenShape(req.Token) {
		writeError(w, http.StatusBadRequest, "token_required", "paste the Cloudflare token again (the one saved in Control Panel › Hostnames)")
		return
	}
	s.submit(w, r, u, JobKindNBStandbyDNS, "Confirm the standby's address and VPS for "+d.Name,
		nbsDNSParams{Action: "rebind", Name: d.Name, TokenRef: jobSecrets.put(strings.TrimSpace(req.Token))},
		"netbird.standby.dns.rebind", d.Name, nil)
}

func (s *Server) handleNBStandbyTakeover(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.nbsReady(w) {
		return
	}
	var req nbstandby.TakeOverArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	st, err := s.nbsRootStatus(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "hardyd-priv didn't answer")
		return
	}
	svc := s.nbs()
	set, err := svc.Settings(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	d, _ := s.nbsDNS(ctx, st.Hostname)
	hasAAAA := false
	for _, a := range d.Adopted {
		hasAAAA = hasAAAA || a.Type == "AAAA"
	}
	if err := svc.CheckTakeOver(st, set, d.Name, hasAAAA, req); err != nil {
		code := "invalid"
		switch {
		case errors.Is(err, nbstandby.ErrVersion):
			code = "version_newer"
		case st.Hostname != "" && strings.ToLower(strings.TrimSpace(req.Confirm)) != st.Hostname:
			code = "confirm_required"
		}
		writeError(w, http.StatusBadRequest, code, err.Error())
		return
	}
	if o, err := s.appsStatus(ctx); err != nil || findApp(o, ports.NetBirdStandbyApp) == nil {
		writeError(w, http.StatusBadRequest, "invalid", "install the standby first")
		return
	}
	req.Confirm, req.By = st.Hostname, u.Username
	detail := "accept version"
	if !req.AcceptVersion {
		detail = ""
	}
	s.submit(w, r, u, JobKindNBStandbyTakeover, "Take over "+st.Hostname, nbsTakeoverParams{Args: req, By: u.Username}, "netbird.standby.takeover", st.Hostname+" "+detail, nil)
}

type nbsTakeoverParams struct {
	Args nbstandby.TakeOverArgs `json:"args"`
	By   string                 `json:"by"`
}

func (s *Server) handleNBStandbyHandback(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.nbsReady(w) {
		return
	}
	var req nbstandby.HandBackArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	st, err := s.nbsRootStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "hardyd-priv didn't answer")
		return
	}
	if st.Mode != nbstandby.ModeTakenOver {
		writeError(w, http.StatusConflict, "not_taken_over", "HardyOS hasn't taken over")
		return
	}
	if strings.ToLower(strings.TrimSpace(req.Confirm)) != st.Hostname || !req.AcceptSplitBrain {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the NetBird server's name and confirm that the standby's state replaces the VPS's")
		return
	}
	req.Confirm = st.Hostname
	what := "hand back"
	if req.Discard {
		what = "discard the standby's changes and hand back"
	}
	s.submit(w, r, u, JobKindNBStandbyHandback, "Hand "+st.Hostname+" back to the VPS", req, "netbird.standby.handback", st.Hostname+" "+what, nil)
}

func (s *Server) handleNBStandbyForget(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.nbsReady(w) {
		return
	}
	var req NBStandbyConfirm
	if !decodeJSON(w, r, &req) {
		return
	}
	st, err := s.nbsRootStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "hardyd-priv didn't answer")
		return
	}
	if st.Mode == nbstandby.ModeTakenOver {
		writeError(w, http.StatusConflict, "taken_over", "HardyOS has taken over: hand back first")
		return
	}
	if st.Hostname != "" && strings.ToLower(strings.TrimSpace(req.Confirm)) != st.Hostname {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the NetBird server's name to forget the standby")
		return
	}
	s.submit(w, r, u, JobKindNBStandbyForget, "Forget the NetBird standby", NBStandbyConfirm{Confirm: st.Hostname}, "netbird.standby.forget", st.Hostname, nil)
}

// ---- jobs ------------------------------------------------------------------------

func (s *Server) registerNBStandbyJobs(m *jobs.Manager) {
	l := func(json.RawMessage) string { return "netbird-standby" }
	m.Register(jobs.Kind{Name: JobKindNBStandbySettings, AdminOnly: true, LockKey: l, Run: s.runNBStandbySettings})
	m.Register(jobs.Kind{Name: JobKindNBStandbyInstall, AdminOnly: true, LockKey: func(json.RawMessage) string { return "app:" + ports.NetBirdStandbyApp }, Run: s.runNBStandbyInstall})
	m.Register(jobs.Kind{Name: JobKindNBStandbySync, AdminOnly: true, LockKey: l, Run: s.runNBStandbySync})
	m.Register(jobs.Kind{Name: JobKindNBStandbyDNS, AdminOnly: true, LockKey: l, Run: s.runNBStandbyDNS})
	m.Register(jobs.Kind{Name: JobKindNBStandbyTakeover, AdminOnly: true, LockKey: l, Run: s.runNBStandbyTakeover})
	m.Register(jobs.Kind{Name: JobKindNBStandbyHandback, AdminOnly: true, LockKey: l, Run: s.runNBStandbyHandback})
	m.Register(jobs.Kind{Name: JobKindNBStandbyForget, AdminOnly: true, LockKey: l, Run: s.runNBStandbyForget})
}

func (s *Server) runNBStandbySettings(jc *jobs.Context) (any, error) {
	var req NBStandbySettingsRequest
	if err := jc.Params(&req); err != nil {
		return nil, err
	}
	jc.Progress(20, "Saving the VPS connection")
	var st nbstandby.Status
	if err := s.cfg.Priv.Call(jc, priv.OpNBStandbyConfigure, nbstandby.ConfigureArgs{VPSHost: req.VPSHost, VPSPort: req.VPSPort, VPSUser: req.VPSUser,
		HostKey: req.HostKey, Hostname: req.Hostname, From: req.Settings.ConnectFrom, NewKey: req.NewKey}, &st); err != nil {
		return nil, err
	}
	if st.PublicIPv4 != req.Settings.PublicIPv4 || st.PublicIPv6 != req.Settings.PublicIPv6 {
		jc.Progress(60, "Saving this server's public address")
		if err := s.cfg.Priv.Call(jc, priv.OpNBStandbyAddress, nbstandby.AddressArgs{IPv4: req.Settings.PublicIPv4, IPv6: req.Settings.PublicIPv6,
			Confirm: req.AddressConfirm}, &st); err != nil {
			return nil, err
		}
	}
	if _, err := s.nbs().SaveSettings(jc, req.Settings); err != nil {
		return nil, err
	}
	// The installed app learns a new hostname (its dashboard's addresses).
	if o, err := s.appsStatus(jc); err == nil && findApp(o, ports.NetBirdStandbyApp) != nil {
		var prep apps.PrepareResult
		if err := s.cfg.Priv.Call(jc, priv.OpAppsReconfigure, apps.ReconfigureArgs{ID: ports.NetBirdStandbyApp,
			Settings: map[string]string{"NB_DOMAIN": st.Hostname}}, &prep); err != nil {
			return st, fmt.Errorf("saved, but the standby app didn't take the new name: %w", err)
		}
	}
	return st, nil
}

func (s *Server) runNBStandbyInstall(jc *jobs.Context) (any, error) {
	var req NBStandbyInstallRequest
	if err := jc.Params(&req); err != nil {
		return nil, err
	}
	pc := s.cfg.Priv
	st, err := s.nbsRootStatus(jc)
	if err != nil {
		return nil, err
	}
	if st.Hostname == "" {
		return nil, errors.New("save the standby's settings first")
	}
	settings := map[string]string{"NB_DOMAIN": st.Hostname}
	o, err := s.appsStatus(jc)
	if err != nil {
		return nil, err
	}
	var notes []string
	if findApp(o, ports.NetBirdStandbyApp) == nil {
		ref := AppPackageRef{Source: appstore.SourceCatalog, Ref: ports.NetBirdStandbyApp}
		plan, err := s.appPlan(jc, ref)
		if err != nil {
			return nil, fmt.Errorf("the NetBird standby isn't in this server's catalog: %w", err)
		}
		if plan.EnginePool == "" && req.Pool == "" {
			return nil, errors.New("choose the pool apps go on (no app is installed yet)")
		}
		pkg, err := s.appStore().LoadFrom(jc, appstore.SourceCatalog, ports.NetBirdStandbyApp, 0)
		if err != nil {
			return nil, err
		}
		jc.Progress(5, "Setting up the standby (it stays stopped)")
		ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
		var prep apps.PrepareResult
		err = pc.Call(ctx, priv.OpAppsPrepare, apps.PrepareArgs{Package: pkg.Raw, Pool: req.Pool, Ports: map[string]int{
			"HTTP": ports.NetBirdStandbyHTTP, "HTTPS": ports.NetBirdStandbyHTTPS, "STUN": ports.NetBirdStandbySTUN},
			Settings: settings, Source: apps.SourceCatalog}, &prep)
		cancel()
		if err != nil {
			return nil, err
		}
		notes = append(notes, prep.Warnings...)
		pulled, err := pullImages(jc, pc, ports.NetBirdStandbyApp, prep.Services, 10, 90)
		notes = append(notes, pulled...)
		if err != nil {
			return nil, err
		}
		_ = s.appStore().SetOrigin(context.WithoutCancel(jc), appstore.Origin{AppID: ports.NetBirdStandbyApp, Source: appstore.SourceCatalog, Ref: ports.NetBirdStandbyApp})
	} else {
		jc.Progress(10, "Updating the standby's settings")
		var prep apps.PrepareResult
		if err := pc.Call(jc, priv.OpAppsReconfigure, apps.ReconfigureArgs{ID: ports.NetBirdStandbyApp, Settings: settings}, &prep); err != nil {
			return nil, err
		}
		notes = append(notes, prep.Warnings...)
	}
	// Closed until a take-over (the firewall table follows the app).
	if err := pc.Call(jc, priv.OpNBStandbyRefresh, nil, nil); err != nil {
		return nil, err
	}
	jc.Progress(100, "The standby is installed and stopped")
	if notes == nil {
		notes = []string{}
	}
	return map[string]any{"installed": true, "notes": notes}, nil
}

func (s *Server) runNBStandbySync(jc *jobs.Context) (any, error) {
	var p nbsSyncParams
	_ = jc.Params(&p)
	started := time.Now().UTC()
	jc.Progress(10, "Copying the VPS's NetBird server")
	var rec nbstandby.SnapshotRecord
	err := s.cfg.Priv.Call(jc, priv.OpNBStandbySync, nil, &rec)
	row := nbstandby.SyncRow{StartedAt: started, FinishedAt: time.Now().UTC(), OK: err == nil, Auto: p.Auto}
	if err != nil {
		row.Error = privMessage(err)
	} else {
		row.Bytes, row.SHA256, row.Version, row.Peers = rec.Info.Bytes, rec.Info.SHA256, rec.Info.Version, rec.Info.Peers
	}
	svc := s.nbs()
	_ = svc.RecordSync(context.WithoutCancel(jc), row)
	if st, e := s.nbsRootStatus(context.WithoutCancel(jc)); e == nil {
		set, _ := svc.Settings(context.WithoutCancel(jc))
		svc.CheckAlerts(context.WithoutCancel(jc), st, set)
	}
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *Server) runNBStandbyDNS(jc *jobs.Context) (any, error) {
	var p nbsDNSParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	tok, ok := jobSecrets.take(p.TokenRef)
	if !ok {
		return nil, errors.New("the token was lost (hardyd restarted?): paste it again")
	}
	var st priv.DNSStatus
	switch p.Action {
	case "adopt":
		if err := s.cfg.Priv.Call(jc, priv.OpDNSStandbyAdopt, priv.DNSStandbyAdoptArgs{Name: p.Name, Confirm: p.Confirm, IDs: p.IDs, Token: tok}, &st); err != nil {
			return nil, err
		}
	case "forget":
		if err := s.cfg.Priv.Call(jc, priv.OpDNSStandbyForget, priv.DNSStandbyForgetArgs{Confirm: p.Confirm, Token: tok}, &st); err != nil {
			return nil, err
		}
	case "rebind":
		if err := s.cfg.Priv.Call(jc, priv.OpDNSStandbyRebind, priv.DNSStandbyRebindArgs{Token: tok}, &st); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unknown action")
	}
	return st.Standby, nil
}

func (s *Server) runNBStandbyTakeover(jc *jobs.Context) (any, error) {
	var p nbsTakeoverParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	p.Args.By = p.By
	rec, err := s.nbs().TakeOver(jc, &privStandby{s: s}, p.Args, jc.Progress)
	if err != nil {
		return nil, err
	}
	s.recordSystem(context.WithoutCancel(jc), "netbird.standby.takenover", p.Args.Confirm,
		fmt.Sprintf("dns=%v peers %d/%d final sync=%v", rec.DNSChanged, rec.PeersConnected, rec.PeersTotal, rec.FinalSync))
	return rec, nil
}

func (s *Server) runNBStandbyHandback(jc *jobs.Context) (any, error) {
	var p nbstandby.HandBackArgs
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	res, err := s.nbs().HandBack(jc, &privStandby{s: s}, p, jc.Progress)
	if err != nil {
		return nil, err
	}
	s.recordSystem(context.WithoutCancel(jc), "netbird.standby.handedback", p.Confirm, fmt.Sprintf("bytes=%d discard=%v", res.Bytes, p.Discard))
	return res, nil
}

func (s *Server) runNBStandbyForget(jc *jobs.Context) (any, error) {
	var p NBStandbyConfirm
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	var st nbstandby.Status
	if err := s.cfg.Priv.Call(jc, priv.OpNBStandbyForget, nbstandby.ConfirmArgs{Confirm: p.Confirm}, &st); err != nil {
		return nil, err
	}
	return st, nil
}

// privStandby is the take-over's Backend over hardyd-priv.
type privStandby struct{ s *Server }

func (b *privStandby) call(ctx context.Context, op string, args, out any) error {
	return b.s.cfg.Priv.Call(ctx, op, args, out)
}

func (b *privStandby) Status(ctx context.Context) (*nbstandby.Status, error) {
	return b.s.nbsRootStatus(ctx)
}

func (b *privStandby) Sync(ctx context.Context) (*nbstandby.SnapshotRecord, error) {
	started := time.Now().UTC()
	var rec nbstandby.SnapshotRecord
	err := b.call(ctx, priv.OpNBStandbySync, nil, &rec)
	row := nbstandby.SyncRow{StartedAt: started, FinishedAt: time.Now().UTC(), OK: err == nil}
	if err != nil {
		row.Error = privMessage(err)
	} else {
		row.Bytes, row.SHA256, row.Version, row.Peers = rec.Info.Bytes, rec.Info.SHA256, rec.Info.Version, rec.Info.Peers
	}
	_ = b.s.nbs().RecordSync(context.WithoutCancel(ctx), row)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

func (b *privStandby) VPS(ctx context.Context) (*nbstandby.VPSStatus, error) {
	var vs nbstandby.VPSStatus
	return &vs, b.call(ctx, priv.OpNBStandbyVPS, nil, &vs)
}

func (b *privStandby) Fence(ctx context.Context, on bool) error {
	op := priv.OpNBStandbyFence
	if !on {
		op = priv.OpNBStandbyUnfence
	}
	return b.call(ctx, op, nil, nil)
}

func (b *privStandby) Stage(ctx context.Context, confirm string) (*nbstandby.StageResult, error) {
	var res nbstandby.StageResult
	return &res, b.call(ctx, priv.OpNBStandbyStage, nbstandby.ConfirmArgs{Confirm: confirm}, &res)
}

func (b *privStandby) Unstage(ctx context.Context, confirm string) error {
	return b.call(ctx, priv.OpNBStandbyUnstage, nbstandby.ConfirmArgs{Confirm: confirm}, nil)
}

func (b *privStandby) Network(ctx context.Context, open bool) error {
	return b.call(ctx, priv.OpNBStandbyNetwork, nbstandby.NetworkArgs{Open: open}, nil)
}

func (b *privStandby) Handback(ctx context.Context, confirm string) (*nbstandby.HandbackResult, error) {
	var res nbstandby.HandbackResult
	return &res, b.call(ctx, priv.OpNBStandbyHandback, nbstandby.ConfirmArgs{Confirm: confirm}, &res)
}

func (b *privStandby) AppUp(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	return b.call(ctx, priv.OpAppsUp, priv.AppRef{ID: ports.NetBirdStandbyApp}, nil)
}

func (b *privStandby) AppStop(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	return b.call(ctx, priv.OpAppsStop, priv.AppRef{ID: ports.NetBirdStandbyApp}, nil)
}

func (b *privStandby) DNSStandby(ctx context.Context) (string, bool, error) {
	var st priv.DNSStatus
	if err := b.call(ctx, priv.OpDNSStatus, nil, &st); err != nil {
		return "", false, err
	}
	if st.Standby == nil {
		return "", false, nil
	}
	aaaa := false
	for _, a := range st.Standby.Adopted {
		aaaa = aaaa || a.Type == "AAAA"
	}
	return st.Standby.Name, aaaa, nil
}

func (b *privStandby) DNSSet(ctx context.Context, typ, content string) error {
	name, _, err := b.DNSStandby(ctx)
	if err != nil {
		return err
	}
	if name == "" {
		return errors.New("HardyOS doesn't manage the NetBird server's name")
	}
	return b.call(ctx, priv.OpDNSRecordSet, priv.DNSRecordSetArgs{Name: name, Type: typ, Content: content, TTL: 60}, nil)
}

func (b *privStandby) DNSRestore(ctx context.Context) error {
	return b.call(ctx, priv.OpDNSStandbyRestore, struct{}{}, nil)
}

// Peers counts peers through NetBird's API with Remote Access's token; while
// taken over, the hostname leads to the local standby (decision 426).
func (b *privStandby) Peers(ctx context.Context) (int, int, error) {
	pub := b.s.cfg.Remote
	if pub == nil || pub.Store == nil {
		return 0, 0, nbstandby.ErrNoPeerCheck
	}
	set, err := pub.Store.Load(ctx)
	if err != nil {
		return 0, 0, err
	}
	if tok, err := pub.Store.Token(ctx); err != nil || tok == "" {
		return 0, 0, nbstandby.ErrNoPeerCheck
	}
	in, _, _ := remoteInputs(ctx, b.s.cfg.Priv, b.s.cfg.DB)
	api, err := pub.API(ctx, set, in)
	if err != nil {
		return 0, 0, err
	}
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	peers, err := api.Peers(pctx, "")
	if err != nil {
		return 0, 0, err
	}
	conn := 0
	for _, p := range peers {
		if p.Connected {
			conn++
		}
	}
	return len(peers), conn, nil
}

// RunNetBirdStandby keeps the standby in sync: every minute it checks
// whether a sync is due (and starts one), and raises or clears alerts.
func (s *Server) RunNetBirdStandby(ctx context.Context) {
	if s.cfg.Priv == nil || s.cfg.DB == nil || s.cfg.Jobs == nil {
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		s.nbsTick(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) nbsTick(ctx context.Context, now time.Time) {
	st, err := s.nbsRootStatus(ctx)
	if err != nil || !st.Configured {
		return
	}
	svc := s.nbs()
	set, err := svc.Settings(ctx)
	if err != nil {
		return
	}
	svc.CheckAlerts(ctx, st, set)
	if !nbstandby.Due(st, set, now) {
		return
	}
	nbsLoop.mu.Lock()
	defer nbsLoop.mu.Unlock()
	if now.Sub(nbsLoop.submitted) < time.Duration(set.IntervalMinutes)*time.Minute {
		return
	}
	if _, err := s.cfg.Jobs.Submit(ctx, JobKindNBStandbySync, "Copy the VPS's NetBird server", nbsSyncParams{Auto: true}, nil); err != nil {
		s.log.Warn("netbird standby: sync", "err", err)
		return
	}
	nbsLoop.submitted = now
}
