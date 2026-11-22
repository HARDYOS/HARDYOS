package api

// Control Panel › Hostnames (decisions 450-459): the Cloudflare token
// (root's: set, verified and cleared through hardyd-priv, never shown), the
// wildcard certificate, and the LAN records.

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cfdns"
	"github.com/hardyos/hardyos/daemon/internal/domain"
	"github.com/hardyos/hardyos/daemon/internal/hostnames"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/nbstandby"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/publish"
)

// Hostnames job kinds.
const (
	JobKindHostnamesDNS      = "hostnames.dns"
	JobKindHostnamesSettings = "hostnames.settings"
	JobKindHostnamesIssue    = "hostnames.issue"
	JobKindHostnamesLAN      = "hostnames.lan"
)

// HostnamesStatus is Control Panel › Hostnames.
type HostnamesStatus struct {
	// Active: apps are served at their hostnames now.
	Active   bool                `json:"active"`
	Problem  string              `json:"problem,omitempty"`
	Settings hostnames.Settings  `json:"settings"`
	Token    HostnamesTokenState `json:"token"`
	// RemoteBase is Remote Access's base domain ("" when none): the
	// hostnames must use the same one.
	RemoteBase  string            `json:"remoteBase"`
	DesktopURL  string            `json:"desktopUrl"`
	Certificate *HostnamesCert    `json:"certificate"`
	LastError   *hostnames.Cert   `json:"lastError"`
	Names       []HostnameEntry   `json:"names"`
	LAN         HostnamesLANState `json:"lan"`
}

// HostnamesTokenState says whether root holds a token: never the token.
type HostnamesTokenState struct {
	Set        bool       `json:"set"`
	Base       string     `json:"base"`
	Zone       string     `json:"zone"`
	VerifiedAt *time.Time `json:"verifiedAt"`
	Problem    string     `json:"problem,omitempty"`
	// Apex: the base is its Cloudflare zone's apex (the DC can only hold
	// the names when that's the AD domain or inside it).
	Apex bool `json:"apex"`
}

// HostnamesCert is the certificate in service.
type HostnamesCert struct {
	Names       []string  `json:"names"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	Fingerprint string    `json:"fingerprint"`
	RenewsAt    time.Time `json:"renewsAt"`
}

// HostnameEntry is one name and what it serves.
type HostnameEntry struct {
	Label string `json:"label"`
	Host  string `json:"host"`
	What  string `json:"what"`
}

// HostnamesLANState is how devices at home find the names.
type HostnamesLANState struct {
	Addresses []string `json:"addresses"`
	NetBirdIP string   `json:"netbirdIp"`
	// DomainDNS: HardyOS's own domain controller runs and can hold them.
	DomainDNS bool   `json:"domainDns"`
	Domain    string `json:"domain"`
}

func (s *Server) hostnamesRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/hostnames", s.admin(s.handleHostnames))
	m.Handle("GET /api/v1/hostnames/desktop", s.authed(s.handleHostnamesDesktop))
	m.Handle("PUT /api/v1/hostnames/token", s.admin(s.handleHostnamesToken))
	m.Handle("POST /api/v1/hostnames/token/verify", s.admin(s.handleHostnamesVerify))
	m.Handle("DELETE /api/v1/hostnames/token", s.admin(s.handleHostnamesClear))
	m.Handle("PUT /api/v1/hostnames/settings", s.admin(s.handleHostnamesSettings))
	m.Handle("POST /api/v1/hostnames/certificate", s.admin(s.handleHostnamesIssue))
	m.Handle("POST /api/v1/hostnames/lan", s.admin(s.handleHostnamesLAN))
	if s.cfg.Jobs != nil {
		s.registerHostnamesJobs(s.cfg.Jobs)
	}
}

func (s *Server) hostnamesReady(w http.ResponseWriter) (*hostnames.Manager, bool) {
	m := s.cfg.Hostnames
	if m == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "hostnames aren't available on this server")
		return nil, false
	}
	return m, true
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (s *Server) handleHostnames(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	m, ok := s.hostnamesReady(w)
	if !ok {
		return
	}
	ctx := r.Context()
	s.hosts.refresh(ctx)
	set, err := m.Store.Load(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	out := HostnamesStatus{Settings: set, Names: []HostnameEntry{}, LAN: HostnamesLANState{Addresses: lanAddresses()}}
	out.RemoteBase, _ = s.cfg.DB.GetSetting(ctx, publish.SettingBaseDomain)
	if st, err := m.DNS.Status(ctx); err != nil {
		out.Token.Problem = "hardyd-priv didn't answer: " + err.Error()
	} else {
		out.Token = HostnamesTokenState{Set: st.Set, Base: st.Base, Zone: st.Zone, VerifiedAt: timePtr(st.VerifiedAt), Problem: st.Problem,
			Apex: st.Set && st.Base == st.Zone}
	}
	if _, leaf := m.Certs.Wildcard(); leaf != nil {
		out.Certificate = &HostnamesCert{Names: leaf.DNSNames, Issuer: leaf.Issuer.CommonName, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter,
			Fingerprint: hostnames.Fingerprint(leaf), RenewsAt: leaf.NotAfter.Add(-hostnames.RenewBefore)}
	}
	if _, failed, err := m.Store.Last(ctx); err == nil {
		out.LastError = failed
	}
	active, base, desk := s.hosts.snapshot()
	out.Active = active
	s.hosts.mu.Lock()
	out.Problem = s.hosts.problem
	s.hosts.mu.Unlock()
	if base == "" {
		base = out.Token.Base
	}
	if base != "" {
		out.DesktopURL = "https://" + desk + "." + base
		for _, l := range s.hosts.lanLabels(ctx) {
			out.Names = append(out.Names, HostnameEntry{Label: l, Host: l + "." + base, What: s.hostnameWhat(l, desk)})
		}
		sort.Slice(out.Names, func(i, j int) bool { return out.Names[i].Label < out.Names[j].Label })
	}
	if s.cfg.Priv != nil {
		if _, nb, _ := remoteInputs(ctx, s.cfg.Priv, s.cfg.DB); nb != nil && nb.Connected {
			out.LAN.NetBirdIP = nb.IP
		}
	}
	var dst domain.Status
	if s.cfg.Priv != nil && s.cfg.Priv.Call(ctx, priv.OpDomainStatus, nil, &dst) == nil && dst.Config != nil && dst.Running {
		out.LAN.DomainDNS, out.LAN.Domain = true, dst.Config.Domain
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) hostnameWhat(label, desk string) string {
	switch label {
	case desk:
		return "Desktop"
	case hostnames.SSOLabel:
		return "HardyOS sign-in"
	case hostnames.FilesLabel:
		return "Share links"
	case hostnames.OfficeLabel:
		return "Office editor"
	case hostnames.PhotosLabel:
		return "Photos"
	case hostnames.MailLabel:
		return "Webmail, mail and calendar settings"
	}
	if a, ok := s.hosts.app(label); ok {
		return a.Name
	}
	return label
}

// lanAddresses are this server's IPv4 addresses on its own networks (not
// Docker's, VMs' private network, NetBird's or the DC's shim).
func lanAddresses() []string {
	out := []string{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifs {
		n := i.Name
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		skip := false
		for _, p := range []string{"docker", "br-", "veth", "virbr", "wt", "hdc", "vnet", "tap", "tun"} {
			skip = skip || strings.HasPrefix(n, p)
		}
		if skip {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
					ip = ip.Unmap()
					if ip.Is4() && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
						out = append(out, ip.String())
					}
				}
			}
		}
	}
	return out
}

// HostnamesDesktop is where the desktop is at its hostname ("" while off).
type HostnamesDesktop struct {
	URL string `json:"url"`
}

func (s *Server) handleHostnamesDesktop(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	u := ""
	if d := s.hosts.desktopHost(); d != "" {
		u = "https://" + d
	}
	writeJSON(w, http.StatusOK, HostnamesDesktop{URL: u})
}

// HostnamesTokenRequest hands the Cloudflare token to root.
type HostnamesTokenRequest struct {
	Token string `json:"token"`
	Base  string `json:"base"`
}

type hostDNSParams struct {
	Action   string `json:"action"` // set, verify, clear
	Base     string `json:"base,omitempty"`
	TokenRef string `json:"tokenRef,omitempty"`
	Confirm  string `json:"confirm,omitempty"`
}

func (s *Server) handleHostnamesToken(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if _, ok := s.hostnamesReady(w); !ok {
		return
	}
	var req HostnamesTokenRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	tok := strings.TrimSpace(req.Token)
	base := cfdns.Normalize(req.Base)
	if len(tok) < 20 || len(tok) > 200 || strings.ContainsAny(tok, " \r\n\t\"'") {
		writeError(w, http.StatusBadRequest, "invalid", "that doesn't look like a Cloudflare API token")
		return
	}
	if !cfdns.ValidDomain(base) {
		writeError(w, http.StatusBadRequest, "invalid", "the base domain must be a domain like home.example.net")
		return
	}
	if rb, _ := s.cfg.DB.GetSetting(r.Context(), publish.SettingBaseDomain); rb != "" && rb != base {
		writeError(w, http.StatusBadRequest, "invalid", "use Remote Access's base domain ("+rb+"): names must be the same at home and over NetBird")
		return
	}
	p := hostDNSParams{Action: "set", Base: base, TokenRef: jobSecrets.put(tok)}
	s.submit(w, r, u, JobKindHostnamesDNS, "Save the Cloudflare token", p, "hostnames.token", base, nil)
}

func (s *Server) handleHostnamesVerify(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if _, ok := s.hostnamesReady(w); !ok {
		return
	}
	s.submit(w, r, u, JobKindHostnamesDNS, "Check the Cloudflare token", hostDNSParams{Action: "verify"}, "hostnames.token.verify", "", nil)
}

// HostnamesClearRequest forgets the token; Confirm is the base domain.
type HostnamesClearRequest struct {
	Confirm string `json:"confirm"`
}

func (s *Server) handleHostnamesClear(w http.ResponseWriter, r *http.Request, u *auth.User) {
	m, ok := s.hostnamesReady(w)
	if !ok {
		return
	}
	var req HostnamesClearRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	st, err := m.DNS.Status(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "hardyd-priv didn't answer")
		return
	}
	if !st.Set || cfdns.Normalize(req.Confirm) != st.Base {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the base domain to forget the token")
		return
	}
	if nst, err := s.nbsRootStatus(r.Context()); err == nil && nst.Mode == nbstandby.ModeTakenOver {
		// Hand-back needs the token to put the NetBird name back.
		writeError(w, http.StatusConflict, "taken_over", "the NetBird standby has taken over: hand back before forgetting the token")
		return
	}
	s.submit(w, r, u, JobKindHostnamesDNS, "Forget the Cloudflare token", hostDNSParams{Action: "clear", Confirm: st.Base}, "hostnames.token.clear", st.Base, nil)
}

func (s *Server) handleHostnamesSettings(w http.ResponseWriter, r *http.Request, u *auth.User) {
	m, ok := s.hostnamesReady(w)
	if !ok {
		return
	}
	var req hostnames.Settings
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if err := req.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if req.Enabled {
		if st, err := m.DNS.Status(r.Context()); err != nil || !st.Set {
			writeError(w, http.StatusBadRequest, "invalid", "save a Cloudflare token first")
			return
		}
	}
	s.submit(w, r, u, JobKindHostnamesSettings, "Save the hostnames settings", req, "hostnames.settings",
		"enabled="+boolWord(req.Enabled)+" staging="+boolWord(req.Staging), nil)
}

type hostIssueParams struct {
	Auto bool `json:"auto,omitempty"`
}

func (s *Server) handleHostnamesIssue(w http.ResponseWriter, r *http.Request, u *auth.User) {
	m, ok := s.hostnamesReady(w)
	if !ok {
		return
	}
	if st, err := m.DNS.Status(r.Context()); err != nil || !st.Set {
		writeError(w, http.StatusBadRequest, "invalid", "save a Cloudflare token first")
		return
	}
	s.submit(w, r, u, JobKindHostnamesIssue, "Get the hostnames' certificate", hostIssueParams{}, "hostnames.certificate", "", nil)
}

// HostnamesLANRequest adds (or removes) the names in this server's own
// domain controller's DNS.
type HostnamesLANRequest struct {
	Remove  bool   `json:"remove"`
	Address string `json:"address"`
}

func (s *Server) handleHostnamesLAN(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if _, ok := s.hostnamesReady(w); !ok {
		return
	}
	var req HostnamesLANRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !req.Remove {
		found := false
		for _, a := range lanAddresses() {
			found = found || a == req.Address
		}
		if !found {
			writeError(w, http.StatusBadRequest, "invalid", "choose one of this server's addresses")
			return
		}
	}
	what := "add"
	if req.Remove {
		what = "remove"
	}
	s.submit(w, r, u, JobKindHostnamesLAN, "Update the hostnames in the domain's DNS", req, "hostnames.lan", what+" "+req.Address, nil)
}

func (s *Server) registerHostnamesJobs(m *jobs.Manager) {
	l := func(json.RawMessage) string { return "hostnames" }
	m.Register(jobs.Kind{Name: JobKindHostnamesDNS, AdminOnly: true, LockKey: l, Run: s.runHostnamesDNS})
	m.Register(jobs.Kind{Name: JobKindHostnamesSettings, AdminOnly: true, LockKey: l, Run: s.runHostnamesSettings})
	m.Register(jobs.Kind{Name: JobKindHostnamesIssue, AdminOnly: true, LockKey: l, Run: s.runHostnamesIssue})
	m.Register(jobs.Kind{Name: JobKindHostnamesLAN, AdminOnly: true, LockKey: l, Run: s.runHostnamesLAN})
}

func (s *Server) runHostnamesDNS(jc *jobs.Context) (any, error) {
	m := s.cfg.Hostnames
	if m == nil {
		return nil, errors.New("hostnames aren't available")
	}
	var p hostDNSParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	var st priv.DNSStatus
	switch p.Action {
	case "set":
		tok, ok := jobSecrets.take(p.TokenRef)
		if !ok {
			return nil, errors.New("the token was lost (hardyd restarted?): paste it again")
		}
		jc.Progress(30, "Checking the token with Cloudflare")
		if err := s.cfg.Priv.Call(jc, priv.OpDNSTokenSet, priv.DNSTokenSetArgs{Token: tok, Base: p.Base}, &st); err != nil {
			return nil, err
		}
		if b, _ := m.Certs.Wildcard(); b != "" && b != st.Base {
			m.Remove() // a certificate for another base
		}
	case "verify":
		if err := s.cfg.Priv.Call(jc, priv.OpDNSTokenVerify, struct{}{}, &st); err != nil {
			return nil, err
		}
		if st.Problem != "" {
			return nil, errors.New(st.Problem)
		}
	case "clear":
		if err := s.cfg.Priv.Call(jc, priv.OpDNSTokenClear, priv.DNSTokenClearArgs{Confirm: p.Confirm}, &st); err != nil {
			return nil, err
		}
		// Back to ports and the self-signed certificate.
		m.Remove()
		set, _ := m.Store.Load(jc)
		set.Enabled = false
		_ = m.Store.Save(jc, set)
	default:
		return nil, errors.New("unknown action")
	}
	s.hosts.refresh(jc)
	return HostnamesTokenState{Set: st.Set, Base: st.Base, Zone: st.Zone, VerifiedAt: timePtr(st.VerifiedAt), Problem: st.Problem}, nil
}

func (s *Server) runHostnamesSettings(jc *jobs.Context) (any, error) {
	m := s.cfg.Hostnames
	if m == nil {
		return nil, errors.New("hostnames aren't available")
	}
	var set hostnames.Settings
	if err := jc.Params(&set); err != nil {
		return nil, err
	}
	if err := set.Validate(); err != nil {
		return nil, err
	}
	old, _ := m.Store.Load(jc)
	if err := m.Store.Save(jc, set); err != nil {
		return nil, err
	}
	if !set.Enabled {
		// Off means off: the certificate goes, names under the base are
		// refused (decision 450).
		m.Remove()
	}
	if set.Enabled {
		st, err := m.DNS.Status(jc)
		if err != nil {
			return nil, err
		}
		if st.Set && (m.Due(st.Base) || old.Staging != set.Staging) {
			jc.Progress(10, "Getting the certificate")
			if _, err := m.Issue(jc, jc.Progress); err != nil {
				s.hosts.refresh(jc)
				return nil, err
			}
		}
	}
	s.hosts.refresh(jc)
	return set, nil
}

func (s *Server) runHostnamesIssue(jc *jobs.Context) (any, error) {
	m := s.cfg.Hostnames
	if m == nil {
		return nil, errors.New("hostnames aren't available")
	}
	var p hostIssueParams
	_ = jc.Params(&p)
	rec, err := m.Issue(jc, jc.Progress)
	s.hosts.refresh(jc)
	if err != nil {
		if p.Auto && s.cfg.Notify != nil {
			_ = s.cfg.Notify.Send(jc, notify.Notification{Level: notify.Error, Title: "The hostnames' certificate couldn't be renewed",
				Body:   err.Error() + " HardyOS tries again in a few hours; apps go back to their old addresses if it expires.",
				Source: "hostnames", AdminOnly: true, Kind: "hostnames.certificate", Link: "control/hostnames"})
		}
		return nil, err
	}
	s.recordSystem(jc, "hostnames.certificate", rec.Names, "valid until "+rec.NotAfter.UTC().Format(time.DateOnly))
	return rec, nil
}

func (s *Server) runHostnamesLAN(jc *jobs.Context) (any, error) {
	var req HostnamesLANRequest
	if err := jc.Params(&req); err != nil {
		return nil, err
	}
	m := s.cfg.Hostnames
	if m == nil {
		return nil, errors.New("hostnames aren't available")
	}
	args := domain.HostRecordsArgs{Labels: []string{}}
	if !req.Remove {
		// Removing works from the DC's own list (also after the token was
		// forgotten); adding needs the token's base.
		st, err := m.DNS.Status(jc)
		if err != nil {
			return nil, err
		}
		if !st.Set {
			return nil, errors.New("save a Cloudflare token first")
		}
		s.hosts.refresh(jc)
		_, _, desk := s.hosts.snapshot()
		args = domain.HostRecordsArgs{Base: st.Base, Address: req.Address, Labels: s.hosts.lanLabels(jc), Desktop: desk}
	}
	jc.Progress(40, "Updating the domain's DNS")
	var res domain.HostRecordsResult
	if err := s.cfg.Priv.Call(jc, priv.OpDomainHostRecords, args, &res); err != nil {
		return nil, err
	}
	return res, nil
}
