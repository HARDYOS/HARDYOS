package publish

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/netbird"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Backend is the part of NetBird's API the sync uses (*netbird.API).
type Backend interface {
	Peers(ctx context.Context, ip string) ([]netbird.Peer, error)
	Groups(ctx context.Context) ([]netbird.Group, error)
	Domains(ctx context.Context) ([]netbird.Domain, error)
	Services(ctx context.Context) ([]netbird.Service, error)
	CreateService(ctx context.Context, req netbird.ServiceRequest) (*netbird.Service, error)
	UpdateService(ctx context.Context, id string, req netbird.ServiceRequest) (*netbird.Service, error)
	DeleteService(ctx context.Context, id string) error
}

// App is an installed app with a web page.
type App struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Inputs is what the sync needs to know about this server.
type Inputs struct {
	// NetBirdIP is this server's NetBird address ("" when not connected).
	NetBirdIP string
	// ManagementURL is the NetBird server this server joined (the default
	// API address).
	ManagementURL string
	// Apps are the installed apps with a web page.
	Apps []App
	// Known: Apps is the full list (false when the root helper didn't
	// answer: apps' services are then left alone).
	Known bool
	// ShareLinks: at least one share link is active (files.<base> is
	// published for it).
	ShareLinks bool
}

// Item is one published (or publishable) thing.
type Item struct {
	Key string `json:"key"`
	// Label is its name under the base domain (the desktop's name or the
	// app id); Name what people call it.
	Label  string        `json:"label"`
	Name   string        `json:"name"`
	Domain string        `json:"domain"`
	URL    string        `json:"url"`
	Config ServiceConfig `json:"config"`
	// Published: NetBird has HardyOS's service for it.
	Published bool   `json:"published"`
	ServiceID string `json:"serviceId,omitempty"`
	// Status is NetBird's (pending, certificate_pending, active, ...).
	Status   string `json:"status,omitempty"`
	Error    string `json:"error,omitempty"`
	SyncedAt string `json:"syncedAt,omitempty"`
}

// Result is a sync's outcome.
type Result struct {
	Items   []Item `json:"items"`
	Created int    `json:"created"`
	Updated int    `json:"updated"`
	Deleted int    `json:"deleted"`
	// Problem stops the whole sync (no token, NetBird not connected, the
	// base domain not in NetBird).
	Problem string `json:"problem,omitempty"`
}

// Publisher keeps HardyOS's services in NetBird in line with the settings.
type Publisher struct {
	Store *Store
	// NewAPI makes the API client for an address and token (nil: the real
	// client).
	NewAPI      func(baseURL, token string) Backend
	GatewayPort int
	Now         func() time.Time
	// OnNamesChanged runs after the settings are saved (the sign-in
	// provider's NamesChanged: its issuer follows the base domain).
	OnNamesChanged func()
	// Issuer is HardyOS's sign-in provider's issuer (nil: no provider).
	// sso.<base> is published only while it is exactly https://sso.<base>:
	// any other issuer means the provider doesn't answer there, and the
	// gateway would have nothing to serve on a public host.
	Issuer func(ctx context.Context) string

	mu sync.Mutex // one sync at a time
}

func (p *Publisher) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Publisher) port() int {
	if p.GatewayPort != 0 {
		return p.GatewayPort
	}
	return DefaultGatewayPort
}

// API returns the client for the saved settings and token.
func (p *Publisher) API(ctx context.Context, s Settings, in Inputs) (Backend, error) {
	tok, err := p.Store.Token(ctx)
	if err != nil {
		return nil, err
	}
	if tok == "" {
		return nil, errors.New("paste a NetBird access token first")
	}
	base := s.APIURL
	if base == "" {
		base = in.ManagementURL
	}
	if base == "" {
		return nil, errors.New("join a NetBird network first (or enter NetBird's API address)")
	}
	if p.NewAPI != nil {
		return p.NewAPI(base, tok), nil
	}
	return &netbird.API{BaseURL: base, Token: tok}, nil
}

// SaveSettings saves the settings and tells the sign-in provider.
func (p *Publisher) SaveSettings(ctx context.Context, s Settings) (Settings, error) {
	out, err := p.Store.Save(ctx, s)
	if err == nil && p.OnNamesChanged != nil {
		p.OnNamesChanged()
	}
	return out, err
}

// ServicePrefix is the name prefix of this server's services.
func ServicePrefix(s Settings) string { return "hardyos-" + s.Instance + "-" }

func serviceName(s Settings, key string) string {
	return ServicePrefix(s) + strings.ReplaceAll(key, ":", "-")
}

type want struct {
	item Item
	req  *netbird.ServiceRequest // nil: not published
	hash string
}

// Items lists what would be published, with the last sync's records, but
// doesn't talk to NetBird.
func (p *Publisher) Items(ctx context.Context, in Inputs) ([]Item, error) {
	s, err := p.Store.Load(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.Store.rows(ctx)
	if err != nil {
		return nil, err
	}
	var out []Item
	for _, w := range p.plan(s, rows, in.Apps, in.ShareLinks, p.ssoReady(ctx, s)) {
		out = append(out, w.item)
	}
	return out, nil
}

// SSOIssuerFor is the only issuer sso.<base> is published for.
func SSOIssuerFor(base string) string { return "https://" + SSOLabel + "." + base }

// ssoReady reports whether the sign-in provider's issuer is exactly
// https://sso.<base> (no path, no port), so that it answers every request
// on that host.
func (p *Publisher) ssoReady(ctx context.Context, s Settings) bool {
	if p.Issuer == nil || s.BaseDomain == "" {
		return false
	}
	return p.Issuer(ctx) == SSOIssuerFor(s.BaseDomain)
}

// ssoNotReady is why sso.<base> isn't published while its issuer is another.
const ssoNotReady = "HardyOS sign-in's issuer isn't https://sso.<base domain> (Control Panel › Sign-in), so this address isn't published"

// plan lists the desktop and every app with what the settings ask for
// (without the NetBird-side parts of the requests).
func (p *Publisher) plan(s Settings, rows map[string]*row, apps []App, shareLinks, ssoReady bool) []want {
	mk := func(key, label, name string) want {
		r := rows[key]
		it := Item{Key: key, Label: label, Name: name, Config: resolve(key, r, s)}
		if s.BaseDomain != "" {
			it.Domain = label + "." + s.BaseDomain
			it.URL = "https://" + it.Domain
		}
		if r != nil {
			it.ServiceID, it.Status, it.Error, it.SyncedAt = r.rec.ServiceID, r.rec.Status, r.rec.Error, r.rec.SyncedAt
			it.Published = r.rec.ServiceID != ""
		}
		return want{item: it}
	}
	files := mk(FilesKey, FilesLabel, "Share links")
	if !s.PublicShareLinks && !shareLinks {
		files.item.Config.Mode = ModeOff
	}
	sso := mk(SSOKey, SSOLabel, "HardyOS sign-in")
	if !ssoReady {
		sso.item.Config.Mode = ModeOff
	}
	out := []want{mk(DesktopKey, s.DesktopName, "Desktop"), sso, files}
	sorted := slices.Clone(apps)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for _, a := range sorted {
		out = append(out, mk(AppKey(a.ID), a.ID, a.Name))
	}
	return out
}

// Sync makes NetBird's services match the settings: creates and changes
// HardyOS's services and removes the ones nothing asks for any more. It
// only ever touches services named with this server's prefix.
func (p *Publisher) Sync(ctx context.Context, in Inputs) (*Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, err := p.Store.Load(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.Store.rows(ctx)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	ssoReady := p.ssoReady(ctx, s)
	plan := p.plan(s, rows, in.Apps, in.ShareLinks, ssoReady)
	finish := func(problem string) (*Result, error) {
		res.Problem = problem
		for _, w := range plan {
			res.Items = append(res.Items, w.item)
		}
		return res, nil
	}
	if s.Instance == "" || s.BaseDomain == "" {
		if s.Enabled {
			return finish("choose the base domain first")
		}
		return finish("")
	}
	api, err := p.API(ctx, s, in)
	if err != nil {
		return finish(err.Error())
	}
	existing, err := api.Services(ctx)
	if err != nil {
		return finish(err.Error())
	}
	prefix := ServicePrefix(s)
	ours := map[string]netbird.Service{}
	others := map[string]string{} // domain -> name of a service HardyOS doesn't own
	for _, v := range existing {
		if strings.HasPrefix(v.Name, prefix) {
			ours[v.Name] = v
		} else {
			others[strings.ToLower(v.Domain)] = v.Name
		}
	}
	now := p.now().UTC().Format(time.RFC3339)
	var peer *netbird.Peer
	var dom *netbird.Domain
	var groups []netbird.Group
	var gatewaySecret string
	if s.Enabled {
		problem := ""
		if in.NetBirdIP == "" {
			problem = "this server isn't connected to NetBird"
		}
		if problem == "" {
			peers, err := api.Peers(ctx, in.NetBirdIP)
			switch {
			case err != nil:
				problem = err.Error()
			case len(peers) != 1:
				problem = fmt.Sprintf("NetBird doesn't list one peer with this server's address %s", in.NetBirdIP)
			default:
				peer = &peers[0]
			}
		}
		if problem == "" {
			doms, err := api.Domains(ctx)
			if err != nil {
				problem = err.Error()
			}
			for i := range doms {
				if strings.EqualFold(doms[i].Domain, s.BaseDomain) {
					dom = &doms[i]
				}
			}
			if problem == "" && dom == nil {
				problem = s.BaseDomain + " isn't a domain in NetBird yet (Reverse Proxy › Custom Domains)"
			} else if problem == "" && !dom.Validated {
				problem = s.BaseDomain + " is in NetBird but not verified yet: add the CNAME record and verify it"
			}
		}
		if problem == "" {
			if groups, err = api.Groups(ctx); err != nil {
				problem = err.Error()
			}
		}
		if problem == "" {
			if gatewaySecret, err = p.Store.GatewaySecret(ctx); err != nil {
				problem = err.Error()
			}
		}
		if problem != "" {
			// Leave everything as it is: a passing problem mustn't take
			// every app offline.
			return finish(problem)
		}
	}
	// label -> key; HardyOS's own names (the desktop's too) are never an
	// app's, even while they aren't published: an app must not take the
	// desktop's address while the desktop is off.
	taken := map[string]string{SSOLabel: SSOKey, FilesLabel: FilesKey, s.DesktopName: DesktopKey}
	for i := range plan {
		w := &plan[i]
		w.item.Error = ""
		if w.item.Key == SSOKey && !ssoReady && s.Enabled {
			w.item.Error = ssoNotReady
		}
		if !s.Enabled || w.item.Config.Mode == ModeOff {
			continue
		}
		if !netbird.ValidDNSLabel(w.item.Label) {
			w.item.Error = w.item.Label + " can't be a name under " + s.BaseDomain
			continue
		}
		if k, ok := taken[w.item.Label]; ok && k != w.item.Key {
			w.item.Error = w.item.Domain + " is already " + k + "'s address"
			continue
		}
		taken[w.item.Label] = w.item.Key
		if n, ok := others[strings.ToLower(w.item.Domain)]; ok {
			w.item.Error = w.item.Domain + " is used by another NetBird service (" + n + "); HardyOS leaves it alone"
			continue
		}
		req, why := p.request(s, w.item, rows[w.item.Key], peer, in.NetBirdIP, dom, groups, gatewaySecret)
		if why != "" {
			w.item.Error = why
			continue
		}
		w.req = req
		w.hash = p.hashRequest(*req, rows[w.item.Key])
	}
	seen := map[string]bool{}
	for i := range plan {
		w := &plan[i]
		name := serviceName(s, w.item.Key)
		seen[name] = true
		cur, has := ours[name]
		rec := Record{Key: w.item.Key, Domain: w.item.Domain, SyncedAt: now}
		switch {
		case w.req == nil && has:
			// Not wanted (or can't be published as asked): remove it.
			if err := api.DeleteService(ctx, cur.ID); err != nil && !netbird.IsNotFound(err) {
				w.item.Error = joinErr(w.item.Error, "removing it from NetBird: "+err.Error())
				rec.ServiceID, rec.Status = cur.ID, cur.Meta.Status
			} else {
				res.Deleted++
			}
		case w.req == nil:
		case !has:
			v, err := api.CreateService(ctx, *w.req)
			if err != nil {
				w.item.Error = "adding it to NetBird: " + err.Error()
			} else {
				res.Created++
				rec.ServiceID, rec.Status, rec.applied = v.ID, v.Meta.Status, w.hash
			}
		default:
			rec.ServiceID, rec.Status, rec.applied = cur.ID, cur.Meta.Status, w.hash
			r := rows[w.item.Key]
			if (r == nil || r.rec.applied != w.hash || !matches(cur, *w.req)) && !cur.Terminated {
				req := *w.req
				req.AccessRestrictions = cur.AccessRestrictions // IP and country rules are NetBird's dashboard's
				v, err := api.UpdateService(ctx, cur.ID, req)
				if err != nil {
					w.item.Error = "changing it in NetBird: " + err.Error()
					rec.applied = ""
				} else {
					res.Updated++
					rec.Status = v.Meta.Status
				}
			}
			if cur.Terminated {
				w.item.Error = "NetBird terminated this service; remove it in NetBird's dashboard"
			}
		}
		rec.Error = w.item.Error
		w.item.ServiceID, w.item.Status, w.item.SyncedAt = rec.ServiceID, rec.Status, rec.SyncedAt
		w.item.Published = rec.ServiceID != ""
		if err := p.Store.saveRecord(ctx, rec); err != nil {
			return nil, err
		}
	}
	// Services of ours nothing lists any more (apps removed). Apps' are
	// left alone when the app list isn't known.
	for name, v := range ours {
		if seen[name] || (!in.Known && strings.HasPrefix(name, prefix+"app-")) {
			continue
		}
		if err := api.DeleteService(ctx, v.ID); err != nil && !netbird.IsNotFound(err) {
			res.Problem = joinErr(res.Problem, "removing "+v.Domain+" from NetBird: "+err.Error())
			continue
		}
		res.Deleted++
	}
	if in.Known {
		for key := range rows {
			if strings.HasPrefix(key, "app:") && !seen[serviceName(s, key)] {
				_ = p.Store.Forget(ctx, key)
			}
		}
	}
	return finish(res.Problem)
}

func joinErr(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// request builds the service NetBird should have for an item, or says why
// it can't be published as asked.
func (p *Publisher) request(s Settings, it Item, r *row, peer *netbird.Peer, ip string, dom *netbird.Domain,
	groups []netbird.Group, secret string) (*netbird.ServiceRequest, string) {
	c := it.Config
	target := netbird.Target{
		TargetID: peer.ID, TargetType: "peer", Protocol: "https", Host: ip, Port: p.port(), Enabled: true,
		Options: &netbird.TargetOptions{
			// The gateway has the desktop's self-signed certificate; the
			// hop runs inside WireGuard.
			SkipTLSVerify: true,
			// Per service: the gateway checks it against the request's Host.
			CustomHeaders: map[string]string{GatewayHeader: GatewayValue(secret, it.Domain)},
		},
	}
	req := &netbird.ServiceRequest{
		Name: serviceName(s, it.Key), Domain: it.Domain, Mode: "http", Enabled: true,
		Targets:        []netbird.Target{target},
		PassHostHeader: true, // the gateway routes by Host
		Auth:           &netbird.Auth{},
	}
	known := map[string]bool{}
	all := ""
	for _, g := range groups {
		known[g.ID] = true
		if g.Name == "All" {
			all = g.ID
		}
	}
	for _, g := range c.Groups {
		if !known[g] {
			return nil, "the NetBird group " + g + " doesn't exist any more: choose the groups again"
		}
	}
	switch c.Mode {
	case ModeNetBird:
		if !dom.SupportsPrivate {
			return nil, "NetBird-only needs a proxy cluster with the Private capability (a NetBird proxy running inside a NetBird client); " +
				dom.TargetCluster + " doesn't have it. Choose Public, or set up such a proxy in NetBird"
		}
		req.Private = true
		req.AccessGroups = slices.Clone(c.Groups)
		if len(req.AccessGroups) == 0 {
			if all == "" {
				return nil, "choose which NetBird groups may reach it"
			}
			req.AccessGroups = []string{all}
		}
	case ModePublic:
		switch c.Auth {
		case AuthSSO:
			req.Auth.BearerAuth = &netbird.BearerAuth{Enabled: true, DistributionGroups: slices.Clone(c.Groups)}
		case AuthPassword, AuthPIN:
			v, err := p.Store.secretOf(r)
			if err != nil {
				return nil, err.Error()
			}
			if v == "" {
				return nil, "enter the " + map[string]string{AuthPassword: "password", AuthPIN: "PIN"}[c.Auth] + " again"
			}
			if c.Auth == AuthPassword {
				req.Auth.PasswordAuth = &netbird.PasswordAuth{Enabled: true, Password: v}
			} else {
				req.Auth.PINAuth = &netbird.PINAuth{Enabled: true, PIN: v}
			}
		}
		if it.Key == DesktopKey && c.Auth != AuthNone {
			// Share links and HardyOS's own sign-in provider (OIDC, which
			// NetBird's server and SSO themselves use) must open without
			// NetBird's sign-in in front.
			for _, path := range []string{"/s/", "/oidc"} {
				t := target
				pp := path
				t.Path, t.AccessAction = &pp, "bypass"
				req.Targets = append(req.Targets, t)
			}
		}
	default:
		return nil, ""
	}
	if it.Key == FilesKey {
		// Share link pages only: everything else on the host is blocked in
		// NetBird already (the gateway refuses it too).
		links, rest := target, target
		lp, rp := "/s/", "/"
		links.Path, rest.Path, rest.AccessAction = &lp, &rp, "block"
		req.Targets = []netbird.Target{links, rest}
	}
	return req, ""
}

// hashRequest identifies what HardyOS last sent, with a password or PIN
// counted by its sealed form (never hashed in the clear).
func (p *Publisher) hashRequest(req netbird.ServiceRequest, r *row) string {
	if req.Auth != nil {
		a := *req.Auth
		if a.PasswordAuth != nil || a.PINAuth != nil {
			sealed := ""
			if r != nil {
				sealed = r.secret
			}
			if a.PasswordAuth != nil {
				a.PasswordAuth = &netbird.PasswordAuth{Enabled: true, Password: sealed}
			}
			if a.PINAuth != nil {
				a.PINAuth = &netbird.PINAuth{Enabled: true, PIN: sealed}
			}
		}
		req.Auth = &a
	}
	b, _ := json.Marshal(req)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// matches reports whether NetBird's service still is what HardyOS asked
// for, as far as NetBird shows it (secrets aren't given back).
func matches(cur netbird.Service, w netbird.ServiceRequest) bool {
	if !strings.EqualFold(cur.Domain, w.Domain) || cur.Enabled != w.Enabled || cur.PassHostHeader != w.PassHostHeader ||
		cur.RewriteRedirect != w.RewriteRedirects || cur.Private != w.Private || !sameSet(cur.AccessGroups, w.AccessGroups) ||
		len(cur.Targets) != len(w.Targets) {
		return false
	}
	for i := range w.Targets {
		a, b := cur.Targets[i], w.Targets[i]
		if a.TargetID != b.TargetID || a.TargetType != b.TargetType || a.Protocol != b.Protocol || a.Port != b.Port || a.Enabled != b.Enabled ||
			path(a.Path) != path(b.Path) || action(a.AccessAction) != action(b.AccessAction) {
			return false
		}
		ao, bo := a.Options, b.Options
		if ao == nil {
			ao = &netbird.TargetOptions{}
		}
		if bo == nil {
			bo = &netbird.TargetOptions{}
		}
		if ao.SkipTLSVerify != bo.SkipTLSVerify || headerValue(ao.CustomHeaders, GatewayHeader) != headerValue(bo.CustomHeaders, GatewayHeader) {
			return false
		}
	}
	ca, wa := cur.Auth, netbird.Auth{}
	if w.Auth != nil {
		wa = *w.Auth
	}
	enabled := func(a netbird.Auth) (pw, pin, sso bool, groups []string) {
		if a.PasswordAuth != nil {
			pw = a.PasswordAuth.Enabled
		}
		if a.PINAuth != nil {
			pin = a.PINAuth.Enabled
		}
		if a.BearerAuth != nil {
			sso, groups = a.BearerAuth.Enabled, a.BearerAuth.DistributionGroups
		}
		return
	}
	p1, n1, s1, g1 := enabled(ca)
	p2, n2, s2, g2 := enabled(wa)
	return p1 == p2 && n1 == n2 && s1 == s2 && sameSet(g1, g2)
}

func headerValue(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func path(p *string) string {
	if p == nil || *p == "/" {
		return ""
	}
	return *p
}

func action(a string) string {
	if a == "" {
		return "inherit"
	}
	return a
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// RemoveAll deletes every service of this server from NetBird (leaving
// NetBird, or turning publishing off for good).
func (p *Publisher) RemoveAll(ctx context.Context, in Inputs) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, err := p.Store.Load(ctx)
	if err != nil || s.Instance == "" {
		return 0, err
	}
	api, err := p.API(ctx, s, in)
	if err != nil {
		return 0, err
	}
	list, err := api.Services(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, v := range list {
		if strings.HasPrefix(v.Name, ServicePrefix(s)) {
			if err := api.DeleteService(ctx, v.ID); err != nil && !netbird.IsNotFound(err) {
				return n, err
			}
			n++
		}
	}
	_, err = p.Store.DB.ExecContext(ctx, `UPDATE remote_services SET service_id = '', status = '', applied = '', error = '', synced_at = ?`, store.Now())
	return n, err
}
