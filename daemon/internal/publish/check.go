package publish

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/netbird"
)

// Admin is the rest of NetBird's API the setup screen uses (*netbird.API).
type Admin interface {
	Backend
	Clusters(ctx context.Context) ([]netbird.Cluster, error)
	AddDomain(ctx context.Context, req netbird.DomainRequest) error
	ValidateDomain(ctx context.Context, id string) error
	IdentityProviders(ctx context.Context) ([]netbird.IdentityProvider, error)
}

// Resolver looks up DNS (net.DefaultResolver; tests use a fake).
type Resolver interface {
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// Step is one line of the setup check.
type Step struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// State: ok, warn, bad or skipped.
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// DNSRecord is the record to add at the DNS provider (Cloudflare).
type DNSRecord struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Target string `json:"target"`
	// Proxy is Cloudflare's proxy status: DNS only (the grey cloud), so
	// NetBird's proxy gets the connections and makes the certificates.
	Proxy string `json:"proxy"`
	TTL   string `json:"ttl"`
}

// CheckResult is the setup check.
type CheckResult struct {
	Steps  []Step     `json:"steps"`
	Record *DNSRecord `json:"record,omitempty"`
	// Ready: services can be published.
	Ready           bool              `json:"ready"`
	SupportsPrivate bool              `json:"supportsPrivate"`
	Domain          *netbird.Domain   `json:"domain,omitempty"`
	Domains         []netbird.Domain  `json:"domains"`
	Clusters        []netbird.Cluster `json:"clusters"`
	Groups          []netbird.Group   `json:"groups"`
	// SSO is the issuer NetBird would need as a sign-in provider for
	// "HardyOS sign-in" on public services ("" when HardyOS's own provider
	// isn't set up).
	SSOIssuer string `json:"ssoIssuer,omitempty"`
}

// SSOIssuer says what HardyOS's own OIDC provider's issuer is ("" when it
// isn't set up). Part B (internal/oidc) provides it.
type SSOIssuer func(ctx context.Context) string

func (p *Publisher) admin(ctx context.Context, s Settings, in Inputs) (Admin, error) {
	api, err := p.API(ctx, s, in)
	if err != nil {
		return nil, err
	}
	a, ok := api.(Admin)
	if !ok {
		return nil, errors.New("this NetBird client can't manage domains")
	}
	return a, nil
}

// clusterFor is the proxy cluster address for the base domain's CNAME.
func clusterFor(s Settings, dom *netbird.Domain, clusters []netbird.Cluster) string {
	if dom != nil && dom.TargetCluster != "" {
		return dom.TargetCluster
	}
	if s.Cluster != "" {
		return s.Cluster
	}
	if len(clusters) == 1 {
		return clusters[0].Address
	}
	return ""
}

// CNAMERecord is the wildcard CNAME the base domain needs.
func CNAMERecord(base, cluster string) *DNSRecord {
	if base == "" || cluster == "" {
		return nil
	}
	return &DNSRecord{Type: "CNAME", Name: "*." + base, Target: cluster, Proxy: "DNS only", TTL: "Auto"}
}

// Check walks through what publishing needs and says what's missing.
func (p *Publisher) Check(ctx context.Context, in Inputs, res Resolver, sso SSOIssuer) (*CheckResult, error) {
	s, err := p.Store.Load(ctx)
	if err != nil {
		return nil, err
	}
	out := &CheckResult{Domains: []netbird.Domain{}, Clusters: []netbird.Cluster{}, Groups: []netbird.Group{}}
	add := func(id, title, state, detail string) {
		out.Steps = append(out.Steps, Step{ID: id, Title: title, State: state, Detail: detail})
	}
	skip := func(ids ...string) {
		titles := map[string]string{"token": "Access token", "peer": "This server in NetBird", "domain": "Base domain in NetBird",
			"dns": "Wildcard DNS record", "private": "NetBird-only services", "sso": "HardyOS sign-in for public apps"}
		for _, id := range ids {
			add(id, titles[id], "skipped", "")
		}
	}
	if in.NetBirdIP != "" {
		add("netbird", "Connected to NetBird", "ok", "This server is "+in.NetBirdIP+" in the NetBird network.")
	} else {
		add("netbird", "Connected to NetBird", "bad", "Join a NetBird network first (above).")
	}
	if s.BaseDomain == "" {
		add("base", "Base domain", "bad", "Choose the domain apps are published under, like home.example.net.")
	} else {
		add("base", "Base domain", "ok", "Apps will be https://<app>."+s.BaseDomain+", the desktop https://"+s.DesktopName+"."+s.BaseDomain+".")
	}
	api, err := p.admin(ctx, s, in)
	if err != nil {
		add("token", "Access token", "bad", err.Error())
		skip("peer", "domain", "dns", "private", "sso")
		return out, nil
	}
	doms, err := api.Domains(ctx)
	if err != nil {
		add("token", "Access token", "bad", err.Error())
		skip("peer", "domain", "dns", "private", "sso")
		return out, nil
	}
	add("token", "Access token", "ok", "NetBird accepted the token.")
	out.Domains = doms
	if cl, err := api.Clusters(ctx); err == nil {
		out.Clusters = cl
	}
	if g, err := api.Groups(ctx); err == nil {
		out.Groups = g
	}
	if in.NetBirdIP == "" {
		skip("peer")
	} else if peers, err := api.Peers(ctx, in.NetBirdIP); err != nil {
		add("peer", "This server in NetBird", "bad", err.Error())
	} else if len(peers) != 1 {
		add("peer", "This server in NetBird", "bad", "NetBird doesn't list a peer with this server's address "+in.NetBirdIP+".")
	} else {
		add("peer", "This server in NetBird", "ok", "Peer "+peers[0].Name+".")
	}
	for i := range doms {
		if s.BaseDomain != "" && strings.EqualFold(doms[i].Domain, s.BaseDomain) {
			out.Domain = &doms[i]
		}
	}
	cluster := clusterFor(s, out.Domain, out.Clusters)
	out.Record = CNAMERecord(s.BaseDomain, cluster)
	switch {
	case s.BaseDomain == "":
		skip("domain")
	case out.Domain == nil:
		add("domain", "Base domain in NetBird", "bad", s.BaseDomain+" isn't a custom domain in NetBird yet. Add it here (Add to NetBird) or in NetBird's dashboard: Reverse Proxy › Custom Domains › Add Domain, with your proxy cluster.")
	case !out.Domain.Validated:
		add("domain", "Base domain in NetBird", "warn", s.BaseDomain+" is waiting for verification: add the DNS record below, then press Verify. NetBird drops unverified domains after 48 hours.")
	default:
		add("domain", "Base domain in NetBird", "ok", "Verified, served by "+out.Domain.TargetCluster+".")
	}
	switch {
	case s.BaseDomain == "" || cluster == "":
		add("dns", "Wildcard DNS record", "skipped", "Pick the proxy cluster first.")
	default:
		probe := "hardyos-check-" + randomHex(4) + "." + s.BaseDomain
		got, err := res.LookupCNAME(ctx, probe)
		got = strings.ToLower(strings.TrimSuffix(got, "."))
		// The resolver follows the whole chain: the cluster's own name may
		// be a CNAME too.
		canon, _ := res.LookupCNAME(ctx, cluster)
		canon = strings.ToLower(strings.TrimSuffix(canon, "."))
		switch {
		case err == nil && (got == strings.ToLower(cluster) || (canon != "" && got == canon)):
			add("dns", "Wildcard DNS record", "ok", "*."+s.BaseDomain+" points at "+cluster+".")
		case err == nil && got != "" && got != strings.ToLower(probe):
			add("dns", "Wildcard DNS record", "bad", "*."+s.BaseDomain+" points at "+got+", not "+cluster+". Change the record below.")
		default:
			add("dns", "Wildcard DNS record", "bad", "No CNAME for *."+s.BaseDomain+" yet. Add the record below at your DNS provider (in Cloudflare: proxy status DNS only, the grey cloud). It can take a few minutes to show up.")
		}
	}
	if out.Domain != nil {
		out.SupportsPrivate = out.Domain.SupportsPrivate
	}
	switch {
	case out.Domain == nil:
		skip("private")
	case out.SupportsPrivate:
		add("private", "NetBird-only services", "ok", "The proxy cluster can serve apps to NetBird devices only.")
	default:
		add("private", "NetBird-only services", "warn", "The proxy cluster "+out.Domain.TargetCluster+" has no Private capability, so apps can only be Public (with sign-in in front). For NetBird-only apps, run a NetBird proxy inside a NetBird client (NetBird's Bring Your Own Proxy with the private option).")
	}
	issuer := ""
	if sso != nil {
		issuer = sso(ctx)
	}
	out.SSOIssuer = issuer
	if issuer == "" {
		add("sso", "HardyOS sign-in for public apps", "warn", "HardyOS's own sign-in provider (Control Panel › Sign-in) isn't set up yet. Until NetBird uses it as its identity provider, \"HardyOS sign-in\" in front of public apps signs people in with NetBird's current provider.")
	} else if idps, err := api.IdentityProviders(ctx); err != nil {
		add("sso", "HardyOS sign-in for public apps", "warn", "Couldn't check NetBird's identity providers ("+err.Error()+"). Make sure NetBird signs people in with "+issuer+".")
	} else {
		found := false
		for _, idp := range idps {
			if strings.TrimSuffix(idp.Issuer, "/") == strings.TrimSuffix(issuer, "/") {
				found = true
			}
		}
		if found {
			add("sso", "HardyOS sign-in for public apps", "ok", "NetBird signs people in with HardyOS ("+issuer+").")
		} else {
			add("sso", "HardyOS sign-in for public apps", "warn", "NetBird doesn't use HardyOS ("+issuer+") as an identity provider yet: add it in Control Panel › Sign-in › NetBird.")
		}
	}
	out.Ready = in.NetBirdIP != "" && out.Domain != nil && out.Domain.Validated
	for _, st := range out.Steps {
		if st.State == "bad" && st.ID != "dns" {
			out.Ready = false
		}
	}
	return out, nil
}

// AddDomain registers the base domain in NetBird with a proxy cluster.
func (p *Publisher) AddDomain(ctx context.Context, in Inputs, cluster string) error {
	s, err := p.Store.Load(ctx)
	if err != nil {
		return err
	}
	if s.BaseDomain == "" {
		return errors.New("choose the base domain first")
	}
	api, err := p.admin(ctx, s, in)
	if err != nil {
		return err
	}
	if cluster == "" {
		cl, err := api.Clusters(ctx)
		if err != nil {
			return err
		}
		if len(cl) != 1 {
			return errors.New("choose the proxy cluster")
		}
		cluster = cl[0].Address
	}
	if !netbird.ValidDomain(strings.ToLower(cluster)) {
		return errors.New("that isn't a proxy cluster address")
	}
	if err := api.AddDomain(ctx, netbird.DomainRequest{Domain: s.BaseDomain, TargetCluster: cluster}); err != nil {
		return err
	}
	s.Cluster = cluster
	_, err = p.Store.Save(ctx, s)
	return err
}

// VerifyDomain asks NetBird to check the base domain's CNAME again.
func (p *Publisher) VerifyDomain(ctx context.Context, in Inputs) error {
	s, err := p.Store.Load(ctx)
	if err != nil {
		return err
	}
	api, err := p.admin(ctx, s, in)
	if err != nil {
		return err
	}
	doms, err := api.Domains(ctx)
	if err != nil {
		return err
	}
	for _, d := range doms {
		if strings.EqualFold(d.Domain, s.BaseDomain) {
			return api.ValidateDomain(ctx, d.ID)
		}
	}
	return errors.New(s.BaseDomain + " isn't in NetBird yet")
}

// DefaultResolver is the system's DNS.
var DefaultResolver Resolver = net.DefaultResolver
