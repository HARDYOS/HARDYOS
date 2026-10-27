// Package netbird talks to NetBird: the management server's public API
// (peers, groups and the reverse proxy's services, custom domains and proxy
// clusters) for hardyd, and the NetBird client on this server (netbird up,
// down, status) for hardyd-priv.
//
// The reverse proxy is beta. The types below follow NetBird's OpenAPI
// description (shared/management/http/api/openapi.yml, October 2026) and
// carry only the fields HardyOS uses; fields HardyOS doesn't know are kept
// by decoding into json.RawMessage where a PUT must send them back.
package netbird

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// API is a NetBird management API client authenticated with a personal
// access token (a service user's token works the same).
type API struct {
	// BaseURL is the management server, e.g. https://vpn.example.net (a
	// trailing /api is accepted and removed).
	BaseURL string
	// Token is the access token. It is only ever sent in the Authorization
	// header and never appears in errors.
	Token string
	// HTTP is the client to use (nil: a client with a 30 s timeout).
	HTTP *http.Client
}

// maxBody is the largest response HardyOS reads.
const maxBody = 8 << 20

// APIError is a non-2xx answer from the management server.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		return "NetBird refused the access token (401): check it or create a new one"
	case http.StatusForbidden:
		return "the access token isn't allowed to do this (403): it needs a service user with the Network Admin role (or Admin)"
	}
	if e.Message != "" {
		return fmt.Sprintf("NetBird answered %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("NetBird answered %d", e.Status)
}

// IsNotFound reports whether err is NetBird's 404.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// NormalizeBaseURL checks a management URL and returns it without a
// trailing slash or /api: https only (http for localhost tests), a host,
// no query, user info or fragment.
func NormalizeBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q isn't a URL like https://vpn.example.net", raw)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return "", errors.New("the NetBird address must start with https://")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("the NetBird address can't have a user, query or fragment")
	}
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(p, "/api")
	u.Path, u.RawPath = p, ""
	return strings.TrimRight(u.String(), "/"), nil
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func (a *API) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// do sends one request and decodes a JSON answer into out (may be nil).
func (a *API) do(ctx context.Context, method, path string, in, out any) error {
	base, err := NormalizeBaseURL(a.BaseURL)
	if err != nil {
		return err
	}
	if a.Token == "" {
		return errors.New("no NetBird access token")
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+a.Token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := a.client().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL is known; keep the message short
		}
		return fmt.Errorf("couldn't reach NetBird at %s: %w", base, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("reading NetBird's answer: %w", err)
	}
	if len(raw) > maxBody {
		return errors.New("NetBird's answer is too large")
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Message
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		return &APIError{Status: res.StatusCode, Message: msg}
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("NetBird's answer to %s %s isn't what HardyOS expects: %w", method, path, err)
	}
	return nil
}

// GroupMinimum is a group as listed in a peer.
type GroupMinimum struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Peer is one machine in the NetBird network.
type Peer struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	IP        string         `json:"ip"`
	DNSLabel  string         `json:"dns_label"`
	Hostname  string         `json:"hostname"`
	Connected bool           `json:"connected"`
	Groups    []GroupMinimum `json:"groups"`
}

// Group is a NetBird peer group.
type Group struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PeersCount int    `json:"peers_count"`
	Issued     string `json:"issued,omitempty"`
}

// Cluster is a reverse proxy cluster (GET /api/reverse-proxies/clusters).
type Cluster struct {
	ID                  string `json:"id"`
	Address             string `json:"address"`
	Type                string `json:"type"` // account (BYOP) or shared
	Online              bool   `json:"online"`
	ConnectedProxies    int    `json:"connected_proxies"`
	SupportsCustomPorts bool   `json:"supports_custom_ports"`
	RequireSubdomain    bool   `json:"require_subdomain"`
	SupportsCrowdsec    bool   `json:"supports_crowdsec"`
	// Private: a proxy in the cluster runs inside a NetBird client and can
	// serve NetBird-only services.
	Private bool `json:"private"`
}

// Domain is a reverse proxy domain: a free one or a custom one
// (GET /api/reverse-proxies/domains).
type Domain struct {
	ID               string `json:"id"`
	Domain           string `json:"domain"`
	Validated        bool   `json:"validated"`
	Type             string `json:"type"` // free or custom
	TargetCluster    string `json:"target_cluster"`
	RequireSubdomain bool   `json:"require_subdomain"`
	SupportsPrivate  bool   `json:"supports_private"`
}

// TargetOptions are a target's advanced settings.
type TargetOptions struct {
	SkipTLSVerify  bool              `json:"skip_tls_verify,omitempty"`
	RequestTimeout string            `json:"request_timeout,omitempty"`
	PathRewrite    string            `json:"path_rewrite,omitempty"`
	CustomHeaders  map[string]string `json:"custom_headers,omitempty"`
	DirectUpstream bool              `json:"direct_upstream,omitempty"`
}

// Target is where a service sends requests.
type Target struct {
	TargetID     string         `json:"target_id"`
	TargetType   string         `json:"target_type"` // peer, host, domain, subnet, cluster
	Path         *string        `json:"path,omitempty"`
	AccessAction string         `json:"access_action,omitempty"` // inherit, bypass, block
	Protocol     string         `json:"protocol"`                // http, https
	Host         string         `json:"host,omitempty"`
	Port         int            `json:"port"`
	Enabled      bool           `json:"enabled"`
	Options      *TargetOptions `json:"options,omitempty"`
}

// PasswordAuth is a shared password in front of a service.
type PasswordAuth struct {
	Enabled  bool   `json:"enabled"`
	Password string `json:"password"`
}

// PINAuth is a numeric PIN in front of a service.
type PINAuth struct {
	Enabled bool   `json:"enabled"`
	PIN     string `json:"pin"`
}

// BearerAuth is SSO through the management server's identity provider.
type BearerAuth struct {
	Enabled            bool     `json:"enabled"`
	DistributionGroups []string `json:"distribution_groups,omitempty"`
}

// LinkAuth is NetBird's link sign-in.
type LinkAuth struct {
	Enabled bool `json:"enabled"`
}

// Auth is a service's sign-in in front of the backend.
type Auth struct {
	PasswordAuth *PasswordAuth    `json:"password_auth,omitempty"`
	PINAuth      *PINAuth         `json:"pin_auth,omitempty"`
	BearerAuth   *BearerAuth      `json:"bearer_auth,omitempty"`
	LinkAuth     *LinkAuth        `json:"link_auth,omitempty"`
	HeaderAuths  []map[string]any `json:"header_auths,omitempty"`
}

// ServiceMeta is a service's state as NetBird reports it.
type ServiceMeta struct {
	CreatedAt           string `json:"created_at"`
	CertificateIssuedAt string `json:"certificate_issued_at,omitempty"`
	// Status: pending, active, tunnel_not_created, certificate_pending,
	// certificate_failed or error.
	Status string `json:"status"`
}

// Service is a reverse proxy service (GET /api/reverse-proxies/services).
type Service struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	Domain          string      `json:"domain"`
	Mode            string      `json:"mode,omitempty"`
	ProxyCluster    string      `json:"proxy_cluster,omitempty"`
	Targets         []Target    `json:"targets"`
	Enabled         bool        `json:"enabled"`
	Terminated      bool        `json:"terminated,omitempty"`
	PassHostHeader  bool        `json:"pass_host_header"`
	RewriteRedirect bool        `json:"rewrite_redirects"`
	Auth            Auth        `json:"auth"`
	Meta            ServiceMeta `json:"meta"`
	Private         bool        `json:"private"`
	AccessGroups    []string    `json:"access_groups,omitempty"`
	// AccessRestrictions are left as NetBird has them: HardyOS leaves IP
	// and country rules to NetBird's dashboard and sends them back as is.
	AccessRestrictions json.RawMessage `json:"access_restrictions,omitempty"`
}

// ServiceRequest creates or replaces a service.
type ServiceRequest struct {
	Name               string          `json:"name"`
	Domain             string          `json:"domain"`
	Mode               string          `json:"mode"`
	Targets            []Target        `json:"targets"`
	Enabled            bool            `json:"enabled"`
	PassHostHeader     bool            `json:"pass_host_header"`
	RewriteRedirects   bool            `json:"rewrite_redirects"`
	Auth               *Auth           `json:"auth,omitempty"`
	AccessRestrictions json.RawMessage `json:"access_restrictions,omitempty"`
	Private            bool            `json:"private"`
	AccessGroups       []string        `json:"access_groups,omitempty"`
}

// DomainRequest registers a custom domain.
type DomainRequest struct {
	Domain        string `json:"domain"`
	TargetCluster string `json:"target_cluster"`
}

// IdentityProvider is a sign-in provider NetBird is configured with
// (self-hosted: the embedded IdP's connectors).
type IdentityProvider struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
}

// IdentityProviders lists the account's identity providers. Older
// management servers don't have the endpoint (404).
func (a *API) IdentityProviders(ctx context.Context) ([]IdentityProvider, error) {
	var out []IdentityProvider
	return out, a.do(ctx, http.MethodGet, "/api/identity-providers", nil, &out)
}

// Peers lists peers; ip (optional) filters by NetBird address.
func (a *API) Peers(ctx context.Context, ip string) ([]Peer, error) {
	path := "/api/peers"
	if ip != "" {
		path += "?ip=" + url.QueryEscape(ip)
	}
	var out []Peer
	return out, a.do(ctx, http.MethodGet, path, nil, &out)
}

// Groups lists peer groups.
func (a *API) Groups(ctx context.Context) ([]Group, error) {
	var out []Group
	return out, a.do(ctx, http.MethodGet, "/api/groups", nil, &out)
}

// Clusters lists the reverse proxy clusters.
func (a *API) Clusters(ctx context.Context) ([]Cluster, error) {
	var out []Cluster
	return out, a.do(ctx, http.MethodGet, "/api/reverse-proxies/clusters", nil, &out)
}

// Domains lists the reverse proxy domains.
func (a *API) Domains(ctx context.Context) ([]Domain, error) {
	var out []Domain
	return out, a.do(ctx, http.MethodGet, "/api/reverse-proxies/domains", nil, &out)
}

// AddDomain registers a custom domain (NetBird starts checking its CNAME).
// NetBird's documentation shows a service in the answer; HardyOS lists the
// domains again instead of trusting the answer's shape.
func (a *API) AddDomain(ctx context.Context, req DomainRequest) error {
	return a.do(ctx, http.MethodPost, "/api/reverse-proxies/domains", req, nil)
}

// ValidateDomain asks NetBird to check a custom domain's CNAME again.
func (a *API) ValidateDomain(ctx context.Context, id string) error {
	return a.do(ctx, http.MethodGet, "/api/reverse-proxies/domains/"+url.PathEscape(id)+"/validate", nil, nil)
}

// Services lists the reverse proxy services.
func (a *API) Services(ctx context.Context) ([]Service, error) {
	var out []Service
	return out, a.do(ctx, http.MethodGet, "/api/reverse-proxies/services", nil, &out)
}

// Service returns one service.
func (a *API) Service(ctx context.Context, id string) (*Service, error) {
	var out Service
	if err := a.do(ctx, http.MethodGet, "/api/reverse-proxies/services/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateService adds a service.
func (a *API) CreateService(ctx context.Context, req ServiceRequest) (*Service, error) {
	var out Service
	if err := a.do(ctx, http.MethodPost, "/api/reverse-proxies/services", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateService replaces a service.
func (a *API) UpdateService(ctx context.Context, id string, req ServiceRequest) (*Service, error) {
	var out Service
	if err := a.do(ctx, http.MethodPut, "/api/reverse-proxies/services/"+url.PathEscape(id), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteService removes a service.
func (a *API) DeleteService(ctx context.Context, id string) error {
	return a.do(ctx, http.MethodDelete, "/api/reverse-proxies/services/"+url.PathEscape(id), nil, nil)
}
