// Package nbtest is an in-memory NetBird management API for tests: peers,
// groups, proxy clusters, custom domains and reverse proxy services, with
// the request bodies it was sent.
package nbtest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/hardyos/hardyos/daemon/internal/netbird"
)

// Server is a fake management server.
type Server struct {
	*httptest.Server
	Token string

	mu       sync.Mutex
	Peers    []netbird.Peer
	Groups   []netbird.Group
	Clusters []netbird.Cluster
	Domains  []netbird.Domain
	Services map[string]*netbird.Service
	IdPs     []netbird.IdentityProvider
	// Requests are "METHOD path" in order; Bodies the request bodies.
	Requests []string
	Bodies   [][]byte
	// FailServices makes service changes fail with this status (0: don't).
	FailServices int
	next         int
}

// New starts a fake with a NAS peer (100.83.40.2), the All and Family
// groups, one proxy cluster and the custom domain home.example.net.
func New(token string) *Server {
	s := &Server{Token: token, Services: map[string]*netbird.Service{}}
	s.Peers = []netbird.Peer{{ID: "peer-nas", Name: "nas", IP: "100.83.40.2", Connected: true, Hostname: "nas"}}
	s.Groups = []netbird.Group{{ID: "group-all", Name: "All", PeersCount: 3}, {ID: "group-family", Name: "Family", PeersCount: 2}}
	s.Clusters = []netbird.Cluster{{ID: "cl1", Address: "proxy.example.net", Type: "account", Online: true, ConnectedProxies: 1}}
	s.Domains = []netbird.Domain{
		{ID: "d-free", Domain: "proxy.example.net", Validated: true, Type: "free", TargetCluster: "proxy.example.net"},
		{ID: "d-home", Domain: "home.example.net", Validated: true, Type: "custom", TargetCluster: "proxy.example.net"},
	}
	s.Server = httptest.NewServer(s)
	return s
}

// Lock and Unlock guard the fake's state for tests that change it.
func (s *Server) Lock()   { s.mu.Lock() }
func (s *Server) Unlock() { s.mu.Unlock() }

// ServiceList returns the services sorted by domain.
func (s *Server) ServiceList() []netbird.Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []netbird.Service
	for _, v := range s.Services {
		out = append(out, *v)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Domain < out[j-1].Domain; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// Count returns how many requests matched "METHOD path-prefix".
func (s *Server) Count(prefix string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.Requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Requests = append(s.Requests, r.Method+" "+r.URL.RequestURI())
	s.Bodies = append(s.Bodies, body)
	if r.Header.Get("Authorization") != "Token "+s.Token {
		writeErr(w, 401, "token invalid")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api")
	switch {
	case r.Method == "GET" && path == "/peers":
		ip := r.URL.Query().Get("ip")
		out := []netbird.Peer{}
		for _, p := range s.Peers {
			if ip == "" || p.IP == ip {
				out = append(out, p)
			}
		}
		writeJSON(w, out)
	case r.Method == "GET" && path == "/identity-providers":
		writeJSON(w, append([]netbird.IdentityProvider{}, s.IdPs...))
	case r.Method == "GET" && path == "/groups":
		writeJSON(w, s.Groups)
	case r.Method == "GET" && path == "/reverse-proxies/clusters":
		writeJSON(w, s.Clusters)
	case r.Method == "GET" && path == "/reverse-proxies/domains":
		writeJSON(w, s.Domains)
	case r.Method == "POST" && path == "/reverse-proxies/domains":
		var d netbird.DomainRequest
		if json.Unmarshal(body, &d) != nil || d.Domain == "" {
			writeErr(w, 400, "bad domain")
			return
		}
		s.next++
		s.Domains = append(s.Domains, netbird.Domain{ID: fmt.Sprintf("d%d", s.next), Domain: d.Domain, Type: "custom", TargetCluster: d.TargetCluster})
		writeJSON(w, map[string]any{})
	case r.Method == "GET" && strings.HasPrefix(path, "/reverse-proxies/domains/") && strings.HasSuffix(path, "/validate"):
		w.WriteHeader(200)
	case r.Method == "GET" && path == "/reverse-proxies/services":
		out := []netbird.Service{}
		for _, v := range s.Services {
			out = append(out, *v)
		}
		writeJSON(w, out)
	case r.Method == "POST" && path == "/reverse-proxies/services":
		if s.FailServices != 0 {
			writeErr(w, s.FailServices, "service change refused")
			return
		}
		var req netbird.ServiceRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		for _, v := range s.Services {
			if v.Domain == req.Domain {
				writeErr(w, 409, "domain already in use")
				return
			}
		}
		s.next++
		id := fmt.Sprintf("svc%d", s.next)
		s.Services[id] = fromRequest(id, req)
		writeJSON(w, s.Services[id])
	case strings.HasPrefix(path, "/reverse-proxies/services/"):
		id := strings.TrimPrefix(path, "/reverse-proxies/services/")
		cur := s.Services[id]
		if cur == nil {
			writeErr(w, 404, "service not found")
			return
		}
		switch r.Method {
		case "GET":
			writeJSON(w, cur)
		case "PUT":
			if s.FailServices != 0 {
				writeErr(w, s.FailServices, "service change refused")
				return
			}
			var req netbird.ServiceRequest
			if err := json.Unmarshal(body, &req); err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			s.Services[id] = fromRequest(id, req)
			writeJSON(w, s.Services[id])
		case "DELETE":
			delete(s.Services, id)
			w.WriteHeader(200)
		default:
			writeErr(w, 405, "method")
		}
	default:
		writeErr(w, 404, "no such endpoint")
	}
}

// fromRequest is the service NetBird would store: secrets aren't given
// back.
func fromRequest(id string, req netbird.ServiceRequest) *netbird.Service {
	v := &netbird.Service{ID: id, Name: req.Name, Domain: req.Domain, Mode: req.Mode, Targets: req.Targets, Enabled: req.Enabled,
		PassHostHeader: req.PassHostHeader, RewriteRedirect: req.RewriteRedirects, Private: req.Private, AccessGroups: req.AccessGroups,
		AccessRestrictions: req.AccessRestrictions, Meta: netbird.ServiceMeta{CreatedAt: "2026-10-26T18:00:00Z", Status: "active"}}
	if req.Auth != nil {
		a := *req.Auth
		if a.PasswordAuth != nil {
			a.PasswordAuth = &netbird.PasswordAuth{Enabled: a.PasswordAuth.Enabled}
		}
		if a.PINAuth != nil {
			a.PINAuth = &netbird.PINAuth{Enabled: a.PINAuth.Enabled}
		}
		v.Auth = a
	}
	return v
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"message": msg, "code": status})
}
