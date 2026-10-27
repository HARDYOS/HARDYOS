package office

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/clientip"
)

// InternalPort is hardyd's listener for the Document Server (plain HTTP on
// the Docker host gateway address; decision 253).
const InternalPort = 44251

// InternalHandler serves the two things the Document Server asks hardyd
// for, and nothing else:
//
//	GET  /office/file/<token>      a document to open (one-time URL)
//	POST /office/callback/<key>    who is editing, and saves
//
// allow says which peers may call (the Docker networks on this server);
// everyone else gets 403 before anything is looked at.
func (s *Service) InternalHandler(allow func(netip.Addr) bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /office/file/{token}", func(w http.ResponseWriter, r *http.Request) {
		s.ServeDownload(w, r, r.PathValue("token"))
	})
	mux.HandleFunc("POST /office/callback/{key}", s.serveCallback)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, err := netip.ParseAddr(clientip.Peer(r))
		if err != nil || allow == nil || !allow(a.Unmap()) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func callbackAnswer(w http.ResponseWriter, status int, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	out := map[string]any{"error": code}
	if msg != "" {
		out["message"] = msg
	}
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Service) serveCallback(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if !ValidKey(key) {
		callbackAnswer(w, http.StatusNotFound, 1, "unknown document")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxCallbackBytes+1))
	if err != nil || len(body) > MaxCallbackBytes {
		callbackAnswer(w, http.StatusRequestEntityTooLarge, 1, "callback too big")
		return
	}
	secret, err := s.Secret(r.Context())
	if err != nil {
		callbackAnswer(w, http.StatusServiceUnavailable, 1, "not ready")
		return
	}
	cb, err := ParseCallback(secret, r.Header.Get("Authorization"), body, s.now())
	if err != nil {
		s.audit(r.Context(), AuditEvent{Action: "office.callback", Target: "document " + key[:8], Outcome: audit.Denied, Detail: err.Error()})
		callbackAnswer(w, http.StatusForbidden, 1, "refused")
		return
	}
	res, err := s.HandleCallback(r.Context(), key, cb)
	if err != nil {
		if errors.Is(err, ErrCallbackKey) || errors.Is(err, ErrCallbackSession) {
			s.audit(r.Context(), AuditEvent{Action: "office.callback", Target: "document " + key[:8], Outcome: audit.Denied, Detail: err.Error()})
		}
		// error 1: the Document Server keeps the document (as a "forgotten"
		// file an administrator can recover) instead of dropping the edits.
		callbackAnswer(w, http.StatusOK, 1, "not saved")
		return
	}
	_ = res
	callbackAnswer(w, http.StatusOK, 0, "")
}

// DockerPeers allows loopback and the addresses of this server's Docker
// bridge networks (docker0 and br-*), read from the interfaces at most every
// 30 seconds.
func DockerPeers() func(netip.Addr) bool {
	var mu sync.Mutex
	var nets []netip.Prefix
	var at time.Time
	return func(a netip.Addr) bool {
		if a.IsLoopback() {
			return true
		}
		mu.Lock()
		if time.Since(at) > 30*time.Second {
			nets, at = dockerNets(), time.Now()
		}
		list := nets
		mu.Unlock()
		for _, p := range list {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
}

func dockerNets() []netip.Prefix {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, ifc := range ifs {
		if ifc.Name != "docker0" && !strings.HasPrefix(ifc.Name, "br-") {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if p, err := netip.ParsePrefix(n.String()); err == nil {
					out = append(out, p.Masked())
				}
			}
		}
	}
	return out
}

// HostGateway is the address containers reach the host at
// (host.docker.internal = Docker's default bridge, docker0), or false
// while Docker isn't running.
func HostGateway() (netip.Addr, bool) {
	ifc, err := net.InterfaceByName("docker0")
	if err != nil {
		return netip.Addr{}, false
	}
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok && ip.Unmap().Is4() {
				return ip.Unmap(), true
			}
		}
	}
	return netip.Addr{}, false
}
