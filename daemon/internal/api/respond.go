package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
)

func parseFloat(s string) (float64, error) { return strconv.ParseFloat(s, 64) }

// ErrorResponse is the body of every non-2xx API response.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Details lists every problem when a form has several (optional).
	Details []string `json:"details,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, ErrorResponse{Code: code, Message: msg})
}

// decodeJSON reads a JSON body of at most 1 MiB into v, rejecting unknown fields.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid id")
		return 0, false
	}
	return id, true
}

// clientIP is the address a request is from: the connection's peer, or
// the address a trusted reverse proxy (Config.TrustedProxies) forwarded.
// Everything that records or limits by address goes through it.
func (s *Server) clientIP(r *http.Request) string {
	if g := gatewayInfo(r); g != nil && g.client != "" {
		// Through the app gateway: the address NetBird's proxy saw (believed
		// only after the per-service secret checked out).
		return g.client
	}
	return s.ips.IP(r)
}

func internalError(s *Server, w http.ResponseWriter, err error) {
	s.log.Error("internal error", "err", err)
	writeError(w, http.StatusInternalServerError, "internal", "something went wrong; see the system log")
}

func isErr(err error, targets ...error) bool {
	for _, t := range targets {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}
