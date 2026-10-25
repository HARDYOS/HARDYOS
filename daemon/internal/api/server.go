// Package api implements hardyd's HTTP API and serves the web desktop.
package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/version"
)

// Config controls the API server.
type Config struct {
	// WebRoot is a directory holding the built web desktop. Empty disables static serving.
	WebRoot string
	// Logger receives request logs. Defaults to slog.Default().
	Logger *slog.Logger
}

// Server is hardyd's HTTP handler.
type Server struct {
	cfg     Config
	mux     *http.ServeMux
	started time.Time
}

// New builds the API server and registers its routes.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux(), started: time.Now()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/version", s.handleVersion)
	s.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "no such API endpoint")
	})
	if s.cfg.WebRoot != "" {
		s.mux.Handle("/", spaHandler(os.DirFS(s.cfg.WebRoot)))
	}
}

// ServeHTTP implements http.Handler with request logging and baseline security headers.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	h.Set("Referrer-Policy", "same-origin")
	rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	s.mux.ServeHTTP(rw, r)
	s.cfg.Logger.Debug("http request",
		"method", r.Method, "path", r.URL.Path, "status", rw.status,
		"duration", time.Since(start).String())
}

// HealthResponse is returned by GET /api/v1/health.
type HealthResponse struct {
	Status        string  `json:"status"`
	UptimeSeconds float64 `json:"uptimeSeconds"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{
		Status:        "ok",
		UptimeSeconds: time.Since(s.started).Seconds(),
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, version.Get())
}

// ErrorResponse is the body of every non-2xx API response.
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, ErrorResponse{Code: code, Message: msg})
}

// spaHandler serves files from root and falls back to index.html for client-side routes.
func spaHandler(root fs.FS) http.Handler {
	files := http.FileServerFS(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "."
		}
		if _, err := fs.Stat(root, p); errors.Is(err, fs.ErrNotExist) {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
