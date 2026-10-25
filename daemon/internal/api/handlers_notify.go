package api

import (
	"net/http"
	"strconv"

	"github.com/hardyos/hardyos/daemon/internal/auth"
)

func (s *Server) notifyRoutes() {
	if s.cfg.Notify == nil {
		return
	}
	s.mux.Handle("GET /api/v1/notifications", s.authed(s.handleListNotifications))
	s.mux.Handle("POST /api/v1/notifications/{id}/read", s.authed(s.handleReadNotification))
	s.mux.Handle("POST /api/v1/notifications/read-all", s.authed(s.handleReadAllNotifications))
}

func (s *Server) handleListNotifications(w http.ResponseWriter, r *http.Request, u *auth.User) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := s.cfg.Notify.List(r.Context(), u.IsAdmin(), limit)
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleReadNotification(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.cfg.Notify.MarkRead(r.Context(), id, u.IsAdmin()); err != nil {
		internalError(s, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleReadAllNotifications(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if err := s.cfg.Notify.MarkRead(r.Context(), 0, u.IsAdmin()); err != nil {
		internalError(s, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
