package api

import (
	"errors"
	"net/http"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

func writeUserError(s *Server, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "user not found")
	case errors.Is(err, auth.ErrUserExists):
		writeError(w, http.StatusConflict, "user_exists", err.Error())
	case errors.Is(err, auth.ErrLastAdmin):
		writeError(w, http.StatusConflict, "last_admin", err.Error())
	case errors.Is(err, auth.ErrDomainManaged):
		writeError(w, http.StatusConflict, "domain_account", err.Error())
	case isErr(err, auth.ErrInvalidName, auth.ErrWeakPassword, auth.ErrPasswordTooLong, auth.ErrInvalidRole):
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
	default:
		internalError(s, w, err)
	}
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	list, err := s.users.List(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	if list == nil {
		list = []*auth.User{}
	}
	writeJSON(w, http.StatusOK, list)
}

type createUserRequest struct {
	Username    string    `json:"username"`
	Password    string    `json:"password"`
	DisplayName string    `json:"displayName"`
	Email       string    `json:"email"`
	Role        auth.Role `json:"role"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request, me *auth.User) {
	var req createUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Role == "" {
		req.Role = auth.RoleUser
	}
	u, err := s.users.Create(r.Context(), auth.NewUser{
		Username: req.Username, Password: req.Password, DisplayName: req.DisplayName,
		Email: req.Email, Role: req.Role,
	})
	if err != nil {
		s.record(r, me, "user.create", req.Username, audit.Failure, err.Error())
		writeUserError(s, w, err)
		return
	}
	s.record(r, me, "user.create", u.Username, audit.Success, "role="+string(u.Role))
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	u, err := s.users.Get(r.Context(), id)
	if err != nil {
		writeUserError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

type updateUserRequest struct {
	DisplayName *string    `json:"displayName"`
	Email       *string    `json:"email"`
	Role        *auth.Role `json:"role"`
	Disabled    *bool      `json:"disabled"`
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request, me *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req updateUserRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := s.users.Update(r.Context(), id, auth.UserUpdate{
		DisplayName: req.DisplayName, Email: req.Email, Role: req.Role, Disabled: req.Disabled,
	})
	if err != nil {
		s.record(r, me, "user.update", r.PathValue("id"), audit.Failure, err.Error())
		writeUserError(s, w, err)
		return
	}
	if u.Disabled {
		_ = s.sessions.RevokeUser(r.Context(), u.ID)
		s.proxy.endUser(u.ID)
		s.endOIDCUser(r.Context(), u.ID)
		s.office.dropUser(u.ID, "the account was turned off")
	}
	s.record(r, me, "user.update", u.Username, audit.Success, "")
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request, me *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	u, err := s.users.Get(r.Context(), id)
	if err != nil {
		writeUserError(s, w, err)
		return
	}
	if err := s.users.Delete(r.Context(), id); err != nil {
		s.record(r, me, "user.delete", u.Username, audit.Failure, err.Error())
		writeUserError(s, w, err)
		return
	}
	s.record(r, me, "user.delete", u.Username, audit.Success, "")
	s.office.dropUser(id, "the account was deleted")
	w.WriteHeader(http.StatusNoContent)
}

type resetPasswordRequest struct {
	Password string `json:"password"`
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request, me *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req resetPasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	u, err := s.users.Get(r.Context(), id)
	if err != nil {
		writeUserError(s, w, err)
		return
	}
	if err := s.users.SetPassword(r.Context(), id, req.Password); err != nil {
		writeUserError(s, w, err)
		return
	}
	_ = s.sessions.RevokeUser(r.Context(), id)
	s.proxy.endUser(id)
	s.endOIDCUser(r.Context(), id)
	s.record(r, me, "user.password.reset", u.Username, audit.Success, "")
	w.WriteHeader(http.StatusNoContent)
}
