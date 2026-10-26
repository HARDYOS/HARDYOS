package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/sharelinks"
)

// Web share links (docs/plans/file-sharing.md section 4, decisions 96-98):
// the management API under /api/v1/sharelinks and the public pages at
// /s/<token>, which work without a desktop session.

// ShareLinkCreated is the answer to making a link: the token is in it once.
type ShareLinkCreated struct {
	Link *sharelinks.Link `json:"link"`
	// URL is the link's path on this server ("/s/<token>").
	URL   string `json:"url"`
	Token string `json:"token"`
}

func (s *Server) shareLinkRoutes() {
	s.links = &sharelinks.Store{DB: s.cfg.DB}
	m := s.mux
	m.Handle("GET /api/v1/sharelinks", s.authed(s.handleShareLinks))
	m.Handle("POST /api/v1/sharelinks", s.authed(s.handleShareLinkCreate))
	m.Handle("POST /api/v1/sharelinks/{id}/revoke", s.authed(s.handleShareLinkRevoke))

	pub := &sharelinks.Public{
		Links:    s.links,
		Files:    s.cfg.Files,
		Owner:    s.linkOwner,
		Audit:    s.recordLink,
		Log:      s.log,
		Insecure: s.cfg.Insecure,
	}
	if s.cfg.Files == nil {
		pub.Files = unavailableFiles{}
	}
	pub.Register(m)
}

// whoFor is who files are read and written as for a HardyOS account.
func whoFor(u *auth.User) files.Who {
	return files.Who{Principal: u.IdentityPrincipal(), Local: u.IdentitySource() == auth.SourceLocal, Admin: u.IsAdmin()}
}

// linkOwner says who made a link, as of now: like a session, a deleted or
// disabled account, or a domain account that may no longer sign in, stops
// its links (sharelinks.ErrOwnerGone).
func (s *Server) linkOwner(ctx context.Context, id int64) (files.Who, error) {
	u, err := s.users.Get(ctx, id)
	if err != nil || u.Disabled {
		return files.Who{}, sharelinks.ErrOwnerGone
	}
	if u.Source == auth.SourceDomain {
		nu, err := s.signin.Refresh(ctx, u)
		if errors.Is(err, auth.ErrAccountGone) {
			return files.Who{}, sharelinks.ErrOwnerGone
		}
		if err == nil {
			u = nu
		}
	}
	return whoFor(u), nil
}

func (s *Server) recordLink(r *http.Request, l *sharelinks.Link, action, target string, outcome audit.Outcome, detail string) {
	e := audit.Entry{Action: action, Target: target, Outcome: outcome, Detail: detail, IP: clientIP(r),
		Actor: "link #" + strconv.FormatInt(l.ID, 10) + " of " + l.CreatedBy}
	if err := s.audit.Record(r.Context(), e); err != nil {
		s.log.Error("audit write failed", "action", action, "err", err)
	}
}

func (s *Server) handleShareLinks(w http.ResponseWriter, r *http.Request, u *auth.User) {
	mine := u.ID
	if r.URL.Query().Get("scope") == "all" {
		if !u.IsAdmin() {
			writeError(w, http.StatusForbidden, "forbidden", "only administrators see everyone's links")
			return
		}
		mine = 0
	}
	list, err := s.links.List(r.Context(), mine)
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": list})
}

func (s *Server) handleShareLinkCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if s.cfg.Files == nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "file access isn't available on this server yet")
		return
	}
	var q sharelinks.Request
	if !decodeJSON(w, r, &q) {
		return
	}
	if probs := q.Validate(); len(probs) > 0 {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Code: "invalid", Message: probs[0], Details: probs})
		return
	}
	target := q.Share + "/" + q.Path
	e, err := s.cfg.Files.Stat(r.Context(), whoFor(u), q.Share, q.Path)
	switch {
	case isErr(err, files.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", files.ErrNotFound.Error())
		return
	case isErr(err, files.ErrNoAccess, files.ErrNotAllowed):
		s.record(r, u, "sharelink.create", target, audit.Denied, err.Error())
		writeError(w, http.StatusForbidden, "forbidden", files.ErrNoAccess.Error())
		return
	case err != nil:
		internalError(s, w, err)
		return
	}
	// Anyone who may change the folder (or file) may share it; admins any.
	if !e.Writable && !u.IsAdmin() {
		s.record(r, u, "sharelink.create", target, audit.Denied, "no write access")
		writeError(w, http.StatusForbidden, "forbidden", "you can share only files and folders you can change")
		return
	}
	if q.AllowUpload && !e.Dir {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Code: "invalid", Message: "Only links to folders can take uploads.",
			Details: []string{"Only links to folders can take uploads."}})
		return
	}
	if _, err := s.links.Prune(r.Context()); err != nil {
		s.log.Warn("prune share links", "err", err)
	}
	l, token, err := s.links.Create(r.Context(), q, e.Dir, sharelinks.Owner{ID: u.ID, Principal: u.IdentityPrincipal()})
	if err != nil {
		internalError(s, w, err)
		return
	}
	detail := "expires " + l.ExpiresAt.UTC().Format("2006-01-02")
	if l.HasPassword {
		detail += ", password"
	}
	if l.AllowUpload {
		detail += ", uploads"
	}
	if l.MaxDownloads > 0 {
		detail += ", at most " + strconv.Itoa(l.MaxDownloads) + " downloads"
	}
	s.record(r, u, "sharelink.create", target, audit.Success, "link #"+strconv.FormatInt(l.ID, 10)+": "+detail)
	writeJSON(w, http.StatusCreated, ShareLinkCreated{Link: l, URL: "/s/" + token, Token: token})
}

func (s *Server) handleShareLinkRevoke(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	l, err := s.links.Get(r.Context(), id)
	if err != nil || (l.CreatedByID != u.ID && !u.IsAdmin()) {
		// Someone else's link looks the same as no link.
		writeError(w, http.StatusNotFound, "not_found", "there's no such link")
		return
	}
	if l, err = s.links.Revoke(r.Context(), id); err != nil {
		internalError(s, w, err)
		return
	}
	s.record(r, u, "sharelink.revoke", l.Share+"/"+l.Path, audit.Success, "link #"+strconv.FormatInt(l.ID, 10)+" of "+l.CreatedBy)
	writeJSON(w, http.StatusOK, l)
}

// unavailableFiles stops every link while file access isn't wired up.
type unavailableFiles struct{ files.Access }

func (unavailableFiles) Stat(context.Context, files.Who, string, string) (*files.Entry, error) {
	return nil, files.ErrNotImplemented
}
