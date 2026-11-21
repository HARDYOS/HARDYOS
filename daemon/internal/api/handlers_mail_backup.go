package api

import (
	"net/http"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cloudbackup"
	"github.com/hardyos/hardyos/daemon/internal/mail"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// Mail in cloud backups and replication (decisions 460-469): what a
// version of the mail holds, and the checks every mail restore request
// gets before it becomes a job (hardyd-priv checks them again).

// checkMailRestore validates what of the mail to restore; overwriting and
// restoring everything need their confirmation typed.
func checkMailRestore(w http.ResponseWriter, a *mail.RestoreArgs) bool {
	if a == nil {
		writeError(w, http.StatusBadRequest, "invalid", "choose what of the mail to restore")
		return false
	}
	if err := a.Check(); err != nil {
		code := "invalid"
		if a.Mode == mail.RestoreOverwrite || a.Scope == mail.ScopeAll {
			code = "confirm_required"
		}
		writeError(w, http.StatusBadRequest, code, err.Error())
		return false
	}
	return true
}

// describeMailRestore is a mail restore in the audit log.
func describeMailRestore(a *mail.RestoreArgs) string {
	if a == nil {
		return ""
	}
	d := " mail " + a.Scope + " " + a.Mode
	switch a.Scope {
	case mail.ScopeMailbox, mail.ScopeCalendars:
		d += " " + a.Key
		if a.Into != a.Key {
			d += " into " + a.Into
		}
	case mail.ScopeDomain:
		d += " " + a.Domain
	}
	return d
}

// handleMailRestoreTargets lists this server's mailboxes by storage key,
// what a restore puts a version's mailbox into (admin).
// mailContentsResponse is a version's (or this server's) mailboxes and the
// room the mail storage has now, for the restore's estimate.
type mailContentsResponse struct {
	cloudbackup.MailContents
	FreeBytes *int64 `json:"freeBytes,omitempty"`
}

// mailFree asks root for the mail dataset's free space (nil if unknown).
func (s *Server) mailFree(r *http.Request) *int64 {
	var sp mail.Space
	if s.cfg.Priv == nil || s.cfg.Priv.Call(r.Context(), mail.OpSpace, nil, &sp) != nil {
		return nil
	}
	return &sp.FreeBytes
}

func (s *Server) handleMailRestoreTargets(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	svc := s.mailSvc()
	out := cloudbackup.MailContents{Contents: mail.Contents{Domains: []string{}, Mailboxes: []mail.ContentsMailbox{}}}
	if svc == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	mbs, err := svc.Store.Mailboxes(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	doms, err := svc.Store.Domains(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	for _, d := range doms {
		out.Domains = append(out.Domains, d.Name)
	}
	for _, m := range mbs {
		if !m.Deleting && mail.ValidMailboxKey(m.Key) {
			out.Mailboxes = append(out.Mailboxes, mail.ContentsMailbox{Key: m.Key, Address: m.Address})
		}
	}
	if st, err := svc.Store.LoadSettings(r.Context()); err == nil {
		out.Hostname = st.Hostname
	}
	writeJSON(w, http.StatusOK, mailContentsResponse{MailContents: out, FreeBytes: s.mailFree(r)})
}

func (s *Server) handleCloudMailContents(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var res cloudbackup.MailContents
	if err := s.cfg.Priv.Call(r.Context(), priv.OpCloudMailContents, cloudbackup.MailContentsArgs{Target: r.PathValue("id"), Snapshot: r.URL.Query().Get("snapshot")}, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	if res.Domains == nil {
		res.Domains = []string{}
	}
	if res.Mailboxes == nil {
		res.Mailboxes = []mail.ContentsMailbox{}
	}
	writeJSON(w, http.StatusOK, mailContentsResponse{MailContents: res, FreeBytes: s.mailFree(r)})
}
