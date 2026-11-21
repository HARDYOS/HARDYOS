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
	writeJSON(w, http.StatusOK, res)
}
