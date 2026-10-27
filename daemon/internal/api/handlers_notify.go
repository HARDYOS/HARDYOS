package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/notify"
)

func (s *Server) notifyRoutes() {
	if s.cfg.Notify == nil {
		return
	}
	m := s.mux
	m.Handle("GET /api/v1/notifications", s.authed(s.handleListNotifications))
	m.Handle("GET /api/v1/notifications/unread", s.authed(s.handleUnreadNotifications))
	m.Handle("POST /api/v1/notifications/{id}/read", s.authed(s.handleReadNotification))
	m.Handle("POST /api/v1/notifications/read-all", s.authed(s.handleReadAllNotifications))
	if s.cfg.Alerts == nil {
		return
	}
	// Control Panel > Notifications: where alerts go.
	m.Handle("GET /api/v1/alerts/channels", s.admin(s.handleListChannels))
	m.Handle("POST /api/v1/alerts/channels", s.admin(s.handleCreateChannel))
	m.Handle("PATCH /api/v1/alerts/channels/{id}", s.admin(s.handleUpdateChannel))
	m.Handle("DELETE /api/v1/alerts/channels/{id}", s.admin(s.handleDeleteChannel))
	m.Handle("POST /api/v1/alerts/channels/{id}/test", s.admin(s.handleTestChannel))
	m.Handle("GET /api/v1/alerts/routes", s.admin(s.handleListRoutes))
	m.Handle("PUT /api/v1/alerts/routes", s.admin(s.handleSetRoutes))
	m.Handle("GET /api/v1/alerts/settings", s.admin(s.handleAlertSettings))
	m.Handle("PUT /api/v1/alerts/settings", s.admin(s.handleSaveAlertSettings))
	m.Handle("GET /api/v1/alerts/deliveries", s.admin(s.handleDeliveries))
	m.Handle("GET /api/v1/alerts/categories", s.admin(s.handleAlertCategories))
}

func (s *Server) handleListNotifications(w http.ResponseWriter, r *http.Request, u *auth.User) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := s.cfg.Notify.ListFor(r.Context(), u.ID, u.IsAdmin(), limit)
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// UnreadCount is how many notifications someone hasn't read.
type UnreadCount struct {
	Count int `json:"count"`
}

func (s *Server) handleUnreadNotifications(w http.ResponseWriter, r *http.Request, u *auth.User) {
	n, err := s.cfg.Notify.Unread(r.Context(), u.ID, u.IsAdmin())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, UnreadCount{Count: n})
}

func (s *Server) handleReadNotification(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.cfg.Notify.MarkRead(r.Context(), u.ID, id, u.IsAdmin()); err != nil {
		internalError(s, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleReadAllNotifications(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if err := s.cfg.Notify.MarkRead(r.Context(), u.ID, 0, u.IsAdmin()); err != nil {
		internalError(s, w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) writeAlertError(w http.ResponseWriter, err error) {
	var ve *notify.ValidationError
	switch {
	case errors.As(err, &ve):
		writeError(w, http.StatusBadRequest, "invalid", ve.Msg)
	case errors.Is(err, notify.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such channel")
	default:
		internalError(s, w, err)
	}
}

func (s *Server) handleListChannels(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	list, err := s.cfg.Alerts.Channels.List(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCreateChannel(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var in notify.ChannelInput
	if !decodeJSON(w, r, &in) {
		return
	}
	ch, err := s.cfg.Alerts.Channels.Create(r.Context(), in)
	if err != nil {
		s.record(r, u, "alerts.channel.create", in.Type+" "+in.Name, audit.Failure, err.Error())
		s.writeAlertError(w, err)
		return
	}
	s.record(r, u, "alerts.channel.create", strconv.FormatInt(ch.ID, 10)+" "+ch.Type+" "+ch.Name, audit.Success, "")
	writeJSON(w, http.StatusCreated, ch)
}

// secretsChanged names which secrets a request replaces (for the audit
// log; never the values).
func secretsChanged(in *notify.SecretsInput) string {
	if in == nil {
		return ""
	}
	var out string
	for name, set := range map[string]bool{"url": in.URL != nil, "password": in.Password != nil, "secretAccessKey": in.SecretAccessKey != nil} {
		if set {
			out += " " + name
		}
	}
	if out == "" {
		return ""
	}
	return "secrets changed:" + out
}

func (s *Server) handleUpdateChannel(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in notify.ChannelInput
	if !decodeJSON(w, r, &in) {
		return
	}
	old, err := s.cfg.Alerts.Channels.Get(r.Context(), id)
	if err != nil {
		s.writeAlertError(w, err)
		return
	}
	ch, err := s.cfg.Alerts.Channels.Update(r.Context(), id, in)
	if err != nil {
		s.record(r, u, "alerts.channel.update", strconv.FormatInt(id, 10), audit.Failure, err.Error())
		s.writeAlertError(w, err)
		return
	}
	detail := secretsChanged(in.Secrets)
	if notify.DestinationChanged(ch.Type, old.Config, ch.Config) {
		detail = strings.TrimSpace("destination changed " + detail)
	}
	s.record(r, u, "alerts.channel.update", strconv.FormatInt(id, 10)+" "+ch.Name, audit.Success, detail)
	writeJSON(w, http.StatusOK, ch)
}

func (s *Server) handleDeleteChannel(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.cfg.Alerts.Channels.Delete(r.Context(), id); err != nil {
		s.record(r, u, "alerts.channel.delete", strconv.FormatInt(id, 10), audit.Failure, err.Error())
		s.writeAlertError(w, err)
		return
	}
	s.record(r, u, "alerts.channel.delete", strconv.FormatInt(id, 10), audit.Success, "")
	w.WriteHeader(http.StatusNoContent)
}

// ChannelTestResult is how a test message went.
type ChannelTestResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func (s *Server) handleTestChannel(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	err := s.cfg.Alerts.Test(r.Context(), id)
	if errors.Is(err, notify.ErrNotFound) {
		s.writeAlertError(w, err)
		return
	}
	res := ChannelTestResult{OK: err == nil}
	outcome := audit.Success
	if err != nil {
		res.Error, outcome = err.Error(), audit.Failure
	}
	s.record(r, u, "alerts.channel.test", strconv.FormatInt(id, 10), outcome, res.Error)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	routes, err := s.cfg.Alerts.Channels.Routes(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, routes)
}

type routesRequest struct {
	Routes []notify.Route `json:"routes"`
}

func (s *Server) handleSetRoutes(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req routesRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Routes == nil {
		req.Routes = []notify.Route{}
	}
	if err := s.cfg.Alerts.Channels.SetRoutes(r.Context(), req.Routes); err != nil {
		s.record(r, u, "alerts.routes.save", strconv.Itoa(len(req.Routes))+" rules", audit.Failure, err.Error())
		s.writeAlertError(w, err)
		return
	}
	s.record(r, u, "alerts.routes.save", strconv.Itoa(len(req.Routes))+" rules", audit.Success, "")
	s.handleListRoutes(w, r, u)
}

func (s *Server) handleAlertSettings(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	writeJSON(w, http.StatusOK, s.cfg.Alerts.Settings(r.Context()))
}

func (s *Server) handleSaveAlertSettings(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var st notify.Settings
	if !decodeJSON(w, r, &st) {
		return
	}
	saved, err := s.cfg.Alerts.SaveSettings(r.Context(), st)
	if err != nil {
		s.record(r, u, "alerts.settings.save", "", audit.Failure, err.Error())
		s.writeAlertError(w, err)
		return
	}
	s.record(r, u, "alerts.settings.save", "", audit.Success, "quiet hours "+strconv.FormatBool(saved.QuietHours.Enabled))
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) handleDeliveries(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := s.cfg.Alerts.Deliveries(r.Context(), limit)
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// AlertCategory is a row of the routing table.
type AlertCategory struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// alertCategories are the routing categories (an event's kind before the
// first dot). "*" is everything not listed.
var alertCategories = []AlertCategory{
	{"disk", "Disks", "SMART health, temperature and self-tests"},
	{"pool", "Pools", "Pool health, disk errors, scrubs and space"},
	{"ups", "UPS", "Power cuts, low battery and shutdowns"},
	{"backup", "Backups", "Backup runs that fail or finish"},
	{"replication", "Replication", "Replication to and from other servers"},
	{"app", "Apps", "Apps that crash, restart over and over or fail health checks"},
	{"vm", "Virtual machines", "VMs that crash or stop unexpectedly"},
	{"remote", "Remote access", "NetBird connection and published apps"},
	{"domain", "Domain", "Domain controller replication"},
	{"system", "System", "Updates, the root helper, temperatures and other notices"},
	{"*", "Everything else", "Any other kind of alert"},
}

func (s *Server) handleAlertCategories(w http.ResponseWriter, _ *http.Request, _ *auth.User) {
	writeJSON(w, http.StatusOK, alertCategories)
}
