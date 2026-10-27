package api

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/mail"
	"github.com/hardyos/hardyos/daemon/internal/mail/manage"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/store"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// The family mail server (docs/mail.md): Control Panel › Mail, the "Set up
// my phone or computer" page, mail app settings for anyone, calendars and
// contacts at /dav-mail/, and hardyd's mail sign-in listener for Dovecot.

// Mail job kinds (all locked on "mail": one change at a time).
const (
	JobKindMailApply    = "mail.apply"
	JobKindMailDisable  = "mail.disable"
	JobKindMailDelete   = "mail.mailbox.delete"
	JobKindMailCert     = "mail.certificate"
	JobKindMailCertUp   = "mail.certificate.upload"
	JobKindMailPublish  = "mail.dns.publish"
	JobKindMailSES      = "mail.ses.verify"
	JobKindMailSync     = "mail.sync"
	JobKindMailQueueRun = "mail.queue.flush"
)

// WebmailAppID is the catalog app the Mail app is (Roundcube): its window
// proxy signs the person in to their mailbox.
const WebmailAppID = "roundcube"

// RegisterMailJobs adds the mail server's job kinds.
func RegisterMailJobs(m *jobs.Manager, svc *manage.Service, pc *priv.Client) {
	if svc == nil {
		return
	}
	lock := func(json.RawMessage) string { return "mail" }
	apply := func(jc *jobs.Context) (any, error) {
		ctx, cancel := context.WithTimeout(jc, 5*time.Minute)
		defer cancel()
		return svc.Apply(ctx, jc.Progress)
	}
	m.Register(jobs.Kind{Name: JobKindMailApply, AdminOnly: true, LockKey: lock, Run: apply})
	m.Register(jobs.Kind{Name: JobKindMailDisable, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		jc.Progress(30, "Stopping the mail server (mail stays on the pool)")
		if err := pc.Call(jc, mail.OpStop, nil, nil); err != nil {
			return nil, err
		}
		return map[string]string{"message": "The mail server is off. Mailboxes and messages are kept."}, nil
	}})
	m.Register(jobs.Kind{Name: JobKindMailSync, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		jc.Progress(20, "Looking at the domain's accounts")
		res, err := svc.SyncAccounts(jc)
		if err != nil {
			return nil, err
		}
		if _, err := apply(jc); err != nil {
			return nil, err
		}
		return res, nil
	}})
	m.Register(jobs.Kind{Name: JobKindMailDelete, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p mailDeleteParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		st, err := svc.Store.LoadSettings(jc)
		if err != nil {
			return nil, err
		}
		mb, err := svc.Store.GetMailbox(jc, p.ID)
		if err != nil {
			return nil, err
		}
		if mb.Address != p.Address {
			return nil, errors.New("the mailbox's address changed; delete it again")
		}
		jc.Progress(20, "Removing the mailbox from the mail server")
		if err := svc.Store.DeleteMailboxRow(jc, p.ID); err != nil {
			return nil, err
		}
		if err := svc.Store.PruneGroups(jc, mb.Address); err != nil {
			return nil, err
		}
		if st.Enabled {
			if _, err := apply(jc); err != nil {
				return nil, err
			}
		}
		if st.Pool != "" {
			jc.Progress(70, "Deleting its messages")
			if err := pc.Call(jc, mail.OpDelete, mail.DeleteArgs{Pool: st.Pool, Address: mb.Address, Confirm: mb.Address}, nil); err != nil {
				return nil, err
			}
		}
		return map[string]string{"message": "Deleted " + mb.Address + " and its messages."}, nil
	}})
	m.Register(jobs.Kind{Name: JobKindMailCert, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p struct {
			Force bool `json:"force"`
		}
		_ = jc.Params(&p)
		ctx, cancel := context.WithTimeout(jc, 10*time.Minute)
		defer cancel()
		return svc.RenewCertificate(ctx, p.Force, jc.Progress)
	}})
	m.Register(jobs.Kind{Name: JobKindMailCertUp, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p struct {
			SecretRef string `json:"secretRef"`
		}
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		raw, ok := jobSecrets.take(p.SecretRef)
		if !ok {
			return nil, errors.New("the certificate is no longer waiting (hardyd restarted?); upload it again")
		}
		var up mailCertUpload
		if err := json.Unmarshal([]byte(raw), &up); err != nil {
			return nil, err
		}
		jc.Progress(50, "Installing the certificate")
		return svc.UploadCertificate(jc, up.Chain, up.Key)
	}})
	m.Register(jobs.Kind{Name: JobKindMailPublish, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p mailDomainParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(30, "Writing the records into Cloudflare")
		return svc.PublishDNS(jc, p.Domain)
	}})
	m.Register(jobs.Kind{Name: JobKindMailSES, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		var p mailDomainParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(30, "Asking Amazon SES")
		return svc.SESVerify(jc, p.Domain)
	}})
	m.Register(jobs.Kind{Name: JobKindMailQueueRun, AdminOnly: true, LockKey: lock, Run: func(jc *jobs.Context) (any, error) {
		jc.Progress(50, "Retrying waiting mail")
		if err := pc.Call(jc, mail.OpFlush, nil, nil); err != nil {
			return nil, err
		}
		return map[string]string{"message": "Waiting mail is being retried."}, nil
	}})
}

type mailDeleteParams struct {
	ID      int64  `json:"id"`
	Address string `json:"address"`
}

type mailDomainParams struct {
	Domain string `json:"domain"`
}

type mailCertUpload struct {
	Chain string `json:"chain"`
	Key   string `json:"key"`
}

func (s *Server) mailRoutes() {
	if s.cfg.Mail == nil {
		return
	}
	m := s.mux
	m.Handle("GET /api/v1/mail", s.admin(s.handleMailOverview))
	m.Handle("PUT /api/v1/mail/settings", s.admin(s.handleMailSettings))
	m.Handle("POST /api/v1/mail/apply", s.admin(s.handleMailApply))
	m.Handle("GET /api/v1/mail/domains", s.admin(s.handleMailDomains))
	m.Handle("POST /api/v1/mail/domains", s.admin(s.handleMailDomainAdd))
	m.Handle("PATCH /api/v1/mail/domains/{name}", s.admin(s.handleMailDomainUpdate))
	m.Handle("DELETE /api/v1/mail/domains/{name}", s.admin(s.handleMailDomainDelete))
	m.Handle("GET /api/v1/mail/domains/{name}/dns", s.admin(s.handleMailDNS))
	m.Handle("POST /api/v1/mail/domains/{name}/check", s.admin(s.handleMailDNSCheck))
	m.Handle("POST /api/v1/mail/domains/{name}/publish", s.admin(s.handleMailDNSPublish))
	m.Handle("POST /api/v1/mail/domains/{name}/ses", s.admin(s.handleMailSESVerify))
	m.Handle("GET /api/v1/mail/ses", s.admin(s.handleMailSES))
	m.Handle("GET /api/v1/mail/vps", s.admin(s.handleMailVPS))
	m.Handle("POST /api/v1/mail/vps/check", s.admin(s.handleMailVPSCheck))
	m.Handle("GET /api/v1/mail/mailboxes", s.admin(s.handleMailMailboxes))
	m.Handle("POST /api/v1/mail/mailboxes/sync", s.admin(s.handleMailSync))
	m.Handle("PATCH /api/v1/mail/mailboxes/{id}", s.admin(s.handleMailMailboxUpdate))
	m.Handle("DELETE /api/v1/mail/mailboxes/{id}", s.admin(s.handleMailMailboxDelete))
	m.Handle("GET /api/v1/mail/groups", s.admin(s.handleMailGroups))
	m.Handle("PUT /api/v1/mail/groups/{address}", s.admin(s.handleMailGroupSet))
	m.Handle("DELETE /api/v1/mail/groups/{address}", s.admin(s.handleMailGroupDelete))
	m.Handle("GET /api/v1/mail/queue", s.admin(s.handleMailQueue))
	m.Handle("POST /api/v1/mail/queue/flush", s.admin(s.handleMailQueueFlush))
	m.Handle("POST /api/v1/mail/certificate", s.admin(s.handleMailCertRenew))
	m.Handle("PUT /api/v1/mail/certificate", s.admin(s.handleMailCertUpload))
	// Everyone signed in: their own mailbox and how to set up their devices.
	m.Handle("GET /api/v1/mail/me", s.authed(s.handleMailMe))
	m.Handle("GET /api/v1/mail/me/profile", s.authed(s.handleMailProfile))
	// No sign-in: what mail apps ask for (server names and ports only).
	m.HandleFunc("GET /.well-known/autoconfig/mail/config-v1.1.xml", s.handleAutoconfig)
	m.HandleFunc("GET /mail/config-v1.1.xml", s.handleAutoconfig)
	m.HandleFunc("/autodiscover/autodiscover.xml", s.handleAutodiscover)
	m.HandleFunc("/Autodiscover/Autodiscover.xml", s.handleAutodiscover)
	m.HandleFunc("/.well-known/caldav", s.handleDAVWellKnown)
	m.HandleFunc("/.well-known/carddav", s.handleDAVWellKnown)
	// Calendars and contacts: each request signed in with the person's own
	// mail password (Basic over HTTPS), then handed to Radicale.
	m.HandleFunc(mail.DAVPath, s.handleMailDAV)
}

// mailPublicPath reports whether path is something mail.<base> serves.
func mailPublicPath(p string) bool {
	switch p {
	case "/.well-known/autoconfig/mail/config-v1.1.xml", "/mail/config-v1.1.xml",
		"/autodiscover/autodiscover.xml", "/Autodiscover/Autodiscover.xml",
		"/.well-known/caldav", "/.well-known/carddav":
		return true
	}
	return strings.HasPrefix(p, mail.DAVPath)
}

func (s *Server) mailSvc() *manage.Service { return s.cfg.Mail }

// writeMailError answers a mail error: validation (400), missing (404),
// the root helper's errors, or a 500.
func (s *Server) writeMailError(w http.ResponseWriter, err error) {
	var ve *mail.ValidationError
	switch {
	case errors.As(err, &ve):
		writeError(w, http.StatusBadRequest, "invalid", ve.Msg)
	case errors.Is(err, manage.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such mail domain, mailbox or group")
	default:
		var pe *priv.Error
		if errors.As(err, &pe) {
			s.writePrivError(w, err)
			return
		}
		var se *manage.SESError
		var ce *manage.CFError
		if errors.As(err, &se) || errors.As(err, &ce) {
			writeError(w, http.StatusBadGateway, "upstream", err.Error())
			return
		}
		internalError(s, w, err)
	}
}

// mailApplyIfOn queues an apply when the server is on (the change is
// saved either way) and answers with the job, or with v.
func (s *Server) mailApplyIfOn(w http.ResponseWriter, r *http.Request, u *auth.User, action, target string, v any) {
	st, err := s.mailSvc().Store.LoadSettings(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	if !st.Enabled {
		s.record(r, u, action, target, audit.Success, "saved; the mail server is off")
		writeJSON(w, http.StatusOK, v)
		return
	}
	s.submit(w, r, u, JobKindMailApply, "Update the mail server", map[string]string{"reason": action}, action, target, nil)
}

// MailOverview is Control Panel › Mail's first page.
type MailOverview struct {
	Settings         manage.Settings `json:"settings"`
	SESSecretSet     bool            `json:"sesSecretSet"`
	CloudflareSet    bool            `json:"cloudflareTokenSet"`
	Status           *mail.Status    `json:"status,omitempty"`
	StatusError      string          `json:"statusError,omitempty"`
	Domains          []manage.Domain `json:"domains"`
	MailboxCount     int             `json:"mailboxCount"`
	NetBirdAddress   string          `json:"netbirdAddress"`
	WebmailInstalled bool            `json:"webmailInstalled"`
	Pools            []string        `json:"pools"`
	PublishedURL     string          `json:"publishedUrl"`
}

func (s *Server) mailNetBirdAddr(ctx context.Context) string {
	in, _, _ := remoteInputs(ctx, s.cfg.Priv, s.cfg.DB)
	return in.NetBirdIP
}

func (s *Server) handleMailOverview(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	ctx := r.Context()
	svc := s.mailSvc()
	st, err := svc.Store.LoadSettings(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	doms, err := svc.Store.Domains(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	mbs, err := svc.Store.Mailboxes(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	o := MailOverview{Settings: st, Domains: doms, MailboxCount: len(mbs), Pools: []string{},
		SESSecretSet: svc.Store.HasSecret(ctx, manage.SecretSES), CloudflareSet: svc.Store.HasSecret(ctx, manage.SecretCloudflare)}
	if s.cfg.Priv != nil {
		var status mail.Status
		if err := s.cfg.Priv.Call(ctx, mail.OpStatus, mail.StatusArgs{Pool: st.Pool}, &status); err != nil {
			o.StatusError = err.Error()
		} else {
			o.Status = &status
		}
		var pools []zfs.Pool
		if err := s.cfg.Priv.Call(ctx, priv.OpPools, nil, &pools); err == nil {
			for _, p := range pools {
				o.Pools = append(o.Pools, p.Name)
			}
		}
		o.NetBirdAddress = s.mailNetBirdAddr(ctx)
		if ov, err := s.appsStatus(ctx); err == nil {
			for _, a := range ov.Apps {
				if a.ID == WebmailAppID && a.Source == apps.SourceCatalog {
					o.WebmailInstalled = true
				}
			}
		}
	}
	if s.cfg.Remote != nil {
		if ps, err := s.cfg.Remote.Store.Load(ctx); err == nil && ps.Enabled {
			if label, ok := mailLabel(st, ps.BaseDomain); ok {
				o.PublishedURL = "https://" + label + "." + ps.BaseDomain
			}
		}
	}
	writeJSON(w, http.StatusOK, o)
}

// MailSettingsRequest saves settings and, optionally, secrets (nil keeps a
// secret, "" removes it).
type MailSettingsRequest struct {
	Settings        manage.Settings `json:"settings"`
	SESSecretKey    *string         `json:"sesSecretKey,omitempty"`
	CloudflareToken *string         `json:"cloudflareToken,omitempty"`
}

func (s *Server) handleMailSettings(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req MailSettingsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ctx := r.Context()
	svc := s.mailSvc()
	prev, err := svc.Store.LoadSettings(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	doms, err := svc.Store.Domains(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	st, err := manage.ValidateSettings(req.Settings, doms)
	if err != nil {
		s.record(r, u, "mail.settings", "", audit.Failure, err.Error())
		s.writeMailError(w, err)
		return
	}
	if req.CloudflareToken != nil && *req.CloudflareToken != "" {
		tok := strings.TrimSpace(*req.CloudflareToken)
		if len(tok) > 200 || strings.ContainsAny(tok, " \r\n") {
			writeError(w, http.StatusBadRequest, "invalid", "the Cloudflare token isn't valid")
			return
		}
		vctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := manage.VerifyCloudflare(vctx, tok)
		cancel()
		if err != nil {
			s.record(r, u, "mail.settings", "cloudflare", audit.Failure, err.Error())
			writeError(w, http.StatusBadRequest, "invalid", "Cloudflare didn't accept the token: "+err.Error())
			return
		}
		*req.CloudflareToken = tok
	}
	if req.SESSecretKey != nil && *req.SESSecretKey != "" {
		k := strings.TrimSpace(*req.SESSecretKey)
		if len(k) < 16 || len(k) > 128 || strings.ContainsAny(k, " \r\n") {
			writeError(w, http.StatusBadRequest, "invalid", "the secret access key isn't valid")
			return
		}
		*req.SESSecretKey = k
	}
	// A stored secret only goes where it was entered for (decision 216):
	// a new region or access key needs the secret key again.
	if (st.SESRegion != prev.SESRegion || st.SESAccessID != prev.SESAccessID) && prev.SESAccessID != "" &&
		svc.Store.HasSecret(ctx, manage.SecretSES) && (req.SESSecretKey == nil || *req.SESSecretKey == "") {
		writeError(w, http.StatusBadRequest, "secret_required", "enter the secret access key again for the new region or access key")
		return
	}
	if st.TLSMode == "acme" && !svc.Store.HasSecret(ctx, manage.SecretCloudflare) && (req.CloudflareToken == nil || *req.CloudflareToken == "") {
		writeError(w, http.StatusBadRequest, "invalid", "Let's Encrypt certificates need a Cloudflare API token (DNS challenge)")
		return
	}
	for name, v := range map[string]*string{manage.SecretSES: req.SESSecretKey, manage.SecretCloudflare: req.CloudflareToken} {
		if v != nil {
			if err := svc.Store.SetSecret(ctx, name, *v); err != nil {
				internalError(s, w, err)
				return
			}
		}
	}
	if err := svc.Store.SaveSettings(ctx, st); err != nil {
		internalError(s, w, err)
		return
	}
	detail := fmt.Sprintf("enabled=%v pool=%s host=%s vps=%s ses=%s/%s clamav=%v tls=%s", st.Enabled, st.Pool, st.Hostname,
		st.VPSPeer, st.SESRegion, st.SESAccessID, st.ClamAV, st.TLSMode)
	if req.SESSecretKey != nil {
		detail += " ses-secret-changed"
	}
	if req.CloudflareToken != nil {
		detail += " cloudflare-token-changed"
	}
	switch {
	case st.Enabled:
		s.submit(w, r, u, JobKindMailApply, "Set up the mail server", map[string]string{"reason": "settings"}, "mail.settings", detail, nil)
	case prev.Enabled:
		s.submit(w, r, u, JobKindMailDisable, "Turn the mail server off", map[string]string{}, "mail.settings", detail, nil)
	default:
		s.record(r, u, "mail.settings", "", audit.Success, detail)
		writeJSON(w, http.StatusOK, st)
	}
}

func (s *Server) handleMailApply(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.submit(w, r, u, JobKindMailApply, "Update the mail server", map[string]string{"reason": "manual"}, "mail.apply", "", nil)
}

func (s *Server) handleMailDomains(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	doms, err := s.mailSvc().Store.Domains(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, doms)
}

// MailDomainRequest adds a domain.
type MailDomainRequest struct {
	Name        string `json:"name"`
	DMARCPolicy string `json:"dmarcPolicy"`
	Cloudflare  bool   `json:"cloudflare"`
}

func (s *Server) handleMailDomainAdd(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req MailDomainRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	name := strings.ToLower(strings.TrimSpace(req.Name))
	svc := s.mailSvc()
	d, err := svc.Store.AddDomain(r.Context(), name, req.DMARCPolicy, req.Cloudflare)
	if err != nil {
		s.record(r, u, "mail.domain.add", name, audit.Failure, err.Error())
		s.writeMailError(w, err)
		return
	}
	// The first domain becomes the default for new mailboxes.
	if st, err := svc.Store.LoadSettings(r.Context()); err == nil && st.DefaultDomain == "" {
		st.DefaultDomain = d.Name
		_ = svc.Store.SaveSettings(r.Context(), st)
	}
	s.mailApplyIfOn(w, r, u, "mail.domain.add", d.Name, d)
}

func (s *Server) handleMailDomainUpdate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req manage.DomainUpdate
	if !decodeJSON(w, r, &req) {
		return
	}
	name := r.PathValue("name")
	d, err := s.mailSvc().Store.UpdateDomain(r.Context(), name, req)
	if err != nil {
		s.record(r, u, "mail.domain.update", name, audit.Failure, err.Error())
		s.writeMailError(w, err)
		return
	}
	b, _ := json.Marshal(req)
	if req.RotateDKIM {
		s.record(r, u, "mail.dkim.rotate", name, audit.Success, "new selector "+d.Selector)
	}
	s.mailApplyIfOn(w, r, u, "mail.domain.update", name+" "+string(b), d)
}

// ConfirmRequest carries a typed confirmation.
type ConfirmRequest struct {
	Confirm string `json:"confirm"`
}

func (s *Server) handleMailDomainDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	name := r.PathValue("name")
	var req ConfirmRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Confirm != name {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the domain's name to remove it")
		return
	}
	svc := s.mailSvc()
	if err := svc.Store.DeleteDomain(r.Context(), name); err != nil {
		s.record(r, u, "mail.domain.delete", name, audit.Failure, err.Error())
		s.writeMailError(w, err)
		return
	}
	if st, err := svc.Store.LoadSettings(r.Context()); err == nil && st.DefaultDomain == name {
		st.DefaultDomain = ""
		if doms, _ := svc.Store.Domains(r.Context()); len(doms) > 0 {
			st.DefaultDomain = doms[0].Name
		}
		_ = svc.Store.SaveSettings(r.Context(), st)
	}
	s.mailApplyIfOn(w, r, u, "mail.domain.delete", name, map[string]bool{"deleted": true})
}

// MailDNS is a domain's records with the last check.
type MailDNS struct {
	Domain    string            `json:"domain"`
	Records   []mail.Record     `json:"records"`
	LastCheck *manage.DNSState  `json:"lastCheck,omitempty"`
	MTASTS    string            `json:"mtaStsPolicy,omitempty"`
	Missing   map[string]string `json:"missing"`
}

func (s *Server) handleMailDNS(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	svc := s.mailSvc()
	d, err := svc.Store.GetDomain(r.Context(), r.PathValue("name"))
	if err != nil {
		s.writeMailError(w, err)
		return
	}
	recs, err := svc.DomainRecords(r.Context(), d)
	if err != nil {
		internalError(s, w, err)
		return
	}
	st, _ := svc.Store.LoadSettings(r.Context())
	out := MailDNS{Domain: d.Name, Records: recs, LastCheck: d.LastCheck, Missing: map[string]string{}}
	if d.MTASTS != "off" {
		out.MTASTS = mail.MTASTSPolicy(d.MTASTS, st.Hostname)
	}
	if st.Hostname == "" {
		out.Missing["hostname"] = "Set the mail server's name to see the MX record."
	}
	if d.DKIMPublic == "" {
		out.Missing["dkim"] = "The DKIM key is made when the mail server is turned on."
	}
	if st.SESAccessID != "" && len(d.SESDKIM) == 0 {
		out.Missing["ses"] = "Verify the domain with Amazon SES to see its records."
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleMailDNSCheck(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	st, err := s.mailSvc().CheckDomain(ctx, r.PathValue("name"))
	if err != nil {
		s.writeMailError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleMailDNSPublish(w http.ResponseWriter, r *http.Request, u *auth.User) {
	name := r.PathValue("name")
	if _, err := s.mailSvc().Store.GetDomain(r.Context(), name); err != nil {
		s.writeMailError(w, err)
		return
	}
	s.submit(w, r, u, JobKindMailPublish, "Publish "+name+"'s mail records in Cloudflare", mailDomainParams{Domain: name}, "mail.dns.publish", name, nil)
}

func (s *Server) handleMailSESVerify(w http.ResponseWriter, r *http.Request, u *auth.User) {
	name := r.PathValue("name")
	if _, err := s.mailSvc().Store.GetDomain(r.Context(), name); err != nil {
		s.writeMailError(w, err)
		return
	}
	s.submit(w, r, u, JobKindMailSES, "Verify "+name+" with Amazon SES", mailDomainParams{Domain: name}, "mail.ses.verify", name, nil)
}

func (s *Server) handleMailSES(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	st, err := s.mailSvc().SESState(ctx)
	if err != nil {
		s.writeMailError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// MailVPS is the VPS page: what to run there.
type MailVPS struct {
	Script     string `json:"script"`
	Problem    string `json:"problem,omitempty"`
	HomePeer   string `json:"homePeer"`
	Hostname   string `json:"hostname"`
	RelayPort  int    `json:"relayPort"`
	ProxyPorts []int  `json:"proxyPorts"`
}

func (s *Server) handleMailVPS(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	svc := s.mailSvc()
	st, _ := svc.Store.LoadSettings(r.Context())
	out := MailVPS{HomePeer: s.mailNetBirdAddr(r.Context()), Hostname: st.Hostname, RelayPort: mail.PortRelay,
		ProxyPorts: []int{mail.PortProxyIMAPS, mail.PortProxySubms, mail.PortProxySubm}}
	script, err := svc.VPSScriptFor(r.Context())
	if err != nil {
		var ve *mail.ValidationError
		if !errors.As(err, &ve) {
			internalError(s, w, err)
			return
		}
		out.Problem = ve.Msg
	}
	out.Script = script
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleMailVPSCheck(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	checks, err := s.mailSvc().CheckVPSNow(ctx)
	if err != nil {
		s.writeMailError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, checks)
}

// MailboxView is a mailbox with its use.
type MailboxView struct {
	manage.Mailbox
	UsedKB int64 `json:"usedKb"`
}

func (s *Server) handleMailMailboxes(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	svc := s.mailSvc()
	mbs, err := svc.Store.Mailboxes(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	used := map[string]int64{}
	if st, _ := svc.Store.LoadSettings(r.Context()); st.Enabled && s.cfg.Priv != nil && len(mbs) > 0 {
		var addrs []string
		for _, m := range mbs {
			addrs = append(addrs, m.Address)
		}
		var us []mail.Usage
		if err := s.cfg.Priv.Call(r.Context(), mail.OpUsage, mail.UsageArgs{Addresses: addrs}, &us); err == nil {
			for _, u := range us {
				used[u.Address] = u.UsedKB
			}
		}
	}
	out := []MailboxView{}
	for _, m := range mbs {
		out = append(out, MailboxView{Mailbox: m, UsedKB: used[m.Address]})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleMailSync(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.submit(w, r, u, JobKindMailSync, "Give every account a mailbox", map[string]string{}, "mail.sync", "", nil)
}

func (s *Server) handleMailMailboxUpdate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req manage.MailboxUpdate
	if !decodeJSON(w, r, &req) {
		return
	}
	m, err := s.mailSvc().Store.UpdateMailbox(r.Context(), id, req)
	if err != nil {
		s.record(r, u, "mail.mailbox.update", fmt.Sprint(id), audit.Failure, err.Error())
		s.writeMailError(w, err)
		return
	}
	b, _ := json.Marshal(req)
	if !m.CanSignIn() && s.cfg.Priv != nil {
		_ = s.cfg.Priv.Call(r.Context(), mail.OpKick, mail.AddressArgs{Address: m.Address}, nil)
	}
	s.mailApplyIfOn(w, r, u, "mail.mailbox.update", m.Address+" "+string(b), m)
}

func (s *Server) handleMailMailboxDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req ConfirmRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	m, err := s.mailSvc().Store.GetMailbox(r.Context(), id)
	if err != nil {
		s.writeMailError(w, err)
		return
	}
	if req.Confirm != m.Address {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the mailbox's address to delete it and every message in it")
		return
	}
	if m.AccountState == "active" {
		writeError(w, http.StatusConflict, "refused", "the account still exists: turn the mailbox off instead, or delete the account in Control Panel › Domain first")
		return
	}
	s.submit(w, r, u, JobKindMailDelete, "Delete the mailbox "+m.Address, mailDeleteParams{ID: m.ID, Address: m.Address}, "mail.mailbox.delete", m.Address, nil)
}

func (s *Server) handleMailGroups(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	gs, err := s.mailSvc().Store.Groups(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, gs)
}

// MailGroupRequest sets a group address's mailboxes.
type MailGroupRequest struct {
	Targets []string `json:"targets"`
}

func (s *Server) handleMailGroupSet(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req MailGroupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	addr := r.PathValue("address")
	g, err := s.mailSvc().Store.SetGroup(r.Context(), manage.Group{Address: addr, Targets: req.Targets})
	if err != nil {
		s.record(r, u, "mail.group.set", addr, audit.Failure, err.Error())
		s.writeMailError(w, err)
		return
	}
	s.mailApplyIfOn(w, r, u, "mail.group.set", g.Address+" "+strings.Join(g.Targets, ","), g)
}

func (s *Server) handleMailGroupDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	addr := r.PathValue("address")
	if err := s.mailSvc().Store.DeleteGroup(r.Context(), addr); err != nil {
		s.writeMailError(w, err)
		return
	}
	s.mailApplyIfOn(w, r, u, "mail.group.delete", addr, map[string]bool{"deleted": true})
}

func (s *Server) handleMailQueue(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	st, _ := s.mailSvc().Store.LoadSettings(r.Context())
	var status mail.Status
	if err := s.cfg.Priv.Call(r.Context(), mail.OpStatus, mail.StatusArgs{Pool: st.Pool}, &status); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status.Queue)
}

func (s *Server) handleMailQueueFlush(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.submit(w, r, u, JobKindMailQueueRun, "Retry waiting mail", map[string]string{}, "mail.queue.flush", "", nil)
}

func (s *Server) handleMailCertRenew(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req struct {
		Force bool `json:"force"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &req) {
		return
	}
	s.submit(w, r, u, JobKindMailCert, "Get the mail server's certificate", map[string]bool{"force": req.Force}, "mail.certificate", "", nil)
}

func (s *Server) handleMailCertUpload(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req mailCertUpload
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Chain) > 256<<10 || len(req.Key) > 64<<10 || req.Chain == "" || req.Key == "" {
		writeError(w, http.StatusBadRequest, "invalid", "paste the certificate chain and its private key (PEM)")
		return
	}
	b, _ := json.Marshal(req)
	ref := jobSecrets.put(string(b))
	s.submit(w, r, u, JobKindMailCertUp, "Install the mail server's certificate", map[string]string{"secretRef": ref}, "mail.certificate.upload", "", nil)
}

// ---- the person's own mailbox ----

// accountOf is a domain account's name for a HardyOS user ("" for local
// accounts).
func accountOf(u *auth.User) string {
	if u == nil || u.IdentitySource() != auth.SourceDomain {
		return ""
	}
	name := u.Username
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		name = name[i+1:]
	}
	return strings.ToLower(name)
}

// MailMe is the "Set up my phone or computer" page.
type MailMe struct {
	Enabled          bool                 `json:"enabled"`
	Mailbox          *manage.Mailbox      `json:"mailbox,omitempty"`
	UsedKB           int64                `json:"usedKb"`
	Settings         *mail.ManualSettings `json:"settings,omitempty"`
	WebmailInstalled bool                 `json:"webmailInstalled"`
	Reason           string               `json:"reason,omitempty"`
}

func (s *Server) handleMailMe(w http.ResponseWriter, r *http.Request, u *auth.User) {
	svc := s.mailSvc()
	st, err := svc.Store.LoadSettings(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	out := MailMe{Enabled: st.Enabled}
	if !st.Enabled {
		out.Reason = "The mail server isn't turned on."
		writeJSON(w, http.StatusOK, out)
		return
	}
	acct := accountOf(u)
	if acct == "" {
		out.Reason = "Mailboxes belong to domain accounts; you're signed in with a HardyOS account."
		writeJSON(w, http.StatusOK, out)
		return
	}
	m, err := svc.Store.MailboxByAccount(r.Context(), acct)
	if errors.Is(err, manage.ErrNotFound) {
		out.Reason = "You don't have a mailbox yet; it's made within a few minutes of the account."
		writeJSON(w, http.StatusOK, out)
		return
	}
	if err != nil {
		internalError(s, w, err)
		return
	}
	out.Mailbox = m
	ms := mail.Manual(st.Hostname, m.Address, st.SharedCalendar)
	out.Settings = &ms
	var us []mail.Usage
	if err := s.cfg.Priv.Call(r.Context(), mail.OpUsage, mail.UsageArgs{Addresses: []string{m.Address}}, &us); err == nil && len(us) == 1 {
		out.UsedKB = us[0].UsedKB
	}
	if ov, err := s.appsStatus(r.Context()); err == nil {
		for _, a := range ov.Apps {
			if a.ID == WebmailAppID && a.Source == apps.SourceCatalog {
				out.WebmailInstalled = true
			}
		}
	}
	if !m.CanSignIn() {
		out.Reason = "Your mailbox is turned off; ask an administrator."
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleMailProfile(w http.ResponseWriter, r *http.Request, u *auth.User) {
	svc := s.mailSvc()
	st, err := svc.Store.LoadSettings(r.Context())
	if err != nil || !st.Enabled {
		writeError(w, http.StatusNotFound, "not_found", "the mail server isn't turned on")
		return
	}
	m, err := svc.Store.MailboxByAccount(r.Context(), accountOf(u))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "you don't have a mailbox")
		return
	}
	name := m.DisplayName
	if name == "" {
		name = m.Address
	}
	body := mail.MobileConfig(mail.ClientSettings{Hostname: st.Hostname, Address: m.Address, Name: name, Domain: strings.SplitN(m.Address, "@", 2)[1], DAV: true})
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(m.Address, "@", "-at-")+`.mobileconfig"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// ---- public: mail app settings ----

func (s *Server) mailHostFor(r *http.Request, domainName string) (string, bool) {
	svc := s.mailSvc()
	st, err := svc.Store.LoadSettings(r.Context())
	if err != nil || !st.Enabled || st.Hostname == "" {
		return "", false
	}
	if domainName != "" {
		if _, err := svc.Store.GetDomain(r.Context(), domainName); err != nil {
			return "", false
		}
	}
	return st.Hostname, true
}

func (s *Server) handleAutoconfig(w http.ResponseWriter, r *http.Request) {
	addr := strings.ToLower(r.URL.Query().Get("emailaddress"))
	dom := ""
	if at := strings.LastIndexByte(addr, '@'); at > 0 {
		dom = addr[at+1:]
	} else {
		// autoconfig.<domain>
		dom = strings.TrimPrefix(strings.ToLower(hostOnly(r.Host)), "autoconfig.")
	}
	host, ok := s.mailHostFor(r, dom)
	if !ok {
		host, ok = s.mailHostFor(r, "")
		dom = ""
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	if dom == "" {
		doms, _ := s.mailSvc().Store.Domains(r.Context())
		if len(doms) == 0 {
			http.NotFound(w, r)
			return
		}
		dom = doms[0].Name
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = io.WriteString(w, mail.AutoconfigXML(mail.ClientSettings{Domain: dom, Hostname: host}))
}

func (s *Server) handleAutodiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req mail.AutodiscoverRequest
	if r.Method == http.MethodPost {
		_ = xml.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req)
	}
	addr, err := mail.NormalizeAddress(req.Request.EMailAddress)
	if err != nil {
		addr = ""
	}
	dom := ""
	if addr != "" {
		_, dom, _ = mail.SplitAddress(addr)
	}
	host, ok := s.mailHostFor(r, dom)
	if !ok || addr == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, mail.AutodiscoverXML(mail.ClientSettings{Domain: dom, Hostname: host, Address: addr}))
}

func (s *Server) handleDAVWellKnown(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.mailHostFor(r, ""); !ok {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, mail.DAVPath, http.StatusMovedPermanently)
}

// davProxy forwards to Radicale.
var davProxy = &httputil.ReverseProxy{
	Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(&url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", fmt.Sprint(mail.PortRadicale))})
		pr.Out.URL.Path = "/" + strings.TrimPrefix(pr.In.URL.Path, mail.DAVPath)
		pr.Out.URL.RawPath = ""
		pr.Out.Header.Set("X-Script-Name", strings.TrimSuffix(mail.DAVPath, "/"))
		pr.Out.Header.Del("Cookie")
		pr.Out.Header.Del("X-Remote-User")
		pr.Out.Header.Del("X-Forwarded-For")
	},
	ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "calendars aren't available right now", http.StatusBadGateway)
	},
}

func (s *Server) handleMailDAV(w http.ResponseWriter, r *http.Request) {
	svc := s.mailSvc()
	if _, ok := s.mailHostFor(r, ""); !ok {
		http.NotFound(w, r)
		return
	}
	login, pw, ok := r.BasicAuth()
	login = strings.ToLower(strings.TrimSpace(login))
	if !ok || login == "" || pw == "" || r.TLS == nil && !s.cfg.Insecure && gatewayInfo(r) == nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="HardyOS calendars and contacts", charset="UTF-8"`)
		http.Error(w, "sign in with your mail address and password", http.StatusUnauthorized)
		return
	}
	remote, _ := netip.ParseAddr(s.clientIP(r))
	if v := svc.Throttle.Check(login, remote); v.Block || v.Wait > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(int(v.Wait.Seconds())+1))
		http.Error(w, "too many failed sign-ins; try again later", http.StatusTooManyRequests)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	err := svc.CheckLogin(ctx, login, pw)
	cancel()
	blocked := svc.Throttle.Result(login, remote, err == nil)
	if blocked {
		svc.AuthEvent(mail.AuthEvent{Login: login, Remote: remote.String(), Protocol: "dav", Blocked: true})
	}
	if err != nil || login == mail.NotifyLogin {
		w.Header().Set("WWW-Authenticate", `Basic realm="HardyOS calendars and contacts", charset="UTF-8"`)
		http.Error(w, "wrong address or password", http.StatusUnauthorized)
		return
	}
	dav, err := svc.DAVPassword(r.Context(), login)
	if err != nil {
		internalError(s, w, err)
		return
	}
	r2 := r.Clone(r.Context())
	r2.SetBasicAuth(login, dav)
	r2.Body = http.MaxBytesReader(w, r.Body, 50<<20)
	davProxy.ServeHTTP(w, r2)
}

// ---- hardyd's sign-in listener for Dovecot ----

// MailOptions configures RunMail.
type MailOptions struct {
	// Addr is the listener (default 127.0.0.1:44250).
	Addr string
}

// RunMail serves Dovecot's sign-in questions on 127.0.0.1 and keeps the
// mail server's accounts and alerts going until ctx ends.
func (s *Server) RunMail(ctx context.Context, opts MailOptions) {
	svc := s.mailSvc()
	if svc == nil {
		return
	}
	if opts.Addr == "" {
		opts.Addr = fmt.Sprintf("127.0.0.1:%d", mail.DefaultAuthPort)
	}
	as := &mail.AuthServer{Secret: func() string { return svc.AuthSecret(context.Background()) },
		Checker: svc, Limits: svc.Throttle, OnEvent: svc.AuthEvent, Log: s.log}
	srv := &http.Server{Addr: opts.Addr, Handler: as, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go svc.Run(ctx)
	for {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
			return
		}
		s.log.Warn("mail sign-in listener", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

// mailPasswords checks domain passwords for the mail server like a desktop
// sign-in (decision 78: this server's own domain controller only).
type mailPasswords struct{ s *Server }

func (m mailPasswords) CheckDomainPassword(ctx context.Context, account, password string) error {
	si := m.s.signin
	if si == nil || si.Domain == nil {
		return auth.ErrNoLocalDC
	}
	info, err := si.Domain.Info(ctx)
	if err != nil {
		return err
	}
	if info == nil {
		return auth.ErrNoLocalDC
	}
	u, err := si.Authenticate(ctx, info.NetBIOS+`\`+account, password)
	if err != nil {
		return err
	}
	if u.Disabled {
		return auth.ErrDisabledHere
	}
	return nil
}

// mailDirectory lists domain accounts through hardyd-priv.
type mailDirectory struct{ s *Server }

func (d mailDirectory) Users(ctx context.Context) ([]manage.DirUser, error) {
	si := d.s.signin
	if si == nil || si.Domain == nil {
		return nil, nil
	}
	if info, err := si.Domain.Info(ctx); err != nil || info == nil {
		return nil, err
	}
	var out priv.DomainUsersResult
	if err := d.s.cfg.Priv.Call(ctx, priv.OpDomainUsers, nil, &out); err != nil {
		return nil, err
	}
	users := make([]manage.DirUser, 0, len(out.Users))
	for _, u := range out.Users {
		users = append(users, manage.DirUser{Username: u.Username, GivenName: u.GivenName, DisplayName: u.DisplayName,
			Enabled: u.Enabled, Builtin: u.Builtin})
	}
	return users, nil
}

// mailLabel is the mail server's published label, if it's directly under
// the base domain.
func mailLabel(st manage.Settings, base string) (string, bool) {
	if !st.Enabled {
		return "", false
	}
	if st.Hostname == "" || base == "" || !strings.HasSuffix(st.Hostname, "."+base) {
		return "", false
	}
	l := strings.TrimSuffix(st.Hostname, "."+base)
	return l, l != "" && !strings.Contains(l, ".")
}

// mailPublishHost is the mail server's name for publishing ("" when off).
func mailPublishHost(ctx context.Context, db *store.DB) string {
	if db == nil {
		return ""
	}
	st, err := (&manage.Store{DB: db}).LoadSettings(ctx)
	if err != nil || !st.Enabled {
		return ""
	}
	return st.Hostname
}

// ConfigureMail connects the mail service to the server (sign-in, the
// directory, the window proxy) — called by New.
func (s *Server) configureMail() {
	svc := s.cfg.Mail
	if svc == nil {
		return
	}
	if svc.Passwords == nil {
		svc.Passwords = mailPasswords{s}
	}
	if svc.Dir == nil {
		svc.Dir = mailDirectory{s}
	}
	if svc.Throttle == nil {
		svc.Throttle = mail.NewThrottle()
	}
	if svc.NetBirdAddr == nil {
		svc.NetBirdAddr = s.mailNetBirdAddr
	}
	if svc.SessionAlive == nil {
		svc.SessionAlive = s.proxy.sessionAlive
	}
	if svc.Log == nil {
		svc.Log = s.log
	}
	if svc.Submit == nil && s.cfg.Jobs != nil {
		svc.Submit = func(ctx context.Context, kind, title string, params any) error {
			_, err := s.cfg.Jobs.Submit(ctx, kind, title, params, nil)
			if err == nil {
				s.recordSystem(ctx, kind, "", "queued by the mail server")
			}
			return err
		}
	}
}
