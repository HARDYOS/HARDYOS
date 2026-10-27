package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/cloudbackup"
	"github.com/hardyos/hardyos/daemon/internal/cloudbackups"
	"github.com/hardyos/hardyos/daemon/internal/files"
	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// Versioned cloud backups (docs/backup.md): destinations, tasks, versions,
// restores and the recovery kit for administrators, and restores of their
// own files for everyone (as themselves, checked by hardyd-priv).

// Jobs that carry a credential in memory (jobSecrets), never in their
// parameters.
const (
	jobCloudTargetSave   = "backup.cloud.target.save"
	jobCloudTargetRemove = "backup.cloud.target.remove"
)

func (s *Server) cloudBackupRoutes() {
	m := s.mux
	m.Handle("GET /api/v1/backup", s.admin(s.handleCloudOverview))
	m.Handle("POST /api/v1/backup/targets", s.admin(s.handleCloudTargetCreate))
	m.Handle("PUT /api/v1/backup/targets/{id}", s.admin(s.handleCloudTargetUpdate))
	m.Handle("DELETE /api/v1/backup/targets/{id}", s.admin(s.handleCloudTargetRemove))
	m.Handle("PUT /api/v1/backup/targets/{id}/maintenance", s.admin(s.handleCloudMaintenance))
	m.Handle("POST /api/v1/backup/targets/{id}/recovery-kit", s.admin(s.handleCloudKit))
	m.Handle("POST /api/v1/backup/targets/{id}/prune", s.admin(s.handleCloudUpkeep(cloudbackups.JobPrune, "Free space")))
	m.Handle("POST /api/v1/backup/targets/{id}/check", s.admin(s.handleCloudUpkeep(cloudbackups.JobCheck, "Check backups")))
	m.Handle("GET /api/v1/backup/targets/{id}/versions", s.admin(s.handleCloudVersions))
	m.Handle("GET /api/v1/backup/targets/{id}/browse", s.admin(s.handleCloudBrowse))
	m.Handle("GET /api/v1/backup/tasks", s.admin(s.handleCloudTasks))
	m.Handle("POST /api/v1/backup/tasks", s.admin(s.handleCloudTaskCreate))
	m.Handle("PUT /api/v1/backup/tasks/{id}", s.admin(s.handleCloudTaskUpdate))
	m.Handle("DELETE /api/v1/backup/tasks/{id}", s.admin(s.handleCloudTaskDelete))
	m.Handle("POST /api/v1/backup/tasks/{id}/run", s.admin(s.handleCloudTaskRun))
	m.Handle("GET /api/v1/backup/runs", s.admin(s.handleCloudRuns))
	m.Handle("POST /api/v1/backup/restore", s.admin(s.handleCloudRestore))
	m.Handle("GET /api/v1/backup/rebuild", s.admin(s.handleCloudOffer))
	m.Handle("POST /api/v1/backup/rebuild", s.admin(s.handleCloudRebuild))
	m.Handle("DELETE /api/v1/backup/rebuild", s.admin(s.handleCloudOfferDismiss))
	if s.cfg.Files != nil {
		m.Handle("GET /api/v1/files/backups", s.authed(s.handleFileBackupVersions))
		m.Handle("GET /api/v1/files/backups/browse", s.authed(s.handleFileBackupBrowse))
		m.Handle("POST /api/v1/files/backups/restore", s.authed(s.handleFileBackupRestore))
	}
}

// writeCloudError: validation problems are 400, the rest as root errors.
func (s *Server) writeCloudError(w http.ResponseWriter, err error) {
	var p *cloudbackups.Problem
	switch {
	case errors.As(err, &p):
		writeError(w, http.StatusBadRequest, "invalid", p.Msg)
	case errors.Is(err, cloudbackups.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	default:
		s.writePrivError(w, err)
	}
}

// CloudOverview is GET /backup.
type CloudOverview struct {
	Targets []cloudbackups.Target     `json:"targets"`
	Tasks   []cloudbackups.Task       `json:"tasks"`
	Offer   *cloudbackup.RebuildOffer `json:"offer"`
}

func (s *Server) handleCloudOverview(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	cb := s.cfg.CloudBackups
	targets, err := cb.Targets(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	tasks, err := cb.Tasks(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	var offer priv.CloudOfferResult
	_ = s.cfg.Priv.Call(r.Context(), priv.OpCloudOffer, nil, &offer)
	writeJSON(w, http.StatusOK, CloudOverview{Targets: targets, Tasks: tasks, Offer: offer.Offer})
}

// cloudTargetRequest is a destination as typed in. The keys never go into
// job parameters.
type cloudTargetRequest struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	Endpoint         string `json:"endpoint,omitempty"`
	Bucket           string `json:"bucket"`
	Prefix           string `json:"prefix,omitempty"`
	Region           string `json:"region,omitempty"`
	AllowLAN         bool   `json:"allowLan,omitempty"`
	LimitUploadKiB   int    `json:"limitUploadKiB,omitempty"`
	LimitDownloadKiB int    `json:"limitDownloadKiB,omitempty"`
	AccessKey        string `json:"accessKey,omitempty"`
	SecretKey        string `json:"secretKey,omitempty"`
	RepoKey          string `json:"repoKey,omitempty"`
}

// cloudTargetParams is the save job's parameters.
type cloudTargetParams struct {
	Target    cloudbackup.Target `json:"target"`
	Update    bool               `json:"update"`
	SecretRef string             `json:"secretRef,omitempty"`
}

type cloudTargetSecrets struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
	RepoKey   string `json:"repoKey"`
}

func (s *Server) handleCloudTargetCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.cloudTargetSave(w, r, u, "", false)
}

func (s *Server) handleCloudTargetUpdate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.cloudTargetSave(w, r, u, r.PathValue("id"), true)
}

func (s *Server) cloudTargetSave(w http.ResponseWriter, r *http.Request, u *auth.User, id string, update bool) {
	var req cloudTargetRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if update {
		req.ID = id
	}
	t := cloudbackup.Target{ID: req.ID, Name: req.Name, Kind: req.Kind, Endpoint: req.Endpoint, Bucket: req.Bucket, Prefix: req.Prefix,
		Region: req.Region, AllowLAN: req.AllowLAN, LimitUploadKiB: req.LimitUploadKiB, LimitDownloadKiB: req.LimitDownloadKiB}
	// Fail fast on what can be checked here; hardyd-priv checks it all again.
	check := t
	if err := check.Normalize(false); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if !update || req.AccessKey != "" || req.SecretKey != "" {
		if err := cloudbackup.CheckCredentials(t.Kind, cloudbackup.Credentials{AccessKey: req.AccessKey, SecretKey: req.SecretKey}); err != nil {
			writeError(w, http.StatusBadRequest, "invalid", err.Error())
			return
		}
	}
	if req.RepoKey != "" {
		if err := cloudbackup.ValidRepoPassword(req.RepoKey); err != nil {
			writeError(w, http.StatusBadRequest, "invalid", err.Error())
			return
		}
	}
	params := cloudTargetParams{Target: t, Update: update}
	if req.AccessKey != "" || req.SecretKey != "" || req.RepoKey != "" {
		b, _ := json.Marshal(cloudTargetSecrets{AccessKey: req.AccessKey, SecretKey: req.SecretKey, RepoKey: req.RepoKey})
		params.SecretRef = jobSecrets.put(string(b))
	}
	title := "Add backup destination " + t.Name
	action := "backup.target.create"
	if update {
		title, action = "Change backup destination "+t.Name, "backup.target.update"
	}
	detail := t.Kind + " " + t.Repository()
	if req.RepoKey != "" {
		detail += " (existing repository)"
	}
	if !s.jobsReady(w) {
		return
	}
	uid := u.ID
	j, err := s.cfg.Jobs.Submit(r.Context(), jobCloudTargetSave, title, params, &uid)
	if err != nil {
		internalError(s, w, err)
		return
	}
	s.record(r, u, action, t.ID, audit.Success, detail+"; job "+j.ID)
	writeJSON(w, http.StatusAccepted, JobAccepted{Job: j, Warnings: []string{}})
}

func (s *Server) handleCloudTargetRemove(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req struct {
		Confirm string `json:"confirm"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	if used, err := s.cfg.CloudBackups.TasksUsing(r.Context(), id); err == nil && len(used) > 0 {
		writeError(w, http.StatusConflict, "in_use", "backup tasks use this destination: "+strings.Join(used, ", ")+"; delete them first")
		return
	}
	s.submit(w, r, u, jobCloudTargetRemove, "Remove backup destination", priv.CloudTargetRef{ID: id, Confirm: req.Confirm}, "backup.target.remove", id, nil)
}

func (s *Server) registerCloudJobs(m *jobs.Manager) {
	cb := s.cfg.CloudBackups
	m.Register(jobs.Kind{Name: jobCloudTargetSave, AdminOnly: true, LockKey: func(raw json.RawMessage) string {
		var p cloudTargetParams
		_ = json.Unmarshal(raw, &p)
		return "cloud-backup:" + p.Target.ID
	}, Run: func(jc *jobs.Context) (any, error) {
		var p cloudTargetParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		var sec cloudTargetSecrets
		if p.SecretRef != "" {
			raw, ok := jobSecrets.take(p.SecretRef)
			if !ok {
				return nil, errors.New("the keys were lost (hardyd restarted); enter them again")
			}
			_ = json.Unmarshal([]byte(raw), &sec)
		}
		jc.Progress(10, "Testing access to the bucket")
		var res cloudbackup.SaveResult
		err := s.cfg.Priv.Call(jc, priv.OpCloudTargetSave, cloudbackup.SaveArgs{Target: p.Target, AccessKey: sec.AccessKey, SecretKey: sec.SecretKey,
			RepoPassword: sec.RepoKey, Update: p.Update}, &res)
		if err != nil {
			return nil, err
		}
		return res, nil
	}})
	m.Register(jobs.Kind{Name: jobCloudTargetRemove, AdminOnly: true, LockKey: func(raw json.RawMessage) string {
		var p priv.CloudTargetRef
		_ = json.Unmarshal(raw, &p)
		return "cloud-backup:" + p.ID
	}, Run: func(jc *jobs.Context) (any, error) {
		var p priv.CloudTargetRef
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		if err := s.cfg.Priv.Call(jc, priv.OpCloudTargetRemove, p, nil); err != nil {
			return nil, err
		}
		_ = cb.ForgetTarget(jc, p.ID)
		return map[string]string{"removed": p.ID}, nil
	}})
}

func (s *Server) handleCloudMaintenance(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var m cloudbackups.Maintenance
	if !decodeJSON(w, r, &m) {
		return
	}
	id := r.PathValue("id")
	if err := s.cfg.CloudBackups.SetMaintenance(r.Context(), id, m); err != nil {
		s.writeCloudError(w, err)
		return
	}
	s.record(r, u, "backup.target.maintenance", id, audit.Success, fmt.Sprintf("weekday %d at %s, check %d%%", m.Weekday, m.Time, m.CheckPercent))
	writeJSON(w, http.StatusOK, m)
}

// RecoveryKit is the recovery kit download.
type RecoveryKit struct {
	FileName string `json:"fileName"`
	Text     string `json:"text"`
}

var kitNameRE = regexp.MustCompile(`[^A-Za-z0-9-]+`)

// handleCloudKit hands out a destination's recovery kit after the
// administrator's password is checked again (like the terminal); every
// try is audited.
func (s *Server) handleCloudKit(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	key := "backupkit:" + strconv.FormatInt(u.ID, 10)
	if ok, wait := s.cfg.Limiter.Allowed(key); !ok {
		s.record(r, u, "backup.recovery_kit", id, audit.Denied, "rate limited")
		writeError(w, http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("too many wrong passwords; try again in %d minutes", int(wait.Minutes())+1))
		return
	}
	if err := s.signin.Verify(r.Context(), u, req.Password); err != nil {
		if errors.Is(err, auth.ErrDomainUnavailable) || errors.Is(err, auth.ErrClockSkew) {
			writeError(w, http.StatusServiceUnavailable, "domain_unavailable", err.Error())
			return
		}
		if errors.Is(err, auth.ErrBadCredentials) || errors.Is(err, auth.ErrAccountRevoked) ||
			errors.Is(err, auth.ErrPasswordExpired) || errors.Is(err, auth.ErrAccountGone) {
			s.cfg.Limiter.Fail(key)
			s.record(r, u, "backup.recovery_kit", id, audit.Failure, "wrong password")
			writeError(w, http.StatusUnauthorized, "bad_credentials", "that password isn't right")
			return
		}
		internalError(s, w, err)
		return
	}
	s.cfg.Limiter.Succeed(key)
	var kit cloudbackup.RecoveryKit
	if err := s.cfg.Priv.Call(r.Context(), priv.OpCloudKit, priv.CloudKitArgs{ID: id, User: u.Username}, &kit); err != nil {
		s.record(r, u, "backup.recovery_kit", id, audit.Failure, err.Error())
		s.writePrivError(w, err)
		return
	}
	_ = s.cfg.CloudBackups.KitDownloaded(r.Context(), id)
	s.record(r, u, "backup.recovery_kit", id, audit.Success, "downloaded")
	host, _ := os.Hostname()
	writeJSON(w, http.StatusOK, RecoveryKit{
		FileName: "hardyos-recovery-kit-" + strings.Trim(kitNameRE.ReplaceAllString(kit.Target.ID, "-"), "-") + ".txt",
		Text:     RenderKit(kit, host, time.Now()),
	})
}

// RenderKit writes a recovery kit's text: instructions, then the framed
// block the installer reads.
func RenderKit(k cloudbackup.RecoveryKit, host string, at time.Time) string {
	var b strings.Builder
	t := k.Target
	fmt.Fprintf(&b, "HardyOS recovery kit: %s\n", t.Name)
	fmt.Fprintf(&b, "Made %s on %s.\n\n", at.Format("January 2, 2006 15:04 MST"), host)
	b.WriteString("KEEP THIS FILE SAFE AND OFFLINE (print it, or keep it in a password manager).\n")
	b.WriteString("With it and the bucket's access keys, anyone can read these backups. Without\n")
	b.WriteString("it, nobody can - not even you: HardyOS can't recover a lost key.\n\n")
	switch t.Kind {
	case cloudbackup.KindS3:
		fmt.Fprintf(&b, "Where:       S3-compatible storage at %s\n", t.Endpoint)
	case cloudbackup.KindB2:
		b.WriteString("Where:       Backblaze B2\n")
	}
	fmt.Fprintf(&b, "Bucket:      %s\n", t.Bucket)
	if t.Prefix != "" {
		fmt.Fprintf(&b, "Folder:      %s\n", t.Prefix)
	}
	fmt.Fprintf(&b, "Repository:  %s\n", k.Repository)
	fmt.Fprintf(&b, "Key:         %s\n\n", k.Key)
	b.WriteString("To rebuild a server from these backups:\n")
	b.WriteString("  1. Start the server from the HardyOS installer and choose \"Restore from backup\".\n")
	b.WriteString("  2. Open or paste this file, and enter the bucket's access key and secret key.\n")
	b.WriteString("  3. Choose a version. The installer brings back the settings, accounts and domain.\n")
	b.WriteString("  4. After the first start, make a storage pool, then open Backup > Rebuild to bring\n")
	b.WriteString("     back the shared folders, apps and virtual machines.\n\n")
	b.WriteString("The backups are a restic repository: with restic installed anywhere,\n")
	fmt.Fprintf(&b, "RESTIC_REPOSITORY=%s restic snapshots   (the key above is the password)\n", k.Repository)
	b.WriteString("lists them.\n\n")
	b.WriteString(cloudbackup.EncodeKit(cloudbackup.KitData{Target: t, Repository: k.Repository, Key: k.Key}))
	return b.String()
}

func (s *Server) handleCloudUpkeep(kind, title string) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, u *auth.User) {
		id := r.PathValue("id")
		if err := cloudbackup.ValidID(id); err != nil {
			writeError(w, http.StatusNotFound, "not_found", "there's no such destination")
			return
		}
		s.submit(w, r, u, kind, title, cloudbackups.TargetParams{Target: id}, "backup."+strings.TrimPrefix(kind, "backup.cloud."), id, nil)
	}
}

func (s *Server) handleCloudVersions(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var res priv.CloudVersionsResult
	if err := s.cfg.Priv.Call(r.Context(), priv.OpCloudVersions, priv.CloudTargetRef{ID: r.PathValue("id")}, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	if res.Versions == nil {
		res.Versions = []cloudbackup.Version{}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleCloudBrowse(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	q := r.URL.Query()
	var res priv.CloudBrowseResult
	if err := s.cfg.Priv.Call(r.Context(), priv.OpCloudBrowse, cloudbackup.BrowseArgs{Target: r.PathValue("id"), Snapshot: q.Get("snapshot"), Path: q.Get("path")}, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	if res.Entries == nil {
		res.Entries = []cloudbackup.Entry{}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleCloudTasks(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	l, err := s.cfg.CloudBackups.Tasks(r.Context())
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": l})
}

func describeItems(items []cloudbackup.Item) string {
	var parts []string
	for _, it := range items {
		parts = append(parts, it.Key())
	}
	return strings.Join(parts, ", ")
}

func (s *Server) handleCloudTaskCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var in cloudbackups.TaskInput
	if !decodeJSON(w, r, &in) {
		return
	}
	t, err := s.cfg.CloudBackups.CreateTask(r.Context(), in)
	if err != nil {
		s.record(r, u, "backup.task.create", in.Name, audit.Failure, err.Error())
		s.writeCloudError(w, err)
		return
	}
	s.record(r, u, "backup.task.create", t.ID, audit.Success, t.Name+" to "+t.Target+": "+describeItems(t.Items))
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) handleCloudTaskUpdate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var in cloudbackups.TaskInput
	if !decodeJSON(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	t, err := s.cfg.CloudBackups.UpdateTask(r.Context(), id, in)
	if err != nil {
		s.record(r, u, "backup.task.update", id, audit.Failure, err.Error())
		s.writeCloudError(w, err)
		return
	}
	s.record(r, u, "backup.task.update", t.ID, audit.Success, t.Name+" to "+t.Target+": "+describeItems(t.Items)+"; enabled="+strconv.FormatBool(t.Enabled))
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) handleCloudTaskDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	id := r.PathValue("id")
	if err := s.cfg.CloudBackups.DeleteTask(r.Context(), id); err != nil {
		s.writeCloudError(w, err)
		return
	}
	s.record(r, u, "backup.task.delete", id, audit.Success, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCloudTaskRun(w http.ResponseWriter, r *http.Request, u *auth.User) {
	t, err := s.cfg.CloudBackups.Task(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeCloudError(w, err)
		return
	}
	if !s.jobsReady(w) {
		return
	}
	uid := u.ID
	j, err := s.cfg.CloudBackups.SubmitRun(r.Context(), t, "manual", &uid)
	if err != nil {
		internalError(s, w, err)
		return
	}
	s.record(r, u, "backup.task.run", t.ID, audit.Success, "job "+j.ID)
	writeJSON(w, http.StatusAccepted, JobAccepted{Job: j, Warnings: []string{}})
}

func (s *Server) handleCloudRuns(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	l, err := s.cfg.CloudBackups.Runs(r.Context(), r.URL.Query().Get("task"), limit)
	if err != nil {
		internalError(s, w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": l})
}

type cloudRestoreRequest struct {
	Target   string   `json:"target"`
	Snapshot string   `json:"snapshot"`
	Paths    []string `json:"paths,omitempty"`
	Mode     string   `json:"mode"`
	Folder   string   `json:"folder,omitempty"`
	Confirm  string   `json:"confirm,omitempty"`
}

func (s *Server) handleCloudRestore(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req cloudRestoreRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Mode == cloudbackup.ModeRollback && strings.TrimSpace(req.Confirm) == "" {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the name of what you're rolling back to confirm")
		return
	}
	switch req.Mode {
	case cloudbackup.ModeCopy, cloudbackup.ModeInPlace, cloudbackup.ModeRollback:
	default:
		writeError(w, http.StatusBadRequest, "invalid", "choose how to restore")
		return
	}
	p := cloudbackups.RestoreParams{RestoreArgs: cloudbackup.RestoreArgs{Target: req.Target, Snapshot: req.Snapshot, Paths: req.Paths,
		Mode: req.Mode, Folder: req.Folder, Confirm: req.Confirm}}
	s.submit(w, r, u, cloudbackups.JobRestore, "Restore from backup", p, "backup.restore."+req.Mode, req.Target+"/"+req.Snapshot, nil)
}

func (s *Server) handleCloudOffer(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	var res priv.CloudOfferResult
	if err := s.cfg.Priv.Call(r.Context(), priv.OpCloudOffer, nil, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleCloudRebuild(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req cloudbackup.RebuildArgs
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Confirm != "rebuild" {
		writeError(w, http.StatusBadRequest, "confirm_required", "confirm the rebuild")
		return
	}
	s.submit(w, r, u, cloudbackups.JobRebuild, "Rebuild from backup", req, "backup.rebuild", req.Target+"/"+req.Run, nil)
}

func (s *Server) handleCloudOfferDismiss(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if err := s.cfg.Priv.Call(r.Context(), priv.OpCloudOfferDismiss, nil, nil); err != nil {
		s.writePrivError(w, err)
		return
	}
	s.record(r, u, "backup.rebuild.dismiss", "", audit.Success, "")
	w.WriteHeader(http.StatusNoContent)
}

// ---- people's own files ------------------------------------------------------------------

// fileBackupWho is the person as hardyd-priv acts as them.
func fileBackupWho(u *auth.User) fileworker.Who {
	return fileworker.Who{Principal: u.IdentityPrincipal(), Local: u.IdentitySource() != auth.SourceDomain, Admin: u.IsAdmin(), Groups: u.IdentityGroups()}
}

// canOpenShare: the folder is among those the person can open today.
func (s *Server) canOpenShare(ctx context.Context, u *auth.User, share string) bool {
	l, err := s.cfg.Files.Shares(ctx, files.WhoFor(u))
	if err != nil {
		return false
	}
	for _, sh := range l {
		if sh.ID == share {
			return true
		}
	}
	return false
}

// FileBackupVersion is a version holding a shared folder.
type FileBackupVersion struct {
	Target     string    `json:"target"`
	TargetName string    `json:"targetName"`
	Run        string    `json:"run"`
	Time       time.Time `json:"time"`
	Snapshot   string    `json:"snapshot"`
}

func (s *Server) handleFileBackupVersions(w http.ResponseWriter, r *http.Request, u *auth.User) {
	share := r.URL.Query().Get("share")
	if !s.canOpenShare(r.Context(), u, share) {
		writeError(w, http.StatusNotFound, "not_found", "there's no such shared folder")
		return
	}
	out := []FileBackupVersion{}
	if s.cfg.CloudBackups == nil {
		writeJSON(w, http.StatusOK, map[string]any{"versions": out})
		return
	}
	targets, err := s.cfg.CloudBackups.Targets(r.Context())
	if err != nil {
		s.writePrivError(w, err)
		return
	}
	for _, t := range targets {
		var res priv.CloudVersionsResult
		if err := s.cfg.Priv.Call(r.Context(), priv.OpCloudVersions, priv.CloudTargetRef{ID: t.ID}, &res); err != nil {
			s.log.Warn("cloud backup versions", "target", t.ID, "err", err)
			continue
		}
		for _, v := range res.Versions {
			if !v.ThisServer {
				continue // another server's (decision 229)
			}
			for _, it := range v.Items {
				if it.Item == "share:"+share && it.Snapshot != "" {
					out = append(out, FileBackupVersion{Target: t.ID, TargetName: t.Name, Run: v.Run, Time: v.Time, Snapshot: it.Snapshot})
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": out})
}

func (s *Server) handleFileBackupBrowse(w http.ResponseWriter, r *http.Request, u *auth.User) {
	q := r.URL.Query()
	share := q.Get("share")
	if !s.canOpenShare(r.Context(), u, share) {
		writeError(w, http.StatusNotFound, "not_found", "there's no such shared folder")
		return
	}
	who := fileBackupWho(u)
	var res priv.CloudBrowseResult
	if err := s.cfg.Priv.Call(r.Context(), priv.OpCloudBrowse, cloudbackup.BrowseArgs{Target: q.Get("target"), Snapshot: q.Get("snapshot"), Path: q.Get("path"), Who: &who}, &res); err != nil {
		s.writePrivError(w, err)
		return
	}
	if res.Entries == nil {
		res.Entries = []cloudbackup.Entry{}
	}
	writeJSON(w, http.StatusOK, res)
}

type fileBackupRestoreRequest struct {
	Share    string   `json:"share"`
	Target   string   `json:"target"`
	Snapshot string   `json:"snapshot"`
	Paths    []string `json:"paths,omitempty"`
	Mode     string   `json:"mode"`
	Folder   string   `json:"folder,omitempty"`
}

func (s *Server) handleFileBackupRestore(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req fileBackupRestoreRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.canOpenShare(r.Context(), u, req.Share) {
		writeError(w, http.StatusNotFound, "not_found", "there's no such shared folder")
		return
	}
	if req.Mode != cloudbackup.ModeCopy && req.Mode != cloudbackup.ModeInPlace {
		writeError(w, http.StatusBadRequest, "invalid", "choose to restore into a new folder or in place")
		return
	}
	// The version must be of this very folder (hardyd-priv checks the
	// person's access to the folder the version is of).
	var vr priv.CloudVersionsResult
	if err := s.cfg.Priv.Call(r.Context(), priv.OpCloudVersions, priv.CloudTargetRef{ID: req.Target}, &vr); err != nil {
		s.writePrivError(w, err)
		return
	}
	ok := false
	for _, v := range vr.Versions {
		for _, it := range v.Items {
			ok = ok || (v.ThisServer && it.Item == "share:"+req.Share && it.Snapshot == req.Snapshot)
		}
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "that version isn't of this folder")
		return
	}
	who := fileBackupWho(u)
	p := cloudbackups.RestoreParams{RestoreArgs: cloudbackup.RestoreArgs{Target: req.Target, Snapshot: req.Snapshot, Paths: req.Paths,
		Mode: req.Mode, Folder: req.Folder, Who: &who}}
	s.submit(w, r, u, cloudbackups.JobRestore, "Restore files from backup", p, "files.backup.restore", req.Share+" "+req.Snapshot, nil)
}
