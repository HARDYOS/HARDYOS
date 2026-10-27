package api

import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/replica"
	"github.com/hardyos/hardyos/daemon/internal/replication"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Replication between HardyOS servers (Control Panel › Replication, and
// the Backup app's Replication tab). Everything is for administrators;
// every change is a job and audited.

func (s *Server) replicationRoutes() {
	if s.cfg.Replication == nil {
		return
	}
	s.cfg.Replication.Secrets = jobSecrets.take
	m := s.mux
	m.Handle("GET /api/v1/replication", s.admin(s.handleReplication))
	m.Handle("GET /api/v1/replication/items", s.admin(s.handleReplicationItems))
	m.Handle("POST /api/v1/replication/targets", s.admin(s.handleReplicationPair))
	m.Handle("PATCH /api/v1/replication/targets/{id}", s.admin(s.handleReplicationTargetUpdate))
	m.Handle("DELETE /api/v1/replication/targets/{id}", s.admin(s.handleReplicationTargetDelete))
	m.Handle("POST /api/v1/replication/targets/{id}/test", s.admin(s.handleReplicationTargetTest))
	m.Handle("GET /api/v1/replication/targets/{id}/replicas", s.admin(s.handleReplicationReplicas))
	m.Handle("GET /api/v1/replication/targets/{id}/replicas/{kind}/{item}/snapshots", s.admin(s.handleReplicationReplicaSnapshots))
	m.Handle("GET /api/v1/replication/targets/{id}/replicas/{kind}/{item}/browse", s.admin(s.handleReplicationBrowse))
	m.Handle("POST /api/v1/replication/targets/{id}/restore", s.admin(s.handleReplicationRestore))
	m.Handle("POST /api/v1/replication/tasks", s.admin(s.handleReplicationTaskCreate))
	m.Handle("PATCH /api/v1/replication/tasks/{id}", s.admin(s.handleReplicationTaskUpdate))
	m.Handle("DELETE /api/v1/replication/tasks/{id}", s.admin(s.handleReplicationTaskDelete))
	m.Handle("POST /api/v1/replication/tasks/{id}/run", s.admin(s.handleReplicationTaskRun))
	m.Handle("POST /api/v1/replication/tasks/{id}/cancel", s.admin(s.handleReplicationTaskCancel))
	m.Handle("GET /api/v1/replication/tasks/{id}/history", s.admin(s.handleReplicationTaskHistory))
	m.Handle("GET /api/v1/replication/receive", s.admin(s.handleReplicationReceive))
	m.Handle("POST /api/v1/replication/receive/pairing", s.admin(s.handleReplicationPairingCreate))
	m.Handle("DELETE /api/v1/replication/receive/pairing", s.admin(s.handleReplicationPairingCancel))
	m.Handle("PATCH /api/v1/replication/receive/sources/{id}", s.admin(s.handleReplicationSourceUpdate))
	m.Handle("DELETE /api/v1/replication/receive/sources/{id}", s.admin(s.handleReplicationSourceDelete))
}

func (s *Server) replErr(w http.ResponseWriter, err error) {
	var re *replication.RemoteError
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such server, task or replica")
	case errors.As(err, &re):
		status := http.StatusBadGateway
		if re.Status == http.StatusNotFound {
			status = http.StatusNotFound
		}
		writeError(w, status, "remote", re.Error())
	case strings.HasPrefix(err.Error(), "can't reach the other server"):
		writeError(w, http.StatusBadGateway, "unreachable", err.Error())
	default:
		s.writePrivError(w, err)
	}
}

// ReplicationTask is a task with what the page shows about it.
type ReplicationTask struct {
	replication.Task
	TargetName string     `json:"targetName"`
	RunningJob string     `json:"runningJob"`
	NextRunAt  *time.Time `json:"nextRunAt"`
	Stale      bool       `json:"stale"`
}

// ReplicationOverview is the sending side's page.
type ReplicationOverview struct {
	Hostname string               `json:"hostname"`
	Pin      string               `json:"pin"`
	Port     int                  `json:"port"`
	Targets  []replication.Target `json:"targets"`
	Tasks    []ReplicationTask    `json:"tasks"`
}

func hostnameOf() string {
	h, _ := os.Hostname()
	return h
}

func (s *Server) handleReplication(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	svc := s.cfg.Replication
	ctx := r.Context()
	id, err := svc.Identity(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	st := svc.Store()
	targets, err := st.Targets(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	tasks, err := st.Tasks(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	names := map[string]string{}
	for i := range targets {
		names[targets[i].ID] = targets[i].Name
		targets[i].Pin = shortPin(targets[i].Pin)
	}
	out := ReplicationOverview{Hostname: hostnameOf(), Pin: id.Pin, Targets: targets, Tasks: []ReplicationTask{}, Port: replication.DefaultPort}
	now := time.Now().UTC()
	for _, t := range tasks {
		v := ReplicationTask{Task: t, TargetName: names[t.TargetID], RunningJob: svc.RunningJob(t.ID)}
		if t.Enabled {
			next := now
			if t.LastRunAt != nil {
				next = t.LastRunAt.Add(time.Duration(t.IntervalMinutes) * time.Minute)
			}
			v.NextRunAt = &next
			since := t.CreatedAt
			if t.LastSuccessAt != nil {
				since = *t.LastSuccessAt
			}
			v.Stale = now.Sub(since) > replication.StaleAfter(t.IntervalMinutes)
		}
		out.Tasks = append(out.Tasks, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func shortPin(p string) string {
	if len(p) > 16 {
		return p[:16]
	}
	return p
}

func (s *Server) handleReplicationItems(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	l, err := s.cfg.Replication.Root.Items(r.Context())
	if err != nil {
		s.replErr(w, err)
		return
	}
	if l == nil {
		l = []replica.LocalItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": l})
}

type replicationPairRequest struct {
	Address string `json:"address"`
	Code    string `json:"code"`
}

func (s *Server) handleReplicationPair(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req replicationPairRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	addr, err := replication.CleanAddress(req.Address)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if _, err := replication.ParseCode(req.Code); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	ref := jobSecrets.put(req.Code)
	s.submit(w, r, u, replication.JobPair, "Pair with "+addr, replication.PairParams{Address: addr, SecretRef: ref}, "replication.target.pair", addr, nil)
}

type replicationTargetUpdate struct {
	Address string `json:"address"`
}

func (s *Server) handleReplicationTargetUpdate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req replicationTargetUpdate
	if !decodeJSON(w, r, &req) {
		return
	}
	t, err := s.cfg.Replication.Store().Target(r.Context(), r.PathValue("id"))
	if err != nil {
		s.replErr(w, err)
		return
	}
	addr, err := replication.CleanAddress(req.Address)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	s.submit(w, r, u, replication.JobTargetUpdate, "Change the address of "+t.Name, replication.TargetUpdateParams{Target: t.ID, Address: addr},
		"replication.target.update", t.Name+" "+addr, nil)
}

type replConfirmRequest struct {
	Confirm string `json:"confirm"`
}

func (s *Server) handleReplicationTargetDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req replConfirmRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	t, err := s.cfg.Replication.Store().Target(r.Context(), r.PathValue("id"))
	if err != nil {
		s.replErr(w, err)
		return
	}
	if strings.TrimSpace(req.Confirm) != t.Name {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the server's name ("+t.Name+") to confirm")
		return
	}
	s.submit(w, r, u, replication.JobTargetDelete, "Forget "+t.Name, replication.TargetDeleteParams{Target: t.ID, Confirm: req.Confirm},
		"replication.target.delete", t.Name, nil)
}

func (s *Server) handleReplicationTargetTest(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	name, err := s.cfg.Replication.TestTarget(r.Context(), r.PathValue("id"))
	if err != nil {
		s.replErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
}

func (s *Server) handleReplicationReplicas(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	l, err := s.cfg.Replication.TargetReplicas(r.Context(), r.PathValue("id"))
	if err != nil {
		s.replErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": l})
}

func replicaPath(w http.ResponseWriter, r *http.Request) (replica.Item, bool) {
	it := replica.Item{Kind: r.PathValue("kind"), ID: r.PathValue("item")}
	if err := it.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return it, false
	}
	return it, true
}

func (s *Server) handleReplicationReplicaSnapshots(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	it, ok := replicaPath(w, r)
	if !ok {
		return
	}
	l, err := s.cfg.Replication.TargetSnapshots(r.Context(), r.PathValue("id"), it.Kind, it.ID)
	if err != nil {
		s.replErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": l})
}

func (s *Server) handleReplicationBrowse(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	it, ok := replicaPath(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	if err := replica.ValidSnap(q.Get("snapshot"), ""); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if err := replica.ValidChild(q.Get("child")); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	res, err := s.cfg.Replication.TargetBrowse(r.Context(), r.PathValue("id"), it.Kind, it.ID, q.Get("child"), q.Get("snapshot"), q.Get("path"))
	if err != nil {
		s.replErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

type replicationRestoreRequest struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Snapshot string `json:"snapshot"`
	Pool     string `json:"pool"`
	NewID    string `json:"newId"`
	Name     string `json:"name"`
	Confirm  bool   `json:"confirm"`
}

func (s *Server) handleReplicationRestore(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req replicationRestoreRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	t, err := s.cfg.Replication.Store().Target(r.Context(), r.PathValue("id"))
	if err != nil {
		s.replErr(w, err)
		return
	}
	if err := (replica.Item{Kind: req.Kind, ID: req.ID}).Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if err := replica.ValidSnap(req.Snapshot, ""); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	switch req.Kind {
	case replica.KindShare:
		if replica.ValidPool(req.Pool) != nil || replica.ValidItem(req.NewID) != nil || strings.TrimSpace(req.Name) == "" {
			writeError(w, http.StatusBadRequest, "invalid", "choose a pool, an id and a name for the restored shared folder")
			return
		}
	case replica.KindVM:
		if replica.ValidPool(req.Pool) != nil {
			writeError(w, http.StatusBadRequest, "invalid", "choose the pool the VM was on")
			return
		}
	}
	if !req.Confirm {
		writeError(w, http.StatusBadRequest, "confirm_required", "confirm the restore: it copies the replica back onto this server")
		return
	}
	p := replication.RestoreParams{Target: t.ID, Kind: req.Kind, ID: req.ID, Snapshot: req.Snapshot, Pool: req.Pool, NewID: req.NewID, Name: strings.TrimSpace(req.Name)}
	s.submit(w, r, u, replication.JobRestore, "Restore "+req.ID+" from "+t.Name, p, "replication.restore", t.Name+" "+req.Kind+"/"+req.ID+"@"+req.Snapshot, nil)
}

type replicationTaskRequest struct {
	Name            string         `json:"name"`
	TargetID        string         `json:"targetId"`
	Items           []replica.Item `json:"items"`
	IntervalMinutes int            `json:"intervalMinutes"`
	BandwidthKBps   int            `json:"bandwidthKBps"`
	KeepLocal       int            `json:"keepLocal"`
	KeepRemote      int            `json:"keepRemote"`
	Enabled         bool           `json:"enabled"`
}

func (req replicationTaskRequest) task() replication.Task {
	return replication.Task{Name: req.Name, TargetID: req.TargetID, Items: req.Items, IntervalMinutes: req.IntervalMinutes,
		BandwidthKBps: req.BandwidthKBps, KeepLocal: req.KeepLocal, KeepRemote: req.KeepRemote, Enabled: req.Enabled}
}

func (s *Server) handleReplicationTaskCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req replicationTaskRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	t := req.task()
	if err := replication.CheckTask(&t); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if _, err := s.cfg.Replication.Store().Target(r.Context(), t.TargetID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", "choose a paired server")
		return
	}
	s.submit(w, r, u, replication.JobTaskCreate, "Create the replication task "+t.Name, t, "replication.task.create", t.Name, nil)
}

func (s *Server) handleReplicationTaskUpdate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req replicationTaskRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	old, err := s.cfg.Replication.Store().Task(r.Context(), r.PathValue("id"))
	if err != nil {
		s.replErr(w, err)
		return
	}
	t := req.task()
	t.ID, t.TargetID = old.ID, old.TargetID
	if err := replication.CheckTask(&t); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	s.submit(w, r, u, replication.JobTaskUpdate, "Change the replication task "+t.Name, t, "replication.task.update", t.ID+" "+t.Name, nil)
}

func (s *Server) handleReplicationTaskDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req replConfirmRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	t, err := s.cfg.Replication.Store().Task(r.Context(), r.PathValue("id"))
	if err != nil {
		s.replErr(w, err)
		return
	}
	if strings.TrimSpace(req.Confirm) != t.Name {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the task's name ("+t.Name+") to confirm")
		return
	}
	s.submit(w, r, u, replication.JobTaskDelete, "Delete the replication task "+t.Name, replication.TaskDeleteParams{Task: t.ID, Confirm: req.Confirm},
		"replication.task.delete", t.ID+" "+t.Name, nil)
}

func (s *Server) handleReplicationTaskRun(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if !s.jobsReady(w) {
		return
	}
	id := u.ID
	j, err := s.cfg.Replication.RunNow(r.Context(), r.PathValue("id"), &id)
	if errors.Is(err, replication.ErrRunning) {
		writeError(w, http.StatusConflict, "running", err.Error())
		return
	}
	if err != nil {
		s.replErr(w, err)
		return
	}
	s.record(r, u, "replication.task.run", r.PathValue("id"), audit.Success, "job "+j.ID)
	writeJSON(w, http.StatusAccepted, JobAccepted{Job: j, Warnings: []string{}})
}

func (s *Server) handleReplicationTaskCancel(w http.ResponseWriter, r *http.Request, u *auth.User) {
	if err := s.cfg.Replication.Cancel(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusConflict, "not_running", err.Error())
		return
	}
	s.record(r, u, "replication.task.cancel", r.PathValue("id"), audit.Success, "")
	writeJSON(w, http.StatusOK, map[string]bool{"cancelled": true})
}

func (s *Server) handleReplicationTaskHistory(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	l, err := s.cfg.Replication.Store().Runs(r.Context(), r.PathValue("id"), 100)
	if err != nil {
		s.replErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"runs": l})
}

// ReplicationSourceView is a source with its replicas' sizes.
type ReplicationSourceView struct {
	replication.Source
	UsedBytes uint64                   `json:"usedBytes"`
	Replicas  []replication.RemoteItem `json:"replicas"`
}

// ReplicationReceive is the receiving side's page.
type ReplicationReceive struct {
	Receiving bool                    `json:"receiving"`
	Hostname  string                  `json:"hostname"`
	Port      int                     `json:"port"`
	Pin       string                  `json:"pin"`
	Pairing   *replication.Pairing    `json:"pairing"`
	Sources   []ReplicationSourceView `json:"sources"`
	Problem   string                  `json:"problem,omitempty"`
}

func (s *Server) handleReplicationReceive(w http.ResponseWriter, r *http.Request, _ *auth.User) {
	svc := s.cfg.Replication
	ctx := r.Context()
	id, err := svc.Identity(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	st := svc.Store()
	pairing, err := st.Pairing(ctx, time.Now().UTC())
	if err != nil {
		internalError(s, w, err)
		return
	}
	sources, err := st.Sources(ctx)
	if err != nil {
		internalError(s, w, err)
		return
	}
	out := ReplicationReceive{Receiving: pairing != nil || len(sources) > 0, Hostname: hostnameOf(), Port: replication.DefaultPort,
		Pin: id.Pin, Pairing: pairing, Sources: []ReplicationSourceView{}}
	reps, err := svc.Root.Replicas(ctx)
	if err != nil {
		out.Problem = "the replicas' sizes can't be read: " + err.Error()
	}
	for _, src := range sources {
		v := ReplicationSourceView{Source: src, Replicas: []replication.RemoteItem{}}
		names := map[string]string{}
		for _, it := range src.Items {
			names[it.Kind+"/"+it.ID] = it.Name
		}
		for _, rs := range reps {
			if rs.Source != src.ID || rs.Pool != src.Pool {
				continue
			}
			v.UsedBytes = rs.UsedBytes
			for _, it := range rs.Items {
				name := names[it.Kind+"/"+it.ID]
				if name == "" {
					name = it.ID
				}
				v.Replicas = append(v.Replicas, replication.RemoteItem{Kind: it.Kind, ID: it.ID, Name: name, UsedBytes: it.UsedBytes,
					Snapshots: it.Snapshots, LastSnapshot: it.LastSnapshot, LastAt: it.LastAt, Partial: it.Partial})
			}
		}
		out.Sources = append(out.Sources, v)
	}
	writeJSON(w, http.StatusOK, out)
}

type replicationPairingRequest struct {
	Pool       string `json:"pool"`
	QuotaBytes uint64 `json:"quotaBytes"`
	MinKeep    int    `json:"minKeep"`
}

// ReplicationPairingCode is a new pairing code, shown once.
type ReplicationPairingCode struct {
	Job       any       `json:"job"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
	Port      int       `json:"port"`
	Hostname  string    `json:"hostname"`
}

func (s *Server) handleReplicationPairingCreate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req replicationPairingRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := replica.ValidPool(req.Pool); err != nil {
		writeError(w, http.StatusBadRequest, "invalid", "choose the pool that keeps the replicas")
		return
	}
	if req.MinKeep == 0 {
		req.MinKeep = 3
	}
	if req.MinKeep < 1 || req.MinKeep > replication.MaxKeep {
		writeError(w, http.StatusBadRequest, "invalid", "keep at least 1 snapshot")
		return
	}
	if !s.jobsReady(w) {
		return
	}
	_, code := replication.NewCode()
	ref := jobSecrets.put(code)
	id := u.ID
	j, err := s.cfg.Jobs.Submit(r.Context(), replication.JobPairingCreate, "Open a replication pairing code",
		replication.PairingParams{Pool: req.Pool, QuotaBytes: req.QuotaBytes, MinKeep: req.MinKeep, SecretRef: ref}, &id)
	if err != nil {
		internalError(s, w, err)
		return
	}
	s.record(r, u, "replication.receive.pairing", req.Pool, audit.Success, "job "+j.ID)
	writeJSON(w, http.StatusAccepted, ReplicationPairingCode{Job: j, Code: code, ExpiresAt: time.Now().UTC().Add(replication.PairingTTL),
		Port: replication.DefaultPort, Hostname: hostnameOf()})
}

func (s *Server) handleReplicationPairingCancel(w http.ResponseWriter, r *http.Request, u *auth.User) {
	s.submit(w, r, u, replication.JobPairingCancel, "Close the replication pairing code", map[string]string{}, "replication.receive.pairing.cancel", "", nil)
}

type replicationSourceUpdate struct {
	QuotaBytes uint64 `json:"quotaBytes"`
	MinKeep    int    `json:"minKeep"`
}

func (s *Server) handleReplicationSourceUpdate(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req replicationSourceUpdate
	if !decodeJSON(w, r, &req) {
		return
	}
	src, err := s.cfg.Replication.Store().Source(r.Context(), r.PathValue("id"))
	if err != nil {
		s.replErr(w, err)
		return
	}
	if req.MinKeep < 1 || req.MinKeep > replication.MaxKeep {
		writeError(w, http.StatusBadRequest, "invalid", "keep at least 1 snapshot")
		return
	}
	s.submit(w, r, u, replication.JobSourceUpdate, "Change replication from "+src.Name,
		replication.SourceUpdateParams{Source: src.ID, QuotaBytes: req.QuotaBytes, MinKeep: req.MinKeep}, "replication.source.update", src.ID+" "+src.Name, nil)
}

type replicationSourceDelete struct {
	Confirm        string `json:"confirm"`
	DeleteReplicas bool   `json:"deleteReplicas"`
}

func (s *Server) handleReplicationSourceDelete(w http.ResponseWriter, r *http.Request, u *auth.User) {
	var req replicationSourceDelete
	if !decodeJSON(w, r, &req) {
		return
	}
	src, err := s.cfg.Replication.Store().Source(r.Context(), r.PathValue("id"))
	if err != nil {
		s.replErr(w, err)
		return
	}
	if strings.TrimSpace(req.Confirm) != src.Name {
		writeError(w, http.StatusBadRequest, "confirm_required", "type the server's name ("+src.Name+") to confirm: its replicas are gone for good")
		return
	}
	title := "Stop receiving from " + src.Name
	if req.DeleteReplicas {
		title = "Delete the replicas from " + src.Name
	}
	s.submit(w, r, u, replication.JobSourceDelete, title, replication.SourceDeleteParams{Source: src.ID, DeleteReplicas: req.DeleteReplicas, Confirm: req.Confirm},
		"replication.source.delete", src.ID+" "+src.Name, nil)
}
