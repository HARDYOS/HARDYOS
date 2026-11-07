package member

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/cluster/witness"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/notify"
	"github.com/hardyos/hardyos/daemon/internal/secretbox"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Job kinds (every change goes through a job and the audit log).
const (
	JobCreate   = "cluster.create"
	JobJoin     = "cluster.join"
	JobLeave    = "cluster.leave"
	JobRemove   = "cluster.remove"
	JobDissolve = "cluster.dissolve"
)

// WitnessBinaryPath is where hardyos-core installs the witness binary
// members hand to the install script.
const WitnessBinaryPath = "/usr/lib/hardyos/hardyos-witness"

// Service runs this server's cluster membership inside hardyd.
type Service struct {
	DB      *store.DB
	Keys    secretbox.Source
	Jobs    *jobs.Manager
	Audit   *audit.Log
	Notify  notify.Notifier
	Log     *slog.Logger
	Version string
	// Dir is cluster.StateDir unless set (tests).
	Dir string
	// Net is the network (tests use a fake).
	Net cluster.Network
	// Addrs finds this server's addresses (nil: Discover).
	Addrs func(storage netip.Prefix) cluster.Addresses
	// Hostname is this server's name (nil: os.Hostname).
	Hostname func() string
	// Secrets hands a job its join code (the API's in-memory secret box).
	Secrets func(ref string) (string, bool)
	// WitnessBinary is the witness binary's path (WitnessBinaryPath).
	WitnessBinary string
	// Configure is called with every new core before it starts (the API
	// sets the relay handler; parts B and C register appliers and peer
	// endpoints).
	Configure []func(c *cluster.Core)
	// Health is this server's own report in heartbeats (parts B and C:
	// storage paths, LAN, running workloads); nil reports all well.
	Health func(ctx context.Context) cluster.LocalHealth
	// Raft, Paths and Timings tune the core (tests).
	Raft    cluster.RaftTimings
	Paths   cluster.PathTimings
	Timings *cluster.Timings

	mu     sync.Mutex
	st     *DBStore
	core   *cluster.Core
	live   *Live
	ctx    context.Context
	bootID string
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) store() *DBStore {
	if s.st == nil {
		s.st = &DBStore{DB: s.DB, Keys: s.Keys}
	}
	return s.st
}

// Store is the membership store.
func (s *Service) Store() *DBStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store()
}

func (s *Service) hostname() string {
	if s.Hostname != nil {
		return s.Hostname()
	}
	h, _ := os.Hostname()
	return strings.ToLower(strings.SplitN(h, ".", 2)[0])
}

var nonID = regexp.MustCompile(`[^a-z0-9-]+`)

// NodeIDFor makes a node id from a hostname.
func NodeIDFor(host string) cluster.NodeID {
	id := strings.Trim(nonID.ReplaceAllString(strings.ToLower(host), "-"), "-")
	if id == "" || id[0] < 'a' || id[0] > 'z' {
		id = "n-" + id
	}
	if len(id) > 32 {
		id = strings.TrimRight(id[:32], "-")
	}
	return cluster.NodeID(id)
}

// Init prepares the core (reading the membership); call before Start
// and before the API is served.
func (s *Service) Init(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx = context.WithoutCancel(ctx)
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		s.bootID = strings.TrimSpace(string(b))
	}
	return s.newCoreLocked(ctx)
}

func (s *Service) dir() string {
	if s.Dir != "" {
		return s.Dir
	}
	return cluster.StateDir
}

// spoolDir holds relayed request bodies too large for memory: on hardyd's
// own disk (the cluster folder), not in a tmpfs (decision 371).
func (s *Service) spoolDir() string { return filepath.Join(s.dir(), "spool") }

func (s *Service) newCoreLocked(ctx context.Context) error {

	st := s.store()
	id, err := st.Identity(ctx)
	if err != nil {
		return err
	}
	if id == nil {
		if id, err = st.NewIdentity(ctx, s.hostname()); err != nil {
			return err
		}
	}
	m := state.New()
	var core *cluster.Core
	core, err = cluster.New(ctx, cluster.Config{
		Identity: id, Store: st, Machine: m, Net: s.Net, Dir: s.dir(),
		Version: s.Version, Features: state.Features(), BootID: s.bootID,
		Addresses: func() cluster.Addresses {
			sn := m.Snapshot().StorageSubnet
			if s.Addrs != nil {
				return s.Addrs(sn)
			}
			return Discover(sn)
		},
		Raft: s.Raft, Paths: s.Paths, Timings: s.Timings, Health: s.Health,
		WitnessBinary: s.openWitnessBinary,
		SpoolDir:      s.spoolDir(),
		OnJoin:        s.auditJoin,
		Log:           s.log(),
	})
	if err != nil {
		return err
	}
	for _, f := range s.Configure {
		f(core)
	}
	s.core = core
	return nil
}

// Core is the current cluster core.
func (s *Service) Core() *cluster.Core {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.core
}

// Run starts the core when this server is a member and watches it for
// alerts until ctx ends.
func (s *Service) Run(ctx context.Context) {
	if c := s.Core(); c != nil && c.Info() != nil {
		if err := c.Start(ctx); err != nil {
			s.log().Error("cluster: starting", "err", err)
		}
	}
	s.watch(ctx)
	if c := s.Core(); c != nil {
		c.Stop()
	}
}

// watch raises alerts for lost quorum and a stopped state machine.
func (s *Service) watch(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	quorate := true
	halted := false
	since := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c := s.Core()
		if c == nil || c.Info() == nil || !c.Running() {
			if c != nil && c.Halted() != nil && !halted {
				halted = true
				s.alert(ctx, "cluster.halted", notify.SeverityCritical, "This server stopped following the cluster",
					c.Halted().Error()+" Update HardyOS on this server.")
			}
			quorate, since = true, time.Now()
			continue
		}
		ok, _ := c.Quorate()
		if ok != quorate && (ok || time.Since(since) > 30*time.Second) {
			quorate = ok
			if ok {
				s.alert(ctx, "cluster.quorum", notify.SeverityInfo, "The cluster has quorum again", "This server reaches a majority of the cluster's voters.")
			} else {
				s.alert(ctx, "cluster.quorum", notify.SeverityWarning, "This server lost the cluster's quorum",
					"It can't reach a majority of the voters. Changes wait; high-availability workloads here stop until it can.")
			}
		}
		if ok {
			since = time.Now()
		}
	}
}

func (s *Service) alert(ctx context.Context, kind, sev, title, body string) {
	if s.Notify == nil {
		return
	}
	s.Notify.Notify(ctx, notify.Event{Kind: kind, Severity: sev, Title: title, Body: body, Link: "cluster", Time: time.Now()})
}

func (s *Service) record(ctx context.Context, e audit.Entry) {
	if s.Audit == nil {
		return
	}
	if err := s.Audit.Record(context.WithoutCancel(ctx), e); err != nil {
		s.log().Warn("cluster: audit", "err", err)
	}
}

func (s *Service) auditJoin(ctx context.Context, e cluster.JoinEvent) {
	out, detail := audit.Success, fmt.Sprintf("%s %s joined (code by %s)", e.Role, e.Name, e.CodeBy)
	if !e.OK {
		out, detail = audit.Denied, e.Problem
	}
	s.record(ctx, audit.Entry{Action: "cluster.member.join", Target: string(e.Node), Outcome: out, Detail: detail, IP: e.IP,
		Actor: "server:" + string(e.Node)})
}

func (s *Service) openWitnessBinary() (io.ReadSeekCloser, error) {
	p := s.WitnessBinary
	if p == "" {
		p = WitnessBinaryPath
	}
	return os.Open(p)
}

// ---- jobs --------------------------------------------------------------------

// CreateParams is cluster.create's.
type CreateParams struct {
	Name          string        `json:"name"`
	Role          cluster.Role  `json:"role"`
	StorageSubnet string        `json:"storageSubnet,omitempty"`
	Actor         cluster.Actor `json:"actor"`
}

// JoinParams is cluster.join's (the code waits in the secret box).
type JoinParams struct {
	Address   string       `json:"address"`
	Role      cluster.Role `json:"role"`
	SecretRef string       `json:"secretRef"`
}

// LeaveParams is cluster.leave's and cluster.dissolve's.
type LeaveParams struct {
	Confirm string        `json:"confirm"`
	Actor   cluster.Actor `json:"actor"`
}

// RemoveParams is cluster.remove's.
type RemoveParams struct {
	Node    cluster.NodeID `json:"node"`
	Confirm string         `json:"confirm"`
	Actor   cluster.Actor  `json:"actor"`
}

// RegisterJobs adds the cluster job kinds (one at a time: lock "cluster").
func (s *Service) RegisterJobs(m *jobs.Manager) {
	lock := func(json.RawMessage) string { return "cluster" }
	m.Register(jobs.Kind{Name: JobCreate, LockKey: lock, AdminOnly: true, Run: s.runCreate})
	m.Register(jobs.Kind{Name: JobJoin, LockKey: lock, AdminOnly: true, Run: s.runJoin})
	m.Register(jobs.Kind{Name: JobLeave, LockKey: lock, AdminOnly: true, Run: s.runLeave})
	m.Register(jobs.Kind{Name: JobRemove, LockKey: lock, AdminOnly: true, Run: s.runRemove})
	m.Register(jobs.Kind{Name: JobDissolve, LockKey: lock, AdminOnly: true, Run: s.runDissolve})
}

// Create makes a new cluster with this server (the job's work).
func (s *Service) Create(ctx context.Context, p CreateParams) (cluster.ClusterID, error) {
	if p.Name == "" || len(p.Name) > 64 {
		return "", errors.New("give the cluster a name (1-64 characters)")
	}
	var sn netip.Prefix
	if p.StorageSubnet != "" {
		var err error
		if sn, err = netip.ParsePrefix(p.StorageSubnet); err != nil {
			return "", errors.New("the storage network must be written like 10.77.0.0/24")
		}
		sn = sn.Masked()
	}
	c := s.Core()
	host := s.hostname()
	id := NodeIDFor(host)
	if err := state.ValidNodeID(id); err != nil {
		return "", err
	}
	if !s.addrs(sn).LAN.IsValid() {
		return "", errors.New("this server has no LAN address")
	}
	return c.Create(ctx, cluster.CreateParams{Name: p.Name, Node: id, NodeName: host, Role: p.Role, StorageSubnet: sn}, p.Actor)
}

func (s *Service) addrs(sn netip.Prefix) cluster.Addresses {
	if s.Addrs != nil {
		return s.Addrs(sn)
	}
	return Discover(sn)
}

func (s *Service) runCreate(jc *jobs.Context) (any, error) {
	var p CreateParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	jc.Progress(10, "Starting the cluster log")
	id, err := s.Create(jc, p)
	if err != nil {
		return nil, err
	}
	return map[string]any{"cluster": id}, nil
}

// Join joins a cluster through a member (the job's work).
func (s *Service) Join(ctx context.Context, address, code string, role cluster.Role) (*cluster.JoinAnswer, error) {
	if role != cluster.RoleCompute && role != cluster.RoleStorage {
		return nil, errors.New("a server joins as compute or storage")
	}
	c := s.Core()
	host := s.hostname()
	ans, err := c.Join(ctx, cluster.JoinParams{Address: address, Code: code, Node: NodeIDFor(host), Name: host, Role: role})
	if err != nil {
		return nil, err
	}
	fctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := c.FinishJoin(fctx, nil); err != nil {
		return ans, fmt.Errorf("joined, but catching up didn't finish: %w", err)
	}
	return ans, nil
}

func (s *Service) runJoin(jc *jobs.Context) (any, error) {
	var p JoinParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	code, ok := "", false
	if s.Secrets != nil {
		code, ok = s.Secrets(p.SecretRef)
	}
	if !ok {
		return nil, errors.New("the join code expired before the job started: try again")
	}
	jc.Progress(10, "Pairing with "+p.Address)
	ans, err := s.Join(jc, p.Address, code, p.Role)
	if err != nil {
		return nil, err
	}
	return map[string]any{"cluster": ans.Cluster, "name": ans.Name, "warnings": ans.Warnings}, nil
}

// reset forgets the key and makes a new core (after leaving: the old pin
// is useless; a later join pairs with a new key).
func (s *Service) reset(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.store().DeleteIdentity(ctx); err != nil {
		return err
	}
	return s.newCoreLocked(ctx)
}

func (s *Service) runLeave(jc *jobs.Context) (any, error) {
	var p LeaveParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	c := s.Core()
	info := c.Info()
	if info == nil {
		return nil, cluster.ErrNotMember
	}
	if p.Confirm != c.Machine().Snapshot().Name {
		return nil, errors.New("type the cluster's name to confirm")
	}
	jc.Progress(20, "Leaving the cluster")
	if err := c.Leave(jc, p.Actor); err != nil {
		return nil, err
	}
	return nil, s.reset(jc)
}

func (s *Service) runDissolve(jc *jobs.Context) (any, error) {
	var p LeaveParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	if err := s.Core().Dissolve(jc, p.Confirm); err != nil {
		return nil, err
	}
	return nil, s.reset(jc)
}

func (s *Service) runRemove(jc *jobs.Context) (any, error) {
	var p RemoveParams
	if err := jc.Params(&p); err != nil {
		return nil, err
	}
	jc.Progress(20, "Removing "+string(p.Node))
	return nil, s.Core().Remove(jc, p.Node, p.Confirm, p.Actor)
}

// ---- the witness -------------------------------------------------------------

// WitnessScript opens a witness join code and renders the install script.
func (s *Service) WitnessScript(ctx context.Context, by string) ([]byte, *cluster.JoinOffer, error) {
	c := s.Core()
	self, err := c.Self()
	if err != nil {
		return nil, nil, err
	}
	f, err := s.openWitnessBinary()
	if err != nil {
		return nil, nil, errors.New("the witness binary isn't installed on this server")
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil {
		return nil, nil, err
	}
	off, err := c.OpenJoinCode(ctx, cluster.RoleWitness, by)
	if err != nil {
		return nil, nil, err
	}
	script, err := witness.Script(witness.ScriptParams{Cluster: c.Info().Cluster, Node: "witness", Code: off.Code,
		Members:   []witness.ScriptMember{{NetBird: self.Addresses.NetBird, Pin: self.Pin}},
		BinarySHA: hex.EncodeToString(h.Sum(nil)), Version: s.Version})
	if err != nil {
		return nil, nil, err
	}
	return script, off, nil
}

// Status is the cluster status for the API (this node's view).
func (s *Service) Status(ctx context.Context) cluster.Status {
	c := s.Core()
	if c == nil {
		return cluster.Status{Nodes: []cluster.NodeStatus{}}
	}
	return c.Status(ctx)
}
