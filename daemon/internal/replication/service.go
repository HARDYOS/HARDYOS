package replication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hardyos/hardyos/daemon/internal/audit"
	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/replica"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// Severities of a notification.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Event is a notification replication raises (the shape internal/notify's
// Event has; until that lands, main wires a no-op).
type Event struct {
	Kind     string
	Severity string
	Title    string
	Body     string
	Link     string
	Time     time.Time
}

// Notifier delivers notifications.
type Notifier interface {
	Notify(ctx context.Context, e Event)
}

// NopNotifier drops every notification.
type NopNotifier struct{}

// Notify implements Notifier.
func (NopNotifier) Notify(context.Context, Event) {}

// Event kinds.
const (
	EventFailed    = "replication.failed"
	EventStale     = "replication.stale"
	EventRecovered = "replication.recovered"
	EventRestored  = "replication.restored"
)

// DefaultPort is where a receiving server listens for other HardyOS
// servers (mutual TLS, pinned keys).
const DefaultPort = 44400

// Limits on task settings.
const (
	MinIntervalMinutes = 5
	MaxIntervalMinutes = 7 * 24 * 60
	MaxKeep            = 1000
	MaxItemsPerTask    = 100
	PairingTTL         = 30 * time.Minute
	MaxPairFailures    = 10
)

// Service is replication in hardyd.
type Service struct {
	DB       *store.DB
	Root     Root
	Jobs     *jobs.Manager
	Notifier Notifier
	Audit    *audit.Log
	Sealer   *Sealer
	Log      *slog.Logger
	// Hostname is this server's name as other servers see it.
	Hostname func() string
	Now      func() time.Time
	// ListenAddr is where the receiving side listens (default ":44400").
	ListenAddr string
	// Secrets hands a job a pairing code kept out of its parameters.
	Secrets func(ref string) (string, bool)
	// Poll is how often streams are checked on (default 250ms).
	Poll time.Duration

	initOnce  sync.Once
	st        *Store
	idMu      sync.Mutex
	id        *Identity
	pairMu    sync.Mutex
	pairFails failCounter
	browse    browseGate

	runMu   sync.Mutex
	running map[string]string // task id -> job id

	slotMu sync.Mutex
	slots  map[string]int // source id -> transfers running here
}

// MaxStreamsPerSource bounds how many transfers one source runs here at
// once (a run sends one dataset at a time; restores add one).
const MaxStreamsPerSource = 4

// slot takes one of a source's transfer slots; ok is false when it has
// them all.
func (s *Service) slot(source string) (release func(), ok bool) {
	s.slotMu.Lock()
	defer s.slotMu.Unlock()
	if s.slots == nil {
		s.slots = map[string]int{}
	}
	if s.slots[source] >= MaxStreamsPerSource {
		return nil, false
	}
	s.slots[source]++
	return func() {
		s.slotMu.Lock()
		defer s.slotMu.Unlock()
		s.slots[source]--
	}, true
}

func (s *Service) init() {
	s.initOnce.Do(func() {
		if s.Sealer == nil {
			s.Sealer = &Sealer{}
		}
		s.st = &Store{DB: s.DB, Sealer: s.Sealer}
		s.running = map[string]string{}
	})
}

// Store returns the records.
func (s *Service) Store() *Store {
	s.init()
	return s.st
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) hostname() string {
	if s.Hostname != nil {
		if h := s.Hostname(); h != "" {
			return h
		}
	}
	h, _ := os.Hostname()
	if h == "" {
		h = "hardyos"
	}
	return h
}

func (s *Service) notifier() Notifier {
	if s.Notifier != nil {
		return s.Notifier
	}
	return NopNotifier{}
}

func (s *Service) poll() time.Duration {
	if s.Poll > 0 {
		return s.Poll
	}
	return 250 * time.Millisecond
}

// Identity returns this server's replication identity.
func (s *Service) Identity(ctx context.Context) (*Identity, error) {
	s.init()
	s.idMu.Lock()
	defer s.idMu.Unlock()
	if s.id != nil {
		return s.id, nil
	}
	id, err := loadIdentity(ctx, s.DB, s.Sealer, s.hostname())
	if err != nil {
		return nil, err
	}
	s.id = id
	return id, nil
}

func (s *Service) record(ctx context.Context, action, target, detail, ip string, outcome audit.Outcome) {
	if s.Audit == nil {
		return
	}
	if err := s.Audit.Record(ctx, audit.Entry{Action: action, Target: target, Outcome: outcome, Detail: detail, IP: ip, Actor: "hardyos"}); err != nil {
		s.log().Warn("replication: audit", "err", err)
	}
}

// ---- validation -------------------------------------------------------------

var (
	hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$`)
)

// CleanAddress checks host, host:port, an IP or [IPv6]:port and returns
// it as host:port.
func CleanAddress(a string) (string, error) {
	a = strings.TrimSpace(a)
	a = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(a, "https://"), "http://"), "/")
	if a == "" || len(a) > 260 {
		return "", errors.New("enter the other server's address (a name or IP address, optionally with :port)")
	}
	host, port := a, strconv.Itoa(DefaultPort)
	if h, p, err := net.SplitHostPort(a); err == nil {
		host, port = h, p
	} else if strings.Count(a, ":") > 1 {
		host = strings.Trim(a, "[]")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("the port %q isn't valid", port)
	}
	if ip := net.ParseIP(host); ip == nil && !hostRE.MatchString(host) {
		return "", fmt.Errorf("%q isn't a server name or IP address", host)
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

// cleanLabel makes a name another server sent safe to show and store.
func cleanLabel(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	// No control, format (bidi overrides, zero-width), private-use,
	// line or paragraph separator characters: a name can't hide or
	// reorder what's shown next to it.
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs) || r == 0xfeff {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return s
}

// CheckTask validates a task's settings.
func CheckTask(t *Task) error {
	t.Name = cleanLabel(t.Name, 60)
	if t.Name == "" {
		return errors.New("give the task a name")
	}
	if t.IntervalMinutes < MinIntervalMinutes || t.IntervalMinutes > MaxIntervalMinutes {
		return fmt.Errorf("run every %d minutes to 7 days", MinIntervalMinutes)
	}
	if t.BandwidthKBps < 0 || t.BandwidthKBps > 10_000_000 {
		return errors.New("the bandwidth limit isn't valid")
	}
	if t.KeepLocal < 1 || t.KeepLocal > MaxKeep || t.KeepRemote < 1 || t.KeepRemote > MaxKeep {
		return fmt.Errorf("keep between 1 and %d snapshots on each side", MaxKeep)
	}
	if len(t.Items) == 0 {
		return errors.New("choose at least one shared folder, app or VM")
	}
	if len(t.Items) > MaxItemsPerTask {
		return fmt.Errorf("at most %d items per task", MaxItemsPerTask)
	}
	seen := map[string]bool{}
	for _, it := range t.Items {
		if err := it.Validate(); err != nil {
			return err
		}
		if seen[it.String()] {
			return fmt.Errorf("%s is listed twice", it)
		}
		seen[it.String()] = true
	}
	return nil
}

// StaleAfter is how long without a successful run before a task is
// reported as stale: three intervals, and at least an hour more than one.
func StaleAfter(intervalMinutes int) time.Duration {
	iv := time.Duration(intervalMinutes) * time.Minute
	return max(3*iv, iv+time.Hour)
}

// ---- jobs ---------------------------------------------------------------------

// Job kinds.
const (
	JobRun           = "replication.run"
	JobRestore       = "replication.restore"
	JobPair          = "replication.pair"
	JobTargetUpdate  = "replication.target.update"
	JobTargetDelete  = "replication.target.delete"
	JobTaskCreate    = "replication.task.create"
	JobTaskUpdate    = "replication.task.update"
	JobTaskDelete    = "replication.task.delete"
	JobPairingCreate = "replication.receive.pairing"
	JobPairingCancel = "replication.receive.pairing.cancel"
	JobSourceUpdate  = "replication.source.update"
	JobSourceDelete  = "replication.source.delete"
)

// TaskParams names a task.
type TaskParams struct {
	Task string `json:"task"`
}

// PairParams pairs with a receiving server; the code waits in Secrets.
type PairParams struct {
	Address   string `json:"address"`
	SecretRef string `json:"secretRef"`
}

// TargetUpdateParams changes a target's address.
type TargetUpdateParams struct {
	Target  string `json:"target"`
	Address string `json:"address"`
}

// TargetDeleteParams forgets a target (Confirm = its name).
type TargetDeleteParams struct {
	Target  string `json:"target"`
	Confirm string `json:"confirm"`
}

// TaskDeleteParams deletes a task and its snapshots here (Confirm = its
// name). Replicas on the target stay.
type TaskDeleteParams struct {
	Task    string `json:"task"`
	Confirm string `json:"confirm"`
}

// RestoreParams brings a replica's snapshot back.
type RestoreParams struct {
	Target   string `json:"target"`
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Snapshot string `json:"snapshot"`
	Pool     string `json:"pool,omitempty"`
	NewID    string `json:"newId,omitempty"`
	Name     string `json:"name,omitempty"`
}

// PairingParams opens a pairing code (the code waits in Secrets).
type PairingParams struct {
	Pool       string `json:"pool"`
	QuotaBytes uint64 `json:"quotaBytes"`
	MinKeep    int    `json:"minKeep"`
	MinAgeDays *int   `json:"minAgeDays,omitempty"`
	SecretRef  string `json:"secretRef"`
}

// SourceUpdateParams changes a source's rules.
type SourceUpdateParams struct {
	Source string `json:"source"`
	SourceRules
}

// SourceDeleteParams forgets a source; with DeleteReplicas its replicas
// go too (Confirm = its name).
type SourceDeleteParams struct {
	Source         string `json:"source"`
	DeleteReplicas bool   `json:"deleteReplicas"`
	Confirm        string `json:"confirm"`
}

// RegisterJobs adds replication's job kinds.
func (s *Service) RegisterJobs(m *jobs.Manager) {
	s.init()
	taskLock := func(raw json.RawMessage) string {
		var p struct {
			Task string `json:"task"`
		}
		_ = json.Unmarshal(raw, &p)
		return "replication:" + p.Task
	}
	cfgLock := func(json.RawMessage) string { return "replication" }
	reg := func(name string, lock func(json.RawMessage) string, run jobs.RunFunc) {
		m.Register(jobs.Kind{Name: name, AdminOnly: true, Run: run, LockKey: lock})
	}
	reg(JobRun, taskLock, func(jc *jobs.Context) (any, error) {
		var p TaskParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		defer s.finished(p.Task, jc.ID())
		return s.runTask(jc, p.Task)
	})
	reg(JobRestore, func(json.RawMessage) string { return "replication-restore" }, func(jc *jobs.Context) (any, error) {
		var p RestoreParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		return s.restore(jc, p)
	})
	reg(JobPair, cfgLock, func(jc *jobs.Context) (any, error) {
		var p PairParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		code, ok := "", false
		if s.Secrets != nil {
			code, ok = s.Secrets(p.SecretRef)
		}
		if !ok {
			return nil, errors.New("the pairing code is gone (hardyd restarted?); enter it again")
		}
		jc.Progress(20, "Connecting to "+p.Address)
		return s.Pair(jc, p.Address, code)
	})
	reg(JobTargetUpdate, cfgLock, func(jc *jobs.Context) (any, error) {
		var p TargetUpdateParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		addr, err := CleanAddress(p.Address)
		if err != nil {
			return nil, err
		}
		if err := s.st.UpdateTargetAddress(jc, p.Target, addr); err != nil {
			return nil, err
		}
		return s.st.Target(jc, p.Target)
	})
	reg(JobTargetDelete, cfgLock, func(jc *jobs.Context) (any, error) {
		var p TargetDeleteParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		return nil, s.deleteTarget(jc, p)
	})
	reg(JobTaskCreate, cfgLock, func(jc *jobs.Context) (any, error) {
		var t Task
		if err := jc.Params(&t); err != nil {
			return nil, err
		}
		t.ID = ""
		return s.saveTask(jc, &t)
	})
	reg(JobTaskUpdate, cfgLock, func(jc *jobs.Context) (any, error) {
		var t Task
		if err := jc.Params(&t); err != nil {
			return nil, err
		}
		if t.ID == "" {
			return nil, store.ErrNotFound
		}
		return s.saveTask(jc, &t)
	})
	reg(JobTaskDelete, cfgLock, func(jc *jobs.Context) (any, error) {
		var p TaskDeleteParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		return nil, s.deleteTask(jc, p)
	})
	reg(JobPairingCreate, cfgLock, func(jc *jobs.Context) (any, error) {
		var p PairingParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		code, ok := "", false
		if s.Secrets != nil {
			code, ok = s.Secrets(p.SecretRef)
		}
		if !ok {
			return nil, errors.New("the pairing code is gone (hardyd restarted?); make a new one")
		}
		raw, err := ParseCode(code)
		if err != nil {
			return nil, err
		}
		return s.OpenPairing(jc, raw, p)
	})
	reg(JobPairingCancel, cfgLock, func(jc *jobs.Context) (any, error) {
		return nil, s.st.ClearPairing(jc)
	})
	reg(JobSourceUpdate, cfgLock, func(jc *jobs.Context) (any, error) {
		var p SourceUpdateParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		if err := p.SourceRules.Check(); err != nil {
			return nil, err
		}
		if err := s.st.UpdateSource(jc, p.Source, p.SourceRules); err != nil {
			return nil, err
		}
		return s.st.Source(jc, p.Source)
	})
	reg(JobSourceDelete, cfgLock, func(jc *jobs.Context) (any, error) {
		var p SourceDeleteParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		return nil, s.deleteSource(jc, p)
	})
}

func (s *Service) saveTask(ctx context.Context, t *Task) (*Task, error) {
	if err := CheckTask(t); err != nil {
		return nil, err
	}
	if t.ID != "" {
		old, err := s.st.Task(ctx, t.ID)
		if err != nil {
			return nil, err
		}
		t.TargetID = old.TargetID // a task's target never changes: its replicas are there
	}
	if _, err := s.st.Target(ctx, t.TargetID); err != nil {
		return nil, fmt.Errorf("choose a paired server: %w", err)
	}
	// An item goes to one server once: two tasks sending it to the same
	// place would each break the other's chain of snapshots.
	all, err := s.st.Tasks(ctx)
	if err != nil {
		return nil, err
	}
	mine := map[string]bool{}
	for _, it := range t.Items {
		mine[it.String()] = true
	}
	for _, o := range all {
		if o.ID == t.ID || o.TargetID != t.TargetID {
			continue
		}
		for _, it := range o.Items {
			if mine[it.String()] {
				return nil, fmt.Errorf("%s already goes to that server in the task %s", it, o.Name)
			}
		}
	}
	if err := s.st.SaveTask(ctx, t); err != nil {
		return nil, err
	}
	return s.st.Task(ctx, t.ID)
}

func (s *Service) deleteTask(ctx context.Context, p TaskDeleteParams) error {
	t, err := s.st.Task(ctx, p.Task)
	if err != nil {
		return err
	}
	if strings.TrimSpace(p.Confirm) != t.Name {
		return fmt.Errorf("type the task's name (%s) to confirm", t.Name)
	}
	if s.isRunning(t.ID) {
		return errors.New("the task is running; cancel it first")
	}
	// Its snapshots here go: nothing would ever prune them again.
	for _, it := range t.Items {
		if _, err := s.Root.Prune(ctx, replica.PruneArgs{Task: t.ID, Kind: it.Kind, ID: it.ID, Forget: true}); err != nil {
			s.log().Warn("replication: removing a deleted task's snapshots", "task", t.ID, "item", it.String(), "err", err)
		}
	}
	return s.st.DeleteTask(ctx, t.ID)
}

func (s *Service) deleteTarget(ctx context.Context, p TargetDeleteParams) error {
	t, err := s.st.Target(ctx, p.Target)
	if err != nil {
		return err
	}
	if strings.TrimSpace(p.Confirm) != t.Name {
		return fmt.Errorf("type the server's name (%s) to confirm", t.Name)
	}
	tasks, err := s.st.Tasks(ctx)
	if err != nil {
		return err
	}
	for _, task := range tasks {
		if task.TargetID == t.ID {
			return fmt.Errorf("the task %s still sends to %s; delete it first", task.Name, t.Name)
		}
	}
	return s.st.DeleteTarget(ctx, t.ID)
}

func (s *Service) deleteSource(ctx context.Context, p SourceDeleteParams) error {
	src, err := s.st.Source(ctx, p.Source)
	if err != nil {
		return err
	}
	if strings.TrimSpace(p.Confirm) != src.Name {
		return fmt.Errorf("type the server's name (%s) to confirm", src.Name)
	}
	if p.DeleteReplicas {
		if err := s.Root.DeleteSource(ctx, replica.DeleteSourceArgs{Pool: src.Pool, Source: src.ID, Confirm: src.ID}); err != nil {
			return err
		}
	}
	return s.st.DeleteSource(ctx, src.ID)
}

// ---- running tasks ----------------------------------------------------------

func (s *Service) isRunning(task string) bool {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	_, ok := s.running[task]
	return ok
}

// RunningJob is the job running a task, if any.
func (s *Service) RunningJob(task string) string {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	return s.running[task]
}

func (s *Service) finished(task, job string) {
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if s.running[task] == job {
		delete(s.running, task)
	}
}

// ErrRunning means the task already runs.
var ErrRunning = errors.New("the task is already running")

// RunNow queues a task's run (by an administrator, or the schedule when
// userID is nil).
func (s *Service) RunNow(ctx context.Context, taskID string, userID *int64) (*jobs.Job, error) {
	s.init()
	t, err := s.st.Task(ctx, taskID)
	if err != nil {
		return nil, err
	}
	s.runMu.Lock()
	defer s.runMu.Unlock()
	if _, ok := s.running[t.ID]; ok {
		return nil, ErrRunning
	}
	j, err := s.Jobs.Submit(ctx, JobRun, "Replicate "+t.Name, TaskParams{Task: t.ID}, userID)
	if err != nil {
		return nil, err
	}
	s.running[t.ID] = j.ID
	return j, nil
}

// Cancel stops a task's running job.
func (s *Service) Cancel(ctx context.Context, taskID string) error {
	id := s.RunningJob(taskID)
	if id == "" {
		return errors.New("the task isn't running")
	}
	return s.Jobs.Cancel(ctx, id)
}

// Run is the schedule: every minute, due tasks are started and late ones
// reported. It also listens for other servers while this one receives.
func (s *Service) Run(ctx context.Context) {
	s.init()
	s.st.failInterrupted(ctx)
	go s.serveWhileReceiving(ctx)
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
			t.Reset(time.Minute)
		}
	}
}

// Tick starts due tasks and raises stale alerts.
func (s *Service) Tick(ctx context.Context) {
	s.init()
	tasks, err := s.st.Tasks(ctx)
	if err != nil {
		s.log().Warn("replication: listing tasks", "err", err)
		return
	}
	now := s.now()
	for _, t := range tasks {
		if !t.Enabled {
			continue
		}
		iv := time.Duration(t.IntervalMinutes) * time.Minute
		if t.LastRunAt == nil || now.Sub(*t.LastRunAt) >= iv {
			if _, err := s.RunNow(ctx, t.ID, nil); err != nil && !errors.Is(err, ErrRunning) {
				s.log().Warn("replication: starting a task", "task", t.ID, "err", err)
			}
		}
		since := t.CreatedAt
		if t.LastSuccessAt != nil {
			since = *t.LastSuccessAt
		}
		if now.Sub(since) > StaleAfter(t.IntervalMinutes) && t.Alert != "stale" {
			last := "never"
			if t.LastSuccessAt != nil {
				last = t.LastSuccessAt.Format("2006-01-02 15:04 UTC")
			}
			s.notifier().Notify(ctx, Event{Kind: EventStale, Severity: SeverityCritical, Title: "Replication " + t.Name + " is behind",
				Body: "Its last successful run was " + last + ". " + t.LastError, Link: "replication:" + t.ID, Time: now})
			_ = s.st.setAlert(ctx, t.ID, "stale")
		}
	}
}

// Address is one of this server's addresses other servers can use.
type Address struct {
	Address   string `json:"address"`
	Interface string `json:"interface"`
	NetBird   bool   `json:"netbird"`
}

// skipInterfaces are never listened on: Docker, libvirt and VM taps, the
// domain controller's shim, WireGuard tunnels other than NetBird's.
var skipInterfaces = []string{"lo", "docker", "veth", "br-", "virbr", "vnet", "tap", "hdc", "macvtap"}

// LocalAddresses lists this server's global unicast addresses on its LAN
// ports, bridges for VMs (br0) and NetBird (wt0).
func LocalAddresses() []Address {
	out := []Address{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		skip := false
		for _, p := range skipInterfaces {
			skip = skip || strings.HasPrefix(ifc.Name, p)
		}
		if skip {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || !ipn.IP.IsGlobalUnicast() {
				continue
			}
			out = append(out, Address{Address: ipn.IP.String(), Interface: ifc.Name, NetBird: ifc.Name == "wt0"})
		}
	}
	return out
}
