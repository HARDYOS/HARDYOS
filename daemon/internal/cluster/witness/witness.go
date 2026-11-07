// Package witness is the cluster witness that runs on the VPS
// (docs/plans/cluster.md 3.3): the cluster core only (stream layer, Raft,
// the pure state machine, heartbeats and witness.hello). It votes when the
// cluster's HardyOS voter count is even, holds the log, hands leadership
// over at once if it ever leads, signs nothing but its own hello, and runs
// no workloads. It is reached over NetBird only.
package witness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
)

// Config is /etc/hardyos-witness/witness.json, written by the install
// script (nothing secret).
type Config struct {
	Cluster cluster.ClusterID `json:"cluster"`
	// Node is the witness's id in the cluster, Name its hostname.
	Node cluster.NodeID `json:"node"`
	Name string         `json:"name"`
	// Listen is the VPS's NetBird address (the only one it listens on).
	Listen netip.Addr `json:"listen"`
	// Members are the members' NetBird endpoints and key pins the join
	// may use (the script got them from the member that made it).
	Members []Member `json:"members"`
}

// Member is one member the witness may join through.
type Member struct {
	Address netip.AddrPort `json:"address"`
	Pin     string         `json:"pin"`
}

// LoadConfig reads and checks the configuration.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := state.ValidNodeID(c.Node); err != nil {
		return nil, err
	}
	if err := state.ValidClusterID(c.Cluster); err != nil {
		return nil, err
	}
	if !c.Listen.IsValid() {
		return nil, errors.New("the configuration has no NetBird address to listen on")
	}
	if len(c.Members) == 0 {
		return nil, errors.New("the configuration names no members")
	}
	return &c, nil
}

// FileStore keeps the witness's membership in its state directory.
type FileStore struct {
	Dir string
	mu  sync.Mutex
}

func (f *FileStore) path(name string) string { return filepath.Join(f.Dir, name) }

func (f *FileStore) write(name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := f.path(name + ".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path(name))
}

// Info implements cluster.Store.
func (f *FileStore) Info(context.Context) (*cluster.Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := os.ReadFile(f.path("membership.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var i cluster.Info
	return &i, json.Unmarshal(b, &i)
}

// SetInfo implements cluster.Store.
func (f *FileStore) SetInfo(_ context.Context, i *cluster.Info) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.write("membership.json", i)
}

// ClearInfo implements cluster.Store.
func (f *FileStore) ClearInfo(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	err := os.Remove(f.path("membership.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Seq implements cluster.Store.
func (f *FileStore) Seq(context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := os.ReadFile(f.path("seq.json"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var s uint64
	return s, json.Unmarshal(b, &s)
}

// SetSeq implements cluster.Store.
func (f *FileStore) SetSeq(_ context.Context, s uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.write("seq.json", s)
}

// The witness never admits anyone: it has no join codes.

// JoinCodes implements cluster.Store.
func (f *FileStore) JoinCodes(context.Context, time.Time) ([]cluster.JoinCode, error) {
	return nil, nil
}

// AddJoinCode implements cluster.Store.
func (f *FileStore) AddJoinCode(context.Context, cluster.JoinCode) error {
	return errors.New("the witness doesn't admit servers")
}

// TakeJoinCode implements cluster.Store.
func (f *FileStore) TakeJoinCode(context.Context, string) error { return nil }

// JoinCodeFailed implements cluster.Store.
func (f *FileStore) JoinCodeFailed(context.Context, string) (int, error) { return 0, nil }

// LoadIdentity reads the witness's key (0600 in its state directory),
// making one the first time.
func LoadIdentity(dir, name string) (*cluster.Identity, error) {
	p := filepath.Join(dir, "identity.json")
	b, err := os.ReadFile(p)
	if err == nil {
		return cluster.UnmarshalIdentity(b)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	id, err := cluster.NewIdentity(name)
	if err != nil {
		return nil, err
	}
	b, err = cluster.MarshalIdentity(id)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(p+".tmp", b, 0o600); err != nil {
		return nil, err
	}
	return id, os.Rename(p+".tmp", p)
}

// Status is written to status.json for the install script (no secrets).
type Status struct {
	Joined  bool              `json:"joined"`
	Cluster cluster.ClusterID `json:"cluster,omitempty"`
	Node    cluster.NodeID    `json:"node,omitempty"`
	Leader  cluster.NodeID    `json:"leader,omitempty"`
	Voter   bool              `json:"voter"`
	Problem string            `json:"problem,omitempty"`
	Time    time.Time         `json:"time"`
}

// Options run a witness.
type Options struct {
	Config  *Config
	Dir     string
	Version string
	BootID  string
	// JoinCode is read only while the witness isn't a member yet.
	JoinCode func() (string, error)
	Net      cluster.Network
	Port     int
	Log      *slog.Logger
	// Raft and Paths tune timings (tests); zero: defaults.
	Raft    cluster.RaftTimings
	Paths   cluster.PathTimings
	Timings *cluster.Timings
}

// Witness is a running witness.
type Witness struct {
	opts Options
	core *cluster.Core
	log  *slog.Logger
}

// New prepares a witness.
func New(ctx context.Context, o Options) (*Witness, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	id, err := LoadIdentity(o.Dir, o.Config.Name)
	if err != nil {
		return nil, fmt.Errorf("witness key: %w", err)
	}
	addrs := cluster.Addresses{NetBird: o.Config.Listen}
	core, err := cluster.New(ctx, cluster.Config{
		Identity: id, Store: &FileStore{Dir: o.Dir}, Machine: state.New(), Net: o.Net, Port: o.Port, Dir: o.Dir,
		Version: o.Version, Features: state.Features(), BootID: o.BootID,
		Addresses: func() cluster.Addresses { return addrs },
		Raft:      o.Raft, Paths: o.Paths, Timings: o.Timings, Log: o.Log,
	})
	if err != nil {
		return nil, err
	}
	return &Witness{opts: o, core: core, log: o.Log}, nil
}

// Core is the witness's cluster core.
func (w *Witness) Core() *cluster.Core { return w.core }

func (w *Witness) hello() state.WitnessHelloBody {
	return state.WitnessHelloBody{Addresses: cluster.Addresses{NetBird: w.opts.Config.Listen}, Version: w.opts.Version,
		Features: state.Features(), BootID: w.opts.BootID}
}

// Join joins through the configured members (each one's key must be the
// pinned one).
func (w *Witness) Join(ctx context.Context) error {
	if w.core.Info() != nil {
		return nil
	}
	code, err := w.opts.JoinCode()
	if err != nil {
		return fmt.Errorf("the join code: %w", err)
	}
	var errs []string
	for _, m := range w.opts.Config.Members {
		_, err := w.core.Join(ctx, cluster.JoinParams{Address: m.Address.String(), Code: strings.TrimSpace(code),
			Node: w.opts.Config.Node, Name: w.opts.Config.Name, Role: cluster.RoleWitness, Pins: []string{m.Pin}})
		if err == nil {
			w.log.Info("witness: joined the cluster", "through", m.Address)
			return nil
		}
		var jr *cluster.JoinRefused
		if errors.As(err, &jr) {
			return err
		}
		errs = append(errs, m.Address.String()+": "+err.Error())
	}
	return errors.New("couldn't join through any member: " + strings.Join(errs, "; "))
}

// Run joins if needed, then takes part until ctx ends.
func (w *Witness) Run(ctx context.Context) error {
	if err := w.Join(ctx); err != nil {
		w.writeStatus(err.Error())
		return err
	}
	if !w.core.Running() {
		if err := w.core.Start(ctx); err != nil {
			return err
		}
	}
	defer w.core.Stop()
	// Announce (or re-announce) this witness: its first hello makes it
	// active; later ones carry a new version or address.
	go func() {
		for ctx.Err() == nil {
			if err := w.announce(ctx); err == nil {
				w.writeStatus("")
				return
			} else {
				w.log.Debug("witness: hello", "err", err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
		}
	}()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			w.writeStatus("")
		}
	}
}

func (w *Witness) announce(ctx context.Context) error {
	info := w.core.Info()
	self, ok := w.core.Machine().Node(info.Node)
	if ok && self.State == cluster.NodeJoining {
		return w.core.FinishJoin(ctx, w.hello())
	}
	h := w.hello()
	if ok && self.Version == h.Version && self.BootID == h.BootID && self.Addresses.NetBird == h.Addresses.NetBird &&
		slices.Equal(self.Features, h.Features) {
		return nil
	}
	if !ok {
		return errors.New("not in the state yet")
	}
	_, err := w.core.Propose(ctx, cluster.CmdWitnessHello, h, cluster.Actor{Kind: "system", Name: "witness"})
	return err
}

func (w *Witness) writeStatus(problem string) {
	st := Status{Problem: problem, Time: time.Now().UTC()}
	if info := w.core.Info(); info != nil {
		st.Joined, st.Cluster, st.Node = true, info.Cluster, info.Node
		st.Leader, _ = w.core.Leader()
		for _, n := range w.core.Status(context.Background()).Nodes {
			if n.ID == info.Node {
				st.Voter = n.Live == cluster.Voter
			}
		}
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	p := filepath.Join(w.opts.Dir, "status.json")
	if err := os.WriteFile(p+".tmp", b, 0o644); err == nil {
		_ = os.Rename(p+".tmp", p)
	}
}
