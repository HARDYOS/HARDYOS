// Package sanclient is a compute node's side of cluster storage
// (docs/plans/cluster.md section 6.1), run by hardyd-priv: open-iscsi
// logins to this node's own target on the storage node (mutual CHAP, the
// secrets only in root-only node records, never in a command line), the
// optional multipath allow list, NFSv4.2 mounts under /mnt/hc, block-mode
// app volumes, and the attachment records the VM and app engines read
// through their StorageBackend implementations (backends.go).
//
// Nothing here decides what may be attached: hardyd attaches what the
// applied cluster state grants this node, and the storage node only lets
// this node reach what it granted. Root still validates every name and
// path, and refuses storage paths that would leave over NetBird.
package sanclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Operation names (priv/sanclient_ops.go).
const (
	OpStatus         = "sanclient.status"
	OpInitiatorSet   = "sanclient.initiator.set"
	OpLogin          = "sanclient.iscsi.login"
	OpLogout         = "sanclient.iscsi.logout"
	OpRescan         = "sanclient.iscsi.rescan"
	OpNFSMount       = "sanclient.nfs.mount"
	OpNFSUmount      = "sanclient.nfs.umount"
	OpMultipathApply = "sanclient.multipath.apply"
	OpAttach         = "sanclient.attach"
	OpDetach         = "sanclient.detach"
	OpFreeze         = "sanclient.vm.freeze"
	OpThaw           = "sanclient.vm.thaw"
	OpAppDump        = "sanclient.app.dump"
)

// Paths.
const (
	ISCSIDir      = "/etc/iscsi"
	AttachedFile  = "/run/hardyos/cluster/attached.json"
	MultipathConf = "/etc/multipath/conf.d/hardyos-cluster.conf"
)

// Client is the compute node's root side.
type Client struct {
	Runner sysexec.Runner
	// Sys prefixes system paths; "/" in production.
	Sys string
	Log *slog.Logger
	// DeviceWait bounds waiting for a LUN's device (default 10 s).
	DeviceWait time.Duration
	// Dump runs an app's backup dump on this node (apps.Manager.PreBackup).
	Dump func(ctx context.Context, id string) (bool, error)
	// ThawAfter is the automatic thaw of a forwarded freeze (default 60 s).
	ThawAfter time.Duration

	mu     sync.Mutex
	thaws  map[string]*time.Timer
	recsMu sync.Mutex
}

func (c *Client) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

func (c *Client) sys(p string) string {
	if c.Sys == "" || c.Sys == "/" {
		return p
	}
	return filepath.Join(c.Sys, p)
}

func (c *Client) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return sysexec.Output(ctx, c.Runner, name, args...)
}

// ValidationError is a refused request (bad_args).
type ValidationError struct{ Err error }

func (e *ValidationError) Error() string { return e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

func bad(format string, a ...any) error { return &ValidationError{fmt.Errorf(format, a...)} }

var (
	ifRE   = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$`)
	idRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	poolRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.:-]{0,63}$`)
	wwnRE  = regexp.MustCompile(`^6001405[0-9a-f]{25}$`)
	diskRE = regexp.MustCompile(`^disk[0-9]$`)
	shRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

// netbirdRange is NetBird's default CGNAT range; storage never goes there.
var netbirdRange = netip.MustParsePrefix("100.64.0.0/10")

// RouteCheck refuses a storage address whose route doesn't leave on the
// storage interface (never wt0, never NetBird's range): bulk storage must
// not go over NetBird or the LAN by accident.
func (c *Client) RouteCheck(ctx context.Context, iface string, addr netip.Addr) error {
	if !ifRE.MatchString(iface) {
		return bad("storage interface %q isn't valid", iface)
	}
	if strings.HasPrefix(iface, "wt") {
		return bad("%s is NetBird's interface; storage never goes over NetBird", iface)
	}
	if !addr.Is4() || netbirdRange.Contains(addr) {
		return bad("%s can't be a storage network address", addr)
	}
	out, err := c.run(ctx, "ip", "-j", "route", "get", addr.String())
	if err != nil {
		return fmt.Errorf("finding the route to %s: %w", addr, err)
	}
	var routes []struct {
		Dev     string `json:"dev"`
		PrefSrc string `json:"prefsrc"`
		Gateway string `json:"gateway"`
	}
	if err := json.Unmarshal(out, &routes); err != nil || len(routes) == 0 {
		return fmt.Errorf("reading the route to %s: %v", addr, err)
	}
	r := routes[0]
	if r.Dev != iface {
		return fmt.Errorf("the storage server %s is reached through %s, not the storage network (%s); refusing", addr, r.Dev, iface)
	}
	if r.Gateway != "" {
		return fmt.Errorf("the storage server %s is behind a router (%s); the storage network must be one segment", addr, r.Gateway)
	}
	if src, err := netip.ParseAddr(r.PrefSrc); err == nil && netbirdRange.Contains(src) {
		return fmt.Errorf("the route to %s uses a NetBird address; refusing", addr)
	}
	return nil
}

// Status is sanclient.status's answer.
type Status struct {
	Initiator string            `json:"initiator"`
	Sessions  []Session         `json:"sessions"`
	Mounts    []string          `json:"mounts"`
	Attached  []Record          `json:"attached"`
	Shares    map[string]string `json:"shares"`
	Healthy   bool              `json:"healthy"`
	Problem   string            `json:"problem,omitempty"`
	Multipath bool              `json:"multipath"`
	Frozen    []string          `json:"frozen,omitempty"`
}

// Status reports sessions, mounts and attachments, and whether every
// attached path answers.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	st := &Status{Shares: map[string]string{}, Attached: []Record{}}
	st.Initiator = c.initiatorName()
	sess, err := c.sessions(ctx)
	if err != nil {
		st.Problem = err.Error()
	}
	st.Sessions = sess
	recs, err := c.loadRecords()
	if err != nil {
		return nil, err
	}
	for _, r := range recs.Workloads {
		st.Attached = append(st.Attached, r)
		st.Multipath = st.Multipath || r.Multipath
	}
	for id, m := range recs.Shares {
		st.Shares[id] = m.MountPath
	}
	st.Mounts = c.clusterMounts()
	ok, problem := c.Healthy(ctx)
	st.Healthy = ok
	if problem != "" {
		st.Problem = problem
	}
	c.mu.Lock()
	for id := range c.thaws {
		st.Frozen = append(st.Frozen, id)
	}
	c.mu.Unlock()
	return st, nil
}

// Healthy checks that every attached device exists and every cluster
// mount answers within a few seconds (a stat on a hard NFS mount of a
// lost server would block, so it runs with a deadline in a goroutine).
func (c *Client) Healthy(ctx context.Context) (bool, string) {
	recs, err := c.loadRecords()
	if err != nil {
		return false, err.Error()
	}
	var problems []string
	for _, r := range recs.Workloads {
		for name, dev := range r.Disks {
			if !c.exists(dev) {
				problems = append(problems, fmt.Sprintf("%s/%s: %s is gone", r.Workload.ID, name, dev))
			}
		}
	}
	dirs := []string{}
	for _, r := range recs.Workloads {
		if r.StateDir != "" {
			dirs = append(dirs, r.StateDir)
		}
	}
	for _, s := range recs.Shares {
		dirs = append(dirs, s.MountPath)
	}
	for _, d := range dirs {
		if !c.answers(d, 5*time.Second) {
			problems = append(problems, d+" doesn't answer")
		}
	}
	if len(problems) > 0 {
		return false, strings.Join(problems, "; ")
	}
	return true, ""
}

// SessionArgs names this node's target.
type SessionArgs struct {
	Cluster cluster.ClusterID `json:"cluster"`
	Node    cluster.NodeID    `json:"node"`
	// Force (logout): drop the session even with devices in use (self
	// fencing).
	Force bool `json:"force,omitempty"`
}

func (a SessionArgs) check() error {
	if err := san.ValidCluster(a.Cluster); err != nil {
		return &ValidationError{err}
	}
	if err := san.ValidNode(a.Node); err != nil {
		return &ValidationError{err}
	}
	return nil
}

var errNoSessions = errors.New("no iSCSI sessions")
