package replica

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// serviceProps are HardyOS's own properties that make a dataset something
// (a shared folder, a VM, an app's kept disk). A replica must never become
// one of those on the receiving server, whatever the stream says.
var serviceProps = []string{
	"org.hardyos:share", "org.hardyos:name", "org.hardyos:description", "org.hardyos:access",
	"org.hardyos:apps", "org.hardyos:recycle", "org.hardyos:guest", "org.hardyos:services",
	"org.hardyos:nfs-uid", "org.hardyos:vm", "org.hardyos:kept", "org.hardyos:role",
	"org.hardyos:snapshot", "org.hardyos:label", "org.hardyos:consistent", "org.hardyos:version",
	PropRestored, PropRestoring,
}

// receiveArgs are the zfs receive arguments for a replica: never mounted
// (canmount=off, a mountpoint under the pool's replicas folder), read
// only, no NFS/SMB sharing and none of HardyOS's service properties,
// volumes without device nodes (volmode=none: the host never looks at a
// guest's partitions), resumable (-s) and not mounted after (-u).
func receiveArgs(t Target, label string, objset uint32) []string {
	args := []string{"receive", "-u", "-s"}
	if objset == ObjsetVolume {
		args = append(args, "-o", "readonly=on", "-o", "volmode=none", "-o", "refreservation=none")
	} else {
		args = append(args, "-o", "canmount=off", "-o", "mountpoint="+t.Mountpoint(), "-o", "readonly=on",
			"-o", "exec=off", "-o", "setuid=off", "-o", "devices=off",
			"-x", "sharenfs", "-x", "sharesmb")
	}
	args = append(args, "-o", PropReplica+"="+t.Source)
	for _, p := range serviceProps {
		args = append(args, "-x", p)
	}
	return append(args, t.Dataset()+"@"+label)
}

// RecvArgs starts receiving a stream into a replica. Pool, quota and
// MinKeep come from hardyd's record of the source (chosen on this
// server); everything else from the sending server, validated here.
type RecvArgs struct {
	Target
	Task       string `json:"task"`
	Snapshot   string `json:"snapshot"`
	QuotaBytes uint64 `json:"quotaBytes"`
}

// RecvStart is a started receive; the file handed over is where the
// stream goes.
type RecvStart struct {
	Stream string `json:"stream"`
}

// ensureLayout makes <pool>/replicas/<source>/<kind> as needed (never
// mounted, read only) and applies the source's quota.
func (m *Manager) ensureLayout(ctx context.Context, t Target, quota uint64) error {
	if _, err := m.zfs(ctx, "list", "-H", "-o", "name", t.Pool); err != nil {
		return fmt.Errorf("there's no pool called %s", t.Pool)
	}
	root := RootDataset(t.Pool)
	if _, ok := m.exists(ctx, root); !ok {
		if _, err := m.zfs(ctx, "create", "-o", "canmount=off", "-o", "mountpoint="+zfs.MountRoot+"/"+t.Pool+"/"+ReplicasDataset,
			"-o", "readonly=on", "-o", PropRole+"=replicas", root); err != nil {
			return fmt.Errorf("creating %s: %w", root, err)
		}
	} else if v := m.prop(ctx, root, PropRole); v != "replicas" {
		return fmt.Errorf("%s exists but isn't HardyOS's replicas dataset; rename it first", root)
	}
	src := SourceDataset(t.Pool, t.Source)
	if _, ok := m.exists(ctx, src); !ok {
		if _, err := m.zfs(ctx, "create", "-o", "canmount=off", "-o", PropRole+"=replica-source", "-o", PropReplica+"="+t.Source, src); err != nil {
			return fmt.Errorf("creating %s: %w", src, err)
		}
	} else if v := m.prop(ctx, src, PropReplica); v != t.Source {
		return fmt.Errorf("%s isn't this source's replicas", src)
	}
	q := "none"
	if quota > 0 {
		q = strconv.FormatUint(quota, 10)
	}
	if v := m.prop(ctx, src, "quota"); v != q && !(q == "none" && v == "0") {
		if _, err := m.zfs(ctx, "set", "quota="+q, src); err != nil {
			return fmt.Errorf("setting the source's quota: %w", err)
		}
	}
	kind := KindDataset(t.Pool, t.Source, t.Kind)
	if _, ok := m.exists(ctx, kind); !ok {
		if _, err := m.zfs(ctx, "create", "-o", "canmount=off", "-o", PropReplica+"="+t.Source, kind); err != nil {
			return fmt.Errorf("creating %s: %w", kind, err)
		}
	}
	return nil
}

// prop reads one property's value ("" when unset or unreadable).
func (m *Manager) prop(ctx context.Context, ds, name string) string {
	out, err := m.zfs(ctx, "get", "-H", "-p", "-o", "value", name, ds)
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if v == "-" {
		return ""
	}
	return v
}

// Recv starts a receive into a replica and returns the write end of the
// pipe hardyd copies the stream into. Before zfs sees anything, the
// stream's first record is checked (Policy): one dataset, no properties,
// known features, the right snapshot, incremental over an existing
// replica. The dataset name zfs is given is built here, under
// <pool>/replicas/<source>/; the stream's own name for it is ignored.
func (m *Manager) Recv(ctx context.Context, a RecvArgs) (*RecvStart, *os.File, error) {
	if err := a.Target.Validate(); err != nil {
		return nil, nil, err
	}
	if err := ValidTask(a.Task); err != nil {
		return nil, nil, err
	}
	if err := ValidSnap(a.Snapshot, a.Task); err != nil {
		return nil, nil, err
	}
	if err := m.ensureLayout(ctx, a.Target, a.QuotaBytes); err != nil {
		return nil, nil, err
	}
	ds := a.Dataset()
	pol := Policy{Label: a.Snapshot}
	if a.Child != "" {
		parent := ds[:strings.LastIndex(ds, "/")]
		if _, ok := m.exists(ctx, parent); !ok {
			return nil, nil, fmt.Errorf("%s comes before %s: %w", parent, ds, ErrNotFound)
		}
	}
	if typ, ok := m.exists(ctx, ds); ok {
		switch typ {
		case "filesystem":
			pol.Objset = ObjsetFilesystem
		case "volume":
			pol.Objset = ObjsetVolume
		default:
			return nil, nil, fmt.Errorf("%s is a %s", ds, typ)
		}
		// PropReplica is inherited from <pool>/replicas/<source>, so even
		// a partly received dataset has it.
		if v := m.prop(ctx, ds, PropReplica); v != a.Source {
			return nil, nil, fmt.Errorf("%s isn't a replica from this source", ds)
		}
		// A full stream that was interrupted leaves the new dataset with
		// a resume token: only the rest of that stream may follow.
		pol.Incremental = true
	}
	s, err := m.streams.add(ds)
	if err != nil {
		return nil, nil, err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		s.finish(err)
		return nil, nil, err
	}
	s.mu.Lock()
	s.closer = pr
	s.mu.Unlock()
	go func() {
		defer pr.Close()
		s.finish(m.receive(pr, s, a.Target, pol))
	}()
	m.log().Info("replication: receive", "stream", s.id, "dataset", ds, "snapshot", a.Snapshot)
	return &RecvStart{Stream: s.id}, pw, nil
}

// receive checks the stream's first record and runs zfs receive on it.
func (m *Manager) receive(r io.Reader, s *stream, t Target, pol Policy) error {
	hdr := make([]byte, BeginRecordSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return fmt.Errorf("reading the stream: %w", err)
	}
	b, err := ParseBegin(hdr)
	if err != nil {
		return err
	}
	if err := pol.Check(b); err != nil {
		m.log().Warn("replication: refused a stream", "dataset", t.Dataset(), "err", err)
		return err
	}
	s.bytes.Add(int64(len(hdr)))
	return m.runReceive(s, receiveArgs(t, pol.Label, b.Objset), io.MultiReader(bytes.NewReader(hdr), countingReader{r: r, n: &s.bytes}))
}

func (m *Manager) runReceive(s *stream, args []string, in io.Reader) error {
	s.mu.Lock()
	if s.killed {
		s.mu.Unlock()
		return fmt.Errorf("cancelled")
	}
	errs := &tail{}
	p, err := m.starter().Start("zfs", args, in, io.Discard, errs)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.proc = p
	s.mu.Unlock()
	if err := p.Wait(); err != nil {
		if msg := errs.String(); msg != "" {
			return fmt.Errorf("zfs receive: %s", msg)
		}
		return fmt.Errorf("zfs receive: %w", err)
	}
	return nil
}

// RecvState is what the sending server needs to know about a replica.
type RecvState struct {
	Exists bool   `json:"exists"`
	Type   string `json:"type,omitempty"`
	// Snapshots are its replication snapshots, oldest first.
	Snapshots []SnapInfo `json:"snapshots"`
	// Token resumes an interrupted transfer (zfs send -t).
	Token     string `json:"token,omitempty"`
	UsedBytes uint64 `json:"usedBytes"`
}

// State reports a replica's snapshots and any interrupted transfer.
func (m *Manager) State(ctx context.Context, t Target) (*RecvState, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	st := &RecvState{Snapshots: []SnapInfo{}}
	ds := t.Dataset()
	typ, ok := m.exists(ctx, ds)
	if !ok {
		return st, nil
	}
	if v := m.prop(ctx, ds, PropReplica); v != t.Source {
		return nil, fmt.Errorf("%s isn't a replica from this source", ds)
	}
	st.Exists, st.Type = true, typ
	if tok := m.prop(ctx, ds, "receive_resume_token"); tok != "" && ValidToken(tok) == nil {
		st.Token = tok
	}
	if n, err := strconv.ParseUint(m.prop(ctx, ds, "used"), 10, 64); err == nil {
		st.UsedBytes = n
	}
	l, err := m.listSnaps(ctx, ds, "")
	if err != nil {
		return nil, err
	}
	if l != nil {
		st.Snapshots = l
	}
	return st, nil
}

// Abort throws away an interrupted transfer into a replica (zfs receive
// -A), so a fresh one can start.
func (m *Manager) Abort(ctx context.Context, t Target) error {
	if err := t.Validate(); err != nil {
		return err
	}
	ds := t.Dataset()
	if m.streams.running(ds) {
		return ErrBusy
	}
	if _, ok := m.exists(ctx, ds); !ok {
		return nil
	}
	if v := m.prop(ctx, ds, PropReplica); v != t.Source {
		return fmt.Errorf("%s isn't a replica from this source", ds)
	}
	if m.prop(ctx, ds, "receive_resume_token") == "" {
		return nil
	}
	if _, err := m.zfs(ctx, "receive", "-A", ds); err != nil {
		return fmt.Errorf("discarding the interrupted transfer: %w", err)
	}
	return nil
}

// RecvPruneArgs prunes a replica: keep the newest Keep of the task's
// snapshots (never fewer than 1).
type RecvPruneArgs struct {
	Target
	Task string `json:"task"`
	Keep int    `json:"keep"`
}

// PruneReplica removes a task's older snapshots of a replicated item.
func (m *Manager) PruneReplica(ctx context.Context, a RecvPruneArgs) (*PruneResult, error) {
	a.Child = ""
	if err := a.Target.Validate(); err != nil {
		return nil, err
	}
	if err := ValidTask(a.Task); err != nil {
		return nil, err
	}
	if a.Keep < 1 {
		a.Keep = 1
	}
	ds := a.ItemDataset()
	if m.streams.running(ds) {
		return nil, ErrBusy
	}
	if _, ok := m.exists(ctx, ds); !ok {
		return &PruneResult{Deleted: []string{}}, nil
	}
	if v := m.prop(ctx, ds, PropReplica); v != a.Source {
		return nil, fmt.Errorf("%s isn't a replica from this source", ds)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pruneTree(ctx, ds, a.Task, a.Keep, nil)
}

// ReplicaItem is one replicated item on this server.
type ReplicaItem struct {
	Kind      string `json:"kind"`
	ID        string `json:"id"`
	UsedBytes uint64 `json:"usedBytes"`
	// LastSnapshot is the newest replication snapshot, if any.
	LastSnapshot string     `json:"lastSnapshot,omitempty"`
	LastAt       *time.Time `json:"lastAt,omitempty"`
	Snapshots    int        `json:"snapshots"`
	// Partial: an interrupted transfer waits to be resumed.
	Partial bool `json:"partial"`
}

// ReplicaSource is one source's replicas on one pool.
type ReplicaSource struct {
	Pool       string        `json:"pool"`
	Source     string        `json:"source"`
	UsedBytes  uint64        `json:"usedBytes"`
	QuotaBytes uint64        `json:"quotaBytes"`
	Items      []ReplicaItem `json:"items"`
}

// Replicas lists every source's replicas on every pool.
func (m *Manager) Replicas(ctx context.Context) ([]ReplicaSource, error) {
	out, err := sysexecOutput(ctx, m, "zpool", "list", "-H", "-o", "name")
	if err != nil {
		return nil, err
	}
	res := []ReplicaSource{}
	for _, pool := range lines(out) {
		if ValidPool(pool) != nil {
			continue
		}
		root := RootDataset(pool)
		if v := m.prop(ctx, root, PropRole); v != "replicas" {
			continue
		}
		dl, err := m.zfs(ctx, "list", "-H", "-p", "-o", "name,used,quota,receive_resume_token,"+PropReplica, "-r", "-t", "filesystem,volume", root)
		if err != nil {
			return nil, err
		}
		bySrc := map[string]*ReplicaSource{}
		items := map[string]*ReplicaItem{}
		for _, l := range lines(dl) {
			f := strings.Split(l, "\t")
			if len(f) != 5 {
				continue
			}
			rel, ok := strings.CutPrefix(f[0], root+"/")
			if !ok {
				continue
			}
			parts := strings.Split(rel, "/")
			if ValidSource(parts[0]) != nil || f[4] != parts[0] {
				continue
			}
			used, _ := strconv.ParseUint(f[1], 10, 64)
			src := bySrc[parts[0]]
			if src == nil {
				src = &ReplicaSource{Pool: pool, Source: parts[0], Items: []ReplicaItem{}}
				bySrc[parts[0]] = src
			}
			switch {
			case len(parts) == 1:
				src.UsedBytes = used
				src.QuotaBytes, _ = strconv.ParseUint(f[2], 10, 64)
			case len(parts) == 3 && ValidKind(parts[1]) == nil && ValidItem(parts[2]) == nil:
				it := &ReplicaItem{Kind: parts[1], ID: parts[2], UsedBytes: used}
				items[f[0]] = it
				it.Partial = f[3] != "-" && f[3] != ""
			case len(parts) > 3:
				if it := items[root+"/"+strings.Join(parts[:3], "/")]; it != nil && f[3] != "-" && f[3] != "" {
					it.Partial = true
				}
			}
		}
		for ds, it := range items {
			snaps, err := m.listSnaps(ctx, ds, "")
			if err == nil && len(snaps) > 0 {
				last := snaps[len(snaps)-1]
				_, at, _ := ParseSnap(last.Name)
				it.LastSnapshot, it.LastAt, it.Snapshots = last.Name, &at, len(snaps)
			}
			src := bySrc[strings.Split(strings.TrimPrefix(ds, root+"/"), "/")[0]]
			src.Items = append(src.Items, *it)
		}
		for _, src := range bySrc {
			sort.Slice(src.Items, func(i, j int) bool {
				if src.Items[i].Kind != src.Items[j].Kind {
					return src.Items[i].Kind < src.Items[j].Kind
				}
				return src.Items[i].ID < src.Items[j].ID
			})
			res = append(res, *src)
		}
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].Source != res[j].Source {
			return res[i].Source < res[j].Source
		}
		return res[i].Pool < res[j].Pool
	})
	return res, nil
}

func sysexecOutput(ctx context.Context, m *Manager, name string, args ...string) ([]byte, error) {
	res, err := m.Runner.Run(ctx, nil, name, args...)
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("%s exited %d: %s", name, res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return res.Stdout, nil
}

// DeleteSourceArgs deletes every replica of one source on one pool.
// Confirm must repeat the source id (hardyd asks the person to type the
// source server's name first).
type DeleteSourceArgs struct {
	Pool    string `json:"pool"`
	Source  string `json:"source"`
	Confirm string `json:"confirm"`
}

// DeleteSource destroys <pool>/replicas/<source> and everything in it.
func (m *Manager) DeleteSource(ctx context.Context, a DeleteSourceArgs) error {
	if err := ValidPool(a.Pool); err != nil {
		return err
	}
	if err := ValidSource(a.Source); err != nil {
		return err
	}
	if a.Confirm != a.Source {
		return invalid("confirm with the source's id (%s): its replicas are gone for good", a.Source)
	}
	ds := SourceDataset(a.Pool, a.Source)
	if m.streams.running(ds) {
		return ErrBusy
	}
	if _, ok := m.exists(ctx, ds); !ok {
		return nil
	}
	if m.prop(ctx, RootDataset(a.Pool), PropRole) != "replicas" || m.prop(ctx, ds, PropReplica) != a.Source {
		return fmt.Errorf("%s isn't this source's replicas", ds)
	}
	if _, err := m.zfs(ctx, "destroy", "-r", ds); err != nil {
		return fmt.Errorf("deleting the replicas: %w", err)
	}
	m.log().Info("replication: deleted a source's replicas", "dataset", ds)
	return nil
}

// ReplicaSendArgs sends a replica's snapshot back (to restore it on the
// source): one dataset, the whole snapshot.
type ReplicaSendArgs struct {
	Target
	Snapshot string `json:"snapshot"`
}

// SendReplica starts zfs send of a replica's snapshot.
func (m *Manager) SendReplica(ctx context.Context, a ReplicaSendArgs) (*SendStart, *os.File, error) {
	if err := a.Target.Validate(); err != nil {
		return nil, nil, err
	}
	if err := ValidSnap(a.Snapshot, ""); err != nil {
		return nil, nil, err
	}
	ds := a.Dataset()
	if v := m.prop(ctx, ds, PropReplica); v != a.Source {
		return nil, nil, fmt.Errorf("%s: %w", ds, ErrNotFound)
	}
	snap := ds + "@" + a.Snapshot
	if _, ok := m.exists(ctx, snap); !ok {
		return nil, nil, fmt.Errorf("snapshot %s: %w", snap, ErrNotFound)
	}
	args := append(append([]string{"send"}, sendFlags...), snap)
	var est int64
	if out, err := m.zfs(ctx, append([]string{"send", "-n", "-P"}, args[1:]...)...); err == nil {
		est = sizeOf(out)
	}
	return m.startSend(args, est)
}

// ReplicaChildren lists a replicated item's datasets as of a snapshot
// (those that have it), relative to the item.
func (m *Manager) ReplicaChildren(ctx context.Context, t Target, snapshot string) ([]Child, error) {
	t.Child = ""
	if err := t.Validate(); err != nil {
		return nil, err
	}
	if err := ValidSnap(snapshot, ""); err != nil {
		return nil, err
	}
	top := t.ItemDataset()
	if v := m.prop(ctx, top, PropReplica); v != t.Source {
		return nil, fmt.Errorf("%s: %w", top, ErrNotFound)
	}
	kids, err := m.children(ctx, top)
	if err != nil {
		return nil, err
	}
	var res []Child
	for _, k := range kids {
		if _, ok := m.exists(ctx, top+childSuffix(k.Child)+"@"+snapshot); ok {
			res = append(res, k)
		}
	}
	if len(res) == 0 || res[0].Child != "" {
		return nil, fmt.Errorf("snapshot %s@%s: %w", top, snapshot, ErrNotFound)
	}
	return res, nil
}

// ReplicaSnapshots lists a replicated item's snapshots (newest last).
func (m *Manager) ReplicaSnapshots(ctx context.Context, t Target) ([]SnapInfo, error) {
	t.Child = ""
	if err := t.Validate(); err != nil {
		return nil, err
	}
	top := t.ItemDataset()
	if v := m.prop(ctx, top, PropReplica); v != t.Source {
		return []SnapInfo{}, nil
	}
	l, err := m.listSnaps(ctx, top, "")
	if l == nil {
		l = []SnapInfo{}
	}
	return l, err
}
