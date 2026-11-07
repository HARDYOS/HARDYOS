package state

// Part B's appliers (docs/plans/cluster.md sections 5 and 7.4): the storage
// node's acknowledgements (grants applied, fences in place, unfences),
// shared folders in the cluster, app user ids and an app's storage layout.
// Like every applier they are pure: no clock (the command's Time is used),
// no I/O, deterministic on every node and the witness.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// StorageAppliedBody is storage.applied: LIO and the exports match these
// grants (each at its generation).
type StorageAppliedBody struct {
	Grants []GrantAck `json:"grants"`
}

// GrantAck acknowledges one grant at one generation.
type GrantAck struct {
	Workload   cluster.WorkloadRef `json:"workload"`
	Generation uint64              `json:"generation"`
}

// StorageFencedBody is storage.fenced: the node's target is disabled, its
// exports are removed, its NFSv4 clients expired and its address dropped.
type StorageFencedBody struct {
	Node  cluster.NodeID `json:"node"`
	Epoch uint64         `json:"epoch"`
}

// StorageUnfencedBody is storage.unfenced: a rejoining node's target is
// enabled again (nothing mapped) and it is back in the shares' exports.
type StorageUnfencedBody struct {
	Node  cluster.NodeID `json:"node"`
	Epoch uint64         `json:"epoch"`
}

// ShareClusterBody is storage.share: a shared folder joins (In) or leaves
// the cluster exports.
type ShareClusterBody struct {
	Share cluster.ClusterShare `json:"share"`
	In    bool                 `json:"in"`
}

// AppUIDBody is storage.appuid: give an app a cluster-wide user id, or
// release it (Release).
type AppUIDBody struct {
	App     string `json:"app"`
	UID     int    `json:"uid"`
	Release bool   `json:"release,omitempty"`
}

// StorageLayoutBody is storage.layout: a stopped workload's storage
// changed (an app moved between NFS and block mode). Generation is the
// placement generation the storage node moved the data under.
type StorageLayoutBody struct {
	Workload   cluster.WorkloadRef     `json:"workload"`
	Generation uint64                  `json:"generation"`
	Storage    cluster.WorkloadStorage `json:"storage"`
}

// First and last app user ids (apps.FirstAppUID..LastAppUID; repeated
// here so the state package stays free of system packages).
const (
	firstAppUID = 30000
	lastAppUID  = 30999
)

var (
	idRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	poolRE  = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.:-]{0,63}$`)
	fsidRE  = regexp.MustCompile(`^[0-9]{1,20}$`)
	shareRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	diskRE  = regexp.MustCompile(`^disk[0-9]$`)
)

// Storage is part B's Applier.
type Storage struct{}

var _ cluster.Applier = Storage{}

// Types implements cluster.Applier.
func (Storage) Types() []cluster.CommandType {
	return []cluster.CommandType{cluster.CmdStorageApplied, cluster.CmdStorageFenced, cluster.CmdStorageUnfence,
		cluster.CmdShareCluster, cluster.CmdAppUID, cluster.CmdStorageLayout}
}

// Signers implements cluster.Applier: acknowledgements, fences and layout
// changes come only from the storage node (it is the one that acted);
// shares and app ids from any HardyOS member.
func (Storage) Signers(t cluster.CommandType) []cluster.Role {
	switch t {
	case cluster.CmdStorageApplied, cluster.CmdStorageFenced, cluster.CmdStorageUnfence, cluster.CmdStorageLayout,
		cluster.CmdShareCluster:
		return []cluster.Role{cluster.RoleStorage}
	case cluster.CmdAppUID:
		return []cluster.Role{cluster.RoleCompute, cluster.RoleStorage}
	}
	return nil
}

// Apply implements cluster.Applier.
func (st Storage) Apply(s *cluster.Snapshot, c cluster.Command) error {
	switch c.Type {
	case cluster.CmdStorageApplied:
		var b StorageAppliedBody
		if err := decode(c.Body, &b); err != nil {
			return err
		}
		return applyApplied(s, b)
	case cluster.CmdStorageFenced:
		var b StorageFencedBody
		if err := decode(c.Body, &b); err != nil {
			return err
		}
		return applyFenced(s, b, c)
	case cluster.CmdStorageUnfence:
		var b StorageUnfencedBody
		if err := decode(c.Body, &b); err != nil {
			return err
		}
		return applyUnfenced(s, b)
	case cluster.CmdShareCluster:
		var b ShareClusterBody
		if err := decode(c.Body, &b); err != nil {
			return err
		}
		return applyShare(s, b)
	case cluster.CmdAppUID:
		var b AppUIDBody
		if err := decode(c.Body, &b); err != nil {
			return err
		}
		return applyAppUID(s, b)
	case cluster.CmdStorageLayout:
		var b StorageLayoutBody
		if err := decode(c.Body, &b); err != nil {
			return err
		}
		return applyLayout(s, b)
	}
	return fmt.Errorf("storage applier: unexpected command %q", c.Type)
}

func decode(raw json.RawMessage, v any) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("bad command body: %w", err)
	}
	return nil
}

// applyApplied marks grants applied. An acknowledgement for a generation
// that is no longer current is skipped (the grant changed after the storage
// node acted); an entry acknowledging nothing current is rejected.
func applyApplied(s *cluster.Snapshot, b StorageAppliedBody) error {
	n := 0
	for _, a := range b.Grants {
		g := s.Grants[a.Workload]
		if g == nil || g.Generation != a.Generation {
			continue
		}
		g.Applied = true
		n++
	}
	if n == 0 {
		return errors.New("storage.applied: no current grant to acknowledge")
	}
	return nil
}

func applyFenced(s *cluster.Snapshot, b StorageFencedBody, c cluster.Command) error {
	f := s.Fences[b.Node]
	if f == nil || f.Epoch != b.Epoch {
		return fmt.Errorf("storage.fenced: no fence of %s at epoch %d", b.Node, b.Epoch)
	}
	if f.Confirmed {
		return fmt.Errorf("storage.fenced: %s's fence at epoch %d is already confirmed", b.Node, b.Epoch)
	}
	f.Confirmed = true
	f.ConfirmedAt = c.Time
	if n := s.Nodes[b.Node]; n != nil && n.State == cluster.NodeDead {
		n.State = cluster.NodeFenced
	}
	// The fenced node holds no grant any more: the storage node removed it
	// from every target and export.
	for _, g := range s.Grants {
		if containsNode(g.Nodes, b.Node) {
			g.Applied = false
		}
	}
	return nil
}

func applyUnfenced(s *cluster.Snapshot, b StorageUnfencedBody) error {
	n := s.Nodes[b.Node]
	if n == nil {
		return fmt.Errorf("storage.unfenced: %s isn't a member", b.Node)
	}
	f := s.Fences[b.Node]
	if f == nil || f.Epoch != b.Epoch || !f.Confirmed {
		return fmt.Errorf("storage.unfenced: no confirmed fence of %s at epoch %d", b.Node, b.Epoch)
	}
	if n.State != cluster.NodeRejoining {
		return fmt.Errorf("storage.unfenced: %s is %s, not rejoining", b.Node, n.State)
	}
	n.State = cluster.NodeActive
	delete(s.Fences, b.Node)
	return nil
}

// ValidClusterShare checks a cluster share record: names, the dataset
// under <pool>/shares/ and the mount path under the cluster mount root.
func ValidClusterShare(sh cluster.ClusterShare) error {
	if !shareRE.MatchString(sh.ID) {
		return fmt.Errorf("share id %q isn't valid", sh.ID)
	}
	if !poolRE.MatchString(sh.Pool) {
		return fmt.Errorf("pool %q isn't valid", sh.Pool)
	}
	if sh.Dataset != sh.Pool+"/shares/"+sh.ID {
		return fmt.Errorf("share %s: dataset %q isn't %s/shares/%s", sh.ID, sh.Dataset, sh.Pool, sh.ID)
	}
	if sh.MountPath != cluster.RemoteMountRoot+"/"+sh.Pool+"/shares/"+sh.ID {
		return fmt.Errorf("share %s: mount path %q isn't under %s", sh.ID, sh.MountPath, cluster.RemoteMountRoot)
	}
	if !strings.HasPrefix(sh.Path, "/") || strings.Contains(sh.Path, "..") || strings.ContainsAny(sh.Path, " \t\n\"'\\") {
		return fmt.Errorf("share %s: path %q can't be exported", sh.ID, sh.Path)
	}
	if !fsidRE.MatchString(sh.FSID) {
		return fmt.Errorf("share %s: fsid %q isn't a dataset GUID", sh.ID, sh.FSID)
	}
	return nil
}

func applyShare(s *cluster.Snapshot, b ShareClusterBody) error {
	if !b.In {
		if s.ClusterShares[b.Share.ID] == nil {
			return fmt.Errorf("storage.share: %s isn't in the cluster", b.Share.ID)
		}
		delete(s.ClusterShares, b.Share.ID)
		return nil
	}
	if err := ValidClusterShare(b.Share); err != nil {
		return fmt.Errorf("storage.share: %w", err)
	}
	if s.ClusterShares == nil {
		s.ClusterShares = map[string]*cluster.ClusterShare{}
	}
	sh := b.Share
	s.ClusterShares[sh.ID] = &sh
	return nil
}

func applyAppUID(s *cluster.Snapshot, b AppUIDBody) error {
	if !idRE.MatchString(b.App) {
		return fmt.Errorf("storage.appuid: app id %q isn't valid", b.App)
	}
	if b.Release {
		if s.AppUIDs[b.App] != b.UID {
			return fmt.Errorf("storage.appuid: %s doesn't have user id %d", b.App, b.UID)
		}
		delete(s.AppUIDs, b.App)
		return nil
	}
	if b.UID < firstAppUID || b.UID > lastAppUID {
		return fmt.Errorf("storage.appuid: %d is outside %d-%d", b.UID, firstAppUID, lastAppUID)
	}
	if u, ok := s.AppUIDs[b.App]; ok {
		return fmt.Errorf("storage.appuid: %s already has user id %d", b.App, u)
	}
	for app, u := range s.AppUIDs {
		if u == b.UID {
			return fmt.Errorf("storage.appuid: %d belongs to %s", b.UID, app)
		}
	}
	if s.AppUIDs == nil {
		s.AppUIDs = map[string]int{}
	}
	s.AppUIDs[b.App] = b.UID
	return nil
}

// FreeAppUID returns the lowest app user id not used in the state (0 when
// all are taken). Proposers use it; the applier still checks.
func FreeAppUID(s *cluster.Snapshot) int {
	used := map[int]bool{}
	for _, u := range s.AppUIDs {
		used[u] = true
	}
	for u := firstAppUID; u <= lastAppUID; u++ {
		if !used[u] {
			return u
		}
	}
	return 0
}

func applyLayout(s *cluster.Snapshot, b StorageLayoutBody) error {
	p := s.Placements[b.Workload]
	if p == nil {
		return fmt.Errorf("storage.layout: %s/%s isn't a cluster workload", b.Workload.Kind, b.Workload.ID)
	}
	if p.Generation != b.Generation {
		return cluster.ErrStaleGeneration
	}
	if p.State != cluster.PlacementStopped || p.Requested != cluster.RequestStopped {
		return fmt.Errorf("storage.layout: %s must be stopped", b.Workload.ID)
	}
	if err := ValidWorkloadStorage(b.Workload, b.Storage); err != nil {
		return fmt.Errorf("storage.layout: %w", err)
	}
	if b.Storage.Pool != p.Storage.Pool {
		return errors.New("storage.layout: the pool can't change")
	}
	p.Storage = b.Storage
	// A new generation: nodes re-attach the new layout, and the storage
	// node must apply (and acknowledge) the grant again.
	p.Generation++
	if g := s.Grants[b.Workload]; g != nil {
		g.Generation = p.Generation
		g.Applied = false
	}
	return nil
}

// ValidWorkloadStorage checks that a workload's storage names only its own
// datasets: VM disks <pool>/vms/<id>/diskN, the VM state <pool>/vms/<id>,
// an app's <pool>/apps/<id> and, in block mode, its <pool>/apps/<id>/block.
func ValidWorkloadStorage(w cluster.WorkloadRef, ws cluster.WorkloadStorage) error {
	if !idRE.MatchString(w.ID) {
		return fmt.Errorf("workload id %q isn't valid", w.ID)
	}
	if !poolRE.MatchString(ws.Pool) {
		return fmt.Errorf("pool %q isn't valid", ws.Pool)
	}
	switch w.Kind {
	case cluster.KindVM:
		if ws.Mode != "" || ws.BlockFS != "" {
			return errors.New("a VM has no data mode")
		}
		base := ws.Pool + "/vms/" + w.ID
		for _, v := range ws.Volumes {
			if !diskRE.MatchString(v.Disk) || v.Dataset != base+"/"+v.Disk {
				return fmt.Errorf("volume %q isn't one of %s's disks", v.Dataset, w.ID)
			}
		}
		for _, e := range ws.Exports {
			if e.Kind != cluster.ExportVMState || e.Dataset != base {
				return fmt.Errorf("export %q isn't %s's state", e.Dataset, w.ID)
			}
		}
	case cluster.KindApp:
		base := ws.Pool + "/apps/" + w.ID
		switch ws.Mode {
		case "", cluster.StorageNFS:
			if len(ws.Volumes) != 0 || ws.BlockFS != "" {
				return errors.New("an app in NFS mode has no volumes")
			}
			for _, e := range ws.Exports {
				if e.Kind != cluster.ExportAppData || e.Dataset != base {
					return fmt.Errorf("export %q isn't %s's data", e.Dataset, w.ID)
				}
			}
		case cluster.StorageBlock:
			if ws.BlockFS != "ext4" && ws.BlockFS != "xfs" {
				return fmt.Errorf("block file system %q must be ext4 or xfs", ws.BlockFS)
			}
			if len(ws.Exports) != 0 {
				return errors.New("an app in block mode has no exports")
			}
			if len(ws.Volumes) != 1 || ws.Volumes[0].Dataset != base+"/block" || ws.Volumes[0].Disk != "block" {
				return fmt.Errorf("an app in block mode has exactly one volume, %s/block", base)
			}
		default:
			return fmt.Errorf("data mode %q isn't nfs or block", ws.Mode)
		}
	default:
		return fmt.Errorf("workload kind %q isn't vm or app", w.Kind)
	}
	ids := make([]string, len(ws.Shares))
	copy(ids, ws.Shares)
	sort.Strings(ids)
	for i, id := range ids {
		if i > 0 && ids[i-1] == id {
			return fmt.Errorf("share %s is listed twice", id)
		}
	}
	return nil
}

func containsNode(l []cluster.NodeID, n cluster.NodeID) bool {
	for _, x := range l {
		if x == n {
			return true
		}
	}
	return false
}
