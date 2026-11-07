// Package cluster joins HardyOS servers into one cluster: membership and
// consensus (embedded Raft), a witness on the VPS, the cluster desktop, a
// shared storage node, placement, moves and high availability with fencing.
// See docs/plans/cluster.md.
//
// This file is the contract the three build parts code against:
//
//   - part A (cluster core) implements Membership, PeerClient, PeerMux and
//     the FSM that calls registered Appliers;
//   - part B (storage) implements StorageService, StorageAttacher and the
//     storage node's agent;
//   - part C (placement, moves, HA, fencing) implements Scheduler, Mover, HA,
//     FenceAgent and Runtime.
//
// It holds types, constants and interfaces only; behaviour lives in the
// parts' own files and subpackages.
package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/ports"
)

// ---- errors -----------------------------------------------------------------

var (
	// ErrNotImplemented marks contract operations not built yet.
	ErrNotImplemented = errors.New("not implemented yet")
	// ErrNotMember: this server isn't in a cluster, or the node named isn't
	// a member.
	ErrNotMember = errors.New("not a member of the cluster")
	// ErrNoQuorum: the change needs the cluster's agreement and this node
	// can't reach a majority of the voters now.
	ErrNoQuorum = errors.New("the cluster has no quorum; changes have to wait")
	// ErrFenced: this node (or the node named) is fenced and may not run or
	// attach cluster workloads until it has rejoined.
	ErrFenced = errors.New("the server is fenced from cluster storage")
	// ErrNotOwner: the placement doesn't name this node for the workload.
	ErrNotOwner = errors.New("the workload is placed on another server")
	// ErrStaleGeneration: a placement or grant changed since the caller read
	// it.
	ErrStaleGeneration = errors.New("the workload's placement changed; try again")
	// ErrStorageUnavailable: the storage node can't be reached, or the
	// workload's storage isn't granted to this node.
	ErrStorageUnavailable = errors.New("cluster storage isn't available")
	// ErrNoFit: no compute node can take the workload (Scheduler).
	ErrNoFit = errors.New("no server in the cluster can run it")
)

// ---- wire constants ---------------------------------------------------------

const (
	// Port is the cluster listener on every member and on the witness
	// TLS 1.3, mutual, pinned keys, ALPN-multiplexed.
	Port = ports.Cluster

	// ALPN protocol names on Port.
	ALPNRaft    = "hardyos-raft/1"    // Raft stream layer
	ALPNPeer    = "hardyos-peer/1"    // HTTP/2: heartbeats, proposals, API proxy, storage control, join
	ALPNMigrate = "hardyos-migrate/1" // the relayed libvirt connection of one live migration
	// ALPNRelay is HTTP/1.1 for proxied desktop requests that need a
	// connection of their own: WebSocket upgrades (events, VM console,
	// terminal), app windows and plain API requests from the entry node
	// (decision 331).
	ALPNRelay = "hardyos-relay/1"

	// PeerPathPrefix prefixes the peer API on ALPNPeer.
	PeerPathPrefix = "/cluster/v1/"

	// AssertionHeader carries the entry node's signed statement of who the
	// person is on a proxied API request (Assertion, compact ES256 JWS).
	AssertionHeader = "X-Hardyos-Cluster-Assertion"

	// SecretsPurpose is the secretbox purpose for the cluster identity, join
	// codes and CHAP secrets.
	SecretsPurpose = "cluster"

	// ProtocolVersion is the peer protocol; members accept ±1 while
	// upgrading.
	ProtocolVersion = 1

	// IQNPrefix starts every target and initiator name:
	// IQNPrefix + "." + <cluster id, 8 chars> + "." + <node> [+ ".init"].
	IQNPrefix = "iqn.2026-11.net.hardynetworks:hardyos"

	// RemoteMountRoot is where compute nodes mount the storage node's
	// datasets: RemoteMountRoot/<pool>/{vms,apps,shares}/<id>.
	RemoteMountRoot = "/mnt/hc"

	// StateDir holds Raft's log, stable store and snapshots on each member
	// (on the shared rpool/hardyos dataset).
	StateDir = "/var/lib/hardyos/cluster"
)

// ---- identities and roles ---------------------------------------------------

// ClusterID is 128 random bits, base32 lowercase without padding.
type ClusterID string

// NodeID names a member: lowercase letters, digits and '-', 1-32
// characters, starting with a letter; unique in the cluster. It is the Raft
// server ID and address (the stream layer resolves it to a path).
type NodeID string

// Role is what a member does. Fixed at join.
type Role string

const (
	RoleCompute Role = "compute" // runs cluster VMs and apps
	RoleStorage Role = "storage" // holds the pool, serves iSCSI/NFS, arbitrates disk access (one in Phase 8)
	RoleWitness Role = "witness" // votes when useful, holds the log, runs nothing
)

// NodeState is a member's committed state.
type NodeState string

const (
	NodeJoining     NodeState = "joining"     // added, catching up as a non-voter
	NodeActive      NodeState = "active"      // normal
	NodeMaintenance NodeState = "maintenance" // drained, non-voter, may reboot freely
	NodeDead        NodeState = "dead"        // declared dead by the leader; fence pending
	NodeFenced      NodeState = "fenced"      // the storage node confirmed the fence
	NodeRejoining   NodeState = "rejoining"   // back after a fence, nothing placed on it yet
	NodeRemoved     NodeState = "removed"     // gone; its pin is refused
)

// Suffrage mirrors Raft's: a voter, or a non-voter that receives the log.
type Suffrage string

const (
	Voter    Suffrage = "voter"
	NonVoter Suffrage = "nonvoter"
)

// Addresses are a member's paths.
type Addresses struct {
	// LAN is the first path for control traffic.
	LAN netip.Addr `json:"lan"`
	// NetBird is the failover path for control traffic (the witness's only
	// one). Invalid when the node isn't on NetBird.
	NetBird netip.Addr `json:"netbird"`
	// Storage is the node's address on the storage network (compute and
	// storage roles). iSCSI, NFS and live migration only.
	Storage netip.Addr `json:"storage"`
	// Portals are the storage node's iSCSI portals (two for multipath).
	Portals []netip.AddrPort `json:"portals,omitempty"`
}

// Node is a member as recorded in the replicated state.
type Node struct {
	ID   NodeID `json:"id"`
	Name string `json:"name"` // the server's hostname, for display
	Role Role   `json:"role"`
	// Pin is the SHA-256 (hex) of the node's cluster public key
	// (SubjectPublicKeyInfo), as replication pins keys.
	Pin string `json:"pin"`
	// PublicKey is the node's cluster public key (SubjectPublicKeyInfo,
	// DER); Pin is its SHA-256. The FSM verifies signed commands with it
	// (decision 330).
	PublicKey []byte    `json:"publicKey"`
	Addresses Addresses `json:"addresses"`
	State     NodeState `json:"state"`
	Suffrage  Suffrage  `json:"suffrage"`
	// Version is the HardyOS version the node last announced; Features the
	// feature names it supports (see Snapshot.FeatureLevel).
	Version  string   `json:"version"`
	Features []string `json:"features,omitempty"`
	// BootID changes on every boot (/proc/sys/kernel/random/boot_id); a
	// rejoin after a fence must carry a new one.
	BootID string `json:"bootId,omitempty"`
	// FenceEpoch is the epoch of the node's latest fence (0: never fenced).
	FenceEpoch uint64 `json:"fenceEpoch,omitempty"`
	// Compute describes a compute node's capacity and hardware (nil for
	// other roles).
	Compute *ComputeInfo `json:"compute,omitempty"`
	Joined  time.Time    `json:"joined"`
}

// ComputeInfo is what placement needs to know about a compute node.
type ComputeInfo struct {
	CPUs     int    `json:"cpus"`
	MemoryMB int    `json:"memoryMB"`
	CPUModel string `json:"cpuModel"` // libvirt host-model name
	// Bridges lists the VM bridges and the VLANs each carries.
	Bridges map[string][]int `json:"bridges,omitempty"`
	// Watchdog: "hardware", "softdog" or "" (none).
	Watchdog string `json:"watchdog"`
	KVM      bool   `json:"kvm"`
}

// Path is the network a peer connection is using.
type Path string

const (
	PathLAN Path = "lan"
	// PathStorage is the storage network used as the middle control path
	// (heartbeats, Raft, peer API; never bulk traffic over NetBird) when
	// the LAN fails: LAN, then storage network, then NetBird (decision 332).
	PathStorage Path = "storage"
	PathNetBird Path = "netbird"
	PathNone    Path = "none"
)

// Health is the leader's (or a peer's) live view of a node. Not committed.
type Health struct {
	Node      NodeID        `json:"node"`
	LastHeard time.Time     `json:"lastHeard"`
	Path      Path          `json:"path"`
	RTT       time.Duration `json:"rtt"`
	Suspect   bool          `json:"suspect"`
	// Quorate is the node's own report that its quorum lease is valid.
	Quorate bool `json:"quorate"`
	// StorageOK: its iSCSI sessions and NFS mounts answer.
	StorageOK bool `json:"storageOK"`
	// LANOK: its bridge/LAN port has carrier and the gateway answers.
	LANOK bool `json:"lanOK"`
	// Running lists the workloads it runs now, with the generation each
	// was started under.
	Running []RunningWorkload `json:"running,omitempty"`
}

// RunningWorkload is one entry of Health.Running.
type RunningWorkload struct {
	Workload   WorkloadRef `json:"workload"`
	Generation uint64      `json:"generation"`
}

// ---- timings ----------------------------------------------------------------

// Timings drive liveness, self-fencing and failover. Invariant (checked
// when they change, part C): Dead >= QuorumLease + Watchdog + 10s and
// SelfStop < Watchdog.
type Timings struct {
	Heartbeat       time.Duration `json:"heartbeat"`       // node -> leader
	Suspect         time.Duration `json:"suspect"`         // leader shows a node as suspect
	QuorumLease     time.Duration `json:"quorumLease"`     // Q: a node without a confirmed heartbeat starts self-fencing
	SelfStop        time.Duration `json:"selfStop"`        // S: time to stop HA workloads before letting the watchdog fire
	Watchdog        time.Duration `json:"watchdog"`        // W: hardware watchdog timeout
	Dead            time.Duration `json:"dead"`            // F: leader declares a node dead
	StorageIsolated time.Duration `json:"storageIsolated"` // node reports storage down while others don't
	LANIsolated     time.Duration `json:"lanIsolated"`     // node reports LAN down while others don't
	FenceAck        time.Duration `json:"fenceAck"`        // wait for the storage node's fence confirmation before retrying
}

// DefaultTimings are the defaults of docs/plans/cluster.md section 7.1.
var DefaultTimings = Timings{
	Heartbeat:       1 * time.Second,
	Suspect:         10 * time.Second,
	QuorumLease:     15 * time.Second,
	SelfStop:        5 * time.Second,
	Watchdog:        10 * time.Second,
	Dead:            40 * time.Second,
	StorageIsolated: 15 * time.Second,
	LANIsolated:     60 * time.Second,
	FenceAck:        30 * time.Second,
}

// ---- workloads --------------------------------------------------------------

// WorkloadKind is a VM or an app.
type WorkloadKind string

const (
	KindVM  WorkloadKind = "vm"
	KindApp WorkloadKind = "app"
)

// WorkloadRef names a cluster workload. IDs are unique cluster-wide (they
// are allocated in the replicated state).
type WorkloadRef struct {
	Kind WorkloadKind `json:"kind"`
	ID   string       `json:"id"`
}

// Requested is what the person asked for.
type Requested string

const (
	RequestRunning Requested = "running"
	RequestStopped Requested = "stopped"
)

// PlacementState is a workload's cluster-level state.
type PlacementState string

const (
	PlacementStopped    PlacementState = "stopped"
	PlacementStarting   PlacementState = "starting"
	PlacementRunning    PlacementState = "running"
	PlacementStopping   PlacementState = "stopping"
	PlacementMigrating  PlacementState = "migrating"  // live migration Owner -> Target
	PlacementMoving     PlacementState = "moving"     // offline move Owner -> Target
	PlacementRecovering PlacementState = "recovering" // owner dead; waiting for the fence
	PlacementPending    PlacementState = "pending"    // no node fits; retried
	PlacementError      PlacementState = "error"      // too many restarts or relocations
)

// HAPolicy is a workload's high-availability setting.
type HAPolicy struct {
	Enabled bool `json:"enabled"`
	// Priority orders recovery: higher first (0-100, default 50).
	Priority int `json:"priority"`
	// MaxRestarts in place per hour before relocating (default 3).
	MaxRestarts int `json:"maxRestarts"`
	// MaxRelocations per hour before giving up (state error; default 2).
	MaxRelocations int `json:"maxRelocations"`
	// Preferred nodes, in order; Restricted limits placement to them.
	Preferred  []NodeID `json:"preferred,omitempty"`
	Restricted bool     `json:"restricted,omitempty"`
	// AntiAffinity: workloads sharing a group are kept on different nodes
	// when possible.
	AntiAffinity string `json:"antiAffinity,omitempty"`
	// FailBack moves the workload back to its first preferred node (live,
	// when possible) once that node is active again.
	FailBack bool `json:"failBack,omitempty"`
}

// Placement is a cluster workload's committed record.
type Placement struct {
	Workload WorkloadRef `json:"workload"`
	Name     string      `json:"name"` // display name
	// Owner runs it (or would). Empty: not placed yet.
	Owner NodeID `json:"owner,omitempty"`
	// Target is the other node of a move or live migration in progress.
	Target NodeID `json:"target,omitempty"`
	// Generation increases with every change of owner or grant. A node
	// runs the workload only with an attachment of this generation.
	Generation uint64         `json:"generation"`
	Requested  Requested      `json:"requested"`
	State      PlacementState `json:"state"`
	HA         HAPolicy       `json:"ha"`
	// Pinned: never moved automatically (passthrough devices, or the
	// person's choice).
	Pinned bool `json:"pinned,omitempty"`
	// Storage is what the workload has on the storage node.
	Storage WorkloadStorage `json:"storage"`
	// Problem says why it is pending or in error.
	Problem string    `json:"problem,omitempty"`
	Changed time.Time `json:"changed"`
}

// Requirements is what a workload needs from a compute node (Scheduler).
type Requirements struct {
	MemoryMB int `json:"memoryMB"`
	CPUs     int `json:"cpus"`
	// CPUModel: "" (cluster baseline) or a host model the node must match
	// (host-passthrough VMs).
	CPUModel string `json:"cpuModel,omitempty"`
	// Bridges: bridge name -> VLANs the workload's NICs use.
	Bridges map[string][]int `json:"bridges,omitempty"`
	// Devices: the workload needs these node-local devices (pins it).
	Devices []string `json:"devices,omitempty"`
	// Images an app needs pulled (for moves and recovery planning).
	Images []string `json:"images,omitempty"`
	KVM    bool     `json:"kvm,omitempty"`
}

// ---- storage ----------------------------------------------------------------

// Volume is a zvol on the storage node exposed as an iSCSI LUN.
type Volume struct {
	// Dataset: <pool>/vms/<vm>/<disk>.
	Dataset string `json:"dataset"`
	// Disk is the VM's disk name (disk0, …).
	Disk   string `json:"disk"`
	SizeGB int    `json:"sizeGB"`
	// WWN is the LUN's NAA identifier (hex, from the zvol's GUID); compute
	// nodes find the device as /dev/disk/by-id/wwn-0x<WWN>.
	WWN string `json:"wwn"`
}

// ExportKind is what an NFS export holds.
type ExportKind string

const (
	ExportVMState ExportKind = "vmstate" // <pool>/vms/<id>: vm.json, nvram, TPM, seed; owner only
	ExportAppData ExportKind = "appdata" // <pool>/apps/<id>; owner only
	ExportShare   ExportKind = "share"   // a shared folder; every active compute node
)

// Export is a dataset on the storage node mounted over NFS by compute nodes.
type Export struct {
	Kind    ExportKind `json:"kind"`
	Dataset string     `json:"dataset"`
	// Path is the export path on the storage node (the dataset's
	// mountpoint) and MountPath where compute nodes mount it
	// (RemoteMountRoot/<pool>/…).
	Path      string `json:"path"`
	MountPath string `json:"mountPath"`
	// FSID is the export's fixed fsid (the dataset's GUID).
	FSID string `json:"fsid"`
}

// StorageMode is how an app's data reaches its node (decision 341).
type StorageMode string

const (
	// StorageNFS: the app's dataset <pool>/apps/<id>, mounted over NFS.
	StorageNFS StorageMode = "nfs"
	// StorageBlock: a zvol <pool>/apps/<id>/block with ext4 or xfs, a LUN
	// in the owner's target (exclusive like a VM disk), mounted by the
	// owner at the same folder.
	StorageBlock StorageMode = "block"
)

// ClusterShare is a shared folder exported to every active compute node
// (root_squash). Compute nodes mount it at MountPath.
type ClusterShare struct {
	ID        string `json:"id"`
	Pool      string `json:"pool"`
	Dataset   string `json:"dataset"`   // <pool>/shares/<id>
	Path      string `json:"path"`      // its mountpoint on the storage node
	MountPath string `json:"mountPath"` // RemoteMountRoot/<pool>/shares/<id>
	FSID      string `json:"fsid"`      // the dataset's GUID
}

// WorkloadStorage is everything a workload has on the storage node.
type WorkloadStorage struct {
	Pool string `json:"pool"`
	// Mode is an app's data mode ("" means StorageNFS; VMs leave it empty).
	Mode StorageMode `json:"mode,omitempty"`
	// BlockFS is the file system on an app's block volume: ext4 or xfs.
	BlockFS string   `json:"blockFS,omitempty"`
	Volumes []Volume `json:"volumes,omitempty"`
	Exports []Export `json:"exports,omitempty"`
	// Shares are shared folder ids an app uses (exported to every compute
	// node, not granted per workload).
	Shares []string `json:"shares,omitempty"`
}

// GrantMode says how many nodes may hold a workload's storage.
type GrantMode string

const (
	GrantExclusive GrantMode = "exclusive" // Nodes has one entry
	GrantMigration GrantMode = "migration" // Nodes has two: source and destination of a live migration
)

// Grant is the committed decision of which node(s) may access a workload's
// volumes and owner-only exports. Only the storage node acts on it.
type Grant struct {
	Workload   WorkloadRef `json:"workload"`
	Nodes      []NodeID    `json:"nodes"`
	Mode       GrantMode   `json:"mode"`
	Generation uint64      `json:"generation"`
	// Applied is set by the storage node's acknowledgement (storage.applied)
	// once LIO and the exports match this grant.
	Applied bool `json:"applied"`
}

// Fence is a node's fence record.
type Fence struct {
	Node   NodeID `json:"node"`
	Epoch  uint64 `json:"epoch"`
	Reason string `json:"reason"` // "dead", "isolated", "removed"
	// Confirmed by the storage node (storage.fenced): the node's target is
	// disabled, its exports removed, its NFS clients expired.
	Confirmed   bool      `json:"confirmed"`
	Requested   time.Time `json:"requested"`
	ConfirmedAt time.Time `json:"confirmedAt,omitempty"`
}

// WatchdogOverride is an administrator's typed confirmation that a node
// without a hardware watchdog may host HA workloads (softdog doesn't
// survive a kernel hang). Part C amendment.
type WatchdogOverride struct {
	Node NodeID `json:"node"`
	// Kind is the watchdog the node had when it was allowed ("softdog" or
	// ""); the override lapses when the node reports another kind.
	Kind  string    `json:"kind"`
	Actor Actor     `json:"actor"`
	At    time.Time `json:"at"`
}

// StorageHealth is the storage node's report.
type StorageHealth struct {
	Node      NodeID `json:"node"`
	Reachable bool   `json:"reachable"`
	Pool      string `json:"pool"`
	PoolState string `json:"poolState"` // ONLINE, DEGRADED, …
	// Sessions: compute node -> logged-in iSCSI sessions.
	Sessions map[NodeID]int `json:"sessions,omitempty"`
	// Fenced nodes the storage node is currently refusing.
	Fenced  []NodeID `json:"fenced,omitempty"`
	Problem string   `json:"problem,omitempty"`
}

// Attachment is what a compute node has attached for a workload.
type Attachment struct {
	Workload   WorkloadRef `json:"workload"`
	Generation uint64      `json:"generation"`
	// Disks: VM disk name -> block device (/dev/disk/by-id/wwn-0x… or
	// /dev/mapper/<wwid>).
	Disks map[string]string `json:"disks,omitempty"`
	// StateDir: a VM's state folder or an app's data folder (an NFS mount
	// under RemoteMountRoot).
	StateDir  string `json:"stateDir"`
	Multipath bool   `json:"multipath,omitempty"`
}

// ---- replicated state -------------------------------------------------------

// Snapshot is the whole replicated state (the FSM's data). Appliers mutate
// it; readers get copies. Small: tens of nodes, hundreds of workloads.
type Snapshot struct {
	Cluster ClusterID `json:"cluster"`
	Name    string    `json:"name"`
	// FeatureLevel gates new command types and fields (raised only by
	// "Finish upgrade" once every member supports it).
	FeatureLevel int `json:"featureLevel"`
	// StorageSubnet is the storage network's prefix.
	StorageSubnet netip.Prefix `json:"storageSubnet"`
	// CPUBaseline is the libvirt CPU model cluster VMs use by default.
	CPUBaseline string  `json:"cpuBaseline,omitempty"`
	Timings     Timings `json:"timings"`

	Nodes      map[NodeID]*Node           `json:"nodes"`
	Placements map[WorkloadRef]*Placement `json:"-"` // JSON as a list (part A's codec)
	Grants     map[WorkloadRef]*Grant     `json:"-"` // JSON as a list
	Fences     map[NodeID]*Fence          `json:"fences"`
	// Seq is the last applied sequence number per proposer (replay guard).
	Seq map[NodeID]uint64 `json:"seq"`
	// AppUIDs: app id -> its user id (30000-30999), unique cluster-wide.
	AppUIDs map[string]int `json:"appUids,omitempty"`
	// ClusterShares are the shared folders on the storage node with "Use in
	// the cluster" on, by share id (storage.share; part B).
	ClusterShares map[string]*ClusterShare `json:"clusterShares,omitempty"`
	// HAOverrides: nodes an administrator allowed to host HA workloads
	// without a hardware watchdog (CmdHAWatchdog; part C amendment).
	HAOverrides map[NodeID]*WatchdogOverride `json:"haOverrides,omitempty"`
	// Index is the Raft index this snapshot reflects.
	Index uint64 `json:"index"`
}

// State reads the replicated state as this node has applied it.
type State interface {
	// Snapshot returns a deep copy.
	Snapshot() *Snapshot
	Node(id NodeID) (*Node, bool)
	Placement(w WorkloadRef) (*Placement, bool)
	Grant(w WorkloadRef) (*Grant, bool)
	// Index is the last applied Raft index.
	Index() uint64
}

// ---- commands ---------------------------------------------------------------

// CommandType names a log entry. Each is owned by one part (its applier).
type CommandType string

const (
	// Part A: membership.
	CmdClusterCreate CommandType = "cluster.create"
	CmdMemberAdd     CommandType = "member.add"
	CmdMemberReady   CommandType = "member.ready"
	CmdMemberUpdate  CommandType = "member.update" // addresses, version, features, compute info
	CmdMemberRemove  CommandType = "member.remove"
	CmdMaintenance   CommandType = "node.maintenance" // enter/leave
	CmdFeatureLevel  CommandType = "cluster.featurelevel"
	CmdTimings       CommandType = "cluster.timings"
	CmdWitnessHello  CommandType = "witness.hello" // the only type the witness signs

	// Part B: storage.
	CmdStorageApplied CommandType = "storage.applied" // storage node: LIO/exports match grants up to a generation
	CmdStorageFenced  CommandType = "storage.fenced"  // storage node: a fence is in place
	CmdStorageUnfence CommandType = "storage.unfenced"
	CmdShareCluster   CommandType = "storage.share" // a shared folder in or out of the cluster
	CmdAppUID         CommandType = "storage.appuid"
	// CmdStorageLayout changes a stopped workload's storage (an app's NFS
	// or block mode) after the storage node moved its data (part B,
	// decision 342).
	CmdStorageLayout CommandType = "storage.layout"

	// Part C: placement, HA, fencing.
	CmdWorkloadAdd    CommandType = "workload.add"
	CmdWorkloadRemove CommandType = "workload.remove"
	CmdPlacementSet   CommandType = "placement.set" // owner, generation, grant
	CmdRequested      CommandType = "placement.requested"
	CmdWorkloadState  CommandType = "placement.state" // owner's report: running, stopped, error
	CmdMoveBegin      CommandType = "move.begin"
	CmdMoveEnd        CommandType = "move.end"
	CmdHAPolicy       CommandType = "ha.policy"
	CmdNodeDead       CommandType = "node.dead"
	CmdNodeIsolated   CommandType = "node.isolated"
	CmdNodeRejoin     CommandType = "node.rejoin"
	CmdCPUBaseline    CommandType = "cluster.cpubaseline"
	// CmdHAWatchdog records an administrator's per-node override that lets
	// HA workloads run on a node without a hardware watchdog (softdog or
	// none; decision 352). Part C amendment.
	CmdHAWatchdog CommandType = "ha.watchdog"
)

// Actor is who caused a command: a person through a node, or HardyOS
// itself (Kind "system", e.g. the HA coordinator).
type Actor struct {
	Kind string `json:"kind"` // "local", "domain" or "system"
	Name string `json:"name"`
	SID  string `json:"sid,omitempty"`
	Via  NodeID `json:"via"`
}

// Command is a log entry before signing. Body is the type's own JSON.
type Command struct {
	Type     CommandType     `json:"type"`
	Cluster  ClusterID       `json:"cluster"`
	Proposer NodeID          `json:"proposer"`
	Seq      uint64          `json:"seq"`
	Actor    Actor           `json:"actor"`
	Time     time.Time       `json:"time"`
	Body     json.RawMessage `json:"body"`
	// Level is the feature level the type needs (LevelOf; omitted for
	// level 1). A node that doesn't know the type refuses it when the level
	// isn't enabled or is one it supports, and stops only when the cluster
	// enabled a level above its own (decision 366).
	Level int `json:"level,omitempty"`
}

// SignedCommand is what the log holds: the canonical JSON of a Command and
// the proposer's ES256 signature over it.
type SignedCommand struct {
	Command   json.RawMessage `json:"command"`
	Signature []byte          `json:"signature"`
}

// Applier applies one or more command types to the state. Apply must be
// deterministic and pure (no clock, no I/O, no randomness): every node and
// the witness run it on the same entries. Returning an error makes the
// entry a no-op everywhere (the error is logged and shown to the proposer).
// The FSM (part A) has already checked the signature, the proposer's
// sequence and the cluster id; Signers says which roles may sign each type.
type Applier interface {
	Types() []CommandType
	Signers(t CommandType) []Role
	Apply(s *Snapshot, c Command) error
}

// ---- part A: membership, peers, the desktop ---------------------------------

// Event is a change of the applied state or of liveness, for subscribers.
type Event struct {
	Index    uint64       `json:"index"`
	Type     CommandType  `json:"type,omitempty"` // the applied command, if any
	Node     NodeID       `json:"node,omitempty"`
	Workload *WorkloadRef `json:"workload,omitempty"`
	// Leader / Quorate report liveness changes (Type empty).
	Leader  NodeID `json:"leader,omitempty"`
	Quorate bool   `json:"quorate"`
}

// Membership is this node's view of the cluster (part A).
type Membership interface {
	// Self is this node's record; ErrNotMember outside a cluster.
	Self() (Node, error)
	State() State
	// Leader is the current leader, if known.
	Leader() (NodeID, bool)
	// Quorate reports whether this node's quorum lease is valid now, and
	// until when (monotonic time).
	Quorate() (bool, time.Time)
	// Health is the leader's live view of every node (fetched from the
	// leader when this node isn't it).
	Health(ctx context.Context) ([]Health, error)
	// Propose signs a command with this node's key and sequence, forwards it
	// to the leader and returns its index once committed. body is encoded
	// as the command's Body. ErrNoQuorum when it can't be committed.
	Propose(ctx context.Context, t CommandType, body any, actor Actor) (index uint64, err error)
	// WaitApplied returns once this node has applied index.
	WaitApplied(ctx context.Context, index uint64) error
	// Subscribe streams events until ctx ends.
	Subscribe(ctx context.Context) <-chan Event
	// Register adds an applier (at start, before the FSM replays the log).
	Register(a Applier)
}

// PeerClient calls another member's peer API (PeerPathPrefix + path) over
// the current path (LAN, else NetBird), with mutual TLS and pins (part A).
type PeerClient interface {
	// Call sends in as JSON and decodes the answer into out (either may be
	// nil). A peer's error answer comes back as *PeerError.
	Call(ctx context.Context, node NodeID, method, path string, in, out any) error
	// Do sends a raw request (streams, WebSocket upgrades); the URL's host
	// is ignored and replaced by the node.
	Do(ctx context.Context, node NodeID, r *http.Request) (*http.Response, error)
}

// PeerError is a peer's error answer.
type PeerError struct {
	Node    NodeID `json:"node"`
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func (e *PeerError) Error() string { return string(e.Node) + ": " + e.Message }

// PeerMux registers handlers on this node's peer API (part A serves it).
// Handlers only see requests from current members (fenced members only for
// paths registered with AllowFenced).
type PeerMux interface {
	Handle(pattern string, h http.Handler)
	AllowFenced(pattern string, h http.Handler)
	// Caller is the member that sent r (from its TLS pin).
	Caller(r *http.Request) (Node, bool)
}

// Principal is the person on a proxied request.
type Principal struct {
	Kind  string `json:"kind"` // "local" or "domain"
	Name  string `json:"name"`
	SID   string `json:"sid,omitempty"`
	Admin bool   `json:"admin"`
}

// Assertion is the claims of AssertionHeader (compact ES256 JWS signed with
// the entry node's cluster key).
type Assertion struct {
	Issuer    NodeID    `json:"iss"`
	Audience  NodeID    `json:"aud"`
	Subject   Principal `json:"sub"`
	Session   string    `json:"sid"` // SHA-256 (hex) of the entry node's session id
	IssuedAt  int64     `json:"iat"`
	ExpiresAt int64     `json:"exp"` // at most IssuedAt + 60
	Nonce     string    `json:"jti"`
	// Request is the SHA-256 (hex) of method, path, query and body.
	Request string `json:"req"`
	// Host is the Host the browser sent to the entry node (the desktop's
	// or an app window's address), so the target builds links and checks
	// origins as the browser sees them (decision 373).
	Host string `json:"host,omitempty"`
}

// JoinOffer is an open join code (shown once to the admin).
type JoinOffer struct {
	Code      string           `json:"code"` // formatted like replication's codes
	Role      Role             `json:"role"`
	Addresses []netip.AddrPort `json:"addresses"` // this member's LAN and NetBird endpoints
	Expires   time.Time        `json:"expires"`
}

// ---- part B: storage --------------------------------------------------------

// VMStorageRequest asks for a cluster VM's storage.
type VMStorageRequest struct {
	VM    string        `json:"vm"`
	Pool  string        `json:"pool"`
	Disks []DiskRequest `json:"disks"`
}

// DiskRequest is one disk of a VMStorageRequest.
type DiskRequest struct {
	Name   string `json:"name"` // disk0, disk1, …
	SizeGB int    `json:"sizeGB"`
}

// AppStorageRequest asks for a cluster app's data dataset.
type AppStorageRequest struct {
	App  string `json:"app"`
	Pool string `json:"pool"`
	// UID is the app's cluster-wide user id (CmdAppUID).
	UID int `json:"uid"`
	// Mode is the app's data mode ("" = StorageNFS); block mode also
	// needs BlockFS (ext4 or xfs) and BlockSizeGB (part B, decision 341).
	Mode        StorageMode `json:"mode,omitempty"`
	BlockFS     string      `json:"blockFS,omitempty"`
	BlockSizeGB int         `json:"blockSizeGB,omitempty"`
}

// SnapshotInfo is one snapshot of a workload's datasets on the storage node.
type SnapshotInfo struct {
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Used    int64     `json:"used"`
	Reason  string    `json:"reason,omitempty"`
}

// StorageService manages workloads' storage on the storage node (part B).
// Callable on any member; it executes on the storage node (over the peer
// API) as jobs there. Destructive calls need confirm = the workload's id.
type StorageService interface {
	ProvisionVM(ctx context.Context, r VMStorageRequest, actor Actor) (*WorkloadStorage, error)
	ProvisionApp(ctx context.Context, r AppStorageRequest, actor Actor) (*WorkloadStorage, error)
	ResizeDisk(ctx context.Context, w WorkloadRef, disk string, sizeGB int, actor Actor) error
	Destroy(ctx context.Context, w WorkloadRef, confirm string, actor Actor) error
	Snapshots(ctx context.Context, w WorkloadRef) ([]SnapshotInfo, error)
	// Snapshot takes one; for a running VM the storage node asks the owner
	// to freeze the guest first (Freezer).
	Snapshot(ctx context.Context, w WorkloadRef, name string, actor Actor) (*SnapshotInfo, error)
	// Rollback needs the workload stopped; confirm = the snapshot's name.
	Rollback(ctx context.Context, w WorkloadRef, snapshot, confirm string, actor Actor) error
	DeleteSnapshot(ctx context.Context, w WorkloadRef, snapshot, confirm string, actor Actor) error
	Health(ctx context.Context) (*StorageHealth, error)
}

// StorageAttacher attaches granted storage on a compute node (part B).
type StorageAttacher interface {
	// Attach logs in / rescans iSCSI, waits for the volumes' devices and
	// mounts the exports, after checking that the applied grant names this
	// node with g's generation. Idempotent.
	Attach(ctx context.Context, w WorkloadStorage, g Grant) (*Attachment, error)
	// Detach unmounts and removes the devices of a workload (force: lazy
	// unmount and session drop, for self-fencing).
	Detach(ctx context.Context, w WorkloadRef, force bool) error
	Attached(ctx context.Context) ([]Attachment, error)
	// Healthy reports whether the storage paths answer now (Health.StorageOK).
	Healthy(ctx context.Context) (bool, string)
}

// StorageFencer is the storage node's side of a fence (part B; driven by
// the applied state, exposed for tests and for "Remove node").
type StorageFencer interface {
	FenceNode(ctx context.Context, node NodeID, epoch uint64) error
	UnfenceNode(ctx context.Context, node NodeID, epoch uint64) error
}

// Freezer freezes a running VM's guest file systems around fn (the guest
// agent), on whichever node owns it. consistent is false when there was no
// agent.
type Freezer interface {
	Frozen(ctx context.Context, vm string, fn func(ctx context.Context) error) (consistent bool, err error)
}

// ---- part C: placement, moves, HA, fencing ----------------------------------

// Scheduler chooses a node for a workload (part C). Pure over the snapshot
// and the live health; skipped nodes come back with reasons.
type Scheduler interface {
	Place(s *Snapshot, health []Health, w WorkloadRef, req Requirements, exclude []NodeID) (NodeID, map[NodeID]string, error)
}

// MoveMode is how a workload moves.
type MoveMode string

const (
	MoveOffline MoveMode = "offline"
	MoveLive    MoveMode = "live" // VMs only
)

// MoveRequest asks for a move. To empty: the scheduler picks.
type MoveRequest struct {
	Workload WorkloadRef `json:"workload"`
	To       NodeID      `json:"to,omitempty"`
	Mode     MoveMode    `json:"mode"`
	// Generation the caller saw (ErrStaleGeneration if it changed).
	Generation uint64 `json:"generation"`
}

// MoveResult reports a finished move.
type MoveResult struct {
	Workload   WorkloadRef   `json:"workload"`
	From       NodeID        `json:"from"`
	To         NodeID        `json:"to"`
	Mode       MoveMode      `json:"mode"`
	Downtime   time.Duration `json:"downtime"`
	Generation uint64        `json:"generation"`
}

// Mover moves workloads and drains nodes (part C). Both run as jobs on the
// node that was asked.
type Mover interface {
	Move(ctx context.Context, r MoveRequest, actor Actor) (*MoveResult, error)
	Drain(ctx context.Context, node NodeID, stopOthers bool, actor Actor) ([]MoveResult, error)
}

// HA manages HA policies and shows recovery (part C). The coordinator runs
// on the leader when it is a HardyOS node.
type HA interface {
	SetPolicy(ctx context.Context, w WorkloadRef, p HAPolicy, actor Actor) error
	// Status lists every placement with its live state.
	Status(ctx context.Context) ([]Placement, error)
}

// StopMode is how a runtime stops a workload.
type StopMode string

const (
	StopGraceful StopMode = "graceful" // guest agent / ACPI / compose stop
	StopForce    StopMode = "force"    // virsh destroy / docker kill (self-fencing)
)

// WorkloadStatus is a runtime's report of one workload on this node.
type WorkloadStatus struct {
	Workload   WorkloadRef `json:"workload"`
	Running    bool        `json:"running"`
	Paused     bool        `json:"paused,omitempty"` // a VM paused on an I/O error
	Generation uint64      `json:"generation"`
	Problem    string      `json:"problem,omitempty"`
}

// Runtime runs cluster workloads of one kind on this node through
// hardyd-priv (part C; one for VMs, one for apps).
type Runtime interface {
	Kind() WorkloadKind
	Requirements(ctx context.Context, w WorkloadRef) (*Requirements, error)
	// Start defines (VMs) and starts the workload from its attachment.
	Start(ctx context.Context, w WorkloadRef, a *Attachment) error
	Stop(ctx context.Context, w WorkloadRef, mode StopMode) error
	Status(ctx context.Context) ([]WorkloadStatus, error)
}

// LiveMigrator migrates a running VM to another node (part C; VM runtime).
type LiveMigrator interface {
	Migrate(ctx context.Context, vm string, to NodeID, generation uint64) error
}

// Watchdog is hardyd-priv's watchdog (cluster.watchdog.* ops; part C).
// Root pets the device itself while now < until (monotonic on root's side;
// until is sent as a duration from now).
type Watchdog interface {
	Arm(ctx context.Context, timeout time.Duration) (kind string, err error)
	Pet(ctx context.Context, validFor time.Duration) error
	Disarm(ctx context.Context) error
	// Expire stops petting at once (self-fence ordered by the cluster).
	Expire(ctx context.Context) error
}

// FenceState is the node fence agent's state.
type FenceState string

const (
	FenceDisarmed    FenceState = "disarmed"
	FenceArmed       FenceState = "armed"
	FenceSelfFencing FenceState = "selffencing"
)

// FenceAgent is the node-local self-fencing state machine (part C).
type FenceAgent interface {
	State() FenceState
	// Run drives the agent until ctx ends: arms when HA workloads are
	// placed here, pets while the quorum lease is valid, self-fences when
	// it isn't or when the state says node.isolated.
	Run(ctx context.Context) error
}

// PowerFencer powers a node off out of band (IPMI/Redfish; later). Used in
// addition to the storage fence, never instead of it.
type PowerFencer interface {
	PowerOff(ctx context.Context, node NodeID) error
	PowerState(ctx context.Context, node NodeID) (on bool, err error)
}
