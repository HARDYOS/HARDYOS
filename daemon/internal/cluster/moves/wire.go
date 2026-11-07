// Package moves moves cluster workloads between compute nodes
// (docs/plans/cluster.md section 6.4): offline moves of VMs and apps, live
// migration of VMs on shared storage, and draining a node. The Mover runs
// as a job on the node the person used; each step on the source or
// destination is a call to that node's peer API (Node).
package moves

import (
	"encoding/json"
	"errors"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Peer API paths (under cluster.PeerPathPrefix).
const (
	PathHold          = "moves/hold"
	PathPrepare       = "moves/prepare"
	PathStop          = "moves/stop"
	PathAttach        = "moves/attach"
	PathStart         = "moves/start"
	PathDetach        = "moves/detach"
	PathAccept        = "moves/migrate/accept"
	PathSend          = "moves/migrate/send"
	PathEnd           = "moves/migrate/end"
	PathStream        = "moves/migrate/stream"
	PathPublishExport = "moves/publish/export"
	PathPublishImport = "moves/publish/import"
	PathRequirements  = "workloads/requirements"
	PathImages        = "workloads/images"
)

// ErrConfirm: the move needs the person's typed confirmation (passthrough
// devices, or starting a workload of a server that is down elsewhere).
var ErrConfirm = errors.New("this move needs a typed confirmation")

// ErrNotLive: the workload can't move live.
var ErrNotLive = errors.New("it can't move live")

// HoldRequest keeps a node's reconciler off a workload for Seconds (0
// releases).
type HoldRequest struct {
	Workload cluster.WorkloadRef `json:"workload"`
	Seconds  int                 `json:"seconds"`
}

// PrepareRequest asks the destination to get ready: check passthrough
// devices against its own, pull an app's images.
type PrepareRequest struct {
	Workload cluster.WorkloadRef `json:"workload"`
	Mode     cluster.MoveMode    `json:"mode"`
	Devices  json.RawMessage     `json:"devices,omitempty"` // the VM's devices.Device list
	Images   []string            `json:"images,omitempty"`
}

// StepRequest names a workload at a generation.
type StepRequest struct {
	Workload   cluster.WorkloadRef `json:"workload"`
	Generation uint64              `json:"generation"`
	// Start (start step): start it after attaching.
	Start bool `json:"start,omitempty"`
	// Force (detach step).
	Force bool `json:"force,omitempty"`
	// Migration (attach step): the node takes part in a live migration at
	// this generation.
	Migration bool `json:"migration,omitempty"`
}

// StepResult is a step's outcome.
type StepResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// AcceptRequest admits a live migration on the destination.
type AcceptRequest struct {
	VM         string         `json:"vm"`
	From       cluster.NodeID `json:"from"`
	Token      string         `json:"token"`
	Generation uint64         `json:"generation"`
}

// SendRequest runs a live migration on the source.
type SendRequest struct {
	VM         string         `json:"vm"`
	To         cluster.NodeID `json:"to"`
	Token      string         `json:"token"`
	Generation uint64         `json:"generation"`
	MigrateURI string         `json:"migrateUri"`
}

// EndRequest closes a migration's admission.
type EndRequest struct {
	VM    string `json:"vm"`
	Token string `json:"token"`
}

// PublishConfig is an app's NetBird publishing settings handed from the
// old owner to the new one.
type PublishConfig struct {
	App    string          `json:"app"`
	Config json.RawMessage `json:"config,omitempty"`
}
