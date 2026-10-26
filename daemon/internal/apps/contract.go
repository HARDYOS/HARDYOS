package apps

// Types shared between the apps engine, hardyd and the shared-folders code.
// See docs/plans/app-store-v2.md. The names and JSON shapes here are the
// contract; the behaviour lives in manager.go, policy.go, access.go,
// resources.go and lifecycle.go.

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented marks contract operations not built yet.
var ErrNotImplemented = errors.New("not implemented yet")

// Source is where an app's package came from.
type Source string

const (
	SourceCatalog  Source = "catalog"  // shipped with HardyOS
	SourceUpload   Source = "upload"   // a .hardyapp an admin uploaded
	SourceImported Source = "imported" // from an imported catalog (SourceName)
	SourceCustom   Source = "custom"   // built from a pasted Compose file
)

// Trusted reports whether the source may use the permissions its manifest
// declares without per-app grants.
func (s Source) Trusted() bool { return s == SourceCatalog || s == "" }

// ShareMount is a shared folder an app can be given (manifest "shares").
type ShareMount struct {
	Name     string `json:"name"` // MEDIA -> ${HARDY_SHARE_MEDIA}
	Label    string `json:"label"`
	Help     string `json:"help,omitempty"`
	Access   string `json:"access"`            // "read" or "write": the most the app gets
	Suggest  string `json:"suggest,omitempty"` // share id to preselect
	Required bool   `json:"required,omitempty"`
}

// ShareEnv is the environment variable holding a share's host path.
func ShareEnv(name string) string { return "HARDY_SHARE_" + name }

// ShareChoice is what an admin picked for one of the app's ShareMounts.
type ShareChoice struct {
	Share  string `json:"share"`            // shared folder id; "" = none
	Path   string `json:"path,omitempty"`   // subfolder inside it
	Access string `json:"access,omitempty"` // "read" or "write" (at most the manifest's)
}

// AppShare is a shared folder an installed app has.
type AppShare struct {
	Name   string `json:"name"`
	Label  string `json:"label"`
	Share  string `json:"share"`
	Path   string `json:"path"`
	Access string `json:"access"`
}

// Limits caps an app's resources (0 = no limit).
type Limits struct {
	MemoryMB int     `json:"memoryMB"`
	CPUs     float64 `json:"cpus"`
}

// Grant names an extra permission given to an untrusted app.
const (
	GrantHostNetwork = "hostNetwork"
	GrantGPU         = "gpu"
	GrantDevice      = "device:" // + path, e.g. device:/dev/dri
	GrantCapability  = "cap:"    // + name, e.g. cap:NET_ADMIN
)

// App user IDs.
const (
	FirstAppUID = 30000
	LastAppUID  = 30999
)

// ShareResolver is what the apps engine needs from shared folders
// (implemented by shares.Manager; wired in hardyd-priv's main).
type ShareResolver interface {
	// Resolve returns the real host path of a share (or a subfolder).
	Resolve(ctx context.Context, share, sub string) (string, error)
	GrantApp(ctx context.Context, share, app string, uid int, write bool) error
	RevokeApp(ctx context.Context, app string) error
}

// ReconfigureArgs changes an installed app's settings. Nil/omitted fields
// keep their current values; an empty password setting keeps its value.
type ReconfigureArgs struct {
	ID       string                 `json:"id"`
	Ports    map[string]int         `json:"ports,omitempty"`
	Settings map[string]string      `json:"settings,omitempty"`
	Shares   map[string]ShareChoice `json:"shares,omitempty"`
	Grants   *[]string              `json:"grants,omitempty"`
	Limits   *Limits                `json:"limits,omitempty"`
}

// SnapshotArgs snapshots an app's dataset.
type SnapshotArgs struct {
	ID     string `json:"id"`
	Reason string `json:"reason"` // "update" or "manual"
}

// Snapshot is one snapshot of an app's dataset.
type Snapshot struct {
	Name    string    `json:"name"` // the part after @
	Created time.Time `json:"created"`
	Version string    `json:"version"`
}

// RollbackArgs puts an app back to a snapshot. Confirm is the app's name.
type RollbackArgs struct {
	ID       string `json:"id"`
	Snapshot string `json:"snapshot"`
	Confirm  string `json:"confirm"`
}

// SettingValue is a current setting for the settings screen. Secret values
// are never returned: Value is "" and Set says whether one exists.
type SettingValue struct {
	Env   string `json:"env"`
	Value string `json:"value"`
	Set   bool   `json:"set"`
}

// AppConfig is an installed app's current configuration.
type AppConfig struct {
	ID         string         `json:"id"`
	Source     Source         `json:"source"`
	SourceName string         `json:"sourceName"`
	UID        int            `json:"uid"`
	Manifest   Manifest       `json:"manifest"`
	Ports      map[string]int `json:"ports"`
	Settings   []SettingValue `json:"settings"`
	Shares     []AppShare     `json:"shares"`
	Grants     []string       `json:"grants"`
	Limits     Limits         `json:"limits"`
}
