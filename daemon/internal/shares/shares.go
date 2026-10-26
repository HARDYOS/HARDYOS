// Package shares manages shared folders: ZFS datasets <pool>/shares/<id>
// whose settings live on the dataset as org.hardyos:* user properties, so
// they move with the pool. It runs inside hardyd-priv. File sharing (SMB,
// NFS, ...) and apps both use them. See docs/plans/app-store-v2.md.
package shares

import (
	"errors"
	"time"
)

// ErrNotFound means there's no shared folder with that id.
var ErrNotFound = errors.New("there's no shared folder with that id")

// ValidationError is the caller's mistake (shown to the person as is).
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// Access levels.
const (
	LevelRead  = "read"
	LevelWrite = "write"
	LevelNone  = "none"
)

// Principal kinds.
const (
	KindUser     = "user"
	KindGroup    = "group"
	KindEveryone = "everyone"
)

// Rule gives a user, group or everyone a level of access.
type Rule struct {
	Kind  string `json:"kind"`
	Name  string `json:"name,omitempty"` // HOME\alice, HOME\Family; empty for everyone
	Level string `json:"level"`
}

// AppGrant records an app's access to a share (applied as POSIX ACLs).
type AppGrant struct {
	App   string `json:"app"`
	UID   int    `json:"uid"`
	Level string `json:"level"`
}

// Share is a shared folder.
type Share struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Pool        string     `json:"pool"`
	Dataset     string     `json:"dataset"`
	Path        string     `json:"path"`
	Mounted     bool       `json:"mounted"`
	QuotaBytes  uint64     `json:"quotaBytes"`
	UsedBytes   uint64     `json:"usedBytes"`
	Recycle     bool       `json:"recycle"`
	Guest       bool       `json:"guest"`
	Access      []Rule     `json:"access"`
	Apps        []AppGrant `json:"apps"`
	CreatedAt   time.Time  `json:"createdAt"`
	// Services: how the folder is shared on the network, and snapshots.
	Services Services `json:"services"`
}

// NewShare creates a shared folder.
type NewShare struct {
	Pool        string   `json:"pool"`
	Name        string   `json:"name"`
	ID          string   `json:"id,omitempty"` // default: derived from Name
	Description string   `json:"description,omitempty"`
	QuotaBytes  uint64   `json:"quotaBytes,omitempty"`
	Recycle     bool     `json:"recycle"`
	Guest       bool     `json:"guest"`
	Access      []Rule   `json:"access,omitempty"`
	Subfolders  []string `json:"subfolders,omitempty"`
	// Services; nil = DefaultServices.
	Services *Services `json:"services,omitempty"`
}

// ShareUpdate changes a shared folder; nil fields keep their values.
type ShareUpdate struct {
	ID          string    `json:"id"`
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	QuotaBytes  *uint64   `json:"quotaBytes,omitempty"`
	Recycle     *bool     `json:"recycle,omitempty"`
	Guest       *bool     `json:"guest,omitempty"`
	Access      *[]Rule   `json:"access,omitempty"`
	Services    *Services `json:"services,omitempty"`
}

// StarterArgs creates the starter set on a pool.
type StarterArgs struct {
	Pool    string `json:"pool"`
	Media   bool   `json:"media"`   // Media with Movies, TV, Music, Photos
	Backups bool   `json:"backups"` // Backups
}
