// Package shares manages shared folders: ZFS datasets <pool>/shares/<id>
// whose settings live on the dataset as org.hardyos:* user properties, so
// they move with the pool. It runs inside hardyd-priv. File sharing (SMB,
// NFS, ...) and apps both use them. See docs/plans/app-store-v2.md.
package shares

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// ErrNotImplemented marks operations not built yet.
var ErrNotImplemented = errors.New("not implemented yet")

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
}

// ShareUpdate changes a shared folder; nil fields keep their values.
type ShareUpdate struct {
	ID          string  `json:"id"`
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	QuotaBytes  *uint64 `json:"quotaBytes,omitempty"`
	Recycle     *bool   `json:"recycle,omitempty"`
	Guest       *bool   `json:"guest,omitempty"`
	Access      *[]Rule `json:"access,omitempty"`
}

// StarterArgs creates the starter set on a pool.
type StarterArgs struct {
	Pool    string `json:"pool"`
	Media   bool   `json:"media"`   // Media with Movies, TV, Music, Photos
	Backups bool   `json:"backups"` // Backups
}

// Manager manages shared folders. It runs as root.
type Manager struct {
	Runner sysexec.Runner
	Log    *slog.Logger
	// Root prefixes system paths; "/" in production.
	Root string
}

// List returns every shared folder on every imported pool.
func (m *Manager) List(ctx context.Context) ([]Share, error) { return nil, ErrNotImplemented }

// Create makes a shared folder.
func (m *Manager) Create(ctx context.Context, a NewShare) (*Share, error) {
	return nil, ErrNotImplemented
}

// Update changes a shared folder's settings.
func (m *Manager) Update(ctx context.Context, a ShareUpdate) (*Share, error) {
	return nil, ErrNotImplemented
}

// Delete destroys a shared folder and its files. Confirm is its name.
func (m *Manager) Delete(ctx context.Context, id, confirm string) error { return ErrNotImplemented }

// CreateStarter makes the starter shared folders that don't exist yet.
func (m *Manager) CreateStarter(ctx context.Context, a StarterArgs) ([]Share, error) {
	return nil, ErrNotImplemented
}

// Folders lists the subfolders of a share's folder sub (for pickers).
func (m *Manager) Folders(ctx context.Context, id, sub string) ([]string, error) {
	return nil, ErrNotImplemented
}

// Resolve returns the real host path of a share or a subfolder in it.
func (m *Manager) Resolve(ctx context.Context, id, sub string) (string, error) {
	return "", ErrNotImplemented
}

// GrantApp gives an app's user read or write access to a share.
func (m *Manager) GrantApp(ctx context.Context, id, app string, uid int, write bool) error {
	return ErrNotImplemented
}

// RevokeApp removes an app's access from every share.
func (m *Manager) RevokeApp(ctx context.Context, app string) error { return ErrNotImplemented }
