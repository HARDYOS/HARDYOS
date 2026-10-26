// Package files is hardyd's side of reading and writing files in shared
// folders as the person asking (see docs/plans/file-sharing.md section 3).
// The work itself happens in hardyd-priv, in a child that has dropped to the
// person's Linux identity; hardyd only gets file descriptors back.
package files

import (
	"context"
	"errors"
	"os"
	"time"
)

// ErrNotImplemented marks operations not built yet.
var ErrNotImplemented = errors.New("not implemented yet")

// Errors the API maps to status codes.
var (
	ErrNotFound   = errors.New("there's no such file or folder")
	ErrNoAccess   = errors.New("you don't have access to that")
	ErrExists     = errors.New("something with that name is already there")
	ErrNotAllowed = errors.New("that isn't allowed here")
	// ErrFull: the shared folder (its quota or its pool) is full.
	ErrFull = errors.New("there's no space left in this shared folder")
)

// HomeShare is the share id the person's own home folder goes by.
const HomeShare = "~home"

// Who is the person files are read and written as.
type Who struct {
	// Principal: "HOME\\alice" for domain accounts, "admin" for local ones.
	Principal string
	// Local: a HardyOS account (not a domain one); only admins may use
	// files, and they act as the hardyos-files system user.
	Local bool
	Admin bool
}

// Entry is a file or folder.
type Entry struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"` // inside the share, "/" separated, no leading slash
	Dir      bool      `json:"dir"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	// Writable: the person may change or delete it.
	Writable bool `json:"writable"`
}

// ShareInfo is a shared folder (or Home) the person can open.
type ShareInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Writable bool   `json:"writable"`
	Recycle  bool   `json:"recycle"`
}

// Version is an older copy of a path, from a snapshot.
type Version struct {
	Snapshot string    `json:"snapshot"`
	Taken    time.Time `json:"taken"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	// Dir: the path was a folder in that snapshot.
	Dir bool `json:"dir"`
}

// Access reads and writes files as a person. Paths are inside the share,
// "/" separated; "" is its top.
type Access interface {
	Shares(ctx context.Context, who Who) ([]ShareInfo, error)
	List(ctx context.Context, who Who, share, path string) ([]Entry, error)
	Stat(ctx context.Context, who Who, share, path string) (*Entry, error)
	// Open opens a file for reading.
	Open(ctx context.Context, who Who, share, path string) (*os.File, *Entry, error)
	// Create opens a new file for writing (overwrite replaces an existing one).
	Create(ctx context.Context, who Who, share, path string, overwrite bool) (*os.File, error)
	Mkdir(ctx context.Context, who Who, share, path string) error
	Rename(ctx context.Context, who Who, share, from, toShare, to string) error
	Copy(ctx context.Context, who Who, share, from, toShare, to string) error
	// Delete moves to the share's recycle bin when it has one.
	Delete(ctx context.Context, who Who, share, path string) error
	Versions(ctx context.Context, who Who, share, path string) ([]Version, error)
	OpenVersion(ctx context.Context, who Who, share, path, snapshot string) (*os.File, *Entry, error)
	// Restore copies an older version back; returns the path it was written to.
	Restore(ctx context.Context, who Who, share, path, snapshot string) (string, error)
}
