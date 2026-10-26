package files

import (
	"context"
	"os"
	"time"
)

// Listing is a folder and what's in it.
type Listing struct {
	// Folder is the folder itself (Writable: things can be made in it).
	Folder  Entry   `json:"folder"`
	Entries []Entry `json:"entries"`
	// Truncated: the folder holds more than MaxEntries; not all are listed.
	Truncated bool `json:"truncated"`
}

// MaxEntries is the most entries one listing returns.
const MaxEntries = 50000

// Location is a file or folder in a share, now or in an older version.
type Location struct {
	Share string `json:"share"`
	Path  string `json:"path"`
	// Snapshot: read it from this automatic snapshot (read only).
	Snapshot string `json:"snapshot,omitempty"`
}

// Conflict says what a copy does when the target name is taken.
type Conflict string

const (
	// ConflictFail stops with ErrExists.
	ConflictFail Conflict = "fail"
	// ConflictRename picks a free name: "photo (copy).jpg", "photo (copy 2).jpg".
	ConflictRename Conflict = "rename"
	// ConflictSkip leaves the existing one and copies nothing.
	ConflictSkip Conflict = "skip"
	// ConflictReplace overwrites files and merges folders.
	ConflictReplace Conflict = "replace"
)

// Progress reports a copy's progress.
type Progress struct {
	Files      int    `json:"files"`
	TotalFiles int    `json:"totalFiles"`
	Bytes      int64  `json:"bytes"`
	TotalBytes int64  `json:"totalBytes"`
	Current    string `json:"current"`
}

// CopyOptions tune CopyTree.
type CopyOptions struct {
	Conflict Conflict
	// Suffix names the copy on ConflictRename: "copy" (default) gives
	// "photo (copy).jpg".
	Suffix string
	// Progress, if set, is called as the copy goes (after a first pass that
	// counts what there is to copy).
	Progress func(Progress)
}

// Extended is what hardyd's API needs beyond Access: uploads in chunks,
// copies with progress, permanent deletes. *Client implements both.
type Extended interface {
	// ListDir lists a folder, now or in a snapshot.
	ListDir(ctx context.Context, who Who, share, path, snapshot string) (*Listing, error)
	// StatVersion describes a path as it is now or in a snapshot ("").
	StatVersion(ctx context.Context, who Who, share, path, snapshot string) (*Entry, error)
	// OpenWrite opens an existing file for writing without truncating it
	// (the next chunk of an upload).
	OpenWrite(ctx context.Context, who Who, share, path string) (*os.File, *Entry, error)
	// Replace renames a file over another one (finishing an upload that
	// replaces a file). Folders are never replaced.
	Replace(ctx context.Context, who Who, share, from, to string) error
	// DeleteItem deletes a file or folder: to the recycle bin when the share
	// has one and permanent is false. recycled says which happened.
	DeleteItem(ctx context.Context, who Who, share, path string, permanent bool) (recycled bool, err error)
	// SetModified sets a file's modification time.
	SetModified(ctx context.Context, who Who, share, path string, t time.Time) error
	// CopyTree copies a file or folder (from a snapshot too) to dst.Path,
	// returning the path it was written to ("" when skipped).
	CopyTree(ctx context.Context, who Who, src, dst Location, opt CopyOptions) (string, error)
	// RestoreWith is Restore with progress.
	RestoreWith(ctx context.Context, who Who, share, path, snapshot string, progress func(Progress)) (string, error)
}

// Service is Access and Extended.
type Service interface {
	Access
	Extended
}
