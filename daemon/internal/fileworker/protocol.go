// Package fileworker is the root side of reading and writing files in shared
// folders as the person asking (docs/plans/file-sharing.md section 3).
//
// hardyd-priv never touches a person's files itself. For each operation it
// works out the person's Linux identity, opens the shared folder's root
// directory (O_PATH) and starts a short-lived child: the same binary with the
// fixed subcommand "fileworker", already running as that person (the
// credentials are set between fork and exec, so the child never runs a line
// of code as root). The child resolves every path with openat2 beneath the
// root it was handed, without following any link, does the one operation,
// writes its JSON result to stdout and, for downloads and uploads, sends the
// open file descriptor back over a socket (SCM_RIGHTS). No file content goes
// through JSON.
package fileworker

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Subcommand is the argument hardyd-priv is re-run with to become a worker.
const Subcommand = "fileworker"

// FilesUID is the hardyos-files system user HardyOS administrators (local
// accounts, not domain ones) act as. The shares manager gives it read and
// write on every shared folder, like an app grant.
const FilesUID = 29999

// FilesUserName is the hardyos-files account's name.
const FilesUserName = "hardyos-files"

// HomeShare is the share id of the person's own home folder.
const HomeShare = "~home"

// Operations a worker runs.
const (
	OpShares    = "shares"    // which of the given roots the person can read / write
	OpList      = "list"      // a folder's entries
	OpStat      = "stat"      // one entry
	OpOpen      = "open"      // a file for reading (fd)
	OpCreate    = "create"    // a new file for writing (fd)
	OpOpenWrite = "openwrite" // an existing file for writing, no truncation (fd)
	OpMkdir     = "mkdir"
	OpRename    = "rename"   // within or across roots; cross-device is reported, not copied
	OpDelete    = "delete"   // to the recycle bin, or permanently
	OpSetTime   = "settime"  // set a file's modification time
	OpVersions  = "versions" // a path's older versions in the automatic snapshots
)

// Error codes a worker (and the files.* priv operations) report.
const (
	CodeNotFound    = "not_found"
	CodeNoAccess    = "no_access"
	CodeExists      = "exists"
	CodeNotAllowed  = "not_allowed"
	CodeFull        = "full"
	CodeCrossDevice = "cross_device"
	CodeBadArgs     = "bad_args"
	CodeFailed      = "failed"
)

// Error is an operation's failure, with a code from the list above.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

func errorf(code, format string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, a...)}
}

// Request is what the parent sends a worker on stdin.
type Request struct {
	Op string `json:"op"`
	// UID and GID the worker must be running as (checked before anything else).
	UID int `json:"uid"`
	GID int `json:"gid"`
	// Roots is how many root directories follow the socket (fds 4, 5, ...).
	Roots int `json:"roots"`

	Path     string `json:"path,omitempty"`
	Snapshot string `json:"snapshot,omitempty"`
	// ToRoot is the index of the destination root for rename (0 or 1).
	ToRoot    int       `json:"toRoot,omitempty"`
	To        string    `json:"to,omitempty"`
	Overwrite bool      `json:"overwrite,omitempty"`
	Recycle   bool      `json:"recycle,omitempty"`
	Bin       string    `json:"bin,omitempty"` // the person's folder in .recycle
	Modified  time.Time `json:"modified,omitempty"`
	// ReadOnly: the folder's access rules give this person read only, so
	// nothing is shown as writable.
	ReadOnly bool `json:"readOnly,omitempty"`
}

// Response is what a worker writes to stdout.
type Response struct {
	OK    bool   `json:"ok"`
	Error *Error `json:"error,omitempty"`
	Data  any    `json:"data,omitempty"`
}

// Entry is a file or folder.
type Entry struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Dir      bool      `json:"dir"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	Writable bool      `json:"writable"`
}

// Listing is a folder and what's in it.
type Listing struct {
	Folder    Entry   `json:"folder"`
	Entries   []Entry `json:"entries"`
	Truncated bool    `json:"truncated"`
}

// RootAccess says what the person may do with one root (OpShares).
type RootAccess struct {
	Read  bool `json:"read"`
	Write bool `json:"write"`
}

// Version is an older copy of a path in an automatic snapshot.
type Version struct {
	Snapshot string    `json:"snapshot"`
	Taken    time.Time `json:"taken"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	Dir      bool      `json:"dir"`
}

// MaxEntries bounds one listing.
const MaxEntries = 50000

// Path limits.
const (
	maxPathLen = 4000
	maxNameLen = 255
	maxDepth   = 256
)

// UploadPrefix starts the temporary name of an upload in progress (hidden).
const UploadPrefix = ".hardyos-upload-"

// UploadTempRE is an upload's temporary name: the one hidden name a path
// may end in, so hardyd can write and finish the upload.
var UploadTempRE = regexp.MustCompile(`^\.hardyos-upload-[0-9a-f]{24}$`)

// SnapshotRE matches the automatic snapshots' names (contract section 2):
// hardyos-auto-<kind>_<YYYY-MM-DD-HHMM>, UTC.
var SnapshotRE = regexp.MustCompile(`^hardyos-auto-(hourly|daily|weekly|monthly)_([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{4})$`)

// SnapshotTime is when an automatic snapshot was taken.
func SnapshotTime(name string) (time.Time, bool) {
	m := SnapshotRE.FindStringSubmatch(name)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02-1504", m[2])
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// Hidden reports whether a name is never shown or reachable: the recycle
// bin, ZFS's snapshot directory and HardyOS's own files.
func Hidden(name string) bool {
	return name == ".recycle" || name == ".zfs" || strings.HasPrefix(name, ".hardyos")
}

// ErrBadPath is returned by CleanPath.
var ErrBadPath = errors.New("bad path")

// CleanPath checks a path inside a share ("/" separated; a leading or
// trailing "/" is ignored; "" is the top) and returns its components. "." and
// ".." components, empty components ("a//b"), hidden names, NUL bytes and
// names that aren't UTF-8 are refused.
func CleanPath(p string) ([]string, error) {
	if len(p) > maxPathLen {
		return nil, errorf(CodeBadArgs, "the path is too long")
	}
	if !utf8.ValidString(p) || strings.ContainsRune(p, 0) {
		return nil, errorf(CodeBadArgs, "the path isn't valid")
	}
	p = strings.TrimSuffix(strings.TrimPrefix(p, "/"), "/")
	if p == "" {
		return nil, nil
	}
	parts := strings.Split(p, "/")
	if len(parts) > maxDepth {
		return nil, errorf(CodeBadArgs, "the path is too deep")
	}
	for i, c := range parts {
		switch {
		case i == len(parts)-1 && UploadTempRE.MatchString(c):
		case c == "":
			return nil, errorf(CodeBadArgs, "the path has an empty folder name")
		case c == "." || c == "..":
			return nil, errorf(CodeNotAllowed, "paths can't use . or ..")
		case len(c) > maxNameLen:
			return nil, errorf(CodeBadArgs, "the name %.40q... is too long", c)
		case Hidden(c):
			return nil, errorf(CodeNotAllowed, "%s is reserved and can't be used", c)
		}
	}
	return parts, nil
}

// CleanName checks a single new file or folder name.
func CleanName(n string) error {
	parts, err := CleanPath(n)
	if err != nil {
		return err
	}
	if len(parts) != 1 || parts[0] != n {
		return errorf(CodeBadArgs, "a name can't contain /")
	}
	return nil
}

// Join builds a share path from components.
func Join(parts []string) string { return strings.Join(parts, "/") }
