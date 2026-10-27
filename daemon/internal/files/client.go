package files

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/auth"
	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// Error is a failure the API shows as is; errors.Is matches its Kind
// (ErrNotFound, ErrNoAccess, ErrExists, ErrNotAllowed, ErrFull).
type Error struct {
	Kind error
	Msg  string
}

func (e *Error) Error() string { return e.Msg }
func (e *Error) Unwrap() error { return e.Kind }

// errCrossDevice: a rename between shares has to be a copy.
var errCrossDevice = errors.New("cross device")

// Client implements Service over hardyd-priv's files.* operations.
type Client struct {
	Priv *priv.Client
	// Lookup says who a Who is right now: their groups for the folders'
	// rules, whether they're (still) an administrator, and refuses
	// disabled or removed accounts. nil trusts Who as given (no groups).
	Lookup func(ctx context.Context, who Who) (auth.Identity, error)
}

var _ Service = (*Client)(nil)

// UserLookup looks people up in hardyd's accounts (domain accounts as of
// their last sign-in or group refresh).
func UserLookup(users *auth.Users) func(ctx context.Context, who Who) (auth.Identity, error) {
	return func(ctx context.Context, who Who) (auth.Identity, error) {
		u, err := users.GetByName(ctx, who.Principal)
		if err != nil || u.Disabled || (u.IdentitySource() == auth.SourceLocal) != who.Local {
			return nil, &Error{Kind: ErrNoAccess, Msg: "that account can't use files"}
		}
		return u, nil
	}
}

// WhoFor is the Who of a signed-in person.
func WhoFor(id auth.Identity) Who {
	return Who{Principal: id.IdentityPrincipal(), Local: id.IdentitySource() != auth.SourceDomain, Admin: id.IsAdmin()}
}

func (c *Client) who(ctx context.Context, w Who) (fileworker.Who, error) {
	if w.Principal == "" {
		return fileworker.Who{}, &Error{Kind: ErrNoAccess, Msg: "nobody to act as"}
	}
	if c.Lookup == nil {
		return fileworker.Who{Principal: w.Principal, Local: w.Local, Admin: w.Admin}, nil
	}
	id, err := c.Lookup(ctx, w)
	if err != nil {
		return fileworker.Who{}, err
	}
	fw := fileworker.Who{
		Principal: id.IdentityPrincipal(),
		Local:     id.IdentitySource() != auth.SourceDomain,
		Admin:     id.IsAdmin(),
		Groups:    id.IdentityGroups(),
	}
	if fw.Local && !fw.Admin {
		return fileworker.Who{}, &Error{Kind: ErrNoAccess, Msg: "files can be used by administrators and domain accounts; ask an administrator for a domain account"}
	}
	return fw, nil
}

// mapErr turns hardyd-priv's answer into this package's errors.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var pe *priv.Error
	if !errors.As(err, &pe) {
		return err
	}
	switch pe.Code {
	case priv.CodeNotFound:
		return &Error{Kind: ErrNotFound, Msg: pe.Message}
	case priv.CodeNoAccess:
		return &Error{Kind: ErrNoAccess, Msg: pe.Message}
	case priv.CodeExists:
		return &Error{Kind: ErrExists, Msg: pe.Message}
	case priv.CodeNotAllowed, priv.CodeBadArgs:
		return &Error{Kind: ErrNotAllowed, Msg: pe.Message}
	case priv.CodeFull:
		return &Error{Kind: ErrFull, Msg: pe.Message}
	case priv.CodeCrossDevice:
		return &Error{Kind: errCrossDevice, Msg: pe.Message}
	}
	return err
}

func (c *Client) call(ctx context.Context, w fileworker.Who, op string, a fileworker.Args, out any) error {
	a.Who = w
	return mapErr(c.Priv.Call(ctx, op, a, out))
}

func (c *Client) callFile(ctx context.Context, w fileworker.Who, op string, a fileworker.Args) (*os.File, *Entry, error) {
	a.Who = w
	var e Entry
	f, err := c.Priv.CallFile(ctx, op, a, &e)
	if err != nil {
		return nil, nil, mapErr(err)
	}
	return f, &e, nil
}

// do resolves who and runs one call.
func (c *Client) do(ctx context.Context, who Who, op string, a fileworker.Args, out any) error {
	w, err := c.who(ctx, who)
	if err != nil {
		return err
	}
	return c.call(ctx, w, op, a, out)
}

// ---- Access ------------------------------------------------------------------

// Shares lists the shared folders the person can open, Home first.
func (c *Client) Shares(ctx context.Context, who Who) ([]ShareInfo, error) {
	var l []fileworker.ShareAccess
	if err := c.do(ctx, who, priv.OpFilesShares, fileworker.Args{}, &l); err != nil {
		return nil, err
	}
	out := make([]ShareInfo, 0, len(l))
	for _, s := range l {
		out = append(out, ShareInfo{ID: s.ID, Name: s.Name, Writable: s.Writable, Recycle: s.Recycle})
	}
	return out, nil
}

// List lists a folder.
func (c *Client) List(ctx context.Context, who Who, share, path string) ([]Entry, error) {
	l, err := c.ListDir(ctx, who, share, path, "")
	if err != nil {
		return nil, err
	}
	return l.Entries, nil
}

// ListDir implements Extended.
func (c *Client) ListDir(ctx context.Context, who Who, share, path, snapshot string) (*Listing, error) {
	var l Listing
	if err := c.do(ctx, who, priv.OpFilesList, fileworker.Args{Share: share, Path: path, Snapshot: snapshot}, &l); err != nil {
		return nil, err
	}
	if l.Entries == nil {
		l.Entries = []Entry{}
	}
	return &l, nil
}

// Stat describes one file or folder.
func (c *Client) Stat(ctx context.Context, who Who, share, path string) (*Entry, error) {
	return c.stat(ctx, who, Location{Share: share, Path: path})
}

// StatVersion implements Extended.
func (c *Client) StatVersion(ctx context.Context, who Who, share, path, snapshot string) (*Entry, error) {
	return c.stat(ctx, who, Location{Share: share, Path: path, Snapshot: snapshot})
}

func (c *Client) stat(ctx context.Context, who Who, l Location) (*Entry, error) {
	var e Entry
	if err := c.do(ctx, who, priv.OpFilesStat, fileworker.Args{Share: l.Share, Path: l.Path, Snapshot: l.Snapshot}, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// Open opens a file for reading.
func (c *Client) Open(ctx context.Context, who Who, share, path string) (*os.File, *Entry, error) {
	return c.OpenVersion(ctx, who, share, path, "")
}

// OpenVersion opens a file as it was in a snapshot ("" = now).
func (c *Client) OpenVersion(ctx context.Context, who Who, share, path, snapshot string) (*os.File, *Entry, error) {
	w, err := c.who(ctx, who)
	if err != nil {
		return nil, nil, err
	}
	return c.callFile(ctx, w, priv.OpFilesOpen, fileworker.Args{Share: share, Path: path, Snapshot: snapshot})
}

// Create opens a new file for writing.
func (c *Client) Create(ctx context.Context, who Who, share, path string, overwrite bool) (*os.File, error) {
	w, err := c.who(ctx, who)
	if err != nil {
		return nil, err
	}
	f, _, err := c.callFile(ctx, w, priv.OpFilesCreate, fileworker.Args{Share: share, Path: path, Overwrite: overwrite})
	return f, err
}

// OpenWrite implements Extended.
func (c *Client) OpenWrite(ctx context.Context, who Who, share, path string) (*os.File, *Entry, error) {
	w, err := c.who(ctx, who)
	if err != nil {
		return nil, nil, err
	}
	return c.callFile(ctx, w, priv.OpFilesOpenWrite, fileworker.Args{Share: share, Path: path})
}

// Mkdir makes a folder.
func (c *Client) Mkdir(ctx context.Context, who Who, share, path string) error {
	return c.do(ctx, who, priv.OpFilesMkdir, fileworker.Args{Share: share, Path: path}, nil)
}

// Rename renames or moves a file or folder; between shares it's a copy and
// a delete.
func (c *Client) Rename(ctx context.Context, who Who, share, from, toShare, to string) error {
	_, err := c.Move(ctx, who, share, from, toShare, to, nil)
	return err
}

// Move is Rename with progress for the copy a move between shares takes.
// moved is false when it had to copy.
func (c *Client) Move(ctx context.Context, who Who, share, from, toShare, to string, progress func(Progress)) (moved bool, err error) {
	if toShare == "" {
		toShare = share
	}
	err = c.do(ctx, who, priv.OpFilesRename, fileworker.Args{Share: share, Path: from, ToShare: toShare, To: to}, nil)
	if !errors.Is(err, errCrossDevice) {
		return err == nil, err
	}
	if _, err := c.CopyTree(ctx, who, Location{Share: share, Path: from}, Location{Share: toShare, Path: to},
		CopyOptions{Conflict: ConflictFail, Progress: progress}); err != nil {
		return false, err
	}
	if _, err := c.DeleteItem(ctx, who, share, from, true); err != nil {
		return false, fmt.Errorf("copied to %s, but the original couldn't be removed: %w", to, err)
	}
	return false, nil
}

// Replace implements Extended.
func (c *Client) Replace(ctx context.Context, who Who, share, from, to string) error {
	return c.do(ctx, who, priv.OpFilesRename, fileworker.Args{Share: share, Path: from, To: to, Overwrite: true}, nil)
}

// Copy copies a file or folder; the target must not exist.
func (c *Client) Copy(ctx context.Context, who Who, share, from, toShare, to string) error {
	if toShare == "" {
		toShare = share
	}
	_, err := c.CopyTree(ctx, who, Location{Share: share, Path: from}, Location{Share: toShare, Path: to}, CopyOptions{Conflict: ConflictFail})
	return err
}

// Delete moves to the share's recycle bin when it has one.
func (c *Client) Delete(ctx context.Context, who Who, share, path string) error {
	_, err := c.DeleteItem(ctx, who, share, path, false)
	return err
}

// DeleteItem implements Extended.
func (c *Client) DeleteItem(ctx context.Context, who Who, share, path string, permanent bool) (bool, error) {
	if strings.Trim(path, "/") == "" {
		return false, &Error{Kind: ErrNotAllowed, Msg: "the top of a shared folder can't be deleted"}
	}
	var res struct {
		Recycled bool `json:"recycled"`
	}
	err := c.do(ctx, who, priv.OpFilesDelete, fileworker.Args{Share: share, Path: path, Permanent: permanent}, &res)
	return res.Recycled, err
}

// SetModified implements Extended.
func (c *Client) SetModified(ctx context.Context, who Who, share, path string, t time.Time) error {
	return c.do(ctx, who, priv.OpFilesSetTime, fileworker.Args{Share: share, Path: path, Modified: t}, nil)
}

// Versions lists a path's older versions, newest first.
func (c *Client) Versions(ctx context.Context, who Who, share, path string) ([]Version, error) {
	var l []Version
	if err := c.do(ctx, who, priv.OpFilesVersions, fileworker.Args{Share: share, Path: path}, &l); err != nil {
		return nil, err
	}
	if l == nil {
		l = []Version{}
	}
	return l, nil
}

// Restore copies an older version back next to the current one.
func (c *Client) Restore(ctx context.Context, who Who, share, path, snapshot string) (string, error) {
	return c.RestoreWith(ctx, who, share, path, snapshot, nil)
}

// RestoreWith implements Extended: the older version is copied to path if
// nothing is there now, otherwise to "name (restored 2026-10-26).ext".
func (c *Client) RestoreWith(ctx context.Context, who Who, share, path, snapshot string, progress func(Progress)) (string, error) {
	taken, ok := fileworker.SnapshotTime(snapshot)
	if !ok {
		return "", &Error{Kind: ErrNotFound, Msg: "there's no such older version"}
	}
	if strings.Trim(path, "/") == "" {
		return "", &Error{Kind: ErrNotAllowed, Msg: "restore files and folders inside the shared folder, not the whole folder"}
	}
	return c.CopyTree(ctx, who, Location{Share: share, Path: path, Snapshot: snapshot}, Location{Share: share, Path: path},
		CopyOptions{Conflict: ConflictRename, Suffix: "restored " + taken.Format("2006-01-02"), Progress: progress})
}
