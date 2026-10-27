package files

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/fileworker"
	"github.com/hardyos/hardyos/daemon/internal/priv"
)

// maxCopyDepth bounds how deep a copied folder may go.
const maxCopyDepth = 64

// copyChunk is how much is copied between progress reports and checks for
// cancelling.
const copyChunk = 32 << 20

// CopyTree implements Extended. hardyd copies the bytes between the two
// files it's handed (copy_file_range, so ZFS can clone blocks); each file
// is opened and created by a worker as the person.
func (c *Client) CopyTree(ctx context.Context, who Who, src, dst Location, opt CopyOptions) (string, error) {
	w, err := c.who(ctx, who)
	if err != nil {
		return "", err
	}
	if dst.Snapshot != "" {
		return "", &Error{Kind: ErrNotAllowed, Msg: "older versions can't be changed"}
	}
	src.Path, dst.Path = cleanRel(src.Path), cleanRel(dst.Path)
	if src.Path == "" || dst.Path == "" {
		return "", &Error{Kind: ErrNotAllowed, Msg: "the top of a shared folder can't be copied or replaced"}
	}
	// Copying something onto itself only works as "name (copy)".
	if src.Snapshot == "" && src.Share == dst.Share && (dst.Path == src.Path || strings.HasPrefix(dst.Path, src.Path+"/")) &&
		!(dst.Path == src.Path && opt.Conflict == ConflictRename) {
		return "", &Error{Kind: ErrNotAllowed, Msg: "a folder can't be copied into itself"}
	}
	cp := &copier{c: c, w: w, opt: opt}
	top, err := cp.stat(ctx, src)
	if err != nil {
		return "", err
	}
	target, merge, err := cp.target(ctx, dst, top.Dir)
	if err != nil || target == "" {
		return target, err
	}
	dst.Path = target
	if opt.Progress != nil {
		if err := cp.count(ctx, src, top, 0); err != nil {
			return "", err
		}
		opt.Progress(cp.p)
	}
	if err := cp.copy(ctx, src, dst, top, merge, 0); err != nil {
		return "", err
	}
	return target, nil
}

func cleanRel(p string) string { return strings.Trim(p, "/") }

type copier struct {
	c   *Client
	w   fileworker.Who
	opt CopyOptions
	p   Progress
}

func (cp *copier) args(l Location) fileworker.Args {
	return fileworker.Args{Share: l.Share, Path: l.Path, Snapshot: l.Snapshot}
}

func (cp *copier) stat(ctx context.Context, l Location) (*Entry, error) {
	var e Entry
	if err := cp.c.call(ctx, cp.w, priv.OpFilesStat, cp.args(l), &e); err != nil {
		return nil, err
	}
	return &e, nil
}

func (cp *copier) list(ctx context.Context, l Location) (*Listing, error) {
	var ls Listing
	if err := cp.c.call(ctx, cp.w, priv.OpFilesList, cp.args(l), &ls); err != nil {
		return nil, err
	}
	if ls.Truncated {
		return nil, &Error{Kind: ErrNotAllowed, Msg: fmt.Sprintf("%s holds more than %d items, too many to copy at once", l.Path, MaxEntries)}
	}
	return &ls, nil
}

// target picks the destination path for the conflict rule; merge means an
// existing folder is copied into.
func (cp *copier) target(ctx context.Context, dst Location, dir bool) (string, bool, error) {
	ex, err := cp.stat(ctx, dst)
	if errors.Is(err, ErrNotFound) {
		return dst.Path, false, nil
	}
	if err != nil {
		return "", false, err
	}
	switch cp.opt.Conflict {
	case ConflictSkip:
		return "", false, nil
	case ConflictReplace:
		if ex.Dir != dir {
			return "", false, &Error{Kind: ErrExists, Msg: fmt.Sprintf("%s is already there and isn't a %s", ex.Name, map[bool]string{true: "folder", false: "file"}[dir])}
		}
		return dst.Path, dir, nil
	case ConflictRename:
		suffix := cp.opt.Suffix
		if suffix == "" {
			suffix = "copy"
		}
		dirPart, name := path.Split(dst.Path)
		stem, ext := splitExt(name, dir)
		for i := 1; i <= 100; i++ {
			n := fmt.Sprintf("%s (%s)%s", stem, suffix, ext)
			if i > 1 {
				n = fmt.Sprintf("%s (%s %d)%s", stem, suffix, i, ext)
			}
			cand := dirPart + n
			if _, err := cp.stat(ctx, Location{Share: dst.Share, Path: cand}); errors.Is(err, ErrNotFound) {
				return cand, false, nil
			} else if err != nil {
				return "", false, err
			}
		}
		return "", false, &Error{Kind: ErrExists, Msg: "there are too many copies with that name already"}
	}
	return "", false, &Error{Kind: ErrExists, Msg: fmt.Sprintf("%s is already there", ex.Name)}
}

func splitExt(name string, dir bool) (string, string) {
	if dir {
		return name, ""
	}
	i := strings.LastIndexByte(name, '.')
	if i <= 0 {
		return name, ""
	}
	return name[:i], name[i:]
}

func (cp *copier) count(ctx context.Context, src Location, e *Entry, depth int) error {
	if !e.Dir {
		cp.p.TotalFiles++
		cp.p.TotalBytes += e.Size
		return nil
	}
	if depth >= maxCopyDepth {
		return &Error{Kind: ErrNotAllowed, Msg: "the folder is too deep to copy"}
	}
	ls, err := cp.list(ctx, src)
	if err != nil {
		return err
	}
	for i := range ls.Entries {
		ce := ls.Entries[i]
		if err := cp.count(ctx, Location{Share: src.Share, Path: ce.Path, Snapshot: src.Snapshot}, &ce, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (cp *copier) copy(ctx context.Context, src, dst Location, e *Entry, merge bool, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !e.Dir {
		return cp.copyFile(ctx, src, dst, e)
	}
	if depth >= maxCopyDepth {
		return &Error{Kind: ErrNotAllowed, Msg: "the folder is too deep to copy"}
	}
	if !merge {
		if err := cp.c.call(ctx, cp.w, priv.OpFilesMkdir, fileworker.Args{Share: dst.Share, Path: dst.Path}, nil); err != nil {
			return err
		}
	}
	ls, err := cp.list(ctx, src)
	if err != nil {
		return err
	}
	for i := range ls.Entries {
		ce := ls.Entries[i]
		cs := Location{Share: src.Share, Path: ce.Path, Snapshot: src.Snapshot}
		cd := Location{Share: dst.Share, Path: dst.Path + "/" + ce.Name}
		childMerge := false
		if merge {
			ex, err := cp.stat(ctx, cd)
			switch {
			case errors.Is(err, ErrNotFound):
			case err != nil:
				return err
			case ex.Dir != ce.Dir:
				return &Error{Kind: ErrExists, Msg: fmt.Sprintf("%s is already there and isn't a %s", cd.Path, map[bool]string{true: "folder", false: "file"}[ce.Dir])}
			default:
				childMerge = ce.Dir
			}
		}
		if err := cp.copy(ctx, cs, cd, &ce, childMerge, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (cp *copier) copyFile(ctx context.Context, src, dst Location, e *Entry) error {
	cp.p.Current = e.Name
	in, ie, err := cp.c.callFile(ctx, cp.w, priv.OpFilesOpen, cp.args(src))
	if err != nil {
		return err
	}
	defer in.Close()
	out, _, err := cp.c.callFile(ctx, cp.w, priv.OpFilesCreate, fileworker.Args{
		Share: dst.Share, Path: dst.Path, Overwrite: cp.opt.Conflict == ConflictReplace})
	if err != nil {
		return err
	}
	if err := copyData(ctx, out, in, func(n int64) {
		cp.p.Bytes += n
		if cp.opt.Progress != nil {
			cp.opt.Progress(cp.p)
		}
	}); err != nil {
		out.Close()
		// Don't leave half a file behind.
		_ = cp.c.call(context.Background(), cp.w, priv.OpFilesDelete, fileworker.Args{Share: dst.Share, Path: dst.Path, Permanent: true}, nil)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	cp.p.Files++
	if cp.opt.Progress != nil {
		cp.opt.Progress(cp.p)
	}
	// Keep the modification time, like Explorer and Finder do.
	return cp.c.call(ctx, cp.w, priv.OpFilesSetTime, fileworker.Args{Share: dst.Share, Path: dst.Path, Modified: ie.Modified}, nil)
}

// copyData copies in to out in chunks, stopping when ctx is done.
func copyData(ctx context.Context, out, in *os.File, done func(int64)) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.CopyN(out, in, copyChunk)
		if n > 0 {
			done(n)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return mapIOErr(err)
		}
	}
}

// mapIOErr gives a full disk its own error.
func mapIOErr(err error) error {
	var pe *os.PathError
	msg := err.Error()
	if errors.As(err, &pe) {
		msg = pe.Err.Error()
	}
	if strings.Contains(msg, "no space left") || strings.Contains(msg, "quota exceeded") {
		return &Error{Kind: ErrFull, Msg: ErrFull.Error()}
	}
	return err
}
