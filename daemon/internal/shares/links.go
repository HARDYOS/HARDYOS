package shares

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LinkScan is what ScanLinks found in a shared folder.
type LinkScan struct {
	// Escaping are links (paths relative to the share, with '/') whose
	// target is absolute, can't be resolved, or resolves outside the
	// share: an app that reads the folder in a container would follow
	// them to whatever the container sees there (another of its mounts).
	Escaping []string `json:"escaping"`
	// Count is how many escaping links there are (Escaping holds at most
	// MaxEscaping of them).
	Count int `json:"count"`
	// Entries is how many files and folders were looked at.
	Entries int `json:"entries"`
	// Truncated: the walk stopped at MaxScanEntries (or the time limit)
	// before it saw everything.
	Truncated bool `json:"truncated"`
}

// Limits of a link scan.
const (
	MaxEscaping    = 1000
	MaxScanEntries = 5_000_000
)

// ScanLinks walks a shared folder (never following links) and lists its
// symbolic links that lead out of it. Absolute targets always count: in a
// container they resolve against the container's own tree, not the host's.
// The walk ends when ctx does (Truncated then).
func (m *Manager) ScanLinks(ctx context.Context, id string) (*LinkScan, error) {
	sh, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !sh.Usable() {
		return nil, invalid("the shared folder %s isn't available right now", sh.Name)
	}
	base, err := filepath.EvalSymlinks(m.sys(sh.Path))
	if err != nil {
		return nil, err
	}
	return scanLinks(ctx, base)
}

// ScanLinksIn is ScanLinks for a folder given by its path.
func ScanLinksIn(ctx context.Context, dir string) (*LinkScan, error) {
	base, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	return scanLinks(ctx, base)
}

var errStop = errors.New("stop")

func scanLinks(ctx context.Context, base string) (*LinkScan, error) {
	out := &LinkScan{Escaping: []string{}}
	inside := func(p string) bool {
		return p == base || strings.HasPrefix(p, base+string(filepath.Separator))
	}
	err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable folder: skipped, like an app reading it would.
			if d != nil && d.IsDir() && p != base {
				return fs.SkipDir
			}
			return nil
		}
		out.Entries++
		if out.Entries%4096 == 0 && ctx.Err() != nil {
			out.Truncated = true
			return errStop
		}
		if out.Entries >= MaxScanEntries {
			out.Truncated = true
			return errStop
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		escaping := false
		target, err := os.Readlink(p)
		switch {
		case err != nil || filepath.IsAbs(target):
			escaping = true
		default:
			real, err := filepath.EvalSymlinks(p)
			escaping = err != nil || !inside(real)
		}
		if escaping {
			out.Count++
			if len(out.Escaping) < MaxEscaping {
				rel, _ := filepath.Rel(base, p)
				out.Escaping = append(out.Escaping, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStop) {
		return nil, err
	}
	return out, nil
}
