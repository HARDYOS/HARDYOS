// Package rootfile reads state files that hardyd-priv (root) wrote into
// /var/lib/hardyos. That directory belongs to the hardyd account, so hardyd
// could put its own file in place of root's. Root must only act on files root
// wrote: owned by root, a regular file, not writable by group or others.
// hardyd can't create root-owned files, so it can't forge one.
package rootfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// Enforce turns the ownership check on. hardyd-priv sets it at start when
// running as root; tests (which don't run as root) leave it off.
var Enforce = false

// ErrNotTrusted means a state file wasn't written by root.
var ErrNotTrusted = errors.New("not written by root; ignoring it")

// Check verifies that path is a root-owned regular file nobody else can write.
// A missing file returns the fs.ErrNotExist error.
func Check(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !Enforce {
		return nil
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: %w", path, ErrNotTrusted)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: %w", path, ErrNotTrusted)
	}
	return nil
}

// IsNotExist reports whether err means the file isn't there.
func IsNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }
