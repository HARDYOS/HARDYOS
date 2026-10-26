//go:build linux

package apps

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestMkdirStrictSymlinkSwap plays a container that keeps exchanging a
// folder in its data with a symbolic link to a folder outside
// (renameat2 RENAME_EXCHANGE, atomic) while root creates and chmods a
// folder inside it. Nothing may ever happen outside.
func TestMkdirStrictSymlinkSwap(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	must(t, os.Chmod(outside, 0o755))
	must(t, os.Mkdir(filepath.Join(base, "cfg"), 0o755))
	must(t, os.Symlink(outside, filepath.Join(base, "swap")))
	a, b := filepath.Join(base, "cfg"), filepath.Join(base, "swap")
	if err := unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE); errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
		t.Skip("renameat2 RENAME_EXCHANGE isn't available here")
	} else if err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
			}
		}
	}()
	own := dirOwner{UID: 30007, GID: 30007}
	deadline := time.Now().Add(300 * time.Millisecond)
	tries, ok := 0, 0
	for time.Now().Before(deadline) || tries < 200 {
		tries++
		if mkdirStrict(base, "cfg/sub", 0o777, own) == nil {
			ok++
		}
		if mkdirStrict(base, "cfg", 0o777, own) == nil {
			ok++
		}
	}
	close(stop)
	wg.Wait()

	if _, err := os.Lstat(filepath.Join(outside, "sub")); err == nil {
		t.Error("a folder was created through the link")
	}
	fi, err := os.Stat(outside)
	must(t, err)
	if fi.Mode().Perm() != 0o755 {
		t.Errorf("the folder outside changed mode: %v", fi.Mode())
	}
	if os.Geteuid() == 0 && ownerOf(t, outside) == 30007 {
		t.Error("the folder outside was given away")
	}
	if ok == 0 {
		t.Error("never succeeded while the folder was in place")
	}
	t.Logf("%d tries, %d succeeded", tries, ok)
}
