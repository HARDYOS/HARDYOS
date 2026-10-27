// Package syslock serialises hardyd-priv's system-wide work: rewriting the
// boot menu (boot.Sync and what calls it), installing an update (which
// builds a new system and syncs the boot menu) and the GPU driver tasks
// (apt and DKMS in this system, or chrooted into a new one). Two of these
// at once would run apt twice, build into a system being unpacked, or
// write grub.cfg from two places.
//
// The lock is held by one holder at a time, named in plain words so a
// refusal can say what's in the way. With Path set (hardyd-priv and
// hardyctl set it), it's also an flock on that file, so separate
// processes (hardyctl boot-sync on the console) take turns too.
package syslock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultPath is the lock file on a server: in hardyd-priv's own runtime
// directory, 0600 root, so hardyd can't open it to hold the lock.
const DefaultPath = "/run/hardyos/system.lock"

// Path is the lock file ("" for an in-process lock only, as in tests).
var Path string

var (
	sem    = make(chan struct{}, 1)
	mu     sync.Mutex
	holder string
)

// BusyError says what holds the lock.
type BusyError struct{ Holder string }

func (e *BusyError) Error() string {
	if e.Holder == "" {
		return "another system task is running (an update, a boot menu change or a graphics driver install); try again when it's done"
	}
	return fmt.Sprintf("%s is in progress; try again when it's done", e.Holder)
}

// ErrBusy matches any BusyError with errors.Is.
var ErrBusy = errors.New("system busy")

func (e *BusyError) Is(target error) bool { return target == ErrBusy }

// Holder returns what holds the lock now ("" if free or held elsewhere).
func Holder() string {
	mu.Lock()
	defer mu.Unlock()
	return holder
}

// TryAcquire takes the lock for what (in plain words: "Installing the
// NVIDIA driver") or fails at once with a BusyError.
func TryAcquire(what string) (release func(), err error) {
	select {
	case sem <- struct{}{}:
	default:
		return nil, &BusyError{Holder: Holder()}
	}
	return finish(what, true)
}

// TryAcquireTask is TryAcquire for a GPU driver task: it excludes the
// other holders in hardyd-priv but leaves the file lock free, because the
// packages it installs run "hardyctl boot-sync" themselves (the kernel
// and initramfs hooks), which takes the file lock and must not wait for
// the task that started it. Nothing else that writes the boot menu can
// run meanwhile: everything in hardyd-priv that does needs the in-process
// lock this holds.
func TryAcquireTask(what string) (release func(), err error) {
	select {
	case sem <- struct{}{}:
	default:
		return nil, &BusyError{Holder: Holder()}
	}
	return finish(what, false)
}

// Acquire waits for the lock until ctx ends.
func Acquire(ctx context.Context, what string) (release func(), err error) {
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return nil, &BusyError{Holder: Holder()}
	}
	for {
		rel, err := finish(what, true)
		if err == nil || !errors.Is(err, ErrBusy) {
			return rel, err
		}
		// Another process holds the file lock (finish gave the in-process
		// one back): wait for it.
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(200 * time.Millisecond):
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return nil, &BusyError{Holder: Holder()}
		}
	}
}

// finish takes the file lock (if any) once the in-process one is held.
func finish(what string, file bool) (func(), error) {
	fd := -1
	if Path != "" && file {
		var err error
		fd, err = unix.Open(Path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err != nil {
			<-sem
			return nil, fmt.Errorf("open the system lock %s: %w", Path, err)
		}
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			unix.Close(fd)
			<-sem
			if errors.Is(err, unix.EWOULDBLOCK) {
				return nil, &BusyError{}
			}
			return nil, fmt.Errorf("lock %s: %w", Path, err)
		}
	}
	mu.Lock()
	holder = what
	mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			mu.Lock()
			holder = ""
			mu.Unlock()
			if fd >= 0 {
				_ = unix.Flock(fd, unix.LOCK_UN)
				unix.Close(fd)
			}
			<-sem
		})
	}, nil
}

// Init sets Path to DefaultPath when its directory exists (hardyd-priv
// and hardyctl on a server).
func Init() {
	if fi, err := os.Stat("/run/hardyos"); err == nil && fi.IsDir() && os.Geteuid() == 0 {
		Path = DefaultPath
	}
}
