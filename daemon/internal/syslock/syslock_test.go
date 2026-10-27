package syslock

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOneHolderAtATime(t *testing.T) {
	for _, file := range []bool{false, true} {
		Path = ""
		if file {
			Path = filepath.Join(t.TempDir(), "system.lock")
		}
		rel, err := TryAcquire("Installing the NVIDIA driver")
		if err != nil {
			t.Fatal(err)
		}
		_, err = TryAcquire("Installing an update")
		if !errors.Is(err, ErrBusy) || !strings.Contains(err.Error(), "Installing the NVIDIA driver is in progress") {
			t.Fatalf("second holder: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		if _, err := Acquire(ctx, "Updating the boot menu"); !errors.Is(err, ErrBusy) {
			t.Fatalf("waiting past the deadline: %v", err)
		}
		cancel()
		done := make(chan error, 1)
		go func() {
			r, err := Acquire(context.Background(), "Updating the boot menu")
			if err == nil {
				r()
			}
			done <- err
		}()
		time.Sleep(20 * time.Millisecond)
		rel()
		rel() // twice is harmless
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if Holder() != "" {
			t.Fatalf("holder left: %q", Holder())
		}
	}
	Path = ""
}

// Another process (hardyctl boot-sync) holding the file lock.
func TestOtherProcessHoldsTheFile(t *testing.T) {
	Path = filepath.Join(t.TempDir(), "system.lock")
	defer func() { Path = "" }()
	fd, err := unix.Open(Path, unix.O_RDWR|unix.O_CREAT, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if _, err := TryAcquire("x"); !errors.Is(err, ErrBusy) {
		t.Fatalf("try: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := Acquire(ctx, "x"); !errors.Is(err, ErrBusy) {
		t.Fatalf("acquire: %v", err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = unix.Flock(fd, unix.LOCK_UN)
	}()
	rel, err := Acquire(context.Background(), "x")
	if err != nil {
		t.Fatal(err)
	}
	rel()
}
