//go:build linux

package install

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Chroot work (the system directories bound into a new system, and the
// commands run in it) happens in a mount namespace of its own: a slave of
// the server's, so the server's own changes (a USB stick appearing under
// /dev) still show inside, but nothing mounted inside ever propagates out,
// to the server or to the namespaces of its services (libvirtd, logind,
// chronyd... each a slave of the server's). When the work is done the
// namespace ends, and everything mounted in it with it.
//
// Binding /dev into a target that is itself shared (a ZFS dataset mounted
// on the server) used to copy the bind into every service's namespace;
// unmounting it on the server after cutting propagation left those copies
// in place, holding the dataset, and "zpool export" failed with "pool is
// busy" (decision 145).

// privateMountNS runs fn on an OS thread of its own in a new mount
// namespace (a recursive slave of the caller's). Commands fn starts (from
// the same goroutine) are born in it. Processes still in it when fn
// returns (a daemon a package started in the chroot) are listed and
// killed, so the namespace, and every mount in it, goes away.
func privateMountNS(fn func() error) error {
	type result struct {
		err    error
		killed []string
	}
	done := make(chan result, 1)
	go func() {
		// Never unlocked: the thread ends with this goroutine, and takes
		// the namespace with it.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
			done <- result{err: fmt.Errorf("make a private mount namespace: %w", err)}
			return
		}
		if err := unix.Mount("", "/", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
			done <- result{err: fmt.Errorf("make the mount namespace a slave: %w", err)}
			return
		}
		ns, _ := os.Readlink("/proc/thread-self/ns/mnt")
		err := fn()
		done <- result{err: err, killed: killNamespace(ns)}
	}()
	res := <-done
	if len(res.killed) > 0 {
		slog.Warn("processes left behind in a new system's chroot were stopped", "processes", strings.Join(res.killed, ", "))
	}
	return res.err
}

// killNamespace stops every process whose mount namespace is ns ("" does
// nothing), and returns them ("1234 dirmngr").
func killNamespace(ns string) []string {
	if ns == "" {
		return nil
	}
	var out []string
	for attempt := 0; attempt < 50; attempt++ {
		pids := pidsInNamespace(ns)
		if len(pids) == 0 {
			break
		}
		for _, pid := range pids {
			if attempt == 0 {
				comm, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
				out = append(out, fmt.Sprintf("%d %s", pid, strings.TrimSpace(string(comm))))
			}
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return out
}

func pidsInNamespace(ns string) []int {
	self := os.Getpid()
	procs, _ := os.ReadDir("/proc")
	var out []int
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil || pid == self {
			continue
		}
		if t, err := os.Readlink(filepath.Join("/proc", p.Name(), "ns/mnt")); err == nil && t == ns {
			// A zombie has no namespace link; a live one is still in it.
			out = append(out, pid)
		}
	}
	return out
}

// OtherNamespaceMounts lists mounts under target in other processes' mount
// namespaces than this one ("/target/dev (pid 812 libvirtd)"), one entry
// per namespace and mount point: what keeps a pool busy that this
// namespace can't see.
func OtherNamespaceMounts(target string) []string {
	self, _ := os.Readlink("/proc/self/ns/mnt")
	prefix := strings.TrimSuffix(target, "/") + "/"
	seenNS := map[string]bool{self: true}
	procs, _ := os.ReadDir("/proc")
	var out []string
	for _, p := range procs {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		ns, err := os.Readlink(filepath.Join("/proc", p.Name(), "ns/mnt"))
		if err != nil || seenNS[ns] {
			continue
		}
		seenNS[ns] = true
		b, err := os.ReadFile(filepath.Join("/proc", p.Name(), "mountinfo"))
		if err != nil {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join("/proc", p.Name(), "comm"))
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) > 4 && strings.HasPrefix(unescapeOctal(f[4]), prefix) {
				out = append(out, fmt.Sprintf("%s (pid %s %s)", unescapeOctal(f[4]), p.Name(), strings.TrimSpace(string(comm))))
				if len(out) >= 20 {
					return append(out, "…")
				}
			}
		}
	}
	return out
}
