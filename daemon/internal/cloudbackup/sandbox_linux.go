package cloudbackup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// The restic sandbox (decisions 176 and 182). restic parses data from a
// bucket someone else can write to and runs as root, so the kernel holds it
// to what each run needs:
//
//   - Network: restic runs in a network namespace of its own with only a
//     loopback interface. The egress proxy's listening socket is made in
//     that namespace (by a thread that entered it, which then starts
//     restic), and the proxy dials out from the host's namespace: the
//     proxy is the only thing restic can reach.
//   - Files: a private mount namespace where every mount is read-only
//     except restic's cache and, for a restore, the staging folder it
//     restores into; root's secrets (keys, SSH host keys, the database)
//     are hidden under empty read-only tmpfs mounts.
//   - Capabilities: the bounding set keeps only what the run needs (reading
//     any file for a backup; owners and modes for a restore; nothing
//     otherwise), with no_new_privs.
//
// The mount and capability steps can't run in Go between fork and exec, so
// hardyd-priv re-executes itself with SandboxArg (SandboxMain), which sets
// them up and executes restic.

// SandboxArg is the first argument that makes hardyd-priv SandboxMain.
const SandboxArg = "__hardyos-restic-sandbox"

// DefaultMask is what restic never sees.
var DefaultMask = []string{"/var/lib/hardyos", "/etc/hardyos", "/etc/ssh", "/etc/ssl/private", "/root", "/var/lib/samba/private", "/var/lib/hardyos-domain"}

// Sandbox isolates restic runs; nil runs restic directly (tests without
// root).
type Sandbox struct {
	// Helper runs SandboxMain (default /proc/self/exe: hardyd-priv).
	Helper string
	// Mask overrides DefaultMask.
	Mask []string
}

// Capability profiles.
var (
	capsNone    []int
	capsRead    = []int{unix.CAP_DAC_READ_SEARCH}
	capsRestore = []int{unix.CAP_CHOWN, unix.CAP_FOWNER, unix.CAP_DAC_OVERRIDE, unix.CAP_FSETID, unix.CAP_MKNOD}
)

type sandboxSpec struct {
	Binary string   `json:"binary"`
	RW     []string `json:"rw"`
	Mask   []string `json:"mask"`
	Caps   []int    `json:"caps"`
}

func (s *Sandbox) command(binary string, args, rw []string, caps []int) (*exec.Cmd, error) {
	for _, p := range append([]string{binary}, rw...) {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return nil, fmt.Errorf("sandbox: bad path %q", p)
		}
	}
	mask := s.Mask
	if mask == nil {
		mask = DefaultMask
	}
	spec, err := json.Marshal(sandboxSpec{Binary: binary, RW: rw, Mask: mask, Caps: caps})
	if err != nil {
		return nil, err
	}
	helper := s.Helper
	if helper == "" {
		helper = "/proc/self/exe"
	}
	cmd := exec.Command(helper, append([]string{SandboxArg, string(spec)}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Cloneflags: syscall.CLONE_NEWNS}
	return cmd, nil
}

// inNewNetns runs start on a thread that has entered a new network
// namespace with loopback up. Sockets start makes, and processes it starts,
// live in that namespace. The thread is never used again (the goroutine
// ends locked, so the runtime ends the thread).
func inNewNetns(start func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// No UnlockOSThread: this thread's namespace is not the process's.
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			done <- fmt.Errorf("sandbox: a network namespace for restic: %w", err)
			return
		}
		if err := loopbackUp(); err != nil {
			done <- fmt.Errorf("sandbox: loopback: %w", err)
			return
		}
		done <- start()
	}()
	return <-done
}

func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// SandboxMain is hardyd-priv started with SandboxArg (in a new mount
// namespace): it locks the namespace down and executes restic. It returns
// only on failure, with the exit status to use.
func SandboxMain(args []string) int {
	if len(args) < 2 || args[0] != SandboxArg {
		fmt.Fprintln(os.Stderr, "sandbox: bad arguments")
		return 125
	}
	var spec sandboxSpec
	if err := json.Unmarshal([]byte(args[1]), &spec); err != nil || spec.Binary == "" {
		fmt.Fprintln(os.Stderr, "sandbox: bad spec")
		return 125
	}
	if err := sandboxSetup(&spec); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox:", err)
		return 125
	}
	argv := append([]string{spec.Binary}, args[2:]...)
	err := unix.Exec(spec.Binary, argv, os.Environ())
	fmt.Fprintln(os.Stderr, "sandbox: exec:", err)
	return 126
}

func sandboxSetup(spec *sandboxSpec) error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("private mounts: %w", err)
	}
	for _, p := range spec.RW {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
			return fmt.Errorf("bad writable path %q", p)
		}
		if err := unix.Mount(p, p, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("binding %s: %w", p, err)
		}
	}
	if err := unix.MountSetattr(-1, "/", unix.AT_RECURSIVE, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY | unix.MOUNT_ATTR_NOSUID}); err != nil {
		return fmt.Errorf("read-only mounts: %w", err)
	}
	for _, p := range spec.RW {
		if err := unix.MountSetattr(-1, p, unix.AT_RECURSIVE, &unix.MountAttr{Attr_clr: unix.MOUNT_ATTR_RDONLY}); err != nil {
			return fmt.Errorf("writable %s: %w", p, err)
		}
	}
	for _, m := range spec.Mask {
		if !filepath.IsAbs(m) || filepath.Clean(m) != m || m == "/" {
			return fmt.Errorf("bad mask %q", m)
		}
		covers := false
		for _, p := range spec.RW {
			covers = covers || p == m || strings.HasPrefix(p, m+"/")
		}
		if covers {
			continue
		}
		fi, err := os.Lstat(m)
		if err != nil || !fi.IsDir() {
			continue
		}
		if err := unix.Mount("hardyos-masked", m, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=4k,mode=0500"); err != nil {
			return fmt.Errorf("hiding %s: %w", m, err)
		}
	}
	return dropCaps(spec.Caps)
}

// dropCaps leaves keep in the bounding set (root gets exactly those at
// exec), clears the ambient set and sets no_new_privs.
func dropCaps(keep []int) error {
	last := 63
	if b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap"); err == nil {
		fmt.Sscan(strings.TrimSpace(string(b)), &last)
	}
	for c := 0; c <= last; c++ {
		kept := false
		for _, k := range keep {
			kept = kept || k == c
		}
		if kept {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("dropping capability %d: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
		return err
	}
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}
