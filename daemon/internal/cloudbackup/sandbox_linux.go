package cloudbackup

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The restic sandbox (decisions 226, 232 and 236). restic parses data from a
// bucket someone else can write to, so the sandbox assumes a repository can
// get code running inside restic and holds that code to what the run needs:
//
//   - Network: its own network namespace with only loopback, where the
//     egress proxy's socket is made (by a thread that entered it and then
//     starts restic); the proxy dials out from the host. A seccomp filter
//     allows socket() only for AF_INET and AF_INET6, so no local socket
//     (hardyd-priv's, Docker's, netlink) can even be made.
//   - Files: an allowlist root. A new mount namespace whose root is an
//     empty tmpfs holding only what the run needs, bound in: the restic
//     binary and the CA bundle read-only, a minimal /dev (null, zero,
//     random, urandom), a fresh /proc of its own PID namespace (only its own
//     process visible), the folder a backup reads (read-only), and the
//     destination's cache and a restore's staging folder (read-write).
//     Everything is nosuid and nodev (but the four device nodes). Nothing
//     else of the host exists in there: no /run, /var/lib, /etc, shares,
//     pools or sockets.
//   - Identity: the hardyos-restic user (not root), with only the run's
//     capabilities as ambient capabilities (reading any file for a backup
//     of folders; owners, modes and writing for a restore; none otherwise),
//     no_new_privs, in a PID namespace of its own.
//
// Any setup step that fails stops the run (fail closed). The mount, PID,
// identity and seccomp steps can't run in Go between fork and exec, so
// hardyd-priv re-executes itself with SandboxArg (SandboxMain), which sets
// them up and executes restic.

// SandboxArg is the first argument that makes hardyd-priv SandboxMain.
const SandboxArg = "__hardyos-restic-sandbox"

// SandboxUser is the user restic runs as.
const SandboxUser = "hardyos-restic"

// CABundle is the system's CA certificates (bound into the sandbox).
const CABundle = "/etc/ssl/certs/ca-certificates.crt"

// Sandbox isolates restic runs; nil runs restic directly (tests without
// root).
type Sandbox struct {
	// Helper runs SandboxMain (default /proc/self/exe: hardyd-priv).
	Helper string
	// UID and GID restic runs as (hardyos-restic); never 0.
	UID, GID int
	// ExtraRO are more folders bound read-only (tests: a dynamically
	// linked helper's libraries).
	ExtraRO []string
}

// Capability profiles.
var (
	capsNone    []int
	capsRead    = []int{unix.CAP_DAC_READ_SEARCH}
	capsRestore = []int{unix.CAP_CHOWN, unix.CAP_DAC_OVERRIDE, unix.CAP_FOWNER}
)

type sandboxSpec struct {
	Binary string   `json:"binary"`
	RO     []string `json:"ro"`
	RW     []string `json:"rw"`
	Caps   []int    `json:"caps"`
	UID    int      `json:"uid"`
	GID    int      `json:"gid"`
}

func cleanAbs(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p && p != "/" }

func (s *Sandbox) command(binary string, args, ro, rw []string, caps []int) (*exec.Cmd, error) {
	if s.UID <= 0 || s.GID <= 0 {
		return nil, errors.New("sandbox: no user for restic (hardyos-restic is missing)")
	}
	ro = append(append([]string{}, ro...), s.ExtraRO...)
	for _, p := range append(append([]string{binary}, ro...), rw...) {
		if !cleanAbs(p) {
			return nil, fmt.Errorf("sandbox: bad path %q", p)
		}
	}
	spec, err := json.Marshal(sandboxSpec{Binary: binary, RO: ro, RW: rw, Caps: caps, UID: s.UID, GID: s.GID})
	if err != nil {
		return nil, err
	}
	helper := s.Helper
	if helper == "" {
		helper = "/proc/self/exe"
	}
	cmd := exec.Command(helper, append([]string{SandboxArg, string(spec)}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID}
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

// SandboxMain is hardyd-priv started with SandboxArg (PID 1 of a new PID
// namespace, in a new mount namespace): it builds restic's root, becomes
// hardyos-restic with the run's capabilities and executes restic. It
// returns only on failure, with the exit status to use.
func SandboxMain(args []string) int {
	runtime.LockOSThread() // credentials and seccomp are per thread until exec
	if len(args) < 2 || args[0] != SandboxArg {
		fmt.Fprintln(os.Stderr, "sandbox: bad arguments")
		return 125
	}
	var spec sandboxSpec
	if err := json.Unmarshal([]byte(args[1]), &spec); err != nil || !cleanAbs(spec.Binary) || spec.UID <= 0 || spec.GID <= 0 {
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

const sandboxRoot = "/run/hardyos-restic-root"

func sandboxSetup(spec *sandboxSpec) error {
	if os.Getpid() != 1 {
		return errors.New("not in a PID namespace of its own")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("private mounts: %w", err)
	}
	for _, p := range append(append([]string{spec.Binary}, spec.RO...), spec.RW...) {
		if !cleanAbs(p) {
			return fmt.Errorf("bad path %q", p)
		}
	}
	if err := os.MkdirAll(sandboxRoot, 0o700); err != nil {
		return err
	}
	root := sandboxRoot
	if err := unix.Mount("hardyos-restic", root, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=1m,mode=0755"); err != nil {
		return fmt.Errorf("the sandbox's root: %w", err)
	}
	bind := func(src string, rw bool) error {
		fi, err := os.Stat(src)
		if err != nil {
			return err
		}
		dst := filepath.Join(root, src)
		if fi.IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			f.Close()
		}
		if err := unix.Mount(src, dst, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("binding %s: %w", src, err)
		}
		attr := unix.MountAttr{Attr_set: unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV}
		if !rw {
			attr.Attr_set |= unix.MOUNT_ATTR_RDONLY
		} else {
			attr.Attr_clr = unix.MOUNT_ATTR_RDONLY
		}
		if err := unix.MountSetattr(-1, dst, unix.AT_RECURSIVE, &attr); err != nil {
			return fmt.Errorf("locking down %s: %w", src, err)
		}
		return nil
	}
	if err := bind(spec.Binary, false); err != nil {
		return err
	}
	for _, p := range spec.RO {
		if err := bind(p, false); err != nil {
			return err
		}
	}
	for _, p := range spec.RW {
		if err := bind(p, true); err != nil {
			return err
		}
	}
	// A minimal /dev.
	dev := filepath.Join(root, "dev")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		return err
	}
	if err := unix.Mount("hardyos-restic-dev", dev, "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC, "size=64k,mode=0755"); err != nil {
		return err
	}
	for _, n := range []string{"null", "zero", "random", "urandom"} {
		p := filepath.Join(dev, n)
		f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o666)
		if err != nil {
			return err
		}
		f.Close()
		if err := unix.Mount("/dev/"+n, p, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("/dev/%s: %w", n, err)
		}
		if err := unix.MountSetattr(-1, p, 0, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NOEXEC}); err != nil {
			return err
		}
	}
	for n, t := range map[string]string{"fd": "/proc/self/fd", "stdin": "/proc/self/fd/0", "stdout": "/proc/self/fd/1", "stderr": "/proc/self/fd/2"} {
		if err := os.Symlink(t, filepath.Join(dev, n)); err != nil {
			return err
		}
	}
	if err := unix.MountSetattr(-1, dev, 0, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}); err != nil {
		return err
	}
	// Its own /proc: only its own PID namespace, process directories only.
	proc := filepath.Join(root, "proc")
	if err := os.MkdirAll(proc, 0o555); err != nil {
		return err
	}
	if err := unix.Mount("proc", proc, "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "hidepid=invisible,subset=pid"); err != nil {
		return fmt.Errorf("/proc: %w", err)
	}
	// Into it, the host's tree gone.
	if err := os.MkdirAll(filepath.Join(root, ".old"), 0o700); err != nil {
		return err
	}
	if err := unix.PivotRoot(root, filepath.Join(root, ".old")); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	if err := unix.Unmount("/.old", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detaching the host's tree: %w", err)
	}
	if err := os.Remove("/.old"); err != nil {
		return err
	}
	if err := unix.MountSetattr(-1, "/", 0, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}); err != nil {
		return fmt.Errorf("read-only root: %w", err)
	}
	if err := becomeRestic(spec); err != nil {
		return err
	}
	return seccompSockets()
}

// becomeRestic switches this thread to the restic user keeping only caps,
// which the exec'd restic gets as ambient capabilities.
func becomeRestic(spec *sandboxSpec) error {
	keep := map[int]bool{}
	for _, c := range spec.Caps {
		keep[c] = true
	}
	for c := 0; c <= 63; c++ {
		if keep[c] {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("dropping capability %d: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		return err
	}
	// This thread only: it's the one that executes restic.
	if _, _, e := unix.RawSyscall(unix.SYS_SETGROUPS, 0, 0, 0); e != 0 {
		return fmt.Errorf("setgroups: %w", e)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETRESGID, uintptr(spec.GID), uintptr(spec.GID), uintptr(spec.GID)); e != 0 {
		return fmt.Errorf("setresgid: %w", e)
	}
	if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, uintptr(spec.UID), uintptr(spec.UID), uintptr(spec.UID)); e != 0 {
		return fmt.Errorf("setresuid: %w", e)
	}
	var data [2]unix.CapUserData
	for _, c := range spec.Caps {
		data[c/32].Effective |= 1 << (uint(c) % 32)
		data[c/32].Permitted |= 1 << (uint(c) % 32)
		data[c/32].Inheritable |= 1 << (uint(c) % 32)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return err
	}
	for _, c := range spec.Caps {
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(c), 0, 0); err != nil {
			return fmt.Errorf("ambient capability %d: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		return errors.New("still root")
	}
	return nil
}

// auditArch is this architecture's seccomp audit value (detected at run
// time; an unknown architecture fails closed).
func auditArch() (uint32, error) {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64, nil
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64, nil
	}
	return 0, fmt.Errorf("no seccomp filter for %s", runtime.GOARCH)
}

// seccompSockets installs a filter that lets socket() make only AF_INET
// and AF_INET6 sockets (EAFNOSUPPORT otherwise) and kills a process using
// another architecture's or the x32 system call numbers.
func seccompSockets() error {
	arch, err := auditArch()
	if err != nil {
		return err
	}
	const (
		ldW  = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeqK = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		jgeK = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		ret  = unix.BPF_RET | unix.BPF_K
	)
	argLow := uint32(16) // seccomp_data.args[0], low half (little-endian)
	if binary.NativeEndian.Uint16([]byte{0, 1}) == 1 {
		argLow = 20
	}
	prog := []unix.SockFilter{
		{Code: ldW, K: 4}, // arch
		{Code: jeqK, Jt: 1, Jf: 0, K: arch},
		{Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: ldW, K: 0}, // nr
		{Code: jgeK, Jt: 0, Jf: 1, K: 0x40000000},
		{Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: jeqK, Jt: 1, Jf: 0, K: uint32(unix.SYS_SOCKET)},
		{Code: ret, K: unix.SECCOMP_RET_ALLOW},
		{Code: ldW, K: argLow},
		{Code: jeqK, Jt: 2, Jf: 0, K: unix.AF_INET},
		{Code: jeqK, Jt: 1, Jf: 0, K: unix.AF_INET6},
		{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EAFNOSUPPORT)},
		{Code: ret, K: unix.SECCOMP_RET_ALLOW},
	}
	fp := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if _, _, e := unix.RawSyscall(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&fp))); e != 0 {
		return fmt.Errorf("seccomp: %w", e)
	}
	return nil
}

// SystemSandbox is the sandbox hardyd-priv uses: restic as hardyos-restic.
// Without that user every run fails (closed), saying so.
func SystemSandbox() *Sandbox {
	s := &Sandbox{}
	if u, err := user.Lookup(SandboxUser); err == nil {
		s.UID, _ = strconv.Atoi(u.Uid)
		s.GID, _ = strconv.Atoi(u.Gid)
	}
	return s
}
