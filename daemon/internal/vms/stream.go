package vms

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
)

// Streamer runs the long commands of imports (decision 134): qemu-img on a
// private copy of the image, and xz unpacking. Production runs both in a
// throwaway systemd sandbox as an unprivileged user without a network;
// tests replace it.
type Streamer interface {
	// QemuImg runs qemu-img with j.Args and returns what it printed.
	// The sandbox sees j.Image (read-only) and, when set, the block device
	// j.Target (read-write), nothing else of the pools or shares; j.OnPct
	// gets the percentages qemu-img -p prints.
	QemuImg(ctx context.Context, j ImgJob) ([]byte, error)
	// Unpack decompresses an .xz stream from in to out, reporting the
	// compressed bytes read. Writes to out may fail (a size limit), which
	// stops it.
	Unpack(ctx context.Context, in io.Reader, out io.Writer, onRead func(int64)) error
}

// ImgJob is one qemu-img run.
type ImgJob struct {
	Args   []string
	Image  string // host path of the private copy, readable by the sandbox user
	Target string // host path of the block device to write, or ""
	OnPct  func(float64)
}

func (m *Manager) stream() Streamer {
	if m.Stream != nil {
		return m.Stream
	}
	return SandboxStreamer{User: m.importUser()}
}

// ImportUser is the unprivileged user (and group) that runs qemu-img and
// xz for imports; packaging creates it.
const ImportUser = "hardyos-import"

func (m *Manager) importUser() string {
	if m.ImportUser != "" {
		return m.ImportUser
	}
	return ImportUser
}

func command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	return cmd
}

// SandboxStreamer runs qemu-img and xz with systemd-run as a transient
// service: User (never root), no capabilities, no network, a read-only
// system, private /dev and /tmp, the pools' and shares' usual places
// hidden, and only the files of the job bound in.
type SandboxStreamer struct {
	User string
}

// sandboxProps are the transient service's settings for a job.
func sandboxProps(user, image, target string) []string {
	p := []string{
		"User=" + user, "Group=" + user,
		"NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=",
		"PrivateNetwork=yes", "PrivateIPC=yes", "PrivateTmp=yes", "PrivateDevices=yes",
		"ProtectSystem=strict", "ProtectHome=yes", "ProtectProc=invisible",
		"ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectKernelLogs=yes",
		"ProtectControlGroups=yes", "ProtectClock=yes", "ProtectHostname=yes",
		"RestrictAddressFamilies=AF_UNIX", "RestrictNamespaces=yes", "RestrictSUIDSGID=yes",
		"RestrictRealtime=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
		"SystemCallArchitectures=native", "SystemCallFilter=@system-service", "SystemCallErrorNumber=EPERM",
		"UMask=0077", "MemoryMax=4G", "TasksMax=64", "RuntimeMaxSec=12h",
	}
	// Pools and shares are mounted under these, sockets under /run; what is
	// elsewhere is still only readable as an unprivileged user.
	for _, d := range []string{"/mnt", "/srv", "/media", "/run"} {
		p = append(p, "TemporaryFileSystem="+d+":ro")
	}
	if image != "" {
		p = append(p, "BindReadOnlyPaths="+image)
	}
	if target != "" {
		// The device node is root:disk; the device cgroup lets only this
		// one block device be opened, and it's the only one in the
		// private /dev.
		p = append(p, "SupplementaryGroups=disk", "BindPaths="+target, "DeviceAllow="+target+" rw")
	}
	return p
}

func sandboxCommand(ctx context.Context, user, image, target string, argv ...string) (*exec.Cmd, error) {
	if user == "" || user == "root" || strings.ContainsAny(user, " \t\n=") {
		return nil, errors.New("imports need an unprivileged user")
	}
	for _, p := range []string{image, target} {
		if p != "" && (!filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, " \t\n:\\\"'")) {
			return nil, fmt.Errorf("%q can't be handed to the import sandbox", p)
		}
	}
	args := []string{"--quiet", "--wait", "--collect", "--pipe", "--service-type=exec"}
	for _, p := range sandboxProps(user, image, target) {
		args = append(args, "--property="+p)
	}
	args = append(append(args, "--"), argv...)
	return command(ctx, "systemd-run", args...), nil
}

// QemuImg implements Streamer.
func (s SandboxStreamer) QemuImg(ctx context.Context, j ImgJob) ([]byte, error) {
	cmd, err := sandboxCommand(ctx, s.User, j.Image, j.Target, append([]string{"/usr/bin/qemu-img"}, j.Args...)...)
	if err != nil {
		return nil, err
	}
	return runImg(cmd, j.OnPct)
}

// Unpack implements Streamer.
func (s SandboxStreamer) Unpack(ctx context.Context, in io.Reader, out io.Writer, onRead func(int64)) error {
	cmd, err := sandboxCommand(ctx, s.User, "", "", xzArgs...)
	if err != nil {
		return err
	}
	return runFilter(cmd, in, out, onRead)
}

// xzArgs unpack stdin to stdout with a memory limit.
var xzArgs = []string{"/usr/bin/xz", "--decompress", "--stdout", "--threads=0", "--memlimit-decompress=2GiB"}

// DirectStreamer runs qemu-img and xz as this process, without a sandbox.
// It's for tests (the arguments are the same as in production).
type DirectStreamer struct{}

// QemuImg implements Streamer.
func (DirectStreamer) QemuImg(ctx context.Context, j ImgJob) ([]byte, error) {
	return runImg(command(ctx, "qemu-img", j.Args...), j.OnPct)
}

// Unpack implements Streamer.
func (DirectStreamer) Unpack(ctx context.Context, in io.Reader, out io.Writer, onRead func(int64)) error {
	return runFilter(command(ctx, "xz", xzArgs[1:]...), in, out, onRead)
}

// qemu-img -p prints "    (12.34/100%)" with carriage returns.
var pctRE = regexp.MustCompile(`\((\d+(?:\.\d+)?)/100%\)`)

func splitCR(data []byte, atEOF bool) (int, []byte, error) {
	for i, b := range data {
		if b == '\r' || b == '\n' {
			return i + 1, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// maxImgOutput bounds what qemu-img may print (info's JSON).
const maxImgOutput = 4 << 20

func runImg(cmd *exec.Cmd, onPct func(float64)) ([]byte, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var errb bytes.Buffer
	cmd.Stderr = &limitedBuffer{b: &errb, n: 64 << 10}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	sc := bufio.NewScanner(io.TeeReader(io.LimitReader(stdout, maxImgOutput), &out))
	sc.Buffer(make([]byte, 64<<10), maxImgOutput)
	sc.Split(splitCR)
	for sc.Scan() {
		if onPct == nil {
			continue
		}
		if mt := pctRE.FindSubmatch(sc.Bytes()); mt != nil {
			if p, err := strconv.ParseFloat(string(mt[1]), 64); err == nil {
				onPct(p)
			}
		}
	}
	_, _ = io.Copy(io.Discard, stdout)
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("qemu-img: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

func runFilter(cmd *exec.Cmd, in io.Reader, out io.Writer, onRead func(int64)) error {
	cmd.Stdin = &countingReader{r: in, on: onRead}
	cmd.Stdout = out
	var errb bytes.Buffer
	cmd.Stderr = &limitedBuffer{b: &errb, n: 64 << 10}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}

type limitedBuffer struct {
	b *bytes.Buffer
	n int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// errTooBig is a capped writer's refusal.
var errTooBig = errors.New("bigger than allowed")

// capWriter fails writes past n bytes in all.
type capWriter struct {
	w       io.Writer
	n, done int64
	over    bool // a write was refused
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.done+int64(len(p)) > c.n {
		c.over = true
		return 0, errTooBig
	}
	k, err := c.w.Write(p)
	c.done += int64(k)
	return k, err
}

type countingReader struct {
	r  io.Reader
	n  atomic.Int64
	on func(int64)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 && c.on != nil {
		c.on(c.n.Add(int64(n)))
	}
	return n, err
}
