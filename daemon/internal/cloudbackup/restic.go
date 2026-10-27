package cloudbackup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// DefaultBinary is the restic HardyOS ships (a release binary pinned by its
// SHA-256, installed by the image's 0160-restic hook; decision 160). Only
// this path is ever run.
const DefaultBinary = "/usr/lib/hardyos/restic"

// DefaultCacheDir is restic's cache (root only).
const DefaultCacheDir = "/var/cache/hardyos-restic"

// Host is the host name every snapshot is recorded under, so a server
// rebuilt from a backup carries on with the same repository (restic picks
// the parent snapshot by host and paths).
const Host = "hardyos"

// restic's exit codes (0.17+).
const (
	exitRepoMissing = 10
	exitLocked      = 11
	exitWrongKey    = 12
	exitPartial     = 3 // backup: some files couldn't be read
)

// Errors from restic, in words a person understands.
var (
	ErrRepoMissing = errors.New("there's no backup repository there yet")
	ErrWrongKey    = errors.New("the repository key is wrong (check the recovery kit)")
	ErrLocked      = errors.New("the repository is busy with another backup task; try again later")
)

// Restic runs restic. It never uses a shell; every argument is built from
// validated values, and credentials go only into the environment and a
// password pipe.
type Restic struct {
	Binary   string
	CacheDir string
	// Resolver and TestAllow are for the egress proxy (see egress.go).
	Resolver  Resolver
	TestAllow func(netip.Addr) bool
	// CACert is an extra CA file for S3 (tests with a TLS fake only).
	CACert string
	// KillGrace is how long a cancelled restic gets to remove its lock
	// before its process group is killed (default 15 s).
	KillGrace time.Duration
	// CacheLimit bounds each destination's cache (DefaultCacheLimit).
	CacheLimit int64
	// Sandbox, when set, runs restic isolated (sandbox_linux.go); hardyd-priv
	// always sets it.
	Sandbox *Sandbox
}

func (r *Restic) killGrace() time.Duration {
	if r.KillGrace > 0 {
		return r.KillGrace
	}
	return 15 * time.Second
}

func sleepMS(n int) { time.Sleep(time.Duration(n) * time.Millisecond) }

func (r *Restic) binary() string {
	if r.Binary != "" {
		return r.Binary
	}
	return DefaultBinary
}

// Repo is everything restic needs to open one repository.
type Repo struct {
	Target Target
	Creds  Credentials
}

// call is one restic run.
type call struct {
	args   []string
	stdin  io.Reader
	stdout io.Writer // nil: collected and returned
	// lines receives stdout line by line instead (JSON progress).
	lines func([]byte)
	// upload/download limits apply.
	limit bool
	// writable is where restic may write besides its cache (a restore's
	// staging folder), readable what it reads besides (a backup's folder);
	// caps the capabilities it keeps (sandbox only).
	writable []string
	readable []string
	caps     []int
}

// RunError is restic failing.
type RunError struct {
	Code   int
	Stderr string
}

func (e *RunError) Error() string {
	msg := lastLines(e.Stderr, 3)
	if msg == "" {
		msg = fmt.Sprintf("restic exited %d", e.Code)
	}
	return msg
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := strings.TrimSpace(strings.Join(lines, " "))
	out = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, out)
	if len(out) > 400 {
		out = out[:400] + "…"
	}
	return out
}

// env builds restic's environment: a fixed PATH, its cache, the repository
// and the credentials. Nothing from hardyd-priv's own environment.
func (r *Restic) env(repo *Repo, proxy, cache string) []string {
	env := []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C",
		"HOME=" + cache,
		"TMPDIR=" + cache,
		"RESTIC_CACHE_DIR=" + cache,
		"RESTIC_REPOSITORY=" + repo.Target.Repository(),
		"RESTIC_PASSWORD_FILE=/dev/fd/3",
		"RESTIC_PROGRESS_FPS=0.5",
	}
	switch repo.Target.Kind {
	case KindS3:
		env = append(env, "AWS_ACCESS_KEY_ID="+repo.Creds.AccessKey, "AWS_SECRET_ACCESS_KEY="+repo.Creds.SecretKey)
		if repo.Target.Region != "" {
			env = append(env, "AWS_DEFAULT_REGION="+repo.Target.Region)
		}
	case KindB2:
		env = append(env, "B2_ACCOUNT_ID="+repo.Creds.AccessKey, "B2_ACCOUNT_KEY="+repo.Creds.SecretKey)
	}
	if proxy != "" {
		env = append(env, "HTTPS_PROXY="+proxy, "https_proxy="+proxy, "HTTP_PROXY="+proxy, "NO_PROXY=", "no_proxy=")
	}
	return env
}

// run starts restic and waits for it. Cancelling ctx interrupts restic's
// whole process group (SIGINT, so it removes its lock), then kills it if it
// hasn't stopped after 15 seconds.
func (r *Restic) run(ctx context.Context, repo *Repo, c call) ([]byte, error) {
	cache, err := r.prepareCache(repo)
	if err != nil {
		return nil, err
	}
	global := []string{"--retry-lock", "2m"}
	if r.CACert != "" {
		global = append(global, "--cacert", r.CACert)
	}
	if c.limit {
		if repo.Target.LimitUploadKiB > 0 {
			global = append(global, "--limit-upload", strconv.Itoa(repo.Target.LimitUploadKiB))
		}
		if repo.Target.LimitDownloadKiB > 0 {
			global = append(global, "--limit-download", strconv.Itoa(repo.Target.LimitDownloadKiB))
		}
	}
	rules, err := rulesFor(&repo.Target)
	if err != nil {
		return nil, err
	}
	var eg *egressProxy
	defer func() {
		if eg != nil {
			eg.Close()
		}
	}()

	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer pr.Close()
	var cmd *exec.Cmd
	if r.Sandbox != nil {
		// restic opens the key as /dev/fd/3, which checks the pipe's owner.
		if err := pr.Chown(r.Sandbox.UID, r.Sandbox.GID); err != nil {
			pw.Close()
			return nil, err
		}
		rw := append([]string{cache}, c.writable...)
		ro := append([]string{}, c.readable...)
		if r.CACert != "" {
			ro = append(ro, r.CACert)
		}
		if repo.Target.Kind == KindLocal {
			// A folder repository (tests and development only).
			if err := os.MkdirAll(repo.Target.Path, 0o700); err != nil {
				pw.Close()
				return nil, err
			}
			if err := chownTree(repo.Target.Path, r.Sandbox.UID, r.Sandbox.GID); err != nil {
				pw.Close()
				return nil, err
			}
			rw = append(rw, repo.Target.Path)
		} else {
			ro = append(ro, CABundle)
		}
		cmd, err = r.Sandbox.command(r.binary(), append(global, c.args...), ro, rw, c.caps)
		if err != nil {
			pw.Close()
			return nil, err
		}
	} else {
		cmd = exec.Command(r.binary(), append(global, c.args...)...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	cmd.Dir = cache
	cmd.ExtraFiles = []*os.File{pr} // fd 3: the repository key
	cmd.Stdin = c.stdin
	var out bytes.Buffer
	var stdout io.ReadCloser
	switch {
	case c.lines != nil:
		stdout, err = cmd.StdoutPipe()
		if err != nil {
			pw.Close()
			return nil, err
		}
	case c.stdout != nil:
		cmd.Stdout = c.stdout
	default:
		cmd.Stdout = &limitWriter{w: &out, n: 64 << 20}
	}
	var errb bytes.Buffer
	cmd.Stderr = &limitWriter{w: &errb, n: 256 << 10}
	// The proxy's socket and restic start together: in the sandbox both
	// in restic's own network namespace.
	start := func() error {
		proxy := ""
		if rules != nil {
			res := r.Resolver
			if res == nil {
				res = defaultResolver{}
			}
			p, err := startEgress(rules, res, r.TestAllow)
			if err != nil {
				return err
			}
			eg = p
			proxy = p.URL()
		}
		cmd.Env = r.env(repo, proxy, cache)
		return cmd.Start()
	}
	if r.Sandbox != nil {
		err = inNewNetns(start)
	} else {
		err = start()
	}
	if err != nil {
		pw.Close()
		return nil, fmt.Errorf("starting restic: %w", err)
	}
	pr.Close()
	go func() {
		_, _ = io.WriteString(pw, repo.Creds.RepoPassword+"\n")
		pw.Close()
	}()
	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
			select {
			case <-stop:
			case <-time.After(r.killGrace()):
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		case <-stop:
		}
	}()
	if stdout != nil {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			c.lines(sc.Bytes())
		}
		_, _ = io.Copy(io.Discard, stdout)
	}
	werr := cmd.Wait()
	close(stop)
	// Anything left in the group (restic doesn't start children) goes.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if ctx.Err() != nil {
		return out.Bytes(), ctx.Err()
	}
	if werr != nil {
		var ee *exec.ExitError
		if errors.As(werr, &ee) {
			re := &RunError{Code: ee.ExitCode(), Stderr: errb.String()}
			if eg != nil {
				if why := eg.lastRefusal(); why != "" {
					re.Stderr += "\nblocked: " + why
				}
			}
			switch re.Code {
			case exitRepoMissing:
				return out.Bytes(), fmt.Errorf("%w: %v", ErrRepoMissing, re)
			case exitWrongKey:
				return out.Bytes(), ErrWrongKey
			case exitLocked:
				return out.Bytes(), ErrLocked
			}
			return out.Bytes(), re
		}
		return out.Bytes(), werr
	}
	return out.Bytes(), nil
}

// DefaultCacheLimit bounds a destination's cache (it's emptied above it;
// restic rebuilds what it needs from the repository).
const DefaultCacheLimit int64 = 8 << 30

// prepareCache makes the destination's own cache folder (the only place
// restic writes besides a restore's staging), owned by the sandbox's user,
// and empties it when it has grown past the limit.
func (r *Restic) prepareCache(repo *Repo) (string, error) {
	if err := os.MkdirAll(r.cacheDir(), 0o700); err != nil {
		return "", err
	}
	if !idRE.MatchString(repo.Target.ID) {
		return "", fmt.Errorf("bad destination id %q", repo.Target.ID)
	}
	dir := filepath.Join(r.cacheDir(), repo.Target.ID)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return "", fmt.Errorf("restic's cache %s isn't a folder", dir)
	}
	limit := r.CacheLimit
	if limit <= 0 {
		limit = DefaultCacheLimit
	}
	if treeSize(dir) > limit {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
	if r.Sandbox != nil {
		if err := chownTree(dir, r.Sandbox.UID, r.Sandbox.GID); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// treeSize adds up the sizes below dir (never following a link).
func treeSize(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// chownTree gives dir and everything below it to uid:gid when the top
// isn't theirs yet (never following a link).
func chownTree(dir string, uid, gid int) error {
	var st syscall.Stat_t
	if err := syscall.Lstat(dir, &st); err != nil {
		return err
	}
	if int(st.Uid) == uid && int(st.Gid) == gid {
		return nil
	}
	return filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
}

func (r *Restic) cacheDir() string {
	if r.CacheDir != "" {
		return r.CacheDir
	}
	return DefaultCacheDir
}

type limitWriter struct {
	w io.Writer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > l.n {
		q = q[:l.n]
	}
	l.n -= len(q)
	_, err := l.w.Write(q)
	return len(p), err
}

type defaultResolver struct{}

func (defaultResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return netResolver.LookupNetIP(ctx, network, host)
}

// ---- operations -------------------------------------------------------------

// Exists reports whether the repository is there and the key opens it.
func (r *Restic) Exists(ctx context.Context, repo *Repo) (bool, error) {
	_, err := r.run(ctx, repo, call{args: []string{"cat", "config"}})
	if errors.Is(err, ErrRepoMissing) {
		return false, nil
	}
	return err == nil, err
}

// Init creates the repository.
func (r *Restic) Init(ctx context.Context, repo *Repo) error {
	_, err := r.run(ctx, repo, call{args: []string{"init"}})
	return err
}

// Progress of a backup.
type Progress struct {
	Percent    float64
	BytesDone  int64
	TotalBytes int64
	FilesDone  int64
}

// Summary is a finished backup.
type Summary struct {
	SnapshotID     string `json:"snapshot_id"`
	FilesNew       int64  `json:"files_new"`
	FilesChanged   int64  `json:"files_changed"`
	DataAdded      int64  `json:"data_added"`
	TotalFiles     int64  `json:"total_files_processed"`
	TotalBytes     int64  `json:"total_bytes_processed"`
	ErrorsReported int    `json:"-"`
}

var tagRE = regexp.MustCompile(`^[a-z]+=[A-Za-z0-9._:-]{1,96}$`)

// ResticBackup is one restic backup: either a folder (Path, the stable
// path of a mounted snapshot) or a stream (Stdin with StdinName).
type ResticBackup struct {
	Path      string
	Stdin     io.Reader
	StdinName string
	Tags      []string // key=value
	Excludes  []string // names excluded anywhere (".zfs", ...)
}

var stdinNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Backup runs one backup and reports progress.
func (r *Restic) Backup(ctx context.Context, repo *Repo, a ResticBackup, progress func(Progress)) (*Summary, error) {
	args := []string{"backup", "--json", "--host", Host, "--tag", "hardyos"}
	for _, t := range a.Tags {
		if !tagRE.MatchString(t) {
			return nil, fmt.Errorf("bad tag %q", t)
		}
		args = append(args, "--tag", t)
	}
	switch {
	case a.Stdin != nil:
		if !stdinNameRE.MatchString(a.StdinName) {
			return nil, fmt.Errorf("bad stream name %q", a.StdinName)
		}
		args = append(args, "--stdin", "--stdin-filename", a.StdinName)
	case strings.HasPrefix(a.Path, "/") && !strings.Contains(a.Path, "..") && !strings.HasPrefix(a.Path, "-"):
		for _, x := range a.Excludes {
			if !excludeRE.MatchString(x) {
				return nil, fmt.Errorf("bad exclude %q", x)
			}
			args = append(args, "--exclude", x)
		}
		args = append(args, "--one-file-system", "--", a.Path)
	default:
		return nil, fmt.Errorf("nothing to back up")
	}
	var sum *Summary
	var lerr error
	caps, readable := capsRead, []string{a.Path}
	if a.Stdin != nil {
		caps, readable = capsNone, nil
	}
	_, err := r.run(ctx, repo, call{args: args, stdin: a.Stdin, limit: true, caps: caps, readable: readable, lines: func(l []byte) {
		var m struct {
			Type       string  `json:"message_type"`
			Percent    float64 `json:"percent_done"`
			BytesDone  int64   `json:"bytes_done"`
			TotalBytes int64   `json:"total_bytes"`
			FilesDone  int64   `json:"files_done"`
			Error      struct {
				Message string `json:"message"`
			} `json:"error"`
			Item string `json:"item"`
		}
		if json.Unmarshal(l, &m) != nil {
			return
		}
		switch m.Type {
		case "status":
			if progress != nil {
				progress(Progress{Percent: m.Percent, BytesDone: m.BytesDone, TotalBytes: m.TotalBytes, FilesDone: m.FilesDone})
			}
		case "summary":
			var s Summary
			if json.Unmarshal(l, &s) == nil {
				sum = &s
			}
		case "error":
			lerr = fmt.Errorf("%s: %s", m.Item, m.Error.Message)
		}
	}})
	var re *RunError
	if errors.As(err, &re) && re.Code == exitPartial && sum != nil {
		// Some files couldn't be read; the snapshot exists without them.
		sum.ErrorsReported = 1
		if lerr != nil {
			return sum, fmt.Errorf("some files couldn't be read (%v)", lerr)
		}
		return sum, errors.New("some files couldn't be read")
	}
	if err != nil {
		return nil, err
	}
	if sum == nil || !snapIDRE.MatchString(sum.SnapshotID) {
		return nil, errors.New("restic didn't report the snapshot it made")
	}
	return sum, nil
}

var snapIDRE = regexp.MustCompile(`^[0-9a-f]{8,64}$`)

// Snapshot is one restic snapshot.
type Snapshot struct {
	ID      string    `json:"id"`
	ShortID string    `json:"short_id"`
	Time    time.Time `json:"time"`
	Paths   []string  `json:"paths"`
	Tags    []string  `json:"tags"`
	Host    string    `json:"hostname"`
	Summary *struct {
		TotalBytes int64 `json:"total_bytes_processed"`
		TotalFiles int64 `json:"total_files_processed"`
		DataAdded  int64 `json:"data_added"`
	} `json:"summary,omitempty"`
}

// Tag returns a key=value tag's value.
func (s *Snapshot) Tag(key string) string {
	for _, t := range s.Tags {
		if v, ok := strings.CutPrefix(t, key+"="); ok {
			return v
		}
	}
	return ""
}

// Snapshots lists HardyOS's snapshots in the repository.
func (r *Restic) Snapshots(ctx context.Context, repo *Repo) ([]Snapshot, error) {
	out, err := r.run(ctx, repo, call{args: []string{"snapshots", "--json", "--no-lock", "--tag", "hardyos"}})
	if err != nil {
		return nil, err
	}
	var l []Snapshot
	if err := json.Unmarshal(out, &l); err != nil {
		return nil, fmt.Errorf("reading the repository's snapshots: %w", err)
	}
	ok := l[:0]
	for _, s := range l {
		if snapIDRE.MatchString(s.ID) {
			ok = append(ok, s)
		}
	}
	return ok, nil
}

// Node is an entry in a snapshot.
type Node struct {
	Name    string    `json:"name"`
	Type    string    `json:"type"` // file, dir, symlink, ...
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	Mode    uint32    `json:"mode"`
	UID     int       `json:"uid"`
	GID     int       `json:"gid"`
	ModTime time.Time `json:"mtime"`
}

// Ls lists one folder of a snapshot (not recursive).
func (r *Restic) Ls(ctx context.Context, repo *Repo, snap, dir string) ([]Node, error) {
	if !snapIDRE.MatchString(snap) || !strings.HasPrefix(dir, "/") || strings.Contains(dir, "\x00") {
		return nil, fmt.Errorf("bad listing")
	}
	out, err := r.run(ctx, repo, call{args: []string{"ls", "--json", "--no-lock", snap, "--", dir}})
	if err != nil {
		return nil, err
	}
	var nodes []Node
	for _, line := range bytes.Split(out, []byte("\n")) {
		var n struct {
			Node
			StructType string `json:"struct_type"`
			MessageTyp string `json:"message_type"`
		}
		if len(bytes.TrimSpace(line)) == 0 || json.Unmarshal(line, &n) != nil {
			continue
		}
		if n.StructType != "node" && n.MessageTyp != "node" {
			continue
		}
		if n.Path == dir || parentOf(n.Path) != strings.TrimSuffix(dir, "/") {
			continue
		}
		nodes = append(nodes, n.Node)
	}
	return nodes, nil
}

func parentOf(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return ""
	}
	return p[:i]
}

// Restore restores snap (its folder src and below, or everything with its
// full paths when src is "") into target, which must be an empty folder
// only root can reach. includes, when given, are the paths to restore
// (relative to src, or absolute without it).
func (r *Restic) Restore(ctx context.Context, repo *Repo, snap, src, target string, includes []string, progress func(Progress)) error {
	if !snapIDRE.MatchString(snap) || (src != "" && !strings.HasPrefix(src, "/")) || !strings.HasPrefix(target, "/") {
		return fmt.Errorf("bad restore")
	}
	args := []string{"restore", "--json", "--target", target}
	for _, inc := range includes {
		if !strings.HasPrefix(inc, "/") || strings.Contains(inc, "\x00") {
			return fmt.Errorf("bad include %q", inc)
		}
		// Patterns: escape glob characters so names match literally.
		args = append(args, "--include", globEscape(inc))
	}
	what := snap
	if src != "" {
		what += ":" + src
	}
	args = append(args, "--", what)
	_, err := r.run(ctx, repo, call{args: args, limit: true, writable: []string{target}, caps: capsRestore, lines: func(l []byte) {
		var m struct {
			Type       string  `json:"message_type"`
			Percent    float64 `json:"percent_done"`
			BytesDone  int64   `json:"bytes_restored"`
			TotalBytes int64   `json:"total_bytes"`
		}
		if progress != nil && json.Unmarshal(l, &m) == nil && m.Type == "status" {
			progress(Progress{Percent: m.Percent, BytesDone: m.BytesDone, TotalBytes: m.TotalBytes})
		}
	}})
	return err
}

func globEscape(s string) string {
	var b strings.Builder
	for _, c := range s {
		if strings.ContainsRune(`*?[]\`, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// Dump writes one file of a snapshot to w.
func (r *Restic) Dump(ctx context.Context, repo *Repo, snap, file string, w io.Writer) error {
	if !snapIDRE.MatchString(snap) || !strings.HasPrefix(file, "/") {
		return fmt.Errorf("bad dump")
	}
	_, err := r.run(ctx, repo, call{args: []string{"dump", "--no-lock", snap, "--", file}, stdout: w, limit: true})
	return err
}

// Retention is how many versions a task keeps.
type Retention struct {
	Daily   int `json:"daily"`
	Weekly  int `json:"weekly"`
	Monthly int `json:"monthly"`
}

// DefaultRetention is 7 daily, 4 weekly, 12 monthly.
var DefaultRetention = Retention{Daily: 7, Weekly: 4, Monthly: 12}

// Check validates a retention policy.
func (rt Retention) Check() error {
	for _, n := range []int{rt.Daily, rt.Weekly, rt.Monthly} {
		if n < 0 || n > 1000 {
			return problemf("keep 0-1000 daily, weekly and monthly versions")
		}
	}
	if rt.Daily+rt.Weekly+rt.Monthly == 0 {
		return problemf("keep at least one version")
	}
	return nil
}

// Forget applies a task's retention to its snapshots (each item's on its
// own: grouped by path). Space comes back at the next prune.
func (r *Restic) Forget(ctx context.Context, repo *Repo, task string, rt Retention) error {
	if ValidID(task) != nil || rt.Check() != nil {
		return fmt.Errorf("bad retention")
	}
	_, err := r.run(ctx, repo, call{args: []string{"forget", "--tag", "task=" + task, "--group-by", "paths",
		"--keep-daily", strconv.Itoa(rt.Daily), "--keep-weekly", strconv.Itoa(rt.Weekly), "--keep-monthly", strconv.Itoa(rt.Monthly)}})
	return err
}

// ForgetSnapshots removes the given snapshots (a failed run's leftovers).
func (r *Restic) ForgetSnapshots(ctx context.Context, repo *Repo, ids []string) error {
	args := []string{"forget"}
	for _, id := range ids {
		if !snapIDRE.MatchString(id) {
			return fmt.Errorf("bad snapshot id")
		}
		args = append(args, id)
	}
	if len(ids) == 0 {
		return nil
	}
	_, err := r.run(ctx, repo, call{args: args})
	return err
}

// Prune removes data no snapshot needs any more.
func (r *Restic) Prune(ctx context.Context, repo *Repo) error {
	_, err := r.run(ctx, repo, call{args: []string{"prune"}, limit: true})
	return err
}

// Check verifies the repository's structure and reads back percent% of its
// data (0: structure only).
func (r *Restic) Check(ctx context.Context, repo *Repo, percent int) error {
	args := []string{"check"}
	if percent > 0 {
		if percent > 100 {
			percent = 100
		}
		args = append(args, "--read-data-subset", strconv.Itoa(percent)+"%")
	}
	_, err := r.run(ctx, repo, call{args: args, limit: true})
	return err
}
