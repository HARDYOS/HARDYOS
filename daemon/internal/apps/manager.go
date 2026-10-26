package apps

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Layout of an installed app, all inside its own dataset <pool>/apps/<id>:
//
//	<mountpoint>/.hardyos/      root only (0700): never mounted into a container
//	  hardyapp.json             the manifest
//	  compose.yaml              the compose file as packaged
//	  compose.json              the checked, resolved compose file that runs
//	  app.env                   HardyOS variables, settings and generated secrets (0600)
//	  state.json                ports, non-secret settings, dates
//	  icon.svg / icon.png
//	<mountpoint>/data/          ${HARDY_APP_DATA}: the only place apps can mount
//
// Docker itself keeps images and containers in <pool>/docker, so they
// survive OS updates (each update is a new boot environment).
const (
	DefaultStateDir = "/var/lib/hardyos/apps"
	DaemonJSON      = "/etc/docker/daemon.json"
	metaDir         = ".hardyos"
	dataDirName     = "data"
	engineFile      = "engine.json"
	stateFile       = "state.json"
	envFile         = "app.env"
	resolvedFile    = "compose.json"
	maxLogBytes     = 512 << 10
)

// ErrNotInstalled means no app has that id.
var ErrNotInstalled = errors.New("that app isn't installed")

// ErrNoEngine means apps haven't been set up on a pool yet.
var ErrNoEngine = errors.New("apps aren't set up yet: install an app to choose the pool they live on")

// reservedPorts are used by HardyOS itself or by services it runs.
var reservedPorts = map[int]bool{
	1080: true, 2049: true, 3260: true, 3268: true, 3269: true, 5353: true, 8443: true,
}

// Manager installs and runs apps. It runs inside hardyd-priv (root).
type Manager struct {
	Runner sysexec.Runner
	Log    *slog.Logger
	// Root prefixes system paths (/etc, /var/lib/hardyos); "/" in
	// production. App folders come from ZFS mountpoints and are used as-is.
	Root string
	// StateDir overrides DefaultStateDir (tests).
	StateDir string
	// MemTotal reports the server's memory in bytes (tests can fake it).
	MemTotal func() uint64
	// Shares resolves and grants shared folders (nil: apps get none).
	Shares ShareResolver

	mu sync.Mutex // installs and removals, one at a time

	composeMu sync.Mutex
	compose   []string

	// clock replaces time.Now in tests.
	clock func() time.Time
}

func (m *Manager) now() time.Time {
	if m.clock != nil {
		return m.clock().UTC()
	}
	return time.Now().UTC()
}

// EngineConfig is where Docker keeps its data (written by root).
type EngineConfig struct {
	Pool     string `json:"pool"`
	Dataset  string `json:"dataset"`  // <pool>/docker
	DataRoot string `json:"dataRoot"` // its mountpoint
}

// Overview is what the App Store shows.
type Overview struct {
	// Available is false when this build has no Docker.
	Available     bool          `json:"available"`
	Configured    bool          `json:"configured"`
	Pool          string        `json:"pool"`
	EngineRunning bool          `json:"engineRunning"`
	EngineVersion string        `json:"engineVersion"`
	Problem       string        `json:"problem"`
	Apps          []App         `json:"apps"`
	KeptData      []KeptAppData `json:"keptData"`
}

// App is an installed app and how it's doing.
type App struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	Summary     string      `json:"summary"`
	Publisher   string      `json:"publisher"`
	Website     string      `json:"website"`
	Icon        string      `json:"icon"`
	Dataset     string      `json:"dataset"`
	State       string      `json:"state"` // running, starting, unhealthy, partial, stopped, restarting, not-created
	Containers  []Container `json:"containers"`
	Ports       []AppPort   `json:"ports"`
	Web         *AppWeb     `json:"web"`
	InstalledAt time.Time   `json:"installedAt"`
	UpdatedAt   time.Time   `json:"updatedAt"`

	Source      Source     `json:"source"`
	SourceName  string     `json:"sourceName"`
	UID         int        `json:"uid"`
	Shares      []AppShare `json:"shares"`
	Grants      []string   `json:"grants"`
	Limits      Limits     `json:"limits"`
	Permissions []string   `json:"permissions"`
}

// Container is one service's container.
type Container struct {
	Service string `json:"service"`
	State   string `json:"state"`  // running, exited, restarting, created, paused, dead
	Health  string `json:"health"` // healthy, unhealthy, starting, "" (no health check)
	Status  string `json:"status"` // Docker's own words, e.g. "Up 3 minutes (healthy)"
	Image   string `json:"image"`
}

// AppPort is a port an app publishes on the server.
type AppPort struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// AppWeb is the app's web page.
type AppWeb struct {
	Port   int    `json:"port"`
	Path   string `json:"path"`
	Scheme string `json:"scheme"`
}

// KeptAppData is an app removed without deleting its data; installing it
// again picks the data (and its passwords) back up.
type KeptAppData struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Dataset string `json:"dataset"`
}

// appState is state.json.
type appState struct {
	ID          string            `json:"id"`
	Version     string            `json:"version"`
	Host        string            `json:"host"`
	Ports       map[string]int    `json:"ports"`
	Settings    map[string]string `json:"settings"`
	Icon        string            `json:"icon,omitempty"`
	InstalledAt time.Time         `json:"installedAt"`
	UpdatedAt   time.Time         `json:"updatedAt"`
	Removed     bool              `json:"removed,omitempty"`

	Source     Source                 `json:"source,omitempty"`
	SourceName string                 `json:"sourceName,omitempty"`
	UID        int                    `json:"uid,omitempty"` // also the GID
	Shares     map[string]ShareChoice `json:"shares,omitempty"`
	Grants     []string               `json:"grants,omitempty"`
	Limits     Limits                 `json:"limits"`
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func (m *Manager) root() string {
	if m.Root == "" {
		return "/"
	}
	return m.Root
}

func (m *Manager) sys(p string) string { return filepath.Join(m.root(), p) }

func (m *Manager) stateDir() string {
	if m.StateDir != "" {
		return m.StateDir
	}
	return m.sys(DefaultStateDir)
}

func (m *Manager) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return sysexec.Output(ctx, m.Runner, name, args...)
}

// composeCmd finds Docker Compose: the docker CLI plugin, or the standalone
// docker-compose binary.
func (m *Manager) composeCmd(ctx context.Context) ([]string, error) {
	m.composeMu.Lock()
	defer m.composeMu.Unlock()
	if m.compose != nil {
		return m.compose, nil
	}
	if _, err := m.run(ctx, "docker", "compose", "version"); err == nil {
		m.compose = []string{"docker", "compose"}
	} else if _, err2 := m.run(ctx, "docker-compose", "version"); err2 == nil {
		m.compose = []string{"docker-compose"}
	} else {
		return nil, fmt.Errorf("Docker Compose isn't installed: %v", err)
	}
	return m.compose, nil
}

func (m *Manager) runCompose(ctx context.Context, args ...string) ([]byte, error) {
	cmd, err := m.composeCmd(ctx)
	if err != nil {
		return nil, err
	}
	return m.run(ctx, cmd[0], append(append([]string{}, cmd[1:]...), args...)...)
}

// ---- the Docker engine -----------------------------------------------------

// Available reports whether Docker is installed.
func (m *Manager) Available() bool {
	_, err := os.Stat(m.sys("/usr/bin/docker"))
	return err == nil
}

func (m *Manager) engine() (*EngineConfig, error) {
	b, err := rootfile.ReadFile(filepath.Join(m.stateDir(), engineFile))
	if rootfile.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c EngineConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", engineFile, err)
	}
	if zfs.ValidPoolName(c.Pool) != nil || c.Dataset != c.Pool+"/docker" || !filepath.IsAbs(c.DataRoot) {
		return nil, fmt.Errorf("%s names an invalid pool", engineFile)
	}
	return &c, nil
}

func (m *Manager) mountpoint(ctx context.Context, ds string) (string, bool, error) {
	out, err := m.run(ctx, "zfs", "get", "-Hp", "-o", "value", "mountpoint,mounted", ds)
	if err != nil {
		return "", false, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		return "", false, fmt.Errorf("zfs get %s: unexpected output", ds)
	}
	mp := strings.TrimSpace(lines[0])
	if !filepath.IsAbs(mp) {
		return "", false, fmt.Errorf("%s has no mountpoint", ds)
	}
	return mp, strings.TrimSpace(lines[1]) == "yes", nil
}

func (m *Manager) datasetExists(ctx context.Context, ds string) bool {
	_, err := m.run(ctx, "zfs", "list", "-H", "-o", "name", ds)
	return err == nil
}

// setupEngine puts Docker's storage on pool (first app install).
func (m *Manager) setupEngine(ctx context.Context, pool string) (*EngineConfig, error) {
	if err := zfs.ValidPoolName(pool); err != nil {
		return nil, Problems{err.Error()}
	}
	if !m.datasetExists(ctx, pool) {
		return nil, Problems{fmt.Sprintf("there's no pool called %s", pool)}
	}
	for _, ds := range []string{pool + "/apps", pool + "/docker"} {
		if m.datasetExists(ctx, ds) {
			continue
		}
		// Docker's layers change all the time and can be downloaded again:
		// no automatic snapshots there.
		args := []string{"create", "-o", "org.hardyos:role=" + filepath.Base(ds)}
		if strings.HasSuffix(ds, "/docker") {
			args = append(args, "-o", "com.sun:auto-snapshot=false")
		}
		if _, err := m.run(ctx, "zfs", append(args, ds)...); err != nil {
			return nil, fmt.Errorf("creating %s: %w", ds, err)
		}
	}
	mp, mounted, err := m.mountpoint(ctx, pool+"/docker")
	if err != nil {
		return nil, err
	}
	if !mounted {
		return nil, fmt.Errorf("%s/docker isn't mounted", pool)
	}
	c := &EngineConfig{Pool: pool, Dataset: pool + "/docker", DataRoot: mp}
	b, _ := json.MarshalIndent(c, "", "  ")
	if err := os.MkdirAll(m.stateDir(), 0o700); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(filepath.Join(m.stateDir(), engineFile), b, 0o600); err != nil {
		return nil, err
	}
	return c, m.startEngine(ctx, c)
}

// startEngine points Docker at the pool and starts it. Docker is off at
// boot; hardyd-priv starts it here once the pool is mounted.
func (m *Manager) startEngine(ctx context.Context, c *EngineConfig) error {
	want, _ := json.MarshalIndent(map[string]any{
		"data-root":  c.DataRoot,
		"log-driver": "local",
		"log-opts":   map[string]string{"max-size": "10m", "max-file": "3"},
	}, "", "  ")
	want = append(want, '\n')
	path := m.sys(DaemonJSON)
	old, _ := os.ReadFile(path)
	changed := !bytes.Equal(old, want)
	if changed {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := writeFileAtomic(path, want, 0o644); err != nil {
			return err
		}
	}
	verb := "start"
	if changed {
		verb = "restart"
	}
	if _, err := m.run(ctx, "systemctl", verb, "docker.service"); err != nil {
		return fmt.Errorf("starting Docker: %w", err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		if _, err := m.run(ctx, "docker", "info", "--format", "{{.ServerVersion}}"); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("Docker didn't start within a minute")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// OnStart starts Docker at boot once its pool is mounted. Containers come
// back by themselves (restart policy unless-stopped).
func (m *Manager) OnStart(ctx context.Context) {
	c, err := m.engine()
	if err != nil {
		m.log().Warn("apps: engine settings unreadable", "err", err)
		return
	}
	if c == nil || !m.Available() {
		return
	}
	for i := 0; ; i++ {
		_, mounted, err := m.mountpoint(ctx, c.Dataset)
		if err == nil && mounted {
			break
		}
		if i == 60 {
			m.log().Warn("apps: Docker's dataset isn't mounted; apps stay off", "dataset", c.Dataset, "err", err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
	// The apps' slices live in /run: put them back before Docker restarts
	// the containers, so their limits hold from the first moment.
	if apps, err := m.installed(ctx, c); err == nil {
		for _, ia := range apps {
			if ia.state.Removed {
				continue
			}
			if err := m.writeSlice(ctx, ia.state.ID, ia.state.Limits); err != nil {
				m.log().Warn("apps: writing an app's slice failed", "app", ia.state.ID, "err", err)
			}
		}
	}
	if err := m.startEngine(ctx, c); err != nil {
		m.log().Warn("apps: starting Docker failed", "err", err)
		return
	}
	m.log().Info("apps: Docker started", "pool", c.Pool)
}

// ---- status ----------------------------------------------------------------

// Status lists the installed apps.
func (m *Manager) Status(ctx context.Context) (*Overview, error) {
	o := &Overview{Available: m.Available(), Apps: []App{}, KeptData: []KeptAppData{}}
	if !o.Available {
		return o, nil
	}
	c, err := m.engine()
	if err != nil {
		o.Problem = err.Error()
		return o, nil
	}
	if c == nil {
		return o, nil
	}
	o.Configured, o.Pool = true, c.Pool
	if out, err := m.run(ctx, "docker", "info", "--format", "{{.ServerVersion}}|{{.DockerRootDir}}"); err == nil {
		o.EngineRunning = true
		ver, rootDir, _ := strings.Cut(strings.TrimSpace(string(out)), "|")
		o.EngineVersion = ver
		if filepath.Clean(rootDir) != filepath.Clean(c.DataRoot) {
			o.Problem = fmt.Sprintf("Docker is using %s instead of %s; restart the server so apps keep their images on the pool", rootDir, c.DataRoot)
		}
	} else {
		o.Problem = "Docker isn't running"
	}

	containers := map[string][]Container{}
	if o.EngineRunning {
		containers = m.containers(ctx)
	}
	installed, err := m.installed(ctx, c)
	if err != nil {
		o.Problem = fmt.Sprintf("can't read the apps on %s: %v", c.Pool, err)
		return o, nil
	}
	for _, ia := range installed {
		if ia.state.Removed {
			o.KeptData = append(o.KeptData, KeptAppData{ID: ia.state.ID, Name: ia.manifest.Name, Dataset: ia.dataset})
			continue
		}
		o.Apps = append(o.Apps, ia.view(containers[ia.state.ID], o.EngineRunning))
	}
	return o, nil
}

type installedApp struct {
	dataset  string
	dir      string
	manifest Manifest
	state    appState
	icon     []byte
}

func (ia *installedApp) meta(name string) string { return filepath.Join(ia.dir, metaDir, name) }

func (ia *installedApp) view(cs []Container, engine bool) App {
	mf := ia.manifest
	a := App{
		ID: mf.ID, Name: mf.Name, Version: mf.Version, Summary: mf.Summary, Publisher: mf.Publisher,
		Website: mf.Website, Icon: IconDataURL(ia.state.Icon, ia.icon), Dataset: ia.dataset,
		Containers: cs, Ports: []AppPort{}, InstalledAt: ia.state.InstalledAt, UpdatedAt: ia.state.UpdatedAt,
	}
	if a.Containers == nil {
		a.Containers = []Container{}
	}
	for _, p := range mf.Ports {
		proto := p.Protocol
		if proto == "" {
			proto = "tcp"
		}
		a.Ports = append(a.Ports, AppPort{Name: p.Name, Label: p.Label, Port: ia.state.Ports[p.Name], Protocol: proto})
	}
	if mf.Web != nil {
		w := &AppWeb{Port: ia.state.Ports[mf.Web.Port], Path: mf.Web.Path, Scheme: mf.Web.Scheme}
		if w.Path == "" {
			w.Path = "/"
		}
		if w.Scheme == "" {
			w.Scheme = "http"
		}
		a.Web = w
	}
	a.State = summarize(a.Containers, engine)
	a.Source = ia.state.Source
	if a.Source == "" {
		a.Source = SourceCatalog
	}
	a.SourceName = ia.state.SourceName
	a.UID = ia.state.UID
	a.Shares = ia.shares()
	a.Grants = append([]string{}, ia.state.Grants...)
	a.Limits = ia.state.Limits
	a.Permissions = DescribePermissions(mf)
	return a
}

// shares lists every share the manifest declares and what the app has for
// it (Share "" means none: it gets an empty folder of its own).
func (ia *installedApp) shares() []AppShare {
	out := []AppShare{}
	for _, s := range ia.manifest.Shares {
		ch := ia.state.Shares[s.Name]
		as := AppShare{Name: s.Name, Label: s.Label, Share: ch.Share, Path: ch.Path, Access: ch.Access}
		if as.Access == "" {
			as.Access = s.Access
		}
		out = append(out, as)
	}
	return out
}

// summarize turns container states into one word for the app.
func summarize(cs []Container, engine bool) string {
	if !engine {
		return "stopped"
	}
	if len(cs) == 0 {
		return "not-created"
	}
	running, exited := 0, 0
	for _, c := range cs {
		switch c.State {
		case "running":
			running++
		case "restarting":
			return "restarting"
		case "exited", "dead", "created":
			exited++
		}
	}
	switch {
	case running == len(cs):
		for _, c := range cs {
			if c.Health == "unhealthy" {
				return "unhealthy"
			}
		}
		for _, c := range cs {
			if c.Health == "starting" {
				return "starting"
			}
		}
		return "running"
	case running == 0:
		return "stopped"
	default:
		return "partial"
	}
}

// containers lists every HardyOS app container in one call.
func (m *Manager) containers(ctx context.Context) map[string][]Container {
	out, err := m.run(ctx, "docker", "ps", "-a", "--filter", "label=org.hardyos.app", "--format", "{{json .}}")
	res := map[string][]Container{}
	if err != nil {
		return res
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var row struct {
			Labels string `json:"Labels"`
			State  string `json:"State"`
			Status string `json:"Status"`
			Image  string `json:"Image"`
		}
		if json.Unmarshal(sc.Bytes(), &row) != nil {
			continue
		}
		labels := map[string]string{}
		for _, kv := range strings.Split(row.Labels, ",") {
			k, v, _ := strings.Cut(kv, "=")
			labels[k] = v
		}
		id := labels["org.hardyos.app"]
		if id == "" {
			continue
		}
		c := Container{Service: labels["com.docker.compose.service"], State: strings.ToLower(row.State), Status: row.Status, Image: row.Image}
		switch {
		case strings.Contains(row.Status, "(healthy)"):
			c.Health = "healthy"
		case strings.Contains(row.Status, "(unhealthy)"):
			c.Health = "unhealthy"
		case strings.Contains(row.Status, "health: starting"):
			c.Health = "starting"
		}
		res[id] = append(res[id], c)
	}
	for id := range res {
		sort.Slice(res[id], func(i, j int) bool { return res[id][i].Service < res[id][j].Service })
	}
	return res
}

// installed reads every app on the engine's pool.
func (m *Manager) installed(ctx context.Context, c *EngineConfig) ([]*installedApp, error) {
	out, err := m.run(ctx, "zfs", "list", "-H", "-o", "name", "-d", "1", "-t", "filesystem", c.Pool+"/apps")
	if err != nil {
		return nil, fmt.Errorf("listing apps: %w", err)
	}
	var res []*installedApp
	for _, ds := range strings.Fields(string(out)) {
		id := strings.TrimPrefix(ds, c.Pool+"/apps/")
		if ds == c.Pool+"/apps" || ValidID(id) != nil {
			continue
		}
		ia, err := m.load(ctx, c, id)
		if err != nil {
			if !errors.Is(err, ErrNotInstalled) {
				m.log().Warn("apps: skipping an app that can't be read", "dataset", ds, "err", err)
			}
			continue
		}
		res = append(res, ia)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].manifest.Name < res[j].manifest.Name })
	return res, nil
}

func (m *Manager) load(ctx context.Context, c *EngineConfig, id string) (*installedApp, error) {
	if err := ValidID(id); err != nil {
		return nil, Problems{err.Error()}
	}
	ds := c.Pool + "/apps/" + id
	if !m.datasetExists(ctx, ds) {
		return nil, ErrNotInstalled
	}
	dir, _, err := m.mountpoint(ctx, ds)
	if err != nil {
		return nil, err
	}
	ia := &installedApp{dataset: ds, dir: dir}
	sb, err := os.ReadFile(ia.meta(stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotInstalled
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(sb, &ia.state); err != nil {
		return nil, err
	}
	mb, err := os.ReadFile(ia.meta(ManifestFile))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(mb, &ia.manifest); err != nil {
		return nil, err
	}
	if ia.state.Icon != "" && filepath.Base(ia.state.Icon) == ia.state.Icon {
		ia.icon, _ = os.ReadFile(ia.meta(ia.state.Icon))
	}
	return ia, nil
}

// ---- install -----------------------------------------------------------------

// PrepareArgs installs (or reinstalls, or upgrades) an app up to the point
// where its images need downloading.
type PrepareArgs struct {
	Package []byte `json:"package"`
	// Pool for Docker and the apps, the first time; ignored afterwards.
	Pool string `json:"pool,omitempty"`
	// Host is the server's name or address as people reach it (for links
	// the app builds). Empty on an update keeps the current one.
	Host     string            `json:"host"`
	Ports    map[string]int    `json:"ports,omitempty"`
	Settings map[string]string `json:"settings,omitempty"`
	// Source is where the package came from (see contract.go); it decides
	// which permissions need explicit grants.
	Source     Source                 `json:"source,omitempty"`
	SourceName string                 `json:"sourceName,omitempty"`
	Shares     map[string]ShareChoice `json:"shares,omitempty"`
	Grants     []string               `json:"grants,omitempty"`
	Limits     *Limits                `json:"limits,omitempty"`
}

// PrepareResult tells the install job what to download next.
type PrepareResult struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Services []ServiceImage `json:"services"`
	Upgrade  bool           `json:"upgrade"`
	Warnings []string       `json:"warnings"`
}

// Prepare checks the package and request, creates the app's dataset and
// files, and checks the resolved compose file against the policy.
func (m *Manager) Prepare(ctx context.Context, a PrepareArgs) (*PrepareResult, error) {
	if !m.Available() {
		return nil, errors.New("this HardyOS build doesn't include Docker")
	}
	pkg, err := ReadPackage(a.Package)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.prepare(ctx, pkg, a, false)
}

// prepare does Prepare's work with m.mu held. reconfigure: the package is
// the installed one and the app keeps its source.
func (m *Manager) prepare(ctx context.Context, pkg *Package, a PrepareArgs, reconfigure bool) (*PrepareResult, error) {
	mf := pkg.Manifest
	res := &PrepareResult{ID: mf.ID, Name: mf.Name, Warnings: []string{}}
	if len(mf.Arch) > 0 && !contains(mf.Arch, runtime.GOARCH) {
		return nil, Problems{fmt.Sprintf("%s doesn't run on this server's processor (%s)", mf.Name, runtime.GOARCH)}
	}
	if mf.MinMemoryMB > 0 {
		if have := m.memTotal() >> 20; have > 0 && uint64(mf.MinMemoryMB) > have {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s needs %d MB of memory; this server has %d MB", mf.Name, mf.MinMemoryMB, have))
		}
	}

	c, err := m.engine()
	if err != nil {
		return nil, err
	}
	if c == nil {
		if reconfigure {
			return nil, ErrNoEngine
		}
		if a.Pool == "" {
			return nil, Problems{"choose the pool for apps"}
		}
		if c, err = m.setupEngine(ctx, a.Pool); err != nil {
			return nil, err
		}
	} else if err := m.startEngine(ctx, c); err != nil {
		return nil, err
	}

	ds := c.Pool + "/apps/" + mf.ID
	var prev *installedApp
	if m.datasetExists(ctx, ds) {
		if prev, err = m.load(ctx, c, mf.ID); err != nil && !errors.Is(err, ErrNotInstalled) {
			return nil, err
		}
	} else if reconfigure {
		return nil, ErrNotInstalled
	} else if _, err := m.run(ctx, "zfs", "create", ds); err != nil {
		return nil, fmt.Errorf("creating %s: %w", ds, err)
	}
	if reconfigure && (prev == nil || prev.state.Removed) {
		return nil, ErrNotInstalled
	}
	res.Upgrade = prev != nil && !prev.state.Removed
	// What a live install carries over when the request leaves it out.
	var live *installedApp
	if res.Upgrade {
		live = prev
	}

	// Where the package came from decides which permissions need grants.
	src, srcName, err := chooseSource(a, live, reconfigure)
	if err != nil {
		return nil, err
	}
	askedGrants := a.Grants
	if askedGrants == nil && live != nil {
		askedGrants = live.state.Grants
	}
	grants, err := checkGrants(mf, src, askedGrants)
	if err != nil {
		return nil, err
	}
	limits := Limits{}
	if prev != nil {
		limits = prev.state.Limits
	}
	if a.Limits != nil {
		limits = *a.Limits
	}
	if err := m.checkLimits(limits); err != nil {
		return nil, err
	}

	// An update without a host keeps the one the app was installed with.
	hostArg := a.Host
	if hostArg == "" && prev != nil {
		hostArg = prev.state.Host
	}
	host, err := normalizeHost(hostArg)
	if err != nil {
		return nil, Problems{err.Error()}
	}
	dir, mounted, err := m.mountpoint(ctx, ds)
	if err != nil {
		return nil, err
	}
	if !mounted {
		return nil, fmt.Errorf("%s isn't mounted", ds)
	}
	meta := filepath.Join(dir, metaDir)
	dataDir := filepath.Join(dir, dataDirName)
	if err := mkdirStrict(dir, metaDir, 0o700, -1, -1); err != nil {
		return nil, err
	}
	if err := mkdirStrict(dir, dataDirName, 0o755, -1, -1); err != nil {
		return nil, err
	}

	// The app's own user: kept for as long as its data is.
	uid, err := m.allocUID(ctx, c, prev)
	if err != nil {
		return nil, err
	}

	// Ports: as asked, each free (the app's own current ports count as free).
	var prevPorts map[string]int
	if prev != nil {
		prevPorts = prev.state.Ports
	}
	ports, err := m.choosePorts(ctx, mf, a.Ports, prevPorts)
	if err != nil {
		return nil, err
	}

	// Shared folders: as asked, else as before.
	var prevShares map[string]ShareChoice
	if live != nil {
		prevShares = live.state.Shares
	}
	choices, binds, shareEnv, err := m.chooseShares(ctx, mf, a.Shares, prevShares, dataDir, res)
	if err != nil {
		return nil, err
	}

	// Settings: asked-for values, then earlier values, then defaults;
	// generated secrets are kept across reinstalls.
	oldEnv := map[string]string{}
	if b, err := os.ReadFile(filepath.Join(meta, envFile)); err == nil {
		oldEnv = parseEnv(b)
	}
	env := map[string]string{
		"HARDY_APP_ID":   mf.ID,
		"HARDY_APP_DATA": dataDir,
		"HARDY_HOST":     host,
		"HARDY_TZ":       m.timezone(),
		"HARDY_UID":      strconv.Itoa(uid),
		"HARDY_GID":      strconv.Itoa(uid),
	}
	for name, port := range ports {
		env[PortEnv(name)] = strconv.Itoa(port)
	}
	for k, v := range shareEnv {
		env[k] = v
	}
	saved := map[string]string{}
	var p Problems
	for _, s := range mf.Settings {
		v, asked := a.Settings[s.Env]
		switch {
		case s.Generate != "":
			if old := oldEnv[s.Env]; old != "" {
				v = old
			} else {
				v = randomSecret()
			}
		case asked:
		case oldEnv[s.Env] != "":
			v = oldEnv[s.Env]
		default:
			v = s.Default
		}
		if s.Generate == "" {
			if v == "" && s.Required {
				p.addf("%s is required", settingLabel(s))
				continue
			}
			if v != "" {
				if err := checkSettingValue(s, v); err != nil {
					p.addf("%s: %v", settingLabel(s), err)
					continue
				}
			}
		}
		env[s.Env] = v
		if !s.Secret() {
			saved[s.Env] = v
		}
	}
	for k := range a.Settings {
		if !hasSetting(mf, k) {
			p.addf("%s isn't one of %s's settings", k, mf.Name)
		}
	}
	if err := p.err(); err != nil {
		return nil, err
	}

	files := map[string][]byte{
		ManifestFile: mustJSON(mf),
		ComposeFile:  pkg.Compose,
		envFile:      renderEnv(env),
	}
	if mf.Icon != "" {
		files["icon"+filepath.Ext(mf.Icon)] = pkg.Icon
	}
	for name, b := range files {
		if err := writeFileAtomic(filepath.Join(meta, name), b, 0o600); err != nil {
			return nil, err
		}
	}

	// Resolve with Docker Compose, check the result, keep it as what runs.
	project := ProjectName(mf.ID)
	out, err := m.runCompose(ctx, "-p", project, "--project-directory", dataDir,
		"-f", filepath.Join(meta, ComposeFile), "--env-file", filepath.Join(meta, envFile), "config", "--format", "json")
	if err != nil {
		return nil, Problems{fmt.Sprintf("%s isn't a valid compose file: %v", ComposeFile, err)}
	}
	resolved, err := ParseResolved(out)
	if err != nil {
		return nil, err
	}
	if err := resolved.check(mf, project, dataDir, ports, binds); err != nil {
		return nil, err
	}
	// After the check: what HardyOS itself adds.
	res.Warnings = appendNew(res.Warnings, resolved.adaptGPU(m.detectGPU(), m.sys, mf.Name)...)
	resolved.setCgroupParent(SliceName(mf.ID))
	if err := writeFileAtomic(filepath.Join(meta, resolvedFile), mustJSON(resolved), 0o600); err != nil {
		return nil, err
	}

	for _, f := range mf.Folders {
		// Without an owner, folders belong to the app's own user, but only
		// when HardyOS creates them: a container may have changed the owner
		// since (a database does), and an update mustn't undo that.
		uidF, gidF := -1, -1
		if f.Owner != "" {
			u, g, _ := strings.Cut(f.Owner, ":")
			uidF, _ = strconv.Atoi(u)
			gidF, _ = strconv.Atoi(g)
		} else if _, err := os.Lstat(filepath.Join(dataDir, f.Path)); errors.Is(err, fs.ErrNotExist) {
			uidF, gidF = uid, uid
		}
		mode := os.FileMode(0o755)
		if f.Mode != "" {
			v, _ := strconv.ParseUint(f.Mode, 8, 32)
			mode = os.FileMode(v)
		}
		if err := mkdirStrict(dataDir, f.Path, mode, uidF, gidF); err != nil {
			return nil, err
		}
	}
	// Empty stand-ins for shares the app wasn't given.
	for _, s := range mf.Shares {
		if choices[s.Name].Share != "" {
			continue
		}
		if err := mkdirStrict(dataDir, unsharedDir, 0o755, -1, -1); err != nil {
			return nil, err
		}
		if err := mkdirStrict(dataDir, unsharedDir+"/"+s.Name, 0o755, uid, uid); err != nil {
			return nil, err
		}
	}

	// Shared folder access for the app's user (ACLs), changed only when the
	// choices change.
	if err := m.applyShareGrants(ctx, mf.ID, uid, prevShares, choices); err != nil {
		return nil, err
	}

	st := appState{ID: mf.ID, Version: mf.Version, Host: host, Ports: ports, Settings: saved, UpdatedAt: m.now(),
		Source: src, SourceName: srcName, UID: uid, Shares: choices, Grants: grants, Limits: limits}
	if mf.Icon != "" {
		st.Icon = "icon" + filepath.Ext(mf.Icon)
	}
	if prev != nil && !prev.state.InstalledAt.IsZero() && !prev.state.Removed {
		st.InstalledAt = prev.state.InstalledAt
	} else {
		st.InstalledAt = st.UpdatedAt
	}
	if err := writeFileAtomic(filepath.Join(meta, stateFile), mustJSON(st), 0o600); err != nil {
		return nil, err
	}
	res.Services = resolved.Services()
	m.log().Info("apps: prepared", "app", mf.ID, "version", mf.Version, "upgrade", res.Upgrade, "source", src, "uid", uid)
	return res, nil
}

func settingLabel(s Setting) string {
	if s.Label != "" {
		return s.Label
	}
	return s.Env
}

func hasSetting(mf Manifest, env string) bool {
	for _, s := range mf.Settings {
		if s.Env == env && s.Generate == "" {
			return true
		}
	}
	return false
}

func (m *Manager) memTotal() uint64 {
	if m.MemTotal != nil {
		return m.MemTotal()
	}
	b, _ := os.ReadFile(m.sys("/proc/meminfo"))
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.ParseUint(f[1], 10, 64)
			return kb << 10
		}
	}
	return 0
}

func (m *Manager) timezone() string {
	b, _ := os.ReadFile(m.sys("/etc/timezone"))
	tz := strings.TrimSpace(string(b))
	if !regexp.MustCompile(`^[A-Za-z0-9_+/-]{1,64}$`).MatchString(tz) {
		return "UTC"
	}
	return tz
}

var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}\.)*[A-Za-z0-9-]{0,62}[A-Za-z0-9]$`)

func normalizeHost(h string) (string, error) {
	h = strings.TrimSpace(strings.Trim(h, "[]"))
	if a, err := netip.ParseAddr(h); err == nil {
		if a.Is6() && !a.Is4In6() {
			return "[" + a.String() + "]", nil
		}
		return a.Unmap().String(), nil
	}
	if len(h) > 253 || !hostRE.MatchString(h) {
		return "", fmt.Errorf("server name %q isn't a host name or address", h)
	}
	return strings.ToLower(h), nil
}

// ---- ports -------------------------------------------------------------------

// PortCheck is one wanted port for SuggestPorts.
type PortCheck struct {
	Name     string `json:"name"`
	Default  int    `json:"default"`
	Protocol string `json:"protocol,omitempty"`
	// Fixed: the app can't move to another port (it uses the host
	// network), so the default comes back as is.
	Fixed bool `json:"fixed,omitempty"`
}

// SuggestPorts proposes a free host port for each wanted port: the default
// when free, else the next free one. forID's own current ports count as free.
func (m *Manager) SuggestPorts(ctx context.Context, wanted []PortCheck, forID string) (map[string]int, error) {
	used, err := m.usedPorts(ctx, forID)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, w := range wanted {
		proto := w.Protocol
		if proto == "" {
			proto = "tcp"
		}
		p := w.Default
		if w.Fixed {
			out[w.Name] = p
			continue
		}
		if p < 1024 || p > 65535 {
			p = 8000
		}
		for i := 0; i < 2000; i++ {
			key := fmt.Sprintf("%d/%s", p, proto)
			if !used[key] && !reservedPorts[p] {
				break
			}
			p++
			if p > 65535 {
				p = 10000
			}
		}
		used[fmt.Sprintf("%d/%s", p, proto)] = true
		out[w.Name] = p
	}
	return out, nil
}

// usedPorts lists ports taken by other apps or anything listening on the server.
func (m *Manager) usedPorts(ctx context.Context, exceptID string) (map[string]bool, error) {
	used := map[string]bool{}
	own := map[string]bool{}
	if c, err := m.engine(); err == nil && c != nil {
		if apps, err := m.installed(ctx, c); err == nil {
			for _, ia := range apps {
				for name, p := range ia.state.Ports {
					proto := portProto(ia.manifest, name)
					key := fmt.Sprintf("%d/%s", p, proto)
					if ia.state.ID == exceptID {
						own[key] = true
					} else if !ia.state.Removed {
						used[key] = true
					}
				}
			}
		}
	}
	out, err := m.run(ctx, "ss", "-Hlntu")
	if err != nil {
		return nil, fmt.Errorf("listing listening ports: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		proto := f[0]
		if proto != "tcp" && proto != "udp" {
			continue
		}
		addr := f[4]
		i := strings.LastIndex(addr, ":")
		if i < 0 {
			continue
		}
		key := addr[i+1:] + "/" + proto
		if !own[key] {
			used[key] = true
		}
	}
	return used, nil
}

func portProto(mf Manifest, name string) string {
	for _, p := range mf.Ports {
		if p.Name == name && p.Protocol != "" {
			return p.Protocol
		}
	}
	return "tcp"
}

func (m *Manager) choosePorts(ctx context.Context, mf Manifest, asked, prev map[string]int) (map[string]int, error) {
	used, err := m.usedPorts(ctx, mf.ID)
	if err != nil {
		return nil, err
	}
	var p Problems
	ports := map[string]int{}
	mine := map[string]bool{}
	for _, pt := range mf.Ports {
		port, ok := asked[pt.Name]
		if !ok {
			port, ok = prev[pt.Name]
		}
		if !ok {
			port = pt.Default
		}
		proto := pt.Protocol
		if proto == "" {
			proto = "tcp"
		}
		key := fmt.Sprintf("%d/%s", port, proto)
		switch {
		case mf.Permissions.HostNetwork && port != pt.Default:
			p.addf("%s: %s uses the server's network directly, so this port is fixed at %d", pt.Label, mf.Name, pt.Default)
		case port < minPort(mf.Permissions.HostNetwork) || port > 65535:
			p.addf("%s: port %d must be 1024-65535", pt.Label, port)
		case reservedPorts[port]:
			p.addf("%s: port %d is kept for HardyOS", pt.Label, port)
		case used[key]:
			p.addf("%s: port %d is already in use", pt.Label, port)
		case mine[key]:
			p.addf("%s: port %d is chosen twice", pt.Label, port)
		}
		mine[key] = true
		ports[pt.Name] = port
	}
	for k := range asked {
		found := false
		for _, pt := range mf.Ports {
			found = found || pt.Name == k
		}
		if !found {
			p.addf("%s has no port called %s", mf.Name, k)
		}
	}
	return ports, p.err()
}

// ---- running -----------------------------------------------------------------

func (m *Manager) app(ctx context.Context, id string) (*installedApp, *EngineConfig, error) {
	if err := ValidID(id); err != nil {
		return nil, nil, Problems{err.Error()}
	}
	c, err := m.engine()
	if err != nil {
		return nil, nil, err
	}
	if c == nil {
		return nil, nil, ErrNoEngine
	}
	ia, err := m.load(ctx, c, id)
	if err != nil {
		return nil, nil, err
	}
	if ia.state.Removed {
		return nil, nil, ErrNotInstalled
	}
	return ia, c, nil
}

func (m *Manager) composeArgs(ia *installedApp, args ...string) []string {
	return append([]string{"-p", ProjectName(ia.state.ID), "--project-directory", filepath.Join(ia.dir, dataDirName),
		"-f", ia.meta(resolvedFile)}, args...)
}

// resolved reads the checked compose file and makes sure every folder it
// mounts is still where it was allowed to be: no folder has been swapped
// for a symlink leading out of the app's data folder (a container can write
// in its folders), and every shared folder still resolves to the place the
// file mounts, read-only where the grant is read.
func (m *Manager) resolved(ctx context.Context, ia *installedApp) (Resolved, error) {
	b, err := os.ReadFile(ia.meta(resolvedFile))
	if err != nil {
		return nil, err
	}
	r, err := ParseResolved(b)
	if err != nil {
		return nil, err
	}
	dataDir, err := filepath.EvalSymlinks(filepath.Join(ia.dir, dataDirName))
	if err != nil {
		return nil, err
	}
	binds, err := m.currentShareBinds(ctx, ia)
	if err != nil {
		return nil, err
	}
	for _, vm := range r.bindMounts() {
		src, _ := vm["source"].(string)
		real, err := realOrParent(src)
		if err != nil {
			return nil, err
		}
		share, ok := placeOf(dataDir, binds, real)
		if !ok {
			return nil, fmt.Errorf("%s leads outside the app's data folder and shared folders (%s); refusing to start", src, real)
		}
		if share != nil && !share.Write {
			if ro, _ := vm["read_only"].(bool); !ro {
				return nil, fmt.Errorf("%s is in a shared folder %s may only read, but isn't mounted read-only; refusing to start", src, ia.manifest.Name)
			}
		}
	}
	return r, nil
}

// realOrParent resolves p's real path. A path that doesn't exist yet
// (Docker creates it) resolves through its nearest existing parent.
func realOrParent(p string) (string, error) {
	real, err := filepath.EvalSymlinks(p)
	if err == nil {
		return real, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	rest := filepath.Base(p)
	parent := filepath.Dir(p)
	for {
		if rp, err := filepath.EvalSymlinks(parent); err == nil {
			return filepath.Join(rp, rest), nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if parent == "/" || parent == "." {
			return p, nil
		}
		rest = filepath.Join(filepath.Base(parent), rest)
		parent = filepath.Dir(parent)
	}
}

// Services lists the app's services and images (for downloading them one by one).
func (m *Manager) Services(ctx context.Context, id string) ([]ServiceImage, error) {
	ia, _, err := m.app(ctx, id)
	if err != nil {
		return nil, err
	}
	r, err := m.resolved(ctx, ia)
	if err != nil {
		return nil, err
	}
	return r.Services(), nil
}

// PullResult says how getting an image went.
type PullResult struct {
	// Cached: the registry couldn't be reached, but the image is already on
	// the server, so the app keeps the version it has.
	Cached  bool   `json:"cached"`
	Message string `json:"message,omitempty"`
}

// Pull downloads one service's image, trying a few times. If the registry
// stays unreachable (down, rate limited) and the image is already here, the
// app keeps using the copy it has.
func (m *Manager) Pull(ctx context.Context, id, service string) (*PullResult, error) {
	ia, _, err := m.app(ctx, id)
	if err != nil {
		return nil, err
	}
	r, err := m.resolved(ctx, ia)
	if err != nil {
		return nil, err
	}
	image := ""
	for _, s := range r.Services() {
		if s.Service == service {
			image = s.Image
		}
	}
	if image == "" {
		return nil, Problems{fmt.Sprintf("%s has no service called %q", ia.manifest.Name, service)}
	}
	var pullErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * 5 * time.Second):
			}
		}
		if _, pullErr = m.runCompose(ctx, m.composeArgs(ia, "pull", "--quiet", service)...); pullErr == nil {
			return &PullResult{}, nil
		}
	}
	if _, err := m.run(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", image); err == nil {
		m.log().Warn("apps: couldn't download an image; using the copy on the server", "app", id, "image", image, "err", pullErr)
		return &PullResult{Cached: true, Message: fmt.Sprintf("Couldn't download %s; using the copy already on the server", image)}, nil
	}
	return nil, pullErr
}

// Up creates and starts (or updates) the app's containers.
func (m *Manager) Up(ctx context.Context, id string) error {
	ia, c, err := m.app(ctx, id)
	if err != nil {
		return err
	}
	return m.up(ctx, ia, c)
}

func (m *Manager) up(ctx context.Context, ia *installedApp, c *EngineConfig) error {
	if err := m.startEngine(ctx, c); err != nil {
		return err
	}
	if _, err := m.resolved(ctx, ia); err != nil {
		return err
	}
	if err := m.writeSlice(ctx, ia.state.ID, ia.state.Limits); err != nil {
		return err
	}
	_, err := m.runCompose(ctx, m.composeArgs(ia, "up", "-d", "--remove-orphans")...)
	return err
}

// Start starts a stopped app (recreating containers if needed).
func (m *Manager) Start(ctx context.Context, id string) error { return m.Up(ctx, id) }

// Stop stops the app's containers (they stay stopped across restarts).
func (m *Manager) Stop(ctx context.Context, id string) error {
	ia, _, err := m.app(ctx, id)
	if err != nil {
		return err
	}
	_, err = m.runCompose(ctx, m.composeArgs(ia, "stop")...)
	return err
}

// Restart restarts the app's containers.
func (m *Manager) Restart(ctx context.Context, id string) error {
	ia, _, err := m.app(ctx, id)
	if err != nil {
		return err
	}
	if _, err := m.resolved(ctx, ia); err != nil {
		return err
	}
	if err := m.writeSlice(ctx, ia.state.ID, ia.state.Limits); err != nil {
		return err
	}
	_, err = m.runCompose(ctx, m.composeArgs(ia, "restart")...)
	return err
}

// Logs returns the last lines of every container's output.
func (m *Manager) Logs(ctx context.Context, id string, lines int) (string, error) {
	ia, _, err := m.app(ctx, id)
	if err != nil {
		return "", err
	}
	if lines <= 0 || lines > 5000 {
		lines = 300
	}
	out, err := m.runCompose(ctx, m.composeArgs(ia, "logs", "--no-color", "--timestamps", "--tail", strconv.Itoa(lines))...)
	if err != nil {
		return "", err
	}
	if len(out) > maxLogBytes {
		out = out[len(out)-maxLogBytes:]
	}
	return string(ansiRE.ReplaceAll(out, nil)), nil
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// RemoveArgs removes an app.
type RemoveArgs struct {
	ID string `json:"id"`
	// Confirm repeats the app's name or id.
	Confirm string `json:"confirm"`
	// DeleteData destroys the app's dataset; otherwise its data (and
	// passwords) wait for the app to be installed again.
	DeleteData bool `json:"deleteData"`
}

// Remove stops and deletes the app's containers, and its data if asked.
// Its shared folder access goes either way; its user ID stays reserved
// while its data is kept.
func (m *Manager) Remove(ctx context.Context, a RemoveArgs) error {
	if err := ValidID(a.ID); err != nil {
		return Problems{err.Error()}
	}
	c, err := m.engine()
	if err != nil {
		return err
	}
	if c == nil {
		return ErrNoEngine
	}
	ia, err := m.load(ctx, c, a.ID)
	if err != nil {
		return err
	}
	if !confirmed(a.Confirm, ia) {
		return Problems{fmt.Sprintf("type the app's name (%s) to confirm", ia.manifest.Name)}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !ia.state.Removed {
		if _, err := m.runCompose(ctx, m.composeArgs(ia, "down", "--remove-orphans", "--volumes")...); err != nil {
			return err
		}
	}
	if m.Shares != nil {
		if err := m.Shares.RevokeApp(ctx, a.ID); err != nil {
			return fmt.Errorf("removing %s's access to shared folders: %w", ia.manifest.Name, err)
		}
	}
	if err := m.removeSlice(ctx, a.ID); err != nil {
		m.log().Warn("apps: removing the app's slice failed", "app", a.ID, "err", err)
	}
	if a.DeleteData {
		if _, err := m.run(ctx, "zfs", "destroy", "-r", ia.dataset); err != nil {
			return fmt.Errorf("deleting %s: %w", ia.dataset, err)
		}
		m.log().Info("apps: removed with its data", "app", a.ID)
		return nil
	}
	ia.state.Removed = true
	ia.state.UpdatedAt = m.now()
	m.log().Info("apps: removed, data kept", "app", a.ID)
	return writeFileAtomic(ia.meta(stateFile), mustJSON(ia.state), 0o600)
}

// confirmed reports whether a confirmation repeats the app's name or id.
func confirmed(conf string, ia *installedApp) bool {
	conf = strings.TrimSpace(conf)
	return conf != "" && (strings.EqualFold(conf, ia.manifest.Name) || conf == ia.state.ID)
}

// ---- helpers -----------------------------------------------------------------

// mkdirStrict creates base/rel one level at a time without following
// symlinks, so a link planted by a container can't redirect it. uid/gid
// below 0 leave the owner as is.
func mkdirStrict(base, rel string, mode os.FileMode, uid, gid int) error {
	cur := base
	segs := strings.Split(rel, "/")
	for i, seg := range segs {
		cur = filepath.Join(cur, seg)
		fi, err := os.Lstat(cur)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := os.Mkdir(cur, 0o755); err != nil {
				return err
			}
		case err != nil:
			return err
		case !fi.IsDir():
			return fmt.Errorf("%s exists and isn't a folder", cur)
		}
		if i == len(segs)-1 {
			if err := os.Chmod(cur, mode); err != nil {
				return err
			}
			if uid >= 0 || gid >= 0 {
				if err := os.Lchown(cur, uid, gid); err != nil && !errors.Is(err, syscall.EPERM) {
					return err
				}
			}
		}
	}
	return nil
}

func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

func randomSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// renderEnv writes KEY='value' lines (single quotes: no interpolation).
func renderEnv(env map[string]string) []byte {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b bytes.Buffer
	b.WriteString("# Written by HardyOS. Change settings in the App Store.\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s='%s'\n", k, env[k])
	}
	return b.Bytes()
}

func parseEnv(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(k, "#") || !envRE.MatchString(k) {
			continue
		}
		out[k] = strings.TrimSuffix(strings.TrimPrefix(v, "'"), "'")
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
