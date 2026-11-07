package apps

// Apps on cluster storage (Phase 8 part C, docs/plans/cluster.md section
// 6.2): the app's folder is an NFS mount of the storage server's
// <pool>/apps/<id>; Docker's data-root stays local (Backend.DockerRoot).
// The cluster starts such an app only with the placement generation its
// storage was attached under (decision 326), and its containers never
// restart by themselves: the node's reconciler restarts them in place (HA
// counts restarts), and a fenced server that boots again finds nothing
// running.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// ErrClusterPlaced: a cluster app is started and stopped by the cluster on
// the server it is placed on.
var ErrClusterPlaced = errors.New("this app is on cluster storage: the cluster starts it on the server it is placed on (Cluster › Workloads)")

// ErrGeneration: the storage attached here is of another generation.
var ErrGeneration = errors.New("this server's attachment of the app's storage is of another placement generation")

// ClusterMountRoot is where cluster app folders are mounted
// (cluster.RemoteMountRoot).
const ClusterMountRoot = "/mnt/hc"

// remote finds an app on cluster storage attached here.
func (m *Manager) remote(ctx context.Context, id string) (*installedApp, *AppStorage, error) {
	if m.Backend == nil {
		return nil, nil, ErrNotInstalled
	}
	if err := ValidID(id); err != nil {
		return nil, nil, Problems{err.Error()}
	}
	st, err := m.Backend.Locate(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if !st.Remote {
		return nil, nil, ErrNotInstalled
	}
	dir := filepath.Clean(st.Dir)
	if !filepath.IsAbs(st.Dir) || dir != st.Dir || !strings.HasPrefix(dir, ClusterMountRoot+"/") {
		return nil, nil, fmt.Errorf("the app's folder %q isn't under %s", st.Dir, ClusterMountRoot)
	}
	ia, err := m.loadDir(st.Dataset, dir)
	if err != nil {
		return nil, nil, err
	}
	if ia.state.ID != id || ia.state.Removed {
		return nil, nil, ErrNotInstalled
	}
	ia.remote = true
	return ia, st, nil
}

// clusterEngine is Docker's engine on a compute server: always local.
func (m *Manager) clusterEngine(ctx context.Context) (*EngineConfig, error) {
	if c, err := m.engine(); err == nil && c != nil {
		return c, nil
	}
	ds, dir, err := m.Backend.DockerRoot(ctx)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(dir) || strings.HasPrefix(filepath.Clean(dir), ClusterMountRoot+"/") {
		return nil, errors.New("Docker's data-root must be on this server, never on cluster storage")
	}
	pool, _, _ := strings.Cut(ds, "/")
	return &EngineConfig{Pool: pool, Dataset: ds, DataRoot: dir}, nil
}

// ClusterStartArgs starts a cluster app placed here.
type ClusterStartArgs struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation"`
	// SpecHash is the hash of the app's approved settings in the
	// replicated placement (decision 386): root starts the app only when
	// its own hash of the files on cluster storage is the same.
	SpecHash string `json:"specHash"`
}

// ErrSpecChanged: what is on cluster storage isn't what an administrator
// approved (the hash in the cluster's placement differs).
var ErrSpecChanged = errors.New("the settings on cluster storage aren't the ones an administrator approved; refusing to start")

// ClusterStart starts a cluster app whose storage is attached here under
// the generation hardyd names, only when the files on cluster storage are
// the approved ones (SpecHash) and pass the full policy check again: the
// folder is shared storage that other servers could have written.
func (m *Manager) ClusterStart(ctx context.Context, a ClusterStartArgs) error {
	ia, st, err := m.remote(ctx, a.ID)
	if err != nil {
		return err
	}
	if a.Generation == 0 || st.Generation != a.Generation {
		return fmt.Errorf("%w (attached %d, asked %d)", ErrGeneration, st.Generation, a.Generation)
	}
	h, err := m.clusterHash(ia)
	if err != nil {
		return err
	}
	if a.SpecHash == "" || subtle.ConstantTimeCompare([]byte(h), []byte(a.SpecHash)) != 1 {
		m.log().Warn("apps: refused to start a cluster app whose files changed", "app", a.ID, "have", h, "approved", a.SpecHash)
		return ErrSpecChanged
	}
	if err := m.clusterRecheck(ctx, ia); err != nil {
		return err
	}
	c, err := m.clusterEngine(ctx)
	if err != nil {
		return err
	}
	if err := m.up(ctx, ia, c); err != nil {
		return err
	}
	return m.noRestart(ctx, a.ID)
}

// clusterRecheck runs the install's policy check on the stored resolved
// compose file again, with the app's own manifest, ports and shares
// (only HardyOS's own cgroup slice is taken out first: the check refuses
// it from a package).
func (m *Manager) clusterRecheck(ctx context.Context, ia *installedApp) error {
	b, err := readStateFile(ia.meta(resolvedFile))
	if err != nil {
		return err
	}
	r, err := ParseResolved(b)
	if err != nil {
		return err
	}
	slice := SliceName(ia.state.ID)
	services, _ := r["services"].(map[string]any)
	for name, raw := range services {
		svc, _ := raw.(map[string]any)
		if svc == nil {
			continue
		}
		if cg, ok := svc["cgroup_parent"]; ok {
			if s, _ := cg.(string); s != slice {
				return fmt.Errorf("service %s runs in another cgroup (%v); refusing to start", name, cg)
			}
			delete(svc, "cgroup_parent")
		}
	}
	binds, err := m.currentShareBinds(ctx, ia)
	if err != nil {
		return err
	}
	dataDir := filepath.Join(ia.dir, dataDirName)
	if err := r.check(ia.manifest, ProjectName(ia.state.ID), dataDir, ia.state.Ports, binds); err != nil {
		return fmt.Errorf("the app's compose file on cluster storage no longer passes the policy check: %w", err)
	}
	return nil
}

// clusterSpec is what an administrator approves for a cluster app: the
// resolved compose file, the manifest and what the app was granted.
type clusterSpec struct {
	Manifest      json.RawMessage        `json:"manifest"`
	Resolved      json.RawMessage        `json:"resolved"`
	Ports         map[string]int         `json:"ports"`
	Shares        map[string]ShareChoice `json:"shares"`
	Grants        []string               `json:"grants"`
	Limits        Limits                 `json:"limits"`
	UID           int                    `json:"uid"`
	Source        Source                 `json:"source"`
	CatalogSHA256 string                 `json:"catalogSHA256"`
}

// canonical re-encodes JSON with sorted object keys.
func canonical(b []byte) (json.RawMessage, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// clusterHash is the hash of a cluster app's approved settings.
func (m *Manager) clusterHash(ia *installedApp) (string, error) {
	rb, err := readStateFile(ia.meta(resolvedFile))
	if err != nil {
		return "", err
	}
	mb, err := readStateFile(ia.meta(ManifestFile))
	if err != nil {
		return "", err
	}
	spec := clusterSpec{Ports: ia.state.Ports, Shares: ia.state.Shares, Grants: slices.Clone(ia.state.Grants),
		Limits: ia.state.Limits, UID: ia.state.UID, Source: ia.state.Source, CatalogSHA256: ia.state.CatalogSHA256}
	if spec.Resolved, err = canonical(rb); err != nil {
		return "", fmt.Errorf("the resolved compose file: %w", err)
	}
	if spec.Manifest, err = canonical(mb); err != nil {
		return "", fmt.Errorf("the manifest: %w", err)
	}
	sort.Strings(spec.Grants)
	b, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ClusterHash is the hash of the approved settings of a cluster app
// attached here (hardyd records it in the placement after the
// administrator's install or change: workload.add, workload.spec).
func (m *Manager) ClusterHash(ctx context.Context, id string) (string, error) {
	ia, _, err := m.remote(ctx, id)
	if err != nil {
		return "", err
	}
	if err := m.clusterRecheck(ctx, ia); err != nil {
		return "", err
	}
	return m.clusterHash(ia)
}

// noRestart turns Docker's own restart policy off for a cluster app's
// containers.
func (m *Manager) noRestart(ctx context.Context, id string) error {
	ids, err := m.projectContainers(ctx, id, false)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	_, err = m.run(ctx, "docker", append([]string{"update", "--restart=no"}, ids...)...)
	return err
}

var containerIDRE = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

// projectContainers lists the containers of an app's compose project.
func (m *Manager) projectContainers(ctx context.Context, id string, runningOnly bool) ([]string, error) {
	args := []string{"ps", "-q", "--filter", "label=com.docker.compose.project=" + ProjectName(id)}
	if !runningOnly {
		args = append(args, "-a")
	}
	out, err := m.run(ctx, "docker", args...)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, f := range strings.Fields(string(out)) {
		if containerIDRE.MatchString(f) {
			ids = append(ids, f)
		}
	}
	return ids, nil
}

// ClusterStopArgs stops a cluster app.
type ClusterStopArgs struct {
	ID    string `json:"id"`
	Force bool   `json:"force"`
}

// ClusterStop stops a cluster app (docker kill with Force). A forced stop
// works without its storage too (a fence took it away).
func (m *Manager) ClusterStop(ctx context.Context, a ClusterStopArgs) error {
	if err := ValidID(a.ID); err != nil {
		return Problems{err.Error()}
	}
	ia, _, err := m.remote(ctx, a.ID)
	if err == nil && !a.Force {
		_, err = m.runCompose(ctx, m.composeArgs(ia, "stop")...)
		return err
	}
	if err != nil && !a.Force {
		return err
	}
	ids, err := m.projectContainers(ctx, a.ID, true)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	_, err = m.run(ctx, "docker", append([]string{"kill"}, ids...)...)
	return err
}

// ClusterApp is a cluster app's state on this server.
type ClusterApp struct {
	ID         string `json:"id"`
	Running    bool   `json:"running"`
	Generation uint64 `json:"generation"`
	Attached   bool   `json:"attached"`
}

// ClusterStatus lists cluster apps attached here, and apps running here
// that are neither local nor attached (stale: a fence took their storage).
func (m *Manager) ClusterStatus(ctx context.Context) ([]ClusterApp, error) {
	out := []ClusterApp{}
	if m.Backend == nil {
		return out, nil
	}
	ids, err := m.Backend.List(ctx)
	if err != nil {
		return nil, err
	}
	cs := m.containers(ctx)
	running := func(id string) bool {
		for _, c := range cs[id] {
			if c.State == "running" || c.State == "restarting" {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if ValidID(id) != nil {
			continue
		}
		st, err := m.Backend.Locate(ctx, id)
		if err != nil || !st.Remote {
			continue
		}
		seen[id] = true
		out = append(out, ClusterApp{ID: id, Running: running(id), Generation: st.Generation, Attached: true})
	}
	local := map[string]bool{}
	if c, err := m.engine(); err == nil && c != nil {
		if l, err := m.installed(ctx, c); err == nil {
			for _, ia := range l {
				local[ia.state.ID] = true
			}
		}
	}
	for id := range cs {
		if !seen[id] && !local[id] && running(id) {
			out = append(out, ClusterApp{ID: id, Running: true})
		}
	}
	slices.SortFunc(out, func(a, b ClusterApp) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// imageRefRE is a Docker image reference: [registry[:port]/]path[:tag][@sha256:digest].
var imageRefRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?/)?[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[a-f0-9]{64})?$`)

// ValidImageRef reports whether ref is an image reference.
func ValidImageRef(ref string) bool { return len(ref) <= 255 && imageRefRE.MatchString(ref) }

// MaxPrepull bounds one pre-pull request.
const MaxPrepull = 32

// PrepullArgs keeps HA apps' images on this server (decision 355).
type PrepullArgs struct {
	Images []string `json:"images"`
}

// PrepullResult says how each image went.
type PrepullResult struct {
	Pulled []string          `json:"pulled"`
	Failed map[string]string `json:"failed"`
}

// Prepull downloads images so an HA app can fail over here without the
// internet. Images are only downloaded, never run.
func (m *Manager) Prepull(ctx context.Context, a PrepullArgs) (*PrepullResult, error) {
	if len(a.Images) > MaxPrepull {
		return nil, Problems{fmt.Sprintf("at most %d images at a time", MaxPrepull)}
	}
	for _, img := range a.Images {
		if !ValidImageRef(img) {
			return nil, Problems{fmt.Sprintf("%q isn't an image reference", img)}
		}
	}
	res := &PrepullResult{Pulled: []string{}, Failed: map[string]string{}}
	for _, img := range a.Images {
		st := m.pullState("cluster", img)
		err := m.apiPull(ctx, img, st)
		if errors.Is(err, errNoEngineAPI) {
			_, err = m.run(ctx, "docker", "pull", "--quiet", img)
		}
		if err != nil {
			res.Failed[img] = err.Error()
			continue
		}
		res.Pulled = append(res.Pulled, img)
	}
	return res, nil
}

// HaveImages lists which of images are on this server.
func (m *Manager) HaveImages(ctx context.Context, images []string) ([]string, error) {
	if len(images) > MaxPrepull*4 {
		return nil, Problems{"too many images"}
	}
	have := []string{}
	for _, img := range images {
		if !ValidImageRef(img) {
			return nil, Problems{fmt.Sprintf("%q isn't an image reference", img)}
		}
		if _, err := m.run(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", img); err == nil {
			have = append(have, img)
		}
	}
	return have, nil
}

// ClusterImages lists the images a cluster app attached here uses (for the
// cluster to keep them pulled on other servers).
func (m *Manager) ClusterImages(ctx context.Context, id string) ([]string, error) {
	ia, _, err := m.remote(ctx, id)
	if err != nil {
		return nil, err
	}
	r, err := m.resolved(ctx, ia)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range r.Services() {
		if s.Image != "" && !slices.Contains(out, s.Image) {
			out = append(out, s.Image)
		}
	}
	return out, nil
}
