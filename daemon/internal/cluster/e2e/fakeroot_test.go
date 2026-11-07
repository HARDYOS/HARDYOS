package e2e_test

// The fake root side of the end-to-end cluster: what hardyd-priv would do
// on each server, with the kernel and the hypervisors replaced.
//
//   - The storage node runs part B's REAL root code (san.Root: LIO through
//     configfs, root's own fence records, NFS exports, firewall) against
//     san.FakeFS (an in-memory configfs that behaves like the kernel's) and
//     a fake zfs/exportfs/nft runner.
//   - Compute nodes get fake sanclient, runtime and watchdog operations
//     that consult the storage node's configfs and exports file: a node can
//     only attach what the storage node really maps or exports to it now.
//   - One shared "hypervisor" records which node runs which workload, and
//     flags the moment two nodes run one workload or a workload starts
//     while another node can still reach its storage.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/fence"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/cluster/sanclient"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// ---- the shared world ---------------------------------------------------------------

type world struct {
	t   *testing.T
	t0  time.Time
	cid func() cluster.ClusterID

	// The storage node's kernel: configfs and its file system root.
	storageFS  *san.FakeFS
	storageSys string
	// addrOf maps storage network addresses to nodes.
	addrOf map[netip.Addr]cluster.NodeID

	mu         sync.Mutex
	running    map[cluster.WorkloadRef]map[cluster.NodeID]uint64
	violations []string
	events     []string
}

func newWorld(t *testing.T) *world {
	return &world{t: t, t0: time.Now(), storageFS: san.NewFakeFS(), storageSys: t.TempDir(),
		addrOf: map[netip.Addr]cluster.NodeID{}, running: map[cluster.WorkloadRef]map[cluster.NodeID]uint64{}}
}

func wname(w cluster.WorkloadRef) string { return string(w.Kind) + ":" + w.ID }

func (w *world) notef(format string, a ...any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.noteLocked(format, a...)
}

func (w *world) noteLocked(format string, a ...any) {
	w.events = append(w.events, fmt.Sprintf("%6.2fs ", time.Since(w.t0).Seconds())+fmt.Sprintf(format, a...))
}

func (w *world) violatef(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	w.mu.Lock()
	w.violations = append(w.violations, msg)
	w.noteLocked("VIOLATION %s", msg)
	w.mu.Unlock()
}

// reach lists the nodes the storage node lets reach a workload's storage
// now: an enabled target with one of its LUNs mapped, or an export of one
// of its datasets to the node's storage address.
func (w *world) reach(ws cluster.WorkloadStorage, ref cluster.WorkloadRef) []cluster.NodeID {
	var out []cluster.NodeID
	add := func(n cluster.NodeID) {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	if c := w.cid(); c != "" {
		for node, tg := range san.Current(w.storageFS, c) {
			if !tg.Enabled {
				continue
			}
			for _, v := range ws.Volumes {
				if slices.Contains(tg.LUNs, san.BackstoreName(ref, v.Disk)) {
					add(node)
				}
			}
		}
	}
	for _, e := range ws.Exports {
		for _, n := range w.exportClients(e.Path) {
			add(n)
		}
	}
	slices.Sort(out)
	return out
}

// exportClients reads the storage node's cluster exports file.
func (w *world) exportClients(path string) []cluster.NodeID {
	b, err := os.ReadFile(filepath.Join(w.storageSys, nfs.ClusterExportsFile))
	if err != nil {
		return nil
	}
	var out []cluster.NodeID
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || strings.HasPrefix(f[0], "#") || f[0] != path {
			continue
		}
		for _, c := range f[1:] {
			ip, _, _ := strings.Cut(c, "(")
			if a, err := netip.ParseAddr(ip); err == nil {
				if n, ok := w.addrOf[a]; ok {
					out = append(out, n)
				}
			}
		}
	}
	return out
}

// start records a node starting a workload. It refuses (and flags) a start
// while another node runs it or can still reach its storage.
func (w *world) start(node cluster.NodeID, ref cluster.WorkloadRef, gen uint64, ws cluster.WorkloadStorage) error {
	reach := w.reach(ws, ref)
	w.mu.Lock()
	defer w.mu.Unlock()
	for other := range w.running[ref] {
		if other != node {
			w.violations = append(w.violations, fmt.Sprintf("%s started on %s while it runs on %s", wname(ref), node, other))
			w.noteLocked("VIOLATION two runners of %s: %s and %s", wname(ref), node, other)
		}
	}
	for _, n := range reach {
		if n != node {
			w.violations = append(w.violations, fmt.Sprintf("%s started on %s while %s can still reach its storage", wname(ref), node, n))
			w.noteLocked("VIOLATION %s started on %s; %s still reaches its storage", wname(ref), node, n)
		}
	}
	if !slices.Contains(reach, node) {
		return fmt.Errorf("%s: the storage server doesn't give %s its storage", wname(ref), node)
	}
	if w.running[ref] == nil {
		w.running[ref] = map[cluster.NodeID]uint64{}
	}
	w.running[ref][node] = gen
	w.noteLocked("%s runs %s (generation %d)", node, wname(ref), gen)
	return nil
}

func (w *world) stop(node cluster.NodeID, ref cluster.WorkloadRef, why string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.running[ref][node]; ok {
		delete(w.running[ref], node)
		w.noteLocked("%s stopped %s (%s)", node, wname(ref), why)
	}
}

func (w *world) runners(ref cluster.WorkloadRef) map[cluster.NodeID]uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[cluster.NodeID]uint64{}
	for n, g := range w.running[ref] {
		out[n] = g
	}
	return out
}

func (w *world) runsOn(node cluster.NodeID) map[cluster.WorkloadRef]uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[cluster.WorkloadRef]uint64{}
	for ref, m := range w.running {
		if g, ok := m[node]; ok {
			out[ref] = g
		}
	}
	return out
}

// watchLIO samples the storage node's configfs: a backstore mapped into
// two enabled targets at once is a violation (no live migration here).
func (w *world) watchLIO(ctx context.Context) {
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		c := w.cid()
		if c == "" {
			continue
		}
		by := map[string][]cluster.NodeID{}
		for node, tg := range san.Current(w.storageFS, c) {
			if !tg.Enabled {
				continue
			}
			for _, l := range tg.LUNs {
				by[l] = append(by[l], node)
			}
		}
		for l, nodes := range by {
			if len(nodes) > 1 {
				w.violatef("LUN %s mapped to %v at once", l, nodes)
			}
		}
	}
}

func (w *world) dump() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range w.events {
		w.t.Log(e)
	}
}

// quiet drops the priv servers' per-operation log lines.
var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// ---- a priv server with typed handlers ------------------------------------------------

func handle[T any](s *priv.Server, op string, fn func(ctx context.Context, a T) (any, error)) {
	s.Handle(op, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a T
		if len(raw) > 0 && string(raw) != "null" {
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, priv.Errorf(priv.CodeBadArgs, "%v", err)
			}
		}
		out, err := fn(ctx, a)
		if err != nil {
			var pe *priv.Error
			if errors.As(err, &pe) {
				return nil, pe
			}
			return nil, priv.Errorf(priv.CodeFailed, "%v", err)
		}
		if out == nil {
			out = map[string]bool{"ok": true}
		}
		return out, nil
	})
}

// servePriv serves s on a fresh unix socket and returns its path.
func servePriv(t *testing.T, ctx context.Context, s *priv.Server) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ctx, ln.(*net.UnixListener)) }()
	return sock
}

// ---- the storage node: real san.Root on a fake kernel --------------------------------

// fakeZFS is zfs (and the other commands san.Root and the NFS manager
// run) on an in-memory pool "tank".
type fakeZFS struct {
	sys string

	mu    sync.Mutex
	ds    map[string]map[string]string
	guid  int
	lines []string
}

func newFakeZFS(sys string) *fakeZFS {
	z := &fakeZFS{sys: sys, ds: map[string]map[string]string{}, guid: 7000}
	z.createLocked("tank", false, nil, 0)
	return z
}

func (z *fakeZFS) createLocked(ds string, vol bool, props map[string]string, sizeGB int) {
	z.guid++
	p := map[string]string{"guid": strconv.Itoa(z.guid), "used": "0", "sync": "standard"}
	if vol {
		p["type"], p["mountpoint"], p["mounted"] = "volume", "-", "-"
		p["volsize"] = strconv.Itoa(sizeGB << 30)
		dev := filepath.Join(z.sys, "dev/zvol", ds)
		_ = os.MkdirAll(filepath.Dir(dev), 0o755)
		_ = os.WriteFile(dev, nil, 0o644)
	} else {
		p["type"], p["mountpoint"], p["mounted"] = "filesystem", "/mnt/"+ds, "yes"
		_ = os.MkdirAll(filepath.Join(z.sys, "mnt", ds), 0o755)
	}
	for k, v := range props {
		p[k] = v
	}
	z.ds[ds] = p
}

func ok(out string) (sysexec.Result, error) { return sysexec.Result{Stdout: []byte(out)}, nil }
func fail(msg string) (sysexec.Result, error) {
	return sysexec.Result{ExitCode: 1, Stderr: []byte(msg)}, nil
}

func (z *fakeZFS) Run(_ context.Context, _ []byte, name string, args ...string) (sysexec.Result, error) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.lines = append(z.lines, name+" "+strings.Join(args, " "))
	if name != "zfs" || len(args) == 0 {
		return ok("") // nft, exportfs, systemctl, modprobe: the fake kernel accepts them
	}
	last := args[len(args)-1]
	switch args[0] {
	case "list":
		if slices.Contains(args, "-t") || strings.Contains(last, "@") {
			return ok("")
		}
		if _, exists := z.ds[last]; exists {
			return ok(last + "\n")
		}
		return fail("cannot open '" + last + "': dataset does not exist")
	case "create":
		vol, size := false, 0
		props := map[string]string{}
		for i := 1; i < len(args)-1; i++ {
			switch args[i] {
			case "-s":
			case "-V":
				vol = true
				i++
				size, _ = strconv.Atoi(strings.TrimSuffix(args[i], "G"))
			case "-o":
				i++
				k, v, _ := strings.Cut(args[i], "=")
				props[k] = v
			}
		}
		if _, exists := z.ds[last]; exists {
			return fail("dataset already exists")
		}
		parent := last[:max(strings.LastIndex(last, "/"), 0)]
		if _, exists := z.ds[parent]; !exists {
			return fail("parent does not exist")
		}
		z.createLocked(last, vol, props, size)
		return ok("")
	case "get":
		p, exists := z.ds[last]
		if !exists {
			return fail("dataset does not exist")
		}
		var b strings.Builder
		for _, n := range strings.Split(args[len(args)-2], ",") {
			v, has := p[n]
			if !has {
				v = "-"
			}
			b.WriteString(n + "\t" + v + "\n")
		}
		return ok(b.String())
	case "set":
		p, exists := z.ds[last]
		if !exists {
			return fail("dataset does not exist")
		}
		for _, kv := range args[1 : len(args)-1] {
			k, v, _ := strings.Cut(kv, "=")
			p[k] = v
		}
		return ok("")
	case "destroy":
		for ds := range z.ds {
			if ds == last || strings.HasPrefix(ds, last+"/") {
				delete(z.ds, ds)
			}
		}
		return ok("")
	}
	return ok("")
}

// storageRoot is the storage node's hardyd-priv: part B's real root code.
// Everything is served as is, except an app's dataset in runs that aren't
// root: its folder is given to the app's user id, which only root can do.
func storageRoot(t *testing.T, ctx context.Context, w *world) *priv.Server {
	z := newFakeZFS(w.storageSys)
	root := &san.Root{Runner: z, FS: w.storageFS, Dir: filepath.Join(w.storageSys, "var/lib/hardyos/root/cluster"), Sys: w.storageSys,
		NFS: &nfs.ClusterManager{Runner: z, Root: w.storageSys, Log: quiet}, DeviceWait: time.Second, Log: quiet}
	inner := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}, Logger: quiet}
	priv.RegisterSAN(inner, root)
	ic := priv.NewClient(servePriv(t, ctx, inner))
	outer := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	for _, op := range inner.Ops() {
		op := op
		outer.Handle(op, func(ctx context.Context, raw json.RawMessage) (any, error) {
			if op == san.OpDatasetCreate && os.Geteuid() != 0 {
				var a san.DatasetCreateArgs
				if err := json.Unmarshal(raw, &a); err == nil && a.Kind == cluster.KindApp {
					z.mu.Lock()
					z.createLocked(a.Dataset(), false, map[string]string{san.PropApp: a.ID, san.PropRole: san.RoleCluster}, 0)
					p := z.ds[a.Dataset()]
					z.mu.Unlock()
					return san.DatasetInfo{Dataset: a.Dataset(), Mountpoint: p["mountpoint"], GUID: p["guid"]}, nil
				}
			}
			var out json.RawMessage
			if err := ic.Call(ctx, op, raw, &out); err != nil {
				var pe *priv.Error
				if errors.As(err, &pe) {
					return nil, pe
				}
				return nil, priv.Errorf(priv.CodeFailed, "%v", err)
			}
			return out, nil
		})
	}
	return outer
}

// ---- a compute node's fake root ---------------------------------------------------------

type computeRoot struct {
	w    *world
	node cluster.NodeID

	mu       sync.Mutex
	attached map[cluster.WorkloadRef]sanclient.Record
	storage  map[cluster.WorkloadRef]cluster.WorkloadStorage
	armed    bool
	petUntil time.Time
	pets     int
	fences   int
}

func (h *computeRoot) record(w cluster.WorkloadRef) (sanclient.Record, cluster.WorkloadStorage, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	r, ok := h.attached[w]
	return r, h.storage[w], ok
}

func (h *computeRoot) clusterVMs() []vms.ClusterVM {
	h.mu.Lock()
	att := map[cluster.WorkloadRef]sanclient.Record{}
	for k, v := range h.attached {
		att[k] = v
	}
	h.mu.Unlock()
	run := h.w.runsOn(h.node)
	out := []vms.ClusterVM{}
	seen := map[string]bool{}
	for ref, gen := range run {
		if ref.Kind == cluster.KindVM {
			_, a := att[ref]
			out = append(out, vms.ClusterVM{ID: ref.ID, State: "running", Generation: gen, Attached: a})
			seen[ref.ID] = true
		}
	}
	for ref, r := range att {
		if ref.Kind == cluster.KindVM && !seen[ref.ID] {
			out = append(out, vms.ClusterVM{ID: ref.ID, State: "shut off", Generation: r.Generation, Attached: true})
		}
	}
	return out
}

func (h *computeRoot) clusterApps() []apps.ClusterApp {
	h.mu.Lock()
	att := map[cluster.WorkloadRef]sanclient.Record{}
	for k, v := range h.attached {
		att[k] = v
	}
	h.mu.Unlock()
	run := h.w.runsOn(h.node)
	out := []apps.ClusterApp{}
	seen := map[string]bool{}
	for ref, gen := range run {
		if ref.Kind == cluster.KindApp {
			_, a := att[ref]
			out = append(out, apps.ClusterApp{ID: ref.ID, Running: true, Generation: gen, Attached: a})
			seen[ref.ID] = true
		}
	}
	for ref, r := range att {
		if ref.Kind == cluster.KindApp && !seen[ref.ID] {
			out = append(out, apps.ClusterApp{ID: ref.ID, Generation: r.Generation, Attached: true})
		}
	}
	return out
}

func (h *computeRoot) startW(ref cluster.WorkloadRef, gen uint64) error {
	r, ws, ok := h.record(ref)
	if !ok || r.Generation != gen {
		return priv.Errorf(priv.CodeBadArgs, "%s isn't attached here under generation %d", wname(ref), gen)
	}
	return h.w.start(h.node, ref, gen, ws)
}

const testImage = "ghcr.io/hardyos/notes:1.0"

// computeServer is a compute node's hardyd-priv: sanclient, runtime and
// watchdog operations on the fake world.
func computeServer(w *world, node cluster.NodeID) (*priv.Server, *computeRoot) {
	h := &computeRoot{w: w, node: node, attached: map[cluster.WorkloadRef]sanclient.Record{}, storage: map[cluster.WorkloadRef]cluster.WorkloadStorage{}}
	s := &priv.Server{AllowedUIDs: []uint32{uint32(os.Getuid())}}
	type none struct{}

	// Hardware and the watchdog.
	handle(s, priv.OpVMsCapabilities, func(context.Context, none) (any, error) {
		return vms.Capabilities{Supported: true, KVM: true, CPUs: 16, MemoryMB: 65536, Bridge: "br0", Pools: []string{}}, nil
	})
	handle(s, priv.OpClusterWatchdogStatus, func(context.Context, none) (any, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		st := fence.Status{Armed: h.armed, Kind: fence.KindHardware}
		if left := time.Until(h.petUntil); h.armed && left > 0 {
			st.PettingForMs = left.Milliseconds()
		}
		return st, nil
	})
	handle(s, priv.OpClusterWatchdogArm, func(_ context.Context, a priv.WatchdogArmArgs) (any, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if !h.armed {
			w.notef("%s armed its watchdog (%d s)", node, a.TimeoutSec)
		}
		h.armed = true
		return priv.WatchdogArmResult{Kind: fence.KindHardware}, nil
	})
	handle(s, priv.OpClusterWatchdogPet, func(_ context.Context, a priv.WatchdogPetArgs) (any, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if !h.armed {
			return nil, errors.New("the watchdog isn't armed")
		}
		h.petUntil = time.Now().Add(time.Duration(a.ValidForMs) * time.Millisecond)
		h.pets++
		return nil, nil
	})
	handle(s, priv.OpClusterWatchdogDisarm, func(context.Context, none) (any, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.armed {
			w.notef("%s disarmed its watchdog", node)
		}
		h.armed, h.petUntil = false, time.Time{}
		return nil, nil
	})
	handle(s, priv.OpClusterWatchdogExpire, func(context.Context, none) (any, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.petUntil = time.Time{}
		w.notef("%s stopped petting its watchdog", node)
		return nil, nil
	})
	handle(s, priv.OpClusterSelfFence, func(_ context.Context, a priv.SelfFenceArgs) (any, error) {
		h.mu.Lock()
		h.fences++
		h.mu.Unlock()
		for _, id := range a.VMs {
			w.stop(node, cluster.WorkloadRef{Kind: cluster.KindVM, ID: id}, "self-fence")
		}
		for _, id := range a.Apps {
			w.stop(node, cluster.WorkloadRef{Kind: cluster.KindApp, ID: id}, "self-fence")
		}
		return priv.SelfFenceResult{}, nil
	})

	// The VM and app runtimes.
	handle(s, priv.OpVMsGet, func(_ context.Context, a priv.VMRef) (any, error) {
		return vms.VM{Spec: vms.Spec{ID: a.ID, Name: a.ID, OS: "linux", CPU: vms.CPU{Cores: 2, Threads: 1}, Memory: vms.Memory{MB: 2048}, CPUModel: "x86-64-v2"}}, nil
	})
	handle(s, priv.OpVMsClusterStart, func(_ context.Context, a vms.ClusterStartArgs) (any, error) {
		return nil, h.startW(cluster.WorkloadRef{Kind: cluster.KindVM, ID: a.ID}, a.Generation)
	})
	handle(s, priv.OpVMsClusterStop, func(_ context.Context, a vms.ClusterStopArgs) (any, error) {
		w.stop(node, cluster.WorkloadRef{Kind: cluster.KindVM, ID: a.ID}, map[bool]string{true: "forced", false: "shut down"}[a.Force])
		return vms.VM{}, nil
	})
	handle(s, priv.OpVMsClusterStatus, func(context.Context, none) (any, error) { return h.clusterVMs(), nil })
	handle(s, priv.OpAppsClusterStart, func(_ context.Context, a apps.ClusterStartArgs) (any, error) {
		return nil, h.startW(cluster.WorkloadRef{Kind: cluster.KindApp, ID: a.ID}, a.Generation)
	})
	handle(s, priv.OpAppsClusterStop, func(_ context.Context, a apps.ClusterStopArgs) (any, error) {
		w.stop(node, cluster.WorkloadRef{Kind: cluster.KindApp, ID: a.ID}, map[bool]string{true: "killed", false: "compose stop"}[a.Force])
		return nil, nil
	})
	handle(s, priv.OpAppsClusterStatus, func(context.Context, none) (any, error) { return h.clusterApps(), nil })
	handle(s, priv.OpAppsClusterImages, func(context.Context, priv.AppRef) (any, error) {
		return priv.ImagesResult{Images: []string{testImage}}, nil
	})
	handle(s, priv.OpAppsHaveImages, func(_ context.Context, a apps.PrepullArgs) (any, error) {
		return priv.ImagesResult{Images: a.Images}, nil
	})
	handle(s, priv.OpAppsPrepull, func(_ context.Context, a apps.PrepullArgs) (any, error) {
		return apps.PrepullResult{Pulled: a.Images, Failed: map[string]string{}}, nil
	})

	// Cluster storage, as the storage node allows it now.
	handle(s, sanclient.OpStatus, func(context.Context, none) (any, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		st := sanclient.Status{Healthy: true, Attached: []sanclient.Record{}, Shares: map[string]string{}}
		for _, r := range h.attached {
			st.Attached = append(st.Attached, r)
		}
		return st, nil
	})
	handle(s, sanclient.OpLogin, func(_ context.Context, a sanclient.LoginArgs) (any, error) {
		if err := a.CHAP.Validate(); err != nil {
			return nil, err
		}
		tg, found := san.Current(w.storageFS, a.Cluster)[node]
		if !found || !tg.Enabled {
			return nil, fmt.Errorf("iscsiadm: login to %s's target refused (target missing or disabled)", node)
		}
		return nil, nil
	})
	handle(s, sanclient.OpRescan, func(context.Context, sanclient.SessionArgs) (any, error) { return nil, nil })
	handle(s, sanclient.OpMultipathApply, func(context.Context, sanclient.MultipathArgs) (any, error) { return nil, nil })
	handle(s, san.OpFirewallApply, func(context.Context, san.FirewallSpec) (any, error) { return nil, nil })
	handle(s, sanclient.OpAttach, func(_ context.Context, a sanclient.AttachArgs) (any, error) {
		reach := w.reach(a.Storage, a.Workload)
		if !slices.Contains(reach, node) {
			return nil, fmt.Errorf("%s: the storage server doesn't map or export it to %s", wname(a.Workload), node)
		}
		rec := sanclient.Record{Attachment: cluster.Attachment{Workload: a.Workload, Generation: a.Generation, Disks: map[string]string{}}, At: time.Now()}
		for _, v := range a.Storage.Volumes {
			rec.Disks[v.Disk] = "/dev/disk/by-id/wwn-0x" + v.WWN
			rec.WWNs = append(rec.WWNs, v.WWN)
		}
		for _, e := range a.Storage.Exports {
			rec.StateDir, rec.Dataset = e.MountPath, e.Dataset
			rec.Mounts = append(rec.Mounts, e.MountPath)
		}
		h.mu.Lock()
		h.attached[a.Workload] = rec
		h.storage[a.Workload] = a.Storage
		h.mu.Unlock()
		w.notef("%s attached %s (generation %d)", node, wname(a.Workload), a.Generation)
		return rec, nil
	})
	handle(s, sanclient.OpDetach, func(_ context.Context, a sanclient.DetachArgs) (any, error) {
		h.mu.Lock()
		_, had := h.attached[a.Workload]
		delete(h.attached, a.Workload)
		delete(h.storage, a.Workload)
		h.mu.Unlock()
		if had {
			w.notef("%s detached %s (force %v)", node, wname(a.Workload), a.Force)
		}
		return nil, nil
	})
	handle(s, sanclient.OpFreeze, func(context.Context, sanclient.FreezeArgs) (any, error) {
		return map[string]bool{"consistent": true}, nil
	})
	handle(s, sanclient.OpThaw, func(context.Context, sanclient.FreezeArgs) (any, error) { return nil, nil })
	handle(s, sanclient.OpAppDump, func(context.Context, sanclient.DumpArgs) (any, error) { return map[string]bool{"dumped": false}, nil })
	return s, h
}
