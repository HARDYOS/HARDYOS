package moves_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/ha/clustertest"
	"github.com/hardyos/hardyos/daemon/internal/cluster/moves"
	"github.com/hardyos/hardyos/daemon/internal/cluster/placement"
	"github.com/hardyos/hardyos/daemon/internal/cluster/state"
	"github.com/hardyos/hardyos/daemon/internal/devices"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// peers routes peer calls to each node's moves.Node over real HTTP (the
// migration relay streams), naming the caller in a header.
type peers struct {
	from    cluster.NodeID
	servers map[cluster.NodeID]*httptest.Server
}

func (p *peers) Call(ctx context.Context, node cluster.NodeID, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, "http://x"+path, body)
	res, err := p.Do(ctx, node, req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		return &cluster.PeerError{Node: node, Status: res.StatusCode, Message: string(b)}
	}
	if out != nil {
		return json.NewDecoder(res.Body).Decode(out)
	}
	return nil
}

func (p *peers) Do(ctx context.Context, node cluster.NodeID, r *http.Request) (*http.Response, error) {
	srv, ok := p.servers[node]
	if !ok {
		return nil, fmt.Errorf("no route to %s", node)
	}
	u := *r.URL
	u.Scheme, u.Host = "http", strings.TrimPrefix(srv.URL, "http://")
	r2 := r.Clone(ctx)
	r2.URL, r2.Host, r2.RequestURI = &u, u.Host, ""
	r2.Header.Set("X-Test-Caller", string(p.from))
	return srv.Client().Do(r2)
}

type mux struct{ *http.ServeMux }

func (m mux) Handle(p string, h http.Handler) { m.ServeMux.Handle(p, h) }

// fakePriv is hardyd-priv's migration and device operations.
type fakePriv struct {
	t    *testing.T
	w    *clustertest.World
	node cluster.NodeID
	dir  string

	mu        sync.Mutex
	listen    map[string]string // token -> socket path
	failSend  bool
	relayed   string
	destroyed []string
	// sendLands: the migration arrives although send reports a failure.
	sendLands bool
	leaveCopy bool
	devOK     bool
}

func (f *fakePriv) Call(ctx context.Context, op string, args, out any) error {
	b, _ := json.Marshal(args)
	switch op {
	case priv.OpDevicesCheck:
		res := priv.DevicesCheckResult{OK: f.devOK}
		if !f.devOK {
			res.Problems = append(res.Problems, struct {
				Device  string `json:"device"`
				Message string `json:"message"`
			}{"0000:01:00.0", "this server has no such GPU"})
		}
		return remarshal(res, out)
	case priv.OpVMsMigrateEnd:
		return nil
	case priv.OpVMsClusterStop:
		// Root destroys the domain, whatever the grant says.
		var a vms.ClusterStopArgs
		_ = json.Unmarshal(b, &a)
		f.mu.Lock()
		f.destroyed = append(f.destroyed, a.ID)
		f.mu.Unlock()
		f.w.Nodes[f.node].Kill(cluster.WorkloadRef{Kind: cluster.KindVM, ID: a.ID})
		return nil
	case priv.OpVMsGet:
		var v vms.VM
		v.Devices = []devices.Device{{Kind: devices.KindGPU, ID: "0000:01:00.0"}}
		return remarshal(v, out)
	case priv.OpVMsMigrateSend:
		var a vms.MigrateSendArgs
		_ = json.Unmarshal(b, &a)
		if err := vms.ValidMigrateURI(a.MigrateURI); err != nil {
			return err
		}
		f.mu.Lock()
		sock := f.listen[a.Token]
		fail := f.failSend
		f.mu.Unlock()
		// Pretend to be libvirtd: connect to the one-shot socket and talk
		// to the destination's libvirt through the relay.
		c, err := net.Dial("unix", sock)
		if err != nil {
			return err
		}
		defer c.Close()
		_, _ = c.Write([]byte("hello libvirt\n"))
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			return fmt.Errorf("relay: %w", err)
		}
		f.mu.Lock()
		f.relayed = strings.TrimSpace(line)
		f.mu.Unlock()
		ref := cluster.WorkloadRef{Kind: cluster.KindVM, ID: a.VM}
		f.mu.Lock()
		lands := f.sendLands
		f.mu.Unlock()
		if fail {
			if lands {
				// The memory arrived and the source stopped, but libvirt's
				// confirmation got lost: send reports a failure.
				f.w.Nodes[cluster.NodeID(a.To)].StartProcess(ref, a.Generation)
				f.w.Nodes[f.node].Kill(ref)
				return errors.New("migration failed: connection reset during the confirm phase")
			}
			if f.leaveCopy {
				// The destination's paused copy is left behind.
				f.w.Nodes[cluster.NodeID(a.To)].StartProcess(ref, a.Generation)
			}
			return errors.New("migration failed: destination ran out of memory")
		}
		f.w.Nodes[cluster.NodeID(a.To)].StartProcess(ref, a.Generation)
		f.w.Nodes[f.node].Kill(ref)
		return nil
	}
	return fmt.Errorf("fakePriv: unexpected %s", op)
}

func (f *fakePriv) CallFile(ctx context.Context, op string, args, out any) (*os.File, error) {
	b, _ := json.Marshal(args)
	switch op {
	case priv.OpVMsMigrateAccept:
		// The destination's libvirt: answers each line with ack.
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			return nil, err
		}
		lib := os.NewFile(uintptr(fds[1]), "libvirt")
		go func() {
			defer lib.Close()
			sc := bufio.NewScanner(lib)
			for sc.Scan() {
				_, _ = lib.Write([]byte("ack " + sc.Text() + "\n"))
			}
		}()
		return os.NewFile(uintptr(fds[0]), "conn"), nil
	case priv.OpVMsMigrateListen:
		var a vms.MigrateListenArgs
		_ = json.Unmarshal(b, &a)
		p := filepath.Join(f.dir, a.Token[:8]+".sock")
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
		if err != nil {
			return nil, err
		}
		ln.SetUnlinkOnClose(false)
		file, err := ln.File()
		ln.Close()
		f.mu.Lock()
		f.listen[a.Token] = p
		f.mu.Unlock()
		return file, err
	}
	return nil, fmt.Errorf("fakePriv: unexpected %s", op)
}

func remarshal(in, out any) error {
	if out == nil {
		return nil
	}
	b, _ := json.Marshal(in)
	return json.Unmarshal(b, out)
}

type env struct {
	w     *clustertest.World
	mover *moves.Mover
	privs map[cluster.NodeID]*fakePriv
	nodes map[cluster.NodeID]*moves.Node
}

// pipeStream is the cluster port's hardyos-migrate/1 in memory: the
// destination serves the dialled connection as from (part A names the
// member that dialled).
func pipeStream(nodes map[cluster.NodeID]*moves.Node, from cluster.NodeID) moves.ALPNStream {
	return moves.ALPNStream{Dial: func(_ context.Context, to cluster.NodeID) (net.Conn, error) {
		a, b := net.Pipe()
		go nodes[to].ServeMigrate(b, from)
		return a, nil
	}}
}

func newEnv(t *testing.T) *env {
	w := clustertest.New(t, "c1", "c2", "c3")
	w.SetLeader("c3")
	e := &env{w: w, privs: map[cluster.NodeID]*fakePriv{}}
	servers := map[cluster.NodeID]*httptest.Server{}
	nodes := map[cluster.NodeID]*moves.Node{}
	dir, err := os.MkdirTemp("", "p8c")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	for _, id := range []cluster.NodeID{"c1", "c2", "c3"} {
		n := w.Nodes[id]
		fp := &fakePriv{t: t, w: w, node: id, dir: dir, listen: map[string]string{}, devOK: true}
		e.privs[id] = fp
		m := mux{http.NewServeMux()}
		from := id
		node := &moves.Node{Cluster: n, Reconciler: n.Rec, Attacher: n.Rec.Attacher, Runtimes: n.Rec.Runtimes, Priv: fp,
			Stream:    pipeStream(nodes, from),
			Peers:     &peers{from: id, servers: servers},
			GrantWait: 2 * time.Second, Poll: 5 * time.Millisecond,
			Caller: func(r *http.Request) (cluster.Node, bool) {
				c := r.Header.Get("X-Test-Caller")
				return cluster.Node{ID: cluster.NodeID(c)}, c != ""
			}}
		node.Register(m)
		nodes[id] = node
		e.nodes = nodes
		srv := httptest.NewServer(m)
		t.Cleanup(srv.Close)
		servers[id] = srv
	}
	e.mover = &moves.Mover{Cluster: w.Nodes["c3"], Peers: &peers{from: "c3", servers: servers}, Scheduler: &placement.Scheduler{ReservedMB: 1024},
		GrantWait: 2 * time.Second, Poll: 5 * time.Millisecond, HoldFor: time.Minute}
	return e
}

var actor = cluster.Actor{Kind: "local", Name: "cade", Via: "c3"}

func onlyOn(t *testing.T, w *clustertest.World, ref cluster.WorkloadRef, want cluster.NodeID) {
	t.Helper()
	for _, id := range []cluster.NodeID{"c1", "c2", "c3"} {
		_, ok := w.Nodes[id].RunningGen(ref)
		if ok != (id == want) {
			t.Fatalf("%s running on %s: %v (want only %s)", ref.ID, id, ok, want)
		}
	}
	if ws := w.Writers(ref); len(ws) > 1 {
		t.Fatalf("two writers: %v", ws)
	}
}

func TestOfflineMove(t *testing.T) {
	e := newEnv(t)
	vm := e.w.AddVM("web", "c1", true, 50)
	e.w.Run(2 * time.Second)
	onlyOn(t, e.w, vm, "c1")
	res, err := e.mover.Move(context.Background(), cluster.MoveRequest{Workload: vm, To: "c2", Mode: cluster.MoveOffline, Generation: 1}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if res.From != "c1" || res.To != "c2" || res.Generation != 2 {
		t.Fatalf("%+v", res)
	}
	onlyOn(t, e.w, vm, "c2")
	p := e.w.Snapshot().Placements[vm]
	if p.Owner != "c2" || p.Target != "" || p.State != cluster.PlacementRunning || p.Generation != 2 {
		t.Fatalf("%+v", p)
	}
	if _, ok := e.w.Nodes["c1"].Attached()[vm]; ok {
		t.Fatal("c1 kept the storage attached")
	}
	e.w.Run(5 * time.Second)
	onlyOn(t, e.w, vm, "c2")
	if len(e.w.Violations) > 0 {
		t.Fatal(e.w.Violations)
	}
}

func TestOfflineMoveStaleGeneration(t *testing.T) {
	e := newEnv(t)
	vm := e.w.AddVM("web", "c1", false, 0)
	e.w.Run(2 * time.Second)
	if _, err := e.mover.Move(context.Background(), cluster.MoveRequest{Workload: vm, To: "c2", Generation: 7}, actor); !errors.Is(err, cluster.ErrStaleGeneration) {
		t.Fatalf("%v", err)
	}
}

func TestLiveMigration(t *testing.T) {
	e := newEnv(t)
	vm := e.w.AddVM("web", "c1", true, 50)
	e.w.Run(2 * time.Second)
	res, err := e.mover.Move(context.Background(), cluster.MoveRequest{Workload: vm, To: "c2", Mode: cluster.MoveLive, Generation: 1}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if res.Mode != cluster.MoveLive || res.Generation != 3 {
		t.Fatalf("%+v", res)
	}
	if got := e.privs["c1"].relayed; got != "ack hello libvirt" {
		t.Fatalf("the relayed libvirt connection: %q", got)
	}
	s := e.w.Snapshot()
	p, g := s.Placements[vm], s.Grants[vm]
	if p.Owner != "c2" || p.Generation != 3 || p.State != cluster.PlacementRunning || g.Mode != cluster.GrantExclusive || len(g.Nodes) != 1 {
		t.Fatalf("%+v %+v", p, g)
	}
	onlyOn(t, e.w, vm, "c2")
	// The destination keeps the migrated VM (adopted under the new
	// generation), the source lets its storage go.
	e.w.Run(5 * time.Second)
	onlyOn(t, e.w, vm, "c2")
	if g, _ := e.w.Nodes["c2"].RunningGen(vm); g != 2 {
		t.Fatalf("the migrated VM restarted (process generation %d)", g)
	}
	if a := e.w.Nodes["c2"].Attached()[vm]; a != 3 {
		t.Fatalf("c2's attachment generation: %d", a)
	}
	if _, ok := e.w.Nodes["c1"].Attached()[vm]; ok {
		t.Fatal("c1 kept the storage attached")
	}
	if len(e.w.Violations) > 0 {
		t.Fatal(e.w.Violations)
	}
}

func TestLiveMigrationFailureKeepsSource(t *testing.T) {
	e := newEnv(t)
	vm := e.w.AddVM("web", "c1", true, 50)
	e.w.Run(2 * time.Second)
	e.privs["c1"].failSend = true
	if _, err := e.mover.Move(context.Background(), cluster.MoveRequest{Workload: vm, To: "c2", Mode: cluster.MoveLive}, actor); err == nil {
		t.Fatal("a failed migration reported success")
	}
	p := e.w.Snapshot().Placements[vm]
	if p.Owner != "c1" || p.State != cluster.PlacementRunning || p.Target != "" {
		t.Fatalf("%+v", p)
	}
	e.w.Run(5 * time.Second)
	onlyOn(t, e.w, vm, "c1")
	if g, _ := e.w.Nodes["c1"].RunningGen(vm); g != 1 {
		t.Fatalf("the source restarted the VM (generation %d) instead of keeping it", g)
	}
	if _, ok := e.w.Nodes["c2"].Attached()[vm]; ok {
		t.Fatal("c2 kept the storage of a failed migration")
	}
}

func TestPassthroughVMMoves(t *testing.T) {
	e := newEnv(t)
	ref := cluster.WorkloadRef{Kind: cluster.KindVM, ID: "gaming"}
	e.w.Requirements = map[cluster.WorkloadRef]*cluster.Requirements{ref: {MemoryMB: 2048, Devices: []string{"gpu:0000:01:00.0"}}}
	if err := e.w.Propose("c1", cluster.CmdWorkloadAdd, state.WorkloadAdd{SpecHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Workload: ref, Name: "Gaming", Owner: "c1", Requested: cluster.RequestRunning, Pinned: true}); err != nil {
		t.Fatal(err)
	}
	e.w.Run(2 * time.Second)
	ctx := context.Background()
	if _, err := e.mover.Move(ctx, cluster.MoveRequest{Workload: ref, To: "c2", Mode: cluster.MoveLive}, actor); !errors.Is(err, moves.ErrNotLive) {
		t.Fatalf("live: %v", err)
	}
	if _, err := e.mover.Move(ctx, cluster.MoveRequest{Workload: ref, Mode: cluster.MoveOffline}, actor); err == nil {
		t.Fatal("moved without a chosen server")
	}
	if _, err := e.mover.Move(ctx, cluster.MoveRequest{Workload: ref, To: "c2"}, actor); !errors.Is(err, moves.ErrConfirm) {
		t.Fatalf("unconfirmed: %v", err)
	}
	e.privs["c2"].devOK = false
	if _, err := e.mover.MoveWith(ctx, cluster.MoveRequest{Workload: ref, To: "c2"}, actor, moves.Options{Confirm: "Gaming"}); err == nil {
		t.Fatal("moved to a server without the devices")
	}
	onlyOn(t, e.w, ref, "c1")
	e.privs["c2"].devOK = true
	if _, err := e.mover.MoveWith(ctx, cluster.MoveRequest{Workload: ref, To: "c2"}, actor, moves.Options{Confirm: "Gaming"}); err != nil {
		t.Fatal(err)
	}
	onlyOn(t, e.w, ref, "c2")
}

func TestStartElsewhereNeedsFenceAndConfirm(t *testing.T) {
	e := newEnv(t)
	vm := e.w.AddVM("lab", "c1", false, 0)
	e.w.Run(2 * time.Second)
	e.w.SetStorageUp(false)
	e.w.Nodes["c1"].Crash()
	e.w.Run(45 * time.Second)
	ctx := context.Background()
	if _, err := e.mover.MoveWith(ctx, cluster.MoveRequest{Workload: vm}, actor, moves.Options{Confirm: "lab"}); err == nil || !strings.Contains(err.Error(), "confirmed") {
		t.Fatalf("started elsewhere before the fence: %v", err)
	}
	e.w.SetStorageUp(true)
	if _, err := e.mover.Move(ctx, cluster.MoveRequest{Workload: vm}, actor); !errors.Is(err, moves.ErrConfirm) {
		t.Fatalf("unconfirmed: %v", err)
	}
	res, err := e.mover.MoveWith(ctx, cluster.MoveRequest{Workload: vm}, actor, moves.Options{Confirm: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	e.w.Run(3 * time.Second)
	onlyOn(t, e.w, vm, res.To)
}

func TestDrain(t *testing.T) {
	e := newEnv(t)
	a := e.w.AddVM("a", "c1", true, 90)
	b := e.w.AddVM("b", "c1", false, 0)
	pinned := cluster.WorkloadRef{Kind: cluster.KindVM, ID: "gpu"}
	_ = e.w.Propose("c1", cluster.CmdWorkloadAdd, state.WorkloadAdd{SpecHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Workload: pinned, Name: "gpu", Owner: "c1", Requested: cluster.RequestRunning, Pinned: true})
	e.w.Run(2 * time.Second)
	res, err := e.mover.Drain(context.Background(), "c1", false, actor)
	if err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("a pinned VM should be reported: %v", err)
	}
	if len(res) != 2 || res[0].Workload != a {
		t.Fatalf("HA first: %+v", res)
	}
	s := e.w.Snapshot()
	if s.Placements[a].Owner == "c1" || s.Placements[b].Owner == "c1" {
		t.Fatal("not drained")
	}
	if _, err := e.mover.Drain(context.Background(), "c1", true, actor); err != nil {
		t.Fatal(err)
	}
	e.w.Run(3 * time.Second)
	if _, ok := e.w.Nodes["c1"].RunningGen(pinned); ok {
		t.Fatal("stopOthers left the pinned VM running")
	}
}

func TestStreamRefusesOtherCallers(t *testing.T) {
	e := newEnv(t)
	vm := e.w.AddVM("web", "c1", false, 0)
	e.w.Run(2 * time.Second)
	// An admission for c1 as source; c3 tries to use its token.
	if err := e.w.Propose("c3", cluster.CmdMoveBegin, state.MoveBegin{Workload: vm, Generation: 1, To: "c2", Mode: cluster.MoveLive}); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("cd", 16)
	c3 := e.mover.Peers
	var res moves.StepResult
	if err := c3.Call(context.Background(), "c2", http.MethodPost, cluster.PeerPathPrefix+moves.PathAccept,
		moves.AcceptRequest{VM: "web", From: "c1", Token: token, Generation: 2}, &res); err != nil || !res.OK {
		t.Fatalf("accept: %v %+v", err, res)
	}
	if _, err := pipeStream(e.nodes, "c3").DialMigrate(context.Background(), "c2", token); err == nil {
		t.Fatal("a node other than the source opened the migration stream")
	}
	c, err := pipeStream(e.nodes, "c1").DialMigrate(context.Background(), "c2", token)
	if err != nil {
		t.Fatalf("the source couldn't open its stream: %v", err)
	}
	c.Close()
	if _, err := pipeStream(e.nodes, "c1").DialMigrate(context.Background(), "c2", token); err == nil {
		t.Fatal("an admission's stream was opened twice")
	}
}
