package storagesvc

// The storage server's side of "Make highly available" and "Make local
// again" (docs/plans/make-ha.md, decisions 480-482): peer calls that open
// a zfs stream into or out of cluster storage for a compute server, adopt
// what arrived, park and put back cluster copies, and the one-time copy
// connections (ALPN hardyos-copy/1) that carry the bytes. Every call that
// changes cluster storage needs an administrator's signed request from
// an active compute server; copy connections are accepted only with a
// token this server handed to that same server less than a minute ago.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
)

// FilePriv is the part of priv.Client that hands over a stream's file.
type FilePriv interface {
	CallFile(ctx context.Context, op string, args, out any) (*os.File, error)
}

// HACopyTokenTTL is how long a copy token waits for its connection.
const HACopyTokenTTL = time.Minute

// Copy protocol lines on hardyos-copy/1.
const (
	copyHello  = "hardyos-copy "
	copyOK     = "ok"
	copyDoneOK = "done ok"
)

// HAStreamRequest opens one dataset's stream on the storage server.
type HAStreamRequest struct {
	Workload cluster.WorkloadRef `json:"workload"`
	// Pool is the storage server's pool the conversion uses (until the
	// workload is registered; then its placement's).
	Pool string `json:"pool,omitempty"`
	// Recv (a compute server sends into cluster storage): Conv, Child,
	// Label. Send (cluster storage sends back): Child, From, To or Token.
	Conv  string        `json:"conv,omitempty"`
	Child string        `json:"child,omitempty"`
	Label string        `json:"label,omitempty"`
	From  string        `json:"from,omitempty"`
	To    string        `json:"to,omitempty"`
	Token string        `json:"token,omitempty"`
	Actor cluster.Actor `json:"actor"`
}

// HAStreamOpened is the answer: a one-time token for the copy connection
// and root's stream id there.
type HAStreamOpened struct {
	Token  string `json:"token"`
	Stream string `json:"stream"`
}

// HARequest names a workload's cluster copy (tree, adopt, abort, park,
// put back, snapshot).
type HARequest struct {
	Workload cluster.WorkloadRef `json:"workload"`
	Pool     string              `json:"pool,omitempty"`
	Conv     string              `json:"conv,omitempty"`
	Name     string              `json:"name,omitempty"`
	// KeepUntil (unix seconds) is a parked copy's expiry (0: kept).
	KeepUntil int64         `json:"keepUntil,omitempty"`
	Confirm   string        `json:"confirm,omitempty"`
	Actor     cluster.Actor `json:"actor"`
}

// HAParkedDestroy deletes a parked copy on the storage server now.
type HAParkedDestroy struct {
	Pool    string        `json:"pool"`
	Name    string        `json:"name"`
	Confirm string        `json:"confirm"`
	Actor   cluster.Actor `json:"actor"`
}

// copySession is one open stream waiting for (or using) its connection.
type copySession struct {
	token   string
	node    cluster.NodeID
	recv    bool // bytes flow from the compute server into root's receive
	file    *os.File
	stream  string
	expires time.Time
}

type copySessions struct {
	mu sync.Mutex
	m  map[string]*copySession
}

func (c *copySessions) add(cs *copySession) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*copySession{}
	}
	now := time.Now()
	for t, o := range c.m {
		if now.After(o.expires) {
			o.file.Close()
			delete(c.m, t)
		}
	}
	c.m[cs.token] = cs
}

// take hands out a session once, to the node it was made for.
func (c *copySessions) take(token string, node cluster.NodeID) *copySession {
	c.mu.Lock()
	defer c.mu.Unlock()
	for t, cs := range c.m {
		if subtle.ConstantTimeCompare([]byte(t), []byte(token)) == 1 {
			delete(c.m, t)
			if cs.node != node || time.Now().After(cs.expires) {
				cs.file.Close()
				return nil
			}
			return cs
		}
	}
	return nil
}

var haCopies copySessions

func newCopyToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// storagePool is the cluster's pool on the storage server (run there):
// where its workloads are, or (none yet) its largest healthy data pool.
func (s *Service) storagePool(snap *cluster.Snapshot) (string, error) {
	pools := map[string]int{}
	for _, p := range snap.Placements {
		if p.Storage.Pool != "" {
			pools[p.Storage.Pool]++
		}
	}
	best, n := "", 0
	for p, c := range pools {
		if c > n || (c == n && p < best) {
			best, n = p, c
		}
	}
	if best != "" {
		return best, nil
	}
	var l []struct {
		Name      string `json:"name"`
		SizeBytes uint64 `json:"sizeBytes"`
		Health    string `json:"health"`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Priv.Call(ctx, "zfs.pools", nil, &l); err != nil {
		return "", err
	}
	var size uint64
	for _, p := range l {
		switch p.Name {
		case "rpool", "bpool", "boot-pool", "hardyos-boot":
			continue
		}
		if (p.Health == "ONLINE" || p.Health == "DEGRADED") && p.SizeBytes > size {
			best, size = p.Name, p.SizeBytes
		}
	}
	if best == "" {
		return "", errors.New("the storage server has no data pool for cluster storage")
	}
	return best, nil
}

// HAPool reports the cluster pool on the storage server (any member).
func (s *Service) HAPool(ctx context.Context) (string, error) {
	var out struct {
		Pool string `json:"pool"`
	}
	err := s.onStorage(ctx, "storage/ha/pool", struct{}{}, &out, cluster.Actor{}, func(snap *cluster.Snapshot, _ cluster.Node) error {
		p, err := s.storagePool(snap)
		out.Pool = p
		return err
	})
	return out.Pool, err
}

// clusterRef names a workload's cluster datasets: on its placement's pool,
// else on the pool the conversion chose (pool), else the cluster's.
func (s *Service) clusterRef(snap *cluster.Snapshot, w cluster.WorkloadRef, pool string) (hacopy.Ref, error) {
	if p := snap.Placements[w]; p != nil && p.Storage.Pool != "" {
		return hacopy.Ref{Kind: w.Kind, ID: w.ID, Pool: p.Storage.Pool, Side: hacopy.SideCluster}, nil
	}
	if pool != "" {
		return hacopy.Ref{Kind: w.Kind, ID: w.ID, Pool: pool, Side: hacopy.SideCluster}, nil
	}
	pool, err := s.storagePool(snap)
	return hacopy.Ref{Kind: w.Kind, ID: w.ID, Pool: pool, Side: hacopy.SideCluster}, err
}

// HAOpenRecv opens a receive into the storage server's incoming copy of
// a workload (an HA conversion).
func (s *Service) HAOpenRecv(ctx context.Context, r HAStreamRequest) (*HAStreamOpened, error) {
	var out HAStreamOpened
	err := s.onStorage(ctx, "storage/ha/recv", r, &out, r.Actor, func(*cluster.Snapshot, cluster.Node) error {
		return errors.New("the storage server can't convert its own workloads")
	})
	return &out, err
}

// HAOpenSend opens a send of a cluster workload's dataset (make local).
func (s *Service) HAOpenSend(ctx context.Context, r HAStreamRequest) (*HAStreamOpened, error) {
	var out HAStreamOpened
	err := s.onStorage(ctx, "storage/ha/send", r, &out, r.Actor, func(*cluster.Snapshot, cluster.Node) error {
		return errors.New("the storage server can't convert its own workloads")
	})
	return &out, err
}

// HAStream reports one of root's streams on the storage server.
func (s *Service) HAStream(ctx context.Context, stream string) (*hacopy.StreamState, error) {
	var out hacopy.StreamState
	err := s.onStorage(ctx, "storage/ha/stream", map[string]string{"stream": stream}, &out, cluster.Actor{}, func(*cluster.Snapshot, cluster.Node) error {
		return s.Priv.Call(ctx, hacopy.OpStream, hacopy.StreamArgs{Stream: stream}, &out)
	})
	return &out, err
}

// HATree lists a workload's cluster datasets, or (Conv) its incoming copy.
func (s *Service) HATree(ctx context.Context, r HARequest) (*hacopy.Tree, error) {
	var out hacopy.Tree
	err := s.onStorage(ctx, "storage/ha/tree", r, &out, r.Actor, func(snap *cluster.Snapshot, _ cluster.Node) error {
		ref, err := s.clusterRef(snap, r.Workload, r.Pool)
		if err != nil {
			return err
		}
		return s.Priv.Call(ctx, hacopy.OpTree, hacopy.TreeArgs{Ref: ref, Conv: r.Conv}, &out)
	})
	return &out, err
}

// HAAdopt makes what a conversion received the workload's cluster
// storage; it returns the storage to register with workload.add.
func (s *Service) HAAdopt(ctx context.Context, r HARequest) (*cluster.WorkloadStorage, error) {
	var out cluster.WorkloadStorage
	err := s.onStorage(ctx, "storage/ha/adopt", r, &out, r.Actor, func(*cluster.Snapshot, cluster.Node) error {
		return errors.New("the storage server can't convert its own workloads")
	})
	return &out, err
}

// HAAbort destroys a conversion's incoming copy on the storage server.
func (s *Service) HAAbort(ctx context.Context, r HARequest) error {
	return s.onStorage(ctx, "storage/ha/abort", r, nil, r.Actor, func(*cluster.Snapshot, cluster.Node) error {
		return errors.New("the storage server can't convert its own workloads")
	})
}

// HASnapshot takes a conversion snapshot of a stopped cluster workload.
func (s *Service) HASnapshot(ctx context.Context, r HARequest) error {
	return s.onStorage(ctx, "storage/ha/snapshot", r, nil, r.Actor, func(*cluster.Snapshot, cluster.Node) error {
		return errors.New("the storage server can't convert its own workloads")
	})
}

// HAPark parks a removed workload's cluster copy for its grace period.
func (s *Service) HAPark(ctx context.Context, r HARequest) (*hacopy.ParkResult, error) {
	var out hacopy.ParkResult
	err := s.onStorage(ctx, "storage/ha/park", r, &out, r.Actor, func(*cluster.Snapshot, cluster.Node) error {
		return errors.New("the storage server can't convert its own workloads")
	})
	return &out, err
}

// HAParked lists the parked copies on the storage server.
func (s *Service) HAParked(ctx context.Context) ([]hacopy.Parked, error) {
	var out struct {
		Parked []hacopy.Parked `json:"parked"`
	}
	err := s.onStorage(ctx, "storage/ha/parked", struct{}{}, &out, cluster.Actor{}, func(*cluster.Snapshot, cluster.Node) error {
		return s.Priv.Call(ctx, hacopy.OpParkedList, struct{}{}, &out)
	})
	if out.Parked == nil {
		out.Parked = []hacopy.Parked{}
	}
	return out.Parked, err
}

// HAParkedDestroy deletes a parked copy on the storage server.
func (s *Service) HAParkedDestroy(ctx context.Context, r HAParkedDestroy) error {
	return s.onStorage(ctx, "storage/ha/parked/destroy", r, nil, r.Actor, func(*cluster.Snapshot, cluster.Node) error {
		err := s.Priv.Call(ctx, hacopy.OpParkedDestroy, hacopy.ParkedDestroyArgs{Pool: r.Pool, Name: r.Name, Confirm: r.Confirm}, nil)
		s.audit(ctx, r.Actor, "cluster.ha.parked.destroy", r.Pool+"/"+r.Name, err)
		return err
	})
}

// HAParkedKeep sets a parked copy's expiry on the storage server.
func (s *Service) HAParkedKeep(ctx context.Context, r HARequest) error {
	return s.onStorage(ctx, "storage/ha/parked/keep", r, nil, r.Actor, func(*cluster.Snapshot, cluster.Node) error {
		return s.Priv.Call(ctx, hacopy.OpParkedKeep, hacopy.ParkedKeepArgs{Pool: r.Pool, Name: r.Name, KeepUntil: r.KeepUntil}, nil)
	})
}

// HAUnpark puts a parked cluster copy back (an undone "make local").
func (s *Service) HAUnpark(ctx context.Context, r HARequest) error {
	return s.onStorage(ctx, "storage/ha/unpark", r, nil, r.Actor, func(*cluster.Snapshot, cluster.Node) error {
		return errors.New("the storage server can't convert its own workloads")
	})
}

// ---- storage server side -----------------------------------------------------------

// activeCompute: only an active compute server converts.
func activeCompute(c cluster.Node) error {
	if c.Role != cluster.RoleCompute || c.State != cluster.NodeActive {
		return &forbidden{errors.New("only an active compute server moves workloads to or from cluster storage")}
	}
	return nil
}

func (s *Service) registerHAPeer(h func(path string, fn func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error)),
	storage func(fn func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error)) func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error),
	decode func(b []byte, v any) error) {
	// An administrator's conversion, from the compute server running it.
	admin := func(what string, fn func(r *http.Request, c cluster.Node, q asked, b []byte, snap *cluster.Snapshot) (any, error)) func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		return storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
			if err := activeCompute(c); err != nil {
				return nil, err
			}
			if err := needAdmin(q, what); err != nil {
				return nil, err
			}
			_, snap, err := s.self()
			if err != nil {
				return nil, err
			}
			return fn(r, c, q, b, snap)
		})
	}
	h("ha/pool", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		_, snap, err := s.self()
		if err != nil {
			return nil, err
		}
		p, err := s.storagePool(snap)
		return map[string]string{"pool": p}, err
	}))
	h("ha/stream", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p hacopy.StreamArgs
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		var out hacopy.StreamState
		return &out, s.Priv.Call(r.Context(), hacopy.OpStream, p, &out)
	}))
	h("ha/parked", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var out struct {
			Parked []hacopy.Parked `json:"parked"`
		}
		return &out, s.Priv.Call(r.Context(), hacopy.OpParkedList, struct{}{}, &out)
	}))
	h("ha/tree", storage(func(r *http.Request, c cluster.Node, q asked, b []byte) (any, error) {
		var p HARequest
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		_, snap, err := s.self()
		if err != nil {
			return nil, err
		}
		ref, err := s.clusterRef(snap, p.Workload, p.Pool)
		if err != nil {
			return nil, err
		}
		var out hacopy.Tree
		return &out, s.Priv.Call(r.Context(), hacopy.OpTree, hacopy.TreeArgs{Ref: ref, Conv: p.Conv}, &out)
	}))
	h("ha/recv", admin("moving a workload to cluster storage", func(r *http.Request, c cluster.Node, q asked, b []byte, snap *cluster.Snapshot) (any, error) {
		var p HAStreamRequest
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		if snap.Placements[p.Workload] != nil {
			return nil, &forbidden{fmt.Errorf("%s is a cluster workload already", p.Workload.ID)}
		}
		ref, err := s.clusterRef(snap, p.Workload, p.Pool)
		if err != nil {
			return nil, err
		}
		return s.openStream(r.Context(), c.ID, true, hacopy.OpRecv, hacopy.RecvArgs{Ref: ref, Conv: p.Conv, Child: p.Child, Label: p.Label})
	}))
	h("ha/send", admin("copying a workload off cluster storage", func(r *http.Request, c cluster.Node, q asked, b []byte, snap *cluster.Snapshot) (any, error) {
		var p HAStreamRequest
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		pl := snap.Placements[p.Workload]
		if pl == nil || !stopped(pl) || pl.Requested != cluster.RequestStopped {
			return nil, &forbidden{fmt.Errorf("%s must be a stopped cluster workload", p.Workload.ID)}
		}
		ref, err := s.clusterRef(snap, p.Workload, p.Pool)
		if err != nil {
			return nil, err
		}
		return s.openStream(r.Context(), c.ID, false, hacopy.OpSend, hacopy.SendArgs{Ref: ref, Child: p.Child, From: p.From, To: p.To, Token: p.Token})
	}))
	h("ha/snapshot", admin("snapshotting a workload to move it", func(r *http.Request, c cluster.Node, q asked, b []byte, snap *cluster.Snapshot) (any, error) {
		var p HARequest
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		pl := snap.Placements[p.Workload]
		if pl == nil || !stopped(pl) || pl.Requested != cluster.RequestStopped {
			return nil, &forbidden{fmt.Errorf("%s must be a stopped cluster workload", p.Workload.ID)}
		}
		ref, err := s.clusterRef(snap, p.Workload, p.Pool)
		if err != nil {
			return nil, err
		}
		err = s.Priv.Call(r.Context(), hacopy.OpSnapshot, hacopy.SnapArgs{Ref: ref, Name: p.Name}, nil)
		return ok(err)
	}))
	h("ha/adopt", admin("moving a workload to cluster storage", func(r *http.Request, c cluster.Node, q asked, b []byte, snap *cluster.Snapshot) (any, error) {
		var p HARequest
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		if snap.Placements[p.Workload] != nil {
			return nil, &forbidden{fmt.Errorf("%s is a cluster workload already", p.Workload.ID)}
		}
		ref, err := s.clusterRef(snap, p.Workload, p.Pool)
		if err != nil {
			return nil, err
		}
		var res hacopy.AdoptResult
		err = s.Priv.Call(r.Context(), hacopy.OpAdopt, hacopy.AdoptArgs{Ref: ref, Conv: p.Conv, Cluster: snap.Cluster}, &res)
		s.audit(r.Context(), q.Actor, "cluster.ha.adopt", string(p.Workload.Kind)+" "+p.Workload.ID, err)
		if err != nil {
			return nil, err
		}
		return storageOf(ref, &res), nil
	}))
	h("ha/abort", admin("abandoning a conversion's copy", func(r *http.Request, c cluster.Node, q asked, b []byte, snap *cluster.Snapshot) (any, error) {
		var p HARequest
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		ref, err := s.clusterRef(snap, p.Workload, p.Pool)
		if err != nil {
			return nil, err
		}
		err = s.Priv.Call(r.Context(), hacopy.OpAbort, hacopy.AbortArgs{Ref: ref, Conv: p.Conv}, nil)
		s.audit(r.Context(), q.Actor, "cluster.ha.abort", string(p.Workload.Kind)+" "+p.Workload.ID, err)
		return ok(err)
	}))
	h("ha/park", admin("removing a workload from cluster storage", func(r *http.Request, c cluster.Node, q asked, b []byte, snap *cluster.Snapshot) (any, error) {
		var p HARequest
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		// Only once the cluster forgot it (workload.remove): nothing can
		// be granted it any more, and root refuses while LIO or NFS still
		// has it.
		if snap.Placements[p.Workload] != nil {
			return nil, &forbidden{fmt.Errorf("%s is still a cluster workload", p.Workload.ID)}
		}
		ref, err := s.clusterRef(snap, p.Workload, p.Pool)
		if err != nil {
			return nil, err
		}
		if s.reconcile != nil {
			_ = s.reconcile(r.Context())
		}
		var res hacopy.ParkResult
		err = s.Priv.Call(r.Context(), hacopy.OpPark, hacopy.ParkArgs{Ref: ref, Confirm: p.Confirm, KeepUntil: p.KeepUntil}, &res)
		s.audit(r.Context(), q.Actor, "cluster.ha.park", string(p.Workload.Kind)+" "+p.Workload.ID, err)
		if err != nil {
			return nil, err
		}
		return &res, nil
	}))
	h("ha/unpark", admin("putting a workload's cluster copy back", func(r *http.Request, c cluster.Node, q asked, b []byte, snap *cluster.Snapshot) (any, error) {
		var p HARequest
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		if snap.Placements[p.Workload] != nil {
			return nil, &forbidden{fmt.Errorf("%s is a cluster workload", p.Workload.ID)}
		}
		ref, err := s.clusterRef(snap, p.Workload, p.Pool)
		if err != nil {
			return nil, err
		}
		err = s.Priv.Call(r.Context(), hacopy.OpUnpark, hacopy.UnparkArgs{Ref: ref, Name: p.Name}, nil)
		s.audit(r.Context(), q.Actor, "cluster.ha.unpark", string(p.Workload.Kind)+" "+p.Workload.ID, err)
		return ok(err)
	}))
	h("ha/parked/keep", admin("keeping a copy", func(r *http.Request, c cluster.Node, q asked, b []byte, snap *cluster.Snapshot) (any, error) {
		var p HARequest
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		err := s.Priv.Call(r.Context(), hacopy.OpParkedKeep, hacopy.ParkedKeepArgs{Pool: p.Pool, Name: p.Name, KeepUntil: p.KeepUntil}, nil)
		return ok(err)
	}))
	h("ha/parked/destroy", admin("deleting a kept copy", func(r *http.Request, c cluster.Node, q asked, b []byte, snap *cluster.Snapshot) (any, error) {
		var p HAParkedDestroy
		if err := decode(b, &p); err != nil {
			return nil, err
		}
		err := s.Priv.Call(r.Context(), hacopy.OpParkedDestroy, hacopy.ParkedDestroyArgs{Pool: p.Pool, Name: p.Name, Confirm: p.Confirm}, nil)
		s.audit(r.Context(), q.Actor, "cluster.ha.parked.destroy", p.Pool+"/"+p.Name, err)
		return ok(err)
	}))
}

// storageOf is the workload storage of an adopted cluster copy.
func storageOf(ref hacopy.Ref, res *hacopy.AdoptResult) *cluster.WorkloadStorage {
	ws := &cluster.WorkloadStorage{Pool: ref.Pool}
	kind := cluster.ExportVMState
	if ref.Kind == cluster.KindApp {
		kind = cluster.ExportAppData
		ws.Mode = cluster.StorageNFS
	}
	ws.Exports = []cluster.Export{{Kind: kind, Dataset: res.Dataset, Path: res.Mountpoint,
		MountPath: cluster.RemoteMountRoot + "/" + res.Dataset, FSID: res.GUID}}
	for _, v := range res.Volumes {
		ws.Volumes = append(ws.Volumes, cluster.Volume{Dataset: v.Dataset, Disk: v.Disk, SizeGB: v.SizeGB, WWN: v.WWN})
	}
	return ws
}

// openStream asks root for a stream and keeps its file for the compute
// server's copy connection.
func (s *Service) openStream(ctx context.Context, node cluster.NodeID, recv bool, op string, args any) (*HAStreamOpened, error) {
	fp, ok := s.Priv.(FilePriv)
	if !ok {
		return nil, errors.New("root can't hand over streams here")
	}
	var st hacopy.StreamStart
	f, err := fp.CallFile(ctx, op, args, &st)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, errors.New("root didn't hand over the stream")
	}
	cs := &copySession{token: newCopyToken(), node: node, recv: recv, file: f, stream: st.Stream, expires: time.Now().Add(HACopyTokenTTL)}
	haCopies.add(cs)
	return &HAStreamOpened{Token: cs.token, Stream: st.Stream}, nil
}

// ServeCopy serves one hardyos-copy/1 connection from a compute server:
// its token line, then the stream's bytes one way, then (into cluster
// storage) root's verdict.
func (s *Service) ServeCopy(conn net.Conn, from cluster.Node) {
	defer conn.Close()
	if me, _, err := s.self(); err != nil || me.Role != cluster.RoleStorage || from.Role != cluster.RoleCompute {
		return // only the storage server serves copies, to compute servers
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReaderSize(conn, 4096)
	line, err := br.ReadString('\n')
	if err != nil || len(line) > 200 {
		return
	}
	tok, ok := strings.CutPrefix(strings.TrimSpace(line), copyHello)
	if !ok {
		return
	}
	cs := haCopies.take(tok, from.ID)
	if cs == nil {
		_, _ = io.WriteString(conn, "no unknown or expired copy token\n")
		s.log().Warn("storage: refused an HA copy connection", "from", from.ID)
		return
	}
	defer cs.file.Close()
	if _, err := io.WriteString(conn, copyOK+"\n"); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if !cs.recv {
		_, err := io.Copy(conn, cs.file)
		if err != nil {
			s.log().Warn("storage: an HA copy from cluster storage broke off", "to", from.ID, "err", err)
		}
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		return
	}
	_, err = io.Copy(cs.file, br)
	cs.file.Close()
	verdict := copyDoneOK
	if err != nil {
		verdict = "done error " + err.Error()
	} else if st := s.waitStream(cs.stream); !st.OK {
		verdict = "done error " + st.Error
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(conn, verdict+"\n")
}

// waitStream waits for root's stream to end (up to ten minutes after its
// input closed: zfs receive finishing its last writes).
func (s *Service) waitStream(id string) hacopy.StreamState {
	deadline := time.Now().Add(10 * time.Minute)
	for {
		var st hacopy.StreamState
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := s.Priv.Call(ctx, hacopy.OpStream, hacopy.StreamArgs{Stream: id}, &st)
		cancel()
		if err == nil && st.Done {
			return st
		}
		if time.Now().After(deadline) {
			return hacopy.StreamState{ID: id, Done: true, Error: "the storage server's receive didn't finish"}
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// ---- compute side: the copy connection ------------------------------------------------

// CopyDialer dials the storage server's hardyos-copy/1.
type CopyDialer func(ctx context.Context, node cluster.NodeID) (net.Conn, error)

// HACopyConn dials the storage server for an opened stream and returns
// the connection ready for the stream's bytes.
func (s *Service) HACopyConn(ctx context.Context, dial CopyDialer, token string) (net.Conn, *bufio.Reader, error) {
	_, snap, err := s.self()
	if err != nil {
		return nil, nil, err
	}
	sn, ok := StorageNode(snap)
	if !ok {
		return nil, nil, ErrNoStorageNode
	}
	conn, err := dial(ctx, sn.ID)
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(conn, copyHello+token+"\n"); err != nil {
		conn.Close()
		return nil, nil, err
	}
	br := bufio.NewReaderSize(conn, 64<<10)
	line, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("the storage server's copy connection: %w", err)
	}
	if strings.TrimSpace(line) != copyOK {
		conn.Close()
		return nil, nil, fmt.Errorf("the storage server refused the copy: %s", strings.TrimPrefix(strings.TrimSpace(line), "no "))
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, br, nil
}

// CopyVerdict reads the storage server's verdict after a stream into it.
func CopyVerdict(br *bufio.Reader) error {
	line, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("the storage server didn't say how the copy went: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == copyDoneOK {
		return nil
	}
	return fmt.Errorf("the storage server's receive failed: %s", strings.TrimPrefix(line, "done error "))
}
