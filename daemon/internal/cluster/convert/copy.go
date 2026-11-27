package convert

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
	"github.com/hardyos/hardyos/daemon/internal/cluster/storagesvc"
	"github.com/hardyos/hardyos/daemon/internal/replica"
)

// Conn is an opened copy connection to the storage server.
type Conn interface {
	io.ReadWriteCloser
	// CloseWrite ends the stream into the storage server.
	CloseWrite() error
	// Verdict reads the storage server's verdict on a stream into it.
	Verdict() error
}

// ServiceStorage is Storage on part B's service, dialing copy
// connections with Dial (the cluster port's hardyos-copy/1).
type ServiceStorage struct {
	*storagesvc.Service
	Dial storagesvc.CopyDialer
}

type svcConn struct {
	net.Conn
	br *bufio.Reader
}

func (s svcConn) Read(p []byte) (int, error) { return s.br.Read(p) }

func (s svcConn) CloseWrite() error {
	if cw, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("the copy connection can't be half-closed")
}

func (s svcConn) Verdict() error { return storagesvc.CopyVerdict(s.br) }

// CopyConn implements Storage.
func (s ServiceStorage) CopyConn(ctx context.Context, token string) (Conn, error) {
	if s.Dial == nil {
		return nil, errors.New("this server can't open copy connections")
	}
	c, br, err := s.Service.HACopyConn(ctx, s.Dial, token)
	if err != nil {
		return nil, err
	}
	return svcConn{Conn: c, br: br}, nil
}

// counter reports bytes as they pass.
type counter struct {
	n    atomic.Int64
	tick func(n int64)
	last time.Time
}

func (c *counter) add(n int) {
	v := c.n.Add(int64(n))
	if c.tick != nil && time.Since(c.last) > time.Second {
		c.last = time.Now()
		c.tick(v)
	}
}

type countWriter struct {
	w io.Writer
	c *counter
}

func (w countWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.c.add(n)
	return n, err
}

// step is one stream: a dataset's full stream, an increment, or the rest
// of an interrupted one.
type step struct {
	Child string
	From  string
	To    string
	Token string
}

// plan lists the streams that bring dst up to src's snapshots, dataset by
// dataset (the state folder first): src's oldest snapshot in full, then
// every later one as an increment, from the newest snapshot both have.
func plan(src, dst *hacopy.Tree) ([]step, error) {
	have := map[string]hacopy.TreeDataset{}
	if dst != nil {
		for _, d := range dst.Datasets {
			have[d.Child] = d
		}
	}
	if p := snapsProblem(src); p != "" {
		return nil, errors.New(p)
	}
	var out []step
	for _, s := range src.Datasets {
		if len(s.Snaps) == 0 {
			return nil, fmt.Errorf("%s has no snapshot to send", childName(s.Child))
		}
		d, ok := have[s.Child]
		if ok && d.Token != "" {
			// The rest of an interrupted stream first; then plan again.
			tok, err := replica.DecodeToken(d.Token)
			if err != nil {
				return nil, fmt.Errorf("%s's interrupted copy can't be resumed (%v); abandon it and start again", childName(s.Child), err)
			}
			_, label, _ := strings.Cut(tok.ToName, "@")
			out = append(out, step{Child: s.Child, To: label, Token: d.Token})
			continue
		}
		start := 0
		from := ""
		if ok && len(d.Snaps) > 0 {
			last := d.Snaps[len(d.Snaps)-1]
			idx := -1
			for i, sn := range s.Snaps {
				if sn.GUID == last.GUID && sn.Name == last.Name {
					idx = i
				}
			}
			if idx < 0 {
				return nil, fmt.Errorf("the copy of %s has a snapshot (%s) the source doesn't; abandon it and start again", childName(s.Child), last.Name)
			}
			start, from = idx+1, last.Name
		}
		for i := start; i < len(s.Snaps); i++ {
			out = append(out, step{Child: s.Child, From: from, To: s.Snaps[i].Name})
			from = s.Snaps[i].Name
		}
	}
	return out, nil
}

func childName(c string) string {
	if c == "" {
		return "its settings folder"
	}
	return c
}

func treeBytes(t *hacopy.Tree) int64 {
	var n int64
	for _, d := range t.Datasets {
		n += d.Used
	}
	return n
}

// refOf is what a local ref names on the storage server's side (the
// workload, or a shared folder that moves with an app).
func refOf(local hacopy.Ref) cluster.WorkloadRef {
	return cluster.WorkloadRef{Kind: local.Kind, ID: local.ID}
}

// convFor is the conversion id a local ref's copy is received under: the
// conversion's own, or a shared folder's (ShareMove.Conv).
func convFor(r *Record, local hacopy.Ref) string {
	if local.Kind == hacopy.KindShare {
		for _, s := range r.Options.Shares {
			if s.ID == local.ID {
				return s.Conv
			}
		}
		return "" // refused by both sides: never the app's own copy
	}
	return r.ID
}

// sendToStorage copies a local workload's datasets into the storage
// server's incoming copy until every snapshot is there.
func (c *Converter) sendToStorage(ctx context.Context, r *Record, local hacopy.Ref, actor cluster.Actor, report func(done, total int64)) error {
	for round := 0; round < 3; round++ {
		var src hacopy.Tree
		if err := c.Priv.Call(ctx, hacopy.OpTree, hacopy.TreeArgs{Ref: local}, &src); err != nil {
			return err
		}
		dst, err := c.Storage.HATree(ctx, storagesvc.HARequest{Workload: refOf(local), Pool: r.StoragePool, Conv: convFor(r, local)})
		if err != nil {
			return err
		}
		steps, err := plan(&src, dst)
		if err != nil {
			return err
		}
		if len(steps) == 0 {
			return nil
		}
		total := treeBytes(&src)
		r.BytesTotal = total
		done := treeBytes(dst)
		for _, st := range steps {
			n, err := c.pushStep(ctx, r, local, st, actor, func(n int64) { report(done+n, total) })
			done += n
			if err != nil {
				return err
			}
		}
	}
	return errors.New("the copy didn't catch up with the source")
}

func (c *Converter) pushStep(ctx context.Context, r *Record, local hacopy.Ref, st step, actor cluster.Actor, tick func(int64)) (int64, error) {
	open, err := c.Storage.HAOpenRecv(ctx, storagesvc.HAStreamRequest{Workload: refOf(local), Pool: r.StoragePool, Conv: convFor(r, local),
		Child: st.Child, Label: st.To, Actor: actor})
	if err != nil {
		return 0, fmt.Errorf("the storage server: %w", err)
	}
	var ss hacopy.StreamStart
	f, err := c.Priv.CallFile(ctx, hacopy.OpSend, hacopy.SendArgs{Ref: local, Child: st.Child, From: st.From, To: st.To, Token: st.Token}, &ss)
	if err != nil {
		c.cancelRemote(open.Stream, actor)
		return 0, err
	}
	defer f.Close()
	conn, err := c.Storage.CopyConn(ctx, open.Token)
	if err != nil {
		c.cancelLocal(ss.Stream)
		c.cancelRemote(open.Stream, actor)
		return 0, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
		f.Close()
		c.cancelLocal(ss.Stream)
	})
	defer stop()
	cnt := &counter{tick: tick}
	_, cerr := io.Copy(countWriter{w: conn, c: cnt}, f)
	if cerr == nil {
		cerr = conn.CloseWrite()
	}
	if cerr == nil {
		cerr = conn.Verdict()
	}
	if err := ctx.Err(); err != nil {
		c.cancelRemote(open.Stream, actor)
		return cnt.n.Load(), err
	}
	if lerr := c.waitLocal(ctx, ss.Stream); lerr != nil && cerr == nil {
		cerr = lerr
	}
	if cerr != nil {
		c.cancelRemote(open.Stream, actor)
		return cnt.n.Load(), fmt.Errorf("copying %s: %w", childName(st.Child), cerr)
	}
	return cnt.n.Load(), nil
}

// pullFromStorage copies a cluster workload's datasets into this
// server's incoming copy.
func (c *Converter) pullFromStorage(ctx context.Context, r *Record, local hacopy.Ref, actor cluster.Actor, report func(done, total int64)) error {
	for round := 0; round < 3; round++ {
		src, err := c.Storage.HATree(ctx, storagesvc.HARequest{Workload: r.Ref()})
		if err != nil {
			return err
		}
		var dst hacopy.Tree
		if err := c.Priv.Call(ctx, hacopy.OpTree, hacopy.TreeArgs{Ref: local, Conv: r.ID}, &dst); err != nil {
			return err
		}
		steps, err := plan(src, &dst)
		if err != nil {
			return err
		}
		if len(steps) == 0 {
			return nil
		}
		total := treeBytes(src)
		r.BytesTotal = total
		done := treeBytes(&dst)
		for _, st := range steps {
			n, err := c.pullStep(ctx, r, local, st, actor, func(n int64) { report(done+n, total) })
			done += n
			if err != nil {
				return err
			}
		}
	}
	return errors.New("the copy didn't catch up with the source")
}

func (c *Converter) pullStep(ctx context.Context, r *Record, local hacopy.Ref, st step, actor cluster.Actor, tick func(int64)) (int64, error) {
	var ss hacopy.StreamStart
	f, err := c.Priv.CallFile(ctx, hacopy.OpRecv, hacopy.RecvArgs{Ref: local, Conv: r.ID, Child: st.Child, Label: st.To}, &ss)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	open, err := c.Storage.HAOpenSend(ctx, storagesvc.HAStreamRequest{Workload: r.Ref(), Child: st.Child, From: st.From, To: st.To,
		Token: st.Token, Actor: actor})
	if err != nil {
		c.cancelLocal(ss.Stream)
		return 0, fmt.Errorf("the storage server: %w", err)
	}
	conn, err := c.Storage.CopyConn(ctx, open.Token)
	if err != nil {
		c.cancelLocal(ss.Stream)
		c.cancelRemote(open.Stream, actor)
		return 0, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() {
		conn.Close()
		f.Close()
		c.cancelLocal(ss.Stream)
	})
	defer stop()
	cnt := &counter{tick: tick}
	_, cerr := io.Copy(countWriter{w: f, c: cnt}, conn)
	if cerr != nil {
		c.cancelRemote(open.Stream, actor)
	}
	f.Close()
	if err := ctx.Err(); err != nil {
		c.cancelRemote(open.Stream, actor)
		return cnt.n.Load(), err
	}
	if lerr := c.waitLocal(ctx, ss.Stream); lerr != nil {
		cerr = lerr
	}
	if rs, err := c.Storage.HAStream(ctx, open.Stream); err == nil && rs.Done && !rs.OK && cerr == nil {
		cerr = errors.New(rs.Error)
	}
	if cerr != nil {
		return cnt.n.Load(), fmt.Errorf("copying %s: %w", childName(st.Child), cerr)
	}
	return cnt.n.Load(), nil
}

// cancelRemote gives up the storage server's side of a stream (its own
// timer would, a minute later; this frees the dataset now).
func (c *Converter) cancelRemote(stream string, actor cluster.Actor) {
	if stream == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Storage.HACancel(ctx, stream, actor); err != nil {
		c.log().Debug("convert: cancelling the storage server's stream", "stream", stream, "err", err)
	}
}

func (c *Converter) cancelLocal(stream string) {
	if stream == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = c.Priv.Call(ctx, hacopy.OpCancel, hacopy.StreamArgs{Stream: stream}, nil)
}

// waitLocal waits for this server's stream to finish and says how it went.
func (c *Converter) waitLocal(ctx context.Context, stream string) error {
	deadline := c.now().Add(10 * time.Minute)
	for {
		var st hacopy.StreamState
		err := c.Priv.Call(ctx, hacopy.OpStream, hacopy.StreamArgs{Stream: stream}, &st)
		if err == nil && st.Done {
			if !st.OK {
				return errors.New(st.Error)
			}
			return nil
		}
		if c.now().After(deadline) {
			return errors.New("this server's side of the copy didn't finish")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

var _ Storage = ServiceStorage{}
