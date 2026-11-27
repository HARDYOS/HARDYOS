package hacopy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/replica"
)

// sendFlags: large blocks, embedded data and compressed blocks as they are
// on disk (as replication sends).
var sendFlags = []string{"-L", "-e", "-c"}

// MaxStreams bounds the transfers running at once.
const MaxStreams = 8

// MaxStreamTime bounds one transfer (a receive keeps its resume token).
const MaxStreamTime = 72 * time.Hour

// StreamStart answers ha.send and ha.recv (the file descriptor travels
// with it).
type StreamStart struct {
	Stream string `json:"stream"`
	// Estimate is zfs send's size estimate in bytes (sends only).
	Estimate int64 `json:"estimate,omitempty"`
}

// StreamState is a transfer's state (ha.stream).
type StreamState struct {
	ID    string `json:"id"`
	Done  bool   `json:"done"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Bytes int64  `json:"bytes"`
}

// StreamArgs names a transfer.
type StreamArgs struct {
	Stream string `json:"stream"`
}

type stream struct {
	id     string
	target string
	bytes  atomic.Int64

	mu     sync.Mutex
	proc   replica.Proc
	closer io.Closer
	done   bool
	killed bool
	err    error
	ended  time.Time
	timer  *time.Timer
}

func (s *stream) state() StreamState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := StreamState{ID: s.id, Done: s.done, Bytes: s.bytes.Load()}
	if s.done {
		st.OK = s.err == nil
		if s.err != nil {
			st.Error = s.err.Error()
		}
	}
	return st
}

func (s *stream) cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return
	}
	s.killed = true
	if s.proc != nil {
		s.proc.Kill()
	}
	if s.closer != nil {
		_ = s.closer.Close()
	}
}

func (s *stream) finish(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.killed {
		err = errors.New("cancelled")
	}
	s.done, s.err, s.ended = true, err, time.Now()
	if s.timer != nil {
		s.timer.Stop()
	}
}

type streams struct {
	mu   sync.Mutex
	byID map[string]*stream
}

var (
	// ErrTooMany: too many transfers run.
	ErrTooMany = errors.New("too many transfers are running; try again later")
	// ErrNoStream: no such transfer.
	ErrNoStream = errors.New("no such transfer")
	// ErrTargetBusy: a receive into that dataset runs.
	ErrTargetBusy = errors.New("a transfer into that dataset is already running")
)

func (r *streams) add(target string) (*stream, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byID == nil {
		r.byID = map[string]*stream{}
	}
	running := 0
	for id, s := range r.byID {
		st := s.state()
		if st.Done {
			s.mu.Lock()
			old := time.Since(s.ended) > 15*time.Minute
			s.mu.Unlock()
			if old {
				delete(r.byID, id)
			}
			continue
		}
		running++
		if target != "" && s.target == target {
			return nil, ErrTargetBusy
		}
	}
	if running >= MaxStreams {
		return nil, ErrTooMany
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	s := &stream{id: hex.EncodeToString(b), target: target}
	s.timer = time.AfterFunc(MaxStreamTime, s.cancel)
	r.byID[s.id] = s
	return s, nil
}

func (r *streams) get(id string) (*stream, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s := r.byID[id]; s != nil {
		return s, nil
	}
	return nil, ErrNoStream
}

// cancelTarget ends receives into ds or below it.
func (r *streams) cancelTarget(ds string) {
	r.mu.Lock()
	var l []*stream
	for _, s := range r.byID {
		if s.target == ds || strings.HasPrefix(s.target, ds+"/") {
			l = append(l, s)
		}
	}
	r.mu.Unlock()
	for _, s := range l {
		s.cancel()
	}
}

// Stream reports a transfer.
func (r *Root) Stream(id string) (*StreamState, error) {
	s, err := r.streams.get(id)
	if err != nil {
		return nil, err
	}
	st := s.state()
	return &st, nil
}

// Cancel ends a transfer.
func (r *Root) Cancel(id string) error {
	s, err := r.streams.get(id)
	if err != nil {
		return err
	}
	s.cancel()
	return nil
}

// tail keeps the end of a command's error output.
type tail struct {
	mu  sync.Mutex
	buf []byte
}

func (t *tail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > 4096 {
		t.buf = t.buf[len(t.buf)-4096:]
	}
	return len(p), nil
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.TrimSpace(string(t.buf))
}

type counting struct {
	r io.Reader
	n *atomic.Int64
}

func (c counting) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// ---- send ----------------------------------------------------------------------------

// SendArgs is ha.send: one dataset's snapshot To, as an increment from
// From when set, or the rest of an interrupted transfer (Token, from the
// receiving side).
type SendArgs struct {
	Ref
	Child string `json:"child,omitempty"`
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
	Token string `json:"token,omitempty"`
}

// Send starts zfs send of one of the workload's datasets and returns the
// read end of its output.
func (r *Root) Send(ctx context.Context, a SendArgs) (*StreamStart, *os.File, error) {
	if _, err := r.checkSource(ctx, a.Ref); err != nil {
		return nil, nil, err
	}
	ds, err := a.Ref.dataset(a.Child)
	if err != nil {
		return nil, nil, err
	}
	if _, ok := r.exists(ctx, ds); !ok {
		return nil, nil, invalid("%s doesn't exist", ds)
	}
	snaps, err := r.snaps(ctx, ds)
	if err != nil {
		return nil, nil, err
	}
	find := func(name string) (Snap, bool) {
		for _, s := range snaps {
			if s.Name == name {
				return s, true
			}
		}
		return Snap{}, false
	}
	var args []string
	if a.Token != "" {
		if err := replica.ValidToken(a.Token); err != nil {
			return nil, nil, invalid("%v", err)
		}
		// zfs send -t finds what to send by its GUIDs anywhere in the pool:
		// accept a token only for a snapshot of exactly this dataset.
		tok, err := replica.DecodeToken(a.Token)
		if err != nil {
			return nil, nil, invalid("%v", err)
		}
		tds, label, ok := strings.Cut(tok.ToName, "@")
		to, found := find(label)
		if !ok || tds != ds || !found || strconv.FormatUint(tok.ToGUID, 10) != to.GUID {
			return nil, nil, invalid("the resume token isn't for a snapshot of %s", ds)
		}
		if tok.HasFrom {
			okFrom := false
			for _, s := range snaps {
				if s.GUID == strconv.FormatUint(tok.FromGUID, 10) && s.TXG < to.TXG {
					okFrom = true
				}
			}
			if !okFrom {
				return nil, nil, invalid("the resume token builds on a snapshot %s doesn't have", ds)
			}
		}
		args = []string{"send", "-t", a.Token}
	} else {
		to, ok := find(a.To)
		if !ok {
			return nil, nil, invalid("%s has no snapshot %q", ds, a.To)
		}
		args = append([]string{"send"}, sendFlags...)
		if a.From != "" {
			from, ok := find(a.From)
			if !ok || from.TXG >= to.TXG {
				return nil, nil, invalid("%s has no snapshot %q before %s", ds, a.From, a.To)
			}
			args = append(args, "-i", ds+"@"+a.From)
		}
		args = append(args, ds+"@"+a.To)
	}
	var est int64
	if out, err := r.zfs(ctx, append([]string{"send", "-n", "-P"}, args[1:]...)...); err == nil {
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "size" {
				est, _ = strconv.ParseInt(f[1], 10, 64)
			}
		}
	}
	s, err := r.streams.add("")
	if err != nil {
		return nil, nil, err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		s.finish(err)
		return nil, nil, err
	}
	errs := &tail{}
	p, err := r.starter().Start("zfs", args, nil, pw, errs)
	pw.Close()
	if err != nil {
		pr.Close()
		s.finish(err)
		return nil, nil, err
	}
	s.mu.Lock()
	s.proc = p
	s.mu.Unlock()
	go func() {
		err := p.Wait()
		if err != nil {
			if msg := errs.String(); msg != "" {
				err = fmt.Errorf("zfs send: %s", msg)
			} else {
				err = fmt.Errorf("zfs send: %w", err)
			}
		}
		s.finish(err)
	}()
	r.log().Info("ha: send", "stream", s.id, "dataset", ds, "to", a.To, "from", a.From, "resume", a.Token != "")
	return &StreamStart{Stream: s.id, Estimate: est}, pr, nil
}

// ---- receive -------------------------------------------------------------------------

// RecvArgs is ha.recv: one dataset's stream for conversion Conv, which
// must carry snapshot Label.
type RecvArgs struct {
	Ref
	Conv  string `json:"conv"`
	Child string `json:"child,omitempty"`
	Label string `json:"label"`
}

// Recv starts zfs receive into the workload's incoming datasets and
// returns the write end of its input.
func (r *Root) Recv(ctx context.Context, a RecvArgs) (*StreamStart, *os.File, error) {
	if !snapRE.MatchString(a.Label) {
		return nil, nil, invalid("bad snapshot name")
	}
	dirExists, err := r.checkIncoming(ctx, a.Ref, a.Conv)
	if err != nil {
		return nil, nil, err
	}
	ds, err := a.Ref.incomingDataset(a.Conv, a.Child)
	if err != nil {
		return nil, nil, err
	}
	top := a.incomingTop(a.Conv)
	pol := replica.Policy{Label: a.Label, Objset: replica.ObjsetFilesystem}
	if a.Child != "" {
		pol.Objset = replica.ObjsetVolume
		if _, ok := r.exists(ctx, top); !ok || !dirExists {
			return nil, nil, invalid("%s's state folder comes first", a.ID)
		}
	}
	if typ, ok := r.exists(ctx, ds); ok {
		want := "filesystem"
		if a.Child != "" {
			want = "volume"
		}
		if typ != want {
			return nil, nil, invalid("%s is a %s", ds, typ)
		}
		pol.Incremental = true
	} else if !dirExists {
		if err := r.makeIncoming(ctx, a.Ref, a.Conv); err != nil {
			return nil, nil, err
		}
	}
	args := []string{"receive", "-u", "-s"}
	if pol.Objset == replica.ObjsetVolume {
		args = append(args, "-o", "volmode=none")
	} else {
		args = append(args, "-o", "canmount=noauto", "-x", "mountpoint", "-x", "sharenfs", "-x", "sharesmb")
		if a.Kind == cluster.KindVM || a.Side == SideCluster {
			args = append(args, "-o", "setuid=off", "-o", "devices=off")
		}
		if a.Kind == cluster.KindVM {
			args = append(args, "-o", "exec=off")
		}
	}
	args = append(args, ds)
	s, err := r.streams.add(ds)
	if err != nil {
		return nil, nil, err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		s.finish(err)
		return nil, nil, err
	}
	s.mu.Lock()
	s.closer = pr
	s.mu.Unlock()
	go func() {
		defer pr.Close()
		s.finish(r.receive(pr, s, pol, args))
	}()
	r.log().Info("ha: receive", "stream", s.id, "dataset", ds, "label", a.Label)
	return &StreamStart{Stream: s.id}, pw, nil
}

// makeIncoming makes <pool>/hardyos-ha-incoming/<conv>, marked as ref's.
func (r *Root) makeIncoming(ctx context.Context, ref Ref, conv string) error {
	base := ref.Pool + "/" + IncomingDir
	if _, ok := r.exists(ctx, base); !ok {
		if _, err := r.zfs(ctx, "create", "-o", "canmount=off", "-o", propRole+"=ha-incoming", base); err != nil {
			return err
		}
	}
	if ref.Side == SideCluster && r.EnsureParent != nil {
		if err := r.EnsureParent(ctx, ref.Pool, base); err != nil {
			return err
		}
	}
	_, err := r.zfs(ctx, "create", "-o", "canmount=off", "-o", PropIncoming+"="+ref.incomingValue(), ref.incomingDir(conv))
	return err
}

func (r *Root) makeParent(ctx context.Context, ref Ref, parent string) error {
	if ref.Side == SideCluster {
		if _, err := r.zfs(ctx, "create", parent); err != nil {
			return err
		}
		if r.EnsureParent != nil {
			return r.EnsureParent(ctx, ref.Pool, parent)
		}
		return nil
	}
	args := []string{"create"}
	if ref.Kind == cluster.KindApp {
		args = append(args, "-o", "org.hardyos:role=apps")
	}
	_, err := r.zfs(ctx, append(args, parent)...)
	return err
}

// receive checks the stream's first record against the policy and feeds
// it to zfs receive.
func (r *Root) receive(in io.Reader, s *stream, pol replica.Policy, args []string) error {
	hdr := make([]byte, replica.BeginRecordSize)
	if _, err := io.ReadFull(in, hdr); err != nil {
		return fmt.Errorf("reading the stream: %w", err)
	}
	b, err := replica.ParseBegin(hdr)
	if err != nil {
		return err
	}
	if err := pol.Check(b); err != nil {
		r.log().Warn("ha: refused a stream", "args", args[len(args)-1], "err", err)
		return err
	}
	s.bytes.Add(int64(len(hdr)))
	s.mu.Lock()
	if s.killed {
		s.mu.Unlock()
		return errors.New("cancelled")
	}
	errs := &tail{}
	p, err := r.starter().Start("zfs", args, io.MultiReader(bytes.NewReader(hdr), counting{r: in, n: &s.bytes}), io.Discard, errs)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	s.proc = p
	s.mu.Unlock()
	if err := p.Wait(); err != nil {
		if msg := errs.String(); msg != "" {
			return fmt.Errorf("zfs receive: %s", msg)
		}
		return fmt.Errorf("zfs receive: %w", err)
	}
	return nil
}
