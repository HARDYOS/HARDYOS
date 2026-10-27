package replication

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/replica"
)

// simRoot is a small simulation of hardyd-priv's replication side: datasets
// with snapshots (and GUIDs), streams as a JSON line plus filler bytes,
// interrupted receives that leave a resume token. Enough to test the
// protocol between two hardyds without ZFS.
type simRoot struct {
	mu       sync.Mutex
	items    []replica.LocalItem
	children map[string][]replica.Child // kind/id -> datasets
	local    map[string]*simDS          // kind/id/child on the source
	replicas map[string]*simDS          // dataset on the receiver
	streams  map[string]*simStream
	clock    time.Time
	guid     int
	size     int // payload bytes per stream
	// cutAfter, when > 0, interrupts the next receive after that many
	// payload bytes (a dropped connection).
	cutAfter int
	sends    []replica.SendArgs
	recvs    []replica.RecvArgs
	pruned   []replica.RecvPruneArgs
	restored []replica.RestoreArgs
	finished []replica.RestoreFinishArgs
	aborted  int
}

type simDS struct {
	typ   string
	snaps []replica.SnapInfo
	token string
}

type simStream struct {
	done  bool
	err   error
	bytes int64
}

type simHeader struct {
	DS       string `json:"ds"`
	To       string `json:"to"`
	GUID     string `json:"guid"`
	FromGUID string `json:"fromGuid"`
	Resume   bool   `json:"resume"`
	Type     string `json:"type"`
}

func newSimRoot() *simRoot {
	return &simRoot{
		children: map[string][]replica.Child{}, local: map[string]*simDS{}, replicas: map[string]*simDS{},
		streams: map[string]*simStream{}, clock: time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC), size: 4096,
	}
}

func (r *simRoot) addItem(kind, id, name string, kids ...replica.Child) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, replica.LocalItem{Kind: kind, ID: id, Name: name, Pool: "tank", Dataset: "tank/" + kind + "s/" + id})
	if len(kids) == 0 {
		kids = []replica.Child{{Child: "", Type: "filesystem"}}
	}
	r.children[kind+"/"+id] = kids
	for _, k := range kids {
		r.local[kind+"/"+id+"/"+k.Child] = &simDS{typ: k.Type}
	}
}

func (r *simRoot) nextGUID() string { r.guid++; return strconv.Itoa(1000 + r.guid) }

func (r *simRoot) Items(context.Context) ([]replica.LocalItem, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]replica.LocalItem(nil), r.items...), nil
}

func (r *simRoot) Snapshot(_ context.Context, a replica.SnapshotArgs) (*replica.SnapshotResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	kids, ok := r.children[a.Kind+"/"+a.ID]
	if !ok {
		return nil, replica.ErrNotFound
	}
	r.clock = r.clock.Add(time.Minute)
	label := replica.SnapName(a.Task, r.clock)
	for _, k := range kids {
		ds := r.local[a.Kind+"/"+a.ID+"/"+k.Child]
		ds.snaps = append(ds.snaps, replica.SnapInfo{Name: label, GUID: r.nextGUID(), Created: r.clock})
	}
	return &replica.SnapshotResult{Snapshot: label, Pool: "tank", Children: kids, Consistent: true}, nil
}

func ofTask(l []replica.SnapInfo, task string) []replica.SnapInfo {
	var out []replica.SnapInfo
	for _, s := range l {
		if tk, _, ok := replica.ParseSnap(s.Name); ok && (task == "" || tk == task) {
			out = append(out, s)
		}
	}
	return out
}

func (r *simRoot) LocalSnapshots(_ context.Context, a replica.LocalSnapshotsArgs) ([]replica.SnapInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ds := r.local[a.Kind+"/"+a.ID+"/"+a.Child]
	if ds == nil {
		return nil, replica.ErrNotFound
	}
	return ofTask(ds.snaps, a.Task), nil
}

func find(l []replica.SnapInfo, name string) *replica.SnapInfo {
	for i := range l {
		if l[i].Name == name {
			return &l[i]
		}
	}
	return nil
}

func (r *simRoot) newStream() (string, *simStream) {
	id := fmt.Sprintf("s%d", len(r.streams)+1)
	s := &simStream{}
	r.streams[id] = s
	return id, s
}

func (r *simRoot) Send(_ context.Context, a replica.SendArgs) (*replica.SendStart, io.ReadCloser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sends = append(r.sends, a)
	key := a.Kind + "/" + a.ID + "/" + a.Child
	ds := r.local[key]
	if ds == nil {
		return nil, nil, replica.ErrNotFound
	}
	h := simHeader{DS: key, Type: ds.typ}
	if a.Token != "" {
		raw, err := hex.DecodeString(strings.TrimPrefix(a.Token, "1-0-0-"))
		if err != nil {
			return nil, nil, errors.New("bad token")
		}
		var tok simHeader
		_ = json.Unmarshal(raw, &tok)
		if tok.DS != key || find(ds.snaps, tok.To) == nil {
			return nil, nil, errors.New("the token is for something else")
		}
		h = tok
		h.Resume = true
	} else {
		s := find(ds.snaps, a.Snapshot)
		if s == nil {
			return nil, nil, replica.ErrNotFound
		}
		h.To, h.GUID = s.Name, s.GUID
		if a.From != "" {
			f := find(ds.snaps, a.From)
			if f == nil {
				return nil, nil, replica.ErrNotFound
			}
			h.FromGUID = f.GUID
		}
	}
	id, st := r.newStream()
	pr, pw := io.Pipe()
	go func() {
		b, _ := json.Marshal(h)
		_, err := pw.Write(append(b, '\n'))
		if err == nil {
			_, err = pw.Write(make([]byte, r.size))
		}
		pw.CloseWithError(err)
		r.mu.Lock()
		st.done, st.err = true, err
		r.mu.Unlock()
	}()
	return &replica.SendStart{Stream: id, Estimate: int64(r.size), Snapshot: h.To}, pr, nil
}

func (r *simRoot) Prune(_ context.Context, a replica.PruneArgs) (*replica.PruneResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res := &replica.PruneResult{Deleted: []string{}}
	keep := a.Keep
	if a.Forget {
		keep = 0
	}
	for _, k := range r.children[a.Kind+"/"+a.ID] {
		ds := r.local[a.Kind+"/"+a.ID+"/"+k.Child]
		mine := ofTask(ds.snaps, a.Task)
		var kept []replica.SnapInfo
		for i, s := range mine {
			protected := false
			for _, p := range a.Protect {
				protected = protected || p == s.Name
			}
			if i >= len(mine)-keep || protected {
				kept = append(kept, s)
			} else if k.Child == "" {
				res.Deleted = append(res.Deleted, s.Name)
			}
		}
		ds.snaps = kept
	}
	return res, nil
}

func (r *simRoot) Stream(_ context.Context, id string) (*replica.StreamState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.streams[id]
	if s == nil {
		return nil, replica.ErrNoStream
	}
	st := &replica.StreamState{ID: id, Done: s.done, OK: s.done && s.err == nil, Bytes: s.bytes}
	if s.err != nil {
		st.Error = s.err.Error()
	}
	return st, nil
}

func (r *simRoot) Cancel(context.Context, string) error { return nil }

func (r *simRoot) Recv(_ context.Context, a replica.RecvArgs) (*replica.RecvStart, io.WriteCloser, error) {
	if err := a.Target.Validate(); err != nil {
		return nil, nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recvs = append(r.recvs, a)
	id, st := r.newStream()
	pr, pw := io.Pipe()
	cut := r.cutAfter
	r.cutAfter = 0
	go func() {
		err := r.receive(a, pr, st, cut)
		pr.CloseWithError(errors.New("closed"))
		r.mu.Lock()
		st.done, st.err = true, err
		r.mu.Unlock()
	}()
	return &replica.RecvStart{Stream: id}, pw, nil
}

func (r *simRoot) receive(a replica.RecvArgs, in io.Reader, st *simStream, cut int) error {
	br := bufio.NewReader(in)
	line, err := br.ReadBytes('\n')
	if err != nil {
		return err
	}
	var h simHeader
	if err := json.Unmarshal(line, &h); err != nil {
		return err
	}
	if h.To != a.Snapshot {
		return errors.New("wrong snapshot")
	}
	target := a.Target.Dataset()
	r.mu.Lock()
	ds := r.replicas[target]
	r.mu.Unlock()
	switch {
	case h.Resume:
		if ds == nil || ds.token == "" {
			return errors.New("nothing to resume")
		}
	case ds != nil && h.FromGUID == "":
		return errors.New("the replica exists, so only an incremental stream can follow")
	case ds == nil && h.FromGUID != "":
		return errors.New("an incremental stream needs an existing replica")
	case ds != nil && (len(ds.snaps) == 0 || ds.snaps[len(ds.snaps)-1].GUID != h.FromGUID):
		return errors.New("destination has been modified since the most recent snapshot")
	}
	n := 0
	buf := make([]byte, 512)
	for {
		k, err := br.Read(buf)
		n += k
		r.mu.Lock()
		st.bytes += int64(k)
		r.mu.Unlock()
		if cut > 0 && n >= cut {
			err = errors.New("connection reset")
		}
		if err != nil {
			if errors.Is(err, io.EOF) && n == r.size {
				break
			}
			// Partial: keep a resume token (-s).
			r.mu.Lock()
			if ds == nil {
				ds = &simDS{typ: h.Type}
				r.replicas[target] = ds
			}
			tok := h
			tok.Resume = false
			b, _ := json.Marshal(tok)
			ds.token = "1-0-0-" + hex.EncodeToString(b)
			r.mu.Unlock()
			return fmt.Errorf("zfs receive: %v", err)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if ds == nil {
		ds = &simDS{typ: h.Type}
		r.replicas[target] = ds
	}
	ds.token = ""
	ds.snaps = append(ds.snaps, replica.SnapInfo{Name: h.To, GUID: h.GUID})
	return nil
}

func (r *simRoot) RecvState(_ context.Context, t replica.Target) (*replica.RecvState, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ds := r.replicas[t.Dataset()]
	if ds == nil {
		return &replica.RecvState{Snapshots: []replica.SnapInfo{}}, nil
	}
	return &replica.RecvState{Exists: true, Type: ds.typ, Snapshots: append([]replica.SnapInfo{}, ds.snaps...), Token: ds.token}, nil
}

func (r *simRoot) RecvAbort(_ context.Context, t replica.Target) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.aborted++
	if ds := r.replicas[t.Dataset()]; ds != nil {
		ds.token = ""
		if len(ds.snaps) == 0 {
			delete(r.replicas, t.Dataset())
		}
	}
	return nil
}

func (r *simRoot) RecvPrune(_ context.Context, a replica.RecvPruneArgs) (*replica.PruneResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruned = append(r.pruned, a)
	res := &replica.PruneResult{Deleted: []string{}}
	for name, ds := range r.replicas {
		if !a.Target.Under(name) {
			continue
		}
		mine := ofTask(ds.snaps, a.Task)
		var kept []replica.SnapInfo
		for i, s := range mine {
			if i >= len(mine)-a.Keep {
				kept = append(kept, s)
			} else if name == a.ItemDataset() {
				res.Deleted = append(res.Deleted, s.Name)
			}
		}
		ds.snaps = kept
	}
	return res, nil
}

func (r *simRoot) Replicas(context.Context) ([]replica.ReplicaSource, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	bySrc := map[string]*replica.ReplicaSource{}
	for name, ds := range r.replicas {
		parts := strings.Split(name, "/")
		if len(parts) != 5 {
			continue
		}
		src := bySrc[parts[2]]
		if src == nil {
			src = &replica.ReplicaSource{Pool: parts[0], Source: parts[2]}
			bySrc[parts[2]] = src
		}
		it := replica.ReplicaItem{Kind: parts[3], ID: parts[4], UsedBytes: uint64(len(ds.snaps) * r.size), Snapshots: len(ds.snaps), Partial: ds.token != ""}
		if len(ds.snaps) > 0 {
			it.LastSnapshot = ds.snaps[len(ds.snaps)-1].Name
		}
		src.Items = append(src.Items, it)
		src.UsedBytes += it.UsedBytes
	}
	out := []replica.ReplicaSource{}
	for _, s := range bySrc {
		sort.Slice(s.Items, func(i, j int) bool { return s.Items[i].ID < s.Items[j].ID })
		out = append(out, *s)
	}
	return out, nil
}

func (r *simRoot) ReplicaSnapshots(_ context.Context, t replica.Target) ([]replica.SnapInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ds := r.replicas[t.ItemDataset()]
	if ds == nil {
		return []replica.SnapInfo{}, nil
	}
	return append([]replica.SnapInfo{}, ds.snaps...), nil
}

func (r *simRoot) ReplicaChildren(_ context.Context, t replica.Target, snapshot string) ([]replica.Child, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []replica.Child
	for name, ds := range r.replicas {
		if t.Under(name) && find(ds.snaps, snapshot) != nil {
			out = append(out, replica.Child{Child: strings.TrimPrefix(strings.TrimPrefix(name, t.ItemDataset()), "/"), Type: ds.typ})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Child < out[j].Child })
	if len(out) == 0 {
		return nil, replica.ErrNotFound
	}
	return out, nil
}

func (r *simRoot) ReplicaSend(_ context.Context, a replica.ReplicaSendArgs) (*replica.SendStart, io.ReadCloser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ds := r.replicas[a.Dataset()]
	if ds == nil || find(ds.snaps, a.Snapshot) == nil {
		return nil, nil, replica.ErrNotFound
	}
	id, st := r.newStream()
	pr, pw := io.Pipe()
	go func() {
		b, _ := json.Marshal(simHeader{DS: a.Dataset(), To: a.Snapshot, Type: ds.typ})
		_, err := pw.Write(append(b, '\n'))
		if err == nil {
			_, err = pw.Write(make([]byte, r.size))
		}
		pw.CloseWithError(err)
		r.mu.Lock()
		st.done, st.err = true, err
		r.mu.Unlock()
	}()
	return &replica.SendStart{Stream: id, Estimate: int64(r.size)}, pr, nil
}

func (r *simRoot) Browse(_ context.Context, a replica.BrowseArgs) (*replica.BrowseResult, error) {
	return &replica.BrowseResult{Path: a.Path, Entries: []replica.Entry{{Name: "Photos", Dir: true}, {Name: "notes.txt", Size: 12}}}, nil
}

func (r *simRoot) DeleteSource(_ context.Context, a replica.DeleteSourceArgs) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name := range r.replicas {
		if strings.HasPrefix(name, replica.SourceDataset(a.Pool, a.Source)+"/") {
			delete(r.replicas, name)
		}
	}
	return nil
}

func (r *simRoot) RestoreRecv(_ context.Context, a replica.RestoreArgs) (*replica.RecvStart, io.WriteCloser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.restored = append(r.restored, a)
	id, st := r.newStream()
	pr, pw := io.Pipe()
	go func() {
		n, err := io.Copy(io.Discard, pr)
		r.mu.Lock()
		st.done, st.err, st.bytes = true, err, n
		r.mu.Unlock()
	}()
	return &replica.RecvStart{Stream: id}, pw, nil
}

func (r *simRoot) RestoreFinish(_ context.Context, a replica.RestoreFinishArgs) (*replica.RestoreFinishResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.finished = append(r.finished, a)
	id := a.ID
	if a.Kind == replica.KindShare {
		id = a.NewID
	}
	return &replica.RestoreFinishResult{Dataset: a.Pool + "/" + a.Kind + "s/" + id, ID: id}, nil
}

func (r *simRoot) RestoreAbort(context.Context, replica.RestoreFinishArgs) error { return nil }
