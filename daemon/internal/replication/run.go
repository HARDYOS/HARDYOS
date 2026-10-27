package replication

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/replica"
)

// RunResult is a finished replication.
type RunResult struct {
	Bytes int64    `json:"bytes"`
	Items []string `json:"items"`
}

// progress reports bytes moved to the job.
type progress struct {
	jc      *jobs.Context
	items   int
	done    int
	label   string
	bytes   atomic.Int64 // this transfer
	total   atomic.Int64 // the whole run
	est     int64
	started time.Time
}

func (p *progress) report() {
	if p.jc == nil {
		return
	}
	n := p.bytes.Load()
	frac := 0.0
	if p.est > 0 {
		frac = min(float64(n)/float64(p.est), 1)
	}
	pct := 5 + 90*(float64(p.done)+frac)/float64(max(p.items, 1))
	msg := p.label
	if n > 0 || p.est > 0 {
		msg += ": " + human(n)
		if p.est > 0 {
			msg += " of about " + human(p.est)
		}
		if el := time.Since(p.started).Seconds(); el > 2 {
			msg += fmt.Sprintf(" (%s/s)", human(int64(float64(n)/el)))
		}
	}
	p.jc.Progress(pct, msg)
}

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// counter counts bytes into a progress.
type counter struct {
	r io.Reader
	p *progress
}

func (c counter) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.p.bytes.Add(int64(n))
	c.p.total.Add(int64(n))
	return n, err
}

// limited paces reads to rate bytes a second.
type limited struct {
	ctx   context.Context
	r     io.Reader
	rate  int64
	start time.Time
	n     int64
}

// Limit wraps r so it reads at most kbps KiB a second (0: unlimited).
func Limit(ctx context.Context, r io.Reader, kbps int) io.Reader {
	if kbps <= 0 {
		return r
	}
	return &limited{ctx: ctx, r: r, rate: int64(kbps) * 1024}
}

func (l *limited) Read(b []byte) (int, error) {
	if l.start.IsZero() {
		l.start = time.Now()
	}
	// Small reads keep the pace even.
	if chunk := int(max(l.rate/10, 4096)); len(b) > chunk {
		b = b[:chunk]
	}
	n, err := l.r.Read(b)
	l.n += int64(n)
	want := time.Duration(float64(l.n) / float64(l.rate) * float64(time.Second))
	if wait := want - time.Since(l.start); wait > 0 {
		t := time.NewTimer(wait)
		select {
		case <-l.ctx.Done():
			t.Stop()
			return n, l.ctx.Err()
		case <-t.C:
		}
	}
	return n, err
}

func (s *Service) runTask(jc *jobs.Context, taskID string) (any, error) {
	s.init()
	t, err := s.st.Task(jc, taskID)
	if err != nil {
		return nil, err
	}
	started := s.now()
	runID, err := s.st.recordStart(jc, t.ID, jc.ID(), "replicate", started)
	if err != nil {
		return nil, err
	}
	defer s.st.trimRuns(context.Background(), t.ID)
	pr := &progress{jc: jc, items: len(t.Items), started: time.Now()}
	res, runErr := s.replicate(jc, t, pr)
	state, msg := "succeeded", fmt.Sprintf("%d items, %s", len(t.Items), human(pr.total.Load()))
	switch {
	case runErr == nil:
	case errors.Is(runErr, context.Canceled) || jc.Err() != nil:
		state, msg = "cancelled", "cancelled"
	default:
		state, msg = "failed", runErr.Error()
	}
	end := context.Background()
	_ = s.st.recordEnd(end, runID, t.ID, "replicate", state, pr.total.Load(), msg, s.now())
	s.alert(end, t, state, msg)
	if runErr != nil {
		return nil, runErr
	}
	return res, nil
}

// alert raises or clears a task's notification.
func (s *Service) alert(ctx context.Context, t *Task, state, msg string) {
	now := s.now()
	switch state {
	case "succeeded":
		if t.Alert != "" {
			s.notifier().Notify(ctx, Event{Kind: EventRecovered, Severity: SeverityInfo, Title: "Replication " + t.Name + " is working again",
				Body: "The last run succeeded.", Link: "replication:" + t.ID, Time: now})
			_ = s.st.setAlert(ctx, t.ID, "")
		}
	case "failed":
		if t.Alert == "" {
			s.notifier().Notify(ctx, Event{Kind: EventFailed, Severity: SeverityWarning, Title: "Replication " + t.Name + " failed",
				Body: msg, Link: "replication:" + t.ID, Time: now})
			_ = s.st.setAlert(ctx, t.ID, "failed")
		}
	}
}

func (s *Service) replicate(jc *jobs.Context, t *Task, pr *progress) (*RunResult, error) {
	tgt, err := s.st.Target(jc, t.TargetID)
	if err != nil {
		return nil, fmt.Errorf("the task's server: %w", err)
	}
	jc.Progress(2, "Connecting to "+tgt.Name)
	p, err := s.peer(jc, tgt)
	if err != nil {
		return nil, err
	}
	defer p.close()
	if h, err := p.hello(jc); err != nil {
		return nil, err
	} else if h.SourceID != tgt.SourceID {
		return nil, fmt.Errorf("%s knows this server under another id: pair again", tgt.Name)
	}
	local, err := s.Root.Items(jc)
	if err != nil {
		return nil, err
	}
	byKey := map[string]replica.LocalItem{}
	for _, li := range local {
		byKey[li.Kind+"/"+li.ID] = li
	}
	res := &RunResult{Items: []string{}}
	var failed []string
	for i, it := range t.Items {
		pr.done = i
		if jc.Err() != nil {
			return nil, jc.Err()
		}
		li, ok := byKey[it.String()]
		if !ok {
			failed = append(failed, it.String()+": not on this server any more")
			continue
		}
		if err := s.replicateItem(jc, p, t, li, pr); err != nil {
			if jc.Err() != nil {
				return nil, jc.Err()
			}
			s.log().Warn("replication: item failed", "task", t.ID, "item", it.String(), "err", err)
			failed = append(failed, li.Name+": "+err.Error())
			continue
		}
		res.Items = append(res.Items, it.String())
	}
	res.Bytes = pr.total.Load()
	if len(failed) > 0 {
		return res, &jobs.FailedWith{Err: errors.New(strings.Join(failed, "; ")), Result: res}
	}
	jc.Progress(100, fmt.Sprintf("Replicated %d items (%s)", len(res.Items), human(res.Bytes)))
	return res, nil
}

func (s *Service) replicateItem(ctx *jobs.Context, p *peer, t *Task, li replica.LocalItem, pr *progress) error {
	pr.label = "Snapshotting " + li.Name
	pr.est = 0
	pr.bytes.Store(0)
	pr.report()
	snap, err := s.Root.Snapshot(ctx, replica.SnapshotArgs{Task: t.ID, Kind: li.Kind, ID: li.ID})
	if err != nil {
		return err
	}
	if err := p.putItems(ctx, []itemNote{{Kind: li.Kind, ID: li.ID, Name: li.Name, Pool: snap.Pool, Task: t.ID}}); err != nil {
		return err
	}
	for _, ch := range snap.Children {
		if err := s.sendDataset(ctx, p, t, li, ch.Child, snap.Snapshot, pr); err != nil {
			if ch.Child != "" {
				return fmt.Errorf("%s: %w", ch.Child, err)
			}
			return err
		}
	}
	// Every dataset has the new snapshot on both sides: older ones can go.
	if _, err := p.prune(ctx, t.ID, li.Kind, li.ID, t.KeepRemote); err != nil {
		s.log().Warn("replication: pruning on the receiving server", "task", t.ID, "item", li.Kind+"/"+li.ID, "err", err)
	}
	if _, err := s.Root.Prune(ctx, replica.PruneArgs{Task: t.ID, Kind: li.Kind, ID: li.ID, Keep: t.KeepLocal, Protect: []string{snap.Snapshot}}); err != nil {
		s.log().Warn("replication: pruning here", "task", t.ID, "item", li.Kind+"/"+li.ID, "err", err)
	}
	return nil
}

// ErrNoCommon means the replica and this server share no snapshot.
var ErrNoCommon = errors.New("the replica and this server have no snapshot in common (snapshots were deleted on one side); delete this item's replica on the receiving server to start over with a full copy")

// sendDataset brings one dataset's replica up to label: the rest of an
// interrupted transfer first, then the changes since the newest snapshot
// both sides have (or everything, for a new replica).
func (s *Service) sendDataset(ctx context.Context, p *peer, t *Task, li replica.LocalItem, child, label string, pr *progress) error {
	name := li.Name
	if child != "" {
		name += " (" + child + ")"
	}
	for attempt := 0; attempt < 3; attempt++ {
		st, err := p.state(ctx, li.Kind, li.ID, child)
		if err != nil {
			return err
		}
		if st.Token != "" {
			pr.label = "Resuming " + name
			err := s.transfer(ctx, p, t, replica.SendArgs{Task: t.ID, Kind: li.Kind, ID: li.ID, Child: child, Token: st.Token}, pr)
			if err == nil {
				continue // look again: the newest snapshot may still be missing
			}
			if ctx.Err() != nil {
				return err
			}
			s.log().Info("replication: the interrupted transfer can't be resumed; starting it again", "task", t.ID, "dataset", name, "err", err)
			if err := p.abort(ctx, li.Kind, li.ID, child); err != nil {
				return err
			}
			continue
		}
		have := map[string]bool{}
		for _, sn := range st.Snapshots {
			have[sn.GUID] = true
		}
		local, err := s.Root.LocalSnapshots(ctx, replica.LocalSnapshotsArgs{Task: t.ID, Kind: li.Kind, ID: li.ID, Child: child})
		if err != nil {
			return err
		}
		from := ""
		for i := len(local) - 1; i >= 0; i-- {
			if have[local[i].GUID] {
				from = local[i].Name
				break
			}
		}
		if from == label {
			return nil
		}
		if st.Exists && from == "" {
			return ErrNoCommon
		}
		pr.label = "Sending " + name
		if from == "" {
			pr.label = "Copying " + name + " (first time)"
		}
		return s.transfer(ctx, p, t, replica.SendArgs{Task: t.ID, Kind: li.Kind, ID: li.ID, Child: child, Snapshot: label, From: from}, pr)
	}
	return errors.New("the transfer keeps being interrupted")
}

// transfer runs one zfs send on this server into zfs receive on the
// other, at the task's bandwidth limit.
func (s *Service) transfer(ctx context.Context, p *peer, t *Task, a replica.SendArgs, pr *progress) error {
	st, rc, err := s.Root.Send(ctx, a)
	if err != nil {
		return err
	}
	defer rc.Close()
	snapshot := a.Snapshot
	if snapshot == "" {
		snapshot = st.Snapshot
	}
	pr.est = st.Estimate
	pr.bytes.Store(0)
	pr.started = time.Now()
	stop := make(chan struct{})
	go func() {
		tk := time.NewTicker(time.Second)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				pr.report()
			}
		}
	}()
	_, err = p.stream(ctx, t.ID, a.Kind, a.ID, a.Child, snapshot, counter{r: Limit(ctx, rc, t.BandwidthKBps), p: pr})
	close(stop)
	pr.report()
	if err != nil {
		_ = s.Root.Cancel(context.Background(), st.Stream)
		return err
	}
	// The other side has it all; zfs send must also have finished well.
	res, err := s.waitStream(ctx, st.Stream, 5*time.Minute)
	if err != nil {
		return err
	}
	if !res.OK {
		return errors.New(res.Error)
	}
	return nil
}

// ---- restore ------------------------------------------------------------------

// RestoreResult says where a restored copy is.
type RestoreResult struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Dataset string `json:"dataset"`
	Bytes   int64  `json:"bytes"`
	// Notes say what was changed on the way back (a VM's reset settings).
	Notes []string `json:"notes"`
}

func (s *Service) restore(jc *jobs.Context, a RestoreParams) (any, error) {
	s.init()
	tgt, err := s.st.Target(jc, a.Target)
	if err != nil {
		return nil, err
	}
	p, err := s.peer(jc, tgt)
	if err != nil {
		return nil, err
	}
	defer p.close()
	runID, _ := s.st.recordStart(jc, "restore:"+tgt.ID, jc.ID(), "restore", s.now())
	res, err := s.restoreItem(jc, p, tgt, a)
	state, msg := "succeeded", ""
	if err != nil {
		state, msg = "failed", err.Error()
		if jc.Err() != nil {
			state = "cancelled"
		}
	} else {
		msg = fmt.Sprintf("%s/%s restored as %s", a.Kind, a.ID, res.Dataset)
		if len(res.Notes) > 0 {
			msg += ". Changed: " + strings.Join(res.Notes, "; ")
			jc.Progress(100, "Restored. Changed: "+strings.Join(res.Notes, "; "))
		}
		s.notifier().Notify(context.Background(), Event{Kind: EventRestored, Severity: SeverityInfo, Title: "Restored " + a.ID + " from " + tgt.Name,
			Body: msg, Link: "replication:restore", Time: s.now()})
	}
	if runID != 0 {
		var n int64
		if res != nil {
			n = res.Bytes
		}
		_ = s.st.recordEnd(context.Background(), runID, "restore:"+tgt.ID, "restore", state, n, msg, s.now())
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Service) restoreItem(jc *jobs.Context, p *peer, tgt *Target, a RestoreParams) (*RestoreResult, error) {
	if err := (replica.Item{Kind: a.Kind, ID: a.ID}).Validate(); err != nil {
		return nil, err
	}
	if err := replica.ValidSnap(a.Snapshot, ""); err != nil {
		return nil, err
	}
	jc.Progress(3, "Looking at the replica on "+tgt.Name)
	kids, err := p.children(jc, a.Kind, a.ID, a.Snapshot)
	if err != nil {
		return nil, err
	}
	finish := replica.RestoreFinishArgs{Kind: a.Kind, ID: a.ID, Pool: a.Pool, NewID: a.NewID, Snapshot: a.Snapshot}
	pr := &progress{jc: jc, items: len(kids), started: time.Now()}
	cleanup := func() {
		if err := s.Root.RestoreAbort(context.Background(), finish); err != nil {
			s.log().Warn("replication: removing an unfinished restore", "item", a.Kind+"/"+a.ID, "err", err)
		}
	}
	for i, ch := range kids {
		pr.done = i
		pr.label = "Restoring " + a.ID
		if ch.Child != "" {
			pr.label += " (" + ch.Child + ")"
		}
		if err := s.pull(jc, p, tgt, a, ch.Child, pr); err != nil {
			cleanup()
			return nil, err
		}
	}
	jc.Progress(97, "Putting "+a.ID+" back in place")
	r, err := s.Root.RestoreFinish(jc, finish)
	if err != nil {
		cleanup()
		return nil, err
	}
	notes := r.Notes
	if notes == nil {
		notes = []string{}
	}
	return &RestoreResult{Kind: a.Kind, ID: r.ID, Dataset: r.Dataset, Bytes: pr.total.Load(), Notes: notes}, nil
}

// pull receives one dataset of a replica's snapshot back here.
func (s *Service) pull(ctx context.Context, p *peer, tgt *Target, a RestoreParams, child string, pr *progress) error {
	rs, w, err := s.Root.RestoreRecv(ctx, replica.RestoreArgs{Kind: a.Kind, ID: a.ID, Child: child, Pool: a.Pool, NewID: a.NewID, Name: a.Name,
		Snapshot: a.Snapshot, From: tgt.Name})
	if err != nil {
		return err
	}
	resp, err := p.send(ctx, a.Kind, a.ID, child, a.Snapshot)
	if err != nil {
		w.Close()
		_ = s.Root.Cancel(context.Background(), rs.Stream)
		return err
	}
	defer resp.Body.Close()
	pr.bytes.Store(0)
	pr.est = resp.ContentLength
	if v := resp.Header.Get("X-Hardyos-Estimate"); v != "" {
		fmt.Sscan(v, &pr.est)
	}
	_, copyErr := io.Copy(w, counter{r: resp.Body, p: pr})
	w.Close()
	pr.report()
	if copyErr == nil {
		if st := resp.Trailer.Get(TrailerStatus); st != "ok" {
			copyErr = fmt.Errorf("the other server's send: %s", strings.TrimPrefix(st, "error: "))
		}
	}
	res, err := s.waitStream(context.Background(), rs.Stream, 30*time.Minute)
	if err != nil {
		return err
	}
	if !res.OK {
		return errors.New(res.Error)
	}
	return copyErr
}

// ---- reads for the API ----------------------------------------------------------

// TargetReplicas lists this server's items kept on a target.
func (s *Service) TargetReplicas(ctx context.Context, targetID string) ([]RemoteItem, error) {
	s.init()
	t, err := s.st.Target(ctx, targetID)
	if err != nil {
		return nil, err
	}
	p, err := s.peer(ctx, t)
	if err != nil {
		return nil, err
	}
	defer p.close()
	l, err := p.items(ctx)
	if l == nil {
		l = []RemoteItem{}
	}
	return l, err
}

// TargetSnapshots lists a replicated item's snapshots on a target.
func (s *Service) TargetSnapshots(ctx context.Context, targetID, kind, id string) ([]replica.SnapInfo, error) {
	s.init()
	t, err := s.st.Target(ctx, targetID)
	if err != nil {
		return nil, err
	}
	p, err := s.peer(ctx, t)
	if err != nil {
		return nil, err
	}
	defer p.close()
	l, err := p.snapshots(ctx, kind, id)
	if l == nil {
		l = []replica.SnapInfo{}
	}
	return l, err
}

// TargetBrowse lists a folder in a replicated item's snapshot.
func (s *Service) TargetBrowse(ctx context.Context, targetID, kind, id, child, snapshot, path string) (*replica.BrowseResult, error) {
	s.init()
	t, err := s.st.Target(ctx, targetID)
	if err != nil {
		return nil, err
	}
	p, err := s.peer(ctx, t)
	if err != nil {
		return nil, err
	}
	defer p.close()
	return p.browse(ctx, kind, id, child, snapshot, path)
}
