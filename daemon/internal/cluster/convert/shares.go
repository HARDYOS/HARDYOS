package convert

// Shared folders that move with an app made highly available
// (docs/plans/cluster-gaps-2.md, decisions 500-503). A cluster app runs on
// any compute server, so the shared folders it was given can't stay on
// this server's pool: each one moves to the storage server with it, the
// way the app's folder does (snapshots, a copy while it runs, the final
// increment once it is off), and becomes a shared folder of the storage
// server (same id, name, settings, permissions and app access), used in
// the cluster: every compute server mounts it, and people reach it on the
// storage server. The rules of decisions 480-489 hold for each of them:
// never two copies anyone can write (this server's copy is held from the
// final snapshot, the storage server's is adopted held and let go of only
// once this server's copy is put aside), never the only copy lost (this
// server's copy is parked for the grace period), typed confirmations, and
// every phase resumable.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/hacopy"
	"github.com/hardyos/hardyos/daemon/internal/cluster/sanclient"
	"github.com/hardyos/hardyos/daemon/internal/cluster/storagesvc"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/store"
)

// LibraryShare is the VMs' ISO library (vms.LibraryShareID): it stays on
// its server.
const LibraryShare = "isos"

// ShareMove is one shared folder moving with an app.
type ShareMove struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Pool is this server's pool it is on.
	Pool string `json:"pool"`
	// Path is where this server has it (the app's compose file names it).
	Path  string `json:"path"`
	Write bool   `json:"write"`
	// Conv is the id its copy is received, adopted, held and parked under
	// (the conversion's id with "s" and its place), never the app's own.
	Conv string `json:"conv"`
	// Settings are what it is adopted with on the storage server.
	Settings *shares.Settings `json:"settings,omitempty"`
	// Adopted: the storage server set it up (held). Released: it let go
	// of it (this server's copy was parked first); InCluster: it is used
	// in the cluster.
	Adopted   bool `json:"adopted,omitempty"`
	Released  bool `json:"released,omitempty"`
	InCluster bool `json:"inCluster,omitempty"`
	// ParkedPool and ParkedName name this server's parked copy
	// (ParkedSide "local"); ClusterPool and ClusterName the storage
	// server's copy put aside without an expiry (decision 508: kept apart,
	// so neither is ever taken for the other).
	ParkedPool  string `json:"parkedPool,omitempty"`
	ParkedName  string `json:"parkedName,omitempty"`
	ParkedSide  string `json:"parkedSide,omitempty"`
	ClusterPool string `json:"clusterPool,omitempty"`
	ClusterName string `json:"clusterName,omitempty"`
	// UntilDeleted: the storage server's copy, put aside, may be newer
	// than this server's (it was shared from there): kept until an
	// administrator deletes it, never given a grace period.
	UntilDeleted bool `json:"untilDeleted,omitempty"`
}

func (s *ShareMove) ref(pool string, side hacopy.Side) hacopy.Ref {
	return hacopy.Ref{Kind: hacopy.KindShare, ID: s.ID, Pool: pool, Side: side}
}

func (s *ShareMove) workload() cluster.WorkloadRef {
	return cluster.WorkloadRef{Kind: hacopy.KindShare, ID: s.ID}
}

// ReadyShare is a shared folder an app's readiness lists.
type ReadyShare struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SizeBytes int64  `json:"sizeBytes"`
	Write     bool   `json:"write"`
}

// shareConv is a shared folder's conversion id.
func shareConv(conv string, i int) string { return conv + "s" + strconv.Itoa(i) }

// localShares lists this server's shared folders.
func (c *Converter) localShares(ctx context.Context) ([]shares.Share, error) {
	var l priv.SharesResult
	if err := c.Priv.Call(ctx, priv.OpSharesList, nil, &l); err != nil {
		return nil, err
	}
	return l.Shares, nil
}

func findShare(l []shares.Share, id string) *shares.Share {
	for i := range l {
		if l[i].ID == id {
			return &l[i]
		}
	}
	return nil
}

// planShares builds (or checks against the record) the shared folders an
// app takes along.
func (c *Converter) planShares(ctx context.Context, r *Record, li *localInfo) error {
	if r.Kind != cluster.KindApp {
		return nil
	}
	ids := make([]string, 0, len(li.shares))
	for _, s := range li.shares {
		ids = append(ids, s.ID)
	}
	if len(r.Options.Shares) > 0 {
		had := make([]string, 0, len(r.Options.Shares))
		for _, s := range r.Options.Shares {
			had = append(had, s.ID)
		}
		if !slices.Equal(had, ids) {
			return errors.New("its shared folders changed since this conversion started; abandon it and start again")
		}
		return nil
	}
	l, err := c.localShares(ctx)
	if err != nil {
		return err
	}
	for i, s := range li.shares {
		sh := findShare(l, s.ID)
		if sh == nil {
			return fmt.Errorf("shared folder %s isn't on this server", s.ID)
		}
		r.Options.Shares = append(r.Options.Shares, ShareMove{ID: s.ID, Name: sh.Name, Pool: sh.Pool, Path: s.Path, Write: s.Write, Conv: shareConv(r.ID, i)})
	}
	return nil
}

// sharePools are each moving shared folder's pool on this server (from
// the record: a parked one isn't listed any more).
func (c *Converter) sharePools(_ context.Context, r *Record) (map[string]string, error) {
	out := map[string]string{}
	for _, s := range r.Options.Shares {
		if s.Pool == "" {
			return nil, fmt.Errorf("the conversion doesn't know which pool %s is on; abandon it and start again", s.Name)
		}
		out[s.ID] = s.Pool
	}
	return out, nil
}

// shareProblems says why an app's shared folders can't move now (empty:
// they can), with notes on what changes for the people using them.
func (c *Converter) shareProblems(ctx context.Context, w cluster.WorkloadRef, li *localInfo) (problems, notes []string, ready []ReadyShare) {
	ready = []ReadyShare{}
	if w.Kind != cluster.KindApp || len(li.shares) == 0 {
		return nil, nil, ready
	}
	l, err := c.localShares(ctx)
	if err != nil {
		return []string{"this server's shared folders: " + err.Error()}, nil, ready
	}
	info, err := c.Storage.HAShares(ctx)
	if err != nil {
		return []string{"the storage server's shared folders: " + err.Error()}, nil, ready
	}
	var realm string
	var joined bool
	var fs struct {
		Joined bool `json:"joined"`
		Domain *struct {
			Realm string `json:"realm"`
		} `json:"domain"`
	}
	if c.Priv.Call(ctx, priv.OpFilesStatus, nil, &fs) == nil {
		joined = fs.Joined
		if fs.Domain != nil {
			realm = fs.Domain.Realm
		}
	}
	tasks := c.tasksUsingShares(ctx)
	var total uint64
	for _, s := range li.shares {
		sh := findShare(l, s.ID)
		if sh == nil {
			problems = append(problems, fmt.Sprintf("shared folder %s isn't on this server", s.ID))
			continue
		}
		name := sh.Name
		if p := s.Path; !filepath.IsAbs(p) || filepath.Clean(p) != p || filepath.Base(p) != s.ID || filepath.Base(filepath.Dir(p)) != "shares" {
			problems = append(problems, fmt.Sprintf("%s's folder (%q) isn't where a shared folder is", name, p))
		}
		ready = append(ready, ReadyShare{ID: sh.ID, Name: name, SizeBytes: int64(sh.UsedBytes), Write: s.Write})
		total += sh.UsedBytes
		if sh.ID == LibraryShare {
			problems = append(problems, name+" is the VMs' ISO library, which stays on its server; give "+li.name+" another shared folder")
		}
		if !sh.Mounted { // (RootDev, root's own check, doesn't travel)
			problems = append(problems, name+" isn't mounted on this server")
		}
		var others []string
		for _, g := range sh.Apps {
			if g.App != w.ID && !slices.Contains(others, g.App) {
				others = append(others, g.App)
			}
		}
		if len(others) > 0 {
			problems = append(problems, fmt.Sprintf("%s is also used by %s on this server; a shared folder moves to cluster storage with one app only (take it away from the others first)", name, strings.Join(others, ", ")))
		}
		for _, t := range tasks[sh.ID] {
			problems = append(problems, fmt.Sprintf("%s is in the %s on this server; take it out of that task first (back it up from the storage server once it moved)", name, t))
		}
		for _, o := range info.Shares {
			switch {
			case o.ID == sh.ID:
				problems = append(problems, fmt.Sprintf("the storage server has a shared folder with the id %s already (%s)", sh.ID, o.Name))
			case strings.EqualFold(o.Name, sh.Name):
				problems = append(problems, fmt.Sprintf("the storage server has a shared folder called %s already; rename one of them first", o.Name))
			}
		}
		if hasPeople(sh.Access) {
			switch {
			case !joined || realm == "":
				problems = append(problems, name+"'s permissions name domain accounts, but this server doesn't share files as a domain member")
			case !info.Joined || !strings.EqualFold(info.Realm, realm):
				problems = append(problems, fmt.Sprintf("%s's permissions name accounts of %s, but the storage server isn't a member of that domain (Control Panel › File Services there)", name, realm))
			}
		}
		var t hacopy.Tree
		if err := c.Priv.Call(ctx, hacopy.OpTree, hacopy.TreeArgs{Ref: hacopy.Ref{Kind: hacopy.KindShare, ID: sh.ID, Pool: sh.Pool, Side: hacopy.SideLocal}}, &t); err != nil {
			problems = append(problems, name+": "+err.Error())
		} else if p := snapsProblem(&t); p != "" {
			problems = append(problems, name+": "+p)
		}
		if n := c.shareLinks(ctx, sh.ID); n > 0 {
			notes = append(notes, fmt.Sprintf("%d web link(s) to files in %s stop working (make them again on the storage server)", n, name))
		}
		if sh.Services.SMB.Enabled || sh.Services.NFS.Enabled || sh.Services.SFTP || sh.Services.WebDAV {
			notes = append(notes, name+" is shared on the network from the storage server afterwards, under the same name (computers and Time Machine connect to the storage server instead)")
		}
	}
	if info.FreeBytes > 0 && total+total/10 > info.FreeBytes {
		problems = append(problems, fmt.Sprintf("the storage server has %s free; the shared folders need %s", humanBytes(int64(info.FreeBytes)), humanBytes(int64(total))))
	}
	return problems, notes, ready
}

// hasPeople: rules that name domain users or groups.
func hasPeople(rules []shares.Rule) bool {
	for _, r := range rules {
		if r.Kind == shares.KindUser || r.Kind == shares.KindGroup {
			return true
		}
	}
	return false
}

// tasksUsingShares names this server's backup and replication tasks by
// the shared folders in them.
func (c *Converter) tasksUsingShares(ctx context.Context) map[string][]string {
	out := map[string][]string{}
	if c.DB == nil {
		return out
	}
	for _, q := range []struct{ sql, what string }{
		{`SELECT name, items FROM backup_tasks`, "backup task"},
		{`SELECT name, items FROM repl_tasks`, "replication task"},
	} {
		rows, err := c.DB.QueryContext(ctx, q.sql)
		if err != nil {
			continue
		}
		for rows.Next() {
			var name, items string
			if rows.Scan(&name, &items) != nil {
				continue
			}
			var l []struct {
				Kind string `json:"kind"`
				ID   string `json:"id"`
			}
			if json.Unmarshal([]byte(items), &l) != nil {
				continue
			}
			for _, it := range l {
				if it.Kind == "share" {
					out[it.ID] = append(out[it.ID], q.what+" "+strconv.Quote(name))
				}
			}
		}
		rows.Close()
	}
	return out
}

// shareLinks counts the web links into a shared folder that are still
// valid.
func (c *Converter) shareLinks(ctx context.Context, id string) int {
	if c.DB == nil {
		return 0
	}
	var n int
	_ = c.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM share_links WHERE share = ? AND expires_at > ?`, id, store.FormatTime(c.now())).Scan(&n)
	return n
}

// ---- the phases ----------------------------------------------------------------------

// shareRefs are each moving shared folder's ref on this server.
func (c *Converter) shareRefs(ctx context.Context, r *Record) ([]hacopy.Ref, error) {
	pools, err := c.sharePools(ctx, r)
	if err != nil {
		return nil, err
	}
	out := make([]hacopy.Ref, 0, len(r.Options.Shares))
	for i := range r.Options.Shares {
		s := &r.Options.Shares[i]
		out = append(out, s.ref(pools[s.ID], hacopy.SideLocal))
	}
	return out, nil
}

// copyShares snapshots each moving shared folder and copies it.
func (c *Converter) copyShares(ctx context.Context, r *Record, what string, attempt int, actor cluster.Actor, report func(lo, hi float64, what string) func(done, total int64), lo, hi float64) error {
	refs, err := c.shareRefs(ctx, r)
	if err != nil {
		return err
	}
	n := float64(len(refs))
	for i, ref := range refs {
		s := &r.Options.Shares[i]
		if err := c.ensureSnap(ctx, ref, snapName(s.Conv, what, attempt)); err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
		a, b := lo+(hi-lo)*float64(i)/n, lo+(hi-lo)*float64(i+1)/n
		if err := c.sendToStorage(ctx, r, ref, actor, report(a, b, "Copying "+s.Name)); err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
	}
	return nil
}

// holdShares holds each moving shared folder (file sharing lets go of
// it, read-only, unmounted); on a failure the ones held are let go of.
func (c *Converter) holdShares(ctx context.Context, r *Record) error {
	if len(r.Options.Shares) == 0 {
		return nil
	}
	// The copy may have taken hours: what could have changed meanwhile is
	// checked again just before the hold (decision 508).
	l, err := c.localShares(ctx)
	if err != nil {
		return err
	}
	tasks := c.tasksUsingShares(ctx)
	for _, s := range r.Options.Shares {
		sh := findShare(l, s.ID)
		if sh == nil {
			return fmt.Errorf("shared folder %s isn't on this server any more", s.Name)
		}
		for _, g := range sh.Apps {
			if g.App != r.Workload {
				return fmt.Errorf("%s is used by %s on this server now; a shared folder moves with one app only", s.Name, g.App)
			}
		}
		if t := tasks[s.ID]; len(t) > 0 {
			return fmt.Errorf("%s is in the %s on this server now; take it out of that task first", s.Name, t[0])
		}
	}
	for i := range r.Options.Shares {
		s := &r.Options.Shares[i]
		if err := c.Priv.Call(ctx, priv.OpSharesHAHold, shares.HAHoldArgs{ID: s.ID, Conv: s.Conv}, nil); err != nil {
			c.releaseShares(r)
			return fmt.Errorf("holding %s for the move: %w", s.Name, err)
		}
	}
	return nil
}

// releaseShares lets go of this server's held shared folders (the
// conversion gave up before putting them aside).
func (c *Converter) releaseShares(r *Record) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, s := range r.Options.Shares {
		if s.ParkedName != "" && s.ParkedSide == string(hacopy.SideLocal) {
			continue // put aside: Undo puts it back
		}
		if err := c.Priv.Call(ctx, priv.OpSharesHAHold, shares.HAHoldArgs{ID: s.ID, Conv: s.Conv, Release: true}, nil); err != nil {
			c.log().Warn("convert: letting go of a shared folder's hold", "share", s.ID, "err", err)
		}
	}
}

// adoptShares has the storage server set up each copied shared folder
// (held) with this server's settings for it.
func (c *Converter) adoptShares(ctx context.Context, r *Record, actor cluster.Actor) error {
	if len(r.Options.Shares) == 0 {
		return nil
	}
	l, err := c.localShares(ctx)
	if err != nil {
		return err
	}
	for i := range r.Options.Shares {
		s := &r.Options.Shares[i]
		// Read now, from the folder as it is held (nothing changes it
		// since): never an earlier attempt's (decision 508).
		if sh := findShare(l, s.ID); sh != nil {
			set := shares.SettingsOf(sh)
			s.Settings = &set
		} else {
			return fmt.Errorf("shared folder %s isn't on this server any more", s.Name)
		}
		if _, err := c.Storage.HAAdopt(ctx, storagesvc.HARequest{Workload: s.workload(), Pool: r.StoragePool, Conv: s.Conv, Share: s.Settings, Actor: actor}); err != nil {
			return fmt.Errorf("setting up %s on the storage server: %w", s.Name, err)
		}
		s.Adopted = true
		_ = c.save(ctx, r)
	}
	return nil
}

// asideShares puts aside the shared folders the storage server adopted
// for this conversion: one it still holds for the conversion (never
// shared) for an hour when this server's copy is seen to be there; any
// other, and one the storage server reports as shared from there or
// written after its final snapshot, kept until an administrator deletes
// it (UntilDeleted: the storage server's own state decides, not the
// record, decision 508). One still used in the cluster is taken out of it
// first. abort also destroys what the storage server was still receiving
// of the others (Abandon; otherwise it stays to resume).
func (c *Converter) asideShares(ctx context.Context, r *Record, actor cluster.Actor, abort bool) error {
	var errs []error
	for i := range r.Options.Shares {
		s := &r.Options.Shares[i]
		if s.InCluster {
			if err := c.Storage.SetShareCluster(ctx, storagesvc.ShareRequest{Pool: r.StoragePool, ID: s.ID, In: false, Actor: actor}); err != nil {
				errs = append(errs, fmt.Errorf("taking %s out of the cluster: %w", s.Name, err))
				continue
			}
			s.InCluster = false
			_ = c.save(ctx, r)
		}
		req := storagesvc.HARequest{Workload: s.workload(), Pool: r.StoragePool, Confirm: s.ID, Conv: s.Conv + "x" + strconv.Itoa(r.Options.Attempt),
			Expect: s.Conv, Since: snapName(s.Conv, "final", r.Options.Attempt), Actor: actor}
		hour := !s.Released && c.localShareThere(ctx, s)
		park := func() (*hacopy.ParkResult, error) {
			if hour {
				req.KeepUntil = c.now().Add(time.Hour).Unix()
				if pr, err := c.Storage.HAPark(ctx, req); err == nil {
					return pr, nil
				}
				// Refused an expiry (the storage server let go of it: shared
				// from there), or not there: kept until deleted, if there.
			}
			req.KeepUntil = 0
			return c.Storage.HAPark(ctx, req)
		}
		var pr *hacopy.ParkResult
		var err error
		if !s.Adopted {
			// One the storage server adopted whose answer was lost: put
			// aside only if it carries this conversion's mark (refused
			// otherwise, and there's nothing to put aside then).
			pr, err = park()
			if err != nil {
				pr = nil
			}
			if abort {
				if aerr := c.Storage.HAAbort(ctx, storagesvc.HARequest{Workload: s.workload(), Pool: r.StoragePool, Conv: s.Conv, Actor: actor}); aerr != nil {
					errs = append(errs, fmt.Errorf("dropping what was copied of %s: %w", s.Name, aerr))
				}
			}
		} else {
			err = c.waitFor(ctx, 3*time.Minute, "the storage server letting go of "+s.Name, func(*cluster.Snapshot) (bool, error) {
				var perr error
				pr, perr = park()
				return perr == nil, nil
			})
			if err != nil {
				errs = append(errs, fmt.Errorf("putting %s aside on the storage server: %w", s.Name, err))
				continue
			}
		}
		if pr != nil {
			if req.KeepUntil == 0 {
				s.ClusterPool, s.ClusterName = pr.Pool, pr.Name
				s.UntilDeleted = s.UntilDeleted || s.Released || pr.Changed
			}
			s.Adopted, s.Released = false, false
		}
		_ = c.save(ctx, r)
	}
	return errors.Join(errs...)
}

// clusterChanged: a storage server's copy put aside may be newer than
// this server's (kept until an administrator deletes it).
func clusterChanged(r *Record) bool {
	for _, s := range r.Options.Shares {
		if s.UntilDeleted {
			return true
		}
	}
	return false
}

// localShareThere: this server has the shared folder as its own.
func (c *Converter) localShareThere(ctx context.Context, s *ShareMove) bool {
	l, err := c.localShares(ctx)
	return err == nil && findShare(l, s.ID) != nil
}

// localParkedThere: this server's parked copy of a shared folder is
// there (its pool imported: root lists only those), by the record or by
// the conversion's mark.
func (c *Converter) localParkedThere(ctx context.Context, s *ShareMove) bool {
	found, ok := c.parkedShareHere(ctx, s)
	return ok && (s.ParkedName == "" || found.Name == s.ParkedName)
}

// parkShares puts this server's held shared folders aside (refused when
// written after their final snapshot); on a failure the ones parked are
// put back, still held, so the caller goes back before the park. A
// failure to put one back is reported with it (that folder stays parked:
// Undo, or a resume, puts it back).
func (c *Converter) parkShares(ctx context.Context, r *Record, refs []hacopy.Ref) error {
	for i, ref := range refs {
		s := &r.Options.Shares[i]
		if s.ParkedName != "" && s.ParkedSide == string(hacopy.SideLocal) {
			continue
		}
		var pr hacopy.ParkResult
		err := c.Priv.Call(ctx, hacopy.OpPark, hacopy.ParkArgs{Ref: ref, Confirm: s.ID, Conv: s.Conv,
			Since: snapName(s.Conv, "final", r.Options.Attempt), RefuseChanged: true}, &pr)
		if err == nil && pr.Name == "" {
			err = errors.New("root didn't name the parked copy")
		}
		if err != nil {
			err = fmt.Errorf("putting %s aside: %w", s.Name, err)
			if uerr := c.unparkShares(context.WithoutCancel(ctx), r); uerr != nil {
				return errors.Join(err, &stuckParked{uerr})
			}
			return err
		}
		s.ParkedPool, s.ParkedName, s.ParkedSide = pr.Pool, pr.Name, string(hacopy.SideLocal)
		_ = c.save(ctx, r)
	}
	return nil
}

// stuckParked: a shared folder parked here couldn't be put back.
type stuckParked struct{ err error }

func (e *stuckParked) Error() string { return e.err.Error() }
func (e *stuckParked) Unwrap() error { return e.err }

// sharesParkedHere: a shared folder of r is parked on this server (by
// the record, or found by its conversion's mark).
func (c *Converter) sharesParkedHere(ctx context.Context, r *Record) []string {
	var out []string
	for i := range r.Options.Shares {
		s := &r.Options.Shares[i]
		if (s.ParkedName != "" && s.ParkedSide == string(hacopy.SideLocal)) || c.localParkedThere(ctx, s) {
			out = append(out, s.Name)
		}
	}
	return out
}

// unparkShares puts this server's parked shared folders back (file
// sharing takes them up again); it reports the first failure.
func (c *Converter) unparkShares(ctx context.Context, r *Record) error {
	var first error
	for i := range r.Options.Shares {
		s := &r.Options.Shares[i]
		pool, name := s.ParkedPool, s.ParkedName
		if name == "" || s.ParkedSide != string(hacopy.SideLocal) {
			// One root parked whose answer was lost.
			pool, name = "", ""
			if found, ok := c.parkedShareHere(ctx, s); ok {
				pool, name = found.Pool, found.Name
			}
		}
		if name == "" {
			continue
		}
		ref := s.ref(pool, hacopy.SideLocal)
		if err := c.Priv.Call(ctx, hacopy.OpUnpark, hacopy.UnparkArgs{Ref: ref, Name: name}, nil); err != nil {
			if first == nil {
				first = fmt.Errorf("putting %s back: %w", s.Name, err)
			}
			continue
		}
		s.ParkedPool, s.ParkedName, s.ParkedSide = "", "", ""
		_ = c.save(ctx, r)
	}
	return first
}

// parkedShareHere finds this server's copy of a shared folder its
// conversion parked.
func (c *Converter) parkedShareHere(ctx context.Context, s *ShareMove) (*hacopy.ParkResult, bool) {
	return c.parkedHere(ctx, s.workload(), s.Conv)
}

// shareIntoCluster lets go of each shared folder on the storage server
// (only once this server's copy is parked: from then on that one is the
// only copy) and puts it in the cluster, then waits until this server
// mounts them.
func (c *Converter) shareIntoCluster(ctx context.Context, r *Record, actor cluster.Actor) error {
	for i := range r.Options.Shares {
		s := &r.Options.Shares[i]
		if s.ParkedName == "" || s.ParkedSide != string(hacopy.SideLocal) {
			return fmt.Errorf("this server's copy of %s isn't recorded as put aside; resume the conversion", s.Name)
		}
		if !s.Released {
			if err := c.Storage.HAShareRelease(ctx, storagesvc.HARequest{Workload: s.workload(), Conv: s.Conv, Actor: actor}); err != nil {
				return fmt.Errorf("sharing %s from the storage server: %w", s.Name, err)
			}
			s.Released = true
			_ = c.save(ctx, r)
		}
		if !s.InCluster {
			if err := c.Storage.SetShareCluster(ctx, storagesvc.ShareRequest{Pool: r.StoragePool, ID: s.ID, In: true, Actor: actor}); err != nil {
				return fmt.Errorf("using %s in the cluster: %w", s.Name, err)
			}
			s.InCluster = true
			_ = c.save(ctx, r)
		}
	}
	if len(r.Options.Shares) == 0 {
		return nil
	}
	return c.waitFor(ctx, 3*time.Minute, "this server mounting the shared folders from the storage server", func(*cluster.Snapshot) (bool, error) {
		var st sanclient.Status
		if err := c.Priv.Call(ctx, sanclient.OpStatus, nil, &st); err != nil {
			return false, nil
		}
		for _, s := range r.Options.Shares {
			if st.Shares[s.ID] == "" {
				return false, nil
			}
		}
		return true, nil
	})
}

// sharePaths are the folders the app's compose file names its moving
// shared folders by (apps.HAAdoptArgs.Shares).
func sharePaths(r *Record) map[string]string {
	if len(r.Options.Shares) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, s := range r.Options.Shares {
		out[s.ID] = s.Path
	}
	return out
}

// keepShares gives this server's parked shared folders their grace
// period.
func (c *Converter) keepShares(ctx context.Context, r *Record, actor cluster.Actor) {
	for _, s := range r.Options.Shares {
		if s.ParkedName != "" && s.ParkedSide == string(hacopy.SideLocal) {
			if err := c.keepFor(ctx, hacopy.SideLocal, s.ParkedPool, s.ParkedName, c.grace(), actor); err != nil {
				c.log().Warn("convert: a shared folder's kept copy's grace period", "share", s.ID, "err", err)
			}
		}
		if s.ClusterName != "" && !s.UntilDeleted {
			if err := c.keepFor(ctx, hacopy.SideCluster, s.ClusterPool, s.ClusterName, c.grace(), actor); err != nil {
				c.log().Warn("convert: a shared folder's kept copy's grace period", "share", s.ID, "err", err)
			}
		}
	}
}

// destroyShareSnaps removes the conversion's own snapshots of this
// server's shared folders (an abandoned conversion).
func (c *Converter) destroyShareSnaps(ctx context.Context, r *Record) {
	refs, err := c.shareRefs(ctx, r)
	if err != nil {
		return
	}
	for i, ref := range refs {
		s := r.Options.Shares[i]
		for a := 1; a <= r.Options.Attempt; a++ {
			for _, w := range []string{"pre", "final"} {
				_ = c.Priv.Call(ctx, hacopy.OpSnapDestroy, hacopy.SnapArgs{Ref: ref, Name: snapName(s.Conv, w, a)}, nil)
			}
		}
	}
}

// appShares are the shared folders a cluster app uses, asked of the
// server it is placed on (make local refuses apps that use any: their
// shared folders are the storage server's now).
func (c *Converter) appShares(ctx context.Context, id string) ([]apps.HAShare, error) {
	snap := c.snapshot()
	pl := snap.Placements[cluster.WorkloadRef{Kind: cluster.KindApp, ID: id}]
	if pl == nil {
		return nil, errors.New("it isn't a cluster app")
	}
	self, err := c.Cluster.Self()
	if err != nil {
		return nil, err
	}
	if pl.Owner == self.ID {
		var res apps.HACheckResult
		if err := c.Priv.Call(ctx, priv.OpAppsHACheck, priv.AppRef{ID: id}, &res); err != nil {
			return nil, err
		}
		return res.Shares, nil
	}
	if c.Peers == nil || pl.Owner == "" {
		return nil, errors.New("its server can't be asked")
	}
	var out struct {
		Shares []apps.HAShare `json:"shares"`
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := c.Peers.Call(cctx, pl.Owner, "GET", cluster.PeerPathPrefix+PathAppShares+"?id="+id, nil, &out); err != nil {
		return nil, fmt.Errorf("asking %s: %w", pl.Owner, err)
	}
	return out.Shares, nil
}
