package cloudbackup

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/backup"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Rebuilding a dead server: a fresh install with "Restore from backup"
// (the installer stages the settings and domain from the newest version,
// which hardyd-priv applies at the first start, and leaves the destination
// for this package in ConnectFile), then Rebuild brings the shared
// folders, apps and VMs of a version back onto a pool of the new server.

// ConnectFile is what the installer leaves for the first start: the
// destination and its credentials, in root's state directory (0600). At
// start they are sealed into the targets file and this file is removed.
const ConnectFile = "connect.json"

// RebuildFile records the version a rebuilt server came from, until its
// folders, apps and VMs are back (the Backup app offers to finish).
const RebuildFile = "rebuild.json"

// Connect is a destination as typed into the installer.
type Connect struct {
	Target Target      `json:"target"`
	Creds  Credentials `json:"creds"`
	Run    string      `json:"run"`
}

// RebuildOffer is a rebuilt server's pending rebuild.
type RebuildOffer struct {
	Target string    `json:"target"`
	Run    string    `json:"run"`
	Since  time.Time `json:"since"`
}

// KitBegin and KitEnd frame the machine-readable part of a recovery kit.
const (
	KitBegin = "-----BEGIN HARDYOS RECOVERY KIT-----"
	KitEnd   = "-----END HARDYOS RECOVERY KIT-----"
)

// KitData is the machine-readable part of a recovery kit.
type KitData struct {
	Format     int    `json:"format"`
	Target     Target `json:"target"`
	Repository string `json:"repository"`
	Key        string `json:"key"`
}

// ParseKit reads a recovery kit's text (as downloaded, or just its framed
// block).
func ParseKit(text string) (*KitData, error) {
	i := strings.Index(text, KitBegin)
	j := strings.Index(text, KitEnd)
	if i < 0 || j < i {
		return nil, problemf("that isn't a HardyOS recovery kit (paste the whole file)")
	}
	body := strings.Join(strings.Fields(text[i+len(KitBegin):j]), "")
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, problemf("the recovery kit is damaged")
	}
	var k KitData
	if err := json.Unmarshal(raw, &k); err != nil || k.Format != 1 {
		return nil, problemf("the recovery kit is damaged")
	}
	if err := ValidRepoPassword(k.Key); err != nil {
		return nil, err
	}
	return &k, nil
}

// EncodeKit frames a kit's data for the text file.
func EncodeKit(k KitData) string {
	k.Format = 1
	b, _ := json.Marshal(k)
	enc := base64.StdEncoding.EncodeToString(b)
	var sb strings.Builder
	sb.WriteString(KitBegin + "\n")
	for len(enc) > 64 {
		sb.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	sb.WriteString(enc + "\n" + KitEnd + "\n")
	return sb.String()
}

func (r *Root) dir() string {
	if r.Dir != "" {
		return r.Dir
	}
	return DefaultDir
}

// OnStart takes over what the installer left (ConnectFile).
func (r *Root) OnStart() {
	p := filepath.Join(r.dir(), ConnectFile)
	b, err := rootfile.ReadFileInRootDir(p)
	if rootfile.IsNotExist(err) {
		return
	}
	defer func() {
		if err := removeInRootDir(p); err != nil {
			r.log().Warn("cloud backup: removing the installer's destination file", "err", err)
		}
	}()
	if err != nil {
		r.log().Warn("cloud backup: the installer's destination file", "err", err)
		return
	}
	var c Connect
	if err := json.Unmarshal(b, &c); err != nil {
		r.log().Warn("cloud backup: the installer's destination file", "err", err)
		return
	}
	t := c.Target
	if err := t.Normalize(r.AllowLocal); err != nil || CheckCredentials(t.Kind, c.Creds) != nil || ValidRepoPassword(c.Creds.RepoPassword) != nil {
		r.log().Warn("cloud backup: the installer's destination isn't valid", "err", err)
		return
	}
	t.AccessKeyHint = hint(c.Creds.AccessKey)
	if err := r.targets().put(&Repo{Target: t, Creds: c.Creds}); err != nil {
		r.log().Warn("cloud backup: keeping the installer's destination", "err", err)
		return
	}
	if ValidRunID(c.Run) == nil {
		ob, _ := json.Marshal(RebuildOffer{Target: t.ID, Run: c.Run, Since: r.now()})
		if err := rootfile.WriteInRootDir(filepath.Join(r.dir(), RebuildFile), ob, 0o600, 0o700); err != nil {
			r.log().Warn("cloud backup: recording the rebuild", "err", err)
		}
	}
	r.log().Info("cloud backup: destination from the installer kept", "target", t.ID)
}

// Offer returns the pending rebuild, if any.
func (r *Root) Offer() *RebuildOffer {
	b, err := rootfile.ReadFileInRootDir(filepath.Join(r.dir(), RebuildFile))
	if err != nil {
		return nil
	}
	var o RebuildOffer
	if json.Unmarshal(b, &o) != nil {
		return nil
	}
	return &o
}

// Dismiss forgets the pending rebuild.
func (r *Root) Dismiss() error {
	err := removeInRootDir(filepath.Join(r.dir(), RebuildFile))
	if rootfile.IsNotExist(err) {
		return nil
	}
	return err
}

// readManifest dumps a version's manifest.
func (r *Root) readManifest(ctx context.Context, repo *Repo, id string) (*Manifest, error) {
	var buf bytes.Buffer
	if err := r.Restic.Dump(ctx, repo, id, "/"+ManifestName, &limitWriter{w: &buf, n: 16 << 20}); err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		return nil, fmt.Errorf("the version's manifest can't be read: %w", err)
	}
	return &m, nil
}

// RebuildArgs brings a version's shared folders, apps and VMs back.
type RebuildArgs struct {
	Target string `json:"target"`
	Run    string `json:"run"`
	// Pool is where everything goes.
	Pool string `json:"pool"`
	// Items to bring back (item keys); empty: everything but the settings.
	Items []string `json:"items,omitempty"`
	// Confirm must be "rebuild".
	Confirm string `json:"confirm"`
}

// RebuildResult lists what came back.
type RebuildResult struct {
	Restored []string `json:"restored"`
	Skipped  []string `json:"skipped"`
	Failed   []string `json:"failed"`
}

// StartRebuild starts a rebuild.
func (r *Root) StartRebuild(ctx context.Context, a RebuildArgs) (*Task, error) {
	if a.Confirm != "rebuild" {
		return nil, problemf("confirm the rebuild")
	}
	if err := ValidRunID(a.Run); err != nil {
		return nil, err
	}
	if err := zfs.ValidPoolName(a.Pool); err != nil || backup.BootPools[a.Pool] {
		return nil, problemf("choose a data pool")
	}
	want := map[string]bool{}
	for _, k := range a.Items {
		it, err := ParseItem(k)
		if err != nil {
			return nil, err
		}
		want[it.Key()] = true
	}
	repo, err := r.repo(a.Target)
	if err != nil {
		return nil, err
	}
	return r.tasks.start(TaskRebuild, a.Target, func(ctx context.Context, tc taskCtx) (any, error) {
		return r.rebuild(ctx, tc, repo, a, want)
	})
}

func (r *Root) rebuild(ctx context.Context, tc taskCtx, repo *Repo, a RebuildArgs, want map[string]bool) (*RebuildResult, error) {
	snapshotCache.drop(repo.Target.ID)
	all, err := r.snapshots(ctx, repo)
	if err != nil {
		return nil, err
	}
	var v *Version
	for _, x := range GroupVersions(all) {
		if x.Run == a.Run {
			x := x
			v = &x
		}
	}
	if v == nil || v.Manifest == "" {
		return nil, problemf("that version isn't complete or doesn't exist any more")
	}
	m, err := r.readManifest(ctx, repo, v.Manifest)
	if err != nil {
		return nil, err
	}
	res := &RebuildResult{Restored: []string{}, Skipped: []string{}, Failed: []string{}}
	snapOf := map[string]*Snapshot{}
	for i := range all {
		s := &all[i]
		if s.Tag("run") == a.Run && (s.Tag("part") == "" || s.Tag("part") == "files") {
			snapOf[s.Tag("item")] = s
		}
	}
	n := float64(len(v.Items))
	for i, vi := range v.Items {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		tc.progress(float64(i)/n*100, "Bringing back "+vi.Item)
		it, err := ParseItem(vi.Item)
		if err != nil || it.Kind == ItemSystem || (len(want) > 0 && !want[vi.Item]) {
			continue
		}
		snap := snapOf[vi.Item]
		if snap == nil {
			res.Failed = append(res.Failed, vi.Item+": not in this version")
			continue
		}
		sub := taskCtx{t: tc.t, id: tc.id}
		var ierr error
		switch it.Kind {
		case ItemShare:
			ierr = r.rebuildShare(ctx, sub, repo, snap, it, m, a.Pool, res)
		case ItemApp:
			ierr = r.rebuildApp(ctx, sub, repo, snap, it, a.Pool)
		case ItemVM:
			_, ierr = r.restoreVM(ctx, sub, repo, snap, it, "", a.Pool)
		}
		var p *Problem
		switch {
		case ierr == nil:
			res.Restored = append(res.Restored, vi.Item)
		case errors.As(ierr, &p) && strings.Contains(p.Msg, "already"):
			res.Skipped = append(res.Skipped, vi.Item+": "+p.Msg)
		default:
			res.Failed = append(res.Failed, vi.Item+": "+ierr.Error())
		}
	}
	if len(res.Failed) == 0 {
		_ = r.Dismiss()
	}
	return res, nil
}

func (r *Root) rebuildShare(ctx context.Context, tc taskCtx, repo *Repo, snap *Snapshot, it Item, m *Manifest, pool string, res *RebuildResult) error {
	var rec *ShareRecord
	for i := range m.Shares {
		if m.Shares[i].ID == it.ID {
			rec = &m.Shares[i]
		}
	}
	if rec == nil {
		return fmt.Errorf("the version doesn't describe the shared folder %s", it.ID)
	}
	l, err := r.Shares.List(ctx)
	if err != nil {
		return err
	}
	for _, sh := range l {
		if sh.ID == it.ID {
			return problemf("%s is already on this server", rec.Name)
		}
	}
	svc := rec.Services
	if _, err := r.Shares.Create(ctx, shares.NewShare{Pool: pool, Name: rec.Name, ID: rec.ID, Description: rec.Description,
		QuotaBytes: rec.QuotaBytes, Recycle: rec.Recycle, Guest: rec.Guest, Access: rec.Access, Services: &svc}); err != nil {
		return fmt.Errorf("making %s: %w", rec.Name, err)
	}
	sh, err := r.findShare(ctx, it.ID)
	if err != nil {
		return err
	}
	st, err := r.stage(ctx, tc, repo, snap, pool, nil)
	if err != nil {
		return err
	}
	defer r.unstage(st)
	_, err = r.fillFrom(ctx, st, sh.Path, sh.RootDev, true, nil)
	return err
}

func (r *Root) rebuildApp(ctx context.Context, tc taskCtx, repo *Repo, snap *Snapshot, it Item, pool string) error {
	if r.Apps == nil {
		return errors.New("apps aren't available on this server")
	}
	st, err := r.stage(ctx, tc, repo, snap, pool, nil)
	if err != nil {
		return err
	}
	defer r.unstage(st)
	return r.Apps.RestoreNew(ctx, it.ID, pool, func(ctx context.Context, dir, dataset string) error {
		dev, err := r.Vol.VerifyMount(dir, dataset)
		if err != nil {
			return err
		}
		_, err = r.fillFrom(ctx, st, dir, dev, false, linksOnlyInData)
		return err
	})
}
