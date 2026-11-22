package cloudbackup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/apps"
	"github.com/hardyos/hardyos/daemon/internal/mail"
)

// The mail server as a backup item (decisions 460-469): one restic
// snapshot of <pool>/mail (part=files, prepared by mail.Root so the
// configuration and Rspamd's data are in it) and, when the webmail app is
// installed, one of its dataset (part=webmail: Roundcube's preferences).
// Both come from ZFS snapshots of the same moment of the run.

// Parts of the mail item.
const (
	MailPartFiles   = "files"
	MailPartWebmail = "webmail"
)

// MailRecord is the mail item in a run manifest.
type MailRecord struct {
	Pool      string   `json:"pool"`
	Domains   []string `json:"domains"`
	Mailboxes int      `json:"mailboxes"`
	Bayes     bool     `json:"bayes"`
	Webmail   bool     `json:"webmail"`
}

func (r *Root) backupMail(ctx context.Context, repo *Repo, snap string, tags func(extra ...string) []string, ir *ItemResult, m *Manifest, step func(Progress, string)) error {
	ir.Name, ir.Consistent = "Mail", true
	if r.Mail == nil {
		return errors.New("the mail server can't be backed up here")
	}
	step(Progress{}, "Preparing the mail")
	src, err := r.Mail.PrepareBackup(ctx)
	if errors.Is(err, mail.ErrNotSetUp) {
		// On by default (decision 460): a server without a mail server has
		// nothing to back up, which isn't a failure.
		ir.Warning = "the mail server isn't set up here, so there was nothing to back up"
		return nil
	}
	if err != nil {
		return fmt.Errorf("preparing the mail: %w", err)
	}
	if len(src.Warnings) > 0 {
		ir.Warning = strings.Join(src.Warnings, "; ")
	}
	rec := &MailRecord{Pool: src.Pool, Domains: src.Domains, Mailboxes: src.Mailboxes, Bayes: src.Bayes}
	m.Mail = rec
	// Mail and webmail are snapshotted together, then sent one after the
	// other.
	var web *apps.BackupSource
	if r.Apps != nil {
		if w, err := r.Apps.BackupSource(ctx, WebmailApp); err == nil {
			web = w
		}
	}
	webIt := Item{Kind: ItemMail, ID: MailPartWebmail}
	files := Item{Kind: ItemMail, ID: MailPartFiles}
	unlock := r.itemLock(r.mountDir(files))
	defer unlock()
	if err := r.Vol.Snapshot(ctx, src.Dataset, snap); err != nil {
		return fmt.Errorf("taking the snapshot: %w", err)
	}
	defer func() {
		if err := r.Vol.DestroySnapshot(context.WithoutCancel(ctx), src.Dataset, snap); err != nil {
			r.log().Warn("cloud backup: removing the snapshot", "dataset", src.Dataset, "err", err)
		}
	}()
	if web != nil {
		if err := r.Vol.Snapshot(ctx, web.Dataset, snap); err != nil {
			web = nil
			ir.Warning = joinWarning(ir.Warning, "webmail settings aren't in this version: "+err.Error())
		} else {
			defer func() {
				if err := r.Vol.DestroySnapshot(context.WithoutCancel(ctx), web.Dataset, snap); err != nil {
					r.log().Warn("cloud backup: removing the snapshot", "dataset", web.Dataset, "err", err)
				}
			}()
		}
	}
	parts := 1.0
	if web != nil {
		parts = 2
	}
	if err := r.backupMounted(ctx, repo, src.Dataset, snap, r.mountDir(files), tags("part="+MailPartFiles), ir,
		func(p Progress, what string) { step(Progress{Percent: p.Percent / parts}, what) }, "Backing up the mail"); err != nil {
		return err
	}
	if web != nil {
		wr := ItemResult{}
		if err := r.backupMounted(ctx, repo, web.Dataset, snap, r.mountDir(webIt), tags("part="+MailPartWebmail), &wr,
			func(p Progress, what string) { step(Progress{Percent: 0.5 + p.Percent/2}, what) }, "Backing up the webmail settings"); err != nil {
			ir.Warning = joinWarning(ir.Warning, "webmail settings aren't in this version: "+err.Error())
		} else {
			rec.Webmail = true
			ir.Snapshots = append(ir.Snapshots, wr.Snapshots...)
			ir.Files += wr.Files
			ir.Bytes += wr.Bytes
			ir.Added += wr.Added
		}
	}
	return nil
}

func joinWarning(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// mailConfig reads a version's mail configuration (without staging it).
func (r *Root) mailConfig(ctx context.Context, repo *Repo, snap *Snapshot) (*mail.RootConfig, error) {
	var buf bytes.Buffer
	lw := &limitWriter{w: &buf, n: 8<<20 + 1}
	if err := r.Restic.Dump(ctx, repo, snap.ID, path.Join(snap.Paths[0], mail.BackupDir, mail.BackupConfigName), lw); err != nil {
		return nil, fmt.Errorf("the version's mail configuration can't be read: %w", err)
	}
	if buf.Len() > 8<<20 {
		return nil, errors.New("the version's mail configuration is too large")
	}
	return mail.ParseBackupConfig(buf.Bytes())
}

// MailContentsArgs names a mail version.
type MailContentsArgs struct {
	Target   string `json:"target"`
	Snapshot string `json:"snapshot"`
}

// MailContents is what a mail version holds.
type MailContents struct {
	mail.Contents
	Webmail bool `json:"webmail"`
}

// MailContents lists the domains and mailboxes of a mail version.
func (r *Root) MailContents(ctx context.Context, a MailContentsArgs) (*MailContents, error) {
	repo, err := r.repo(a.Target)
	if err != nil {
		return nil, err
	}
	snap, it, err := r.findSnapshot(ctx, repo, a.Snapshot)
	if err != nil {
		return nil, err
	}
	if it.Kind != ItemMail || (snap.Tag("part") != MailPartFiles && snap.Tag("part") != "") {
		return nil, problemf("that isn't a version of the mail")
	}
	cfg, err := r.mailConfig(ctx, repo, snap)
	if err != nil {
		return nil, err
	}
	out := &MailContents{Contents: mail.ContentsOf(cfg)}
	out.Webmail = r.webmailOf(ctx, repo, snap) != nil
	return out, nil
}

// webmailOf finds the webmail part of the same run, item and server.
func (r *Root) webmailOf(ctx context.Context, repo *Repo, snap *Snapshot) *Snapshot {
	all, err := r.snapshots(ctx, repo)
	if err != nil {
		return nil
	}
	for i := range all {
		s := &all[i]
		if s.Tag("run") == snap.Tag("run") && s.Tag("item") == ItemMail && s.Tag("server") == snap.Tag("server") && s.Tag("part") == MailPartWebmail &&
			len(s.Paths) == 1 && s.Paths[0] == r.mountDir(Item{Kind: ItemMail, ID: MailPartWebmail}) {
			return s
		}
	}
	return nil
}

// mailRels is what of a version a restore needs to download.
func mailRels(a mail.RestoreArgs, ver *mail.RootConfig) [][]string {
	rels := [][]string{{mail.BackupDir}}
	cal := func(key string) []string { return []string{"radicale", "collections", "collection-root", key} }
	switch a.Scope {
	case mail.ScopeMailbox:
		rels = append(rels, []string{"vmail", a.Key})
	case mail.ScopeCalendars:
		rels = append(rels, cal(a.Key))
	case mail.ScopeDomain:
		rels = append(rels, []string{"keys", "dkim"})
		for _, m := range ver.Mailboxes {
			if strings.HasSuffix(m.Address, "@"+a.Domain) {
				rels = append(rels, []string{"vmail", m.Key}, cal(m.Key))
			}
		}
	default:
		return nil // everything
	}
	return rels
}

func (r *Root) restoreMail(ctx context.Context, tc taskCtx, repo *Repo, snap *Snapshot, a mail.RestoreArgs) (*RestoreResult, error) {
	pool, err := r.Mail.Pool(ctx)
	if errors.Is(err, mail.ErrNotSetUp) {
		return nil, problemf("set the mail server up first (Control Panel › Mail), then restore into it; a rebuilt server uses Rebuild")
	}
	if err != nil {
		return nil, err
	}
	tc.progress(2, "Reading what the version holds")
	ver, err := r.mailConfig(ctx, repo, snap)
	if err != nil {
		return nil, err
	}
	st, err := r.stage(ctx, tc, repo, snap, pool, mailRels(a, ver), 0)
	if err != nil {
		return nil, err
	}
	defer r.unstage(st)
	tc.progress(70, "Putting the mail back")
	mr, err := r.Mail.RestoreFrom(ctx, st.root, a)
	res := &RestoreResult{Notes: []string{}, Mail: mr}
	if mr != nil {
		res.Files, res.Bytes, res.Safety = mr.Messages, mr.Bytes, mr.Safety
		res.Notes = append(res.Notes, mr.Notes...)
	}
	if err != nil {
		var ve *mail.ValidationError
		if errors.As(err, &ve) {
			return res, &Problem{Msg: ve.Msg}
		}
		return res, err
	}
	// Everything: Roundcube's preferences too.
	if a.Scope == mail.ScopeAll {
		if web := r.webmailOf(ctx, repo, snap); web != nil {
			tc.progress(90, "Putting the webmail settings back")
			if err := r.restoreWebmail(ctx, tc, repo, web, pool); err != nil {
				res.Notes = append(res.Notes, "webmail settings: "+err.Error())
			} else {
				res.Notes = append(res.Notes, "Webmail settings are back.")
			}
		}
	}
	return res, nil
}

// restoreWebmail puts the webmail app's data back: in place when it's
// installed, or as a new install of it.
func (r *Root) restoreWebmail(ctx context.Context, tc taskCtx, repo *Repo, snap *Snapshot, pool string) error {
	if r.Apps == nil {
		return errors.New("apps aren't available on this server")
	}
	if src, err := r.Apps.BackupSource(ctx, WebmailApp); err == nil {
		st, err := r.stage(ctx, tc, repo, snap, src.Pool, nil, 0)
		if err != nil {
			return err
		}
		defer r.unstage(st)
		return r.Apps.RestoreData(ctx, WebmailApp, src.Name, func(ctx context.Context, dir, dataset string) error {
			dev, err := r.Vol.VerifyMount(dir, dataset)
			if err != nil {
				return err
			}
			_, err = r.fillFrom(ctx, st, dir, dev, false, linksOnlyInData, false)
			return err
		})
	}
	return r.rebuildApp(ctx, tc, repo, snap, Item{Kind: ItemApp, ID: WebmailApp}, pool)
}

func (r *Root) rebuildMail(ctx context.Context, tc taskCtx, repo *Repo, snap *Snapshot, pool string, res *RebuildResult) error {
	if r.Mail == nil {
		return errors.New("the mail server can't be restored here")
	}
	st, err := r.stage(ctx, tc, repo, snap, pool, nil, 0)
	if err != nil {
		return err
	}
	defer r.unstage(st)
	if _, err := r.Mail.RebuildFrom(ctx, pool, st.root); err != nil {
		var ve *mail.ValidationError
		if errors.As(err, &ve) {
			return &Problem{Msg: ve.Msg}
		}
		return err
	}
	if web := r.webmailOf(ctx, repo, snap); web != nil {
		if err := r.restoreWebmail(ctx, tc, repo, web, pool); err != nil {
			var p *Problem
			if !errors.As(err, &p) || !strings.Contains(p.Msg, "already") {
				res.Failed = append(res.Failed, "webmail settings: "+err.Error())
			}
		}
	}
	return nil
}
