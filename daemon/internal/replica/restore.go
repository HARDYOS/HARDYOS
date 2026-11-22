package replica

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// PropRestoring marks a copy that's still coming back; RestoreAbort only
// ever destroys datasets that carry it.
const PropRestoring = "org.hardyos:restoring"

// Restorer turns what a restore brought back into a shared folder, VM or
// app's kept data (in hardyd-priv: the shares, VM and apps managers).
type Restorer interface {
	// ShareProps checks a new shared folder (pool, id and name free and
	// valid) and returns the "-o name=value" properties it's received
	// with: no access for anyone but administrators, no network services.
	ShareProps(ctx context.Context, pool, id, name string) ([]string, error)
	// ShareAdopt is called once the folder's datasets are in place and
	// mounted.
	ShareAdopt(ctx context.Context, pool, id string) error
	// VMFree reports whether no VM uses the id.
	VMFree(ctx context.Context, id string) error
	// VMAdopt defines a restored VM with libvirt (off), after resetting
	// what could reach beyond it; notes say what was reset.
	VMAdopt(ctx context.Context, id string) ([]string, error)
	// AppsPool is the pool apps live on.
	AppsPool(ctx context.Context) (string, error)
	// AppAdopt marks a restored app's data as kept (reinstall it from
	// the App Store to use it again).
	AppAdopt(ctx context.Context, id string) error
	// MailPool is the pool of this server's mail server (a mail copy
	// comes back next to it).
	MailPool(ctx context.Context) (string, error)
	// MailRestore puts what args (mail.RestoreArgs) says into the mail
	// server from dir, the copy mounted read-only; it returns what it did.
	MailRestore(ctx context.Context, dir string, args json.RawMessage) (result json.RawMessage, notes []string, err error)
}

// MailRestoresDataset holds mail copies while they come back:
// <pool>/mail-restores/<id>, never mounted but in MailRestoreDir.
const MailRestoresDataset = "mail-restores"

func (m *Manager) mailRestoreDir() string {
	if m.MailRestoreDir != "" {
		return m.MailRestoreDir
	}
	return "/run/hardyos/mail-restore"
}

// RestoreArgs receives one dataset of an item coming back from a
// replica. Kind and ID name the original item; for shared folders the copy
// becomes a new folder NewID called Name on Pool. VMs come back to the
// pool their settings name (Pool) under their own id, apps to the apps
// pool, both only when nothing there uses the id.
type RestoreArgs struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Child    string `json:"child"`
	Pool     string `json:"pool"`
	NewID    string `json:"newId,omitempty"`
	Name     string `json:"name,omitempty"`
	Snapshot string `json:"snapshot"`
	// From is the replica's server, recorded on the copy.
	From string `json:"from"`
}

var fromRE = strings.NewReplacer("\t", " ", "\n", " ", "\r", " ", "\x00", "")

func (m *Manager) existsDS(ctx context.Context, ds string) bool {
	_, ok := m.exists(ctx, ds)
	return ok
}

// restoreDataset is where a restore puts an item's top dataset.
func (m *Manager) restoreDataset(ctx context.Context, a *RestoreArgs) (string, error) {
	if err := (Item{Kind: a.Kind, ID: a.ID}).Validate(); err != nil {
		return "", err
	}
	if err := ValidChild(a.Child); err != nil {
		return "", err
	}
	if m.Restore == nil {
		return "", fmt.Errorf("restoring isn't available on this server")
	}
	switch a.Kind {
	case KindShare:
		if err := ValidPool(a.Pool); err != nil {
			return "", err
		}
		if err := ValidItem(a.NewID); err != nil {
			return "", err
		}
		return a.Pool + "/shares/" + a.NewID, nil
	case KindVM:
		if err := ValidPool(a.Pool); err != nil {
			return "", err
		}
		return a.Pool + "/vms/" + a.ID, nil
	case KindMail:
		// A copy to put back into the mail server, then destroyed.
		pool, err := m.Restore.MailPool(ctx)
		if err != nil {
			return "", err
		}
		if err := ValidItem(a.NewID); err != nil {
			return "", err
		}
		if a.Child != "" {
			return "", invalid("the mail is one dataset")
		}
		a.Pool = pool
		return pool + "/" + MailRestoresDataset + "/" + a.NewID, nil
	default:
		pool, err := m.Restore.AppsPool(ctx)
		if err != nil {
			return "", err
		}
		a.Pool = pool
		return pool + "/apps/" + a.ID, nil
	}
}

// RestoreRecv starts receiving a replica's snapshot back. The first
// dataset (Child "") must be new; the rest go below it. The stream is
// checked like any other (one dataset, whole snapshot, no properties).
func (m *Manager) RestoreRecv(ctx context.Context, a RestoreArgs) (*RecvStart, *os.File, error) {
	if err := ValidSnap(a.Snapshot, ""); err != nil {
		return nil, nil, err
	}
	top, err := m.restoreDataset(ctx, &a)
	if err != nil {
		return nil, nil, err
	}
	ds := top + childSuffix(a.Child)
	var props []string
	if a.Child == "" {
		if _, ok := m.exists(ctx, top); ok {
			return nil, nil, invalid("%s already exists", top)
		}
		switch a.Kind {
		case KindShare:
			if props, err = m.Restore.ShareProps(ctx, a.Pool, a.NewID, a.Name); err != nil {
				return nil, nil, err
			}
		case KindVM:
			if err := m.Restore.VMFree(ctx, a.ID); err != nil {
				return nil, nil, err
			}
			props = []string{"org.hardyos:vm=" + a.ID, "canmount=on", "devices=off", "setuid=off", "exec=off"}
		case KindApp:
			props = []string{"canmount=on", "devices=off", "setuid=off"}
		case KindMail:
			// Read only, mounted by RestoreFinish in a folder only root
			// may open, never at the pool's mountpoint.
			props = []string{"canmount=noauto", "readonly=on", "devices=off", "setuid=off", "exec=off",
				"mountpoint=" + m.mailRestoreDir() + "/" + a.NewID}
		}
		if parent := top[:strings.LastIndex(top, "/")]; !m.existsDS(ctx, parent) {
			create := []string{"create", parent}
			if a.Kind == KindMail {
				create = []string{"create", "-o", "canmount=off", "-o", "mountpoint=none", parent}
			}
			if _, err := m.zfs(ctx, create...); err != nil {
				return nil, nil, err
			}
		}
	} else {
		if m.prop(ctx, top, PropRestoring) != "1" {
			return nil, nil, invalid("%s isn't being restored", top)
		}
		if _, ok := m.exists(ctx, ds); ok {
			return nil, nil, invalid("%s already exists", ds)
		}
		if a.Kind == KindVM {
			props = []string{"org.hardyos:vm=" + a.ID}
		}
	}
	from := fromRE.Replace(a.From)
	if len(from) > 120 {
		from = from[:120]
	}
	props = append(props, PropRestoring+"=1", PropRestored+"="+from+"@"+a.Snapshot)
	s, err := m.streams.add(ds, kindRestore)
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
		s.finish(m.receiveRestore(pr, s, ds, a, props))
	}()
	m.log().Info("replication: restore", "stream", s.id, "dataset", ds, "snapshot", a.Snapshot)
	return &RecvStart{Stream: s.id}, pw, nil
}

func (m *Manager) receiveRestore(r *os.File, s *stream, ds string, a RestoreArgs, props []string) error {
	hdr := make([]byte, BeginRecordSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return fmt.Errorf("reading the stream: %w", err)
	}
	b, err := ParseBegin(hdr)
	if err != nil {
		return err
	}
	if err := (Policy{Label: a.Snapshot}).Check(b); err != nil {
		m.log().Warn("replication: refused a restore stream", "dataset", ds, "err", err)
		return err
	}
	if a.Child == "" && b.Objset != ObjsetFilesystem {
		return invalid("the item's own dataset must be a file system")
	}
	if b.Objset == ObjsetVolume && a.Kind != KindVM {
		return invalid("only VMs have volumes; a %s doesn't", a.Kind)
	}
	args := []string{"receive", "-u"}
	for _, p := range props {
		if b.Objset == ObjsetVolume && (strings.HasPrefix(p, "canmount=") || strings.HasPrefix(p, "devices=") || strings.HasPrefix(p, "setuid=") || strings.HasPrefix(p, "exec=")) {
			continue
		}
		args = append(args, "-o", p)
	}
	set := map[string]bool{}
	for _, p := range props {
		k, _, _ := strings.Cut(p, "=")
		set[k] = true
	}
	if b.Objset == ObjsetVolume {
		args = append(args, "-o", "refreservation=none")
	} else {
		args = append(args, "-x", "sharenfs", "-x", "sharesmb")
		if !set["mountpoint"] {
			args = append(args, "-x", "mountpoint")
		}
	}
	for _, p := range serviceProps {
		if !set[p] {
			args = append(args, "-x", p)
		}
	}
	args = append(args, ds+"@"+a.Snapshot)
	s.bytes.Add(int64(len(hdr)))
	return m.runReceive(s, args, io.MultiReader(bytes.NewReader(hdr), countingReader{r: r, n: &s.bytes}))
}

// RestoreFinishArgs completes a restore once every dataset is back.
// Snapshot is the replication snapshot that came along, removed from the
// copy (no task would ever prune it there).
type RestoreFinishArgs struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Pool     string `json:"pool"`
	NewID    string `json:"newId,omitempty"`
	Snapshot string `json:"snapshot,omitempty"`
	// Mail says what of a mail copy goes back (mail.RestoreArgs).
	Mail json.RawMessage `json:"mail,omitempty"`
}

// RestoreFinishResult says where the copy is.
type RestoreFinishResult struct {
	Dataset string `json:"dataset"`
	// ID is the new shared folder's, VM's or app's id.
	ID string `json:"id"`
	// Notes say what was changed on the way back (a VM's reset settings).
	Notes []string `json:"notes"`
	// Mail is what a mail restore did (mail.RestoreResult); the copy
	// itself is gone.
	Mail json.RawMessage `json:"mail,omitempty"`
}

// RestoreFinish mounts the copy and hands it to its manager: a new shared
// folder, a VM defined (off), an app's kept data.
func (m *Manager) RestoreFinish(ctx context.Context, a RestoreFinishArgs) (*RestoreFinishResult, error) {
	ra := RestoreArgs{Kind: a.Kind, ID: a.ID, Pool: a.Pool, NewID: a.NewID}
	top, err := m.restoreDataset(ctx, &ra)
	if err != nil {
		return nil, err
	}
	if m.prop(ctx, top, PropRestoring) != "1" {
		return nil, invalid("%s isn't being restored", top)
	}
	if m.streams.running(top) {
		return nil, ErrBusy
	}
	kids, err := m.children(ctx, top)
	if err != nil {
		return nil, err
	}
	if a.Snapshot != "" {
		if err := ValidSnap(a.Snapshot, ""); err != nil {
			return nil, err
		}
		if _, ok := m.exists(ctx, top+"@"+a.Snapshot); ok {
			if _, err := m.zfs(ctx, "destroy", "-r", top+"@"+a.Snapshot); err != nil {
				m.log().Warn("replication: removing the replication snapshot from a restored copy", "dataset", top, "err", err)
			}
		}
	}
	if a.Kind == KindMail {
		if len(kids) != 1 || kids[0].Child != "" || kids[0].Type != "filesystem" {
			return nil, invalid("the mail copy must be one file system")
		}
		if err := os.MkdirAll(m.mailRestoreDir(), 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(m.mailRestoreDir(), 0o700); err != nil {
			return nil, err
		}
	}
	for _, k := range kids {
		ds := top + childSuffix(k.Child)
		if k.Type == "volume" && a.Kind != KindVM {
			return nil, invalid("only VMs have volumes; %s is one", ds)
		}
		if k.Type == "filesystem" && m.prop(ctx, ds, "mounted") != "yes" && m.prop(ctx, ds, "canmount") != "off" {
			if _, err := m.zfs(ctx, "mount", ds); err != nil {
				return nil, fmt.Errorf("mounting %s: %w", ds, err)
			}
		}
	}
	id := a.ID
	notes := []string{}
	switch a.Kind {
	case KindShare:
		id = a.NewID
		err = m.Restore.ShareAdopt(ctx, ra.Pool, a.NewID)
	case KindVM:
		var n []string
		n, err = m.Restore.VMAdopt(ctx, a.ID)
		notes = append(notes, n...)
	case KindApp:
		err = m.Restore.AppAdopt(ctx, a.ID)
	case KindMail:
		return m.finishMail(ctx, top, a)
	}
	if err != nil {
		// Still marked as being restored: RestoreAbort can clean it up.
		return nil, err
	}
	// Only now is it no longer "being restored".
	for _, k := range kids {
		if _, err := m.zfs(ctx, "inherit", PropRestoring, top+childSuffix(k.Child)); err != nil {
			return nil, err
		}
	}
	m.log().Info("replication: restored", "kind", a.Kind, "dataset", top)
	return &RestoreFinishResult{Dataset: top, ID: id, Notes: notes}, nil
}

// finishMail puts the mounted mail copy into the mail server, then
// destroys it: it was only ever a staging copy.
func (m *Manager) finishMail(ctx context.Context, top string, a RestoreFinishArgs) (*RestoreFinishResult, error) {
	want := m.mailRestoreDir() + "/" + a.NewID
	if mp := m.prop(ctx, top, "mountpoint"); mp != want || m.prop(ctx, top, "mounted") != "yes" || m.prop(ctx, top, "readonly") != "on" {
		return nil, fmt.Errorf("the mail copy isn't mounted read-only at %s", want)
	}
	raw, notes, err := m.Restore.MailRestore(ctx, want, a.Mail)
	if err != nil {
		// Still marked as being restored: RestoreAbort removes it.
		return nil, err
	}
	if _, derr := m.zfs(ctx, "destroy", "-r", top); derr != nil {
		m.log().Warn("replication: removing the mail copy after restoring it", "dataset", top, "err", derr)
		notes = append(notes, "the copy "+top+" couldn't be removed: "+derr.Error())
	}
	if notes == nil {
		notes = []string{}
	}
	m.log().Info("replication: mail restored from a replica", "copy", top)
	return &RestoreFinishResult{Dataset: "", ID: MailItem, Notes: notes, Mail: raw}, nil
}

// RestoreAbort removes a restore that didn't finish (only datasets still
// marked as being restored).
func (m *Manager) RestoreAbort(ctx context.Context, a RestoreFinishArgs) error {
	ra := RestoreArgs{Kind: a.Kind, ID: a.ID, Pool: a.Pool, NewID: a.NewID}
	top, err := m.restoreDataset(ctx, &ra)
	if err != nil {
		return err
	}
	if _, ok := m.exists(ctx, top); !ok {
		return nil
	}
	if m.prop(ctx, top, PropRestoring) != "1" {
		return invalid("%s isn't being restored", top)
	}
	if m.streams.running(top) {
		return ErrBusy
	}
	if _, err := m.zfs(ctx, "destroy", "-r", top); err != nil {
		return fmt.Errorf("removing the unfinished copy: %w", err)
	}
	return nil
}

// BrowseArgs lists a folder inside a replica's snapshot.
type BrowseArgs struct {
	Target
	Snapshot string `json:"snapshot"`
	Path     string `json:"path"`
}

// Entry is one thing in a folder.
type Entry struct {
	Name     string    `json:"name"`
	Dir      bool      `json:"dir"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
}

// BrowseResult is a folder's contents (at most MaxEntries).
type BrowseResult struct {
	Path      string  `json:"path"`
	Entries   []Entry `json:"entries"`
	Truncated bool    `json:"truncated"`
}

// MaxEntries bounds a folder listing.
const MaxEntries = 2000

func cleanBrowsePath(p string) (string, error) {
	if p == "" || p == "/" {
		return ".", nil
	}
	if strings.ContainsRune(p, 0) || len(p) > 1024 {
		return "", invalid("path")
	}
	c := path.Clean("/" + p)
	rel := strings.TrimPrefix(c, "/")
	if rel == "" {
		return ".", nil
	}
	for _, part := range strings.Split(rel, "/") {
		if part == ".." {
			return "", invalid("path")
		}
	}
	return rel, nil
}

// Browse mounts a replica's snapshot read-only (nosuid, nodev, noexec) in
// a root-only folder, lists one folder of it without leaving it
// (os.Root), and unmounts it again. Replicas themselves are never mounted.
func (m *Manager) Browse(ctx context.Context, a BrowseArgs) (*BrowseResult, error) {
	if err := a.Target.Validate(); err != nil {
		return nil, err
	}
	if err := ValidSnap(a.Snapshot, ""); err != nil {
		return nil, err
	}
	if a.Kind == KindMail {
		// DKIM and TLS keys: a mail replica is never mounted here
		// (decision 465).
		return nil, invalid("mail replicas can't be browsed")
	}
	rel, err := cleanBrowsePath(a.Path)
	if err != nil {
		return nil, err
	}
	ds := a.Dataset()
	if typ, ok := m.exists(ctx, ds); !ok || typ != "filesystem" {
		return nil, fmt.Errorf("%s: %w", ds, ErrNotFound)
	}
	if v := m.prop(ctx, ds, PropReplica); v != a.Source {
		return nil, fmt.Errorf("%s: %w", ds, ErrNotFound)
	}
	snap := ds + "@" + a.Snapshot
	if _, ok := m.exists(ctx, snap); !ok {
		return nil, fmt.Errorf("snapshot %s: %w", snap, ErrNotFound)
	}
	base := m.BrowseDir
	if base == "" {
		base = "/run/hardyos/replica-browse"
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(base, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(base, "b")
	if err != nil {
		return nil, err
	}
	defer os.Remove(dir)
	if _, err := sysexecOutput(ctx, m, "mount", "-t", "zfs", "-o", "ro,nosuid,nodev,noexec", snap, dir); err != nil {
		return nil, fmt.Errorf("opening the snapshot: %w", err)
	}
	defer func() {
		uctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := sysexecOutput(uctx, m, "umount", dir); err != nil {
			m.log().Warn("replication: unmounting a browsed snapshot", "dir", dir, "err", err)
		}
	}()
	return listIn(dir, rel)
}

// listIn lists rel inside dir without following links out of it.
func listIn(dir, rel string) (*BrowseResult, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(rel)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", rel, ErrNotFound)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.IsDir() {
		return nil, invalid("%s isn't a folder", rel)
	}
	res := &BrowseResult{Path: filepath.ToSlash(rel), Entries: []Entry{}}
	if res.Path == "." {
		res.Path = ""
	}
	for {
		ents, err := f.ReadDir(256)
		for _, e := range ents {
			if len(res.Entries) >= MaxEntries {
				res.Truncated = true
				break
			}
			en := Entry{Name: e.Name(), Dir: e.IsDir()}
			if fi, err := e.Info(); err == nil {
				en.Modified = fi.ModTime().UTC()
				if fi.Mode().IsRegular() {
					en.Size = fi.Size()
				}
				if fi.Mode()&fs.ModeSymlink != 0 {
					en.Dir = false
				}
			}
			res.Entries = append(res.Entries, en)
		}
		if err != nil || len(ents) == 0 || res.Truncated {
			break
		}
	}
	sort.Slice(res.Entries, func(i, j int) bool {
		if res.Entries[i].Dir != res.Entries[j].Dir {
			return res.Entries[i].Dir
		}
		return strings.ToLower(res.Entries[i].Name) < strings.ToLower(res.Entries[j].Name)
	})
	return res, nil
}
