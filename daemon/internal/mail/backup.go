package mail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"syscall"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// Mail in cloud backups and replication (decisions 460-469). The mail
// dataset <pool>/mail holds everything that matters, so its ZFS snapshot
// is the consistency point; right before it, PrepareBackup puts what lives
// elsewhere into the dataset (BackupDir): the applied configuration and
// Rspamd's learned data. Restores read a copy of the dataset (a restic
// version staged by cloudbackup, or a replica's snapshot received back)
// and put chosen parts of it into the live server.

// BackupDir is root's folder in the mail dataset for what a backup needs
// besides the mail itself (0700 root).
const BackupDir = ".hardyos-backup"

// Files in BackupDir.
const (
	BackupConfigName = "config.json" // the applied RootConfig (no secrets)
	BackupBayesName  = "rspamd.rdb"  // Rspamd's Redis dump (statistics, Bayes)
)

// Limits of what a restore reads from a version.
const (
	maxConfigBytes = 8 << 20
	maxBayesBytes  = 1 << 30
	maxDKIMBytes   = 64 << 10
)

// ErrNotSetUp: there's no mail server on this server (nothing applied).
var ErrNotSetUp = errors.New("the mail server isn't set up on this server")

// saved reads the last applied setup (with its secrets).
func (r *Root) saved() (*ApplyArgs, error) {
	b, err := rootfile.ReadFile(r.stateFile())
	if err != nil {
		if rootfile.IsNotExist(err) {
			return nil, ErrNotSetUp
		}
		return nil, err
	}
	var a ApplyArgs
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("the saved mail setup can't be read: %w", err)
	}
	if !poolRE.MatchString(a.Config.Pool) {
		return nil, ErrNotSetUp
	}
	return &a, nil
}

// Pool is the pool of the mail server that is set up here.
func (r *Root) Pool(ctx context.Context) (string, error) {
	a, err := r.saved()
	if err != nil {
		return "", err
	}
	return a.Config.Pool, nil
}

// BackupSource is the mail dataset, ready for its snapshot.
type BackupSource struct {
	Pool       string   `json:"pool"`
	Dataset    string   `json:"dataset"`
	Mountpoint string   `json:"mountpoint"`
	Domains    []string `json:"domains"`
	Mailboxes  int      `json:"mailboxes"`
	// Bayes: Rspamd's data is in the dataset (BackupBayesName).
	Bayes    bool     `json:"bayes"`
	Warnings []string `json:"warnings"`
}

// PrepareBackup writes the configuration and Rspamd's data into the mail
// dataset (BackupDir) and returns the dataset to snapshot. ErrNotSetUp when
// there's no mail server here. Nothing in it is secret except the DKIM and
// TLS keys already in the dataset: the sealed secrets stay in hardyd's
// database (the settings item) and root's state file.
func (r *Root) PrepareBackup(ctx context.Context) (*BackupSource, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, err := r.saved()
	if err != nil {
		return nil, err
	}
	mp, err := r.dataset(ctx, a.Config.Pool)
	if err != nil {
		return nil, err
	}
	src := &BackupSource{Pool: a.Config.Pool, Dataset: a.Config.Pool + "/mail", Mountpoint: mp, Domains: []string{}, Mailboxes: len(a.Config.Mailboxes), Warnings: []string{}}
	for _, d := range a.Config.Domains {
		src.Domains = append(src.Domains, d.Name)
	}
	mr, err := os.OpenRoot(mp)
	if err != nil {
		return nil, err
	}
	defer mr.Close()
	if err := r.rootOnlyDir(mr, BackupDir); err != nil {
		return nil, err
	}
	cfg, _ := json.MarshalIndent(a.Config, "", "  ")
	if err := replaceFile(mr, path.Join(BackupDir, BackupConfigName), func(w io.Writer) error { _, err := w.Write(cfg); return err }, 0o600); err != nil {
		return nil, fmt.Errorf("saving the mail configuration for the backup: %w", err)
	}
	// Rspamd's Redis keeps its data on the system disk: save it now and
	// copy it in, so the snapshot has the filter as it is.
	if _, err := r.run(ctx, "redis-cli", "-s", RedisSocket, "SAVE"); err != nil {
		src.Warnings = append(src.Warnings, "Rspamd's data couldn't be saved just now ("+clipText(err.Error(), 200)+"); the backup has its last automatic save")
	}
	rd, err := os.OpenRoot(r.redisDir())
	if err == nil {
		// Redis's user owns the folder: a regular file with one name only
		// (not a hard link to something of root's), never through a link,
		// checked on the file that was opened.
		var f *os.File
		var st os.FileInfo
		if f, st, err = openRegular(rd, "dump.rdb", maxBayesBytes); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Nlink != 1 {
				err = errors.New("Rspamd's dump has more than one name")
			} else {
				err = replaceFile(mr, path.Join(BackupDir, BackupBayesName), func(w io.Writer) error {
					_, err := io.Copy(w, io.LimitReader(f, maxBayesBytes))
					return err
				}, 0o600)
			}
			f.Close()
		}
		rd.Close()
	}
	switch {
	case err == nil:
		src.Bayes = true
	case errors.Is(err, fs.ErrNotExist):
		_ = mr.Remove(path.Join(BackupDir, BackupBayesName))
		src.Warnings = append(src.Warnings, "Rspamd has no saved data yet (nothing learned)")
	default:
		_ = mr.Remove(path.Join(BackupDir, BackupBayesName))
		src.Warnings = append(src.Warnings, "Rspamd's data isn't in this backup: "+clipText(err.Error(), 200))
	}
	return src, nil
}

func (r *Root) redisDir() string {
	if r.RedisDir != "" {
		return r.RedisDir
	}
	return RedisDataDir
}

// rootOnlyDir makes name in root (one level, never through a link) a
// folder only root may open.
func (r *Root) rootOnlyDir(root *os.Root, name string) error {
	st, err := root.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := root.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	case err != nil:
		return err
	case !st.IsDir():
		return fmt.Errorf("%s isn't a folder", name)
	}
	if r.Chown == nil {
		if err := root.Lchown(name, 0, 0); err != nil {
			return err
		}
	}
	return root.Chmod(name, 0o700)
}

// replaceFile writes name inside root through a new temporary file and a
// rename, so a reader sees the old or the new file, never a part.
func replaceFile(root *os.Root, name string, fill func(io.Writer) error, mode os.FileMode) error {
	tmp := path.Join(path.Dir(name), "."+path.Base(name)+".new")
	_ = root.Remove(tmp)
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	werr := fill(f)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = root.Chmod(tmp, mode)
	}
	if werr != nil {
		_ = root.Remove(tmp)
		return werr
	}
	return root.Rename(tmp, name)
}

// openRegular opens name inside root for reading: a regular file (never a
// link, FIFO or device) of at most max bytes.
func openRegular(root *os.Root, name string, max int64) (*os.File, os.FileInfo, error) {
	st, err := root.Lstat(name)
	if err != nil {
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s isn't a regular file", name)
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	st, err = f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		f.Close()
		return nil, nil, fmt.Errorf("%s isn't a regular file of at most %d bytes", name, max)
	}
	return f, st, nil
}

// readRegular reads a small regular file inside root.
func readRegular(root *os.Root, name string, max int64) ([]byte, error) {
	f, _, err := openRegular(root, name, max)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max+1))
}

// copyRegular copies one regular file between roots (replacing the
// destination through a rename), root-only (0600).
func copyRegular(src *os.Root, from string, dst *os.Root, to string, max int64) error {
	f, _, err := openRegular(src, from, max)
	if err != nil {
		return err
	}
	defer f.Close()
	return replaceFile(dst, to, func(w io.Writer) error {
		_, err := io.Copy(w, io.LimitReader(f, max))
		return err
	}, 0o600)
}

// ---- what a version holds -------------------------------------------------

// ContentsMailbox is a mailbox in a version.
type ContentsMailbox struct {
	Key     string `json:"key"`
	Address string `json:"address"`
}

// Contents is what a version of the mail server holds (for choosing what
// to restore).
type Contents struct {
	Hostname  string            `json:"hostname"`
	Domains   []string          `json:"domains"`
	Mailboxes []ContentsMailbox `json:"mailboxes"`
}

// ParseBackupConfig reads a version's configuration (BackupConfigName),
// keeping only well-formed domains and mailboxes.
func ParseBackupConfig(b []byte) (*RootConfig, error) {
	var c RootConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("the version's mail configuration can't be read: %w", err)
	}
	doms := c.Domains[:0]
	for _, d := range c.Domains {
		if ValidDomain(d.Name) && selectorRE.MatchString(d.Selector) {
			doms = append(doms, d)
		}
	}
	c.Domains = doms
	mbs := c.Mailboxes[:0]
	seen := map[string]bool{}
	for _, m := range c.Mailboxes {
		if _, _, err := SplitAddress(m.Address); err != nil || !keyRE.MatchString(m.Key) || seen[m.Key] {
			continue
		}
		seen[m.Key] = true
		mbs = append(mbs, m)
	}
	c.Mailboxes = mbs
	return &c, nil
}

// ContentsOf lists what a version's configuration names.
func ContentsOf(c *RootConfig) Contents {
	out := Contents{Hostname: clipText(c.Hostname, 253), Domains: []string{}, Mailboxes: []ContentsMailbox{}}
	for _, d := range c.Domains {
		out.Domains = append(out.Domains, d.Name)
	}
	for _, m := range c.Mailboxes {
		out.Mailboxes = append(out.Mailboxes, ContentsMailbox{Key: m.Key, Address: m.Address})
	}
	sort.Strings(out.Domains)
	sort.Slice(out.Mailboxes, func(i, j int) bool { return out.Mailboxes[i].Address < out.Mailboxes[j].Address })
	return out
}

// ---- rebuilding a dead server ------------------------------------------------

// RebuildFrom brings a whole mail server back onto pool of a new server
// whose mail server isn't set up yet (cloud backups' Rebuild): mailboxes
// and calendars under the version's keys (the settings restored with the
// server carry the same keys), DKIM and TLS keys, Rspamd's data. The mail
// server is started by turning it on in Control Panel › Mail.
func (r *Root) RebuildFrom(ctx context.Context, pool, dir string) (*RestoreResult, error) {
	if !poolRE.MatchString(pool) {
		return nil, invalid("invalid pool")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.saved(); err == nil {
		return nil, invalid("the mail server is already set up on this server; restore into it instead")
	}
	src, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("opening the version: %w", err)
	}
	defer src.Close()
	b, err := readRegular(src, path.Join(BackupDir, BackupConfigName), maxConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("the version has no mail configuration (%v)", err)
	}
	ver, err := ParseBackupConfig(b)
	if err != nil {
		return nil, err
	}
	e, err := r.env(ctx, pool)
	if err != nil {
		return nil, err
	}
	radUID, _, err := r.lookupUser("radicale")
	if err != nil {
		return nil, err
	}
	_, rspGID, err := r.lookupUser("_rspamd")
	if err != nil {
		return nil, err
	}
	if err := r.layout(e, radUID, rspGID); err != nil {
		return nil, err
	}
	// Nothing runs and r.mu is held throughout: stopped (no holds, no
	// restarts, no second locking).
	rs := &restore{r: r, ctx: ctx, e: e, live: &ApplyArgs{Config: RootConfig{Pool: pool, Domains: ver.Domains}}, ver: ver, src: src,
		radUID: radUID, rspGID: rspGID, stamp: r.clock().Format("20060102-150405"), stopped: true,
		res: &RestoreResult{Scope: ScopeAll, DKIM: []string{}, Notes: []string{}, Replaced: []string{}}}
	if rs.vm, err = os.OpenRoot(e.VMailDir()); err != nil {
		return nil, err
	}
	defer rs.vm.Close()
	if rs.rad, err = r.radicaleRoot(e); err != nil {
		return nil, err
	}
	defer rs.rad.Close()
	// Only onto an empty mail dataset: no mail, calendars or DKIM keys
	// (decision 468).
	if names, _ := readDirNames(rs.vm, "."); len(names) > 0 {
		return nil, invalid("%s/mail already holds mail; restore into the mail server instead", pool)
	}
	if names, _ := readDirNames(rs.rad, "collection-root"); len(names) > 0 {
		return nil, invalid("%s/mail already holds calendars; restore into the mail server instead", pool)
	}
	if dr, err := os.OpenRoot(e.DKIMDir()); err == nil {
		names, _ := readDirNames(dr, ".")
		dr.Close()
		if len(names) > 0 {
			return nil, invalid("%s/mail already holds DKIM keys; restore into the mail server instead", pool)
		}
	}
	keys := map[string]bool{"family": true}
	for _, m := range ver.Mailboxes {
		keys[m.Key] = true
		md := path.Join("vmail", m.Key, "Maildir")
		if st, err := src.Lstat(md); err != nil || !st.IsDir() {
			continue
		}
		if err := mkdirOwned(rs.vm, m.Key, rs.vmailOwner(), rs.testing()); err != nil {
			return rs.res, err
		}
		home, err := rs.vm.OpenRoot(m.Key)
		if err != nil {
			return rs.res, err
		}
		cs := &treeStats{}
		folders, err := maildirFolders(src, md)
		for _, f := range folders {
			if err != nil {
				break
			}
			err = rs.copyMaildirFolder(path.Join(md, f), path.Join("Maildir", f), f != "", true, home, rs.vmailOwner(), cs, nil)
		}
		home.Close()
		if err != nil {
			return rs.res, fmt.Errorf("%s: %w", m.Address, err)
		}
		rs.res.Mailboxes++
		rs.res.Messages += cs.messages
		rs.res.Bytes += cs.bytes
	}
	if err := rs.ensureRadDir("collection-root"); err != nil {
		return rs.res, err
	}
	names, _ := readDirNames(src, path.Join("radicale", "collections", "collection-root"))
	for _, n := range names {
		if !keys[n] {
			continue
		}
		if err := rs.swapCollections(n, n); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return rs.res, fmt.Errorf("calendars: %w", err)
		}
	}
	for _, d := range ver.Domains {
		if err := rs.dkim(d.Name, true); err != nil {
			return rs.res, err
		}
	}
	// The certificate, kept until a new one is issued: only a key and a
	// chain that belong together (decision 468).
	key, kerr := readRegular(src, path.Join("keys", "tls", "key.pem"), 64<<10)
	chain, cerr := readRegular(src, path.Join("keys", "tls", "fullchain.pem"), 256<<10)
	switch {
	case kerr != nil || cerr != nil:
		rs.res.note("the version has no TLS certificate; a new one is made")
	default:
		if _, err := matchKey(key, chain); err != nil {
			rs.res.note("the version's TLS certificate isn't usable (%v); a new one is made", err)
		} else if tr, err := os.OpenRoot(e.TLSDir()); err == nil {
			for n, b := range map[string][]byte{"key.pem": key, "fullchain.pem": chain} {
				b := b
				if err := replaceFile(tr, n, func(w io.Writer) error { _, err := w.Write(b); return err }, 0o600); err != nil {
					rs.res.note("the TLS certificate: %v (a new one is made)", err)
				}
			}
			tr.Close()
		}
	}
	if err := rs.bayes(); err != nil {
		rs.res.note("Rspamd's data: %v", err)
	}
	if err := r.write(layoutFile(e), []byte(fmt.Sprintf("%d\n", LayoutVersion)), 0o600); err != nil {
		return rs.res, err
	}
	rs.res.note("Turn the mail server on in Control Panel › Mail: its settings came back with the server's settings")
	r.log().Info("mail: rebuilt from a backup", "pool", pool, "mailboxes", rs.res.Mailboxes, "messages", rs.res.Messages)
	return rs.res, nil
}
