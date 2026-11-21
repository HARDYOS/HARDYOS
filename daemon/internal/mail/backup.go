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
	"regexp"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

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
		err = copyRegular(rd, "dump.rdb", mr, path.Join(BackupDir, BackupBayesName), maxBayesBytes)
		rd.Close()
	}
	switch {
	case err == nil:
		src.Bayes = true
	case errors.Is(err, fs.ErrNotExist):
		_ = mr.Remove(path.Join(BackupDir, BackupBayesName))
		src.Warnings = append(src.Warnings, "Rspamd has no saved data yet (nothing learned)")
	default:
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

// ---- restore ------------------------------------------------------------------

// Restore scopes.
const (
	ScopeMailbox   = "mailbox"
	ScopeDomain    = "domain"
	ScopeCalendars = "calendars"
	ScopeAll       = "all"
)

// Restore modes.
const (
	// RestoreCopy puts the version's mail into a new folder of the mailbox
	// ("Restored <date>"), its calendars into new collections: nothing
	// that's there now changes.
	RestoreCopy = "copy"
	// RestoreOverwrite replaces what's there with the version (after a
	// snapshot of the mail dataset).
	RestoreOverwrite = "overwrite"
)

// ConfirmAll is what's typed to restore the whole mail server.
const ConfirmAll = "mail"

// RestoreArgs says what to put back from a version. Mailboxes are matched
// by their storage key (decision 310), never by address: Key is the
// version's mailbox, Into the live one (default the same key; another
// needs its address typed in Confirm).
type RestoreArgs struct {
	Scope   string `json:"scope"`
	Key     string `json:"key,omitempty"`
	Into    string `json:"into,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Confirm string `json:"confirm,omitempty"`
}

// Check validates the arguments on their own (what needs the live server
// or the version is checked by RestoreFrom).
func (a *RestoreArgs) Check() error {
	a.Confirm = strings.TrimSpace(a.Confirm)
	switch a.Scope {
	case ScopeMailbox, ScopeCalendars:
		if !keyRE.MatchString(a.Key) {
			return invalid("choose the mailbox to restore")
		}
		if a.Into == "" {
			a.Into = a.Key
		}
		if !keyRE.MatchString(a.Into) {
			return invalid("choose the mailbox to restore into")
		}
		if a.Domain != "" {
			return invalid("a mailbox's restore names no domain")
		}
	case ScopeDomain:
		if !ValidDomain(a.Domain) {
			return invalid("choose the domain to restore")
		}
		if a.Key != "" || a.Into != "" {
			return invalid("a domain's restore names no mailbox")
		}
	case ScopeAll:
		if a.Key != "" || a.Into != "" || a.Domain != "" {
			return invalid("restoring everything names no mailbox or domain")
		}
		a.Mode = RestoreOverwrite
		if !strings.EqualFold(a.Confirm, ConfirmAll) {
			return invalid("type %s to confirm replacing all of this server's mail", ConfirmAll)
		}
	default:
		return invalid("choose what to restore: a mailbox, a domain, calendars and contacts, or everything")
	}
	if a.Mode != RestoreCopy && a.Mode != RestoreOverwrite {
		return invalid("choose how to restore: into a new folder, or over what's there")
	}
	if a.Mode == RestoreOverwrite && a.Confirm == "" {
		return invalid("type the mailbox's address (or the domain) to confirm replacing what's there")
	}
	return nil
}

// RestoreResult says what a restore did.
type RestoreResult struct {
	Scope       string   `json:"scope"`
	Mailboxes   int      `json:"mailboxes"`
	Messages    int      `json:"messages"`
	Collections int      `json:"collections"`
	Bytes       int64    `json:"bytes"`
	Folder      string   `json:"folder,omitempty"` // the new folder (copy mode)
	Safety      string   `json:"safety,omitempty"` // snapshot of <pool>/mail taken first
	DKIM        []string `json:"dkim"`             // domains whose key came back
	Bayes       bool     `json:"bayes"`
	Notes       []string `json:"notes"`
}

func (res *RestoreResult) note(format string, a ...any) {
	if len(res.Notes) < 50 {
		res.Notes = append(res.Notes, fmt.Sprintf(format, a...))
	}
}

// restore is one restore's state.
type restore struct {
	r       *Root
	ctx     context.Context
	e       Env
	live    *ApplyArgs
	ver     *RootConfig
	src     *os.Root // the version's copy of the dataset
	vm      *os.Root // live vmail/
	rad     *os.Root // live radicale/collections (nil: none)
	radUID  int
	rspGID  int
	stamp   string
	res     *RestoreResult
	byKey   map[string]RootMailbox // live mailboxes
	verKeys map[string]RootMailbox // the version's
}

// RestoreFrom puts what a says back from dir, a copy of the mail dataset
// (a staged backup version or a received replica, which root alone
// writes). Its contents are read as untrusted: only regular files and
// folders, never through links, with the live server's owners and fixed
// modes; a replaced part is snapshotted first.
func (r *Root) RestoreFrom(ctx context.Context, dir string, a RestoreArgs) (*RestoreResult, error) {
	if err := a.Check(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	live, err := r.saved()
	if errors.Is(err, ErrNotSetUp) {
		return nil, invalid("set the mail server up first (Control Panel › Mail), then restore into it; a rebuilt server uses Rebuild instead")
	}
	if err != nil {
		return nil, err
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
	e, err := r.env(ctx, live.Config.Pool)
	if err != nil {
		return nil, err
	}
	rs := &restore{r: r, ctx: ctx, e: e, live: live, ver: ver, src: src, stamp: r.clock().Format("20060102-150405"),
		res: &RestoreResult{Scope: a.Scope, DKIM: []string{}, Notes: []string{}}, byKey: map[string]RootMailbox{}, verKeys: map[string]RootMailbox{}}
	for _, m := range live.Config.Mailboxes {
		rs.byKey[m.Key] = m
	}
	for _, m := range ver.Mailboxes {
		rs.verKeys[m.Key] = m
	}
	if rs.radUID, _, err = r.lookupUser("radicale"); err != nil {
		return nil, err
	}
	if _, rs.rspGID, err = r.lookupUser("_rspamd"); err != nil {
		return nil, err
	}
	if rs.vm, err = os.OpenRoot(e.VMailDir()); err != nil {
		return nil, err
	}
	defer rs.vm.Close()
	if rad, err := r.radicaleRoot(e); err == nil {
		rs.rad = rad
		defer rad.Close()
	}
	if err := rs.run(a); err != nil {
		return rs.res, err
	}
	r.log().Info("mail: restored from a copy", "scope", a.Scope, "mode", a.Mode, "mailboxes", rs.res.Mailboxes, "messages", rs.res.Messages,
		"collections", rs.res.Collections, "dkim", strings.Join(rs.res.DKIM, ","), "bayes", rs.res.Bayes)
	return rs.res, nil
}

func (r *Root) clock() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (rs *restore) run(a RestoreArgs) error {
	switch a.Scope {
	case ScopeMailbox:
		vm, live, err := rs.pair(a)
		if err != nil {
			return err
		}
		if a.Mode == RestoreOverwrite {
			if err := rs.safety(); err != nil {
				return err
			}
		}
		return rs.mailbox(vm, live, a.Mode)
	case ScopeCalendars:
		vm, live, err := rs.pair(a)
		if err != nil {
			return err
		}
		if a.Mode == RestoreOverwrite {
			if err := rs.safety(); err != nil {
				return err
			}
		}
		return rs.calendars(vm, live, a.Mode)
	case ScopeDomain:
		return rs.domain(a)
	case ScopeAll:
		return rs.all()
	}
	return invalid("nothing to restore")
}

// pair finds the version's mailbox and the live one it goes into.
func (rs *restore) pair(a RestoreArgs) (RootMailbox, RootMailbox, error) {
	vm, ok := rs.verKeys[a.Key]
	if !ok {
		return vm, vm, invalid("the version has no such mailbox")
	}
	live, ok := rs.byKey[a.Into]
	if !ok {
		return vm, live, invalid("there's no such mailbox on this server now; choose the mailbox to restore into")
	}
	switch {
	case a.Into != a.Key && a.Confirm != live.Address:
		return vm, live, invalid("restoring %s's mail into another mailbox: type %s to confirm", vm.Address, live.Address)
	case a.Mode == RestoreOverwrite && a.Confirm != live.Address:
		return vm, live, invalid("type %s to confirm replacing its %s", live.Address, map[string]string{ScopeMailbox: "mail", ScopeCalendars: "calendars and contacts"}[a.Scope])
	}
	return vm, live, nil
}

// safety snapshots the mail dataset before anything is replaced.
func (rs *restore) safety() error {
	if rs.res.Safety != "" {
		return nil
	}
	name := "hardyos-manual-" + rs.stamp
	if _, err := rs.r.run(rs.ctx, "zfs", "snapshot", rs.live.Config.Pool+"/mail@"+name); err != nil {
		return fmt.Errorf("taking a snapshot of the mail first: %w", err)
	}
	rs.res.Safety = name
	return nil
}

func (rs *restore) domain(a RestoreArgs) error {
	var vms []RootMailbox
	for _, m := range rs.ver.Mailboxes {
		if _, d, _ := SplitAddress(m.Address); d == a.Domain {
			vms = append(vms, m)
		}
	}
	liveDomain := false
	for _, d := range rs.live.Config.Domains {
		liveDomain = liveDomain || d.Name == a.Domain
	}
	if !liveDomain {
		return invalid("%s isn't one of this mail server's domains now; add it in Control Panel › Mail first", a.Domain)
	}
	if a.Mode == RestoreOverwrite {
		if a.Confirm != a.Domain {
			return invalid("type %s to confirm replacing its mail, calendars and DKIM key", a.Domain)
		}
		if err := rs.safety(); err != nil {
			return err
		}
	}
	if len(vms) == 0 {
		rs.res.note("the version has no mailboxes at %s", a.Domain)
	}
	for _, vm := range vms {
		live, ok := rs.byKey[vm.Key]
		if !ok {
			rs.res.note("%s: no such mailbox here now (restore it into another mailbox on its own)", vm.Address)
			continue
		}
		if err := rs.mailbox(vm, live, a.Mode); err != nil {
			return fmt.Errorf("%s: %w", live.Address, err)
		}
		if a.Mode == RestoreOverwrite {
			if err := rs.calendars(vm, live, RestoreOverwrite); err != nil {
				return fmt.Errorf("%s's calendars: %w", live.Address, err)
			}
		}
	}
	if a.Mode == RestoreOverwrite {
		if err := rs.dkim(a.Domain, true); err != nil {
			return err
		}
	}
	return nil
}

// all puts the whole mail server back: the services stop, everything of
// the mailboxes that exist here (by key), every calendar, the DKIM keys of
// this server's domains and Rspamd's data come back, then the saved setup
// is applied again (which starts everything).
func (rs *restore) all() error {
	if err := rs.safety(); err != nil {
		return err
	}
	rs.r.stopUnits(rs.ctx)
	var errs []error
	for _, vm := range rs.ver.Mailboxes {
		live, ok := rs.byKey[vm.Key]
		if !ok {
			rs.res.note("%s: no such mailbox here now (restore it into another mailbox on its own)", vm.Address)
			continue
		}
		if err := rs.mailbox(vm, live, RestoreOverwrite); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", live.Address, err))
			continue
		}
		if err := rs.calendars(vm, live, RestoreOverwrite); err != nil {
			errs = append(errs, fmt.Errorf("%s's calendars: %w", live.Address, err))
		}
	}
	if rs.live.Config.SharedCalendar && rs.rad != nil {
		if err := rs.swapCollections("family", "family"); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, fmt.Errorf("the family calendar: %w", err))
		}
	}
	for _, d := range rs.live.Config.Domains {
		if err := rs.dkim(d.Name, false); err != nil {
			errs = append(errs, err)
		}
	}
	if err := rs.bayes(); err != nil {
		rs.res.note("Rspamd's data: %v", err)
	}
	// Start again with the saved setup (renders, checks and starts every
	// service; a failure here leaves the restored data in place).
	if _, err := rs.r.apply(rs.ctx, *rs.live, false); err != nil {
		errs = append(errs, fmt.Errorf("starting the mail server again: %w", err))
	}
	return errors.Join(errs...)
}

// stopUnits stops the mail programs (a restore of everything).
func (r *Root) stopUnits(ctx context.Context) {
	all := append(slices.Clone(coreUnits), clamavUnits...)
	slices.Reverse(all)
	_ = r.systemctl(ctx, append([]string{"stop"}, all...)...)
}

// ---- mailboxes ------------------------------------------------------------------

// owner is how a restored tree is written.
type owner struct {
	uid, gid int
	dir      os.FileMode
	file     os.FileMode
}

func (rs *restore) vmailOwner() owner { return owner{rs.e.VMailUID, rs.e.VMailGID, 0o700, 0o600} }

// maildirName: a message's or folder's name in a Maildir.
var maildirName = regexp.MustCompile(`^[^/\x00]{1,255}$`)

// mailbox restores one mailbox: copy puts the version's folders into a new
// folder tree "Restored <date>" (subscribed), overwrite replaces the
// mailbox's home (vmail/<key>) with the version's.
func (rs *restore) mailbox(vm, live RootMailbox, mode string) error {
	srcHome := path.Join("vmail", vm.Key)
	if st, err := rs.src.Lstat(srcHome); err != nil || !st.IsDir() {
		rs.res.note("%s: the version has no mail for it", vm.Address)
		return nil
	}
	cs := &treeStats{}
	if mode == RestoreCopy {
		if err := rs.mailboxCopy(vm, live, cs); err != nil {
			return err
		}
	} else {
		work := ".restoring-" + live.Key + "-" + rs.stamp
		if err := rs.vm.Mkdir(work, 0o700); err != nil {
			return err
		}
		if err := rs.chown(rs.vm, work, rs.vmailOwner()); err != nil {
			return err
		}
		err := copyTree(rs.ctx, rs.src, srcHome, rs.vm, work, rs.vmailOwner(), rs.r.Chown != nil, skipMaildirTmp, cs)
		if err == nil {
			_ = rs.r.kickLocked(rs.ctx, live.Address)
			err = swapIn(rs.vm, work, live.Key, rs.stamp)
		}
		if err != nil {
			_ = rs.vm.RemoveAll(work)
			return err
		}
		// Dovecot reads the restored indexes again and checks them against
		// the folders.
		if _, err := rs.r.run(rs.ctx, "doveadm", "force-resync", "-u", live.Address, "*"); err != nil {
			rs.res.note("%s: Dovecot will check the restored folders when it next opens them (%s)", live.Address, clipText(err.Error(), 120))
		}
	}
	if _, err := rs.r.run(rs.ctx, "doveadm", "quota", "recalc", "-u", live.Address); err != nil {
		rs.res.note("%s: its used space is counted again at its next sign-in", live.Address)
	}
	rs.res.Mailboxes++
	rs.res.Messages += cs.messages
	rs.res.Bytes += cs.bytes
	if cs.skipped > 0 {
		rs.res.note("%s: %d entries that weren't plain files or folders were left out", live.Address, cs.skipped)
	}
	return nil
}

// skipMaildirTmp leaves out files being delivered (tmp/) and the restore's
// own work folders: they aren't mail.
func skipMaildirTmp(rel string, dir bool) bool {
	parts := strings.Split(rel, "/")
	for i, p := range parts {
		if p == "tmp" && i < len(parts)-1 {
			return true
		}
	}
	return false
}

// RestoredFolder names the folder a copy-mode restore makes.
func RestoredFolder(t time.Time) string { return "Restored " + t.Format("2006-01-02 1504") }

// mailboxCopy builds the version's folders under vmail/.restoring-…, then
// moves each into the live Maildir under the new top folder.
func (rs *restore) mailboxCopy(vm, live RootMailbox, cs *treeStats) error {
	srcMd := path.Join("vmail", vm.Key, "Maildir")
	if st, err := rs.src.Lstat(srcMd); err != nil || !st.IsDir() {
		rs.res.note("%s: the version has no mail for it", vm.Address)
		return nil
	}
	liveMd := path.Join(live.Key, "Maildir")
	for _, d := range []string{live.Key, liveMd} {
		if err := rs.ensureVmailDir(d); err != nil {
			return err
		}
	}
	top := RestoredFolder(rs.r.clock())
	for i := 2; ; i++ {
		if _, err := rs.vm.Lstat(path.Join(liveMd, "."+top)); errors.Is(err, fs.ErrNotExist) {
			break
		}
		if i > 20 {
			return errors.New("there are already restored folders of this time; try again in a minute")
		}
		top = RestoredFolder(rs.r.clock()) + fmt.Sprintf(" (%d)", i)
	}
	rs.res.Folder = top
	work := ".restoring-" + live.Key + "-" + rs.stamp
	if err := rs.vm.Mkdir(work, 0o700); err != nil {
		return err
	}
	defer rs.vm.RemoveAll(work)
	if err := rs.chown(rs.vm, work, rs.vmailOwner()); err != nil {
		return err
	}
	// The version's folders: INBOX is the Maildir itself, the others are
	// its ".Name" subfolders (Maildir++).
	type folder struct{ src, name string }
	folders := []folder{{srcMd, ""}}
	names, err := readDirNames(rs.src, srcMd)
	if err != nil {
		return err
	}
	for _, n := range names {
		if len(n) < 2 || n[0] != '.' || n == ".." || !maildirName.MatchString(n) {
			continue
		}
		if st, err := rs.src.Lstat(path.Join(srcMd, n)); err == nil && st.IsDir() {
			folders = append(folders, folder{path.Join(srcMd, n), n[1:]})
		}
	}
	var made []string
	for _, f := range folders {
		dest := "." + top
		if f.name != "" {
			dest += "." + f.name
		}
		w := path.Join(work, dest)
		if err := rs.vm.Mkdir(w, 0o700); err != nil {
			return err
		}
		if err := rs.chown(rs.vm, w, rs.vmailOwner()); err != nil {
			return err
		}
		for _, sub := range []string{"cur", "new", "tmp"} {
			if err := rs.vm.Mkdir(path.Join(w, sub), 0o700); err != nil {
				return err
			}
			if err := rs.chown(rs.vm, path.Join(w, sub), rs.vmailOwner()); err != nil {
				return err
			}
			if sub == "tmp" {
				continue
			}
			if err := copyFlat(rs.ctx, rs.src, path.Join(f.src, sub), rs.vm, path.Join(w, sub), rs.vmailOwner(), rs.r.Chown != nil, cs); err != nil {
				return err
			}
		}
		// Maildir++ marks every subfolder.
		if err := writeOwned(rs.vm, path.Join(w, "maildirfolder"), nil, rs.vmailOwner(), rs.r.Chown != nil); err != nil {
			return err
		}
		made = append(made, dest)
	}
	for _, d := range made {
		if err := rs.vm.Rename(path.Join(work, d), path.Join(liveMd, d)); err != nil {
			return fmt.Errorf("moving the restored folder in: %w", err)
		}
	}
	// Subscribed, so mail apps show them (IMAP names use "/").
	args := []string{"mailbox", "subscribe", "-u", live.Address}
	for _, d := range made {
		args = append(args, strings.ReplaceAll(strings.TrimPrefix(d, "."), ".", "/"))
	}
	if _, err := rs.r.run(rs.ctx, "doveadm", args...); err != nil {
		rs.res.note("%s: subscribe to the folder %s in your mail app to see it", live.Address, top)
	}
	return nil
}

func (rs *restore) ensureVmailDir(name string) error {
	st, err := rs.vm.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := rs.vm.Mkdir(name, 0o700); err != nil {
			return err
		}
		return rs.chown(rs.vm, name, rs.vmailOwner())
	case err != nil:
		return err
	case !st.IsDir():
		return fmt.Errorf("%s isn't a folder", name)
	}
	return nil
}

func (rs *restore) chown(root *os.Root, name string, o owner) error {
	if rs.r.Chown != nil {
		return rs.r.Chown(path.Join(root.Name(), name), o.uid, o.gid)
	}
	return root.Lchown(name, o.uid, o.gid)
}

// swapIn puts the folder work in place of name (both in root): the old one
// is moved aside, then removed (the safety snapshot keeps it).
func swapIn(root *os.Root, work, name, stamp string) error {
	old := ".replaced-" + name + "-" + stamp
	had := true
	if err := root.Rename(name, old); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		had = false
	}
	if err := root.Rename(work, name); err != nil {
		if had {
			_ = root.Rename(old, name)
		}
		return err
	}
	if had {
		return root.RemoveAll(old)
	}
	return nil
}

// ---- calendars and contacts -------------------------------------------------

// collectionName: a Radicale collection's folder.
var collectionName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+=-]{0,127}$`)

func (rs *restore) radOwner() owner { return owner{rs.radUID, rs.radUID, 0o750, 0o640} }

// skipRadicale leaves out Radicale's caches and locks (it makes them again).
func skipRadicale(rel string, dir bool) bool {
	b := path.Base(rel)
	return b == ".Radicale.cache" || b == ".Radicale.lock" || strings.HasPrefix(b, ".Radicale.tmp")
}

// calendars restores one person's calendars and address books: copy adds
// the version's as new collections "<name> (restored <date>)", overwrite
// replaces theirs.
func (rs *restore) calendars(vm, live RootMailbox, mode string) error {
	if rs.rad == nil {
		rs.res.note("calendars and contacts aren't set up here")
		return nil
	}
	srcDir := path.Join("radicale", "collections", "collection-root", vm.Key)
	if st, err := rs.src.Lstat(srcDir); err != nil || !st.IsDir() {
		if mode == RestoreCopy {
			rs.res.note("%s: the version has no calendars or contacts for it", vm.Address)
		}
		return nil
	}
	if mode == RestoreOverwrite {
		return rs.swapCollections(vm.Key, live.Key)
	}
	if err := rs.ensureRadDir(path.Join("collection-root", live.Key)); err != nil {
		return err
	}
	names, err := readDirNames(rs.src, srcDir)
	if err != nil {
		return err
	}
	label := "restored " + rs.r.clock().Format("2006-01-02")
	for _, n := range names {
		if !collectionName.MatchString(n) {
			continue
		}
		if st, err := rs.src.Lstat(path.Join(srcDir, n)); err != nil || !st.IsDir() {
			continue
		}
		dest := path.Join("collection-root", live.Key, n+"-restored-"+rs.stamp)
		if _, err := rs.rad.Lstat(dest); err == nil {
			continue
		}
		if err := rs.rad.Mkdir(dest, 0o750); err != nil {
			return err
		}
		if err := rs.chown(rs.rad, dest, rs.radOwner()); err != nil {
			return err
		}
		cs := &treeStats{}
		if err := copyTree(rs.ctx, rs.src, path.Join(srcDir, n), rs.rad, dest, rs.radOwner(), rs.r.Chown != nil, skipRadicale, cs); err != nil {
			_ = rs.rad.RemoveAll(dest)
			return err
		}
		if err := relabel(rs.rad, dest, n, label, rs.radOwner(), rs.r.Chown != nil); err != nil {
			rs.res.note("%s: the restored collection %s keeps its old name", live.Address, n)
		}
		rs.res.Collections++
	}
	return nil
}

// relabel gives a restored collection a display name that says so.
func relabel(root *os.Root, dir, fallback, label string, o owner, testing bool) error {
	p := path.Join(dir, ".Radicale.props")
	props := map[string]string{}
	if b, err := readRegular(root, p, 1<<20); err == nil {
		if err := json.Unmarshal(b, &props); err != nil {
			return err
		}
	}
	name := props["D:displayname"]
	if name == "" {
		name = fallback
	}
	props["D:displayname"] = clipText(name, 200) + " (" + label + ")"
	b, _ := json.Marshal(props)
	if err := replaceFile(root, p, func(w io.Writer) error { _, err := w.Write(b); return err }, o.file); err != nil {
		return err
	}
	if testing {
		return nil
	}
	return root.Lchown(p, o.uid, o.gid)
}

func (rs *restore) ensureRadDir(name string) error {
	st, err := rs.rad.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := rs.rad.Mkdir(name, 0o750); err != nil {
			return err
		}
		return rs.chown(rs.rad, name, rs.radOwner())
	case err != nil:
		return err
	case !st.IsDir():
		return fmt.Errorf("%s isn't a folder", name)
	}
	return nil
}

// swapCollections replaces collection-root/<to> with the version's
// collection-root/<from>.
func (rs *restore) swapCollections(from, to string) error {
	srcDir := path.Join("radicale", "collections", "collection-root", from)
	if st, err := rs.src.Lstat(srcDir); err != nil || !st.IsDir() {
		return fs.ErrNotExist
	}
	if err := rs.ensureRadDir("collection-root"); err != nil {
		return err
	}
	work := path.Join("collection-root", ".restoring-"+to+"-"+rs.stamp)
	if err := rs.rad.Mkdir(work, 0o750); err != nil {
		return err
	}
	if err := rs.chown(rs.rad, work, rs.radOwner()); err != nil {
		return err
	}
	cs := &treeStats{}
	err := copyTree(rs.ctx, rs.src, srcDir, rs.rad, work, rs.radOwner(), rs.r.Chown != nil, skipRadicale, cs)
	if err == nil {
		cr, oerr := rs.rad.OpenRoot("collection-root")
		if oerr != nil {
			err = oerr
		} else {
			err = swapIn(cr, path.Base(work), to, rs.stamp)
			cr.Close()
		}
	}
	if err != nil {
		_ = rs.rad.RemoveAll(work)
		return err
	}
	names, _ := readDirNames(rs.rad, path.Join("collection-root", to))
	for _, n := range names {
		if collectionName.MatchString(n) {
			rs.res.Collections++
		}
	}
	return nil
}

// ---- DKIM and Rspamd ------------------------------------------------------------

// dkim puts a live domain's DKIM key back from the version (the key the
// domain's DNS record was published for). Missing is noted unless quiet.
func (rs *restore) dkim(domain string, loud bool) error {
	sel := ""
	for _, d := range rs.live.Config.Domains {
		if d.Name == domain {
			sel = d.Selector
		}
	}
	if sel == "" {
		return nil
	}
	name := domain + "." + sel + ".key"
	b, err := readRegular(rs.src, path.Join("keys", "dkim", name), maxDKIMBytes)
	if err != nil {
		if loud || !errors.Is(err, fs.ErrNotExist) {
			rs.res.note("%s: the version has no DKIM key for the selector %s; the current key stays", domain, sel)
		}
		return nil
	}
	if _, err := dkimPublic(b); err != nil {
		return fmt.Errorf("%s: the version's DKIM key isn't usable: %w", domain, err)
	}
	dr, err := os.OpenRoot(rs.e.DKIMDir())
	if err != nil {
		return err
	}
	defer dr.Close()
	if err := replaceFile(dr, name, func(w io.Writer) error { _, err := w.Write(b); return err }, 0o640); err != nil {
		return fmt.Errorf("%s's DKIM key: %w", domain, err)
	}
	if rs.r.Chown != nil {
		_ = rs.r.Chown(path.Join(dr.Name(), name), 0, rs.rspGID)
	} else if err := dr.Lchown(name, 0, rs.rspGID); err != nil {
		return err
	}
	rs.res.DKIM = append(rs.res.DKIM, domain)
	if _, err := rs.r.run(rs.ctx, "systemctl", "reload-or-restart", "rspamd.service"); err != nil {
		rs.res.note("Rspamd signs with the restored key once it restarts")
	}
	return nil
}

// bayes puts Rspamd's data back (Redis is stopped: restore of everything).
func (rs *restore) bayes() error {
	f, _, err := openRegular(rs.src, path.Join(BackupDir, BackupBayesName), maxBayesBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if err := rs.r.ensureRedisDir(); err != nil {
		return err
	}
	rd, err := os.OpenRoot(rs.r.redisDir())
	if err != nil {
		return err
	}
	defer rd.Close()
	if err := replaceFile(rd, "dump.rdb", func(w io.Writer) error {
		_, err := io.Copy(w, io.LimitReader(f, maxBayesBytes))
		return err
	}, 0o640); err != nil {
		return err
	}
	if rs.r.Chown == nil {
		uid, gid, err := rs.r.lookupUser("redis")
		if err != nil {
			return err
		}
		if err := rd.Lchown("dump.rdb", uid, gid); err != nil {
			return err
		}
	}
	rs.res.Bayes = true
	return nil
}

// ---- copying ----------------------------------------------------------------------

type treeStats struct {
	files, dirs, messages, skipped int
	bytes                          int64
}

func readDirNames(root *os.Root, dir string) ([]string, error) {
	f, err := root.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s isn't a folder", dir)
	}
	names, err := f.Readdirnames(-1)
	sort.Strings(names)
	return names, err
}

// writeOwned creates a new file with data in root.
func writeOwned(root *os.Root, name string, data []byte, o owner, testing bool) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, o.file)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if testing {
		return root.Chmod(name, o.file)
	}
	if err := root.Lchown(name, o.uid, o.gid); err != nil {
		return err
	}
	return root.Chmod(name, o.file)
}

// copyFile copies one regular file (keeping its modification time).
func copyFile(src *os.Root, from string, dst *os.Root, to string, o owner, testing bool, cs *treeStats) error {
	f, st, err := openRegular(src, from, 1<<40)
	if err != nil {
		return err
	}
	defer f.Close()
	out, err := dst.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, o.file)
	if err != nil {
		return err
	}
	n, werr := io.Copy(out, f)
	if cerr := out.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if !testing {
		if err := dst.Lchown(to, o.uid, o.gid); err != nil {
			return err
		}
	}
	if err := dst.Chmod(to, o.file); err != nil {
		return err
	}
	_ = dst.Chtimes(to, st.ModTime(), st.ModTime())
	cs.files++
	cs.bytes += n
	return nil
}

// copyFlat copies the regular files directly in from (a Maildir's cur or
// new) into the existing folder to.
func copyFlat(ctx context.Context, src *os.Root, from string, dst *os.Root, to string, o owner, testing bool, cs *treeStats) error {
	names, err := readDirNames(src, from)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, n := range names {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !maildirName.MatchString(n) || n[0] == '.' {
			cs.skipped++
			continue
		}
		st, err := src.Lstat(path.Join(from, n))
		if err != nil || !st.Mode().IsRegular() {
			cs.skipped++
			continue
		}
		if err := copyFile(src, path.Join(from, n), dst, path.Join(to, n), o, testing, cs); err != nil {
			return err
		}
		cs.messages++
	}
	return nil
}

// copyTree copies the folder from (in src) into the existing folder to (in
// dst): folders and regular files only, everything else is left out and
// counted; skip leaves out paths (relative to from).
func copyTree(ctx context.Context, src *os.Root, from string, dst *os.Root, to string, o owner, testing bool, skip func(rel string, dir bool) bool, cs *treeStats) error {
	var walk func(rel string, depth int) error
	walk = func(rel string, depth int) error {
		if depth > 32 {
			return errors.New("folders nested too deep")
		}
		names, err := readDirNames(src, path.Join(from, rel))
		if err != nil {
			return err
		}
		for _, n := range names {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			r := path.Join(rel, n)
			st, err := src.Lstat(path.Join(from, r))
			if err != nil {
				return err
			}
			if !maildirName.MatchString(n) || n == "." || n == ".." {
				cs.skipped++
				continue
			}
			switch {
			case st.IsDir():
				if skip != nil && skip(r, true) {
					continue
				}
				d := path.Join(to, r)
				if err := dst.Mkdir(d, o.dir); err != nil {
					return err
				}
				if !testing {
					if err := dst.Lchown(d, o.uid, o.gid); err != nil {
						return err
					}
				}
				if err := dst.Chmod(d, o.dir); err != nil {
					return err
				}
				cs.dirs++
				if err := walk(r, depth+1); err != nil {
					return err
				}
			case st.Mode().IsRegular():
				if skip != nil && skip(r, false) {
					continue
				}
				if err := copyFile(src, path.Join(from, r), dst, path.Join(to, r), o, testing, cs); err != nil {
					return err
				}
				if b := path.Base(path.Dir(r)); b == "cur" || b == "new" {
					cs.messages++
				}
			default:
				cs.skipped++
			}
		}
		return nil
	}
	return walk("", 0)
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
	rs := &restore{r: r, ctx: ctx, e: e, live: &ApplyArgs{Config: RootConfig{Pool: pool, Domains: ver.Domains}}, ver: ver, src: src,
		radUID: radUID, rspGID: rspGID, stamp: r.clock().Format("20060102-150405"),
		res: &RestoreResult{Scope: ScopeAll, DKIM: []string{}, Notes: []string{}}}
	if rs.vm, err = os.OpenRoot(e.VMailDir()); err != nil {
		return nil, err
	}
	defer rs.vm.Close()
	if names, _ := readDirNames(rs.vm, "."); len(names) > 0 {
		return nil, invalid("%s/mail already holds mail; restore into the mail server instead", pool)
	}
	if rs.rad, err = r.radicaleRoot(e); err != nil {
		return nil, err
	}
	defer rs.rad.Close()
	keys := map[string]bool{"family": true}
	for _, m := range ver.Mailboxes {
		keys[m.Key] = true
		home := path.Join("vmail", m.Key)
		if st, err := src.Lstat(home); err != nil || !st.IsDir() {
			continue
		}
		if err := rs.vm.Mkdir(m.Key, 0o700); err != nil {
			return rs.res, err
		}
		if err := rs.chown(rs.vm, m.Key, rs.vmailOwner()); err != nil {
			return rs.res, err
		}
		cs := &treeStats{}
		if err := copyTree(ctx, src, home, rs.vm, m.Key, rs.vmailOwner(), r.Chown != nil, skipMaildirTmp, cs); err != nil {
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
	// The certificate: kept until a new one is issued.
	if tr, err := os.OpenRoot(e.TLSDir()); err == nil {
		for _, n := range []string{"key.pem", "fullchain.pem"} {
			if err := copyRegular(src, path.Join("keys", "tls", n), tr, n, maxDKIMBytes); err != nil && !errors.Is(err, fs.ErrNotExist) {
				rs.res.note("the TLS certificate: %v (a new one is made)", err)
			}
		}
		tr.Close()
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
