package mail

import (
	"bufio"
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

	"golang.org/x/sys/unix"
)

// Restores of the mail server from a copy of its dataset (decisions
// 460-469). The copy is read as untrusted; what replaces live data is
// built next to it first (root only), then swapped in atomically
// (renameat2 RENAME_EXCHANGE) while that mailbox's delivery is held, and
// what was there stays root-only for ReplacedDays days.

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
	// RestoreOverwrite puts the version back in place of what's there
	// (after a snapshot of the mail dataset). Mail the version doesn't
	// have (arrived or kept since) is kept in the mailbox.
	RestoreOverwrite = "overwrite"
)

// ConfirmAll is what's typed to restore the whole mail server.
const ConfirmAll = "mail"

// ReplacedDays is how long what an overwrite replaced is kept, root only
// (vmail/<key>/.replaced-<time>, collection-root/.replaced-<key>-<time>).
const ReplacedDays = 14

// HoldTransport is the Postfix transport of a held mailbox: its mail waits
// in the queue (here, or on the VPS) until the restore is done.
const HoldTransport = "retry:4.2.1 this mailbox is being restored; try again shortly"

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
	// FromReplica: the copy came from another server (replication). Set
	// by hardyd-priv only, never from a request: Rspamd's data isn't taken
	// from it (decision 467).
	FromReplica bool `json:"-"`
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
	Kept        int      `json:"kept"` // overwrite: messages the version didn't have, kept
	Collections int      `json:"collections"`
	Bytes       int64    `json:"bytes"`
	Needed      int64    `json:"needed"`           // the space the restore needed (estimate)
	Folder      string   `json:"folder,omitempty"` // the new folder (copy mode)
	Safety      string   `json:"safety,omitempty"` // snapshot of <pool>/mail taken first
	Replaced    []string `json:"replaced"`         // root-only copies of what was replaced
	DKIM        []string `json:"dkim"`             // domains whose key came back
	Bayes       bool     `json:"bayes"`
	Notes       []string `json:"notes"`
}

func (res *RestoreResult) note(format string, a ...any) {
	if len(res.Notes) < 50 {
		res.Notes = append(res.Notes, fmt.Sprintf(format, a...))
	}
}

// Space is the room left on the mail dataset.
type Space struct {
	Pool      string `json:"pool"`
	FreeBytes int64  `json:"freeBytes"`
}

// Space reports the mail dataset's free space (for a restore's estimate).
func (r *Root) Space(ctx context.Context) (*Space, error) {
	r.mu.Lock()
	live, err := r.saved()
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	mp, err := r.dataset(ctx, live.Config.Pool)
	if err != nil {
		return nil, err
	}
	free, err := r.free(mp)
	if err != nil {
		return nil, err
	}
	return &Space{Pool: live.Config.Pool, FreeBytes: free}, nil
}

func (r *Root) free(dir string) (int64, error) {
	if r.Free != nil {
		return r.Free(dir)
	}
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
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
	snaps   int
	res     *RestoreResult
	byKey   map[string]RootMailbox // live mailboxes
	verKeys map[string]RootMailbox // the version's
	replica bool
	// stopped: a restore of everything, the services are off and r.mu is
	// held for all of it.
	stopped   bool
	bayesPrev string
}

// RestoreFrom puts what a says back from dir, a copy of the mail dataset
// (a staged backup version or a received replica, which root alone
// writes). Its contents are read as untrusted: only regular files and
// folders, never through links, with the live server's owners and fixed
// modes; a replaced part is snapshotted first.
//
// One restore runs at a time. The mail server's lock (r.mu, which applies
// and backups take too) is held only while live data is swapped, except
// for a restore of everything, which holds it from stopping the services
// to starting them again (decision 466).
func (r *Root) RestoreFrom(ctx context.Context, dir string, a RestoreArgs) (*RestoreResult, error) {
	if err := a.Check(); err != nil {
		return nil, err
	}
	r.restoreMu.Lock()
	defer r.restoreMu.Unlock()
	r.mu.Lock()
	live, err := r.saved()
	r.mu.Unlock()
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
	rs := &restore{r: r, ctx: ctx, e: e, live: live, ver: ver, src: src, stamp: r.clock().Format("20060102-150405"), replica: a.FromReplica,
		res: &RestoreResult{Scope: a.Scope, DKIM: []string{}, Notes: []string{}, Replaced: []string{}}, byKey: map[string]RootMailbox{}, verKeys: map[string]RootMailbox{}}
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
	if err := rs.checkSpace(a); err != nil {
		return nil, err
	}
	if err := rs.run(a); err != nil {
		return rs.res, err
	}
	r.log().Info("mail: restored from a copy", "scope", a.Scope, "mode", a.Mode, "mailboxes", rs.res.Mailboxes, "messages", rs.res.Messages,
		"kept", rs.res.Kept, "collections", rs.res.Collections, "dkim", strings.Join(rs.res.DKIM, ","), "bayes", rs.res.Bayes, "replica", a.FromReplica)
	return rs.res, nil
}

func (r *Root) clock() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// lock takes the mail server's lock for a swap (no-op while a restore of
// everything holds it).
func (rs *restore) lock() func() {
	if rs.stopped {
		return func() {}
	}
	rs.r.mu.Lock()
	return rs.r.mu.Unlock
}

// stillLive re-reads the live setup under the lock: the mailbox must still
// be there with the same address.
func (rs *restore) stillLive(m RootMailbox) error {
	if rs.stopped {
		return nil
	}
	cur, err := rs.r.saved()
	if err != nil {
		return err
	}
	for _, x := range cur.Config.Mailboxes {
		if x.Key == m.Key && x.Address == m.Address {
			return nil
		}
	}
	return fmt.Errorf("%s changed on the server during the restore; start it again", m.Address)
}

// checkSpace refuses a restore that clearly can't fit: everything it
// copies is written next to what's there before the swap (decision 469).
func (rs *restore) checkSpace(a RestoreArgs) error {
	var dirs []string
	switch a.Scope {
	case ScopeMailbox:
		dirs = []string{path.Join("vmail", a.Key, "Maildir")}
	case ScopeCalendars:
		dirs = []string{path.Join("radicale", "collections", "collection-root", a.Key)}
	case ScopeDomain:
		for _, m := range rs.ver.Mailboxes {
			if _, d, _ := SplitAddress(m.Address); d == a.Domain {
				dirs = append(dirs, path.Join("vmail", m.Key, "Maildir"))
				if a.Mode == RestoreOverwrite {
					dirs = append(dirs, path.Join("radicale", "collections", "collection-root", m.Key))
				}
			}
		}
	default:
		dirs = []string{"vmail", path.Join("radicale", "collections")}
	}
	var need int64
	for _, d := range dirs {
		need += treeSize(rs.src, d, 0)
	}
	rs.res.Needed = need
	free, err := rs.r.free(rs.e.MailRoot)
	if err != nil {
		return nil // unknown: the copy itself stops if it runs out
	}
	if need+need/20+64<<20 > free {
		return invalid("this restore needs about %s on the mail storage and %s is free; free some space or raise the mail storage limit first", humanSize(need), humanSize(free))
	}
	return nil
}

// treeSize adds up the regular files under dir (never through links).
func treeSize(root *os.Root, dir string, depth int) int64 {
	if depth > 32 {
		return 0
	}
	names, err := readDirNames(root, dir)
	if err != nil {
		return 0
	}
	var n int64
	for _, name := range names {
		st, err := root.Lstat(path.Join(dir, name))
		switch {
		case err != nil:
		case st.IsDir():
			n += treeSize(root, path.Join(dir, name), depth+1)
		case st.Mode().IsRegular():
			n += st.Size()
		}
	}
	return n
}

func humanSize(n int64) string {
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

func (rs *restore) run(a RestoreArgs) error {
	switch a.Scope {
	case ScopeMailbox:
		vm, live, err := rs.pair(a)
		if err != nil {
			return err
		}
		if a.Mode == RestoreOverwrite {
			if err := rs.snapshot(); err != nil {
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
			if err := rs.snapshot(); err != nil {
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

// snapshot snapshots the mail dataset: first before anything is replaced
// (the result's Safety), then right before each swap.
func (rs *restore) snapshot() error {
	rs.snaps++
	name := "hardyos-manual-" + rs.stamp
	if rs.snaps > 1 {
		name += fmt.Sprintf("-%d", rs.snaps)
	}
	ds := rs.live.Config.Pool + "/mail"
	var err error
	if rs.r.SafetySnapshot != nil {
		err = rs.r.SafetySnapshot(rs.ctx, ds, name)
	} else {
		_, err = rs.r.run(rs.ctx, "zfs", "snapshot", ds+"@"+name)
	}
	if err != nil {
		return fmt.Errorf("taking a snapshot of the mail first: %w", err)
	}
	if rs.res.Safety == "" {
		rs.res.Safety = name
	}
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
		if err := rs.snapshot(); err != nil {
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
		// Only mailboxes that are at the domain now (decision 461): one
		// moved to another domain since is restored on its own.
		if _, d, _ := SplitAddress(live.Address); d != a.Domain {
			rs.res.note("%s is %s now, at another domain: restore it on its own", vm.Address, live.Address)
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
// is applied again (which starts everything), even when the restore is
// cancelled or fails half way.
func (rs *restore) all() (err error) {
	rs.r.mu.Lock()
	defer rs.r.mu.Unlock()
	if err := rs.snapshot(); err != nil {
		return err
	}
	rs.r.stopUnits(rs.ctx)
	rs.stopped = true
	var errs []error
	defer func() {
		// Started again whatever happened, with a context of its own.
		actx, cancel := context.WithTimeout(context.WithoutCancel(rs.ctx), 10*time.Minute)
		defer cancel()
		if _, aerr := rs.r.apply(actx, *rs.live, false); aerr != nil {
			errs = append(errs, fmt.Errorf("starting the mail server again: %w", aerr))
		}
		rs.checkRedis(actx)
		err = errors.Join(append(errs, err)...)
	}()
	for _, vm := range rs.ver.Mailboxes {
		if rs.ctx.Err() != nil {
			return rs.ctx.Err()
		}
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
	return nil
}

// stopUnits stops the mail programs (a restore of everything).
func (r *Root) stopUnits(ctx context.Context) {
	all := append(slices.Clone(coreUnits), clamavUnits...)
	slices.Reverse(all)
	_ = r.systemctl(ctx, append([]string{"stop"}, all...)...)
}

// ---- holding a mailbox's mail ---------------------------------------------------

// HoldFile is Postfix's map of mailboxes whose mail waits (transport_maps):
// empty except while a restore swaps a mailbox.
var HoldFile = path.Join(PostfixMapsDir, "hold")

// hold makes Postfix keep addr's mail in the queue (the relay from the VPS
// keeps it there too) and ends its sessions; release undoes it and sends
// what waited.
func (rs *restore) hold(addr string) (release func()) {
	if rs.stopped {
		return func() {}
	}
	write := func(lines [][2]string) {
		if err := rs.r.write(HoldFile, []byte(mapFile(lines)), 0o644); err != nil {
			rs.res.note("couldn't hold %s's mail during the swap: %v", addr, err)
		}
		if _, err := rs.r.run(rs.ctx, "postfix", "reload"); err != nil {
			rs.r.log().Warn("mail: postfix reload for a restore", "err", err)
		}
	}
	write([][2]string{{addr, HoldTransport}})
	_ = rs.r.kickLocked(rs.ctx, addr)
	return func() {
		ctx := context.WithoutCancel(rs.ctx)
		_ = rs.r.write(HoldFile, []byte(mapFile(nil)), 0o644)
		_, _ = rs.r.run(ctx, "postfix", "reload")
		_, _ = rs.r.run(ctx, "postqueue", "-f")
	}
}

// ---- mailboxes ------------------------------------------------------------------

// owner is how a restored tree is written.
type owner struct {
	uid, gid int
	dir      os.FileMode
	file     os.FileMode
}

func (rs *restore) vmailOwner() owner { return owner{rs.e.VMailUID, rs.e.VMailGID, 0o700, 0o600} }
func rootOwner() owner                { return owner{0, 0, 0o700, 0o600} }

func (rs *restore) testing() bool { return rs.r.Chown != nil }

// maildirName: a message's or folder's name in a Maildir.
var maildirName = regexp.MustCompile(`^[^/\x00]{1,255}$`)

// mailbox restores one mailbox: copy puts the version's folders into a new
// folder tree "Restored <date>" (subscribed), overwrite puts the version's
// Maildir in place of the mailbox's (keeping mail it doesn't have).
func (rs *restore) mailbox(vm, live RootMailbox, mode string) error {
	srcMd := path.Join("vmail", vm.Key, "Maildir")
	if st, err := rs.src.Lstat(srcMd); err != nil || !st.IsDir() {
		rs.res.note("%s: the version has no mail for it", vm.Address)
		return nil
	}
	cs := &treeStats{}
	var err error
	if mode == RestoreCopy {
		err = rs.mailboxCopy(vm, live, cs)
	} else {
		err = rs.mailboxOverwrite(vm, live, cs)
	}
	if err != nil {
		return err
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

// RestoredFolder names the folder a copy-mode restore makes.
func RestoredFolder(t time.Time) string { return "Restored " + t.Format("2006-01-02 1504") }

// maildirFolders lists a Maildir's folders: "" (INBOX) and the ".Name"
// subfolders (Maildir++), only real folders with acceptable names.
func maildirFolders(root *os.Root, md string) ([]string, error) {
	names, err := readDirNames(root, md)
	if err != nil {
		return nil, err
	}
	out := []string{""}
	for _, n := range names {
		if len(n) < 2 || n[0] != '.' || n == ".." || !maildirName.MatchString(n) {
			continue
		}
		if st, err := root.Lstat(path.Join(md, n)); err == nil && st.IsDir() {
			out = append(out, n)
		}
	}
	return out, nil
}

// copyMaildirFolder makes dst (in root) a Maildir folder with the
// version's messages of src: cur/ and new/ (tmp/ empty), its keywords
// file, and maildirfolder for a subfolder. Indexes, caches, the uidlist,
// Sieve scripts and other dotfiles never come along (decision 467): Dovecot
// rebuilds what it needs. Base names of the copied messages go into bases.
func (rs *restore) copyMaildirFolder(src, dst string, sub, mk bool, root *os.Root, o owner, cs *treeStats, bases map[string]bool) error {
	if mk {
		if err := mkdirOwned(root, dst, o, rs.testing()); err != nil {
			return err
		}
	}
	for _, d := range []string{"cur", "new", "tmp"} {
		if err := mkdirOwned(root, path.Join(dst, d), o, rs.testing()); err != nil {
			return err
		}
		if d == "tmp" {
			continue
		}
		if err := copyFlat(rs.ctx, rs.src, path.Join(src, d), root, path.Join(dst, d), o, rs.testing(), cs, bases); err != nil {
			return err
		}
	}
	if st, err := rs.src.Lstat(path.Join(src, "dovecot-keywords")); err == nil && st.Mode().IsRegular() && st.Size() < 64<<10 {
		if err := copyFile(rs.src, path.Join(src, "dovecot-keywords"), root, path.Join(dst, "dovecot-keywords"), o, rs.testing(), cs); err != nil {
			return err
		}
	}
	if sub {
		return writeOwned(root, path.Join(dst, "maildirfolder"), nil, o, rs.testing())
	}
	return nil
}

// mailboxCopy builds the version's folders under vmail/.restoring-…
// (root only), then moves each into the live Maildir under the new top
// folder.
func (rs *restore) mailboxCopy(vm, live RootMailbox, cs *treeStats) error {
	srcMd := path.Join("vmail", vm.Key, "Maildir")
	liveMd := path.Join(live.Key, "Maildir")
	work := ".restoring-" + live.Key + "-" + rs.stamp
	if err := mkdirOwned(rs.vm, work, rootOwner(), rs.testing()); err != nil {
		return err
	}
	defer rs.vm.RemoveAll(work)
	folders, err := maildirFolders(rs.src, srcMd)
	if err != nil {
		return err
	}
	top := RestoredFolder(rs.r.clock())
	var made []string
	for _, f := range folders {
		dest := "." + top
		if f != "" {
			dest += f // ".Restored X" + ".Sent"
		}
		if err := rs.copyMaildirFolder(path.Join(srcMd, f), path.Join(work, dest), true, true, rs.vm, rs.vmailOwner(), cs, nil); err != nil {
			return err
		}
		made = append(made, dest)
	}
	unlock := rs.lock()
	defer unlock()
	if err := rs.stillLive(live); err != nil {
		return err
	}
	for _, d := range []string{live.Key, liveMd} {
		if err := rs.ensureVmailDir(d); err != nil {
			return err
		}
	}
	// A name of its own (a second restore in the same minute gets "(2)").
	final := top
	for i := 2; ; i++ {
		if _, err := rs.vm.Lstat(path.Join(liveMd, "."+final)); errors.Is(err, fs.ErrNotExist) {
			break
		}
		if i > 20 {
			return errors.New("there are already restored folders of this time; try again in a minute")
		}
		final = fmt.Sprintf("%s (%d)", top, i)
	}
	rs.res.Folder = final
	var imap []string
	for _, d := range made {
		to := "." + final + strings.TrimPrefix(d, "."+top)
		if err := rs.vm.Rename(path.Join(work, d), path.Join(liveMd, to)); err != nil {
			return fmt.Errorf("moving the restored folder in: %w", err)
		}
		imap = append(imap, strings.ReplaceAll(strings.TrimPrefix(to, "."), ".", "/"))
	}
	// Subscribed, so mail apps show them (IMAP names use "/").
	if _, err := rs.r.run(rs.ctx, "doveadm", append([]string{"mailbox", "subscribe", "-u", live.Address}, imap...)...); err != nil {
		rs.res.note("%s: subscribe to the folder %s in your mail app to see it", live.Address, final)
	}
	return nil
}

// mailboxOverwrite builds the version's Maildir in the mailbox's home
// (root only while it's built), then, with the mailbox's mail held and a
// snapshot taken, exchanges it with the live Maildir in one step and moves
// in the messages the version doesn't have (arrived since, or until the
// swap). What was there stays, root only, as .replaced-<time>.
func (rs *restore) mailboxOverwrite(vm, live RootMailbox, cs *treeStats) error {
	srcMd := path.Join("vmail", vm.Key, "Maildir")
	if err := rs.ensureVmailDir(live.Key); err != nil {
		return err
	}
	home, err := rs.vm.OpenRoot(live.Key)
	if err != nil {
		return err
	}
	defer home.Close()
	work := ".restoring-" + rs.stamp
	if err := mkdirOwned(home, work, rootOwner(), rs.testing()); err != nil {
		return err
	}
	keepWork := false
	defer func() {
		if !keepWork {
			_ = home.RemoveAll(work)
		}
	}()
	folders, err := maildirFolders(rs.src, srcMd)
	if err != nil {
		return err
	}
	bases := map[string]bool{}
	for _, f := range folders {
		dst := work
		if f != "" {
			dst = path.Join(work, f)
		}
		if err := rs.copyMaildirFolder(path.Join(srcMd, f), dst, f != "", f != "", home, rs.vmailOwner(), cs, bases); err != nil {
			return err
		}
	}
	// The swap: one mailbox's mail waits, sessions end, a snapshot of the
	// moment, then one rename.
	unlock := rs.lock()
	defer unlock()
	if err := rs.stillLive(live); err != nil {
		return err
	}
	release := rs.hold(live.Address)
	defer release()
	if !rs.stopped && rs.snaps > 0 {
		if err := rs.snapshot(); err != nil {
			return err
		}
	}
	if err := chownDir(home, work, rs.vmailOwner(), rs.testing()); err != nil {
		return err
	}
	had, err := exchange(home, work, "Maildir")
	if err != nil {
		keepWork = true // nothing was swapped; the restored copy stays for a look
		_ = chownDir(home, work, rootOwner(), rs.testing())
		return fmt.Errorf("putting the restored mail in place (vmail/%s/%s holds it): %w", live.Key, work, err)
	}
	if had {
		// work is now what was there: what the version doesn't have goes
		// into the restored Maildir, the rest is kept aside, root only.
		kept, err := mergeMissing(home, work, "Maildir", bases, rs.vmailOwner(), rs.testing())
		rs.res.Kept += kept
		if err != nil {
			rs.res.note("%s: some newer messages stayed in vmail/%s/.replaced-%s: %v", live.Address, live.Key, rs.stamp, err)
		}
		if err := chownDir(home, work, rootOwner(), rs.testing()); err != nil {
			keepWork = true
			return fmt.Errorf("what was replaced is in vmail/%s/%s: %w", live.Key, work, err)
		}
		old, err := rs.keepAside(home, work, ".replaced-")
		if err != nil {
			keepWork = true
			return fmt.Errorf("what was replaced is in vmail/%s/%s: %w", live.Key, work, err)
		}
		rs.res.Replaced = append(rs.res.Replaced, path.Join("vmail", live.Key, old))
	}
	_ = rs.r.kickLocked(rs.ctx, live.Address)
	if _, err := rs.r.run(rs.ctx, "doveadm", "force-resync", "-u", live.Address, "*"); err != nil {
		rs.res.note("%s: Dovecot will check the restored folders when it next opens them (%s)", live.Address, clipText(err.Error(), 120))
	}
	return nil
}

// keepAside renames work (in root) to prefix<time>, a name nothing has
// yet (the restore's time, or the next free second after it).
func (rs *restore) keepAside(root *os.Root, work, prefix string) (string, error) {
	d, err := root.Open(".")
	if err != nil {
		return "", err
	}
	defer d.Close()
	fd := int(d.Fd())
	t, _ := time.Parse("20060102-150405", rs.stamp)
	for i := 0; i < 600; i++ {
		name := prefix + t.Add(time.Duration(i)*time.Second).Format("20060102-150405")
		err := unix.Renameat2(fd, work, fd, name, unix.RENAME_NOREPLACE)
		if err == nil {
			return name, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", err
		}
	}
	return "", errors.New("no free name to keep what was replaced")
}

// maildirBase is a message file's unique part (before its ":2,flags").
func maildirBase(name string) string {
	if i := strings.IndexByte(name, ':'); i >= 0 {
		return name[:i]
	}
	return name
}

// mergeMissing moves the messages of the Maildir old (in root) that the
// version doesn't have (by base name, in any folder) into the same folder
// of the Maildir into.
func mergeMissing(root *os.Root, old, into string, bases map[string]bool, o owner, testing bool) (int, error) {
	folders, err := maildirFolders(root, old)
	if err != nil {
		return 0, err
	}
	kept := 0
	var errs []error
	for _, f := range folders {
		for _, sub := range []string{"new", "cur"} {
			from := path.Join(old, f, sub)
			names, err := readDirNames(root, from)
			if err != nil {
				continue
			}
			for _, n := range names {
				if n[0] == '.' || bases[maildirBase(n)] {
					continue
				}
				if st, err := root.Lstat(path.Join(from, n)); err != nil || !st.Mode().IsRegular() {
					continue
				}
				dir := path.Join(into, f)
				if f != "" {
					if _, err := root.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
						for _, d := range []string{dir, path.Join(dir, "cur"), path.Join(dir, "new"), path.Join(dir, "tmp")} {
							if err := mkdirOwned(root, d, o, testing); err != nil {
								errs = append(errs, err)
							}
						}
						_ = writeOwned(root, path.Join(dir, "maildirfolder"), nil, o, testing)
					}
				}
				if err := root.Rename(path.Join(from, n), path.Join(dir, sub, n)); err != nil {
					errs = append(errs, err)
					continue
				}
				kept++
			}
		}
	}
	return kept, errors.Join(errs...)
}

func (rs *restore) ensureVmailDir(name string) error {
	st, err := rs.vm.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return mkdirOwned(rs.vm, name, rs.vmailOwner(), rs.testing())
	case err != nil:
		return err
	case !st.IsDir():
		return fmt.Errorf("%s isn't a folder", name)
	}
	return nil
}

// exchange swaps the folders a and b (both directly in root) in one step;
// when b doesn't exist, a becomes b. had says whether b existed (it's now
// at a).
func exchange(root *os.Root, a, b string) (had bool, err error) {
	d, err := root.Open(".")
	if err != nil {
		return false, err
	}
	defer d.Close()
	fd := int(d.Fd())
	if st, err := root.Lstat(b); err == nil {
		if !st.IsDir() {
			return false, fmt.Errorf("%s isn't a folder", b)
		}
		return true, unix.Renameat2(fd, a, fd, b, unix.RENAME_EXCHANGE)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return false, unix.Renameat2(fd, a, fd, b, unix.RENAME_NOREPLACE)
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
		// Root's until it's complete, then Radicale's.
		if err := mkdirOwned(rs.rad, dest, rootOwner(), rs.testing()); err != nil {
			return err
		}
		cs := &treeStats{}
		if err := copyTree(rs.ctx, rs.src, path.Join(srcDir, n), rs.rad, dest, rs.radOwner(), rs.testing(), skipRadicale, cs); err != nil {
			_ = rs.rad.RemoveAll(dest)
			return err
		}
		if err := relabel(rs.rad, dest, n, label, rs.radOwner(), rs.testing()); err != nil {
			rs.res.note("%s: the restored collection %s keeps its old name", live.Address, n)
		}
		if err := chownDir(rs.rad, dest, rs.radOwner(), rs.testing()); err != nil {
			_ = rs.rad.RemoveAll(dest)
			return err
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
	return chownFile(root, p, o, testing)
}

func (rs *restore) ensureRadDir(name string) error {
	st, err := rs.rad.Lstat(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return mkdirOwned(rs.rad, name, rs.radOwner(), rs.testing())
	case err != nil:
		return err
	case !st.IsDir():
		return fmt.Errorf("%s isn't a folder", name)
	}
	return nil
}

// swapCollections puts the version's collection-root/<from> in place of
// collection-root/<to>; what was there stays, root only, as
// collection-root/.replaced-<to>-<time>.
func (rs *restore) swapCollections(from, to string) error {
	srcDir := path.Join("radicale", "collections", "collection-root", from)
	if st, err := rs.src.Lstat(srcDir); err != nil || !st.IsDir() {
		return fs.ErrNotExist
	}
	if err := rs.ensureRadDir("collection-root"); err != nil {
		return err
	}
	cr, err := rs.rad.OpenRoot("collection-root")
	if err != nil {
		return err
	}
	defer cr.Close()
	work := ".restoring-" + to + "-" + rs.stamp
	if err := mkdirOwned(cr, work, rootOwner(), rs.testing()); err != nil {
		return err
	}
	keepWork := false
	defer func() {
		if !keepWork {
			_ = cr.RemoveAll(work)
		}
	}()
	cs := &treeStats{}
	if err := copyTree(rs.ctx, rs.src, srcDir, cr, work, rs.radOwner(), rs.testing(), skipRadicale, cs); err != nil {
		return err
	}
	unlock := rs.lock()
	defer unlock()
	if err := chownDir(cr, work, rs.radOwner(), rs.testing()); err != nil {
		return err
	}
	had, err := exchange(cr, work, to)
	if err != nil {
		keepWork = true
		_ = chownDir(cr, work, rootOwner(), rs.testing())
		return fmt.Errorf("putting the restored calendars in place (collection-root/%s holds them): %w", work, err)
	}
	if had {
		old := ""
		err := chownDir(cr, work, rootOwner(), rs.testing())
		if err == nil {
			old, err = rs.keepAside(cr, work, ".replaced-"+to+"-")
		}
		if err != nil {
			keepWork = true
			return fmt.Errorf("what was replaced is in collection-root/%s: %w", work, err)
		}
		rs.res.Replaced = append(rs.res.Replaced, path.Join("radicale", "collections", "collection-root", old))
	}
	names, _ := readDirNames(cr, to)
	for _, n := range names {
		if collectionName.MatchString(n) {
			rs.res.Collections++
		}
	}
	return nil
}

// ---- DKIM and Rspamd ------------------------------------------------------------

// dkim puts a live domain's DKIM key back from the version (the key the
// domain's DNS record was published for). Missing is noted when loud.
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
	pub, err := dkimPublic(b)
	if err != nil {
		return fmt.Errorf("%s: the version's DKIM key isn't usable: %w", domain, err)
	}
	dr, err := os.OpenRoot(rs.e.DKIMDir())
	if err != nil {
		return err
	}
	defer dr.Close()
	unlock := rs.lock()
	defer unlock()
	if cur, err := readRegular(dr, name, maxDKIMBytes); err == nil {
		if curPub, err := dkimPublic(cur); err == nil && curPub == pub {
			return nil // the same key: nothing to do
		}
		rs.res.note("%s's DKIM key is now the one in the version: check that its DNS record (%s._domainkey) matches it in Control Panel › Mail › Domains", domain, sel)
	}
	if err := replaceFile(dr, name, func(w io.Writer) error { _, err := w.Write(b); return err }, 0o640); err != nil {
		return fmt.Errorf("%s's DKIM key: %w", domain, err)
	}
	if err := chownFile(dr, name, owner{0, rs.rspGID, 0o750, 0o640}, rs.testing()); err != nil {
		return err
	}
	rs.res.DKIM = append(rs.res.DKIM, domain)
	if rs.stopped {
		return nil // everything starts again at the end
	}
	if _, err := rs.r.run(rs.ctx, "systemctl", "reload-or-restart", "rspamd.service"); err != nil {
		rs.res.note("Rspamd signs with the restored key once it restarts")
	}
	return nil
}

// bayes puts Rspamd's data back (Redis is stopped: restore of everything).
// Never from a replica; from a backup only a dump that passes the checks
// (no functions or modules, redis-check-rdb as Redis's user), keeping the
// previous one to go back to if Redis doesn't start with it.
func (rs *restore) bayes() error {
	if rs.replica {
		rs.res.note("Rspamd's learning isn't taken from another server's copy; it learns again from the restored Junk folders")
		return nil
	}
	f, _, err := openRegular(rs.src, path.Join(BackupDir, BackupBayesName), maxBayesBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if err := CheckRDB(f); err != nil {
		return fmt.Errorf("the version's Rspamd data was refused: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := rs.r.ensureRedisDir(); err != nil {
		return err
	}
	rd, err := os.OpenRoot(rs.r.redisDir())
	if err != nil {
		return err
	}
	defer rd.Close()
	tmp := "dump.rdb.restoring"
	_ = rd.Remove(tmp)
	if err := replaceFile(rd, tmp, func(w io.Writer) error {
		_, err := io.Copy(w, io.LimitReader(f, maxBayesBytes))
		return err
	}, 0o640); err != nil {
		return err
	}
	uid, gid := 0, 0
	if !rs.testing() {
		if uid, gid, err = rs.r.lookupUser("redis"); err != nil {
			_ = rd.Remove(tmp)
			return err
		}
	}
	if err := chownFile(rd, tmp, owner{uid, gid, 0o750, 0o640}, rs.testing()); err != nil {
		_ = rd.Remove(tmp)
		return err
	}
	// Redis's own checker, as Redis's user, without privileges.
	if _, err := rs.r.run(rs.ctx, "setpriv", "--reuid=redis", "--regid=redis", "--clear-groups", "--no-new-privs", "--inh-caps=-all",
		"redis-check-rdb", path.Join(rs.r.redisDir(), tmp)); err != nil {
		_ = rd.Remove(tmp)
		return fmt.Errorf("the version's Rspamd data didn't pass redis-check-rdb: %s", clipText(err.Error(), 200))
	}
	prev := "dump.rdb.before-restore"
	_ = rd.Remove(prev)
	if err := rd.Rename("dump.rdb", prev); err == nil {
		rs.bayesPrev = prev
	}
	if err := rd.Rename(tmp, "dump.rdb"); err != nil {
		return err
	}
	rs.res.Bayes = true
	return nil
}

// checkRedis goes back to the previous Rspamd data if Redis didn't come up
// with the restored one.
func (rs *restore) checkRedis(ctx context.Context) {
	if rs.bayesPrev == "" {
		return
	}
	if _, err := rs.r.run(ctx, "systemctl", "is-active", "--quiet", RedisUnit); err == nil {
		return
	}
	rd, err := os.OpenRoot(rs.r.redisDir())
	if err != nil {
		return
	}
	defer rd.Close()
	if err := rd.Rename(rs.bayesPrev, "dump.rdb"); err != nil {
		return
	}
	_, _ = rs.r.run(ctx, "systemctl", "restart", RedisUnit)
	rs.res.Bayes = false
	rs.res.note("Rspamd's Redis didn't start with the restored data, so its previous data is back")
}

// CheckRDB reads the start of a Redis dump: its header and the records
// before the first database. Function libraries (Lua code Redis would load
// and run) and module data are refused, and so is anything unexpected.
func CheckRDB(r io.Reader) error {
	br := bufio.NewReader(r)
	hdr := make([]byte, 9)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return errors.New("not a Redis dump")
	}
	if string(hdr[:5]) != "REDIS" {
		return errors.New("not a Redis dump")
	}
	v := 0
	for _, c := range hdr[5:] {
		if c < '0' || c > '9' {
			return errors.New("not a Redis dump")
		}
		v = v*10 + int(c-'0')
	}
	if v < 1 || v > 20 {
		return fmt.Errorf("an unknown Redis dump version %d", v)
	}
	for i := 0; i < 10000; i++ {
		op, err := br.ReadByte()
		if err != nil {
			return errors.New("the dump ends too early")
		}
		switch op {
		case 0xFA: // AUX: two strings
			for j := 0; j < 2; j++ {
				if err := skipRDBString(br); err != nil {
					return err
				}
			}
		case 0xFE, 0xFF: // SELECTDB (the data starts) or EOF
			return nil
		case 0xF5, 0xF6:
			return errors.New("it holds Redis functions")
		case 0xF7:
			return errors.New("it holds Redis module data")
		default:
			return fmt.Errorf("unexpected record 0x%02x", op)
		}
	}
	return errors.New("too many records")
}

// rdbLen reads a length; special says it's an encoded value (enc).
func rdbLen(br *bufio.Reader) (n uint64, special bool, err error) {
	b0, err := br.ReadByte()
	if err != nil {
		return 0, false, err
	}
	switch b0 >> 6 {
	case 0:
		return uint64(b0 & 0x3f), false, nil
	case 1:
		b1, err := br.ReadByte()
		return uint64(b0&0x3f)<<8 | uint64(b1), false, err
	case 2:
		size := 4
		if b0 == 0x81 {
			size = 8
		} else if b0 != 0x80 {
			return 0, false, errors.New("a bad length")
		}
		var v uint64
		for i := 0; i < size; i++ {
			c, err := br.ReadByte()
			if err != nil {
				return 0, false, err
			}
			v = v<<8 | uint64(c)
		}
		return v, false, nil
	}
	return uint64(b0 & 0x3f), true, nil
}

func skipN(br *bufio.Reader, n uint64) error {
	if n > 1<<20 {
		return errors.New("a record is too large")
	}
	_, err := br.Discard(int(n))
	return err
}

func skipRDBString(br *bufio.Reader) error {
	n, special, err := rdbLen(br)
	if err != nil {
		return errors.New("the dump ends too early")
	}
	if !special {
		return skipN(br, n)
	}
	switch n {
	case 0:
		return skipN(br, 1)
	case 1:
		return skipN(br, 2)
	case 2:
		return skipN(br, 4)
	case 3: // LZF: compressed length, length, data
		clen, _, err := rdbLen(br)
		if err != nil {
			return err
		}
		if _, _, err := rdbLen(br); err != nil {
			return err
		}
		return skipN(br, clen)
	}
	return errors.New("an unknown string encoding")
}

// ---- keeping and cleaning what was replaced -------------------------------------

var replacedRE = regexp.MustCompile(`^\.replaced-(?:.*-)?([0-9]{8}-[0-9]{6})$`)

// cleanReplaced removes what overwrites replaced once it's older than
// ReplacedDays (the mailboxes' homes and Radicale's collection-root).
func (r *Root) cleanReplaced(e Env) {
	cutoff := r.clock().AddDate(0, 0, -ReplacedDays)
	sweep := func(root *os.Root, dir string) {
		names, err := readDirNames(root, dir)
		if err != nil {
			return
		}
		for _, n := range names {
			m := replacedRE.FindStringSubmatch(n)
			if m == nil {
				continue
			}
			t, err := time.Parse("20060102-150405", m[1])
			if err != nil || t.After(cutoff) {
				continue
			}
			if err := root.RemoveAll(path.Join(dir, n)); err != nil {
				r.log().Warn("mail: removing what a restore replaced", "path", path.Join(root.Name(), dir, n), "err", err)
			}
		}
	}
	if vm, err := os.OpenRoot(e.VMailDir()); err == nil {
		keys, _ := readDirNames(vm, ".")
		for _, k := range keys {
			if keyRE.MatchString(k) {
				sweep(vm, k)
			}
		}
		vm.Close()
	}
	if rad, err := r.radicaleRoot(e); err == nil {
		sweep(rad, "collection-root")
		rad.Close()
	}
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

// openDirNoFollow opens a folder in root without following a link at it.
func openDirNoFollow(root *os.Root, name string) (*os.File, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.IsDir() {
		f.Close()
		return nil, fmt.Errorf("%s isn't a folder", name)
	}
	return f, nil
}

// chownDir gives a folder its owner and mode through a descriptor opened
// without following links (decision 467).
func chownDir(root *os.Root, name string, o owner, testing bool) error {
	f, err := openDirNoFollow(root, name)
	if err != nil {
		return err
	}
	defer f.Close()
	if !testing {
		if err := f.Chown(o.uid, o.gid); err != nil {
			return err
		}
	}
	return f.Chmod(o.dir)
}

// chownFile does the same for a regular file.
func chownFile(root *os.Root, name string, o owner, testing bool) error {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%s isn't a regular file", name)
	}
	if !testing {
		if err := f.Chown(o.uid, o.gid); err != nil {
			return err
		}
	}
	return f.Chmod(o.file)
}

// mkdirOwned makes a new folder (it must not exist) with o's owner and mode.
func mkdirOwned(root *os.Root, name string, o owner, testing bool) error {
	if err := root.Mkdir(name, 0o700); err != nil {
		return err
	}
	return chownDir(root, name, o, testing)
}

// writeOwned creates a new file with data in root.
func writeOwned(root *os.Root, name string, data []byte, o owner, testing bool) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	if werr == nil && !testing {
		werr = f.Chown(o.uid, o.gid)
	}
	if werr == nil {
		werr = f.Chmod(o.file)
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// copyFile copies one regular file (keeping its modification time), owner
// and mode set on the new file's descriptor.
func copyFile(src *os.Root, from string, dst *os.Root, to string, o owner, testing bool, cs *treeStats) error {
	f, st, err := openRegular(src, from, 1<<40)
	if err != nil {
		return err
	}
	defer f.Close()
	out, err := dst.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	n, werr := io.Copy(out, f)
	if werr == nil && !testing {
		werr = out.Chown(o.uid, o.gid)
	}
	if werr == nil {
		werr = out.Chmod(o.file)
	}
	if cerr := out.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	_ = dst.Chtimes(to, st.ModTime(), st.ModTime())
	cs.files++
	cs.bytes += n
	return nil
}

// copyFlat copies the regular files directly in from (a Maildir's cur or
// new) into the existing folder to, recording their base names.
func copyFlat(ctx context.Context, src *os.Root, from string, dst *os.Root, to string, o owner, testing bool, cs *treeStats, bases map[string]bool) error {
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
		if bases != nil {
			bases[maildirBase(n)] = true
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
				if err := mkdirOwned(dst, path.Join(to, r), o, testing); err != nil {
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
			default:
				cs.skipped++
			}
		}
		return nil
	}
	return walk("", 0)
}
