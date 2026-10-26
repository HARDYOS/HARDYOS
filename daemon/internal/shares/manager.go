package shares

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Dataset user properties holding a shared folder's settings.
const (
	PropShare       = "org.hardyos:share"
	PropName        = "org.hardyos:name"
	PropDescription = "org.hardyos:description"
	PropAccess      = "org.hardyos:access"
	PropApps        = "org.hardyos:apps"
	PropRecycle     = "org.hardyos:recycle"
	PropGuest       = "org.hardyos:guest"
	// PropServices holds how the folder is shared on the network (SMB, Time
	// Machine, NFS) and its snapshot schedule, as JSON (see services.go).
	PropServices = "org.hardyos:services"
)

// SharesDataset is the parent of every shared folder on a pool.
func SharesDataset(pool string) string { return pool + "/shares" }

// Dataset is the dataset of shared folder id on pool.
func Dataset(pool, id string) string { return SharesDataset(pool) + "/" + id }

var listProps = []string{"name", PropShare, PropName, PropDescription, PropAccess, PropApps,
	PropRecycle, PropGuest, "quota", "used", "mountpoint", "mounted", "creation", PropServices}

// bgTimeout bounds one background ACL walk (a huge photo library on slow
// disks still finishes well within it).
const bgTimeout = 12 * time.Hour

// Manager manages shared folders. It runs as root.
type Manager struct {
	Runner sysexec.Runner
	Log    *slog.Logger
	// Root prefixes system paths; "/" in production.
	Root string

	mu   sync.Mutex // serializes changes (the apps property is read-modify-write)
	bgMu sync.Mutex
	bg   map[string]*bgJob // background ACL walks by share id + uid
	wg   sync.WaitGroup
	// tree applies ACLs below a share's root; applyTree unless a test sets it.
	tree func(ctx context.Context, root string, uid int, write, revoke bool) (treeStats, error)
}

type bgJob struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func (m *Manager) root() string {
	if m.Root == "" {
		return "/"
	}
	return m.Root
}

func (m *Manager) sys(p string) string { return filepath.Join(m.root(), p) }

func (m *Manager) zfs(ctx context.Context, args ...string) ([]byte, error) {
	return sysexec.Output(ctx, m.Runner, "zfs", args...)
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// ---- reading ---------------------------------------------------------------

func (m *Manager) listArgs(target string) []string {
	args := []string{"list", "-Hp", "-t", "filesystem", "-o", strings.Join(listProps, ",")}
	if target != "" {
		args = append(args, target)
	}
	return args
}

// parseShare reads one `zfs list` row; ok is false for datasets that
// aren't shared folders.
func (m *Manager) parseShare(line string) (Share, bool) {
	f := strings.Split(line, "\t")
	if len(f) != len(listProps) || f[1] != "1" {
		return Share{}, false
	}
	pool, rest, _ := strings.Cut(f[0], "/")
	id, ok := strings.CutPrefix(rest, "shares/")
	if !ok || ValidID(id) != nil {
		return Share{}, false
	}
	val := func(s string) string {
		if s == "-" {
			return ""
		}
		return s
	}
	num := func(s string) uint64 {
		n, _ := strconv.ParseUint(s, 10, 64)
		return n
	}
	sh := Share{
		ID: id, Pool: pool, Dataset: f[0],
		Name: val(f[2]), Description: val(f[3]),
		Access: []Rule{}, Apps: []AppGrant{},
		Recycle: f[6] == "on", Guest: f[7] == "on",
		QuotaBytes: num(f[8]), UsedBytes: num(f[9]),
		Path: val(f[10]), Mounted: f[11] == "yes",
	}
	if sh.Name == "" {
		sh.Name = id
	}
	if !filepath.IsAbs(sh.Path) || strings.Contains(sh.Path, "..") {
		sh.Path, sh.Mounted = "", false
	}
	if s := val(f[4]); s != "" {
		if err := json.Unmarshal([]byte(s), &sh.Access); err != nil {
			m.log().Warn("shared folder has unreadable access rules", "dataset", f[0], "err", err)
			sh.Access = []Rule{}
		}
	}
	if s := val(f[5]); s != "" {
		if err := json.Unmarshal([]byte(s), &sh.Apps); err != nil {
			m.log().Warn("shared folder has an unreadable app list", "dataset", f[0], "err", err)
			sh.Apps = []AppGrant{}
		}
	}
	if secs := num(f[12]); secs > 0 {
		sh.CreatedAt = time.Unix(int64(secs), 0).UTC()
	}
	sh.Services = DefaultServices()
	if s := val(f[13]); s != "" {
		if err := json.Unmarshal([]byte(s), &sh.Services); err != nil {
			m.log().Warn("shared folder has unreadable sharing settings", "dataset", f[0], "err", err)
			sh.Services = DefaultServices()
		}
	}
	sh.Services.normalize()
	return sh, true
}

// List returns every shared folder on every imported pool.
func (m *Manager) List(ctx context.Context) ([]Share, error) {
	out, err := m.zfs(ctx, m.listArgs("")...)
	if err != nil {
		return nil, err
	}
	l := []Share{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if sh, ok := m.parseShare(line); ok {
			l = append(l, sh)
		}
	}
	sort.Slice(l, func(i, j int) bool {
		if a, b := strings.ToLower(l[i].Name), strings.ToLower(l[j].Name); a != b {
			return a < b
		}
		return l[i].Pool < l[j].Pool
	})
	return l, nil
}

// Get returns one shared folder.
func (m *Manager) Get(ctx context.Context, id string) (*Share, error) {
	if err := ValidID(id); err != nil {
		return nil, ErrNotFound
	}
	l, err := m.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range l {
		if l[i].ID == id {
			return &l[i], nil
		}
	}
	return nil, ErrNotFound
}

func (m *Manager) reread(ctx context.Context, ds string) (*Share, error) {
	out, err := m.zfs(ctx, m.listArgs(ds)...)
	if err != nil {
		return nil, err
	}
	sh, ok := m.parseShare(strings.TrimSpace(string(out)))
	if !ok {
		return nil, fmt.Errorf("%s doesn't look like a shared folder any more", ds)
	}
	return &sh, nil
}

func nameTaken(l []Share, name, exceptID string) *Share {
	for i := range l {
		if l[i].ID != exceptID && strings.EqualFold(l[i].Name, name) {
			return &l[i]
		}
	}
	return nil
}

// ---- creating --------------------------------------------------------------

// Create makes a shared folder.
func (m *Manager) Create(ctx context.Context, a NewShare) (*Share, error) {
	a, err := CheckNew(a)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	l, err := m.List(ctx)
	if err != nil {
		return nil, err
	}
	return m.create(ctx, a, l)
}

// create makes a checked shared folder; m.mu is held.
func (m *Manager) create(ctx context.Context, a NewShare, existing []Share) (*Share, error) {
	for _, sh := range existing {
		if sh.ID == a.ID {
			return nil, invalid("there's already a shared folder with the id %q (%s, on %s)", a.ID, sh.Name, sh.Pool)
		}
	}
	if sh := nameTaken(existing, a.Name, ""); sh != nil {
		return nil, invalid("there's already a shared folder called %s (on %s)", sh.Name, sh.Pool)
	}
	if _, err := m.zfs(ctx, "list", "-H", "-o", "name", a.Pool); err != nil {
		return nil, invalid("there's no pool called %s", a.Pool)
	}
	parent := SharesDataset(a.Pool)
	if _, err := m.zfs(ctx, "list", "-H", "-o", "name", parent); err != nil {
		if _, err := m.zfs(ctx, "create", "-o", "org.hardyos:role=shares", parent); err != nil {
			return nil, fmt.Errorf("creating %s: %w", parent, err)
		}
	}
	ds := Dataset(a.Pool, a.ID)
	if err := zfs.ValidDatasetName(ds); err != nil {
		return nil, invalid("%v", err)
	}
	args := []string{"create",
		"-o", "acltype=posixacl", "-o", "xattr=sa", "-o", "aclinherit=passthrough",
		// Nothing in a shared folder needs to be a device or run as
		// someone else, and apps can write there.
		"-o", "devices=off", "-o", "setuid=off",
	}
	// Keep the pool's compression if it has one, otherwise lz4.
	if out, err := m.zfs(ctx, "get", "-H", "-o", "source", "compression", a.Pool); err != nil || strings.TrimSpace(string(out)) == "default" {
		args = append(args, "-o", "compression=lz4")
	}
	if a.QuotaBytes > 0 {
		args = append(args, "-o", "quota="+strconv.FormatUint(a.QuotaBytes, 10))
	}
	args = append(args, "-o", PropShare+"=1", "-o", PropName+"="+a.Name)
	if a.Description != "" {
		args = append(args, "-o", PropDescription+"="+a.Description)
	}
	args = append(args,
		"-o", PropAccess+"="+mustJSON(a.Access),
		"-o", PropApps+"=[]",
		"-o", PropRecycle+"="+onOff(a.Recycle),
		"-o", PropGuest+"="+onOff(a.Guest),
		"-o", PropServices+"="+mustJSON(*a.Services),
		ds)
	if _, err := m.zfs(ctx, args...); err != nil {
		return nil, fmt.Errorf("creating the shared folder: %w", err)
	}
	sh, err := m.reread(ctx, ds)
	if err != nil {
		return nil, err
	}
	if len(a.Subfolders) > 0 {
		if !sh.Mounted {
			return sh, fmt.Errorf("%s was created but isn't mounted, so its subfolders weren't made", sh.Name)
		}
		for _, sub := range a.Subfolders {
			if err := os.Mkdir(m.sys(filepath.Join(sh.Path, sub)), 0o755); err != nil && !os.IsExist(err) {
				return sh, fmt.Errorf("making the subfolder %s: %w", sub, err)
			}
		}
	}
	m.log().Info("shared folder created", "id", sh.ID, "dataset", ds)
	return sh, nil
}

// Starter shared folders.
var starterMedia = NewShare{
	ID: "media", Name: "Media", Description: "Movies, TV shows, music and photos",
	Recycle: true, Access: []Rule{{Kind: KindEveryone, Level: LevelRead}},
	Subfolders: []string{"Movies", "TV", "Music", "Photos"},
}

var starterBackups = NewShare{
	ID: "backups", Name: "Backups", Description: "Backups of the family's computers and phones",
}

// CreateStarter makes the starter shared folders that don't exist yet.
func (m *Manager) CreateStarter(ctx context.Context, a StarterArgs) ([]Share, error) {
	if !a.Media && !a.Backups {
		return nil, invalid("choose at least one of the starter folders")
	}
	if err := zfs.ValidPoolName(a.Pool); err != nil {
		return nil, invalid("%v", err)
	}
	var want []NewShare
	if a.Media {
		want = append(want, starterMedia)
	}
	if a.Backups {
		want = append(want, starterBackups)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	existing, err := m.List(ctx)
	if err != nil {
		return nil, err
	}
	made := []Share{}
	var skipped []string
	for _, w := range want {
		w.Pool = a.Pool
		if nameTaken(existing, w.Name, "") != nil || hasID(existing, w.ID) {
			skipped = append(skipped, w.Name)
			continue
		}
		w, err := CheckNew(w)
		if err != nil {
			return made, err
		}
		sh, err := m.create(ctx, w, existing)
		if err != nil {
			return made, err
		}
		made = append(made, *sh)
		existing = append(existing, *sh)
	}
	if len(made) == 0 {
		return nil, invalid("%s already exist%s", strings.Join(skipped, " and "), map[bool]string{true: "s", false: ""}[len(skipped) == 1])
	}
	return made, nil
}

func hasID(l []Share, id string) bool {
	for _, sh := range l {
		if sh.ID == id {
			return true
		}
	}
	return false
}

// ---- changing --------------------------------------------------------------

// Update changes a shared folder's settings.
func (m *Manager) Update(ctx context.Context, a ShareUpdate) (*Share, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sh, err := m.Get(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	var set []string
	inheritDesc := false
	if a.Name != nil {
		n, err := CleanName(*a.Name)
		if err != nil {
			return nil, err
		}
		if n != sh.Name {
			l, err := m.List(ctx)
			if err != nil {
				return nil, err
			}
			if other := nameTaken(l, n, sh.ID); other != nil {
				return nil, invalid("there's already a shared folder called %s (on %s)", other.Name, other.Pool)
			}
			set = append(set, PropName+"="+n)
		}
	}
	if a.Description != nil {
		d, err := cleanDescription(*a.Description)
		if err != nil {
			return nil, err
		}
		if d != sh.Description {
			if d == "" {
				inheritDesc = true
			} else {
				set = append(set, PropDescription+"="+d)
			}
		}
	}
	if a.QuotaBytes != nil {
		q := *a.QuotaBytes
		switch {
		case q == 0:
			set = append(set, "quota=none")
		case q < minQuota:
			return nil, invalid("the quota is too small: at least 1 MB, or 0 for none")
		case q < sh.UsedBytes:
			return nil, invalid("%s already holds %s, so its quota can't be smaller than that", sh.Name, humanBytes(sh.UsedBytes))
		default:
			set = append(set, "quota="+strconv.FormatUint(q, 10))
		}
	}
	if a.Recycle != nil {
		set = append(set, PropRecycle+"="+onOff(*a.Recycle))
	}
	if a.Guest != nil {
		set = append(set, PropGuest+"="+onOff(*a.Guest))
	}
	if a.Access != nil {
		rules, err := CleanRules(*a.Access)
		if err != nil {
			return nil, err
		}
		if err := checkPropSize(rules); err != nil {
			return nil, err
		}
		set = append(set, PropAccess+"="+mustJSON(rules))
	}
	if a.Services != nil {
		sv, err := CheckServices(*a.Services)
		if err != nil {
			return nil, err
		}
		if len(mustJSON(sv)) > maxPropLen {
			return nil, invalid("the sharing settings are too long")
		}
		set = append(set, PropServices+"="+mustJSON(sv))
	}
	if len(set) > 0 {
		if _, err := m.zfs(ctx, append(append([]string{"set"}, set...), sh.Dataset)...); err != nil {
			return nil, fmt.Errorf("changing %s: %w", sh.Name, err)
		}
	}
	if inheritDesc {
		if _, err := m.zfs(ctx, "inherit", PropDescription, sh.Dataset); err != nil {
			return nil, fmt.Errorf("changing %s: %w", sh.Name, err)
		}
	}
	return m.reread(ctx, sh.Dataset)
}

// Delete destroys a shared folder and its files. Confirm is its name.
func (m *Manager) Delete(ctx context.Context, id, confirm string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sh, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if !strings.EqualFold(strings.Join(strings.Fields(confirm), " "), sh.Name) {
		return invalid("type the shared folder's name (%s) to confirm: every file in it is deleted", sh.Name)
	}
	if len(sh.Apps) > 0 {
		names := make([]string, 0, len(sh.Apps))
		for _, g := range sh.Apps {
			names = append(names, g.App)
		}
		verb := "use"
		if len(names) == 1 {
			verb = "uses"
		}
		return invalid("%s %s %s; take the shared folder away from %s first", joinAnd(names), verb, sh.Name, map[bool]string{true: "it", false: "them"}[len(names) == 1])
	}
	if sh.Dataset != Dataset(sh.Pool, sh.ID) || zfs.ValidDatasetName(sh.Dataset) != nil {
		return fmt.Errorf("refusing to destroy %q: not a shared folder dataset", sh.Dataset)
	}
	m.stopBackground(sh.ID)
	if _, err := m.zfs(ctx, "destroy", "-r", sh.Dataset); err != nil {
		return fmt.Errorf("deleting %s: %w", sh.Name, err)
	}
	m.log().Info("shared folder deleted", "id", sh.ID, "dataset", sh.Dataset)
	return nil
}

func joinAnd(l []string) string {
	switch len(l) {
	case 0:
		return ""
	case 1:
		return l[0]
	}
	return strings.Join(l[:len(l)-1], ", ") + " and " + l[len(l)-1]
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d bytes", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTP"[exp])
}

// ---- folders and paths -----------------------------------------------------

// Folders lists the subfolders of a share's folder sub (for pickers).
// Hidden folders (starting with a dot) and links aren't listed.
func (m *Manager) Folders(ctx context.Context, id, sub string) ([]string, error) {
	p, err := m.Resolve(ctx, id, sub)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(m.sys(p))
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, e.Name())
		}
		if len(out) >= 2000 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out, nil
}

// Resolve returns the real host path of a share or a subfolder in it.
// Links are followed only while they stay inside the share; the folder
// must exist.
func (m *Manager) Resolve(ctx context.Context, id, sub string) (string, error) {
	clean, err := CleanFolder(sub)
	if err != nil {
		return "", err
	}
	sh, err := m.Get(ctx, id)
	if err != nil {
		return "", err
	}
	if !sh.Mounted {
		return "", fmt.Errorf("the shared folder %s isn't available right now (is its pool imported and unlocked?)", sh.Name)
	}
	base, err := filepath.EvalSymlinks(m.sys(sh.Path))
	if err != nil {
		return "", fmt.Errorf("the shared folder %s: %w", sh.Name, err)
	}
	real := base
	if clean != "" {
		real, err = filepath.EvalSymlinks(filepath.Join(m.sys(sh.Path), filepath.FromSlash(clean)))
		if os.IsNotExist(err) {
			return "", invalid("there's no folder %s in %s", clean, sh.Name)
		}
		if err != nil {
			return "", invalid("the folder %s in %s can't be used: %v", clean, sh.Name, err)
		}
	}
	if real != base && !strings.HasPrefix(real, base+string(filepath.Separator)) {
		return "", invalid("the folder %s leads outside the shared folder %s", clean, sh.Name)
	}
	fi, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", invalid("%s in %s is a file, not a folder", clean, sh.Name)
	}
	return m.hostPath(real)
}

// hostPath turns a path under Root into the path on the host.
func (m *Manager) hostPath(p string) (string, error) {
	if m.root() == "/" {
		return p, nil
	}
	r, err := filepath.EvalSymlinks(m.root())
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(r, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("%s is outside %s", p, r)
	}
	return "/" + filepath.ToSlash(rel), nil
}

// ---- apps ------------------------------------------------------------------

func aclPerm(write bool) string {
	if write {
		return "rwX"
	}
	return "r-X"
}

// GrantApp gives an app's user read or write access to a share: an access
// and default ACL entry on the share's folder now, and on everything in it
// in the background.
func (m *Manager) GrantApp(ctx context.Context, id, app string, uid int, write bool) error {
	if err := ValidAppGrant(app, uid); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sh, err := m.Get(ctx, id)
	if err != nil {
		return err
	}
	if !sh.Mounted {
		return fmt.Errorf("the shared folder %s isn't available right now (is its pool imported and unlocked?)", sh.Name)
	}
	level := LevelRead
	if write {
		level = LevelWrite
	}
	path := m.sys(sh.Path)
	grants := []AppGrant{}
	for _, g := range sh.Apps {
		if g.App != app && g.UID == uid {
			// A record left by an app removed while this share was
			// unmounted: the user ID now belongs to app.
			continue
		}
		if g.App != app {
			grants = append(grants, g)
			continue
		}
		if g.UID != uid && !uidUsed(sh.Apps, g.UID, app) {
			// The app got a new user ID: take the old one's access away.
			if err := m.setfacl(ctx, "-x", fmt.Sprintf("u:%d,d:u:%d", g.UID, g.UID), path); err != nil {
				return err
			}
			m.background(sh.ID, path, g.UID, false, true)
		}
	}
	grants = append(grants, AppGrant{App: app, UID: uid, Level: level})
	sort.Slice(grants, func(i, j int) bool { return grants[i].App < grants[j].App })
	perm := aclPerm(write)
	if err := m.setfacl(ctx, "-m", fmt.Sprintf("u:%d:%s,d:u:%d:%s", uid, perm, uid, perm), path); err != nil {
		return err
	}
	if _, err := m.zfs(ctx, "set", PropApps+"="+mustJSON(grants), sh.Dataset); err != nil {
		return fmt.Errorf("recording %s's access to %s: %w", app, sh.Name, err)
	}
	m.background(sh.ID, path, uid, write, false)
	m.log().Info("app given a shared folder", "app", app, "share", sh.ID, "uid", uid, "level", level)
	return nil
}

// RevokeApp removes an app's access from every share.
func (m *Manager) RevokeApp(ctx context.Context, app string) error {
	if !appIDRE.MatchString(app) {
		return invalid("the app id %q isn't valid", app)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	l, err := m.List(ctx)
	if err != nil {
		return err
	}
	for _, sh := range l {
		if !sh.Mounted {
			// Keep the record: the ACL entries are still on disk and are
			// removed when that user ID is next given to an app (GrantApp).
			for _, g := range sh.Apps {
				if g.App == app {
					m.log().Warn("shared folder isn't mounted; its access for a removed app stays until the user ID is reused",
						"app", app, "share", sh.ID, "uid", g.UID)
				}
			}
			continue
		}
		keep := []AppGrant{}
		var gone []AppGrant
		for _, g := range sh.Apps {
			if g.App == app {
				gone = append(gone, g)
			} else {
				keep = append(keep, g)
			}
		}
		if len(gone) == 0 {
			continue
		}
		path := m.sys(sh.Path)
		for _, g := range gone {
			if uidUsed(keep, g.UID, "") {
				continue
			}
			if err := m.setfacl(ctx, "-x", fmt.Sprintf("u:%d,d:u:%d", g.UID, g.UID), path); err != nil {
				return err
			}
			m.background(sh.ID, path, g.UID, false, true)
		}
		if _, err := m.zfs(ctx, "set", PropApps+"="+mustJSON(keep), sh.Dataset); err != nil {
			return fmt.Errorf("removing %s from %s: %w", app, sh.Name, err)
		}
		m.log().Info("app's shared folder taken away", "app", app, "share", sh.ID)
	}
	return nil
}

// uidUsed reports whether another app (not except) has uid on the share.
func uidUsed(grants []AppGrant, uid int, except string) bool {
	for _, g := range grants {
		if g.UID == uid && g.App != except {
			return true
		}
	}
	return false
}

func (m *Manager) setfacl(ctx context.Context, op, spec, path string) error {
	if _, err := sysexec.Output(ctx, m.Runner, "setfacl", op, spec, "--", path); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", path, err)
	}
	return nil
}

// background applies (or removes) uid's ACL entries below root without
// blocking the caller. A newer walk for the same share and uid replaces a
// running one.
func (m *Manager) background(share, root string, uid int, write, revoke bool) {
	key := share + "\x00" + strconv.Itoa(uid)
	ctx, cancel := context.WithTimeout(context.Background(), bgTimeout)
	job := &bgJob{cancel: cancel, done: make(chan struct{})}
	m.bgMu.Lock()
	if m.bg == nil {
		m.bg = map[string]*bgJob{}
	}
	prev := m.bg[key]
	m.bg[key] = job
	m.bgMu.Unlock()
	tree := m.tree
	if tree == nil {
		tree = applyTree
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer close(job.done)
		defer cancel()
		if prev != nil {
			prev.cancel()
			<-prev.done
		}
		start := time.Now()
		st, err := tree(ctx, root, uid, write, revoke)
		m.bgMu.Lock()
		if m.bg[key] == job {
			delete(m.bg, key)
		}
		m.bgMu.Unlock()
		log := m.log().With("share", share, "uid", uid, "revoke", revoke, "changed", st.Changed,
			"seen", st.Seen, "skipped", st.Skipped, "took", time.Since(start).Round(time.Millisecond))
		switch {
		case err != nil && ctx.Err() != nil:
			log.Info("shared folder permissions: stopped before the end", "err", err)
		case err != nil:
			log.Error("shared folder permissions failed", "err", err)
		case st.Failed > 0:
			log.Warn("shared folder permissions: some files couldn't be changed", "failed", st.Failed, "first", st.First)
		default:
			log.Info("shared folder permissions applied")
		}
	}()
}

// stopBackground cancels the share's background walks and waits for them.
func (m *Manager) stopBackground(share string) {
	m.bgMu.Lock()
	var jobs []*bgJob
	for k, j := range m.bg {
		if strings.HasPrefix(k, share+"\x00") {
			jobs = append(jobs, j)
		}
	}
	m.bgMu.Unlock()
	for _, j := range jobs {
		j.cancel()
		<-j.done
	}
}

// Wait waits for background permission changes to finish (tests, shutdown).
func (m *Manager) Wait() { m.wg.Wait() }
