package fileworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Who is the person an operation is for, as hardyd says (hardyd checked
// their session; groups come from the domain at sign-in).
type Who struct {
	// Principal: "HOME\\alice" for domain accounts, the account name for
	// local ones.
	Principal string `json:"principal"`
	Local     bool   `json:"local"`
	Admin     bool   `json:"admin"`
	// Groups: the domain groups ("HOME\\Family"), for the folder's rules.
	Groups []string `json:"groups,omitempty"`
}

// Args are the files.* operations' arguments.
type Args struct {
	Who      Who    `json:"who"`
	Share    string `json:"share,omitempty"`
	Path     string `json:"path,omitempty"`
	Snapshot string `json:"snapshot,omitempty"`
	// ToShare and To: rename's destination.
	ToShare string `json:"toShare,omitempty"`
	To      string `json:"to,omitempty"`
	// Overwrite: create truncates an existing file; rename replaces a file.
	Overwrite bool `json:"overwrite,omitempty"`
	// Permanent: delete skips the recycle bin.
	Permanent bool      `json:"permanent,omitempty"`
	Modified  time.Time `json:"modified,omitempty"`
}

// ShareAccess is a folder the person can open (OpShares' result).
type ShareAccess struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Recycle  bool   `json:"recycle"`
	Writable bool   `json:"writable"`
}

// Identity is the Linux identity a worker runs as.
type Identity struct {
	UID    int   `json:"uid"`
	GID    int   `json:"gid"`
	Groups []int `json:"groups"`
	// Bin is the person's folder in a shared folder's .recycle.
	Bin string `json:"-"`
}

// Domain users' and groups' Linux IDs (contract section 1: winbind's idmap
// ranges). Nothing else may be acted as, root least of all.
var domainIDRanges = [][2]int{{3000, 7999}, {100000, 999999}}

func domainID(id int) bool {
	for _, r := range domainIDRanges {
		if id >= r[0] && id <= r[1] {
			return true
		}
	}
	return false
}

// NETBIOS\name, as the domain sign-in writes principals.
var domainPrincipalRE = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9-]{0,14})\\([\p{L}\p{N}][\p{L}\p{N} ._'$-]{0,63})$`)

// NSSHelper is the fixed helper that asks the system's name service
// (winbind) for a user's IDs: hardyd-priv is built without cgo, and Go's
// own user lookup then only reads /etc/passwd and /etc/group.
const NSSHelper = "/usr/lib/hardyos/hardyos-nss"

// Server runs the files.* operations inside hardyd-priv.
type Server struct {
	// Shares lists the shared folders (shares.Manager).
	Shares interface {
		List(ctx context.Context) ([]shares.Share, error)
	}
	// Runner runs zfs to find home folders; nil means no home folders.
	Runner sysexec.Runner
	// HomesPool is the pool File Services keeps home folders on ("" = home
	// folders are off); only <pool>/homes/<netbios>.<user> whose
	// org.hardyos:home names the person is their home. nil = none.
	HomesPool func() string
	// Mounts says where datasets are really mounted (home folders are
	// checked like shared folders); nil reads /proc/self/mountinfo.
	Mounts func() (shares.MountVerifier, error)
	// MaxWorkers bounds the workers running at once (default 32), and
	// MaxWorkersPerPerson those for one person (default 8); more wait
	// their turn until their request is cancelled.
	MaxWorkers, MaxWorkersPerPerson int
	// Exe and Args start a worker: hardyd-priv itself and Subcommand.
	Exe  string
	Args []string
	// LookupUser resolves a domain user's IDs; nil uses NSSHelper.
	LookupUser func(ctx context.Context, name string) (*Identity, error)
	// FilesUser keeps hardyos-files' access to the shared folders up to
	// date (shares.Manager.EnsureFilesUser); called before an
	// administrator's folders are listed. Optional.
	FilesUser func(ctx context.Context)
	// AcceptID says which user and group IDs a domain account may have;
	// nil means winbind's ranges (3000-7999, 100000-999999). Tests widen it
	// to their own ID. Root (0) is refused whatever it says.
	AcceptID func(id int) bool
	Log      *slog.Logger

	mu       sync.Mutex
	cachedAt time.Time
	cache    []shares.Share
	homes    map[string]homeEntry // by home key ("home.alice")
	ids      map[string]idEntry

	limOnce sync.Once
	slots   chan struct{}
	limMu   sync.Mutex
	per     map[string]*personSlots
}

type homeEntry struct {
	root *root
	err  error
	at   time.Time
}

type personSlots struct {
	ch   chan struct{}
	refs int
}

type idEntry struct {
	id  *Identity
	at  time.Time
	err error
}

// NewServer returns a server that runs workers as hardyd-priv's own binary.
func NewServer(sh interface {
	List(ctx context.Context) ([]shares.Share, error)
}, runner sysexec.Runner, log *slog.Logger) (*Server, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &Server{Shares: sh, Runner: runner, Exe: exe, Args: []string{Subcommand}, Log: log}, nil
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// ---- who -------------------------------------------------------------------

// identity is the Linux identity to act as for who.
func (s *Server) identity(ctx context.Context, who Who) (*Identity, error) {
	if who.Local {
		if !who.Admin {
			return nil, errorf(CodeNoAccess, "only administrators and domain accounts can use files")
		}
		return &Identity{UID: FilesUID, GID: FilesUID, Bin: shares.FilesBin}, nil
	}
	m := domainPrincipalRE.FindStringSubmatch(who.Principal)
	if m == nil {
		return nil, errorf(CodeBadArgs, "%q isn't a domain account", who.Principal)
	}
	// The bin is named so that it can only be this account's (and never
	// the administrators' hardyos-files).
	bin := shares.BinName(m[1], m[2])
	if bin == "" || bin == shares.FilesBin {
		return nil, errorf(CodeBadArgs, "%q can't use files", who.Principal)
	}
	id, err := s.lookup(ctx, who.Principal)
	if err != nil {
		return nil, err
	}
	accept := s.AcceptID
	if accept == nil {
		accept = domainID
	}
	if id.UID == 0 || id.GID == 0 || !accept(id.UID) || !accept(id.GID) {
		return nil, errorf(CodeNoAccess, "%s's Linux user ID (%d:%d) isn't a domain one; refusing to act as it", who.Principal, id.UID, id.GID)
	}
	out := &Identity{UID: id.UID, GID: id.GID, Bin: bin}
	for _, g := range id.Groups {
		if g != 0 && accept(g) && len(out.Groups) < 1024 {
			out.Groups = append(out.Groups, g)
		}
	}
	return out, nil
}

func (s *Server) lookup(ctx context.Context, name string) (*Identity, error) {
	key := strings.ToLower(name)
	s.mu.Lock()
	if e, ok := s.ids[key]; ok && time.Since(e.at) < time.Minute {
		s.mu.Unlock()
		return e.id, e.err
	}
	s.mu.Unlock()
	fn := s.LookupUser
	if fn == nil {
		fn = HelperLookup
	}
	id, err := fn(ctx, name)
	if err != nil && !isCoded(err) {
		err = errorf(CodeFailed, "looking up %s: %v", name, err)
	}
	s.mu.Lock()
	if s.ids == nil {
		s.ids = map[string]idEntry{}
	}
	s.ids[key] = idEntry{id: id, err: err, at: time.Now()}
	s.mu.Unlock()
	return id, err
}

func isCoded(err error) bool {
	var e *Error
	return errors.As(err, &e)
}

// HelperLookup asks NSSHelper for a user's IDs.
func HelperLookup(ctx context.Context, name string) (*Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, NSSHelper, "user", name)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 2 {
			return nil, errorf(CodeNoAccess, "%s isn't known to this server's file sharing yet (has it joined the domain?)", name)
		}
		return nil, fmt.Errorf("%s: %w", NSSHelper, err)
	}
	var id Identity
	if err := json.Unmarshal(out, &id); err != nil {
		return nil, fmt.Errorf("%s: %w", NSSHelper, err)
	}
	return &id, nil
}

// Level is how far a folder's access rules let who in: write, read or
// none. Administrators may use every folder (the disk's permissions still
// apply to domain administrators); a "none" rule beats any other; otherwise
// the highest matching level counts; no matching rule means no access.
func Level(rules []shares.Rule, who Who) string {
	if who.Admin {
		return shares.LevelWrite
	}
	if who.Local {
		return shares.LevelNone
	}
	level := shares.LevelNone
	for _, r := range rules {
		match := false
		switch r.Kind {
		case shares.KindEveryone:
			match = true
		case shares.KindUser:
			match = strings.EqualFold(strings.TrimSpace(r.Name), who.Principal)
		case shares.KindGroup:
			for _, g := range who.Groups {
				if strings.EqualFold(strings.TrimSpace(r.Name), g) {
					match = true
				}
			}
		}
		if !match {
			continue
		}
		switch r.Level {
		case shares.LevelNone:
			return shares.LevelNone
		case shares.LevelWrite:
			level = shares.LevelWrite
		case shares.LevelRead:
			if level == shares.LevelNone {
				level = shares.LevelRead
			}
		}
	}
	return level
}

// ---- where -------------------------------------------------------------------

func (s *Server) refresh(ctx context.Context) ([]shares.Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache != nil && time.Since(s.cachedAt) < 3*time.Second {
		return s.cache, nil
	}
	l, err := s.Shares.List(ctx)
	if err != nil {
		return nil, err
	}
	s.cache, s.cachedAt = l, time.Now()
	return l, nil
}

// root is a folder a worker is given.
type root struct {
	id, name string
	path     string
	// dev is the device of the folder's verified mount (shares.OpenRoot).
	dev     uint64
	recycle bool
	level   string
}

// homeKey is a domain user's home dataset name: <netbios>.<user>, lowercase.
func homeKey(principal string) string {
	m := domainPrincipalRE.FindStringSubmatch(principal)
	if m == nil {
		return ""
	}
	return strings.ToLower(m[1] + "." + m[2])
}

// homeProps are what a home dataset is read for.
var homeProps = []string{"org.hardyos:home", "mountpoint", "mounted"}

// home finds the person's home folder: on the pool File Services keeps
// home folders on and nowhere else, the dataset <pool>/homes/<key> whose
// org.hardyos:home (set when hardyd-priv made it) names this very account,
// mounted (verified in the mount table) where it says.
func (s *Server) home(ctx context.Context, principal string) (*root, error) {
	key := homeKey(principal)
	pool := ""
	if s.HomesPool != nil {
		pool = s.HomesPool()
	}
	if key == "" || pool == "" || s.Runner == nil || zfs.ValidPoolName(pool) != nil {
		return nil, errorf(CodeNotFound, "you don't have a home folder on this server yet")
	}
	ds := pool + "/homes/" + key
	if zfs.ValidDatasetName(ds) != nil {
		return nil, errorf(CodeNotFound, "you don't have a home folder on this server yet")
	}
	s.mu.Lock()
	if e, ok := s.homes[ds]; ok && time.Since(e.at) < 3*time.Second {
		s.mu.Unlock()
		return e.root, e.err
	}
	s.mu.Unlock()
	r, err := s.lookupHome(ctx, principal, ds)
	s.mu.Lock()
	if s.homes == nil || len(s.homes) > 4096 {
		s.homes = map[string]homeEntry{}
	}
	s.homes[ds] = homeEntry{root: r, err: err, at: time.Now()}
	s.mu.Unlock()
	return r, err
}

func (s *Server) lookupHome(ctx context.Context, principal, ds string) (*root, error) {
	none := errorf(CodeNotFound, "you don't have a home folder on this server yet")
	res, err := s.Runner.Run(ctx, nil, "zfs", "get", "-Hp", "-o", "property,value", strings.Join(homeProps, ","), ds)
	if err != nil || res.ExitCode != 0 {
		return nil, none
	}
	v, err := shares.ParseGetOutput(res.Stdout, homeProps)
	if err != nil {
		s.log().Warn("home folder's properties can't be read safely", "dataset", ds, "err", err)
		return nil, none
	}
	owner, mp, mounted := v[0], v[1], v[2]
	if !strings.EqualFold(owner, principal) {
		s.log().Warn("home folder belongs to another account; not used", "dataset", ds, "home", owner, "principal", principal)
		return nil, none
	}
	if mounted != "yes" || !filepath.IsAbs(mp) || filepath.Clean(mp) != mp {
		return nil, errorf(CodeNotFound, "your home folder isn't available right now")
	}
	mv, err := s.mounts()
	if err != nil {
		return nil, errorf(CodeFailed, "reading the mount table: %v", err)
	}
	dev, err := mv.VerifyMount(mp, ds)
	if err != nil {
		s.log().Warn("home folder isn't mounted where its settings say; not used", "dataset", ds, "err", err)
		return nil, errorf(CodeNotFound, "your home folder isn't available right now")
	}
	return &root{id: HomeShare, name: "Home", path: mp, dev: dev, level: shares.LevelWrite}, nil
}

func (s *Server) mounts() (shares.MountVerifier, error) {
	if s.Mounts != nil {
		return s.Mounts()
	}
	t, err := shares.ReadMountTable()
	return t, err
}

func shareRoot(sh *shares.Share, level string) *root {
	return &root{id: sh.ID, name: sh.Name, path: sh.Path, dev: sh.RootDev, recycle: sh.Recycle, level: level}
}

func (s *Server) findRoot(ctx context.Context, who Who, id string) (*root, error) {
	if id == HomeShare {
		if who.Local {
			return nil, errorf(CodeNotFound, "local accounts don't have a home folder")
		}
		return s.home(ctx, who.Principal)
	}
	l, err := s.refresh(ctx)
	if err != nil {
		return nil, err
	}
	for i := range l {
		sh := &l[i]
		if sh.ID != id {
			continue
		}
		if !sh.Usable() {
			return nil, errorf(CodeNotFound, "the shared folder %s isn't available right now", sh.Name)
		}
		lv := Level(sh.Access, who)
		if lv == shares.LevelNone {
			return nil, errorf(CodeNoAccess, "you don't have access to %s", sh.Name)
		}
		return shareRoot(sh, lv), nil
	}
	return nil, errorf(CodeNotFound, "there's no shared folder %q", id)
}

// writeOps change something.
var writeOps = map[string]bool{OpCreate: true, OpOpenWrite: true, OpMkdir: true, OpRename: true, OpDelete: true, OpSetTime: true}

// Ops lists the operations Do accepts (besides OpShares).
var Ops = []string{OpList, OpStat, OpOpen, OpCreate, OpOpenWrite, OpMkdir, OpRename, OpDelete, OpSetTime, OpVersions}

// ---- how many at once --------------------------------------------------------

// acquire waits for a worker slot: one of MaxWorkers overall and of
// MaxWorkersPerPerson for this person (so one person's many requests can't
// starve everyone else, and many requests can't fork the server to death).
func (s *Server) acquire(ctx context.Context, person string) (func(), error) {
	s.limOnce.Do(func() {
		n := s.MaxWorkers
		if n <= 0 {
			n = 32
		}
		s.slots = make(chan struct{}, n)
	})
	per := s.MaxWorkersPerPerson
	if per <= 0 {
		per = 8
	}
	key := strings.ToLower(person)
	s.limMu.Lock()
	if s.per == nil {
		s.per = map[string]*personSlots{}
	}
	p := s.per[key]
	if p == nil {
		p = &personSlots{ch: make(chan struct{}, per)}
		s.per[key] = p
	}
	p.refs++
	s.limMu.Unlock()
	unref := func() {
		s.limMu.Lock()
		if p.refs--; p.refs == 0 {
			delete(s.per, key)
		}
		s.limMu.Unlock()
	}
	busy := func() error {
		if ctx.Err() == context.DeadlineExceeded {
			return errorf(CodeFailed, "the server is busy with other file operations; try again in a moment")
		}
		return errorf(CodeFailed, "the file operation was cancelled")
	}
	select {
	case p.ch <- struct{}{}:
	case <-ctx.Done():
		unref()
		return nil, busy()
	}
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		<-p.ch
		unref()
		return nil, busy()
	}
	return func() {
		<-s.slots
		<-p.ch
		unref()
	}, nil
}

// run starts one worker when there's a slot for it.
func (s *Server) run(ctx context.Context, who Who, ident *Identity, roots []*root, req Request) (json.RawMessage, *os.File, error) {
	release, err := s.acquire(ctx, who.Principal)
	if err != nil {
		return nil, nil, err
	}
	defer release()
	return s.spawn(ctx, ident, roots, req)
}

// ---- operations ----------------------------------------------------------------

// Do runs one operation for a.Who. file is set for open, create and
// openwrite; the caller owns it. Every operation is logged with who asked
// (as hardyd says) and the Linux identity it ran as.
func (s *Server) Do(ctx context.Context, op string, a Args) (data json.RawMessage, file *os.File, err error) {
	log := s.log().With("op", op, "principal", a.Who.Principal, "local", a.Who.Local, "admin", a.Who.Admin)
	ident, err := s.identity(ctx, a.Who)
	if err != nil {
		log.Warn("file operation refused", "err", err)
		return nil, nil, err
	}
	log = log.With("uid", ident.UID, "gid", ident.GID, "share", a.Share, "path", a.Path)
	if op == OpRename {
		log = log.With("toShare", a.ToShare, "to", a.To)
	}
	start := time.Now()
	defer func() {
		attrs := []any{"ok", err == nil, "took", time.Since(start).Round(time.Millisecond)}
		var fe *Error
		if errors.As(err, &fe) {
			attrs = append(attrs, "code", fe.Code)
		} else if err != nil {
			attrs = append(attrs, "err", err)
		}
		log.Info("file operation", attrs...)
	}()
	if op == OpShares {
		return s.shares(ctx, a.Who, ident)
	}
	known := false
	for _, o := range Ops {
		known = known || o == op
	}
	if !known {
		return nil, nil, errorf(CodeBadArgs, "unknown file operation %q", op)
	}
	if a.Snapshot != "" && !SnapshotRE.MatchString(a.Snapshot) {
		return nil, nil, errorf(CodeBadArgs, "there's no such older version")
	}
	r, err := s.findRoot(ctx, a.Who, a.Share)
	if err != nil {
		return nil, nil, err
	}
	// The recycle bin is used when the folder has one and the delete isn't
	// permanent; an upload's temporary name may only be deleted for good.
	recycle := op == OpDelete && r.recycle && !a.Permanent
	if _, err := OpPath(op, a.Path, op == OpDelete && !recycle); err != nil {
		return nil, nil, err
	}
	roots := []*root{r}
	toRoot := 0
	if op == OpRename {
		if _, err := RenameTarget(a.To); err != nil {
			return nil, nil, err
		}
		if a.ToShare != "" && a.ToShare != a.Share {
			tr, err := s.findRoot(ctx, a.Who, a.ToShare)
			if err != nil {
				return nil, nil, err
			}
			roots, toRoot = append(roots, tr), 1
		}
	}
	for _, rt := range roots {
		if writeOps[op] && rt.level != shares.LevelWrite {
			return nil, nil, errorf(CodeNoAccess, "you can only read %s", rt.name)
		}
	}
	req := Request{
		Op: op, Path: a.Path, Snapshot: a.Snapshot, ToRoot: toRoot, To: a.To,
		Overwrite: a.Overwrite, Modified: a.Modified, ReadOnly: r.level != shares.LevelWrite,
	}
	if recycle {
		req.Recycle, req.Bin = true, ident.Bin
	}
	return s.run(ctx, a.Who, ident, roots, req)
}

// shares lists the folders who can open: the access rules let them in and
// the disk's permissions let their Linux identity read the top.
func (s *Server) shares(ctx context.Context, who Who, ident *Identity) (json.RawMessage, *os.File, error) {
	if who.Local && s.FilesUser != nil {
		s.FilesUser(ctx)
	}
	l, err := s.refresh(ctx)
	if err != nil {
		return nil, nil, err
	}
	var cands []*root
	if !who.Local {
		if h, err := s.home(ctx, who.Principal); err == nil {
			cands = append(cands, h)
		}
	}
	for i := range l {
		sh := &l[i]
		if !sh.Usable() {
			continue
		}
		if lv := Level(sh.Access, who); lv != shares.LevelNone {
			cands = append(cands, shareRoot(sh, lv))
		}
	}
	// One folder that isn't its verified mount any more mustn't hide the
	// others: leave it out (spawn opens the rest again the same way).
	ok := cands[:0]
	for _, c := range cands {
		if canOpenRoot(c) {
			ok = append(ok, c)
		} else {
			s.log().Warn("file worker: folder refused", "folder", c.id, "path", c.path)
		}
	}
	cands = ok
	out := []ShareAccess{}
	if len(cands) == 0 {
		b, _ := json.Marshal(out)
		return b, nil, nil
	}
	raw, _, err := s.run(ctx, who, ident, cands, Request{Op: OpShares})
	if err != nil {
		return nil, nil, err
	}
	var acc []RootAccess
	if err := json.Unmarshal(raw, &acc); err != nil || len(acc) != len(cands) {
		return nil, nil, errorf(CodeFailed, "file worker: bad answer")
	}
	for i, c := range cands {
		if !acc[i].Read {
			continue
		}
		out = append(out, ShareAccess{ID: c.id, Name: c.name, Recycle: c.recycle, Writable: acc[i].Write && c.level == shares.LevelWrite})
	}
	b, _ := json.Marshal(out)
	return b, nil, nil
}

// Root is a folder outside the shared folders that hardyd-priv vouches
// for itself (a copy staged from a cloud backup in a dataset only root can
// reach): its path and the device of its verified mount.
type Root struct {
	Name string
	Path string
	Dev  uint64
}

// readOps are what DoIn runs.
var readOps = map[string]bool{OpList: true, OpStat: true, OpOpen: true}

// DoIn runs a read-only operation (list, stat, open) as who, beneath in,
// the same way Do does in a shared folder: the worker is the person, so
// the permissions on disk (as they were in the backup) decide. The caller
// has already checked the folder's access rules.
func (s *Server) DoIn(ctx context.Context, op string, who Who, in Root, a Args) (data json.RawMessage, file *os.File, err error) {
	log := s.log().With("op", op, "principal", who.Principal, "local", who.Local, "admin", who.Admin, "in", in.Path, "path", a.Path)
	if !readOps[op] {
		return nil, nil, errorf(CodeBadArgs, "only reading is possible there")
	}
	ident, err := s.identity(ctx, who)
	if err != nil {
		log.Warn("file operation refused", "err", err)
		return nil, nil, err
	}
	defer func() { log.Info("file operation (staged)", "uid", ident.UID, "ok", err == nil) }()
	if _, err := OpPath(op, a.Path, false); err != nil {
		return nil, nil, err
	}
	r := &root{id: "staged", name: in.Name, path: in.Path, dev: in.Dev, level: shares.LevelRead}
	return s.run(ctx, who, ident, []*root{r}, Request{Op: op, Path: a.Path, ReadOnly: true})
}

// IdentityOf is the Linux identity who's files are read and written as
// (for callers outside this package that check permissions themselves).
func (s *Server) IdentityOf(ctx context.Context, who Who) (*Identity, error) {
	return s.identity(ctx, who)
}

// RulesLevel is the access the folder's rules give who (Level), for
// callers outside this package; "none" when the folder doesn't exist.
func (s *Server) RulesLevel(ctx context.Context, who Who, share string) (string, error) {
	r, err := s.findRoot(ctx, who, share)
	if err != nil {
		return shares.LevelNone, err
	}
	return r.level, nil
}
