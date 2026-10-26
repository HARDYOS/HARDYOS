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
	homes    map[string]string // "home.alice" -> mountpoint
	ids      map[string]idEntry
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
		return &Identity{UID: FilesUID, GID: FilesUID, Bin: FilesUserName}, nil
	}
	m := domainPrincipalRE.FindStringSubmatch(who.Principal)
	if m == nil {
		return nil, errorf(CodeBadArgs, "%q isn't a domain account", who.Principal)
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
	out := &Identity{UID: id.UID, GID: id.GID, Bin: strings.ToLower(m[2])}
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

func (s *Server) refresh(ctx context.Context) ([]shares.Share, map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache != nil && time.Since(s.cachedAt) < 3*time.Second {
		return s.cache, s.homes, nil
	}
	l, err := s.Shares.List(ctx)
	if err != nil {
		return nil, nil, err
	}
	homes := map[string]string{}
	if s.Runner != nil {
		out, err := sysexec.Output(ctx, s.Runner, "zfs", "list", "-H", "-o", "name,mountpoint,mounted", "-t", "filesystem")
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				f := strings.Split(line, "\t")
				if len(f) != 3 || f[2] != "yes" || !filepath.IsAbs(f[1]) {
					continue
				}
				parts := strings.Split(f[0], "/")
				if len(parts) == 3 && parts[1] == "homes" {
					if _, dup := homes[parts[2]]; !dup {
						homes[parts[2]] = f[1]
					}
				}
			}
		} else {
			s.log().Warn("listing home folders", "err", err)
		}
	}
	s.cache, s.homes, s.cachedAt = l, homes, time.Now()
	return l, homes, nil
}

// root is a folder a worker is given.
type root struct {
	id, name string
	path     string
	recycle  bool
	level    string
}

// homeKey is a domain user's home dataset name: <netbios>.<user>, lowercase.
func homeKey(principal string) string {
	m := domainPrincipalRE.FindStringSubmatch(principal)
	if m == nil {
		return ""
	}
	return strings.ToLower(m[1] + "." + m[2])
}

func (s *Server) findRoot(ctx context.Context, who Who, id string) (*root, error) {
	l, homes, err := s.refresh(ctx)
	if err != nil {
		return nil, err
	}
	if id == HomeShare {
		if who.Local {
			return nil, errorf(CodeNotFound, "local accounts don't have a home folder")
		}
		p, ok := homes[homeKey(who.Principal)]
		if !ok {
			return nil, errorf(CodeNotFound, "you don't have a home folder on this server yet")
		}
		return &root{id: HomeShare, name: "Home", path: p, level: shares.LevelWrite}, nil
	}
	for _, sh := range l {
		if sh.ID != id {
			continue
		}
		if !sh.Mounted || sh.Path == "" {
			return nil, errorf(CodeNotFound, "the shared folder %s isn't available right now", sh.Name)
		}
		lv := Level(sh.Access, who)
		if lv == shares.LevelNone {
			return nil, errorf(CodeNoAccess, "you don't have access to %s", sh.Name)
		}
		return &root{id: sh.ID, name: sh.Name, path: sh.Path, recycle: sh.Recycle, level: lv}, nil
	}
	return nil, errorf(CodeNotFound, "there's no shared folder %q", id)
}

// writeOps change something.
var writeOps = map[string]bool{OpCreate: true, OpOpenWrite: true, OpMkdir: true, OpRename: true, OpDelete: true, OpSetTime: true}

// Ops lists the operations Do accepts (besides OpShares).
var Ops = []string{OpList, OpStat, OpOpen, OpCreate, OpOpenWrite, OpMkdir, OpRename, OpDelete, OpSetTime, OpVersions}

// Do runs one operation for a.Who. file is set for open, create and
// openwrite; the caller owns it.
func (s *Server) Do(ctx context.Context, op string, a Args) (json.RawMessage, *os.File, error) {
	ident, err := s.identity(ctx, a.Who)
	if err != nil {
		return nil, nil, err
	}
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
	if _, err := CleanPath(a.Path); err != nil {
		return nil, nil, err
	}
	r, err := s.findRoot(ctx, a.Who, a.Share)
	if err != nil {
		return nil, nil, err
	}
	roots := []*root{r}
	toRoot := 0
	if op == OpRename {
		if _, err := CleanPath(a.To); err != nil {
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
	if op == OpDelete && r.recycle && !a.Permanent {
		req.Recycle, req.Bin = true, ident.Bin
	}
	paths := make([]string, len(roots))
	for i, rt := range roots {
		paths[i] = rt.path
	}
	return s.spawn(ctx, ident, paths, req)
}

// shares lists the folders who can open: the access rules let them in and
// the disk's permissions let their Linux identity read the top.
func (s *Server) shares(ctx context.Context, who Who, ident *Identity) (json.RawMessage, *os.File, error) {
	if who.Local && s.FilesUser != nil {
		s.FilesUser(ctx)
	}
	l, homes, err := s.refresh(ctx)
	if err != nil {
		return nil, nil, err
	}
	var cands []*root
	if !who.Local {
		if p, ok := homes[homeKey(who.Principal)]; ok {
			cands = append(cands, &root{id: HomeShare, name: "Home", path: p, level: shares.LevelWrite})
		}
	}
	for _, sh := range l {
		if !sh.Mounted || sh.Path == "" {
			continue
		}
		if lv := Level(sh.Access, who); lv != shares.LevelNone {
			cands = append(cands, &root{id: sh.ID, name: sh.Name, path: sh.Path, recycle: sh.Recycle, level: lv})
		}
	}
	out := []ShareAccess{}
	if len(cands) == 0 {
		b, _ := json.Marshal(out)
		return b, nil, nil
	}
	paths := make([]string, len(cands))
	for i, c := range cands {
		paths[i] = c.path
	}
	raw, _, err := s.spawn(ctx, ident, paths, Request{Op: OpShares})
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
