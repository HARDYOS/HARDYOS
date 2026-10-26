package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Root is the root-side half (hardyd-priv): it reads and writes the files
// hardyd can't, keeps nightly backups on data pools, and applies a staged
// restore at boot before hardyd starts.
type Root struct {
	Runner sysexec.Runner
	Root   string // "/" in production
	// UID and GID own the restored database and HTTPS files (the hardyd
	// account); -1 leaves ownership alone (tests).
	UID, GID int
	Network  *network.Manager
	Now      func() time.Time
	// Domain adds the domain controller's settings and databases to
	// backups and restores them (nil: no domain support).
	Domain DomainArchiver
}

// DomainArchiver is the domain controller's part of a backup.
type DomainArchiver interface {
	BackupFiles(ctx context.Context) (config, archive []byte, err error)
	RestoreFiles(ctx context.Context, config, archive []byte) (note string, err error)
}

// Paths relative to Root.
const (
	StateDir    = "var/lib/hardyos"
	WorkDir     = "var/lib/hardyos/backups"         // hardyd's own (made backups, uploads)
	PendingDir  = "var/lib/hardyos/restore-pending" // root only
	ResultFile  = "var/lib/hardyos/restore-result.json"
	PoolDataset = "hardyos-backups" // <pool>/hardyos-backups holds nightly backups
)

// BootPools never hold backups: a reinstall wipes them.
var BootPools = map[string]bool{"rpool": true, "bpool": true, "hardyos-boot": true}

func (r *Root) p(rel string) string { return filepath.Join(r.Root, rel) }

func (r *Root) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Collect reads the system files a backup holds. Secrets (storage keys, SSH
// host keys) are included only when asked for. The domain (accounts,
// groups, joined computers) is always included: every download has a
// password, and nightly backups exist so a reinstall keeps the family's
// accounts.
func (r *Root) Collect(ctx context.Context, secrets bool) ([]File, error) {
	var out []File
	add := func(rel string) error {
		fi, err := os.Lstat(r.p(rel))
		if errors.Is(err, fs.ErrNotExist) || (err == nil && !fi.Mode().IsRegular()) {
			return nil
		}
		if err != nil {
			return err
		}
		b, err := os.ReadFile(r.p(rel))
		if err != nil {
			return err
		}
		out = append(out, File{Path: rel, Mode: int64(fi.Mode().Perm()), Data: b, Secret: IsSecret(rel)})
		return nil
	}
	for _, rel := range []string{
		"var/lib/hardyos/network/settings.json",
		"var/lib/hardyos/network/time.json",
		"var/lib/hardyos/tls/server.crt",
		"var/lib/hardyos/tls/server.key",
	} {
		if err := add(rel); err != nil {
			return nil, err
		}
	}
	if r.Domain != nil {
		cfg, archive, err := r.Domain.BackupFiles(ctx)
		if err != nil {
			return nil, err
		}
		if cfg != nil {
			out = append(out,
				File{Path: domainConfigPath, Mode: 0o600, Data: cfg},
				File{Path: domainArchivePath, Mode: 0o600, Data: archive})
		}
	}
	if secrets {
		for _, glob := range []string{"var/lib/hardyos/keys/*.key", "etc/ssh/ssh_host_*"} {
			matches, _ := filepath.Glob(r.p(glob))
			sort.Strings(matches)
			for _, m := range matches {
				rel, _ := filepath.Rel(r.Root, m)
				if AllowedPath(rel) {
					if err := add(rel); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return out, nil
}

// PoolBackup is a backup kept on a data pool.
type PoolBackup struct {
	Pool     string   `json:"pool"`
	Name     string   `json:"name"`
	Size     int64    `json:"size"`
	Manifest Manifest `json:"manifest"`
}

func (r *Root) run(ctx context.Context, name string, args ...string) (string, error) {
	res, err := r.Runner.Run(ctx, nil, name, args...)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		return "", fmt.Errorf("%s: %s", name, strings.TrimSpace(string(res.Stderr)))
	}
	return string(res.Stdout), nil
}

// DataPools lists imported pools that can hold backups.
func (r *Root) DataPools(ctx context.Context) ([]string, error) {
	out, err := r.run(ctx, "zpool", "list", "-H", "-o", "name")
	if err != nil {
		return nil, err
	}
	var pools []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l = strings.TrimSpace(l); l != "" && !BootPools[l] {
			pools = append(pools, l)
		}
	}
	return pools, nil
}

// poolDir returns (creating if asked) the mounted directory of the pool's
// backup dataset.
func (r *Root) poolDir(ctx context.Context, pool string, create bool) (string, error) {
	ds := pool + "/" + PoolDataset
	mp, err := r.run(ctx, "zfs", "get", "-H", "-o", "value", "mountpoint", ds)
	if err != nil {
		if !create {
			return "", nil
		}
		if _, err := r.run(ctx, "zfs", "create", "-o", "compression=lz4", ds); err != nil {
			return "", fmt.Errorf("couldn't create %s: %w", ds, err)
		}
		if mp, err = r.run(ctx, "zfs", "get", "-H", "-o", "value", "mountpoint", ds); err != nil {
			return "", err
		}
	}
	mp = strings.TrimSpace(mp)
	if mp == "" || mp == "none" || mp == "legacy" || !strings.HasPrefix(mp, "/") {
		return "", fmt.Errorf("%s isn't mounted", ds)
	}
	return r.p(mp), nil
}

var poolNameOK = func(p string) bool {
	if p == "" || len(p) > 200 || BootPools[p] {
		return false
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}

func backupNameOK(n string) bool {
	return strings.HasPrefix(n, "hardyos-settings-") && strings.HasSuffix(n, ".hbak") && !strings.ContainsAny(n, "/\\") && !strings.Contains(n, "..") && len(n) < 200
}

// workFile checks that a path given by hardyd is a plain file in its work
// directory (no links out of it).
func (r *Root) workFile(path string) (string, error) {
	work := r.p(WorkDir)
	clean := filepath.Clean(path)
	if !strings.HasPrefix(clean, work+"/") || strings.Contains(strings.TrimPrefix(clean, work+"/"), "/") {
		return "", fmt.Errorf("backup files must be in %s", work)
	}
	fi, err := os.Lstat(clean)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	if fi.Size() > MaxBytes {
		return "", errors.New("the backup file is too large")
	}
	return clean, nil
}

// Store copies a backup hardyd made into the pool's backup dataset and keeps
// the newest `keep` of them.
func (r *Root) Store(ctx context.Context, pool, src string, keep int) (*PoolBackup, error) {
	if !poolNameOK(pool) {
		return nil, fmt.Errorf("%q can't hold backups", pool)
	}
	path, err := r.workFile(src)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := Unpack(b, "")
	if err != nil {
		return nil, fmt.Errorf("refusing to keep it: %w", err)
	}
	if c.Manifest.Secrets {
		return nil, errors.New("backups with encryption keys aren't kept on pools")
	}
	dir, err := r.poolDir(ctx, pool, true)
	if err != nil {
		return nil, err
	}
	name := FileName(c.Manifest.Hostname, c.Manifest.CreatedAt)
	dest := filepath.Join(dir, name)
	if err := writeAtomic(dest, b, 0o600); err != nil {
		return nil, err
	}
	mb, _ := json.Marshal(c.Manifest)
	if err := writeAtomic(strings.TrimSuffix(dest, ".hbak")+".json", mb, 0o600); err != nil {
		return nil, err
	}
	if keep < 1 {
		keep = 14
	}
	list, _ := r.listDir(pool, dir)
	for i := keep; i < len(list); i++ {
		_ = os.Remove(filepath.Join(dir, list[i].Name))
		_ = os.Remove(filepath.Join(dir, strings.TrimSuffix(list[i].Name, ".hbak")+".json"))
	}
	return &PoolBackup{Pool: pool, Name: name, Size: int64(len(b)), Manifest: c.Manifest}, nil
}

// listDir lists backups in a pool's backup directory, newest first.
func (r *Root) listDir(pool, dir string) ([]PoolBackup, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []PoolBackup
	for _, e := range entries {
		if !backupNameOK(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		pb := PoolBackup{Pool: pool, Name: e.Name()}
		if fi, err := e.Info(); err == nil {
			pb.Size = fi.Size()
		}
		if mb, err := os.ReadFile(filepath.Join(dir, strings.TrimSuffix(e.Name(), ".hbak")+".json")); err == nil {
			_ = json.Unmarshal(mb, &pb.Manifest)
		}
		out = append(out, pb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// List returns the backups on every imported data pool, newest first.
func (r *Root) List(ctx context.Context) ([]PoolBackup, error) {
	pools, err := r.DataPools(ctx)
	if err != nil {
		return nil, err
	}
	out := []PoolBackup{}
	for _, pool := range pools {
		dir, err := r.poolDir(ctx, pool, false)
		if err != nil || dir == "" {
			continue
		}
		list, _ := r.listDir(pool, dir)
		out = append(out, list...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Manifest.CreatedAt.After(out[j].Manifest.CreatedAt) })
	return out, nil
}

// Fetch copies a pool backup into hardyd's work directory, so hardyd can
// check it before a restore. It returns the copy's path.
func (r *Root) Fetch(ctx context.Context, pool, name string) (string, error) {
	if !poolNameOK(pool) || !backupNameOK(name) {
		return "", errors.New("invalid backup")
	}
	dir, err := r.poolDir(ctx, pool, false)
	if err != nil || dir == "" {
		return "", fmt.Errorf("%s has no backups", pool)
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "", err
	}
	dest := r.p(filepath.Join(WorkDir, "fetched-"+name))
	if err := writeAtomic(dest, b, 0o640); err != nil {
		return "", err
	}
	if r.UID >= 0 {
		_ = os.Chown(dest, r.UID, r.GID)
	}
	return dest, nil
}

// Staged describes a restore waiting for the next start.
type Staged struct {
	Manifest Manifest  `json:"manifest"`
	StagedAt time.Time `json:"stagedAt"`
}

// Stage unpacks a backup (checking it again as root) into the pending
// directory; it's applied the next time the server starts.
func (r *Root) Stage(src, password string) (*Staged, error) {
	path, err := r.workFile(src)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := Unpack(b, password)
	if err != nil {
		return nil, err
	}
	pending := r.p(PendingDir)
	if err := os.RemoveAll(pending); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(pending, "files"), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(pending, DBName), c.DB, 0o600); err != nil {
		return nil, err
	}
	for _, f := range c.Files {
		dst := filepath.Join(pending, "files", f.Path)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(dst, f.Data, os.FileMode(f.Mode&0o777)); err != nil {
			return nil, err
		}
	}
	st := &Staged{Manifest: c.Manifest, StagedAt: r.now().UTC()}
	sb, _ := json.MarshalIndent(st, "", "  ")
	// The manifest goes last: it's what marks the restore as ready.
	if err := writeAtomic(filepath.Join(pending, ManifestName), sb, 0o600); err != nil {
		return nil, err
	}
	return st, nil
}

// Unstage cancels a waiting restore.
func (r *Root) Unstage() error { return os.RemoveAll(r.p(PendingDir)) }

// PendingRestore returns the restore waiting for the next start, if any.
func (r *Root) PendingRestore() *Staged {
	b, err := rootfile.ReadFile(filepath.Join(r.p(PendingDir), ManifestName))
	if err != nil {
		return nil
	}
	var st Staged
	if json.Unmarshal(b, &st) != nil {
		return nil
	}
	return &st
}

// Result reports the last restore.
type Result struct {
	OK      bool      `json:"ok"`
	At      time.Time `json:"at"`
	Message string    `json:"message"`
	Notes   []string  `json:"notes"`
	From    time.Time `json:"from"` // when the backup was made
}

// LastResult returns the last restore's result, if any.
func (r *Root) LastResult() *Result {
	b, err := rootfile.ReadFile(r.p(ResultFile))
	if err != nil {
		return nil
	}
	var res Result
	if json.Unmarshal(b, &res) != nil {
		return nil
	}
	return &res
}

// ApplyPending restores a staged backup. It runs in hardyd-priv at start,
// before hardyd opens its database. Network settings are skipped when the
// ports they name aren't on this machine, so a restore onto new hardware
// can't leave the server unreachable.
func (r *Root) ApplyPending(ctx context.Context) *Result {
	st := r.PendingRestore()
	if st == nil {
		return nil
	}
	pending := r.p(PendingDir)
	res := &Result{At: r.now().UTC(), From: st.Manifest.CreatedAt, Notes: []string{}}
	defer func() {
		_ = os.RemoveAll(pending)
		b, _ := json.MarshalIndent(res, "", "  ")
		_ = writeAtomic(r.p(ResultFile), b, 0o644)
	}()

	// The database first: without it nothing else matters.
	db, err := rootfile.ReadFile(filepath.Join(pending, DBName))
	if err != nil {
		res.Message = "The settings backup couldn't be restored: " + err.Error()
		return res
	}
	dbPath := r.p(filepath.Join(StateDir, DBName))
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(dbPath + suffix)
	}
	if err := writeAtomic(dbPath, db, 0o640); err != nil {
		res.Message = "The settings backup couldn't be restored: " + err.Error()
		return res
	}
	r.chown(dbPath)

	var netCfg *network.Config
	var timeCfg *network.TimeConfig
	var domainCfg, domainArchive []byte
	_ = filepath.WalkDir(filepath.Join(pending, "files"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(filepath.Join(pending, "files"), p)
		if !AllowedPath(rel) {
			return nil
		}
		b, err := rootfile.ReadFile(p) // staged by root, or not restored
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %v", rel, err))
			return nil
		}
		switch rel {
		case "var/lib/hardyos/network/settings.json":
			var c network.Config
			if json.Unmarshal(b, &c) == nil {
				netCfg = &c
			}
			return nil
		case "var/lib/hardyos/network/time.json":
			var t network.TimeConfig
			if json.Unmarshal(b, &t) == nil {
				timeCfg = &t
			}
			return nil
		case domainConfigPath:
			domainCfg = b
			return nil
		case domainArchivePath:
			domainArchive = b
			return nil
		}
		fi, _ := d.Info()
		mode := os.FileMode(0o600)
		if fi != nil {
			mode = fi.Mode().Perm()
		}
		if err := writeAtomic(r.p(rel), b, mode); err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %v", rel, err))
			return nil
		}
		if strings.HasPrefix(rel, "var/lib/hardyos/tls/") {
			r.chown(r.p(rel))
		}
		return nil
	})

	if netCfg != nil && r.Network != nil {
		netCfg.Normalize()
		if err := netCfg.Validate(r.Network.PortNames()); err != nil {
			res.Notes = append(res.Notes, "Network settings were not restored because they don't work on this server ("+err.Error()+"). The current network settings stay.")
		} else if err := r.Network.WriteNow(*netCfg); err != nil {
			res.Notes = append(res.Notes, "Network settings couldn't be applied: "+err.Error())
		}
	}
	if domainCfg != nil && r.Domain != nil {
		note, err := r.Domain.RestoreFiles(ctx, domainCfg, domainArchive)
		switch {
		case err != nil:
			res.Notes = append(res.Notes, "The domain couldn't be restored: "+err.Error())
		case note != "":
			res.Notes = append(res.Notes, note)
		}
	}
	if timeCfg != nil && r.Network != nil {
		if err := r.Network.SetTime(ctx, *timeCfg); err != nil {
			res.Notes = append(res.Notes, "Date and time settings couldn't be restored: "+err.Error())
		}
	}
	res.OK = true
	res.Message = fmt.Sprintf("Settings restored from the backup made %s.", st.Manifest.CreatedAt.Local().Format("Jan 2, 2006 at 3:04 PM"))
	return res
}

func (r *Root) chown(p string) {
	if r.UID >= 0 {
		_ = os.Chown(p, r.UID, r.GID)
	}
}

func writeAtomic(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".hardyos-tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
