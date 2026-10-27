package apps

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// Cloud backups (internal/cloudbackup) back an app up from a snapshot of
// its dataset (data and .hardyos: package, settings, generated secrets) and
// bring it back as a working app: in place, or onto a rebuilt server.

// BackupSource is an installed app's dataset, for a backup.
type BackupSource struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Pool    string `json:"pool"`
	Dataset string `json:"dataset"`
}

// BackupSource names an installed app's dataset.
func (m *Manager) BackupSource(ctx context.Context, id string) (*BackupSource, error) {
	ia, c, err := m.app(ctx, id)
	if err != nil {
		return nil, err
	}
	return &BackupSource{ID: ia.state.ID, Name: ia.manifest.Name, Version: ia.manifest.Version, Pool: c.Pool, Dataset: ia.dataset}, nil
}

// BackupSources lists every installed app (none when apps aren't set up).
func (m *Manager) BackupSources(ctx context.Context) ([]BackupSource, error) {
	c, err := m.engine()
	if err != nil || c == nil {
		return []BackupSource{}, err
	}
	l, err := m.installed(ctx, c)
	if err != nil {
		return nil, err
	}
	out := []BackupSource{}
	for _, ia := range l {
		if !ia.state.Removed {
			out = append(out, BackupSource{ID: ia.state.ID, Name: ia.manifest.Name, Version: ia.manifest.Version, Pool: c.Pool, Dataset: ia.dataset})
		}
	}
	return out, nil
}

// Fill writes an app's data into its mounted dataset (dir is the
// dataset's mountpoint, dataset its name).
type Fill func(ctx context.Context, dir, dataset string) error

// RestoreData puts an installed app's data back to a version from a
// backup. Confirm is the app's name. The app is stopped, a safety snapshot
// (hardyos-manual-<time>) is taken so the step can be undone, fill
// replaces the dataset's contents, and the app comes back like after a
// rollback: the package and settings the version holds, but never
// permissions the admin has taken away since (decision 77).
func (m *Manager) RestoreData(ctx context.Context, id, confirm string, fill Fill) error {
	ia, c, err := m.app(ctx, id)
	if err != nil {
		return err
	}
	if !confirmed(confirm, ia) {
		return Problems{fmt.Sprintf("type the app's name (%s) to confirm", ia.manifest.Name)}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.runCompose(ctx, m.composeArgs(ia, "stop")...); err != nil {
		return fmt.Errorf("stopping %s: %w", ia.manifest.Name, err)
	}
	safety := "hardyos-manual-" + m.now().Format("20060102-150405")
	if _, err := m.run(ctx, "zfs", "snapshot", "-o", versionProp+"="+ia.manifest.Version, ia.dataset+"@"+safety); err != nil {
		return fmt.Errorf("snapshotting %s first: %w", ia.dataset, err)
	}
	if err := fill(ctx, ia.dir, ia.dataset); err != nil {
		return fmt.Errorf("restoring %s's data (the snapshot %s has it as it was): %w", ia.manifest.Name, safety, err)
	}
	// The version's state.json says where the app came from, what it may
	// do and which user it is: none of that is taken from a backup. The
	// live install's source, grants and user ID stay.
	back, err := m.load(ctx, c, id)
	if err != nil || back.state.ID != id || back.manifest.ID != id {
		return fmt.Errorf("the restored %s can't be read (the snapshot %s has it as it was)", ia.manifest.Name, safety)
	}
	oldUID := back.state.UID
	// The source is decided again from the restored package's bytes, with
	// the live install as the previous state: catalog only if those bytes
	// are shipped (or are the package root found in the catalog), else the
	// live label (upload when the live app was a catalog one).
	raw, _ := readStateFile(back.meta(packageFile))
	src, name, sum, err := m.deriveSource(raw, "", "", &ia.state)
	if err != nil {
		return err
	}
	back.state.Source, back.state.SourceName, back.state.CatalogSHA256 = src, name, sum
	back.state.Grants = append([]string(nil), ia.state.Grants...)
	back.state.UID = ia.state.UID
	back.state.Removed = false
	if err := writeFileAtomic(back.meta(stateFile), mustJSON(back.state), 0o600); err != nil {
		return err
	}
	if err := remapOwner(filepath.Join(back.dir, dataDirName), oldUID, back.state.UID); err != nil {
		return fmt.Errorf("giving the restored data to %s's user: %w", ia.manifest.Name, err)
	}
	return m.bringBack(ctx, ia, c, "the backup")
}

// RestoreNew brings back an app that isn't installed here (a rebuilt
// server): it sets up apps on pool if needed, creates the app's dataset,
// lets fill write its data and starts it from the package and settings the
// backup holds. Shared folders it used come back only where a folder with
// that id exists again.
func (m *Manager) RestoreNew(ctx context.Context, id, pool string, fill Fill) error {
	if err := ValidID(id); err != nil {
		return Problems{err.Error()}
	}
	if !m.Available() {
		return errors.New("this HardyOS build doesn't include Docker")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.engine()
	if err != nil {
		return err
	}
	if c == nil {
		if err := zfs.ValidPoolName(pool); err != nil {
			return Problems{"choose the pool for apps"}
		}
		if c, err = m.setupEngine(ctx, pool); err != nil {
			return err
		}
	} else if err := m.startEngine(ctx, c); err != nil {
		return err
	}
	ds := c.Pool + "/apps/" + id
	if m.datasetExists(ctx, ds) {
		if ia, err := m.load(ctx, c, id); err == nil && !ia.state.Removed {
			return Problems{fmt.Sprintf("%s is already installed; restore it from its own version list instead", ia.manifest.Name)}
		}
		return Problems{fmt.Sprintf("%s already has kept data on this server; remove it first", id)}
	}
	if _, err := m.run(ctx, "zfs", "create", ds); err != nil {
		return fmt.Errorf("creating %s: %w", ds, err)
	}
	dir, _, err := m.mountpoint(ctx, ds)
	if err != nil {
		return err
	}
	if err := fill(ctx, dir, ds); err != nil {
		return fmt.Errorf("restoring %s's data: %w", id, err)
	}
	ia, err := m.load(ctx, c, id)
	if err != nil {
		return fmt.Errorf("the restored app can't be read: %w", err)
	}
	if ia.state.ID != id || ia.manifest.ID != id {
		return Problems{"the backup holds a different app"}
	}
	// Nothing about trust comes from the backup: the source is decided
	// again from the package bytes (catalog only if they match the shipped
	// catalog, otherwise an upload whose extra permissions an
	// administrator grants again), no grants, and the user ID is kept only
	// when no other app has it.
	raw, _ := readStateFile(ia.meta(packageFile))
	src, name, sum, err := m.deriveSource(raw, "", "", nil)
	if err != nil {
		return err
	}
	ia.state.Source, ia.state.SourceName, ia.state.CatalogSHA256 = src, name, sum
	ia.state.Grants = nil
	ia.state.Removed = false
	oldUID := ia.state.UID
	if !m.uidFree(ctx, c, id, oldUID) {
		ia.state.UID = 0
		uid, err := m.allocUID(ctx, c, ia)
		if err != nil {
			return err
		}
		ia.state.UID = uid
	}
	if err := writeFileAtomic(ia.meta(stateFile), mustJSON(ia.state), 0o600); err != nil {
		return err
	}
	if err := remapOwner(filepath.Join(dir, dataDirName), oldUID, ia.state.UID); err != nil {
		return fmt.Errorf("giving the restored data to %s's user: %w", id, err)
	}
	return m.bringBack(ctx, ia, c, "the backup")
}

// uidFree reports whether uid is a valid app user ID no other app on the
// pool has.
func (m *Manager) uidFree(ctx context.Context, c *EngineConfig, id string, uid int) bool {
	if uid < FirstAppUID || uid > LastAppUID {
		return false
	}
	l, err := m.installed(ctx, c)
	if err != nil {
		return false
	}
	for _, o := range l {
		if o.state.ID != id && o.state.UID == uid {
			return false
		}
	}
	return true
}

// remapOwner gives everything below dir that from owns (user and group)
// to to, by descriptor, never following a link.
func remapOwner(dir string, from, to int) error {
	if from == to || from <= 0 || to <= 0 {
		return nil
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return remapAt(fd, from, to, 0)
}

func remapAt(dirfd, from, to, depth int) error {
	if depth > 256 {
		return errors.New("folders nested too deep")
	}
	var st unix.Stat_t
	if err := unix.Fstat(dirfd, &st); err != nil {
		return err
	}
	if err := remapOne(dirfd, "", &st, from, to); err != nil {
		return err
	}
	f := os.NewFile(uintptr(mustDup(dirfd)), "dir")
	names, err := f.Readdirnames(-1)
	f.Close()
	if err != nil {
		return err
	}
	for _, n := range names {
		var cst unix.Stat_t
		if err := unix.Fstatat(dirfd, n, &cst, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			continue
		}
		if cst.Mode&unix.S_IFMT == unix.S_IFDIR {
			cfd, err := unix.Openat(dirfd, n, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				continue
			}
			err = remapAt(cfd, from, to, depth+1)
			unix.Close(cfd)
			if err != nil {
				return err
			}
			continue
		}
		if err := remapOne(dirfd, n, &cst, from, to); err != nil {
			return err
		}
	}
	return nil
}

func remapOne(dirfd int, name string, st *unix.Stat_t, from, to int) error {
	uid, gid := -1, -1
	if int(st.Uid) == from {
		uid = to
	}
	if int(st.Gid) == from {
		gid = to
	}
	if uid < 0 && gid < 0 {
		return nil
	}
	if name == "" {
		return unix.Fchown(dirfd, uid, gid)
	}
	return unix.Fchownat(dirfd, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW)
}

func mustDup(fd int) int {
	n, err := unix.Dup(fd)
	if err != nil {
		return -1
	}
	return n
}
