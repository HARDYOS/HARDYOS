package vms

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"github.com/hardyos/hardyos/daemon/internal/zfs"
)

// The catalog's store (decision 410, amended): verified images live in
// <pool>/vm-catalog, a dataset only root writes (never shared, exec,
// setuid and devices off, its folder 0711), each file root's own and 0444
// so QEMU can read it and nobody can change it. Next to each file root
// keeps <file>.verified (0600): the checksum it was checked against and
// the file's size, modification time and inode then, so a start can trust
// the file without hashing it again. The ISOs shared folder never holds
// what the catalog gives VMs.

// PropCatalog marks a pool's catalog store.
const PropCatalog = "org.hardyos:vm-catalog"

// CatalogStoreDataset is a pool's catalog store.
func CatalogStoreDataset(pool string) string { return pool + "/vm-catalog" }

type catalogStore struct {
	pool string
	dir  string // mountpoint (host path)
}

// store finds (or with create makes) a pool's catalog store.
func (m *Manager) store(ctx context.Context, pool string, create bool) (*catalogStore, error) {
	if zfs.ValidPoolName(pool) != nil || !slices.Contains(m.pools(ctx), pool) {
		return nil, Problems{fmt.Sprintf("there's no pool called %q for verified images", pool)}
	}
	ds := CatalogStoreDataset(pool)
	if out, err := m.zfs(ctx, "get", "-H", "-p", "-o", "value", PropCatalog, ds); err != nil || string(trimNL(out)) != "yes" {
		if !create {
			return nil, os.ErrNotExist
		}
		if err == nil {
			return nil, fmt.Errorf("%s exists but isn't HardyOS's catalog store", ds)
		}
		if _, err := m.zfs(ctx, "create", "-o", PropCatalog+"=yes", "-o", "canmount=on", "-o", "devices=off", "-o", "setuid=off", "-o", "exec=off", ds); err != nil {
			return nil, fmt.Errorf("creating %s: %w", ds, err)
		}
	}
	st, err := m.mounted(ctx, ds) // verified mount, folder 0711
	if err != nil {
		return nil, err
	}
	return &catalogStore{pool: pool, dir: st.dir}, nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

func (m *Manager) openStore(c *catalogStore) (*os.Root, error) {
	return os.OpenRoot(m.sys(c.dir))
}

// storeSink saves downloads into the store.
type storeSink struct{ r *os.Root }

func (s storeSink) create(name string) (*os.File, error) {
	return s.r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
}
func (s storeSink) rename(from, to string) error {
	if _, err := s.r.Lstat(to); err == nil {
		return fmt.Errorf("%s is already in the catalog store", to)
	}
	return s.r.Rename(from, to)
}
func (s storeSink) remove(name string) error { return s.r.Remove(name) }

// stamp is what root knew about a file when it checked it.
type stamp struct {
	Digest  string `json:"digest"`
	Size    int64  `json:"size"`
	MtimeNs int64  `json:"mtimeNs"`
	Ino     uint64 `json:"ino"`
}

func stampName(file string) string { return file + ".verified" }

// fileFacts reads a stored file's size, time and inode, refusing anything
// that isn't a plain file root owns alone, 0444.
func fileFacts(r *os.Root, name string) (os.FileInfo, uint64, error) {
	fi, err := r.Lstat(name)
	if err != nil {
		return nil, 0, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o444 {
		return nil, 0, fmt.Errorf("%s in the catalog store isn't a sealed file", name)
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, 0, errors.New("no file details")
	}
	if rootfile.Enforce && (sys.Uid != 0 || sys.Nlink != 1) {
		return nil, 0, fmt.Errorf("%s in the catalog store isn't root's own file", name)
	}
	return fi, sys.Ino, nil
}

// checkStamp makes sure name is the file root checked against want.
func checkStamp(r *os.Root, name string, want digest, size int64) error {
	fi, ino, err := fileFacts(r, name)
	if err != nil {
		return err
	}
	if size > 0 && fi.Size() != size {
		return fmt.Errorf("%s is %d bytes, not %d", name, fi.Size(), size)
	}
	b, err := r.ReadFile(stampName(name))
	if err != nil {
		return fmt.Errorf("%s hasn't been checked", name)
	}
	var s stamp
	if json.Unmarshal(b, &s) != nil || s.Digest != want.Algo+":"+want.Hex || s.Size != fi.Size() || s.MtimeNs != fi.ModTime().UnixNano() || s.Ino != ino {
		return fmt.Errorf("%s isn't the file that was checked", name)
	}
	return nil
}

// seal makes a checked file read-only and records the check.
func seal(r *os.Root, name string, d digest) error {
	if err := r.Chmod(name, 0o444); err != nil {
		return err
	}
	fi, ino, err := fileFacts(r, name)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(stamp{Digest: d.Algo + ":" + d.Hex, Size: fi.Size(), MtimeNs: fi.ModTime().UnixNano(), Ino: ino})
	_ = r.Remove(stampName(name))
	f, err := r.OpenFile(stampName(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// hashStored hashes a stored file.
func hashStored(r *os.Root, name string, d digest) (string, int64, error) {
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := d.hash()
	n, err := io.Copy(h, io.LimitReader(f, MaxDownloadBytes+1))
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// unseal removes a stored file and its record.
func unseal(r *os.Root, name string) {
	_ = r.Remove(stampName(name))
	_ = r.Remove(name)
}

// virtioPath is the verified VirtIO drivers disc on the pool.
func (m *Manager) virtioPath(ctx context.Context, pool string) (string, error) {
	c, err := m.store(ctx, pool, false)
	if err != nil {
		return "", errors.New("the VirtIO drivers disc isn't downloaded yet")
	}
	r, err := m.openStore(c)
	if err != nil {
		return "", err
	}
	defer r.Close()
	if err := checkStamp(r, VirtioFile, digest{Algo: "sha256", Hex: VirtioSHA256}, VirtioSize); err != nil {
		return "", fmt.Errorf("the VirtIO drivers disc isn't ready: %w", err)
	}
	return filepath.Join(c.dir, VirtioFile), nil
}

// openCatalogImport opens a verified image for a disk's import.
func (m *Manager) openCatalogImport(ctx context.Context, pool string, imp *Import) (*os.File, error) {
	img, cf, err := m.catalogFile(imp.Catalog)
	if err != nil {
		return nil, err
	}
	if cf.File != imp.File || img.Kind != "disk" {
		return nil, Problems{fmt.Sprintf("%s isn't the verified image %s", imp.File, imp.Catalog)}
	}
	c, err := m.store(ctx, pool, false)
	if err != nil {
		return nil, Problems{"the verified image isn't on the VM's pool; create the VM again to download it"}
	}
	r, err := m.openStore(c)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	d := imp.digest()
	if d.Hex == "" {
		return nil, Problems{"a verified image needs its checksum"}
	}
	if err := checkStamp(r, cf.File, d, cf.Size); err != nil {
		return nil, err
	}
	return r.OpenFile(cf.File, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// catalogNames are the library names the catalog's files have; the ISO
// library doesn't take files of those names, so nobody can mistake one
// for the verified copy.
func (m *Manager) catalogNames() map[string]bool {
	out := map[string]bool{}
	for _, c := range m.catalog() {
		for _, f := range c.Files {
			out[f.File] = true
		}
	}
	return out
}
