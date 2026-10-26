package domain

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// Paths of the domain's files inside a settings backup (relative to /).
const (
	BackupConfigPath  = "var/lib/hardyos-dc/hardyos-dc.json"
	BackupArchivePath = "var/lib/hardyos-dc/domain-backup.tar.bz2"
)

// maxArchive bounds a domain backup (a family domain is a few MB).
const maxArchive = 256 << 20

// BackupFiles returns the domain's settings and a consistent copy of its
// databases (samba-tool's offline backup, safe while the DC runs), or nil
// when there's no domain.
func (m *Manager) BackupFiles(ctx context.Context) (config, archive []byte, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.Load()
	if err != nil || c == nil {
		return nil, nil, err
	}
	tmp := m.dataPath("backup-tmp")
	_ = os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmp)
	if _, err := sysexec.Output(ctx, m.Runner, "samba-tool", "domain", "backup", "offline",
		"--targetdir="+filepath.Join(m.Dir(), "backup-tmp"), "-s", m.SmbConf()); err != nil {
		return nil, nil, fmt.Errorf("backing up the domain: %w", err)
	}
	matches, _ := filepath.Glob(filepath.Join(tmp, "*.tar.bz2"))
	if len(matches) != 1 {
		return nil, nil, errors.New("backing up the domain: samba-tool made no backup file")
	}
	archive, err = os.ReadFile(matches[0])
	if err != nil {
		return nil, nil, err
	}
	config, err = json.MarshalIndent(c, "", "  ")
	return config, archive, err
}

// RestoreFiles brings a domain back from a settings backup, at start-up
// before the DC runs. It returns a note for the person either way. A domain
// already on this server is kept; a DC that had partners isn't restored
// (rejoining from a partner is the safe way back; an old copy would fight
// the newer one).
func (m *Manager) RestoreFiles(ctx context.Context, config, archive []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var c Config
	if err := json.Unmarshal(config, &c); err != nil || c.Domain == "" {
		return "", errors.New("the backup's domain settings are damaged")
	}
	if cur, _ := m.Load(); cur != nil {
		return fmt.Sprintf("The domain %s on this server was kept; the backup's copy of %s wasn't restored.", cur.Domain, c.Domain), nil
	}
	if len(c.Others) > 0 {
		return fmt.Sprintf("This server was one of %d domain controllers for %s, so its old copy wasn't restored: join it to the domain again in Control Panel > Domain (the other controller has every account).", len(c.Others)+1, c.Domain), nil
	}
	if !m.Available() {
		return "", errors.New("this HardyOS build doesn't include the domain controller")
	}
	if len(archive) == 0 || len(archive) > maxArchive {
		return "", errors.New("the backup's domain archive is missing or too large")
	}
	if err := m.makeDataDir(ctx); err != nil {
		return "", err
	}
	ok := false
	defer func() {
		if !ok {
			_ = m.removeData(context.WithoutCancel(ctx))
		}
	}()
	if err := extractDomainArchive(archive, m.dataPath()); err != nil {
		return "", fmt.Errorf("unpacking the domain: %w", err)
	}
	// Group policies (sysvol) are packed separately.
	if sv, err := os.ReadFile(m.dataPath("sysvol.tar.gz")); err == nil {
		if err := extractSysvol(sv, m.dataPath("state", "sysvol")); err != nil {
			return "", fmt.Errorf("unpacking group policies: %w", err)
		}
	}
	for _, f := range []string{"sysvol.tar.gz", "backup.txt"} {
		_ = os.Remove(m.dataPath(f))
	}
	// Samba makes new TLS certificates when the folder is empty.
	for _, d := range []struct {
		p    string
		mode os.FileMode
	}{{"private/tls", 0o700}, {"run", 0o755}, {"log", 0o750}, {"state/sysvol", 0o755}} {
		if err := os.MkdirAll(m.dataPath(d.p), d.mode); err != nil {
			return "", err
		}
	}
	c.Enabled = true
	if err := m.writeSmbConf(&c); err != nil {
		return "", err
	}
	if err := m.save(&c); err != nil {
		return "", err
	}
	// The copy is marked as a backup; Samba won't start until that's gone.
	if err := m.admin(ctx, "restore.unmark", map[string]any{}, nil); err != nil {
		return "", fmt.Errorf("finishing the domain restore: %w", err)
	}
	if _, err := sysexec.Output(ctx, m.Runner, "samba-tool", "ntacl", "sysvolreset", "-s", m.SmbConf()); err != nil {
		m.log().Warn("resetting group policy permissions", "err", err)
	}
	ok = true
	return fmt.Sprintf("The domain %s was restored; its controller starts once the network is up.", c.Domain), nil
}

// Top-level names a domain archive may contain.
var archiveTop = map[string]bool{"private": true, "state": true, "etc": true, "bind-dns": true, "cache": true, "sysvol.tar.gz": true, "backup.txt": true}

// safeRel cleans an archive member name; "" means refuse it.
func safeRel(name string) string {
	name = strings.TrimPrefix(name, "./")
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return ""
	}
	clean := path.Clean(name)
	if clean == "." || strings.HasPrefix(clean, "..") || strings.Contains(clean, "/../") {
		return ""
	}
	return clean
}

// untar writes regular files and folders only: no links, devices or paths
// outside dest, whatever the archive says.
func untar(r io.Reader, dest string, allowTop func(string) bool) error {
	tr := tar.NewReader(r)
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		rel := safeRel(h.Name)
		if rel == "" || !allowTop(strings.SplitN(rel, "/", 2)[0]) {
			return fmt.Errorf("unexpected entry %q", h.Name)
		}
		target := filepath.Join(dest, filepath.FromSlash(rel))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			// Never follow something already there.
			if fi, err := os.Lstat(target); err == nil && !fi.Mode().IsRegular() {
				return fmt.Errorf("%s is in the way", rel)
			}
			total += h.Size
			if total > 4*maxArchive {
				return errors.New("the archive unpacks too large")
			}
			mode := os.FileMode(h.Mode).Perm() &^ 0o022
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, io.LimitReader(tr, h.Size))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected kind of entry %q", h.Name)
		}
	}
}

func extractDomainArchive(b []byte, dest string) error {
	return untar(bzip2.NewReader(bytes.NewReader(b)), dest, func(top string) bool { return archiveTop[top] })
}

func extractSysvol(b []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer gz.Close()
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	// sysvol holds one folder per domain (and its .NTACL twin).
	return untar(gz, dest, func(string) bool { return true })
}
