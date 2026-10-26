// Package backup saves and restores HardyOS settings: the hardyd database
// (users, schedules, settings), network and time settings, and the HTTPS
// certificate. Backups with secrets (encryption keys for storage, SSH host
// keys) are always password-protected.
//
// A backup file (.hbak) is "HOSBAK01", one flag byte, then either a gzipped
// tar (flag 0) or, password-protected (flag 1), a 16-byte salt, a 12-byte
// nonce and the AES-256-GCM-sealed gzipped tar, with the key derived from
// the password by argon2id.
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// FormatVersion is written into every manifest.
const FormatVersion = 1

// MaxBytes bounds a backup file.
const MaxBytes = 512 << 20

const magic = "HOSBAK01"

// Archive member names.
const (
	ManifestName = "manifest.json"
	DBName       = "hardyd.db"
)

// File is one system file in a backup.
type File struct {
	Path   string `json:"path"` // relative to /, like var/lib/hardyos/tls/server.crt
	Mode   int64  `json:"mode"`
	Data   []byte `json:"data,omitempty"`
	Secret bool   `json:"secret,omitempty"`
}

// Manifest describes a backup.
type Manifest struct {
	Format    int       `json:"format"`
	CreatedAt time.Time `json:"createdAt"`
	Version   string    `json:"version"` // HardyOS version that made it
	Hostname  string    `json:"hostname"`
	// Schema is the database migration level, so an older HardyOS refuses a
	// database it doesn't understand.
	Schema  int         `json:"schema"`
	Secrets bool        `json:"secrets"`
	Entries []EntryInfo `json:"entries"`
	Users   int         `json:"users"`
	Note    string      `json:"note,omitempty"` // "nightly" or "manual"
}

// EntryInfo lists one archive member with its checksum.
type EntryInfo struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Contents is an unpacked backup.
type Contents struct {
	Manifest Manifest
	DB       []byte
	Files    []File
}

// Allowed is where restored files may go. Anything else in an archive is
// rejected, so a crafted backup can't write over the system.
var Allowed = []string{
	"var/lib/hardyos/network/settings.json",
	"var/lib/hardyos/network/time.json",
	"var/lib/hardyos/tls/server.crt",
	"var/lib/hardyos/tls/server.key",
	"var/lib/hardyos/keys/", // *.key
	"etc/ssh/ssh_host_",     // host keys
	domainConfigPath,
	domainArchivePath,
}

// The domain controller's files (see internal/domain).
const (
	domainConfigPath  = "var/lib/hardyos-dc/hardyos-dc.json"
	domainArchivePath = "var/lib/hardyos-dc/domain-backup.tar.bz2"
)

// AllowedPath reports whether p may be restored.
func AllowedPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.Contains(p, "..") {
		return false
	}
	for _, a := range Allowed {
		if strings.HasSuffix(a, "/") || strings.HasSuffix(a, "_") {
			rest, ok := strings.CutPrefix(p, a)
			if ok && rest != "" && !strings.Contains(rest, "/") {
				if a == "var/lib/hardyos/keys/" && !strings.HasSuffix(rest, ".key") {
					return false
				}
				return true
			}
			continue
		}
		if p == a {
			return true
		}
	}
	return false
}

// Pack builds a backup file. A password is required when any file is secret.
func Pack(c Contents, password string) ([]byte, error) {
	secrets := false
	for _, f := range c.Files {
		if !AllowedPath(f.Path) {
			return nil, fmt.Errorf("%s can't be part of a backup", f.Path)
		}
		secrets = secrets || f.Secret
	}
	if secrets && password == "" {
		return nil, errors.New("a backup with encryption keys needs a password")
	}
	m := c.Manifest
	m.Format = FormatVersion
	m.Secrets = secrets
	m.Entries = nil
	add := func(name string, data []byte) {
		sum := sha256.Sum256(data)
		m.Entries = append(m.Entries, EntryInfo{Path: name, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])})
	}
	add(DBName, c.DB)
	for _, f := range c.Files {
		add("files/"+f.Path, f.Data)
	}

	var tgz bytes.Buffer
	gz := gzip.NewWriter(&tgz)
	tw := tar.NewWriter(gz)
	write := func(name string, mode int64, data []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: m.CreatedAt, Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := write(ManifestName, 0o644, mb); err != nil {
		return nil, err
	}
	if err := write(DBName, 0o640, c.DB); err != nil {
		return nil, err
	}
	for _, f := range c.Files {
		if err := write("files/"+f.Path, f.Mode, f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}

	var out bytes.Buffer
	out.WriteString(magic)
	if password == "" {
		out.WriteByte(0)
		out.Write(tgz.Bytes())
		return out.Bytes(), nil
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aead, err := newAEAD(password, salt)
	if err != nil {
		return nil, err
	}
	out.WriteByte(1)
	out.Write(salt)
	out.Write(nonce)
	out.Write(aead.Seal(nil, nonce, tgz.Bytes(), []byte(magic)))
	return out.Bytes(), nil
}

func newAEAD(password string, salt []byte) (cipher.AEAD, error) {
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Errors from Unpack.
var (
	ErrNotBackup     = errors.New("this isn't a HardyOS settings backup")
	ErrNeedPassword  = errors.New("this backup is password-protected; enter its password")
	ErrWrongPassword = errors.New("the password is wrong, or the backup is damaged")
)

// Encrypted reports whether b is a password-protected backup.
func Encrypted(b []byte) (bool, error) {
	if len(b) < len(magic)+1 || string(b[:len(magic)]) != magic {
		return false, ErrNotBackup
	}
	return b[len(magic)] == 1, nil
}

// Unpack opens a backup file and checks every member against the manifest.
func Unpack(b []byte, password string) (*Contents, error) {
	enc, err := Encrypted(b)
	if err != nil {
		return nil, err
	}
	body := b[len(magic)+1:]
	if enc {
		if password == "" {
			return nil, ErrNeedPassword
		}
		if len(body) < 28 {
			return nil, ErrNotBackup
		}
		aead, err := newAEAD(password, body[:16])
		if err != nil {
			return nil, err
		}
		body, err = aead.Open(nil, body[16:28], body[28:], []byte(magic))
		if err != nil {
			return nil, ErrWrongPassword
		}
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, ErrNotBackup
	}
	tr := tar.NewReader(io.LimitReader(gz, 4*MaxBytes))
	members := map[string][]byte{}
	modes := map[string]int64{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("the backup is damaged: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("the backup holds an unexpected entry %q", h.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, MaxBytes+1))
		if err != nil {
			return nil, fmt.Errorf("the backup is damaged: %w", err)
		}
		members[h.Name] = data
		modes[h.Name] = h.Mode
	}
	mb, ok := members[ManifestName]
	if !ok {
		return nil, ErrNotBackup
	}
	c := &Contents{}
	if err := json.Unmarshal(mb, &c.Manifest); err != nil {
		return nil, ErrNotBackup
	}
	if c.Manifest.Format != FormatVersion {
		return nil, fmt.Errorf("this backup was made by a newer HardyOS (format %d)", c.Manifest.Format)
	}
	if len(members) != len(c.Manifest.Entries)+1 {
		return nil, errors.New("the backup's contents don't match its manifest")
	}
	for _, e := range c.Manifest.Entries {
		data, ok := members[e.Path]
		sum := sha256.Sum256(data)
		if !ok || int64(len(data)) != e.Size || hex.EncodeToString(sum[:]) != e.SHA256 {
			return nil, fmt.Errorf("the backup is damaged (%s doesn't match)", e.Path)
		}
		switch {
		case e.Path == DBName:
			c.DB = data
		case strings.HasPrefix(e.Path, "files/"):
			p := strings.TrimPrefix(e.Path, "files/")
			if !AllowedPath(p) {
				return nil, fmt.Errorf("the backup holds %s, which HardyOS never restores", p)
			}
			c.Files = append(c.Files, File{Path: p, Mode: modes[e.Path] & 0o777, Data: data, Secret: IsSecret(p)})
		default:
			return nil, fmt.Errorf("the backup holds an unexpected entry %q", e.Path)
		}
	}
	if c.DB == nil {
		return nil, errors.New("the backup has no database")
	}
	return c, nil
}

// IsSecret reports whether a file holds keys that only go into
// password-protected backups.
func IsSecret(p string) bool {
	return strings.HasPrefix(p, "var/lib/hardyos/keys/") || (strings.HasPrefix(p, "etc/ssh/ssh_host_") && !strings.HasSuffix(p, ".pub"))
}

// FileName is the name for a backup made at t.
func FileName(hostname string, t time.Time) string {
	return fmt.Sprintf("hardyos-settings-%s-%s.hbak", hostname, t.UTC().Format("20060102-150405"))
}
