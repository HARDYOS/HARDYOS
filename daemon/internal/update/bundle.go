// Package update installs signed HardyOS updates into new ZFS boot
// environments and rolls back automatically when a new version doesn't come
// up healthy.
//
// An update bundle (.hupd) is an uncompressed tar with exactly three
// entries, in order:
//
//	manifest.json    version, architecture and the system image's size and SHA-256
//	manifest.sig     ed25519 signature of manifest.json (base64)
//	rootfs.squashfs  the system image (the live ISO's filesystem.squashfs)
//
// The signature is checked before the image is read, and the image is
// checked against the manifest's hash while it is extracted.
package update

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// BundleFormat is the bundle layout version this build understands.
const BundleFormat = 1

// Bundle entry names.
const (
	manifestName = "manifest.json"
	sigName      = "manifest.sig"
	rootfsName   = "rootfs.squashfs"
)

// MaxImageBytes bounds the system image (a sanity limit, not a target).
const MaxImageBytes = 8 << 30

// Manifest describes an update.
type Manifest struct {
	Format  int       `json:"format"`
	Version string    `json:"version"`
	Arch    string    `json:"arch"`
	Created time.Time `json:"created"`
	RootFS  FileRef   `json:"rootfs"`
	Notes   string    `json:"notes,omitempty"`
}

// FileRef identifies a file inside the bundle.
type FileRef struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

var versionRE = regexp.MustCompile(`^[0-9][0-9A-Za-z.~+-]{0,63}$`)

// Validate checks the manifest's fields.
func (m *Manifest) Validate() error {
	switch {
	case m.Format != BundleFormat:
		return fmt.Errorf("bundle format %d is not supported by this version (expected %d)", m.Format, BundleFormat)
	case !versionRE.MatchString(m.Version):
		return fmt.Errorf("invalid version %q", m.Version)
	case m.Arch == "":
		return errors.New("manifest has no architecture")
	case m.RootFS.Name != rootfsName:
		return fmt.Errorf("unexpected system image name %q", m.RootFS.Name)
	case m.RootFS.Size <= 0 || m.RootFS.Size > MaxImageBytes:
		return fmt.Errorf("system image size %d is out of range", m.RootFS.Size)
	case !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.RootFS.SHA256):
		return errors.New("manifest has no valid SHA-256 for the system image")
	}
	return nil
}

// Keys --------------------------------------------------------------------

const (
	pubPrefix  = "hardyos-ed25519"
	privPrefix = "hardyos-ed25519-private"
)

//go:embed keys
var embeddedKeys embed.FS

// TrustedKeysDir holds extra trusted keys on a server (for testing builds).
const TrustedKeysDir = "/etc/hardyos/trusted-keys.d"

// PublicKey is a trusted signing key.
type PublicKey struct {
	Key     ed25519.PublicKey
	Comment string
}

// ParsePublicKey reads "hardyos-ed25519 <base64> [comment]".
func ParsePublicKey(line string) (PublicKey, error) {
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) < 2 || f[0] != pubPrefix {
		return PublicKey{}, errors.New("not a HardyOS public key")
	}
	raw, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return PublicKey{}, errors.New("malformed HardyOS public key")
	}
	return PublicKey{Key: raw, Comment: strings.Join(f[2:], " ")}, nil
}

// FormatPublicKey writes the one-line form of a public key.
func FormatPublicKey(k ed25519.PublicKey, comment string) string {
	return strings.TrimSpace(fmt.Sprintf("%s %s %s", pubPrefix, base64.StdEncoding.EncodeToString(k), comment)) + "\n"
}

// ParsePrivateKey reads a private key file.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	f := strings.Fields(strings.TrimSpace(string(data)))
	if len(f) < 2 || f[0] != privPrefix {
		return nil, errors.New("not a HardyOS private key")
	}
	seed, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("malformed HardyOS private key")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// GenerateKey creates a new signing key pair in file form.
func GenerateKey(comment string) (priv, pub string, err error) {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	priv = fmt.Sprintf("%s %s\n", privPrefix, base64.StdEncoding.EncodeToString(sk.Seed()))
	return priv, FormatPublicKey(pk, comment), nil
}

// TrustedKeys returns the compiled-in keys plus any in root's TrustedKeysDir.
func TrustedKeys(root string) []PublicKey {
	var keys []PublicKey
	add := func(data []byte) {
		for _, line := range strings.Split(string(data), "\n") {
			if k, err := ParsePublicKey(line); err == nil {
				keys = append(keys, k)
			}
		}
	}
	_ = fs.WalkDir(embeddedKeys, "keys", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".pub") {
			if b, err := embeddedKeys.ReadFile(p); err == nil {
				add(b)
			}
		}
		return nil
	})
	if root != "" {
		matches, _ := filepath.Glob(filepath.Join(root, TrustedKeysDir, "*.pub"))
		for _, m := range matches {
			if b, err := os.ReadFile(m); err == nil {
				add(b)
			}
		}
	}
	return keys
}

// Writing -------------------------------------------------------------------

// CreateBundle writes a signed bundle for the system image at rootfsPath.
func CreateBundle(w io.Writer, priv ed25519.PrivateKey, version, arch, notes, rootfsPath string) (*Manifest, error) {
	f, err := os.Open(rootfsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return nil, err
	}
	m := &Manifest{
		Format: BundleFormat, Version: version, Arch: arch, Created: time.Now().UTC().Truncate(time.Second), Notes: notes,
		RootFS: FileRef{Name: rootfsName, Size: size, SHA256: hex.EncodeToString(h.Sum(nil))},
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, mb)) + "\n")

	tw := tar.NewWriter(w)
	for _, e := range []struct {
		name string
		data []byte
	}{{manifestName, mb}, {sigName, sig}} {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), ModTime: m.Created, Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(e.data); err != nil {
			return nil, err
		}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	if err := tw.WriteHeader(&tar.Header{Name: rootfsName, Mode: 0o644, Size: size, ModTime: m.Created, Format: tar.FormatPAX}); err != nil {
		return nil, err
	}
	if _, err := io.Copy(tw, f); err != nil {
		return nil, err
	}
	return m, tw.Close()
}

// Reading -------------------------------------------------------------------

// ErrUntrusted means the bundle isn't signed by a trusted key.
var ErrUntrusted = errors.New("this update isn't signed by a trusted HardyOS release key")

// ReadManifest reads and verifies a bundle's manifest without extracting the
// image.
func ReadManifest(path string, keys []PublicKey) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m, _, err := readHead(tar.NewReader(f), keys)
	return m, err
}

// Extract verifies a bundle and writes its system image to dst, checking
// the image's size and SHA-256 against the signed manifest. On any error dst
// is removed.
func Extract(path string, keys []PublicKey, dst string) (m *Manifest, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	m, hdr, err := readHead(tr, keys)
	if err != nil {
		return nil, err
	}
	if hdr.Size != m.RootFS.Size {
		return nil, fmt.Errorf("system image is %d bytes, the manifest says %d", hdr.Size, m.RootFS.Size)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(dst)
		}
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(tr, m.RootFS.Size+1))
	if err != nil {
		return nil, fmt.Errorf("read system image: %w", err)
	}
	if n != m.RootFS.Size {
		return nil, errors.New("the update file is truncated")
	}
	if hex.EncodeToString(h.Sum(nil)) != m.RootFS.SHA256 {
		return nil, errors.New("the system image doesn't match the signed manifest (corrupted or modified)")
	}
	return m, nil
}

// readHead reads manifest.json and manifest.sig, verifies the signature and
// returns the header of the following system image entry.
func readHead(tr *tar.Reader, keys []PublicKey) (*Manifest, *tar.Header, error) {
	next := func(want string, limit int64) (*tar.Header, []byte, error) {
		hdr, err := tr.Next()
		if err != nil {
			return nil, nil, fmt.Errorf("not a HardyOS update file (%v)", err)
		}
		if hdr.Name != want || hdr.Typeflag != tar.TypeReg {
			return nil, nil, fmt.Errorf("not a HardyOS update file (found %q, expected %q)", hdr.Name, want)
		}
		if limit == 0 {
			return hdr, nil, nil
		}
		if hdr.Size > limit {
			return nil, nil, fmt.Errorf("%s is too large", want)
		}
		b, err := io.ReadAll(io.LimitReader(tr, limit))
		return hdr, b, err
	}
	_, mb, err := next(manifestName, 64<<10)
	if err != nil {
		return nil, nil, err
	}
	_, sb, err := next(sigName, 1<<10)
	if err != nil {
		return nil, nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sb)))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, errors.New("the update's signature is malformed")
	}
	trusted := false
	for _, k := range keys {
		if ed25519.Verify(k.Key, mb, sig) {
			trusted = true
			break
		}
	}
	if !trusted {
		return nil, nil, ErrUntrusted
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(mb))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, nil, fmt.Errorf("the update's manifest is invalid: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, nil, err
	}
	hdr, _, err := next(rootfsName, 0)
	if err != nil {
		return nil, nil, err
	}
	return &m, hdr, nil
}
