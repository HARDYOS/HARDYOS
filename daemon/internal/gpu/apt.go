package gpu

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// The packages HardyOS installs for NVIDIA cards: Debian's driver (non-free,
// built with DKMS for each kernel), the libraries Docker apps use through
// the container toolkit (CUDA, NVENC/NVDEC video), and NVIDIA's container
// toolkit from NVIDIA's own repository. Data, not code: a Debian release
// that renames a package only changes this list.
var DriverPackages = []string{
	"nvidia-driver", "nvidia-kernel-dkms", "firmware-nvidia-gsp", "firmware-misc-nonfree",
	"nvidia-smi", "nvidia-persistenced", "libcuda1", "libnvidia-encode1", "libnvcuvid1",
	"nvidia-container-toolkit",
}

// NVIDIA's container toolkit repository and its signing key, pinned: the
// key ships inside HardyOS and its fingerprint is checked before use.
const (
	ToolkitRepo           = "https://nvidia.github.io/libnvidia-container/stable/deb"
	ToolkitKeyFingerprint = "C95B321B61E88C1809C4F759DDCAE044F796ECB0"
	toolkitKeyPath        = "/etc/apt/keyrings/hardyos-nvidia-container-toolkit.asc"
	toolkitListPath       = "/etc/apt/sources.list.d/hardyos-nvidia-container-toolkit.list"
	nonFreeSourcesPath    = "/etc/apt/sources.list.d/hardyos-non-free.sources"
	toolkitPinPath        = "/etc/apt/preferences.d/hardyos-nvidia-container-toolkit"
)

// ToolkitPackages are the only packages taken from NVIDIA's repository.
// Everything else it offers is pinned away (priority -1), so the
// repository can never replace one of Debian's packages, or HardyOS's.
var ToolkitPackages = []string{
	"nvidia-container-toolkit", "nvidia-container-toolkit-base",
	"libnvidia-container1", "libnvidia-container-tools",
}

// toolkitPin is the apt preferences file: the toolkit packages from
// nvidia.github.io at the normal priority, nothing else from there. The
// package-specific record comes first; apt prefers it over the general one.
func toolkitPin() string {
	return fmt.Sprintf(`# Added by HardyOS: only NVIDIA's container toolkit comes from NVIDIA's repository.
Package: %s
Pin: origin "nvidia.github.io"
Pin-Priority: 500

Package: *
Pin: origin "nvidia.github.io"
Pin-Priority: -1
`, strings.Join(ToolkitPackages, " "))
}

//go:embed keys/nvidia-container-toolkit.asc
var toolkitKey []byte

// aptEnv makes apt and dpkg ask nothing.
var aptEnv = []string{"DEBIAN_FRONTEND=noninteractive"}

// aptInstallArgs installs packages keeping existing config files.
func aptInstallArgs(extra ...string) []string {
	return append([]string{"-y", "--no-install-recommends", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold", "install"}, extra...)
}

var codenameRE = regexp.MustCompile(`^[a-z]{2,20}$`)

// codename is the Debian release of the system at sysRoot.
func codename(sysRoot string) string {
	f, err := os.Open(filepath.Join(sysRoot, "etc/os-release"))
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "VERSION_CODENAME="); ok {
				v = strings.Trim(v, `"`)
				if codenameRE.MatchString(v) {
					return v
				}
			}
		}
	}
	return "trixie"
}

func debArch(goarch string) string {
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	switch goarch {
	case "amd64", "arm64":
		return goarch
	}
	return goarch
}

// hasNonFree reports whether the system's apt sources already include
// Debian's non-free component.
func hasNonFree(sysRoot string) bool {
	files, _ := filepath.Glob(filepath.Join(sysRoot, "etc/apt/sources.list.d/*"))
	files = append(files, filepath.Join(sysRoot, "etc/apt/sources.list"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			var fields []string
			switch {
			case strings.HasSuffix(f, ".sources") && strings.HasPrefix(line, "Components:"):
				fields = strings.Fields(strings.TrimPrefix(line, "Components:"))
			case !strings.HasSuffix(f, ".sources") && strings.HasPrefix(line, "deb "):
				fields = strings.Fields(line)
			}
			for _, x := range fields {
				if x == "non-free" {
					return true
				}
			}
		}
	}
	return false
}

// writeSources sets up apt at sysRoot for the NVIDIA packages: Debian's
// non-free component (only if missing) and NVIDIA's toolkit repository
// with its pinned key.
func writeSources(sysRoot, arch string) error {
	fp, err := keyFingerprint(toolkitKey)
	if err != nil {
		return fmt.Errorf("the NVIDIA repository key built into HardyOS can't be read: %w", err)
	}
	if fp != ToolkitKeyFingerprint {
		return fmt.Errorf("the NVIDIA repository key built into HardyOS has fingerprint %s, not %s", fp, ToolkitKeyFingerprint)
	}
	put := func(p string, data []byte) error {
		full := filepath.Join(sysRoot, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if old, err := os.ReadFile(full); err == nil && bytes.Equal(old, data) {
			return nil
		}
		tmp := full + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, full)
	}
	if !hasNonFree(sysRoot) {
		c := codename(sysRoot)
		src := fmt.Sprintf(`# Added by HardyOS for the NVIDIA driver (Debian's non-free component).
Types: deb
URIs: http://deb.debian.org/debian
Suites: %[1]s %[1]s-updates
Components: non-free
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://security.debian.org/debian-security
Suites: %[1]s-security
Components: non-free
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
`, c)
		if err := put(nonFreeSourcesPath, []byte(src)); err != nil {
			return err
		}
	}
	if err := put(toolkitKeyPath, toolkitKey); err != nil {
		return err
	}
	if err := put(toolkitPinPath, []byte(toolkitPin())); err != nil {
		return err
	}
	list := fmt.Sprintf("# Added by HardyOS: NVIDIA's container toolkit (key %s).\ndeb [signed-by=%s] %s/%s /\n", ToolkitKeyFingerprint, toolkitKeyPath, ToolkitRepo, debArch(arch))
	return put(toolkitListPath, []byte(list))
}

// removeSources undoes writeSources' NVIDIA repository (the non-free
// component stays: other firmware may come from it).
func removeSources(sysRoot string) {
	_ = os.Remove(filepath.Join(sysRoot, toolkitListPath))
	_ = os.Remove(filepath.Join(sysRoot, toolkitKeyPath))
	_ = os.Remove(filepath.Join(sysRoot, toolkitPinPath))
}

// keyFingerprint is the v4 fingerprint of the first public key in an
// ASCII-armored OpenPGP block: SHA-1 over 0x99, the key packet's two-byte
// length and the packet body (RFC 4880 12.2).
func keyFingerprint(armored []byte) (string, error) {
	var b64 strings.Builder
	in := false
	for _, line := range strings.Split(string(armored), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "-----BEGIN PGP PUBLIC KEY BLOCK"):
			in = true
		case strings.HasPrefix(line, "-----END"):
			in = false
		case !in, strings.Contains(line, ": "), line == "":
		case strings.HasPrefix(line, "="):
			in = false // the CRC line
		default:
			b64.WriteString(line)
		}
	}
	data, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		return "", err
	}
	if len(data) < 3 || data[0]&0x80 == 0 {
		return "", errors.New("not an OpenPGP packet")
	}
	var tag, hdr, n int
	if data[0]&0x40 != 0 { // new format
		tag = int(data[0] & 0x3f)
		switch l := int(data[1]); {
		case l < 192:
			n, hdr = l, 2
		case l < 224:
			n, hdr = ((l-192)<<8)+int(data[2])+192, 3
		case l == 255 && len(data) >= 6:
			n, hdr = int(binary.BigEndian.Uint32(data[2:6])), 6
		default:
			return "", errors.New("unsupported packet length")
		}
	} else { // old format
		tag = int(data[0]>>2) & 0x0f
		switch data[0] & 3 {
		case 0:
			n, hdr = int(data[1]), 2
		case 1:
			n, hdr = int(binary.BigEndian.Uint16(data[1:3])), 3
		case 2:
			if len(data) < 5 {
				return "", errors.New("short packet")
			}
			n, hdr = int(binary.BigEndian.Uint32(data[1:5])), 5
		default:
			return "", errors.New("indeterminate packet length")
		}
	}
	if tag != 6 || hdr+n > len(data) || n > 0xffff {
		return "", errors.New("no public key packet")
	}
	body := data[hdr : hdr+n]
	if body[0] != 4 {
		return "", fmt.Errorf("key version %d isn't supported", body[0])
	}
	h := sha1.New()
	h.Write([]byte{0x99, byte(n >> 8), byte(n)})
	h.Write(body)
	return strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil))), nil
}
