package vms

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"text/template"
	"time"
	"unicode/utf16"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// Game streaming set up by HardyOS (decisions 400-409, docs/plans/streaming.md).
//
// A gaming VM's unattended Windows install can also install Sunshine and a
// virtual display driver at the first sign-in. Root downloads both into
// the pool's catalog store (pinned by version and SHA-256, catalog.go),
// and puts them on a per-VM read-only disc (HARDYOS_STREAM) together with
// a setup script HardyOS ships, the Sunshine web UI account hardyd chose
// (a random password hardyd keeps sealed) and a TLS key and certificate
// root made for this VM's Sunshine. hardyd pins that certificate whenever
// it talks to Sunshine's API (pairing), so nothing else on the network can
// pose as the VM's Sunshine. Like the Windows answer disc, the streaming
// disc lives in /run/hardyos-unattend only (in no dataset, snapshot,
// replica or backup) and is deleted when the install ends.

// Streaming is a VM's game streaming settings. Only root changes them:
// Sunshine, User and CertSHA256 when the VM is made, Remote with
// vms.streaming.publish; updates keep them.
type Streaming struct {
	// Remote publishes Sunshine's streaming ports to NetBird peers
	// (streamfwd.go). Changed only with vms.streaming.publish.
	Remote bool `json:"remote"`
	// Sunshine: HardyOS installed and set up Sunshine in the VM.
	Sunshine bool `json:"sunshine,omitempty"`
	// User is the Sunshine web UI account (its password is hardyd's,
	// sealed); CertSHA256 the SHA-256 of Sunshine's certificate (DER).
	User       string `json:"user,omitempty"`
	CertSHA256 string `json:"certSHA256,omitempty"`
	// Peers are the NetBird devices (addresses) the streaming ports are
	// forwarded from; none until the administrator chooses (decision 404).
	Peers []string `json:"peers,omitempty"`
	// WebUIFrom is the server's home network address the VM's firewall
	// lets reach Sunshine's web page and API (decision 401).
	WebUIFrom string `json:"webUIFrom,omitempty"`
}

// Pinned streaming downloads (decision 402). A new version is a change to
// these lines (and the CI job that downloads them checks the hashes).
const (
	CatalogSunshine = "sunshine"
	CatalogVDD      = "virtual-display"

	SunshineVersion = "v2026.914.233613"
	VDDVersion      = "25.7.23"

	sunshineAMD64SHA256 = "1d7fed8beecd5889dc7ff14cf9f42d6d38f37c3066c13c6c2a5f4e91847e0ccf"
	sunshineARM64SHA256 = "1e211404b924fcf421657c71e1aaa95cf1f76e172cacf8ff8430beacc0e30e4a"
	vddX64SHA256        = "e24210692b442b39af763536330ce78b423f19342b7a7792c26de3944e418b3a"
	vddARM64SHA256      = "dcd487161469c726bab60f174a7e7f70ee02afd437cad0d5c0e6755953de5a25"
	// VDDSignerSHA1 is the Windows thumbprint (SHA-1 of the certificate)
	// of the driver catalogs' signer; the setup script trusts only it,
	// and CI checks it against the downloaded catalogs.
	VDDSignerSHA1 = "0000000000000000000000000000000000000000"

	// MediaStreaming is the per-VM streaming disc.
	MediaStreaming = "streaming"
	// StreamingHook is the first-logon step that runs its setup script.
	StreamingHook = "sunshine"
	// StreamingLabel is the disc's volume label; the hook finds the disc
	// by it, never by a drive letter.
	StreamingLabel = "HARDYOS_STREAM"
	// SunshineUser is the web UI account HardyOS makes.
	SunshineUser = "hardyos"
)

var githubHosts = []string{"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}

// streamingCatalog are the catalog entries (Kind file: never a disk or a
// disc a VM gets, only what goes onto the streaming disc).
var streamingCatalog = []CatalogImage{
	{
		ID: CatalogSunshine, Name: "Sunshine " + SunshineVersion + " for Windows (LizardByte)", Kind: "file",
		Hosts: githubHosts, Verified: "SHA-256 pinned in HardyOS",
		Files: map[string]CatalogFile{
			"x86_64": {
				URL:    "https://github.com/LizardByte/Sunshine/releases/download/" + SunshineVersion + "/Sunshine-Windows-AMD64-installer.msi",
				File:   "sunshine-" + SunshineVersion + "-amd64.msi",
				SHA256: sunshineAMD64SHA256,
			},
			"aarch64": {
				URL:    "https://github.com/LizardByte/Sunshine/releases/download/" + SunshineVersion + "/Sunshine-Windows-ARM64-installer.msi",
				File:   "sunshine-" + SunshineVersion + "-arm64.msi",
				SHA256: sunshineARM64SHA256,
			},
		},
	},
	{
		ID: CatalogVDD, Name: "Virtual Display Driver " + VDDVersion + " (VirtualDrivers, MIT)", Kind: "file",
		Hosts: githubHosts, Verified: "SHA-256 pinned in HardyOS",
		Files: map[string]CatalogFile{
			// The project calls its x64 driver package "x86".
			"x86_64": {
				URL:    "https://github.com/VirtualDrivers/Virtual-Display-Driver/releases/download/" + VDDVersion + "/VirtualDisplayDriver-x86.Driver.Only.zip",
				File:   "vdd-" + VDDVersion + "-x64.zip",
				SHA256: vddX64SHA256,
			},
			"aarch64": {
				URL:    "https://github.com/VirtualDrivers/Virtual-Display-Driver/releases/download/" + VDDVersion + "/VirtualDisplayDriver-ARM64.Driver.Only.zip",
				File:   "vdd-" + VDDVersion + "-arm64.zip",
				SHA256: vddARM64SHA256,
			},
		},
	},
}

// StreamingCommand runs the setup script from the one drive labelled
// HARDYOS_STREAM (none or two: nothing runs), only if the script's SHA-256
// is the one HardyOS made for this architecture.
func StreamingCommand(scriptSHA256 string) string {
	return `powershell -NoProfile -ExecutionPolicy Bypass -Command "$v = @(Get-Volume | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.FileSystemLabel -eq '` + StreamingLabel +
		`' }); if ($v.Count -eq 1) { $f = $v[0].DriveLetter + ':\setup.ps1'; if ((Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash -eq '` + scriptSHA256 + `') { & $f } }"`
}

// catalogArch is the catalog's name for a Windows architecture.
func catalogArch(winArch string) string {
	if winArch == "arm64" {
		return "aarch64"
	}
	return "x86_64"
}

func init() {
	RegisterFirstLogonHook(StreamingHook, func(vm HookVM) []LogonCommand {
		script, err := setupScriptFor(catalogArch(vm.Arch))
		if err != nil {
			return nil
		}
		sum := sha256.Sum256(script)
		return []LogonCommand{{Description: "Game streaming: Sunshine and a virtual display (HardyOS)", CommandLine: StreamingCommand(hex.EncodeToString(sum[:]))}}
	})
}

//go:embed streaming_setup.ps1.tmpl
var setupScriptTmpl string

var setupScript = template.Must(template.New("setup").Parse(setupScriptTmpl))

var (
	streamUserRE = regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`)
	hex64RE      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// streamPassRE: what hardyd's generator makes; safe on a Windows
	// command line and in JSON without any quoting.
	streamPassRE = regexp.MustCompile(`^[A-Za-z0-9]{20,128}$`)
)

// problems checks the streaming settings (Validate).
func (st *Streaming) problems(s *Spec) []string {
	var p []string
	if st.User != "" && !streamUserRE.MatchString(st.User) {
		p = append(p, "the Sunshine account name isn't valid")
	}
	if st.CertSHA256 != "" && !hex64RE.MatchString(st.CertSHA256) {
		p = append(p, "the Sunshine certificate's fingerprint isn't a SHA-256")
	}
	if st.Sunshine && s.OS != "windows" {
		p = append(p, "HardyOS sets Sunshine up in Windows VMs only")
	}
	if len(st.Peers) > MaxStreamPeers {
		p = append(p, fmt.Sprintf("game streaming goes to at most %d NetBird devices", MaxStreamPeers))
	}
	for _, a := range st.Peers {
		if ip, err := netip.ParseAddr(a); err != nil || !ip.Is4() || ip.String() != a {
			p = append(p, fmt.Sprintf("%q isn't a NetBird device's address", a))
		}
	}
	if st.WebUIFrom != "" {
		if ip, err := netip.ParseAddr(st.WebUIFrom); err != nil || !ip.Is4() || !ip.IsPrivate() || ip.String() != st.WebUIFrom {
			p = append(p, "the server's home network address for Sunshine isn't a private IPv4 address")
		}
	}
	return p
}

// HasStreamingMedia reports whether the streaming disc is in a drive.
func (s *Spec) HasStreamingMedia() bool {
	for _, md := range s.Media {
		if md.Kind == MediaStreaming {
			return true
		}
	}
	return false
}

// StreamingSetUp reports a VM whose Sunshine HardyOS set up.
func (s *Spec) StreamingSetUp() bool { return s.Streaming != nil && s.Streaming.Sunshine }

func streamingPath(s *Spec) string {
	return filepath.Join(UnattendRunDir, s.UUID+"-stream.iso")
}

func withoutMedia(media []Media, kind string) []Media {
	out := []Media{}
	for _, md := range media {
		if md.Kind != kind {
			out = append(out, md)
		}
	}
	return out
}

// streamKit is what root makes for a VM's Sunshine.
type streamKit struct {
	certPEM, keyPEM []byte
	password        string
}

// streamingNIC is the VM's card on the home network that streaming uses:
// its first card, bridged, with the anti-spoofing filter on (so the VM
// can't answer for another computer's address; decision 404).
func streamingNIC(s *Spec) (NIC, error) {
	if len(s.NICs) == 0 || s.NICs[0].Mode != NICBridge || s.NICs[0].AllowSpoofing {
		return NIC{}, Problems{"game streaming needs the VM's first network card on the home network (not NAT or a VLAN) with address spoofing off"}
	}
	return s.NICs[0], nil
}

// prepareStreaming fills in a new VM's streaming settings: the account,
// the first-logon step, the disc, and a fresh key and certificate for
// Sunshine (whose fingerprint hardyd pins).
func (m *Manager) prepareStreaming(ctx context.Context, s *Spec, password string) (*streamKit, error) {
	if !s.StreamingSetUp() {
		if s.HasStreamingMedia() {
			return nil, Problems{"the streaming disc only comes with game streaming set up by HardyOS"}
		}
		if s.Unattend != nil && slices.Contains(s.Unattend.Hooks, StreamingHook) {
			return nil, Problems{"the Sunshine first-logon step only comes with game streaming set up by HardyOS"}
		}
		if s.Streaming != nil {
			s.Streaming = nil // the rest is root's to set
		}
		return nil, nil
	}
	var p Problems
	if s.OS != "windows" || s.Unattend == nil {
		p = append(p, "HardyOS sets Sunshine up during an unattended Windows install; turn on Install by itself")
	}
	if _, err := streamingNIC(s); err != nil {
		p = append(p, err.(Problems)...)
	}
	if !streamPassRE.MatchString(password) {
		p = append(p, "the Sunshine password must be 20 to 128 letters and digits (hardyd makes it)")
	}
	if len(p) > 0 {
		return nil, p
	}
	if !s.HasStreamingMedia() {
		s.Media = append(s.Media, Media{Kind: MediaStreaming})
	}
	if !slices.Contains(s.Unattend.Hooks, StreamingHook) {
		s.Unattend.Hooks = append(s.Unattend.Hooks, StreamingHook)
	}
	for _, id := range []string{CatalogSunshine, CatalogVDD} {
		if _, err := m.catalogFilePath(ctx, s.Pool, id); err != nil {
			return nil, err
		}
	}
	// The server's own address on the home network: the only one (with the
	// VM itself) Sunshine's web page and API answer (decision 401).
	if m.Network == nil || m.Network.BridgeName() == "" {
		return nil, Problems{"the home network's bridge isn't set up yet"}
	}
	brAddr, err := m.bridgeIPv4(ctx, m.Network.BridgeName())
	if err != nil || !brAddr.Addr().IsPrivate() {
		return nil, Problems{"game streaming needs this server to have a private IPv4 address on the home network's bridge"}
	}
	certPEM, keyPEM, fp, err := newSunshineCert(m.now())
	if err != nil {
		return nil, err
	}
	s.Streaming = &Streaming{Sunshine: true, User: SunshineUser, CertSHA256: fp, WebUIFrom: brAddr.Addr().String()}
	return &streamKit{certPEM: certPEM, keyPEM: keyPEM, password: password}, nil
}

// newSunshineCert makes the RSA key and self-signed certificate Sunshine
// uses for its web UI and Moonlight pairing (Sunshine makes the same kind
// itself: RSA 2048, long-lived). It returns the certificate's SHA-256.
func newSunshineCert(now time.Time) (certPEM, keyPEM []byte, fp string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, nil, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Sunshine Gamestream Host"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(20, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", err
	}
	sum := sha256.Sum256(der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		hex.EncodeToString(sum[:]), nil
}

// catalogFilePath is a verified catalog file (kind file) on the pool.
func (m *Manager) catalogFilePath(ctx context.Context, pool, id string) (string, error) {
	img, cf, err := m.catalogFile(id)
	if err != nil {
		return "", err
	}
	if img.Kind != "file" || cf.SHA256 == "" {
		return "", fmt.Errorf("%s isn't a pinned file", id)
	}
	c, err := m.store(ctx, pool, false)
	if err != nil {
		return "", Problems{img.Name + " isn't downloaded and checked on " + pool + " yet"}
	}
	r, err := m.openStore(c)
	if err != nil {
		return "", err
	}
	defer r.Close()
	if err := checkStamp(r, cf.File, digest{Algo: "sha256", Hex: cf.SHA256}, cf.Size); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", Problems{img.Name + " isn't downloaded and checked on " + pool + " yet"}
		}
		return "", Problems{img.Name + " isn't ready: " + err.Error()}
	}
	return filepath.Join(c.dir, cf.File), nil
}

// SetupScriptVars are what the setup script is made from: constants only
// (per-VM values are in hardyos-streaming.json on the disc, checked by the
// script), so its SHA-256 per architecture is known to the first-logon
// command.
type SetupScriptVars struct {
	Label, VDDSigner                              string
	SunshineVersion, SunshineFile, SunshineSHA256 string
	VDDVersion, VDDFile, VDDSHA256                string
}

var (
	scriptFileRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	sha1HexRE    = regexp.MustCompile(`^[0-9A-F]{40}$`)
)

// SetupScript is the PowerShell script on the streaming disc.
func SetupScript(v SetupScriptVars) ([]byte, error) {
	for _, s := range []string{v.Label, v.SunshineFile, v.VDDFile, v.SunshineVersion, v.VDDVersion} {
		if !scriptFileRE.MatchString(s) {
			return nil, fmt.Errorf("%q can't go into the setup script", s)
		}
	}
	for _, s := range []string{v.SunshineSHA256, v.VDDSHA256} {
		if !hex64RE.MatchString(s) {
			return nil, errors.New("the setup script needs SHA-256 checksums")
		}
	}
	if !sha1HexRE.MatchString(v.VDDSigner) {
		return nil, errors.New("the setup script needs the driver signer's thumbprint")
	}
	var b bytes.Buffer
	if err := setupScript.Execute(&b, v); err != nil {
		return nil, err
	}
	// Windows PowerShell 5 reads a script without a byte order mark as
	// the system code page; it's ASCII anyway, so CRLF is all it needs.
	return bytes.ReplaceAll(b.Bytes(), []byte("\n"), []byte("\r\n")), nil
}

// setupScriptFor is the setup script for an architecture (catalog name),
// from the pinned streaming catalog: the same bytes for the disc and for
// the first-logon command's checksum.
func setupScriptFor(arch string) ([]byte, error) {
	var sf, vf CatalogFile
	for _, c := range streamingCatalog {
		f, ok := c.Files[arch]
		if !ok {
			return nil, fmt.Errorf("game streaming isn't available for %s", arch)
		}
		switch c.ID {
		case CatalogSunshine:
			sf = f
		case CatalogVDD:
			vf = f
		}
	}
	return SetupScript(SetupScriptVars{
		Label: StreamingLabel, VDDSigner: VDDSignerSHA1,
		SunshineVersion: SunshineVersion, SunshineFile: sf.File, SunshineSHA256: sf.SHA256,
		VDDVersion: VDDVersion, VDDFile: vf.File, VDDSHA256: vf.SHA256,
	})
}

// streamingFiles are the streaming disc's own files (besides the two
// downloads), for writeStreaming and tests.
func (m *Manager) streamingFiles(s *Spec, kit *streamKit) (map[string][]byte, error) {
	script, err := setupScriptFor(m.arch().Arch)
	if err != nil {
		return nil, err
	}
	if ValidID(s.ID) != nil || s.Streaming == nil || s.Streaming.WebUIFrom == "" {
		return nil, errors.New("the VM's streaming settings aren't complete")
	}
	acct, _ := json.Marshal(map[string]string{"user": s.Streaming.User, "password": kit.password})
	vm, _ := json.Marshal(map[string]string{"name": s.ID, "server": s.Streaming.WebUIFrom})
	return map[string][]byte{
		"setup.ps1":              script,
		"hardyos-streaming.json": vm,
		"sunshine-cert.pem":      kit.certPEM,
		"sunshine-key.pem":       kit.keyPEM,
		"sunshine-account.json":  acct,
	}, nil
}

// writeStreaming makes the VM's streaming disc, the way writeUnattend
// makes the answer disc: in a 0700 staging folder, QEMU's own 0600 file
// before it's in place. The two downloads are read from the catalog
// store, checked against their pinned SHA-256 record first.
func (m *Manager) writeStreaming(ctx context.Context, st *stored, kit *streamKit) error {
	files, err := m.streamingFiles(&st.spec, kit)
	if err != nil {
		return err
	}
	var grafts []string
	for _, id := range []string{CatalogSunshine, CatalogVDD} {
		p, err := m.catalogFilePath(ctx, st.spec.Pool, id)
		if err != nil {
			return err
		}
		grafts = append(grafts, "/"+filepath.Base(p)+"="+p)
	}
	dir, err := m.unattendDir()
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(dir, ".stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o700); err != nil {
		return err
	}
	in := filepath.Join(stage, "in")
	if err := os.Mkdir(in, 0o700); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(in, n), files[n], 0o600); err != nil {
			return err
		}
	}
	rel := filepath.Join(UnattendRunDir, filepath.Base(stage))
	if _, err := m.run(ctx, "xorriso", streamingDiscArgs(filepath.Join(rel, "out.iso"), filepath.Join(rel, "in"), grafts)...); err != nil {
		return fmt.Errorf("making the game streaming disc: %w", err)
	}
	out := filepath.Join(stage, "out.iso")
	if err := m.ownSeed(out); err != nil {
		return err
	}
	return os.Rename(out, m.sys(streamingPath(&st.spec)))
}

// streamingDiscArgs are xorriso's arguments for the disc: the folder's
// files at the top, and each graft ("/name=path") as a file of that name.
func streamingDiscArgs(out, in string, grafts []string) []string {
	args := []string{"-as", "mkisofs", "-quiet", "-volid", StreamingLabel, "-joliet", "-rock",
		"-output", out, "-graft-points", "/=" + in}
	return append(args, grafts...)
}

// removeStreaming deletes the streaming disc (it holds the Sunshine
// password and key).
func (m *Manager) removeStreaming(st *stored) {
	if st.spec.UUID == "" {
		return
	}
	if err := os.Remove(m.sys(streamingPath(&st.spec))); err != nil && !os.IsNotExist(err) {
		m.log().Warn("vms: deleting the game streaming disc", "id", st.spec.ID, "err", err)
	}
}

// checkStreamingDisc makes sure the streaming disc is QEMU's own file.
func (m *Manager) checkStreamingDisc(s *Spec) error {
	p := m.sys(streamingPath(s))
	fi, err := os.Lstat(p)
	if err != nil {
		return Problems{"the game streaming disc is gone (it's kept in memory, and the server restarted); take it out of the VM in Hardware, then install Sunshine by hand (see Game streaming on the VM's page)"}
	}
	if !fi.Mode().IsRegular() {
		return errors.New("the game streaming disc isn't a file")
	}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok && rootfile.Enforce && (sys.Nlink != 1 || !m.qemuOwned(seedFile, sys.Uid)) {
		return errors.New("the game streaming disc isn't QEMU's own file")
	}
	return m.ownSeed(p)
}

// isoHasLabel reports whether an ISO 9660 image's primary or any
// supplementary (Joliet) volume descriptor names label (case and padding
// ignored), the way Windows shows a disc's label.
func isoHasLabel(f io.ReaderAt, label string) bool {
	want := strings.ToUpper(label)
	buf := make([]byte, 2048)
	for i := 16; i < 16+32; i++ {
		if _, err := f.ReadAt(buf, int64(i)*2048); err != nil {
			return false
		}
		if string(buf[1:6]) != "CD001" {
			return false
		}
		switch buf[0] {
		case 255: // terminator
			return false
		case 1: // primary: d-characters
			if strings.ToUpper(strings.TrimRight(string(buf[40:72]), " \x00")) == want {
				return true
			}
		case 2: // supplementary: Joliet is UCS-2 big endian
			raw := buf[40:72]
			u := make([]uint16, 0, 16)
			for j := 0; j+1 < len(raw); j += 2 {
				u = append(u, uint16(raw[j])<<8|uint16(raw[j+1]))
			}
			if strings.ToUpper(strings.TrimRight(string(utf16.Decode(u)), " \x00")) == want {
				return true
			}
		}
	}
	return false
}
