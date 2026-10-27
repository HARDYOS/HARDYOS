// Package apps installs and runs Docker apps on HardyOS.
//
// An app arrives as a .hardyapp package: a gzipped tar holding hardyapp.json
// (the manifest), compose.yaml (a Docker Compose file) and an icon. hardyd
// reads packages to show them in the App Store; hardyd-priv reads the package
// again, resolves the compose file with Docker Compose, checks the result
// against the permissions the manifest declares (see policy.go) and only then
// runs it. See docs/apps.md for the format.
package apps

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Package limits. A package is a manifest, a compose file and an icon, so it
// stays small; the limits keep it well inside one root-helper request.
const (
	MaxPackageBytes  = 512 << 10 // compressed
	maxUnpackedBytes = 2 << 20
	maxIconBytes     = 128 << 10
	maxComposeBytes  = 256 << 10
	maxManifestBytes = 64 << 10

	// ManifestFile, ComposeFile: required members of a package.
	ManifestFile = "hardyapp.json"
	ComposeFile  = "compose.yaml"

	// FormatVersion is the manifest format this build understands.
	FormatVersion = 1
)

// optional members kept for people reading the package; HardyOS ignores them.
var optionalFiles = map[string]bool{"README.md": true, "LICENSE": true, "LICENSE.txt": true}

// Manifest describes an app (hardyapp.json).
type Manifest struct {
	Format      int    `json:"format"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Summary     string `json:"summary"`
	Description string `json:"description,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	Website     string `json:"website,omitempty"`
	// Icon names an .svg or .png file in the package.
	Icon string `json:"icon,omitempty"`
	// Arch lists the CPU architectures the images exist for ("amd64",
	// "arm64"). Empty means any.
	Arch []string `json:"arch,omitempty"`
	// MinMemoryMB warns when the server has less memory than the app needs.
	MinMemoryMB int `json:"minMemoryMB,omitempty"`
	// Web is the page the App Store's Open button goes to.
	Web *Web `json:"web,omitempty"`
	// Ports the app publishes on the server. The compose file uses
	// ${HARDY_PORT_<NAME>} for each, and may publish no other ports.
	Ports []Port `json:"ports,omitempty"`
	// Settings become environment variables for the compose file.
	Settings []Setting `json:"settings,omitempty"`
	// Folders are created under ${HARDY_APP_DATA} before the app first starts,
	// with the owner the containers run as.
	Folders []Folder `json:"folders,omitempty"`
	// Shares are shared folders the app can be given (chosen at install).
	// The compose file binds ${HARDY_SHARE_<NAME>}.
	Shares []ShareMount `json:"shares,omitempty"`
	// Permissions beyond a plain container. Anything not declared here is refused.
	Permissions Permissions `json:"permissions,omitempty"`
}

// Web is where the app's web page is.
type Web struct {
	Port   string `json:"port"`             // name of one of Ports
	Path   string `json:"path,omitempty"`   // default "/"
	Scheme string `json:"scheme,omitempty"` // "http" (default) or "https"
}

// Port is a port the app publishes on the server.
type Port struct {
	Name     string `json:"name"` // WEB -> ${HARDY_PORT_WEB}
	Label    string `json:"label"`
	Default  int    `json:"default"`
	Protocol string `json:"protocol,omitempty"` // "tcp" (default) or "udp"
}

// Setting is one environment variable the compose file can use.
type Setting struct {
	Env      string   `json:"env"`
	Label    string   `json:"label,omitempty"`
	Help     string   `json:"help,omitempty"`
	Type     string   `json:"type,omitempty"` // text (default), number, boolean, select, password
	Default  string   `json:"default,omitempty"`
	Options  []string `json:"options,omitempty"`
	Required bool     `json:"required,omitempty"`
	// Generate "secret": HardyOS makes a random value on first install and
	// keeps it on reinstalls and updates. It is never shown or asked for.
	Generate string `json:"generate,omitempty"`
	// Managed: another part of HardyOS sets it (Photos turns Immich's
	// accelerated machine learning on), not the install form. It's an
	// ordinary setting otherwise: checked against its type and options,
	// kept across updates, changed with apps.reconfigure.
	Managed bool `json:"managed,omitempty"`
}

// Hidden reports whether the install form leaves this setting out.
func (s Setting) Hidden() bool { return s.Generate != "" || s.Managed }

// Secret reports whether the value must stay out of job history, logs and the API.
func (s Setting) Secret() bool { return s.Generate != "" || s.Type == "password" }

// Folder is created inside the app's data folder before it first starts.
type Folder struct {
	Path  string `json:"path"`            // relative to ${HARDY_APP_DATA}
	Owner string `json:"owner,omitempty"` // "uid:gid", default the app's own user (HARDY_UID)
	Mode  string `json:"mode,omitempty"`  // octal, default "0755"
}

// Permissions are what an app may use beyond a plain container.
type Permissions struct {
	Capabilities []string `json:"capabilities,omitempty"`
	Devices      []string `json:"devices,omitempty"`
	// HostNetwork lets services use network_mode: host.
	HostNetwork bool `json:"hostNetwork,omitempty"`
	// GPU lets the app use /dev/dri render nodes and NVIDIA GPUs if present.
	GPU bool `json:"gpu,omitempty"`
}

// Package is a read and checked .hardyapp file.
type Package struct {
	Manifest Manifest
	Compose  []byte
	Icon     []byte
	// Raw is the package file itself; SHA256 its hash (hex).
	Raw    []byte
	SHA256 string
}

// Problems lists everything wrong with a package or a request, so a person
// can fix them all at once.
type Problems []string

func (p Problems) Error() string {
	if len(p) == 1 {
		return p[0]
	}
	return fmt.Sprintf("%s (and %d more problems)", p[0], len(p)-1)
}

func (p *Problems) addf(format string, args ...any) { *p = append(*p, fmt.Sprintf(format, args...)) }

func (p Problems) err() error {
	if len(p) == 0 {
		return nil
	}
	return p
}

var (
	idRE        = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	portNameRE  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,23}$`)
	envRE       = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	versionRE   = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+~_-]{0,63}$`)
	ownerRE     = regexp.MustCompile(`^[0-9]{1,10}:[0-9]{1,10}$`)
	modeRE      = regexp.MustCompile(`^0?[0-7]{3}$`)
	folderSegRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	shareIDRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

// Share access levels (manifest shares and admin choices).
const (
	AccessRead  = "read"
	AccessWrite = "write"
)

// reservedIDs would clash with HardyOS's own datasets and names.
var reservedIDs = map[string]bool{"docker": true, "hardyos": true, "system": true, "engine": true, "apps": true}

// ValidID reports whether id can name an app (dataset <pool>/apps/<id>,
// compose project hardyos-<id>).
func ValidID(id string) error {
	if !idRE.MatchString(id) || strings.Contains(id, "--") || reservedIDs[id] {
		return fmt.Errorf("app id %q: use 2-32 lowercase letters, digits and single dashes, starting with a letter", id)
	}
	return nil
}

// ProjectName is the Docker Compose project an app runs as.
func ProjectName(id string) string { return "hardyos-" + id }

// PortEnv is the environment variable holding a port's number.
func PortEnv(name string) string { return "HARDY_PORT_" + name }

// Validate checks the manifest on its own (without the compose file).
func (m *Manifest) Validate() error {
	var p Problems
	if m.Format != FormatVersion {
		p.addf("format %d isn't supported (this HardyOS understands format %d)", m.Format, FormatVersion)
	}
	if err := ValidID(m.ID); err != nil {
		p.addf("%v", err)
	}
	if strings.TrimSpace(m.Name) == "" || len(m.Name) > 60 {
		p.addf("name: 1-60 characters")
	}
	if !versionRE.MatchString(m.Version) {
		p.addf("version %q: use letters, digits and . + ~ _ -", m.Version)
	}
	if strings.TrimSpace(m.Summary) == "" || len(m.Summary) > 200 {
		p.addf("summary: 1-200 characters")
	}
	if len(m.Description) > 4000 {
		p.addf("description: at most 4000 characters")
	}
	if len(m.Publisher) > 80 {
		p.addf("publisher: at most 80 characters")
	}
	if m.Website != "" {
		if u, err := url.Parse(m.Website); err != nil || u.Scheme != "https" || u.Host == "" {
			p.addf("website must be an https:// address")
		}
	}
	if m.Icon != "" && (m.Icon != filepath.Base(m.Icon) || !(strings.HasSuffix(m.Icon, ".svg") || strings.HasSuffix(m.Icon, ".png"))) {
		p.addf("icon %q: name an .svg or .png file at the top of the package", m.Icon)
	}
	for _, a := range m.Arch {
		if a != "amd64" && a != "arm64" {
			p.addf("arch %q: use amd64 or arm64", a)
		}
	}
	if m.MinMemoryMB < 0 || m.MinMemoryMB > 1<<20 {
		p.addf("minMemoryMB out of range")
	}

	ports := map[string]bool{}
	for _, pt := range m.Ports {
		if !portNameRE.MatchString(pt.Name) {
			p.addf("port name %q: use capital letters, digits and _ (e.g. WEB)", pt.Name)
		}
		if ports[pt.Name] {
			p.addf("port %s is declared twice", pt.Name)
		}
		ports[pt.Name] = true
		// An app on the host network listens where it listens (DNS on 53);
		// every other app is published on 1024-65535.
		if lo := minPort(m.Permissions.HostNetwork); pt.Default < lo || pt.Default > 65535 {
			p.addf("port %s: default %d must be %d-65535", pt.Name, pt.Default, lo)
		}
		if pt.Protocol != "" && pt.Protocol != "tcp" && pt.Protocol != "udp" {
			p.addf("port %s: protocol must be tcp or udp", pt.Name)
		}
		if strings.TrimSpace(pt.Label) == "" || len(pt.Label) > 60 {
			p.addf("port %s: label 1-60 characters", pt.Name)
		}
	}
	if len(m.Ports) > 16 {
		p.addf("at most 16 ports")
	}
	if m.Web != nil {
		if !ports[m.Web.Port] {
			p.addf("web.port %q isn't one of the declared ports", m.Web.Port)
		}
		if m.Web.Path != "" && !strings.HasPrefix(m.Web.Path, "/") {
			p.addf("web.path must start with /")
		}
		if m.Web.Scheme != "" && m.Web.Scheme != "http" && m.Web.Scheme != "https" {
			p.addf("web.scheme must be http or https")
		}
	}

	envs := map[string]bool{}
	for _, s := range m.Settings {
		if !envRE.MatchString(s.Env) {
			p.addf("setting %q: environment names use capital letters, digits and _", s.Env)
			continue
		}
		if strings.HasPrefix(s.Env, "HARDY_") {
			p.addf("setting %s: names starting with HARDY_ belong to HardyOS", s.Env)
		}
		if envs[s.Env] {
			p.addf("setting %s is declared twice", s.Env)
		}
		envs[s.Env] = true
		switch s.Generate {
		case "":
			if strings.TrimSpace(s.Label) == "" {
				p.addf("setting %s needs a label", s.Env)
			}
		case "secret":
			if s.Managed {
				p.addf("setting %s: a generated secret can't also be managed", s.Env)
			}
		default:
			p.addf("setting %s: generate must be \"secret\"", s.Env)
		}
		if s.Managed && s.Type == "password" {
			p.addf("setting %s: a password can't be managed", s.Env)
		}
		switch s.Type {
		case "", "text", "number", "boolean", "password":
		case "select":
			if len(s.Options) == 0 {
				p.addf("setting %s: a select needs options", s.Env)
			}
		default:
			p.addf("setting %s: type must be text, number, boolean, select or password", s.Env)
		}
		if s.Default != "" {
			if err := checkSettingValue(s, s.Default); err != nil {
				p.addf("setting %s default: %v", s.Env, err)
			}
		}
	}
	if len(m.Settings) > 64 {
		p.addf("at most 64 settings")
	}

	for _, f := range m.Folders {
		if err := checkFolderPath(f.Path); err != nil {
			p.addf("folder %q: %v", f.Path, err)
		}
		if f.Owner != "" && !ownerRE.MatchString(f.Owner) {
			p.addf("folder %s: owner must be uid:gid numbers", f.Path)
		}
		if f.Mode != "" && !modeRE.MatchString(f.Mode) {
			p.addf("folder %s: mode must be octal like 0755", f.Path)
		}
	}
	shareNames := map[string]bool{}
	for _, s := range m.Shares {
		if !portNameRE.MatchString(s.Name) {
			p.addf("share name %q: use capital letters, digits and _ (e.g. MEDIA)", s.Name)
		}
		if shareNames[s.Name] {
			p.addf("share %s is declared twice", s.Name)
		}
		shareNames[s.Name] = true
		if strings.TrimSpace(s.Label) == "" || len(s.Label) > 60 {
			p.addf("share %s: label 1-60 characters", s.Name)
		}
		if len(s.Help) > 200 {
			p.addf("share %s: help at most 200 characters", s.Name)
		}
		if s.Access != AccessRead && s.Access != AccessWrite {
			p.addf("share %s: access must be read or write", s.Name)
		}
		if s.Suggest != "" && !shareIDRE.MatchString(s.Suggest) {
			p.addf("share %s: suggest %q isn't a shared folder id", s.Name, s.Suggest)
		}
	}
	if len(m.Shares) > 8 {
		p.addf("at most 8 shares")
	}
	for _, c := range m.Permissions.Capabilities {
		if _, ok := AllowedCapabilities[c]; !ok {
			p.addf("capability %s isn't available to apps", c)
		}
	}
	for _, d := range m.Permissions.Devices {
		if _, ok := deviceAllowed(d); !ok {
			p.addf("device %s isn't available to apps", d)
		}
	}
	return p.err()
}

func minPort(hostNetwork bool) int {
	if hostNetwork {
		return 1
	}
	return 1024
}

func checkFolderPath(rel string) error {
	if rel == "" || len(rel) > 200 {
		return errors.New("use a relative path")
	}
	for _, seg := range strings.Split(rel, "/") {
		if !folderSegRE.MatchString(seg) || seg == "." || seg == ".." {
			return errors.New("use a relative path of plain names (no .. or leading /)")
		}
	}
	return nil
}

// checkSettingValue validates a value for a setting. Values go into an
// environment file in single quotes, so they can't contain quotes or line breaks.
func checkSettingValue(s Setting, v string) error {
	if len(v) > 4096 {
		return errors.New("at most 4096 characters")
	}
	if strings.ContainsAny(v, "'\n\r\x00") {
		return errors.New("can't contain quotes or line breaks")
	}
	switch s.Type {
	case "number":
		if !regexp.MustCompile(`^-?[0-9]{1,15}(\.[0-9]{1,6})?$`).MatchString(v) {
			return errors.New("must be a number")
		}
	case "boolean":
		if v != "true" && v != "false" {
			return errors.New("must be true or false")
		}
	case "select":
		for _, o := range s.Options {
			if o == v {
				return nil
			}
		}
		return fmt.Errorf("must be one of %s", strings.Join(s.Options, ", "))
	}
	return nil
}

// ReadPackage reads and checks a .hardyapp file.
func ReadPackage(raw []byte) (*Package, error) {
	if len(raw) > MaxPackageBytes {
		return nil, Problems{fmt.Sprintf("the package is %d KB; app packages can be at most %d KB", len(raw)>>10, MaxPackageBytes>>10)}
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, Problems{"this isn't a .hardyapp package (expected a gzipped tar)"}
	}
	tr := tar.NewReader(io.LimitReader(zr, maxUnpackedBytes+1))
	files := map[string][]byte{}
	total := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, Problems{fmt.Sprintf("the package is damaged: %v", err)}
		}
		name := strings.TrimPrefix(h.Name, "./")
		if h.Typeflag == tar.TypeDir && (name == "" || name == ".") {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return nil, Problems{fmt.Sprintf("%s: packages may hold only regular files", h.Name)}
		}
		if name != filepath.Base(name) || name == "" || strings.HasPrefix(name, ".") {
			return nil, Problems{fmt.Sprintf("%s: files must be at the top of the package", h.Name)}
		}
		if _, dup := files[name]; dup {
			return nil, Problems{fmt.Sprintf("%s appears twice", name)}
		}
		if h.Size < 0 || int64(total)+h.Size > maxUnpackedBytes {
			return nil, Problems{"the package unpacks to more than 2 MB"}
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxUnpackedBytes+1))
		if err != nil {
			return nil, Problems{fmt.Sprintf("the package is damaged: %v", err)}
		}
		total += len(b)
		if total > maxUnpackedBytes {
			return nil, Problems{"the package unpacks to more than 2 MB"}
		}
		files[name] = b
	}

	mb, ok := files[ManifestFile]
	if !ok {
		return nil, Problems{"the package has no " + ManifestFile}
	}
	if len(mb) > maxManifestBytes {
		return nil, Problems{ManifestFile + " is too big"}
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(mb))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, Problems{fmt.Sprintf("%s: %v", ManifestFile, err)}
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	compose, ok := files[ComposeFile]
	if !ok {
		return nil, Problems{"the package has no " + ComposeFile}
	}
	if len(compose) > maxComposeBytes {
		return nil, Problems{ComposeFile + " is too big"}
	}
	pkg := &Package{Manifest: m, Compose: compose, Raw: raw}
	for name := range files {
		if name == ManifestFile || name == ComposeFile || name == m.Icon || optionalFiles[name] {
			continue
		}
		return nil, Problems{fmt.Sprintf("%s: unexpected file in the package", name)}
	}
	if m.Icon != "" {
		icon, ok := files[m.Icon]
		if !ok {
			return nil, Problems{fmt.Sprintf("icon %s isn't in the package", m.Icon)}
		}
		if err := checkIcon(m.Icon, icon); err != nil {
			return nil, Problems{err.Error()}
		}
		pkg.Icon = icon
	}
	sum := sha256.Sum256(raw)
	pkg.SHA256 = hex.EncodeToString(sum[:])
	return pkg, nil
}

func checkIcon(name string, b []byte) error {
	if len(b) > maxIconBytes {
		return fmt.Errorf("icon %s is bigger than %d KB", name, maxIconBytes>>10)
	}
	if strings.HasSuffix(name, ".png") {
		if !bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) {
			return fmt.Errorf("icon %s isn't a PNG", name)
		}
		return nil
	}
	head := strings.ToLower(string(b[:min(len(b), 512)]))
	if !strings.Contains(head, "<svg") {
		return fmt.Errorf("icon %s isn't an SVG", name)
	}
	return nil
}

// IconDataURL returns the icon as a data: URL (images loaded this way can't
// run scripts), or "" without one.
func IconDataURL(name string, b []byte) string {
	if len(b) == 0 {
		return ""
	}
	typ := "image/svg+xml"
	if strings.HasSuffix(name, ".png") {
		typ = "image/png"
	}
	return "data:" + typ + ";base64," + base64.StdEncoding.EncodeToString(b)
}

// Pack builds a .hardyapp from a folder holding hardyapp.json, compose.yaml
// and the icon. The result is the same for the same files (sorted names,
// fixed times), so packages can be compared by hash.
func Pack(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	zw.ModTime = time.Unix(0, 0)
	tw := tar.NewWriter(zw)
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(b)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if _, err := ReadPackage(buf.Bytes()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Setting finds a setting by its variable name.
func (m *Manifest) Setting(env string) *Setting {
	for i := range m.Settings {
		if m.Settings[i].Env == env {
			return &m.Settings[i]
		}
	}
	return nil
}

// NewerVersion reports whether version a is newer than b. Versions compare
// number by number ("1.10.0" > "1.9.2"); a part that isn't a number
// compares as text, and a pre-release ("1.0.0-rc1") is older than its release.
func NewerVersion(a, b string) bool {
	return compareVersions(a, b) > 0
}

func compareVersions(a, b string) int {
	a, b = strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v")
	aMain, aPre, aHasPre := strings.Cut(a, "-")
	bMain, bPre, bHasPre := strings.Cut(b, "-")
	ap, bp := strings.Split(aMain, "."), strings.Split(bMain, ".")
	for i := 0; i < len(ap) || i < len(bp); i++ {
		x, y := "0", "0"
		if i < len(ap) {
			x = ap[i]
		}
		if i < len(bp) {
			y = bp[i]
		}
		xi, errX := strconv.Atoi(x)
		yi, errY := strconv.Atoi(y)
		switch {
		case errX == nil && errY == nil:
			if xi != yi {
				if xi > yi {
					return 1
				}
				return -1
			}
		case x != y:
			return strings.Compare(x, y)
		}
	}
	switch {
	case aHasPre && !bHasPre:
		return -1
	case !aHasPre && bHasPre:
		return 1
	}
	return strings.Compare(aPre, bPre)
}
