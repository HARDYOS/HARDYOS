// Package photos is HardyOS's Photos: the Immich catalog app, set up and
// kept set up by hardyd (docs/photos.md). It holds the settings an
// administrator chooses (Control Panel > Photos), works out what Immich's
// own configuration should be from them and from the rest of HardyOS
// (the sign-in provider at sso.<base>, the published address, the GPUs),
// and applies it through Immich's API as a service account HardyOS made:
// sign-in with HardyOS (OIDC), people's accounts, external libraries for
// photos already in shared folders, and the family library shared as a
// partner.
//
// Nothing here runs as root or touches the app's files: Immich's API on
// 127.0.0.1:<its port> is the only way in, and the app's containers,
// mounts and settings change only through the apps engine's named
// operations (internal/apps, hardyd-priv).
package photos

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/appstore"
	"github.com/hardyos/hardyos/daemon/internal/oidc"
)

// AppID is the catalog app Photos sets up.
const AppID = "immich"

// ClientKey is the managed OIDC client's key (oidc.Clients.Ensure).
const ClientKey = oidc.PhotosClientKey

// KeyPurpose seals Photos' secrets (secretbox purpose).
const KeyPurpose = "photos"

// Shares the Immich package declares for libraries, and where Immich sees
// them (apps/catalog/immich/compose.yaml).
var libraryMounts = map[string]string{
	"EXISTING":   "/mnt/existing",
	"EXISTING_2": "/mnt/existing-2",
	"EXISTING_3": "/mnt/existing-3",
}

// FamilyShare is the package's share for the family library, at
// FamilyMount in Immich.
const (
	FamilyShare = "FAMILY"
	FamilyMount = "/mnt/family"
)

// LibraryShares are the share names a personal library can come from.
func LibraryShares() []string {
	out := make([]string, 0, len(libraryMounts))
	for k := range libraryMounts {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Machine learning modes.
const (
	MLAuto     = "auto"
	MLCPU      = "cpu"
	MLCUDA     = "cuda"
	MLOpenVINO = "openvino"
	MLROCm     = "rocm"
)

// mlServices are the accelerated machine learning services and the managed
// setting that turns each on.
var mlServices = map[string]struct{ Service, Setting string }{
	MLCUDA:     {"immich-machine-learning-cuda", "ML_CUDA_REPLICAS"},
	MLOpenVINO: {"immich-machine-learning-openvino", "ML_OPENVINO_REPLICAS"},
	MLROCm:     {"immich-machine-learning-rocm", "ML_ROCM_REPLICAS"},
}

// CPUService is the machine learning service that always runs.
const CPUService = "immich-machine-learning"

// ServerService is Immich's server.
const ServerService = "immich-server"

// AccelModes are the modes with a service of their own.
var AccelModes = []string{MLCUDA, MLOpenVINO, MLROCm}

// Settings are what an administrator chooses in Control Panel > Photos.
type Settings struct {
	// SSO: people sign in to Immich with their HardyOS account. It needs
	// HardyOS's sign-in provider at https://sso.<base> (Remote Access with
	// a base domain): Immich's server checks the provider's certificate.
	SSO bool `json:"sso"`
	// PasswordLogin keeps Immich's own email and password sign-in while
	// SSO is on (it's always on while SSO isn't).
	PasswordLogin bool `json:"passwordLogin"`
	// AutoLaunch: Immich's sign-in page goes straight to HardyOS.
	AutoLaunch bool `json:"autoLaunch"`
	// DefaultQuotaGiB is the storage limit for people Immich signs up
	// (0: none).
	DefaultQuotaGiB int `json:"defaultQuotaGiB"`
	// MLAcceleration: auto (a GPU the server has, when apps may use it),
	// cpu, cuda (NVIDIA), openvino (Intel) or rocm (AMD).
	MLAcceleration string `json:"mlAcceleration"`
	// ScanHours: how often Immich looks for new and removed files in the
	// libraries of existing photos and the family library (1-168).
	ScanHours int `json:"scanHours"`
	// Watch: Immich also follows changes in those folders as they happen.
	Watch bool `json:"watch"`
	// Libraries are folders of existing photos, each indexed in place in
	// one person's library.
	Libraries []Library `json:"libraries"`
	// Family is the library everyone in the family sees.
	Family Family `json:"family"`
}

// Library is a folder of existing photos in one person's Immich library.
type Library struct {
	// OwnerID is the HardyOS account (users.id) whose library it joins.
	OwnerID int64 `json:"ownerId"`
	// Share is the package's share it's in: EXISTING, EXISTING_2 or
	// EXISTING_3 (whichever shared folder the app was given there).
	Share string `json:"share"`
	// Path is a folder inside it ("" for all of it).
	Path string `json:"path"`
	// Name is the library's name in Immich.
	Name string `json:"name"`
}

// Key identifies a library across settings changes.
func (l Library) Key() string { return fmt.Sprintf("user:%d:%s:%s", l.OwnerID, l.Share, l.Path) }

// ImportPath is the folder as Immich sees it.
func (l Library) ImportPath() string {
	base := libraryMounts[l.Share]
	if l.Path == "" {
		return base
	}
	return base + "/" + l.Path
}

// Family is the family library: an Immich account of its own ("Family
// Photos") owns an external library on the app's FAMILY shared folder and
// shares everything it has, as a partner, with each member.
type Family struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	// Members see it: HardyOS users, domain users and groups, or empty for
	// everyone who may use Immich (its App Store access list).
	Members []appstore.Principal `json:"members"`
}

// FamilyKey is the family library's key.
const FamilyKey = "family"

// Defaults are the settings before an administrator saves any.
func Defaults() Settings {
	return Settings{SSO: true, AutoLaunch: false, MLAcceleration: MLAuto, ScanHours: 6,
		Libraries: []Library{}, Family: Family{Name: "Family Photos", Members: []appstore.Principal{}}}
}

var (
	nameRE   = regexp.MustCompile(`^[^\x00-\x1f<>]{1,64}$`)
	folderRE = regexp.MustCompile(`^[^\x00-\x1f\\]{1,255}$`)
)

// Normalize checks settings and fills in what's left out.
func (s Settings) Normalize() (Settings, error) {
	var problems []string
	if s.MLAcceleration == "" {
		s.MLAcceleration = MLAuto
	}
	switch s.MLAcceleration {
	case MLAuto, MLCPU, MLCUDA, MLOpenVINO, MLROCm:
	default:
		problems = append(problems, fmt.Sprintf("machine learning must be auto, cpu, cuda, openvino or rocm, not %q", s.MLAcceleration))
	}
	if s.ScanHours == 0 {
		s.ScanHours = 6
	}
	if s.ScanHours < 1 || s.ScanHours > 168 {
		problems = append(problems, "rescan every 1 to 168 hours")
	}
	if s.DefaultQuotaGiB < 0 || s.DefaultQuotaGiB > 1<<20 {
		problems = append(problems, "the storage limit is 0 (none) to 1048576 GiB")
	}
	if len(s.Libraries) > 50 {
		problems = append(problems, "at most 50 libraries")
	}
	seen := map[string]bool{}
	libs := []Library{}
	for _, l := range s.Libraries {
		l.Name = strings.TrimSpace(l.Name)
		p, err := cleanFolder(l.Path)
		l.Path = p
		switch {
		case l.OwnerID <= 0:
			problems = append(problems, "choose whose library each folder joins")
		case libraryMounts[l.Share] == "":
			problems = append(problems, fmt.Sprintf("%q isn't one of Immich's existing-photos folders (%s)", l.Share, strings.Join(LibraryShares(), ", ")))
		case err != nil:
			problems = append(problems, err.Error())
		case !nameRE.MatchString(l.Name):
			problems = append(problems, "give each library a name of 1-64 characters")
		case seen[l.Key()]:
			problems = append(problems, fmt.Sprintf("%s is listed twice for the same person", l.ImportPath()))
		default:
			seen[l.Key()] = true
			libs = append(libs, l)
		}
	}
	s.Libraries = libs
	s.Family.Name = strings.TrimSpace(s.Family.Name)
	if s.Family.Name == "" {
		s.Family.Name = "Family Photos"
	}
	if !nameRE.MatchString(s.Family.Name) {
		problems = append(problems, "the family library's name is 1-64 characters")
	}
	members, err := appstore.NormalizePrincipals(s.Family.Members)
	if err != nil {
		problems = append(problems, "family members: "+err.Error())
	}
	if members == nil {
		members = []appstore.Principal{}
	}
	s.Family.Members = members
	if len(problems) > 0 {
		return s, errors.New(strings.Join(problems, "; "))
	}
	return s, nil
}

// cleanFolder checks a folder inside a shared folder: relative, no "..",
// no backslashes or control characters; "" and "." mean the whole share.
func cleanFolder(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "." || p == "/" {
		return "", nil
	}
	if strings.HasPrefix(p, "/") || !folderRE.MatchString(p) {
		return "", fmt.Errorf("%q isn't a folder inside the shared folder (write it like Pictures/2019)", p)
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return "", fmt.Errorf("%q can't go up a folder", p)
		}
	}
	c := path.Clean(p)
	if c == "." {
		return "", nil
	}
	return c, nil
}

// ScanCron is the library rescan schedule for Immich.
// Under a day it's every N hours on the hour; from a day up, at 01:00
// every N/24 days (rounded down).
func (s Settings) ScanCron() string {
	switch h := s.ScanHours; {
	case h <= 1:
		return "0 * * * *"
	case h < 24:
		return fmt.Sprintf("0 */%d * * *", h)
	case h < 48:
		return "0 1 * * *"
	default:
		return fmt.Sprintf("0 1 */%d * *", h/24)
	}
}

// GPU is what Photos needs to know about one of the server's GPUs (from
// the devices inventory).
type GPU struct {
	Vendor string // nvidia, amd, intel, other
	Model  string
	Driver string
	// Owner is apps (the server's driver: Docker apps can use it), vm,
	// vgpu, none or stuck.
	Owner string
	// VM is the VM that has it now (Owner vm).
	VM string
	// Assigned: a VM is configured with it (it goes to that VM whenever
	// the VM runs).
	Assigned bool
}

// MLChoice is the machine learning Photos runs and why.
type MLChoice struct {
	Mode   string `json:"mode"` // cpu, cuda, openvino, rocm
	Reason string `json:"reason"`
	// Lent: the GPU is with a VM now, so Immich uses the processor until
	// it's back (the accelerated service starts again then).
	Lent bool `json:"lent"`
}

// ChooseML picks the machine learning mode for the setting, the server's
// GPUs and processor architecture (accelerated images are amd64 only).
func ChooseML(setting string, gpus []GPU, arch string) MLChoice {
	if arch == "" {
		arch = runtime.GOARCH
	}
	if setting == MLCPU {
		return MLChoice{Mode: MLCPU, Reason: "Set to use the processor"}
	}
	if arch != "amd64" {
		return MLChoice{Mode: MLCPU, Reason: "Immich's accelerated machine learning runs on x86-64 servers only; this one uses the processor"}
	}
	usable := func(g GPU) (string, bool) {
		switch {
		case g.Vendor == "nvidia" && (g.Driver == "nvidia" || g.Owner == "vm"):
			return MLCUDA, true
		case g.Vendor == "intel" && (g.Driver == "i915" || g.Driver == "xe" || g.Owner == "vm"):
			return MLOpenVINO, true
		case g.Vendor == "amd" && (g.Driver == "amdgpu" || g.Owner == "vm"):
			return MLROCm, true
		}
		return "", false
	}
	if setting != MLAuto {
		for _, g := range gpus {
			if m, ok := usable(g); ok && m == setting {
				return MLChoice{Mode: m, Reason: "Uses " + gpuName(g), Lent: g.Owner == "vm"}
			}
		}
		return MLChoice{Mode: setting, Reason: "Set to " + setting + ", but HardyOS found no GPU for it with its driver; Immich uses the processor until it can start"}
	}
	// Auto: a GPU no VM uses beats one a VM has or is set up to take (so
	// Immich doesn't switch back and forth as VMs start and stop); among
	// those NVIDIA first (fastest), then Intel, then AMD.
	best, bestScore := MLChoice{Mode: MLCPU, Reason: "No GPU with a driver Docker apps can use; Immich uses the processor"}, 0
	rank := map[string]int{MLCUDA: 30, MLOpenVINO: 20, MLROCm: 10}
	for _, g := range gpus {
		m, ok := usable(g)
		if !ok || g.Owner == "vgpu" || g.Owner == "stuck" || g.Owner == "none" {
			continue
		}
		score := rank[m]
		if g.Owner == "apps" && !g.Assigned {
			score += 50
		}
		if score > bestScore {
			best, bestScore = MLChoice{Mode: m, Reason: "Uses " + gpuName(g), Lent: g.Owner == "vm"}, score
		}
	}
	return best
}

func gpuName(g GPU) string {
	if g.Model != "" {
		return g.Model
	}
	return g.Vendor + " GPU"
}

// MLSettings are the app's managed settings for a mode: the one
// accelerated service turned on, the others off.
func MLSettings(mode string) map[string]string {
	out := map[string]string{}
	for m, sv := range mlServices {
		v := "0"
		if m == mode {
			v = "1"
		}
		out[sv.Setting] = v
	}
	return out
}

// MLService is the accelerated service for a mode ("" for cpu).
func MLService(mode string) string { return mlServices[mode].Service }

// MLURLs are Immich's machine learning addresses for a mode: the
// accelerated service first, the processor one as the fallback Immich
// switches to whenever the first isn't answering.
func MLURLs(mode string) []string {
	cpu := "http://" + CPUService + ":3003"
	if sv := MLService(mode); sv != "" {
		return []string{"http://" + sv + ":3003", cpu}
	}
	return []string{cpu}
}

// RedirectURIs are the sign-in client's redirect URIs for Immich at these
// origins (https://host[:port], no path): its web sign-in and account
// linking pages, and at the published origin the redirect the phone app
// signs in through (Immich's /api/oauth/mobile-redirect, which hands the
// code to app.immich:///oauth-callback; HardyOS's provider takes https
// redirect URIs only).
func RedirectURIs(published string, others []string) []string {
	var out []string
	add := func(u string) {
		if !slices.Contains(out, u) {
			out = append(out, u)
		}
	}
	for _, o := range append([]string{published}, others...) {
		if o == "" {
			continue
		}
		add(o + "/auth/login")
		add(o + "/user-settings")
	}
	if published != "" {
		add(MobileRedirect(published))
	}
	return out
}

// MobileRedirect is Immich's redirect for the phone app at origin.
func MobileRedirect(origin string) string { return origin + "/api/oauth/mobile-redirect" }

// Status is what the last sync found and did, for the settings page.
type Status struct {
	At        time.Time `json:"at"`
	Installed bool      `json:"installed"`
	// Catalog: the installed Immich came from HardyOS's catalog (Photos
	// sets up nothing else).
	Catalog bool   `json:"catalog"`
	Version string `json:"version,omitempty"`
	// Linked: HardyOS has its Immich service account's key.
	Linked bool `json:"linked"`
	// NeedsLink: Immich already had an administrator when HardyOS first
	// looked (set up before Photos): an Immich API key from an
	// administrator links it.
	NeedsLink bool `json:"needsLink"`
	// Problem is why the last sync stopped ("" when it finished).
	Problem string `json:"problem,omitempty"`
	// Incident: something happened in Immich that only an attacker (or
	// someone bypassing HardyOS) could have done; also sent as an alert.
	Incident string   `json:"incident,omitempty"`
	Notes    []string `json:"notes"`
	SSO      SSOState `json:"sso"`
	// PublishedURL is Immich's address through NetBird ("" when not
	// published); phones back up through it from anywhere.
	PublishedURL string `json:"publishedUrl,omitempty"`
	// PhoneReady: the address is public (or NetBird-only) with HardyOS's
	// gateway sign-in off, which the phone app needs.
	PhoneReady bool           `json:"phoneReady"`
	ML         MLChoice       `json:"ml"`
	Libraries  []LibraryState `json:"libraries"`
	Family     FamilyState    `json:"family"`
	People     []PersonState  `json:"people"`
}

// SSOState is sign-in with HardyOS.
type SSOState struct {
	Active       bool     `json:"active"`
	Issuer       string   `json:"issuer,omitempty"`
	ClientID     string   `json:"clientId,omitempty"`
	RedirectURIs []string `json:"redirectUris"`
	// Why it's off when the settings ask for it.
	Why string `json:"why,omitempty"`
}

// LibraryState is one library HardyOS keeps in Immich.
type LibraryState struct {
	Key        string `json:"key"`
	Name       string `json:"name"`
	Owner      string `json:"owner"`
	ImportPath string `json:"importPath"`
	ImmichID   string `json:"immichId,omitempty"`
	Assets     int    `json:"assets"`
	Problem    string `json:"problem,omitempty"`
}

// FamilyState is the family library.
type FamilyState struct {
	Active   bool   `json:"active"`
	Members  int    `json:"members"`
	ImmichID string `json:"immichId,omitempty"`
	Problem  string `json:"problem,omitempty"`
}

// PersonState is one HardyOS account's Immich account.
type PersonState struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	ImmichID string `json:"immichId"`
	Linked   bool   `json:"linked"` // has signed in with HardyOS
	// Flag is what HardyOS did about the account ("" for nothing): moved
	// aside for holding a HardyOS address, suspended, restored.
	Flag string `json:"flag,omitempty"`
}
