package vms

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp" //nolint:staticcheck // detached signature checks only; no keys are made or trusted beyond the pinned one
)

// The verified image catalog (decision 410). hardyd names an image, never
// a link: root knows where each one comes from, talks only to that image's
// own hosts (redirects too), and checks every byte against the checksum
// its publisher gives:
//
//   - Ubuntu: SHA256SUMS with its detached signature, checked with the
//     pinned Ubuntu cloud image signing key (ubuntu-cloud-images.asc).
//   - Debian: SHA512SUMS from cloud.debian.org (Debian signs no cloud image
//     checksums, so the TLS connection to its own host is what's trusted).
//   - Home Assistant OS and the VirtIO drivers: SHA-256 and size pinned
//     here (a new version is a change to this file).
//
// The image is saved in the ISO library under its publisher's name; a copy
// already there is hashed again and reused when it still matches.

// Catalog image names.
const (
	CatalogDebian13 = "debian-13"
	CatalogUbuntu   = "ubuntu-24.04"
	CatalogHAOS     = "haos"
	CatalogVirtio   = "virtio-win"
)

// UbuntuKeyFingerprint is the Ubuntu cloud image signing key ("UEC Image
// Automatic Signing Key <cdimage@ubuntu.com>").
const UbuntuKeyFingerprint = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"

//go:embed ubuntu-cloud-images.asc
var ubuntuKey string

// CatalogImage is one image the catalog knows.
type CatalogImage struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Kind: disk (a disk image to import) or iso.
	Kind string `json:"kind"`
	// Files per architecture (ArchInfo.Arch).
	Files map[string]CatalogFile `json:"files"`
	// Hosts the download may talk to, redirects included.
	Hosts []string `json:"-"`
	// Mirrors: the image itself (never its checksums) may be redirected
	// to any https host on the internet, as cloud.debian.org sends people
	// to its mirrors; its bytes are checked against the checksum from
	// Hosts all the same.
	Mirrors bool `json:"-"`
	// Verified says how, in plain words.
	Verified string `json:"verified"`
}

// CatalogFile is an image for one architecture.
type CatalogFile struct {
	URL string `json:"url"`
	// File is its name in the ISO library.
	File string `json:"file"`
	// Either the publisher's checksum list...
	SumsURL  string `json:"-"`
	SumsAlgo string `json:"-"` // sha256 or sha512
	// SigURL is the list's detached OpenPGP signature (Key must sign it).
	SigURL string `json:"-"`
	Key    string `json:"-"` // armored public key
	KeyFP  string `json:"-"` // its pinned fingerprint
	// ...or a pinned checksum and size.
	SHA256 string `json:"-"`
	Size   int64  `json:"-"`
}

// Catalog is every image, in the order the wizard shows them.
var Catalog = []CatalogImage{
	{
		ID: CatalogDebian13, Name: "Debian 13 (trixie) cloud image", Kind: "disk",
		Hosts: []string{"cloud.debian.org"}, Mirrors: true,
		Verified: "SHA-512 from Debian's SHA512SUMS on cloud.debian.org",
		Files: map[string]CatalogFile{
			"x86_64": {
				URL:     "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2",
				File:    "debian-13-genericcloud-amd64.qcow2",
				SumsURL: "https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS", SumsAlgo: "sha512",
			},
			"aarch64": {
				URL:     "https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-arm64.qcow2",
				File:    "debian-13-genericcloud-arm64.qcow2",
				SumsURL: "https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS", SumsAlgo: "sha512",
			},
		},
	},
	{
		ID: CatalogUbuntu, Name: "Ubuntu Server 24.04 LTS cloud image", Kind: "disk",
		Hosts:    []string{"cloud-images.ubuntu.com"},
		Verified: "SHA-256 from Ubuntu's SHA256SUMS, signed with Ubuntu's cloud image key",
		Files: map[string]CatalogFile{
			"x86_64": {
				URL:     "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
				File:    "noble-server-cloudimg-amd64.img",
				SumsURL: "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS", SumsAlgo: "sha256",
				SigURL: "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS.gpg", Key: ubuntuKey, KeyFP: UbuntuKeyFingerprint,
			},
			"aarch64": {
				URL:     "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img",
				File:    "noble-server-cloudimg-arm64.img",
				SumsURL: "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS", SumsAlgo: "sha256",
				SigURL: "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS.gpg", Key: ubuntuKey, KeyFP: UbuntuKeyFingerprint,
			},
		},
	},
	{
		ID: CatalogHAOS, Name: "Home Assistant OS 16.2", Kind: "disk",
		// GitHub release downloads redirect to its asset hosts.
		Hosts:    []string{"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"},
		Verified: "SHA-256 and size pinned in HardyOS",
		Files: map[string]CatalogFile{
			"x86_64": {
				URL:    "https://github.com/home-assistant/operating-system/releases/download/16.2/haos_ova-16.2.qcow2.xz",
				File:   "haos_ova-16.2.qcow2.xz",
				SHA256: "a53922b862d4dcf8d96e7e0860db7f07cfaee21f415772c00b28caaf0ce1534c", Size: 340340424,
			},
			"aarch64": {
				URL:    "https://github.com/home-assistant/operating-system/releases/download/16.2/haos_generic-aarch64-16.2.qcow2.xz",
				File:   "haos_generic-aarch64-16.2.qcow2.xz",
				SHA256: "862e78ad3da09e25e70232653c24002a467cfab4f0f0dd80ae24aee1943a7dba", Size: 323713960,
			},
		},
	},
	{
		ID: CatalogVirtio, Name: "VirtIO drivers for Windows (virtio-win 0.1.302)", Kind: "iso",
		Hosts:    []string{"fedorapeople.org"},
		Verified: "SHA-256 and size pinned in HardyOS",
		Files: map[string]CatalogFile{
			// The drivers disc is the same for every architecture Windows runs on.
			"x86_64":  {URL: VirtioURL, File: VirtioFile, SHA256: VirtioSHA256, Size: VirtioSize},
			"aarch64": {URL: VirtioURL, File: VirtioFile, SHA256: VirtioSHA256, Size: VirtioSize},
		},
	},
}

func (m *Manager) catalog() []CatalogImage {
	if m.CatalogImages != nil {
		return m.CatalogImages
	}
	return Catalog
}

// CatalogByID finds an image.
func (m *Manager) catalogImage(id string) (CatalogImage, bool) {
	for _, c := range m.catalog() {
		if c.ID == id {
			return c, true
		}
	}
	return CatalogImage{}, false
}

// CatalogFor is an image's file on this server's architecture.
func (m *Manager) catalogFile(id string) (CatalogImage, CatalogFile, error) {
	img, ok := m.catalogImage(id)
	if !ok {
		return CatalogImage{}, CatalogFile{}, Problems{fmt.Sprintf("%q isn't an image HardyOS knows", id)}
	}
	f, ok := img.Files[m.arch().Arch]
	if !ok {
		return CatalogImage{}, CatalogFile{}, Problems{fmt.Sprintf("%s isn't available for this server's processor (%s)", img.Name, m.arch().Arch)}
	}
	return img, f, nil
}

// FetchArgs gets a catalog image into the ISO library.
type FetchArgs struct {
	Image string `json:"image"`
	// Pool for the ISOs shared folder when it doesn't exist yet.
	Pool string `json:"pool"`
}

// FetchResult names what the task makes.
type FetchResult struct {
	Task *Task `json:"task"`
	// File is the image's name in the library; Digest its verified
	// checksum once the task is done (Task.Digest).
	File string `json:"file"`
}

// Limits on the small files a fetch reads.
const (
	maxSumsBytes = 1 << 20
	maxSigBytes  = 64 << 10
)

// FetchCatalog starts getting a catalog image: a check of the copy already
// in the library, or a download. The task's Digest is the verified
// checksum ("sha256:<hex>"), for the import to check again.
func (m *Manager) FetchCatalog(ctx context.Context, a FetchArgs) (*Task, error) {
	img, cf, err := m.catalogFile(a.Image)
	if err != nil {
		return nil, err
	}
	if err := ValidFile(cf.File); err != nil {
		return nil, err
	}
	for _, t := range m.tasks.list("download") {
		if !t.Done && t.File == cf.File {
			return m.tasks.get(t.ID), nil
		}
	}
	f, err := m.folder(ctx, a.Pool, a.Pool != "")
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, Problems{"choose a pool for the ISOs shared folder"}
	}
	t, err := m.tasks.start("download", "", cf.File)
	if err != nil {
		return nil, err
	}
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
		defer cancel()
		d, err := m.fetch(bg, t, f, img, cf)
		if err == nil {
			m.tasks.setDigest(t.ID, d.Algo+":"+d.Hex)
		}
		m.tasks.finish(t.ID, err)
		if err != nil {
			m.log().Warn("vms: catalog image failed", "image", img.ID, "err", err)
		} else {
			m.log().Info("vms: catalog image ready", "image", img.ID, "file", cf.File, "digest", d.Algo+":"+d.Hex)
		}
	}()
	return m.tasks.get(t.ID), nil
}

// catalogClient talks only to hosts (https), whatever redirects say.
func (m *Manager) catalogClient(hosts []string) *http.Client {
	base := m.client()
	c := *base
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 8 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("the download redirected to an address that isn't https://")
		}
		if !slices.Contains(hosts, req.URL.Hostname()) {
			return fmt.Errorf("the download redirected to %s, which isn't where this image comes from", req.URL.Hostname())
		}
		return nil
	}
	return &c
}

func allowedURL(raw string, hosts []string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || !slices.Contains(hosts, u.Hostname()) {
		return nil, fmt.Errorf("%s isn't one of the image's own https addresses", raw)
	}
	return u, nil
}

func (m *Manager) fetch(ctx context.Context, t *Task, f *Folder, img CatalogImage, cf CatalogFile) (digest, error) {
	client := m.catalogClient(img.Hosts)
	u, err := allowedURL(cf.URL, img.Hosts)
	if err != nil {
		return digest{}, err
	}
	want, err := m.expectedDigest(ctx, t, client, img, cf)
	if err != nil {
		return digest{}, err
	}
	imageClient := client
	if img.Mirrors {
		// https and internet addresses only (client's own rules); the
		// checksum came from the image's own host.
		imageClient = m.client()
	}
	// A copy from before that still matches is used as it is.
	if file, err := openFile(f, cf.File); err == nil {
		m.tasks.progress(t.ID, 1, "Checking the copy of "+cf.File+" already in the ISO library")
		h := want.hash()
		n, cerr := io.Copy(h, io.LimitReader(file, MaxDownloadBytes+1))
		file.Close()
		if cerr == nil && hex.EncodeToString(h.Sum(nil)) == want.Hex && (cf.Size == 0 || n == cf.Size) {
			return want, nil
		}
		m.log().Info("vms: the library's copy of a catalog image is out of date or damaged; downloading it again", "file", cf.File)
		if err := removeFile(f, cf.File); err != nil {
			return digest{}, fmt.Errorf("replacing the old %s: %w", cf.File, err)
		}
	}
	if err := m.download(ctx, t, f, imageClient, u, cf.File, "", want, cf.Size); err != nil {
		return digest{}, err
	}
	return want, nil
}

// expectedDigest is the checksum the image must have.
func (m *Manager) expectedDigest(ctx context.Context, t *Task, client *http.Client, img CatalogImage, cf CatalogFile) (digest, error) {
	if cf.SHA256 != "" {
		return digest{Algo: "sha256", Hex: cf.SHA256}, nil
	}
	if cf.SumsURL == "" || (cf.SumsAlgo != "sha256" && cf.SumsAlgo != "sha512") {
		return digest{}, fmt.Errorf("%s has no checksum to check it against", img.Name)
	}
	m.tasks.progress(t.ID, 0, "Getting "+img.Name+"'s checksums")
	sums, err := getSmall(ctx, client, cf.SumsURL, img.Hosts, maxSumsBytes)
	if err != nil {
		return digest{}, fmt.Errorf("getting the checksums: %w", err)
	}
	if cf.SigURL != "" {
		sig, err := getSmall(ctx, client, cf.SigURL, img.Hosts, maxSigBytes)
		if err != nil {
			return digest{}, fmt.Errorf("getting the checksums' signature: %w", err)
		}
		if err := verifySignature(cf.Key, cf.KeyFP, sums, sig); err != nil {
			return digest{}, err
		}
	}
	name := cf.URL[strings.LastIndexByte(cf.URL, '/')+1:]
	hx, err := findSum(sums, name, cf.SumsAlgo)
	if err != nil {
		return digest{}, err
	}
	return digest{Algo: cf.SumsAlgo, Hex: hx}, nil
}

func getSmall(ctx context.Context, client *http.Client, raw string, hosts []string, limit int64) ([]byte, error) {
	u, err := allowedURL(raw, hosts)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "HardyOS")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", u.Host, res.Status)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is bigger than a checksum file can be", u.Path)
	}
	return b, nil
}

// verifySignature checks a detached signature (binary or armored) over
// data with the one pinned key.
func verifySignature(armoredKey, fingerprint string, data, sig []byte) error {
	ring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredKey))
	if err != nil || len(ring) != 1 {
		return fmt.Errorf("the pinned signing key can't be read: %v", err)
	}
	if got := strings.ToUpper(hex.EncodeToString(ring[0].PrimaryKey.Fingerprint[:])); got != fingerprint {
		return fmt.Errorf("the pinned signing key is %s, not %s", got, fingerprint)
	}
	check := openpgp.CheckDetachedSignature
	if bytes.HasPrefix(bytes.TrimSpace(sig), []byte("-----BEGIN PGP SIGNATURE-----")) {
		check = openpgp.CheckArmoredDetachedSignature
	}
	signer, err := check(ring, bytes.NewReader(data), bytes.NewReader(sig))
	if err != nil {
		return fmt.Errorf("the checksums aren't signed by the image's publisher (%v); nothing was downloaded", err)
	}
	if got := strings.ToUpper(hex.EncodeToString(signer.PrimaryKey.Fingerprint[:])); got != fingerprint {
		return fmt.Errorf("the checksums are signed by %s, not the image's publisher", got)
	}
	return nil
}

var sumLineRE = regexp.MustCompile(`^([0-9a-fA-F]+) [ *]([^\s/]+)$`)

// findSum reads a SHA256SUMS/SHA512SUMS list ("<hex>  name" or
// "<hex> *name") and returns name's checksum. A name listed twice with
// different sums is refused.
func findSum(sums []byte, name, algo string) (string, error) {
	want := 64
	if algo == "sha512" {
		want = 128
	}
	found := ""
	sc := bufio.NewScanner(bytes.NewReader(sums))
	sc.Buffer(make([]byte, 4096), 4096)
	for sc.Scan() {
		mt := sumLineRE.FindStringSubmatch(strings.TrimRight(sc.Text(), "\r"))
		if mt == nil || mt[2] != name {
			continue
		}
		hx := strings.ToLower(mt[1])
		if len(hx) != want {
			return "", fmt.Errorf("the checksum list gives %s a checksum of the wrong length", name)
		}
		if found != "" && found != hx {
			return "", fmt.Errorf("the checksum list gives %s two different checksums", name)
		}
		found = hx
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("reading the checksum list: %w", err)
	}
	if found == "" {
		return "", fmt.Errorf("the checksum list doesn't list %s", name)
	}
	return found, nil
}

// CatalogView is the catalog as the wizard sees it.
type CatalogView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	File     string `json:"file"`
	Verified string `json:"verified"`
}

// CatalogList lists the images available on this server's architecture.
func (m *Manager) CatalogList() []CatalogView {
	out := []CatalogView{}
	for _, c := range m.catalog() {
		if f, ok := c.Files[m.arch().Arch]; ok {
			out = append(out, CatalogView{ID: c.ID, Name: c.Name, Kind: c.Kind, File: f.File, Verified: c.Verified})
		}
	}
	return out
}
