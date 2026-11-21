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
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/openpgp"        //nolint:staticcheck // detached signature checks only; no keys are made or trusted beyond the pinned one
	"golang.org/x/crypto/openpgp/armor"  //nolint:staticcheck // armored signatures
	"golang.org/x/crypto/openpgp/packet" //nolint:staticcheck // reads the signature's creation time
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
// The image is saved in the pool's catalog store (catalogstore.go), never
// in the ISOs shared folder; a copy already there is reused while it's the
// file root checked.

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

// UbuntuMinSigned is when the newest checksums HardyOS was built against
// were signed (testdata/catalog): older ones are refused.
var UbuntuMinSigned = time.Unix(1792268628, 0).UTC()

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
	// SigURL is the list's detached OpenPGP signature (Key must sign it),
	// made no earlier than MinSigned.
	SigURL    string    `json:"-"`
	Key       string    `json:"-"` // armored public key
	KeyFP     string    `json:"-"` // its pinned fingerprint
	MinSigned time.Time `json:"-"`
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
				SigURL: "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS.gpg", Key: ubuntuKey, KeyFP: UbuntuKeyFingerprint, MinSigned: UbuntuMinSigned,
			},
			"aarch64": {
				URL:     "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img",
				File:    "noble-server-cloudimg-arm64.img",
				SumsURL: "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS", SumsAlgo: "sha256",
				SigURL: "https://cloud-images.ubuntu.com/noble/current/SHA256SUMS.gpg", Key: ubuntuKey, KeyFP: UbuntuKeyFingerprint, MinSigned: UbuntuMinSigned,
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
	key := a.Pool + "/" + cf.File
	for _, t := range m.tasks.list("download") {
		if !t.Done && t.File == key {
			return m.tasks.get(t.ID), nil
		}
	}
	c, err := m.store(ctx, a.Pool, true)
	if err != nil {
		return nil, err
	}
	t, err := m.tasks.start("download", "", key)
	if err != nil {
		return nil, err
	}
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
		defer cancel()
		d, err := m.fetchInto(bg, t, c, img, cf)
		if err == nil {
			m.tasks.setDigest(t.ID, d.Algo+":"+d.Hex)
			m.tasks.setFile(t.ID, cf.File)
		}
		m.tasks.finish(t.ID, err)
		if err != nil {
			m.log().Warn("vms: catalog image failed", "image", img.ID, "pool", c.pool, "err", err)
		} else {
			m.log().Info("vms: catalog image ready", "image", img.ID, "pool", c.pool, "file", cf.File, "digest", d.Algo+":"+d.Hex)
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

func (m *Manager) fetchInto(ctx context.Context, t *Task, c *catalogStore, img CatalogImage, cf CatalogFile) (digest, error) {
	r, err := m.openStore(c)
	if err != nil {
		return digest{}, err
	}
	defer r.Close()
	return m.fetch(ctx, t, r, img, cf)
}

func (m *Manager) fetch(ctx context.Context, t *Task, r *os.Root, img CatalogImage, cf CatalogFile) (digest, error) {
	client := m.catalogClient(img.Hosts)
	u, err := allowedURL(cf.URL, img.Hosts)
	if err != nil {
		return digest{}, err
	}
	want, err := m.expectedDigest(ctx, t, client, r, img, cf)
	if err != nil {
		return digest{}, err
	}
	imageClient := client
	if img.Mirrors {
		// https and internet addresses only (client's own rules); the
		// checksum came from the image's own host.
		imageClient = m.client()
	}
	// A copy from before: trusted as checked, or checked again.
	if _, err := r.Lstat(cf.File); err == nil {
		if checkStamp(r, cf.File, want, cf.Size) == nil {
			return want, nil
		}
		m.tasks.progress(t.ID, 1, "Checking the stored copy of "+cf.File)
		if got, n, err := hashStored(r, cf.File, want); err == nil && got == want.Hex && (cf.Size == 0 || n == cf.Size) {
			if err := seal(r, cf.File, want); err == nil {
				return want, nil
			}
		}
		// Root's own store: an out-of-date or damaged copy is replaced.
		m.log().Info("vms: the stored copy of a catalog image is out of date or damaged; downloading it again", "file", cf.File)
		unseal(r, cf.File)
	}
	err = m.download(ctx, t, storeSink{r}, imageClient, u, cf.File, "", want, cf.Size)
	var ce *checksumError
	if errors.As(err, &ce) && cf.SumsURL != "" {
		// "latest" may have moved on between the checksums and the image:
		// once more, with fresh checksums.
		again, derr := m.expectedDigest(ctx, t, client, r, img, cf)
		if derr == nil && again != want {
			want = again
			err = m.download(ctx, t, storeSink{r}, imageClient, u, cf.File, "", want, cf.Size)
		}
	}
	if err != nil {
		return digest{}, err
	}
	if err := seal(r, cf.File, want); err != nil {
		unseal(r, cf.File)
		return digest{}, err
	}
	return want, nil
}

// expectedDigest is the checksum the image must have.
func (m *Manager) expectedDigest(ctx context.Context, t *Task, client *http.Client, r *os.Root, img CatalogImage, cf CatalogFile) (digest, error) {
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
		signed, err := verifySignature(cf.Key, cf.KeyFP, sums, sig)
		if err != nil {
			return digest{}, err
		}
		if err := checkFreshness(r, img.ID, signed, cf.MinSigned); err != nil {
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

// verifySignature checks a detached signature (armored, as Ubuntu's
// SHA256SUMS.gpg is, or binary) over data with the one pinned key and
// returns when it was made.
func verifySignature(armoredKey, fingerprint string, data, sig []byte) (time.Time, error) {
	ring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(armoredKey))
	if err != nil || len(ring) != 1 {
		return time.Time{}, fmt.Errorf("the pinned signing key can't be read: %v", err)
	}
	if got := strings.ToUpper(hex.EncodeToString(ring[0].PrimaryKey.Fingerprint[:])); got != fingerprint {
		return time.Time{}, fmt.Errorf("the pinned signing key is %s, not %s", got, fingerprint)
	}
	if bytes.HasPrefix(bytes.TrimSpace(sig), []byte("-----BEGIN PGP SIGNATURE-----")) {
		blk, err := armor.Decode(bytes.NewReader(sig))
		if err != nil || blk.Type != openpgp.SignatureType {
			return time.Time{}, fmt.Errorf("the checksums' signature can't be read: %v", err)
		}
		if sig, err = io.ReadAll(io.LimitReader(blk.Body, maxSigBytes)); err != nil {
			return time.Time{}, err
		}
	}
	pkt, err := packet.Read(bytes.NewReader(sig))
	if err != nil {
		return time.Time{}, fmt.Errorf("the checksums' signature can't be read: %v", err)
	}
	sp, ok := pkt.(*packet.Signature)
	if !ok {
		return time.Time{}, errors.New("the checksums' signature isn't a signature")
	}
	signer, err := openpgp.CheckDetachedSignature(ring, bytes.NewReader(data), bytes.NewReader(sig))
	if err != nil {
		return time.Time{}, fmt.Errorf("the checksums aren't signed by the image's publisher (%v); nothing was downloaded", err)
	}
	if got := strings.ToUpper(hex.EncodeToString(signer.PrimaryKey.Fingerprint[:])); got != fingerprint {
		return time.Time{}, fmt.Errorf("the checksums are signed by %s, not the image's publisher", got)
	}
	return sp.CreationTime, nil
}

// checkFreshness refuses checksums signed before the pinned date or
// before the newest ones this pool's store has seen (an old, validly
// signed list replayed by a mirror or a man in the middle), and records
// the newer date.
func checkFreshness(r *os.Root, image string, signed, minimum time.Time) error {
	if signed.Before(minimum) {
		return fmt.Errorf("the checksums were signed %s, before the oldest HardyOS accepts (%s); something is replaying old ones", signed.UTC().Format(time.DateOnly), minimum.UTC().Format(time.DateOnly))
	}
	name := "." + image + ".signed"
	if b, err := r.ReadFile(name); err == nil {
		if last, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b))); err == nil && signed.Before(last) {
			return fmt.Errorf("the checksums were signed %s, before ones already seen (%s); something is replaying old ones", signed.UTC().Format(time.RFC3339), last.UTC().Format(time.RFC3339))
		}
	}
	_ = r.Remove(name + ".new")
	f, err := r.OpenFile(name+".new", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(signed.UTC().Format(time.RFC3339) + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	return r.Rename(name+".new", name)
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
