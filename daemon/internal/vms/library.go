package vms

import (
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The VirtIO drivers disc for Windows guests: Fedora's virtio-win, pinned
// and checked by hash (decision 123). A new version is a change here.
const (
	VirtioFile   = "virtio-win-0.1.302.iso"
	VirtioURL    = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.302-1/virtio-win-0.1.302.iso"
	VirtioSHA256 = "303f7ae40dad495d6ae474fdc571df58958a4dbc5c37a522d80f9a203867949d"
	VirtioSize   = 877373440
)

// MaxDownloadBytes bounds one download (a big disk image).
const MaxDownloadBytes = 128 << 30

// LibraryFile is a disc or disk image in the ISOs shared folder.
type LibraryFile struct {
	Name     string    `json:"name"`
	Kind     string    `json:"kind"` // iso or disk
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	// UsedBy lists the VMs that have it in a drive.
	UsedBy []string `json:"usedBy"`
}

// LibraryView is the ISO library.
type LibraryView struct {
	// Pool is where the ISOs shared folder is ("" when there's none yet).
	Pool  string        `json:"pool"`
	Path  string        `json:"path"`
	Files []LibraryFile `json:"files"`
	// Downloads in progress.
	Tasks []Task `json:"tasks"`
}

func (m *Manager) folder(ctx context.Context, pool string, create bool) (*Folder, error) {
	if m.Library == nil {
		return nil, errors.New("there's no ISO library on this server")
	}
	return m.Library.Folder(ctx, pool, create)
}

// ListLibrary lists the ISO library.
func (m *Manager) ListLibrary(ctx context.Context) (*LibraryView, error) {
	v := &LibraryView{Files: []LibraryFile{}, Tasks: m.tasks.list("download")}
	f, err := m.folder(ctx, "", false)
	if err != nil || f == nil {
		return v, err
	}
	v.Pool, v.Path = f.Pool, f.Path
	files, err := listFolder(f)
	if err != nil {
		return nil, err
	}
	used := map[string][]string{}
	if l, err := m.all(ctx); err == nil {
		for _, st := range l {
			names := st.spec.Files()
			if st.spec.NeedsVirtio() {
				names = append(names, VirtioFile)
			}
			for _, d := range st.spec.Disks {
				if d.Import != nil {
					names = append(names, d.Import.File)
				}
			}
			for _, n := range names {
				used[n] = append(used[n], st.spec.ID)
			}
		}
	}
	for i := range files {
		files[i].UsedBy = used[files[i].Name]
		if files[i].UsedBy == nil {
			files[i].UsedBy = []string{}
		}
	}
	v.Files = files
	return v, nil
}

// DeleteFileArgs removes a file from the library.
type DeleteFileArgs struct {
	Name string `json:"name"`
}

// DeleteFile removes a disc or image no VM has in a drive.
func (m *Manager) DeleteFile(ctx context.Context, a DeleteFileArgs) error {
	l, err := m.ListLibrary(ctx)
	if err != nil {
		return err
	}
	for _, f := range l.Files {
		if f.Name == a.Name {
			if len(f.UsedBy) > 0 {
				return Problems{fmt.Sprintf("%s is in a drive of %s; take it out first", a.Name, strings.Join(f.UsedBy, ", "))}
			}
			fo, err := m.folder(ctx, "", false)
			if err != nil || fo == nil {
				return errors.New("the ISOs shared folder isn't available")
			}
			return removeFile(fo, a.Name)
		}
	}
	return Problems{fmt.Sprintf("%s isn't in the ISO library", a.Name)}
}

// DownloadArgs downloads a disc or image into the library.
type DownloadArgs struct {
	// Pool for the ISOs shared folder when it doesn't exist yet.
	Pool string `json:"pool"`
	URL  string `json:"url"`
	// Name to save as (default: from the URL).
	Name string `json:"name,omitempty"`
	// SHA256 of the file as downloaded, checked when given.
	SHA256 string `json:"sha256,omitempty"`
}

// downloadName picks the file name and how to unpack the download.
func downloadName(u *url.URL, name string) (string, string, error) {
	if name == "" {
		base, err := url.PathUnescape(path.Base(u.Path))
		if err != nil || base == "/" || base == "." {
			return "", "", Problems{"the link doesn't end in a file name; give the file a name"}
		}
		name = base
	}
	unpack := ""
	l := strings.ToLower(name)
	switch {
	case strings.HasSuffix(l, ".gz"):
		unpack, name = "gzip", name[:len(name)-3]
	case strings.HasSuffix(l, ".bz2"):
		unpack, name = "bzip2", name[:len(name)-4]
	}
	if err := ValidFile(name); err != nil {
		return "", "", Problems{err.Error()}
	}
	if !IsISO(name) && !IsDiskImage(name) {
		return "", "", Problems{fmt.Sprintf("%s isn't a disc (.iso) or disk image (.qcow2, .img, .raw, .vmdk, .vdi, .vhdx)", name)}
	}
	return name, unpack, nil
}

// StartDownload checks a download and starts it in the background.
func (m *Manager) StartDownload(ctx context.Context, a DownloadArgs) (*Task, error) {
	u, err := url.Parse(strings.TrimSpace(a.URL))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(a.URL) > 2048 {
		return nil, Problems{"the link must be an https:// address"}
	}
	name, unpack, err := downloadName(u, strings.TrimSpace(a.Name))
	if err != nil {
		return nil, err
	}
	sum := strings.ToLower(strings.TrimSpace(a.SHA256))
	if sum != "" {
		if b, err := hex.DecodeString(sum); err != nil || len(b) != sha256.Size {
			return nil, Problems{"the SHA-256 checksum must be 64 hexadecimal characters"}
		}
	}
	f, err := m.folder(ctx, a.Pool, a.Pool != "")
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, Problems{"choose a pool for the ISOs shared folder"}
	}
	if existing, err := listFolder(f); err == nil {
		for _, e := range existing {
			if e.Name == name {
				return nil, Problems{fmt.Sprintf("%s is already in the ISO library", name)}
			}
		}
	}
	for _, t := range m.tasks.list("download") {
		if !t.Done && t.File == name {
			return nil, Problems{fmt.Sprintf("%s is already downloading", name)}
		}
	}
	t, err := m.tasks.start("download", "", name)
	if err != nil {
		return nil, err
	}
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
		defer cancel()
		err := m.download(bg, t, f, u, name, unpack, sum, 0)
		m.tasks.finish(t.ID, err)
		if err != nil {
			m.log().Warn("vms: download failed", "file", name, "err", err)
		} else {
			m.log().Info("vms: downloaded", "file", name, "host", u.Host)
		}
	}()
	return m.tasks.get(t.ID), nil
}

func (m *Manager) download(ctx context.Context, t *Task, f *Folder, u *url.URL, name, unpack, sum string, wantSize int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "HardyOS")
	res, err := m.client().Do(req)
	if err != nil {
		return fmt.Errorf("downloading from %s: %w", u.Host, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", u.Host, res.Status)
	}
	total := res.ContentLength
	if total > MaxDownloadBytes || (wantSize > 0 && total > 0 && total != wantSize) {
		return fmt.Errorf("the file is %d bytes, more than expected", total)
	}
	tmpName := "hardyos-download-" + randomHex(8) + ".part"
	out, err := createTemp(f, tmpName)
	if err != nil {
		return fmt.Errorf("saving into the ISOs shared folder: %w", err)
	}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			_ = removeFile(f, tmpName)
		}
	}()
	h := sha256.New()
	limit := int64(MaxDownloadBytes)
	if wantSize > 0 {
		limit = wantSize
	}
	counted := &countingReader{r: io.LimitReader(res.Body, limit+1), on: func(n int64) {
		if total > 0 {
			m.tasks.progress(t.ID, 99*float64(n)/float64(total), fmt.Sprintf("Downloading %s: %s of %s", name, human(n), human(total)))
		} else {
			m.tasks.progress(t.ID, 0, fmt.Sprintf("Downloading %s: %s", name, human(n)))
		}
	}}
	src := io.TeeReader(counted, h)
	var body io.Reader = src
	switch unpack {
	case "gzip":
		gz, err := gzip.NewReader(src)
		if err != nil {
			return fmt.Errorf("unpacking %s: %w", name, err)
		}
		body = gz
	case "bzip2":
		body = bzip2.NewReader(src)
	}
	n, err := io.Copy(out, io.LimitReader(body, MaxDownloadBytes+1))
	if err != nil {
		return fmt.Errorf("downloading %s: %w", name, err)
	}
	if counted.n.Load() > limit || n > MaxDownloadBytes {
		return errors.New("the file is bigger than allowed")
	}
	if wantSize > 0 && counted.n.Load() != wantSize {
		return fmt.Errorf("the download stopped early (%d of %d bytes)", counted.n.Load(), wantSize)
	}
	if total > 0 && counted.n.Load() != total {
		return fmt.Errorf("the download stopped early (%s of %s)", human(counted.n.Load()), human(total))
	}
	if sum != "" {
		if got := hex.EncodeToString(h.Sum(nil)); got != sum {
			return fmt.Errorf("the file's SHA-256 checksum is %s, not %s; it was damaged or changed, so it was deleted", got, sum)
		}
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := renameInto(f, tmpName, name); err != nil {
		return err
	}
	ok = true
	return nil
}

// EnsureVirtio downloads the VirtIO drivers disc if it isn't in the
// library; the task is nil when it's already there.
func (m *Manager) EnsureVirtio(ctx context.Context, pool string) (*Task, error) {
	if _, err := m.virtioPath(ctx); err == nil {
		return nil, nil
	}
	for _, t := range m.tasks.list("download") {
		if !t.Done && t.File == VirtioFile {
			return m.tasks.get(t.ID), nil
		}
	}
	f, err := m.folder(ctx, pool, pool != "")
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, Problems{"choose a pool for the ISOs shared folder"}
	}
	u, _ := url.Parse(VirtioURL)
	t, err := m.tasks.start("download", "", VirtioFile)
	if err != nil {
		return nil, err
	}
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 6*time.Hour)
		defer cancel()
		// A file of that name that isn't the real disc (an earlier broken
		// copy) makes way for it.
		_ = removeFile(f, VirtioFile)
		err := m.download(bg, t, f, u, VirtioFile, "", VirtioSHA256, VirtioSize)
		m.tasks.finish(t.ID, err)
		if err != nil {
			m.log().Warn("vms: VirtIO drivers download failed", "err", err)
		}
	}()
	return m.tasks.get(t.ID), nil
}

// virtioPath is the drivers disc's path, if it's there in full.
func (m *Manager) virtioPath(ctx context.Context) (string, error) {
	f, err := m.folder(ctx, "", false)
	if err != nil || f == nil {
		return "", errors.New("no ISO library")
	}
	file, err := openFile(f, VirtioFile)
	if err != nil {
		return "", err
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil || fi.Size() != VirtioSize {
		return "", errors.New("the VirtIO drivers disc is incomplete")
	}
	return filepath.Join(f.Path, VirtioFile), nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func human(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%d MB", n>>20)
	default:
		return fmt.Sprintf("%d KB", n>>10)
	}
}

// ---- downloads only reach the internet --------------------------------------

func (m *Manager) client() *http.Client {
	if m.HTTP != nil {
		return m.HTTP
	}
	allowLocal := m.AllowLocalDownloads
	d := &net.Dialer{Timeout: 30 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return err
		}
		if !allowLocal && localAddr(ip) {
			return fmt.Errorf("%s is on this server or its own network; downloads only come from the internet", ip)
		}
		return nil
	}}
	tr := &http.Transport{
		// No proxy: the guard must see the address actually connected to.
		Proxy:                 nil,
		DialContext:           d.DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		MaxIdleConns:          4,
	}
	return &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 8 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("the download redirected to an address that isn't https://")
		}
		return nil
	}}
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func localAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	return !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsLinkLocalMulticast() || cgnat.Contains(ip) || (ip.Is4() && ip.As4()[0] == 0)
}

// ---- background tasks --------------------------------------------------------

// Task is a download or an import running in hardyd-priv; hardyd's job
// follows it with vms.task.
type Task struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"` // download, import
	VM       string    `json:"vm"`
	File     string    `json:"file"`
	Progress float64   `json:"progress"`
	Message  string    `json:"message"`
	Done     bool      `json:"done"`
	Error    string    `json:"error"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
}

// MaxTasks bounds downloads and imports running at once.
const MaxTasks = 4

type taskTable struct {
	mu sync.Mutex
	m  map[string]*Task
}

func (t *taskTable) start(kind, vm, file string) (*Task, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]*Task{}
	}
	active := 0
	for id, x := range t.m {
		if x.Done && time.Since(x.Finished) > time.Hour {
			delete(t.m, id)
			continue
		}
		if !x.Done {
			active++
		}
	}
	if active >= MaxTasks {
		return nil, Problems{fmt.Sprintf("%d downloads and imports are already running; wait for one to finish", MaxTasks)}
	}
	x := &Task{ID: randomHex(12), Kind: kind, VM: vm, File: file, Started: time.Now().UTC(), Message: "Starting"}
	t.m[x.ID] = x
	return x, nil
}

func (t *taskTable) progress(id string, pct float64, msg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if x, ok := t.m[id]; ok && !x.Done {
		x.Progress = min(max(pct, 0), 100)
		x.Message = msg
	}
}

func (t *taskTable) finish(id string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if x, ok := t.m[id]; ok {
		x.Done = true
		x.Finished = time.Now().UTC()
		if err != nil {
			x.Error = err.Error()
			x.Message = "Failed"
		} else {
			x.Progress = 100
			x.Message = "Done"
		}
	}
}

func (t *taskTable) get(id string) *Task {
	t.mu.Lock()
	defer t.mu.Unlock()
	if x, ok := t.m[id]; ok {
		c := *x
		return &c
	}
	return nil
}

func (t *taskTable) list(kind string) []Task {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := []Task{}
	for _, x := range t.m {
		if kind == "" || x.Kind == kind {
			out = append(out, *x)
		}
	}
	return out
}

// TaskArgs names a task.
type TaskArgs struct {
	ID string `json:"id"`
}

// TaskStatus reports a task.
func (m *Manager) TaskStatus(a TaskArgs) (*Task, error) {
	if t := m.tasks.get(a.ID); t != nil {
		return t, nil
	}
	return nil, Problems{"that download or import isn't known (HardyOS restarted?)"}
}

// ---- the library as a shared folder ---------------------------------------

// ShareLibrary is the ISOs shared folder of internal/shares.
type ShareLibrary struct {
	Shares ShareStore
}

// ShareStore is what ShareLibrary needs from shares.Manager.
type ShareStore interface {
	Lookup(ctx context.Context, id string) (pool, path string, dev uint64, err error)
	CreateLibrary(ctx context.Context, pool string) error
}

// LibraryShareID is the ISOs shared folder's id.
const LibraryShareID = "isos"

// Folder implements Library.
func (l ShareLibrary) Folder(ctx context.Context, pool string, create bool) (*Folder, error) {
	p, dir, dev, err := l.Shares.Lookup(ctx, LibraryShareID)
	if err == nil {
		if dev == 0 {
			return nil, errors.New("the ISOs shared folder isn't mounted (is its pool imported and unlocked?)")
		}
		return &Folder{Pool: p, Path: dir, Dev: dev}, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if !create {
		return nil, nil
	}
	if err := l.Shares.CreateLibrary(ctx, pool); err != nil {
		return nil, err
	}
	p, dir, dev, err = l.Shares.Lookup(ctx, LibraryShareID)
	if err != nil {
		return nil, err
	}
	if dev == 0 {
		return nil, errors.New("the new ISOs shared folder isn't mounted")
	}
	return &Folder{Pool: p, Path: dir, Dev: dev}, nil
}
