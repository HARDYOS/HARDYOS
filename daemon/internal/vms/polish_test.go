package vms

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/devices"
	"github.com/hardyos/hardyos/daemon/internal/snapshots"
)

// ---- the verified catalog -----------------------------------------------

type catalogServer struct {
	srv      *httptest.Server
	image    []byte
	sums     string
	imgHits  atomic.Int32
	redirect string // the image redirects here
}

func newCatalogServer(t *testing.T) *catalogServer {
	c := &catalogServer{image: []byte(strings.Repeat("debian cloud image ", 1000))}
	sum := sha512.Sum512(c.image)
	c.sums = hex.EncodeToString(sum[:]) + "  debian-13-genericcloud-amd64.qcow2\n" +
		strings.Repeat("0", 128) + "  debian-13-genericcloud-arm64.qcow2\n"
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest/SHA512SUMS":
			fmt.Fprint(w, c.sums)
		case "/latest/debian-13-genericcloud-amd64.qcow2":
			if c.redirect != "" {
				http.Redirect(w, r, c.redirect, http.StatusFound)
				return
			}
			c.imgHits.Add(1)
			_, _ = w.Write(c.image)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *catalogServer) catalog() []CatalogImage {
	u, _ := url.Parse(c.srv.URL)
	return []CatalogImage{{
		ID: CatalogDebian13, Name: "Debian 13", Kind: "disk", Hosts: []string{u.Hostname()},
		Files: map[string]CatalogFile{"x86_64": {
			URL: c.srv.URL + "/latest/debian-13-genericcloud-amd64.qcow2", File: "debian-13-genericcloud-amd64.qcow2",
			SumsURL: c.srv.URL + "/latest/SHA512SUMS", SumsAlgo: "sha512",
		}},
	}}
}

func catalogEnv(t *testing.T) (*testEnv, *catalogServer) {
	e := newEnv(t)
	c := newCatalogServer(t)
	e.m.HTTP = c.srv.Client()
	e.m.CatalogImages = c.catalog()
	return e, c
}

func TestCatalogFetchVerifiesAndCaches(t *testing.T) {
	e, c := catalogEnv(t)
	ctx := context.Background()
	task, err := e.m.FetchCatalog(ctx, FetchArgs{Image: CatalogDebian13, Pool: "tank"})
	if err != nil {
		t.Fatal(err)
	}
	done := waitDone(t, e.m, task.ID)
	sum := sha512.Sum512(c.image)
	if done.Error != "" || done.Digest != "sha512:"+hex.EncodeToString(sum[:]) || done.File != "debian-13-genericcloud-amd64.qcow2" {
		t.Fatalf("task = %+v", done)
	}
	if b, err := os.ReadFile(filepath.Join(e.isoDir, done.File)); err != nil || string(b) != string(c.image) {
		t.Fatalf("library copy: %v", err)
	}
	// Again: the copy in the library still matches, nothing is downloaded.
	task, _ = e.m.FetchCatalog(ctx, FetchArgs{Image: CatalogDebian13})
	if d := waitDone(t, e.m, task.ID); d.Error != "" || c.imgHits.Load() != 1 {
		t.Fatalf("cached fetch = %+v, %d downloads", d, c.imgHits.Load())
	}
	// A changed copy (someone wrote into the shared folder) is replaced.
	write(t, filepath.Join(e.isoDir, done.File), "tampered")
	task, _ = e.m.FetchCatalog(ctx, FetchArgs{Image: CatalogDebian13})
	if d := waitDone(t, e.m, task.ID); d.Error != "" || c.imgHits.Load() != 2 {
		t.Fatalf("refetch = %+v, %d downloads", d, c.imgHits.Load())
	}
	if b, _ := os.ReadFile(filepath.Join(e.isoDir, done.File)); string(b) != string(c.image) {
		t.Fatal("the tampered copy stayed")
	}
}

func TestCatalogRefusesWrongChecksum(t *testing.T) {
	e, c := catalogEnv(t)
	c.sums = strings.Repeat("ab", 64) + "  debian-13-genericcloud-amd64.qcow2\n"
	task, err := e.m.FetchCatalog(context.Background(), FetchArgs{Image: CatalogDebian13, Pool: "tank"})
	if err != nil {
		t.Fatal(err)
	}
	d := waitDone(t, e.m, task.ID)
	if !strings.Contains(d.Error, "SHA512 checksum") || d.Digest != "" {
		t.Fatalf("task = %+v", d)
	}
	if _, err := os.Stat(filepath.Join(e.isoDir, "debian-13-genericcloud-amd64.qcow2")); err == nil {
		t.Fatal("a file with the wrong checksum was kept")
	}
}

func TestCatalogStaysOnItsHosts(t *testing.T) {
	e, c := catalogEnv(t)
	u, _ := url.Parse(c.srv.URL)
	// Same server, another name: not one of the image's hosts.
	c.redirect = "https://localhost:" + u.Port() + "/elsewhere.qcow2"
	task, err := e.m.FetchCatalog(context.Background(), FetchArgs{Image: CatalogDebian13, Pool: "tank"})
	if err != nil {
		t.Fatal(err)
	}
	if d := waitDone(t, e.m, task.ID); !strings.Contains(d.Error, "isn't where this image comes from") {
		t.Fatalf("task = %+v", d)
	}
	// hardyd can only name images.
	if _, err := e.m.FetchCatalog(context.Background(), FetchArgs{Image: "https://evil.example/x.qcow2"}); err == nil {
		t.Fatal("a link was accepted as an image")
	}
	// Every image's own links are on its own hosts.
	for _, img := range Catalog {
		for arch, f := range img.Files {
			for _, raw := range []string{f.URL, f.SumsURL, f.SigURL} {
				if raw == "" {
					continue
				}
				if _, err := allowedURL(raw, img.Hosts); err != nil {
					t.Errorf("%s/%s: %v", img.ID, arch, err)
				}
			}
			if f.SHA256 == "" && f.SumsURL == "" {
				t.Errorf("%s/%s has nothing to check it against", img.ID, arch)
			}
			if ValidFile(f.File) != nil || !(IsDiskImage(f.File) || IsISO(f.File)) {
				t.Errorf("%s/%s: library name %q", img.ID, arch, f.File)
			}
		}
	}
}

func TestUbuntuSignature(t *testing.T) {
	sums, err := os.ReadFile("testdata/catalog/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile("testdata/catalog/SHA256SUMS.gpg")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(ubuntuKey, UbuntuKeyFingerprint, sums, sig); err != nil {
		t.Fatalf("the real signature: %v", err)
	}
	h, err := findSum(sums, "noble-server-cloudimg-amd64.img", "sha256")
	if err != nil || len(h) != 64 {
		t.Fatalf("sum = %q %v", h, err)
	}
	bad := append([]byte{}, sums...)
	bad[0] ^= 1
	if err := verifySignature(ubuntuKey, UbuntuKeyFingerprint, bad, sig); err == nil {
		t.Fatal("changed checksums passed the signature check")
	}
	if err := verifySignature(ubuntuKey, strings.Repeat("A", 40), sums, sig); err == nil {
		t.Fatal("another key's fingerprint was accepted")
	}
}

func TestFindSum(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	if h, err := findSum([]byte(a+" *x.img\n"), "x.img", "sha256"); err != nil || h != a {
		t.Fatalf("%q %v", h, err)
	}
	for name, in := range map[string]string{
		"missing":      a + "  y.img\n",
		"twice":        a + "  x.img\n" + b + "  x.img\n",
		"short":        "abcd  x.img\n",
		"path":         a + "  ../x.img\n",
		"sha512 short": a + "  x.img\n",
	} {
		algo := "sha256"
		if name == "sha512 short" {
			algo = "sha512"
		}
		if _, err := findSum([]byte(in), "x.img", algo); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The import checks the verified checksum again as it reads the image.
func TestImportChecksDigest(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 1024)
	ctx := context.Background()
	s := linuxSpec(t)
	good := sha256.Sum256(make([]byte, 1024))
	s.Disks[0].Import.Digest = "sha256:" + strings.Repeat("0", 64)
	if _, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	e.stream.info = `{"format":"qcow2","virtual-size":1073741824,"format-specific":{"type":"qcow2","data":{}}}`
	task, err := e.m.StartImport(ctx, ImportArgs{ID: "web", Disk: "disk0"})
	if err != nil {
		t.Fatal(err)
	}
	if d := waitDone(t, e.m, task.ID); !strings.Contains(d.Error, "changed since it was downloaded") {
		t.Fatalf("import = %+v", d)
	}
	// With the right one it goes through.
	e2 := newEnv(t)
	e2.bridge.name = "br0"
	e2.addISO(t, "noble-server-cloudimg-amd64.img", 1024)
	s.Disks[0].Import.Digest = "sha256:" + hex.EncodeToString(good[:])
	if _, err := e2.m.Create(ctx, CreateArgs{Spec: s, Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	e2.stream.info = e.stream.info
	task, err = e2.m.StartImport(ctx, ImportArgs{ID: "web", Disk: "disk0"})
	if err != nil {
		t.Fatal(err)
	}
	if d := waitDone(t, e2.m, task.ID); d.Error != "" {
		t.Fatalf("import = %+v", d)
	}
	// A malformed digest never gets that far.
	s.Disks[0].Import.Digest = "md5:abc"
	s.ID = "web2"
	if _, err := e2.m.Create(ctx, CreateArgs{Spec: s, Password: "longenough"}); err == nil || !strings.Contains(err.Error(), "checksum must be") {
		t.Fatalf("bad digest: %v", err)
	}
}

func TestNewTemplates(t *testing.T) {
	for _, id := range []string{"debian13", "ubuntu2404", "haos"} {
		tp, ok := TemplateByID(id)
		if !ok || tp.Catalog == "" {
			t.Fatalf("%s: %+v", id, tp)
		}
		if _, ok := (&Manager{}).catalogImage(tp.Catalog); !ok {
			t.Errorf("%s names the unknown image %s", id, tp.Catalog)
		}
	}
	for _, id := range []string{"windows11", "windows-server-2025"} {
		tp, _ := TemplateByID(id)
		if !tp.Unattend || !tp.Virtio || !tp.Firmware.TPM || !tp.Firmware.SecureBoot || len(tp.Editions) == 0 {
			t.Errorf("%s: %+v", id, tp)
		}
	}
}

// ---- unattended Windows ---------------------------------------------------

func winSpec(t *testing.T, tmpl string) Spec {
	s := fromTemplate(t, "win", tmpl)
	s.UUID = ""
	s.NICs[0].MAC = ""
	s.Media = append([]Media{{Kind: MediaISO, ISO: "Win11_24H2_English_x64.iso"}}, s.Media...)
	s.Media = append(s.Media, Media{Kind: MediaUnattend})
	s.Unattend = &Unattend{User: "cade", Locale: "en-US", TimeZone: "Pacific Standard Time", Edition: "Windows 11 Pro"}
	return *s
}

var hookOnce sync.Once

func TestAnswerFile(t *testing.T) {
	hookOnce.Do(func() {
		RegisterFirstLogonHook("test-hook", func(s *Spec) []LogonCommand {
			return []LogonCommand{{Description: "Say hello", CommandLine: `cmd /c echo hello & echo <b>`}, {CommandLine: "bad\nline"}}
		})
	})
	s := winSpec(t, "windows11")
	s.Unattend.Hooks = []string{"test-hook"}
	s.Normalize()
	if err := s.Validate(Host{Arch: x86, TPM: true, SecureBoot: true}); err != nil {
		t.Fatal(err)
	}
	b, err := AnswerFile(&s, "x86_64", "S3cret pass&<>")
	if err != nil {
		t.Fatal(err)
	}
	x := string(b)
	var doc struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(b, &doc); err != nil || doc.XMLName.Local != "unattend" {
		t.Fatalf("not XML: %v", err)
	}
	for _, want := range []string{
		`<ComputerName>WIN</ComputerName>`,
		`<Key>/IMAGE/NAME</Key><Value>Windows 11 Pro</Value>`,
		`<Path>E:\vioscsi\w11\amd64</Path>`,
		`<TimeZone>Pacific Standard Time</TimeZone>`,
		`<Name>cade</Name>`,
		`<Type>EFI</Type>`,
		`virtio-win-guest-tools.exe /install /quiet /norestart`,
		`<CommandLine>cmd /c echo hello &amp; echo &lt;b&gt;</CommandLine>`,
		`<PlainText>false</PlainText>`,
		`<LogonCount>1</LogonCount>`,
	} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(x, "S3cret") || strings.Contains(x, "bad\nline") || strings.Contains(x, "ProductKey") {
		t.Fatalf("answer file:\n%s", x)
	}
	if !strings.Contains(x, encodePassword("S3cret pass&<>", "Password")) {
		t.Fatal("the password isn't in the answer file")
	}
	// Windows Server gets its own driver folder.
	srv := winSpec(t, "windows-server-2025")
	srv.Unattend.Edition = ""
	srv.Unattend.ImageIndex = 2
	srv.Normalize()
	b, _ = AnswerFile(&srv, "x86_64", "longenough")
	if !strings.Contains(string(b), `\vioscsi\2k25\amd64`) || !strings.Contains(string(b), `<Key>/IMAGE/INDEX</Key><Value>2</Value>`) {
		t.Fatalf("server answer file:\n%s", b)
	}
}

func TestUnattendValidation(t *testing.T) {
	h := Host{Arch: x86, TPM: true, SecureBoot: true}
	bad := map[string]func(*Spec){
		"administrator": func(s *Spec) { s.Unattend.User = "Administrator" },
		"quote in user": func(s *Spec) { s.Unattend.User = "ca'de" },
		"computer name": func(s *Spec) { s.Unattend.ComputerName = "has space" },
		"locale":        func(s *Spec) { s.Unattend.Locale = "<x>" },
		"edition":       func(s *Spec) { s.Unattend.Edition = "Pro</Value>" },
		"both":          func(s *Spec) { s.Unattend.ImageIndex = 3 },
		"unknown hook":  func(s *Spec) { s.Unattend.Hooks = []string{"rm-rf"} },
		"linux":         func(s *Spec) { s.OS = "linux" },
		"no disc":       func(s *Spec) { s.Media = s.Media[:len(s.Media)-1] },
		"time zone":     func(s *Spec) { s.Unattend.TimeZone = "UTC\n<x>" },
	}
	for name, f := range bad {
		s := winSpec(t, "windows11")
		f(&s)
		s.Normalize()
		if err := s.Validate(h); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := AnswerFile(&Spec{ID: "x", Unattend: &Unattend{}}, "x86_64", "short"); err == nil {
		t.Error("a short password was accepted")
	}
}

func TestCreateUnattended(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "Win11_24H2_English_x64.iso", 10)
	e.addISO(t, VirtioFile, VirtioSize)
	ctx := context.Background()
	s := winSpec(t, "windows11")
	// It needs the installer disc.
	noISO := s
	noISO.Media = noISO.Media[1:]
	if _, err := e.m.Create(ctx, CreateArgs{Spec: noISO, Password: "longenough"}); err == nil || !strings.Contains(err.Error(), "installer disc") {
		t.Fatalf("without the ISO: %v", err)
	}
	res, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "Windows pass 1"})
	if err != nil {
		t.Fatal(err)
	}
	if res.VM.Unattend == nil || !res.VM.Unattend.Pending {
		t.Fatalf("unattend = %+v", res.VM.Unattend)
	}
	disc := filepath.Join(e.root, "mnt/tank/vms/win", unattendFile)
	if fi, err := os.Stat(disc); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("answer disc: %v %v", fi, err)
	}
	if !e.sim.has("xorriso -as mkisofs -quiet -volid UNATTEND") {
		t.Fatal("no answer disc made")
	}
	spec, _ := os.ReadFile(filepath.Join(e.root, "mnt/tank/vms/win", specFile))
	if strings.Contains(string(spec), "Windows pass 1") || strings.Contains(string(spec), encodePassword("Windows pass 1", "Password")) {
		t.Fatal("the password is in vm.json")
	}
	if !strings.Contains(e.sim.defined["win"], "unattend.iso") {
		t.Fatal("the answer disc isn't in a drive")
	}
	// The first start answers the boot prompt, once.
	BootKeyPresses, BootKeyEvery = 2, time.Millisecond
	if _, err := e.m.Start(ctx, "win"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && !e.sim.has("virsh -c qemu:///system -q send-key win KEY_ENTER"); i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if !e.sim.has("virsh -c qemu:///system -q send-key win KEY_ENTER") {
		t.Fatal("no key pressed for the installer")
	}
	v, _ := e.m.Get(ctx, "win")
	if v.Unattend.Pending {
		t.Fatal("still pending after the first start")
	}
	// Taking the disc out ends it and deletes the disc.
	if _, err := e.m.Stop(ctx, StopArgs{ID: "win", Force: true}); err != nil {
		t.Fatal(err)
	}
	up := v.Spec
	up.Media = up.Media[:len(up.Media)-1]
	if _, err := e.m.Update(ctx, UpdateArgs{Spec: up}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(disc); !os.IsNotExist(err) {
		t.Fatalf("the answer disc is still there: %v", err)
	}
	v, _ = e.m.Get(ctx, "win")
	if v.Unattend != nil {
		t.Fatal("the settings stayed")
	}
	// And it can't come back.
	up = v.Spec
	up.Media = append(up.Media, Media{Kind: MediaUnattend})
	up.Unattend = &Unattend{User: "cade", Locale: "en-US"}
	if _, err := e.m.Update(ctx, UpdateArgs{Spec: up}); err == nil || !strings.Contains(err.Error(), "only comes with a new VM") {
		t.Fatalf("answer disc added later: %v", err)
	}
}

// ---- sound and clipboard --------------------------------------------------

func TestSoundAndClipboardXML(t *testing.T) {
	s := fromTemplate(t, "win", "windows11")
	s.Sound, s.Clipboard = true, true
	s.Normalize()
	b, err := DomainXML(s, x86, Paths{StateDir: "/mnt/tank/vms/win", Bridge: "br0", Virtio: "/mnt/tank/isos/" + VirtioFile}, nil)
	if err != nil {
		t.Fatal(err)
	}
	x := string(b)
	for _, want := range []string{
		`<channel type="qemu-vdagent">`, `<clipboard copypaste="yes"></clipboard>`, `<target type="virtio" name="com.redhat.spice.0"></target>`,
		`<sound model="ich9">`, `<audio id="1" type="none"></audio>`, `<listen type="socket"></listen>`,
	} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %s", want)
		}
	}
	if !strings.Contains(between(x, `<graphics type="vnc">`, `</graphics>`), `<audio id="1">`) {
		t.Error("the console doesn't carry the sound")
	}
	s.Sound, s.Clipboard = false, false
	b, _ = DomainXML(s, x86, Paths{StateDir: "/mnt/tank/vms/win", Bridge: "br0", Virtio: "/x"}, nil)
	if strings.Contains(string(b), "<sound") || strings.Contains(string(b), "qemu-vdagent") {
		t.Error("sound or clipboard without asking")
	}
}

// ---- scheduled snapshots ----------------------------------------------------

func TestScheduledSnapshots(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.SetSchedule(ctx, SetScheduleArgs{ID: "web", Schedule: &Schedule{Hourly: 99}}); err == nil {
		t.Fatal("99 hourly snapshots accepted")
	}
	if _, err := e.m.SetSchedule(ctx, SetScheduleArgs{ID: "web", Schedule: &Schedule{Hourly: 2, Daily: 1}}); err != nil {
		t.Fatal(err)
	}
	// A manual one, never pruned.
	manual, err := e.m.TakeSnapshot(ctx, SnapshotArgs{ID: "web", Label: "mine"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 21, 9, 30, 0, 0, time.UTC)
	e.m.Now = func() time.Time { return now }
	for h := 0; h < 4; h++ {
		e.m.TickSchedules(ctx)
		e.m.TickSchedules(ctx) // twice in an hour takes nothing more
		now = now.Add(time.Hour)
	}
	l, err := e.m.Snapshots(ctx, "web")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range l {
		got[s.Name] = s.Kind
	}
	want := map[string]string{
		manual.Name:                    "manual",
		"vm-auto-hourly-20261121-1100": "hourly",
		"vm-auto-hourly-20261121-1200": "hourly",
		"vm-auto-daily-20261121-0000":  "daily",
	}
	if len(got) != len(want) {
		t.Fatalf("snapshots = %v", got)
	}
	for n, k := range want {
		if got[n] != k {
			t.Errorf("%s = %q, want %q (all: %v)", n, got[n], k, got)
		}
	}
	// Updates keep the schedule; rollback to an automatic one works.
	v, _ := e.m.Get(ctx, "web")
	s := v.Spec
	s.Schedule = nil
	if _, err := e.m.Update(ctx, UpdateArgs{Spec: s}); err != nil {
		t.Fatal(err)
	}
	if v, _ := e.m.Get(ctx, "web"); v.Schedule == nil || v.Schedule.Hourly != 2 {
		t.Fatalf("schedule after an update = %+v", v.Schedule)
	}
	if _, err := e.m.Rollback(ctx, RollbackArgs{ID: "web", Snapshot: "vm-auto-daily-20261121-0000", Confirm: "web"}); err != nil {
		t.Fatal(err)
	}
	// Off: nothing more is taken or pruned.
	if _, err := e.m.SetSchedule(ctx, SetScheduleArgs{ID: "web", Schedule: &Schedule{}}); err != nil {
		t.Fatal(err)
	}
	if v, _ := e.m.Get(ctx, "web"); v.Schedule != nil {
		t.Fatal("an all-zero schedule stayed")
	}
}

func TestAutoSnapNames(t *testing.T) {
	at := time.Date(2026, 11, 25, 17, 42, 0, 0, time.UTC) // a Wednesday
	for k, want := range map[snapshots.Kind]string{
		snapshots.Hourly: "vm-auto-hourly-20261125-1700", snapshots.Daily: "vm-auto-daily-20261125-0000",
		snapshots.Weekly: "vm-auto-weekly-20261123-0000", snapshots.Monthly: "vm-auto-monthly-20261101-0000",
	} {
		if got := AutoSnapName(k, at); got != want || !snapNameRE.MatchString(got) {
			t.Errorf("%s = %s", k, got)
		}
		if kk, _, ok := autoKind(want); !ok || kk != k {
			t.Errorf("autoKind(%s) = %s %v", want, kk, ok)
		}
	}
	for _, n := range []string{"vm-auto-daily-20261125-1700", "vm-auto-yearly-20261101-0000", "vm-auto-hourly-20261125-1742"} {
		if _, _, ok := autoKind(n); ok {
			t.Errorf("%s read as automatic", n)
		}
	}
}

// ---- saved templates ----------------------------------------------------------

func (e *testEnv) fakeSendRecv() *[]string {
	var calls []string
	e.m.SendRecvFunc = func(_ context.Context, from, to string) error {
		calls = append(calls, from+" -> "+to)
		e.sim.mu.Lock()
		defer e.sim.mu.Unlock()
		src, snap, _ := strings.Cut(from, "@")
		p := map[string]string{"type": "volume", "volsize": e.sim.datasets[src]["volsize"], "refreservation": "34359738368"}
		e.sim.datasets[to] = p
		e.sim.snaps[to+"@"+snap] = map[string]string{"creation": "1800000000", "used": "0"}
		return nil
	}
	return &calls
}

func TestUserTemplates(t *testing.T) {
	e := newEnv(t)
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	calls := e.fakeSendRecv()
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Start(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.MakeTemplate(ctx, MakeTemplateArgs{VM: "web", ID: "base", Name: "Base"}); err == nil || !strings.Contains(err.Error(), "shut the VM down") {
		t.Fatalf("template of a running VM: %v", err)
	}
	_, _ = e.m.Stop(ctx, StopArgs{ID: "web", Force: true})
	if _, err := e.m.MakeTemplate(ctx, MakeTemplateArgs{VM: "web", ID: "Bad Name", Name: "x"}); err == nil {
		t.Fatal("bad template name accepted")
	}
	task, err := e.m.MakeTemplate(ctx, MakeTemplateArgs{VM: "web", ID: "base", Name: "Base server"})
	if err != nil {
		t.Fatal(err)
	}
	if d := waitDone(t, e.m, task.ID); d.Error != "" {
		t.Fatalf("template task = %+v", d)
	}
	l, err := e.m.UserTemplates(ctx)
	if err != nil || len(l) != 1 {
		t.Fatalf("templates = %+v %v", l, err)
	}
	tp := l[0]
	if tp.ID != "base" || tp.From != "web" || tp.Spec.UUID != "" || tp.Spec.NICs[0].MAC != "" || tp.Spec.CloudInit.PasswordHash != "" ||
		tp.Spec.Disks[0].Import != nil || tp.Spec.Template != "linux" {
		t.Fatalf("template = %+v", tp)
	}
	if !e.sim.has("zfs rename tank/vm-templates/base/disk0@hardyos-tpl-") || !e.sim.has("zfs set refreservation=none tank/vm-templates/base/disk0") {
		t.Fatalf("lines = %v", e.sim.Lines())
	}
	// The VM's own snapshot for the copy is gone.
	if snaps, _ := e.m.Snapshots(ctx, "web"); len(snaps) != 0 {
		t.Fatalf("snapshots left on the VM: %+v", snaps)
	}
	for k := range e.sim.snaps {
		if strings.HasPrefix(k, "tank/vms/web") {
			t.Fatalf("left %s", k)
		}
	}

	// A VM from the template.
	s := tp.Spec
	s.ID, s.Name, s.Pool, s.FromTemplate = "web2", "Web 2", "tank", "base"
	s.Disks[0].Clone = &Clone{Template: "base"}
	s.Disks[0].SizeGB = 8
	if _, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "longenough"}); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("smaller than the template: %v", err)
	}
	s.Disks[0].SizeGB = 40
	res, err := e.m.Create(ctx, CreateArgs{Spec: s, Password: "longenough"})
	if err != nil {
		t.Fatal(err)
	}
	if res.VM.UUID == "" || res.VM.NICs[0].MAC == "" {
		t.Fatalf("new VM = %+v", res.VM)
	}
	if e.sim.has("zfs create -s -V 40G -o volblocksize=16K -o org.hardyos:vm=web2 tank/vms/web2/disk0") {
		t.Fatal("an empty disk was made for a template disk")
	}
	ct, err := e.m.StartClone(ctx, ImportArgs{ID: "web2", Disk: "disk0"})
	if err != nil {
		t.Fatal(err)
	}
	if d := waitDone(t, e.m, ct.ID); d.Error != "" {
		t.Fatalf("clone = %+v", d)
	}
	for _, want := range []string{"zfs destroy tank/vms/web2/disk0@template", "zfs set org.hardyos:vm=web2 tank/vms/web2/disk0", "zfs set volsize=40G tank/vms/web2/disk0"} {
		if !e.sim.has(want) {
			t.Errorf("missing %s", want)
		}
	}
	if (*calls)[len(*calls)-1] != "tank/vm-templates/base/disk0@template -> tank/vms/web2/disk0" {
		t.Fatalf("send/recv = %v", *calls)
	}
	if _, err := e.m.StartClone(ctx, ImportArgs{ID: "web2", Disk: "disk0"}); err == nil {
		t.Fatal("cloned twice")
	}
	// Deleting needs the name; VMs made from it keep their disks.
	if err := e.m.DeleteTemplate(ctx, DeleteTemplateArgs{ID: "base", Confirm: "nope"}); err == nil {
		t.Fatal("deleted without the name")
	}
	if err := e.m.DeleteTemplate(ctx, DeleteTemplateArgs{ID: "base", Confirm: "Base server"}); err != nil {
		t.Fatal(err)
	}
	if l, _ := e.m.UserTemplates(ctx); len(l) != 0 {
		t.Fatalf("still listed: %+v", l)
	}
	if _, ok := e.sim.datasets["tank/vms/web2/disk0"]; !ok {
		t.Fatal("the VM's disk went with the template")
	}
}

func TestGeneralize(t *testing.T) {
	s := winSpec(t, "windows11")
	s.UUID = NewUUID()
	s.NICs[0].MAC = "52:54:00:aa:bb:cc"
	s.Devices = []devices.Device{{Kind: devices.KindUSB, ID: "046d:c52b"}}
	s.Schedule = &Schedule{Daily: 3}
	s.Autostart.Enabled = true
	g := Generalize(s)
	if g.UUID != "" || g.NICs[0].MAC != "" || len(g.Devices) != 0 || g.Schedule != nil || g.Unattend != nil || g.Autostart.Enabled {
		t.Fatalf("generalized = %+v", g)
	}
	for _, m := range g.Media {
		if m.Kind == MediaISO || m.Kind == MediaUnattend {
			t.Fatalf("media kept: %+v", g.Media)
		}
	}
	if s.NICs[0].MAC == "" {
		t.Fatal("the original changed")
	}
}

// ---- USB hot-plug -------------------------------------------------------------

type fakeHotplug struct {
	*fakeDevices
	plugged []string
	refuse  bool
}

func (f *fakeHotplug) HotplugUSB(_ context.Context, vm string, d devices.Device) (string, error) {
	if f.refuse {
		return "", devices.Problems{{Device: d.ID, Message: "The USB device holds the boot disk."}}
	}
	f.plugged = append(f.plugged, vm+" "+d.ID)
	return devices.HostdevUSBByID(d.ID[:4], d.ID[5:])
}

func (f *fakeHotplug) UnplugUSB(_ context.Context, vm, id string) error {
	f.plugged = append(f.plugged, "out "+vm+" "+id)
	return nil
}

func TestUSBHotplug(t *testing.T) {
	e := newEnv(t)
	hp := &fakeHotplug{fakeDevices: e.devs}
	e.m.Devices = hp
	e.bridge.name = "br0"
	e.addISO(t, "noble-server-cloudimg-amd64.img", 10)
	ctx := context.Background()
	if _, err := e.m.Create(ctx, CreateArgs{Spec: linuxSpec(t), Password: "longenough"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.AttachUSB(ctx, USBArgs{ID: "web", Device: "046d:c52b"}); err == nil || !strings.Contains(err.Error(), "start the VM") {
		t.Fatalf("while off: %v", err)
	}
	if _, err := e.m.Start(ctx, "web"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.AttachUSB(ctx, USBArgs{ID: "web", Device: "1-4.2"}); err == nil {
		t.Fatal("a port was hot-plugged")
	}
	v, err := e.m.AttachUSB(ctx, USBArgs{ID: "web", Device: "046d:c52b", Persist: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.LiveUSB) != 1 || len(v.Devices) != 1 || !e.sim.has("virsh -c qemu:///system -q attach-device web /mnt/tank/vms/web/hotplug-") {
		t.Fatalf("vm = %+v / %v", v.LiveUSB, v.Devices)
	}
	if _, err := e.m.AttachUSB(ctx, USBArgs{ID: "web", Device: "046d:c52b"}); err == nil {
		t.Fatal("plugged twice")
	}
	hp.refuse = true
	if _, err := e.m.AttachUSB(ctx, USBArgs{ID: "web", Device: "0781:5583"}); err == nil || !strings.Contains(err.Error(), "boot disk") {
		t.Fatalf("refused device: %v", err)
	}
	v, err = e.m.DetachUSB(ctx, USBArgs{ID: "web", Device: "046d:c52b", Persist: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.LiveUSB) != 0 || len(v.Devices) != 0 {
		t.Fatalf("after unplugging: %+v", v)
	}
	// The temporary device files are gone.
	files, _ := filepath.Glob(filepath.Join(e.root, "mnt/tank/vms/web/hotplug-*"))
	if len(files) != 0 {
		t.Fatalf("left %v", files)
	}
	// Without part D's hot-plug support it says so.
	e.m.Devices = e.devs
	if _, err := e.m.AttachUSB(ctx, USBArgs{ID: "web", Device: "046d:c52b"}); err == nil || !strings.Contains(err.Error(), "isn't available") {
		t.Fatalf("no hot-plug: %v", err)
	}
}
