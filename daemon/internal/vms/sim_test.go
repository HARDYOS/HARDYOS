package vms

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/devices"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/sysexec"
)

// sim pretends to be ZFS and libvirt, closely enough for the Manager.
type sim struct {
	t    *testing.T
	root string

	mu       sync.Mutex
	lines    []string
	stdin    map[string][]byte
	datasets map[string]map[string]string // name -> properties (type, mountpoint, volsize, …)
	snaps    map[string]map[string]string // ds@snap -> properties
	domains  map[string]*simDomain
	defined  map[string]string // name -> last XML
	fail     map[string]string // command prefix -> stderr (exit 1)
}

type simDomain struct {
	state string // running, shut off, paused
	cpu   uint64
}

func newSim(t *testing.T, root string) *sim {
	s := &sim{t: t, root: root, stdin: map[string][]byte{}, datasets: map[string]map[string]string{}, snaps: map[string]map[string]string{},
		domains: map[string]*simDomain{}, defined: map[string]string{}, fail: map[string]string{}}
	s.datasets["tank"] = map[string]string{"type": "filesystem", "mountpoint": "/mnt/tank"}
	s.datasets["tank/vms"] = map[string]string{"type": "filesystem", "mountpoint": "/mnt/tank/vms"}
	return s
}

func (s *sim) Lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.lines...)
}

func (s *sim) has(prefix string) bool {
	for _, l := range s.Lines() {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func ok(out string) (sysexec.Result, error) { return sysexec.Result{Stdout: []byte(out)}, nil }
func bad(msg string) (sysexec.Result, error) {
	return sysexec.Result{ExitCode: 1, Stderr: []byte(msg)}, nil
}

func (s *sim) Run(_ context.Context, stdin []byte, name string, args ...string) (sysexec.Result, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, line)
	if stdin != nil {
		s.stdin[line] = stdin
	}
	for p, msg := range s.fail {
		if strings.HasPrefix(line, p) {
			return bad(msg)
		}
	}
	switch name {
	case "zpool":
		return ok("tank\tONLINE\nrpool\tONLINE\n")
	case "zfs":
		return s.zfs(args)
	case "virsh":
		return s.virsh(args[3:]) // -c qemu:///system -q
	case "openssl":
		return ok("$6$saltsalt$" + strings.Repeat("a", 86) + "\n")
	case "xorriso", "iptables", "bridge":
		return ok("")
	}
	return bad("sim: unexpected command " + line)
}

func (s *sim) zfs(args []string) (sysexec.Result, error) {
	switch args[0] {
	case "list":
		return s.zfsList(args[1:])
	case "get":
		// get -H -p -o value mountpoint DS
		ds := args[len(args)-1]
		p, okd := s.datasets[ds]
		if !okd {
			return bad("cannot open '" + ds + "': dataset does not exist")
		}
		return ok(p["mountpoint"] + "\n")
	case "create":
		props := map[string]string{"type": "filesystem"}
		var ds string
		for i := 1; i < len(args); i++ {
			switch args[i] {
			case "-o":
				k, v, _ := strings.Cut(args[i+1], "=")
				props[k] = v
				i++
			case "-V":
				props["type"] = "volume"
				props["volsize"] = args[i+1]
				i++
			case "-s", "-p":
			default:
				ds = args[i]
			}
		}
		if _, exists := s.datasets[ds]; exists {
			return bad("dataset already exists")
		}
		parent := filepath.Dir(ds)
		if _, okp := s.datasets[parent]; !okp {
			return bad("parent does not exist")
		}
		if props["type"] == "filesystem" {
			props["mountpoint"] = s.datasets[parent]["mountpoint"] + "/" + filepath.Base(ds)
			_ = os.MkdirAll(filepath.Join(s.root, props["mountpoint"]), 0o755)
		} else {
			// The zvol's device node appears.
			dev := filepath.Join(s.root, "/dev/zvol", ds)
			_ = os.MkdirAll(filepath.Dir(dev), 0o755)
			_ = os.WriteFile(dev, nil, 0o600)
		}
		s.datasets[ds] = props
		return ok("")
	case "destroy":
		target := args[len(args)-1]
		if strings.Contains(target, "@") {
			ds, snap, _ := strings.Cut(target, "@")
			for k := range s.snaps {
				d, n, _ := strings.Cut(k, "@")
				if n == snap && (d == ds || strings.HasPrefix(d, ds+"/")) {
					delete(s.snaps, k)
				}
			}
			return ok("")
		}
		if _, exists := s.datasets[target]; !exists {
			return bad("dataset does not exist")
		}
		for k := range s.datasets {
			if k == target || strings.HasPrefix(k, target+"/") {
				delete(s.datasets, k)
			}
		}
		for k := range s.snaps {
			if d, _, _ := strings.Cut(k, "@"); d == target || strings.HasPrefix(d, target+"/") {
				delete(s.snaps, k)
			}
		}
		return ok("")
	case "snapshot":
		var target string
		props := map[string]string{"creation": fmt.Sprint(1800000000 + len(s.snaps)), "used": "4096"}
		for i := 1; i < len(args); i++ {
			if args[i] == "-o" {
				k, v, _ := strings.Cut(args[i+1], "=")
				props[k] = v
				i++
			} else if args[i] != "-r" {
				target = args[i]
			}
		}
		ds, snap, _ := strings.Cut(target, "@")
		for d := range s.datasets {
			if d == ds || strings.HasPrefix(d, ds+"/") {
				c := map[string]string{}
				for k, v := range props {
					c[k] = v
				}
				s.snaps[d+"@"+snap] = c
			}
		}
		return ok("")
	case "rollback":
		target := args[len(args)-1]
		if _, okd := s.snaps[target]; !okd {
			return bad("no such snapshot")
		}
		return ok("")
	case "set":
		k, v, _ := strings.Cut(args[1], "=")
		if p, okd := s.datasets[args[2]]; okd {
			p[k] = v
			return ok("")
		}
		return bad("dataset does not exist")
	case "inherit":
		return ok("")
	case "rename":
		from, to := args[1], args[2]
		for k, v := range s.datasets {
			if k == from || strings.HasPrefix(k, from+"/") {
				delete(s.datasets, k)
				s.datasets[to+strings.TrimPrefix(k, from)] = v
			}
		}
		return ok("")
	}
	return bad("sim: zfs " + strings.Join(args, " "))
}

func (s *sim) zfsList(args []string) (sysexec.Result, error) {
	var typ, cols, under string
	depth := -1
	recursive := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t":
			typ = args[i+1]
			i++
		case "-o":
			cols = args[i+1]
			i++
		case "-d":
			fmt.Sscan(args[i+1], &depth)
			i++
		case "-r":
			recursive = true
		case "-H", "-p", "-s":
		default:
			under = args[i]
		}
	}
	if typ == "" {
		typ = "filesystem,volume"
	}
	if under != "" && !recursive && depth < 0 && typ != "snapshot" {
		if _, okd := s.datasets[under]; !okd {
			return bad("cannot open '" + under + "': dataset does not exist")
		}
	}
	var rows []string
	add := func(name string, props map[string]string) {
		var f []string
		for _, c := range strings.Split(cols, ",") {
			switch c {
			case "name":
				f = append(f, name)
			default:
				v, okv := props[c]
				if !okv {
					v = "-"
				}
				f = append(f, v)
			}
		}
		rows = append(rows, strings.Join(f, "\t"))
	}
	inside := func(name string) bool {
		if under == "" {
			return true
		}
		return name == under || strings.HasPrefix(name, under+"/")
	}
	if typ == "snapshot" {
		for k, p := range s.snaps {
			d, _, _ := strings.Cut(k, "@")
			if inside(d) && (depth != 1 || d == under) {
				add(k, p)
			}
		}
	} else {
		for k, p := range s.datasets {
			if !strings.Contains(typ, p["type"]) || !inside(k) {
				continue
			}
			if under != "" && !recursive && depth < 0 && k != under {
				continue
			}
			props := map[string]string{"used": "1048576"}
			for a, b := range p {
				props[a] = b
			}
			add(k, props)
		}
	}
	sort.Strings(rows)
	return ok(strings.Join(rows, "\n") + "\n")
}

func (s *sim) virsh(args []string) (sysexec.Result, error) {
	switch args[0] {
	case "define":
		b, err := os.ReadFile(filepath.Join(s.root, args[len(args)-1]))
		if err != nil {
			return bad("no file")
		}
		name := between(string(b), "<name>", "</name>")
		s.defined[name] = string(b)
		if s.domains[name] == nil {
			s.domains[name] = &simDomain{state: "shut off"}
		}
		return ok("Domain '" + name + "' defined")
	case "autostart", "version":
		return ok("Running against daemon: 11.3.0")
	case "start":
		d := s.domains[args[1]]
		if d == nil {
			return bad("error: failed to get domain")
		}
		d.state = "running"
		return ok("")
	case "destroy":
		if d := s.domains[args[1]]; d != nil {
			if d.state != "running" && d.state != "paused" {
				return bad("error: Requested operation is not valid: domain is not running")
			}
			d.state = "shut off"
		}
		return ok("")
	case "shutdown":
		if d := s.domains[args[1]]; d != nil {
			d.state = "in shutdown"
		}
		return ok("")
	case "reboot", "reset", "resume", "domfsfreeze", "domfsthaw":
		return ok("")
	case "undefine":
		delete(s.domains, args[1])
		delete(s.defined, args[1])
		return ok("")
	case "domstate":
		d := s.domains[args[1]]
		if d == nil {
			return bad("error: failed to get domain '" + args[1] + "'")
		}
		return ok(d.state + "\n")
	case "domstats":
		var b strings.Builder
		names := []string{}
		for n := range s.domains {
			names = append(names, n)
		}
		sort.Strings(names)
		code := map[string]int{"running": 1, "paused": 3, "in shutdown": 4, "shut off": 5}
		for _, n := range names {
			d := s.domains[n]
			if d.state == "running" {
				d.cpu += 2_000_000_000
			}
			fmt.Fprintf(&b, "Domain: '%s'\n  state.state=%d\n  cpu.time=%d\n  vcpu.current=2\n  balloon.current=4194304\n  balloon.available=4000000\n  balloon.unused=3000000\n\n", n, code[d.state], d.cpu)
		}
		return ok(b.String())
	case "domifaddr":
		return ok(" Name       MAC address          Protocol     Address\n-------------------------------------------------------------------------------\n vnet0      52:54:00:12:34:56    ipv4         192.168.1.77/24\n lo         00:00:00:00:00:00    ipv4         127.0.0.1/8\n")
	case "dumpxml":
		return ok(`<domain><devices><graphics type="vnc" socket="/var/lib/libvirt/qemu/domain-1-` + args[1] + `/vnc.sock"><listen type="socket" socket="/var/lib/libvirt/qemu/domain-1-` + args[1] + `/vnc.sock"/></graphics></devices></domain>`)
	}
	return bad("sim: virsh " + strings.Join(args, " "))
}

func between(s, a, b string) string {
	_, rest, _ := strings.Cut(s, a)
	v, _, _ := strings.Cut(rest, b)
	return v
}

// fakeLibrary is an ISOs folder in a temp directory.
type fakeLibrary struct {
	dir     string
	created string
}

func devOf(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return uint64(fi.Sys().(*syscall.Stat_t).Dev)
}

func (l *fakeLibrary) Folder(_ context.Context, pool string, create bool) (*Folder, error) {
	if _, err := os.Stat(l.dir); err != nil {
		if !create {
			return nil, nil
		}
		if err := os.MkdirAll(l.dir, 0o755); err != nil {
			return nil, err
		}
		l.created = pool
	}
	fi, _ := os.Stat(l.dir)
	return &Folder{Pool: "tank", Path: l.dir, Dev: uint64(fi.Sys().(*syscall.Stat_t).Dev)}, nil
}

// fakeBridge is the network's bridge.
type fakeBridge struct {
	name    string
	ensured int
}

func (b *fakeBridge) BridgeName() string { return b.name }
func (b *fakeBridge) EnsureBridge(context.Context) (string, error) {
	b.ensured++
	b.name = "br0"
	return b.name, nil
}

// fakeDevices records what the VM engine asks of part D.
type fakeDevices struct {
	mu       sync.Mutex
	calls    []string
	checkErr error
}

func (d *fakeDevices) Check(_ context.Context, vm string, ds []devices.Device) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, fmt.Sprintf("check %s %d", vm, len(ds)))
	return d.checkErr
}

func (d *fakeDevices) Prepare(_ context.Context, vm string, ds []devices.Device) ([]devices.Prepared, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, "prepare "+vm)
	var out []devices.Prepared
	for _, x := range ds {
		out = append(out, devices.Prepared{Device: x, XML: `<hostdev mode="subsystem" type="pci" managed="no"><source><address domain="0x0000" bus="0x01" slot="0x00" function="0x0"/></source></hostdev>`})
	}
	return out, nil
}

func (d *fakeDevices) Release(_ context.Context, vm string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, "release "+vm)
	return nil
}

func (d *fakeDevices) log() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return strings.Join(d.calls, ",")
}

// fakeStream pretends to run qemu-img and xz.
type fakeStream struct {
	mu    sync.Mutex
	calls []string
	info  string
}

func (f *fakeStream) RunWithFile(_ context.Context, _ *os.File, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	return []byte(f.info), nil
}

func (f *fakeStream) Progress(_ context.Context, _ *os.File, on func(float64), name string, args ...string) error {
	f.mu.Lock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	f.mu.Unlock()
	on(50)
	on(100)
	return nil
}

func (f *fakeStream) Pipe(_ context.Context, in io.Reader, out io.Writer, on func(int64), name string, args ...string) error {
	f.mu.Lock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	f.mu.Unlock()
	n, err := io.Copy(out, in)
	on(n)
	return err
}

type testEnv struct {
	m       *Manager
	sim     *sim
	lib     *fakeLibrary
	bridge  *fakeBridge
	devs    *fakeDevices
	stream  *fakeStream
	root    string
	isoDir  string
	granted []string
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	root := t.TempDir()
	s := newSim(t, root)
	iso := filepath.Join(t.TempDir(), "isos")
	e := &testEnv{sim: s, root: root, isoDir: iso, lib: &fakeLibrary{dir: iso}, bridge: &fakeBridge{}, devs: &fakeDevices{}, stream: &fakeStream{}}
	arch, _ := ArchFor("amd64")
	e.m = &Manager{
		Runner: s, Root: root, Library: e.lib, Network: e.bridge, Devices: e.devs, Arch: &arch, Stream: e.stream,
		Mounts:   shares.MountFunc(func(string, string) (uint64, error) { return 42, nil }),
		QEMUUser: func() (uint32, error) { return uint32(os.Getuid()), nil },
	}
	e.m.grant = func(_ *Folder, name string, _ uint32) error {
		e.granted = append(e.granted, name)
		return nil
	}
	// The host: 8 CPUs, 32 GB, Secure Boot firmware and swtpm.
	write(t, filepath.Join(root, "proc/cpuinfo"), strings.Repeat("processor\t: 0\n\n", 16))
	write(t, filepath.Join(root, "proc/meminfo"), "MemTotal:       32768000 kB\n")
	write(t, filepath.Join(root, "usr/share/qemu/firmware/40-edk2-x86_64-secure-enrolled.json"),
		`{"interface-types":["uefi"],"targets":[{"architecture":"x86_64","machines":["pc-q35-*"]}],"features":["secure-boot","enrolled-keys","requires-smm"]}`)
	write(t, filepath.Join(root, "usr/bin/swtpm"), "")
	write(t, filepath.Join(root, "dev/kvm"), "")
	return e
}

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) addISO(t *testing.T, name string, size int) {
	t.Helper()
	if err := os.MkdirAll(e.isoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.isoDir, name), make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
}
