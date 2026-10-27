package cloudbackup

import (
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The test binary is also the sandbox helper and the "restic" the sandbox
// runs (a probe that reports what it can reach).
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == SandboxArg {
		os.Exit(SandboxMain(os.Args[1:]))
	}
	for i, a := range os.Args {
		if a == "__sandbox-probe" {
			os.Exit(sandboxProbe(os.Args[i+1:]))
		}
	}
	os.Exit(m.Run())
}

// testSandboxUID is who restic runs as in tests (nobody).
const testSandboxUID = 65534

// testSandbox is the sandbox for tests that run real restic: the test
// binary is the helper. Without root, restic runs directly.
func testSandbox(t *testing.T) *Sandbox {
	if os.Geteuid() != 0 {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return &Sandbox{Helper: exe, UID: testSandboxUID, GID: testSandboxUID, ExtraRO: libDirs(exe)}
}

// libDirs are the library folders a dynamically linked binary needs (the
// test binary may be one; restic is static).
func libDirs(exe string) []string {
	f, err := elf.Open(exe)
	if err != nil {
		return nil
	}
	defer f.Close()
	dynamic := false
	for _, p := range f.Progs {
		dynamic = dynamic || p.Type == elf.PT_INTERP
	}
	if !dynamic {
		return nil
	}
	var out []string
	for _, d := range []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64"} {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			out = append(out, d)
		}
	}
	return out
}

type probeResult struct {
	UID       int      `json:"uid"`
	RootWrite string   `json:"rootWrite"`
	RWWrite   string   `json:"rwWrite"`
	Present   []string `json:"present"` // secrets that exist (not just as the way to a bind)
	Leaked    []string `json:"leaked"`  // anything else found under them
	Dev       []string `json:"dev"`
	Pids      []string `json:"pids"`
	Unix      string   `json:"unix"`
	Netlink   string   `json:"netlink"`
	HostDial  string   `json:"hostDial"`
	ProxyDial string   `json:"proxyDial"`
	CapEff    string   `json:"capEff"`
}

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// Paths that must not exist in the sandbox.
var sandboxSecrets = []string{"/etc/shadow", "/etc/passwd", "/run/hardyos/priv.sock", "/var/run/docker.sock", "/run/docker.sock",
	"/var/lib/samba", "/var/lib/hardyos", "/etc/hardyos", "/root", "/home", "/dev/sda", "/dev/vda", "/dev/zfs", "/dev/kvm", "/sys"}

// sandboxProbe: a writable folder, a host address, and the run's binds
// (comma-separated): their parent folders exist as the empty way to them.
func sandboxProbe(args []string) int {
	if len(args) != 3 {
		return 2
	}
	binds := strings.Split(args[2], ",")
	r := probeResult{UID: os.Getuid()}
	r.RootWrite = errText(os.WriteFile("/x", []byte("x"), 0o600))
	r.RWWrite = errText(os.WriteFile(filepath.Join(args[0], "x"), []byte("x"), 0o600))
	onWay := func(p string) bool { // p is a bind or a folder on the way to one
		for _, b := range binds {
			if p == b || strings.HasPrefix(b, p+"/") {
				return true
			}
		}
		return false
	}
	isBind := func(p string) bool {
		for _, b := range binds {
			if p == b {
				return true
			}
		}
		return false
	}
	for _, p := range sandboxSecrets {
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		if !onWay(p) {
			r.Present = append(r.Present, p)
			continue
		}
		// A parent of a bind: it may hold nothing but the way to the binds.
		_ = filepath.WalkDir(p, func(q string, d os.DirEntry, err error) error {
			if err != nil || q == p {
				return nil
			}
			if !onWay(q) {
				r.Leaked = append(r.Leaked, q)
				return filepath.SkipDir
			}
			if isBind(q) && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		})
	}
	if es, err := os.ReadDir("/dev"); err == nil {
		for _, e := range es {
			r.Dev = append(r.Dev, e.Name())
		}
	}
	if es, err := os.ReadDir("/proc"); err == nil {
		for _, e := range es {
			if _, err := strconv.Atoi(e.Name()); err == nil {
				r.Pids = append(r.Pids, e.Name())
			}
		}
	}
	if fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0); err == nil {
		unix.Close(fd)
		r.Unix = "ok"
	} else {
		r.Unix = err.Error()
	}
	if fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, 0); err == nil {
		unix.Close(fd)
		r.Netlink = "ok"
	} else {
		r.Netlink = err.Error()
	}
	c, err := net.DialTimeout("tcp", args[1], 2*time.Second)
	if err == nil {
		c.Close()
	}
	r.HostDial = errText(err)
	if u, err := url.Parse(os.Getenv("HTTPS_PROXY")); err == nil && u.Host != "" {
		c, err := net.DialTimeout("tcp", u.Host, 2*time.Second)
		if err == nil {
			c.Close()
		}
		r.ProxyDial = errText(err)
	} else {
		r.ProxyDial = "no proxy"
	}
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "CapEff:"); ok {
				r.CapEff = strings.TrimSpace(v)
			}
		}
	}
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
	return 0
}

// TestSandbox runs the probe as restic in the sandbox: not root, only the
// run's capabilities, nothing of the host but what the run needs, no local
// sockets, no other processes, only the egress proxy reachable (decisions
// 226, 232 and 236). Root only.
func TestSandbox(t *testing.T) {
	sb := testSandbox(t)
	if sb == nil {
		t.Skip("the sandbox needs root")
	}
	base := t.TempDir()
	rw := filepath.Join(base, "rw")
	if err := os.MkdirAll(rw, 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	exe, _ := os.Executable()
	r := &Restic{Binary: exe, CacheDir: filepath.Join(base, "cache"), Resolver: staticResolver{}, Sandbox: sb}
	repo := &Repo{Target: Target{ID: "x", Name: "x", Kind: KindS3, Endpoint: "https://s3.example.com", Bucket: "bucket"},
		Creds: Credentials{AccessKey: "a", SecretKey: "b", RepoPassword: "p"}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, c := range []struct {
		name string
		caps []int
		want string
	}{{"read", capsRead, "0000000000000004"}, {"restore", capsRestore, "000000000000000b"}, {"none", capsNone, "0000000000000000"}} {
		t.Run(c.name, func(t *testing.T) {
			binds := append([]string{exe, filepath.Join(base, "cache", "x"), rw}, sb.ExtraRO...)
			out, err := r.run(ctx, repo, call{args: []string{"__sandbox-probe", filepath.Join(base, "cache", "x"), ln.Addr().String(), strings.Join(binds, ",")}, writable: []string{rw}, caps: c.caps})
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			var res probeResult
			if err := json.Unmarshal(out, &res); err != nil {
				t.Fatalf("probe output %q: %v", out, err)
			}
			if res.UID != testSandboxUID {
				t.Errorf("restic ran as %d", res.UID)
			}
			if res.RootWrite == "ok" || res.RWWrite != "ok" {
				t.Errorf("writes: root %q, staging %q", res.RootWrite, res.RWWrite)
			}
			if len(res.Present) > 0 || len(res.Leaked) > 0 {
				t.Errorf("visible in the sandbox: %v; beside the way to its binds: %v", res.Present, res.Leaked)
			}
			sort.Strings(res.Dev)
			if strings.Join(res.Dev, ",") != "fd,null,random,stderr,stdin,stdout,urandom,zero" {
				t.Errorf("/dev holds %v", res.Dev)
			}
			if strings.Join(res.Pids, ",") != "1" {
				t.Errorf("processes visible: %v", res.Pids)
			}
			if res.Unix == "ok" || res.Netlink == "ok" {
				t.Errorf("local sockets: unix %q, netlink %q", res.Unix, res.Netlink)
			}
			if res.HostDial == "ok" || res.ProxyDial != "ok" {
				t.Errorf("network: host %q, proxy %q", res.HostDial, res.ProxyDial)
			}
			if res.CapEff != c.want {
				t.Errorf("capabilities %s, want %s", res.CapEff, c.want)
			}
		})
	}
	// Without the restic user, nothing runs.
	r.Sandbox = &Sandbox{Helper: exe}
	if _, err := r.run(ctx, repo, call{args: []string{"__sandbox-probe", rw, ln.Addr().String(), rw}}); err == nil || !strings.Contains(err.Error(), "hardyos-restic") {
		t.Fatalf("ran without the restic user: %v", err)
	}
}
