package cloudbackup

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

type probeResult struct {
	ROWrite   string `json:"roWrite"`
	RWWrite   string `json:"rwWrite"`
	Masked    string `json:"masked"`
	HostDial  string `json:"hostDial"`
	ProxyDial string `json:"proxyDial"`
	CapEff    string `json:"capEff"`
}

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// sandboxProbe: ro folder, rw folder, a masked file, a host address.
func sandboxProbe(args []string) int {
	if len(args) != 4 {
		return 2
	}
	var r probeResult
	r.ROWrite = errText(os.WriteFile(filepath.Join(args[0], "x"), []byte("x"), 0o600))
	r.RWWrite = errText(os.WriteFile(filepath.Join(args[1], "x"), []byte("x"), 0o600))
	_, err := os.ReadFile(args[2])
	r.Masked = errText(err)
	c, err := net.DialTimeout("tcp", args[3], 2*time.Second)
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
	return &Sandbox{Helper: exe}
}

// TestSandbox runs the probe as restic in the sandbox: writes only where
// allowed, root's secrets hidden, only the egress proxy reachable, only the
// run's capabilities (decisions 176 and 182). Root only.
func TestSandbox(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the sandbox needs root")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	ro, rw, mask := filepath.Join(base, "ro"), filepath.Join(base, "rw"), filepath.Join(base, "secrets")
	for _, d := range []string{ro, rw, mask} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(mask, "master.key")
	write(t, secret, "TOP SECRET")
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

	r := &Restic{Binary: exe, CacheDir: filepath.Join(base, "cache"), Resolver: staticResolver{},
		Sandbox: &Sandbox{Helper: exe, Mask: []string{mask}}}
	repo := &Repo{Target: Target{ID: "x", Name: "x", Kind: KindS3, Endpoint: "https://s3.example.com", Bucket: "bucket"},
		Creds: Credentials{AccessKey: "a", SecretKey: "b", RepoPassword: "p"}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, c := range []struct {
		name string
		caps []int
		want string
	}{{"read", capsRead, "0000000000000004"}, {"restore", capsRestore, "000000000800001b"}, {"none", capsNone, "0000000000000000"}} {
		t.Run(c.name, func(t *testing.T) {
			out, err := r.run(ctx, repo, call{args: []string{"__sandbox-probe", ro, rw, secret, ln.Addr().String()}, writable: []string{rw}, caps: c.caps})
			if err != nil {
				if strings.Contains(err.Error(), "namespace") || strings.Contains(err.Error(), "operation not permitted") {
					t.Skipf("no namespaces here: %v", err)
				}
				t.Fatalf("%v: %s", err, out)
			}
			var res probeResult
			if err := json.Unmarshal(out, &res); err != nil {
				t.Fatalf("probe output %q: %v", out, err)
			}
			if res.ROWrite == "ok" || res.RWWrite != "ok" {
				t.Errorf("writes: read-only folder %q, staging %q", res.ROWrite, res.RWWrite)
			}
			if res.Masked == "ok" {
				t.Error("restic read a hidden secret")
			}
			if res.HostDial == "ok" || res.ProxyDial != "ok" {
				t.Errorf("network: host %q, proxy %q", res.HostDial, res.ProxyDial)
			}
			if res.CapEff != c.want {
				t.Errorf("capabilities %s, want %s", res.CapEff, c.want)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(ro, "x")); err == nil {
		t.Fatal("the read-only folder was written")
	}
}
