package vms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestStreamingPinsDownload downloads the pinned Sunshine and Virtual
// Display Driver files from their release pages, through the catalog's
// own client (https, their hosts only, redirects included), and checks
// them against the pinned SHA-256. It needs the internet: CI's streaming
// job runs it (HARDYOS_NET_TESTS=1).
func TestStreamingPinsDownload(t *testing.T) {
	if os.Getenv("HARDYOS_NET_TESTS") != "1" {
		t.Skip("set HARDYOS_NET_TESTS=1 to download the pinned streaming files")
	}
	m := &Manager{}
	for _, img := range streamingCatalog {
		for arch, f := range img.Files {
			t.Run(img.ID+"/"+arch, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
				defer cancel()
				u, err := allowedURL(f.URL, img.Hosts)
				if err != nil {
					t.Fatal(err)
				}
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
				req.Header.Set("User-Agent", "HardyOS")
				res, err := m.catalogClient(img.Hosts).Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer res.Body.Close()
				if res.StatusCode != http.StatusOK {
					t.Fatalf("%s: %s", f.URL, res.Status)
				}
				h := sha256.New()
				var body bytes.Buffer
				n, err := io.Copy(io.MultiWriter(h, &body), io.LimitReader(res.Body, 512<<20))
				if err != nil {
					t.Fatal(err)
				}
				if f.Size > 0 && n != f.Size {
					t.Fatalf("%s: %d bytes, pinned %d", f.URL, n, f.Size)
				}
				if got := hex.EncodeToString(h.Sum(nil)); got != f.SHA256 {
					t.Fatalf("%s: SHA-256 %s (%d bytes), pinned %s", f.URL, got, n, f.SHA256)
				}
				if img.ID == CatalogVDD {
					// The setup script trusts only this signer.
					got, err := catalogSigner(body.Bytes())
					if err != nil {
						t.Fatalf("%s: reading the driver catalog's signer: %v", f.File, err)
					}
					if got != VDDSignerSHA1 {
						t.Fatalf("%s: the driver catalog's signer is %s, pinned %s", f.File, got, VDDSignerSHA1)
					}
				}
				t.Logf("%s: %d bytes, SHA-256 matches", f.File, n)
			})
		}
	}
}

// TestStreamingRulesLoad loads the generated nftables ruleset and the
// iptables chain into the real kernel, inside a new network namespace
// (unshare -n), so the host's own firewall is never touched. It needs
// root, nft, iptables and unshare: CI's streaming job runs it
// (HARDYOS_NFT_TEST=1).
func TestStreamingRulesLoad(t *testing.T) {
	if os.Getenv("HARDYOS_NFT_TEST") != "1" {
		t.Skip("set HARDYOS_NFT_TEST=1 (as root) to load the rules in a network namespace")
	}
	f := StreamForward{VM: "game", Iface: "wt0", PeerNet: "100.92.0.0/16", Peers: []string{"100.92.1.5"}, HostIP: "100.92.1.2", Bridge: "br0", VMIP: "192.168.1.77"}
	text, err := RenderStreamingNFT(&f)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	nftFile := dir + "/streaming.nft"
	if err := os.WriteFile(nftFile, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	rules, err := StreamingIPTables(f)
	if err != nil {
		t.Fatal(err)
	}
	// The ruleset is loaded twice: the second load replaces the table (the
	// "table; delete table; table {…}" idiom), as every resync does.
	script := "set -e\nnft -f " + nftFile + "\nnft -f " + nftFile + "\nnft list table ip hardyos_streaming\niptables -w -N " + streamChain + "\n"
	for _, r := range rules {
		script += "iptables -w -A " + streamChain + " " + shellJoin(r) + "\n"
	}
	script += "iptables -w -I FORWARD 1 -j " + streamChain + "\niptables -w -S " + streamChain + "\nnft delete table ip hardyos_streaming\n"
	out, err := runUnshare(script)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	t.Logf("%s", out)
}

// TestStreamingForwardsInNamespaces builds a NetBird peer, this server and
// a VM out of three network namespaces, loads the real rules into the
// server's, and checks that the peer reaches the VM's streaming ports (TCP
// and UDP) through the server's NetBird address, that the VM sees the
// server's bridge address (masquerade), and that Sunshine's web UI port
// isn't forwarded. Root and the kernel only: HARDYOS_NFT_TEST=1.
func TestStreamingForwardsInNamespaces(t *testing.T) {
	if os.Getenv("HARDYOS_NFT_TEST") != "1" {
		t.Skip("set HARDYOS_NFT_TEST=1 (as root) to run the namespace test")
	}
	f := StreamForward{VM: "game", Iface: "wt0", PeerNet: "100.92.0.0/16", Peers: []string{"100.92.1.5"}, HostIP: "100.92.1.2", Bridge: "br0", VMIP: "192.168.1.77"}
	text, err := RenderStreamingNFT(&f)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/streaming.nft", []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	vm := `import socket, sys, threading
def tcp(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", port)); s.listen(4)
    while True:
        c, a = s.accept(); c.sendall(("seen " + a[0]).encode()); c.close()
def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", port))
    while True:
        d, a = s.recvfrom(100); s.sendto(b"echo " + d, a)
for p in (47989, 47990):
    threading.Thread(target=tcp, args=(p,), daemon=True).start()
threading.Thread(target=udp, args=(47998,), daemon=True).start()
open(sys.argv[1], "w").write("ready")
threading.Event().wait()
`
	peer := `import socket, sys
s = socket.create_connection(("100.92.1.2", 47989), timeout=5); print(s.recv(100).decode()); s.close()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(5); u.sendto(b"ping", ("100.92.1.2", 47998)); print(u.recvfrom(100)[0].decode())
try:
    socket.create_connection(("100.92.1.2", 47990), timeout=2); print("webui reachable")
except OSError:
    print("webui closed")
# Another NetBird device, not chosen: not forwarded.
try:
    o = socket.socket(); o.settimeout(2); o.bind(("100.92.1.6", 0)); o.connect(("100.92.1.2", 47989)); print("other peer reachable")
except OSError:
    print("other peer closed")
`
	if err := os.WriteFile(dir+"/vm.py", []byte(vm), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/peer.py", []byte(peer), 0o644); err != nil {
		t.Fatal(err)
	}
	sh := `set -e
P=hos-peer-$$; H=hos-host-$$; V=hos-vm-$$
cleanup() { kill $VMPID 2>/dev/null || true; ip netns del $P 2>/dev/null; ip netns del $H 2>/dev/null; ip netns del $V 2>/dev/null; }
trap cleanup EXIT
ip netns add $P; ip netns add $H; ip netns add $V
ip link add wt0 netns $H type veth peer name nb0 netns $P
ip link add br0 netns $H type veth peer name eth0 netns $V
ip -n $H addr add 100.92.1.2/16 dev wt0
ip -n $H addr add 192.168.1.10/24 dev br0
ip -n $P addr add 100.92.1.5/16 dev nb0
ip -n $P addr add 100.92.1.6/16 dev nb0
ip -n $V addr add 192.168.1.77/24 dev eth0
for n in $P $H $V; do ip -n $n link set lo up; done
ip -n $H link set wt0 up; ip -n $H link set br0 up; ip -n $P link set nb0 up; ip -n $V link set eth0 up
ip netns exec $H sysctl -qw net.ipv4.ip_forward=1
ip netns exec $H nft -f DIR/streaming.nft
ip netns exec $V python3 -I DIR/vm.py DIR/ready & VMPID=$!
for i in $(seq 50); do [ -f DIR/ready ] && break; sleep 0.1; done
ip netns exec $P python3 -I DIR/peer.py
`
	out, err := exec.Command("bash", "-c", strings.ReplaceAll(sh, "DIR", dir)).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := string(out)
	if !strings.Contains(got, "seen 192.168.1.10") || !strings.Contains(got, "echo ping") || !strings.Contains(got, "webui closed") || !strings.Contains(got, "other peer closed") {
		t.Fatalf("namespace test:\n%s", got)
	}
}

// TestStreamingDiscXorriso makes a streaming disc with the real xorriso
// and the arguments writeStreaming uses, and lists it: the label Windows
// finds it by and every file at the top. HARDYOS_XORRISO_TEST=1 (CI).
func TestStreamingDiscXorriso(t *testing.T) {
	if os.Getenv("HARDYOS_XORRISO_TEST") != "1" {
		t.Skip("set HARDYOS_XORRISO_TEST=1 to make a disc with xorriso")
	}
	dir := t.TempDir()
	in := dir + "/in"
	if err := os.Mkdir(in, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"setup.ps1", "sunshine-account.json", "sunshine-cert.pem", "sunshine-key.pem"} {
		if err := os.WriteFile(in+"/"+n, []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store := dir + "/store"
	_ = os.Mkdir(store, 0o700)
	msi, zip := "sunshine-"+SunshineVersion+"-amd64.msi", "vdd-"+VDDVersion+"-x64.zip"
	for _, n := range []string{msi, zip} {
		if err := os.WriteFile(store+"/"+n, []byte(n), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	out := dir + "/out.iso"
	args := streamingDiscArgs(out, in, []string{"/" + msi + "=" + store + "/" + msi, "/" + zip + "=" + store + "/" + zip})
	if b, err := exec.Command("xorriso", args...).CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	b, err := exec.Command("xorriso", "-indev", out, "-pvd_info", "-find", "/", "-type", "f").CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, b)
	}
	got := string(b)
	for _, want := range []string{"Volume Id    : " + StreamingLabel, "'/setup.ps1'", "'/sunshine-key.pem'", "'/sunshine-account.json'", "'/" + msi + "'", "'/" + zip + "'"} {
		if !strings.Contains(got, want) {
			t.Errorf("disc lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "'/in/") {
		t.Errorf("files are in a subfolder:\n%s", got)
	}
}
