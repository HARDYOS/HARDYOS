package netcheck

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/net/http2"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Signed probes (decision 491). A probe is POST /cluster/v1/netcheck/probe
// on the peer API (hardyos-peer/1 on the cluster port, pinned mutual TLS),
// dialled straight to the peer's address on one path. The answer is a
// statement signed with the peer's cluster key: the prober's nonce, both
// ids, where the probe came from and arrived, the receiving interface's MTU
// and the padding's hash. Nothing else listens: no new port.

// ProbePath and ReportPath are the peer API paths (under PeerPathPrefix).
const (
	ProbePath  = "netcheck/probe"
	ReportPath = "netcheck/report"
	RunPath    = "netcheck/run"
)

// Domain separates netcheck signatures from every other signature made
// with a cluster key (commands, assertions, heartbeat statements).
const Domain = "hardyos-netcheck/1\n"

// maxProbeBody bounds a probe request (the bulk probe's padding).
const maxProbeBody = 2 * BulkSize

// ProbeRequest is a probe.
type ProbeRequest struct {
	From  cluster.NodeID `json:"from"`
	Nonce string         `json:"nonce"`
	// Pad is the bulk probe's padding (random bytes).
	Pad []byte `json:"pad,omitempty"`
}

// Statement is what a probed server signs.
type Statement struct {
	Node   cluster.NodeID `json:"node"` // the probed server
	Peer   cluster.NodeID `json:"peer"` // the prober
	Nonce  string         `json:"nonce"`
	SeenAs netip.Addr     `json:"seenAs"`
	// Arrived is the address the probe arrived at, MTU its interface's.
	Arrived netip.Addr `json:"arrived"`
	MTU     int        `json:"mtu"`
	// Sum is the SHA-256 (hex) of the padding.
	Sum  string `json:"sum"`
	Time int64  `json:"time"`
}

// ProbeAnswer is the signed answer.
type ProbeAnswer struct {
	Statement json.RawMessage `json:"statement"`
	Signature []byte          `json:"signature"`
}

func digest(raw []byte) []byte {
	sum := sha256.Sum256(append([]byte(Domain), raw...))
	return sum[:]
}

// Sign signs a statement with a cluster key.
func Sign(id *cluster.Identity, st Statement) (*ProbeAnswer, error) {
	raw, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	sig, err := ecdsa.SignASN1(rand.Reader, id.Key, digest(raw))
	if err != nil {
		return nil, err
	}
	return &ProbeAnswer{Statement: raw, Signature: sig}, nil
}

// Verify checks an answer against a member's public key and returns its
// statement.
func Verify(spki []byte, a *ProbeAnswer) (*Statement, error) {
	key, err := cluster.ParsePublicKey(spki)
	if err != nil {
		return nil, err
	}
	if !ecdsa.VerifyASN1(key, digest(a.Statement), a.Signature) {
		return nil, errors.New("the answer isn't signed by that server's key")
	}
	var st Statement
	if err := json.Unmarshal(a.Statement, &st); err != nil {
		return nil, errors.New("unreadable answer")
	}
	return &st, nil
}

// Iface is a network interface as the check needs it.
type Iface struct {
	Name     string
	MTU      int
	Prefixes []netip.Prefix
}

// Interfaces lists this server's interfaces (net.Interfaces).
func Interfaces() ([]Iface, error) {
	l, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Iface
	for _, i := range l {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		f := Iface{Name: i.Name, MTU: i.MTU}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				ip, ok := netip.AddrFromSlice(n.IP)
				if !ok {
					continue
				}
				ones, _ := n.Mask.Size()
				f.Prefixes = append(f.Prefixes, netip.PrefixFrom(ip.Unmap(), ones))
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// ifaceOf finds the interface holding a, its MTU and prefix.
func ifaceOf(list func() ([]Iface, error), a netip.Addr) (Iface, netip.Prefix, bool) {
	if list == nil || !a.IsValid() {
		return Iface{}, netip.Prefix{}, false
	}
	l, err := list()
	if err != nil {
		return Iface{}, netip.Prefix{}, false
	}
	for _, i := range l {
		for _, p := range i.Prefixes {
			if p.Addr() == a {
				return i, p.Masked(), true
			}
		}
	}
	return Iface{}, netip.Prefix{}, false
}

func addrOf(a net.Addr) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// Responder answers probes (registered on the peer API).
type Responder struct {
	Identity func() *cluster.Identity
	Self     func() cluster.NodeID
	// Caller is the member that sent a request (the peer mux's).
	Caller     func(r *http.Request) (cluster.Node, bool)
	Interfaces func() ([]Iface, error)
}

func (rs *Responder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	caller, ok := rs.Caller(r)
	if !ok || (caller.Role != cluster.RoleCompute && caller.Role != cluster.RoleStorage) {
		http.Error(w, "only compute and storage servers probe", http.StatusForbidden)
		return
	}
	var req ProbeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxProbeBody*2)).Decode(&req); err != nil || req.From != caller.ID ||
		len(req.Nonce) != 32 || len(req.Pad) > maxProbeBody {
		http.Error(w, "bad probe", http.StatusBadRequest)
		return
	}
	id := rs.Identity()
	if id == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	arrived := netip.Addr{}
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		arrived = addrOf(la)
	}
	seen, _ := netip.ParseAddrPort(r.RemoteAddr)
	mtu := 0
	if f, _, ok := ifaceOf(rs.Interfaces, arrived); ok {
		mtu = f.MTU
	}
	sum := sha256.Sum256(req.Pad)
	a, err := Sign(id, Statement{Node: rs.Self(), Peer: caller.ID, Nonce: req.Nonce, SeenAs: seen.Addr().Unmap(), Arrived: arrived,
		MTU: mtu, Sum: hex.EncodeToString(sum[:]), Time: time.Now().UnixNano()})
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a)
}

// Prober probes peers over one path at a time.
type Prober struct {
	// Dial opens the peer API (ALPNPeer, the peer's pin checked) to an
	// address ("ip:port") on the path being probed.
	Dial       func(ctx context.Context, addr string, peer cluster.Node) (net.Conn, error)
	Port       int
	Interfaces func() ([]Iface, error)
	// Timeout bounds one path's probes (default 4 s); BulkTimeout the
	// large probe (default 3 s).
	Timeout, BulkTimeout time.Duration
}

func (p *Prober) port() int {
	if p.Port != 0 {
		return p.Port
	}
	return cluster.Port
}

func nonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Probe probes every peer on every path and returns this server's report.
func (p *Prober) Probe(ctx context.Context, self cluster.Node, peers []*cluster.Node) Report {
	rep := Report{Node: self.ID, Checked: time.Now(), Paths: []PathResult{}}
	type job struct {
		peer *cluster.Node
		path cluster.Path
	}
	var jobs []job
	for _, n := range peers {
		if n.ID == self.ID {
			continue
		}
		for _, path := range Paths {
			jobs = append(jobs, job{n, path})
		}
	}
	res := make([]PathResult, len(jobs))
	done := make(chan struct{}, len(jobs))
	for i, j := range jobs {
		go func() {
			res[i] = p.ProbePath(ctx, self, j.peer, j.path)
			done <- struct{}{}
		}()
	}
	for range jobs {
		<-done
	}
	rep.Paths = append(rep.Paths, res...)
	slices.SortFunc(rep.Paths, func(a, b PathResult) int {
		if a.Peer != b.Peer {
			if a.Peer < b.Peer {
				return -1
			}
			return 1
		}
		return slices.Index(Paths, a.Path) - slices.Index(Paths, b.Path)
	})
	return rep
}

// ProbePath probes one peer over one path and judges it.
func (p *Prober) ProbePath(ctx context.Context, self cluster.Node, peer *cluster.Node, path cluster.Path) PathResult {
	pr := PathResult{Peer: peer.ID, Path: path, Addr: pathAddr(self.Addresses, path), PeerAddr: pathAddr(peer.Addresses, path)}
	defer Judge(&pr, &self, peer)
	if !pr.Addr.IsValid() || !pr.PeerAddr.IsValid() {
		return pr
	}
	if f, pfx, ok := ifaceOf(p.Interfaces, pr.Addr); ok {
		pr.Interface, pr.MTU, pr.SameSubnet = f.Name, f.MTU, pfx.Contains(pr.PeerAddr)
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 4 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := p.Dial(ctx, net.JoinHostPort(pr.PeerAddr.String(), fmt.Sprint(p.port())), *peer)
	if err != nil {
		pr.Problem = short(err)
		return pr
	}
	defer conn.Close()
	pr.Local = addrOf(conn.LocalAddr())
	cc, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		pr.Problem = short(err)
		return pr
	}
	defer cc.Close()
	var rtts []time.Duration
	for range Samples {
		st, d, err := p.one(ctx, cc, self, peer, nil)
		if err != nil {
			pr.Problem = short(err)
			return pr
		}
		rtts = append(rtts, d)
		pr.SeenAs, pr.Arrived, pr.PeerMTU = st.SeenAs, st.Arrived, st.MTU
	}
	pr.Answered = true
	pr.RTT = slices.Min(rtts)
	bt := p.BulkTimeout
	if bt == 0 {
		bt = 3 * time.Second
	}
	bctx, bcancel := context.WithTimeout(ctx, bt)
	defer bcancel()
	pad := make([]byte, BulkSize)
	_, _ = rand.Read(pad)
	if _, _, err := p.one(bctx, cc, self, peer, pad); err == nil {
		pr.Bulk = true
	}
	return pr
}

// one sends one probe and checks the signed answer.
func (p *Prober) one(ctx context.Context, cc *http2.ClientConn, self cluster.Node, peer *cluster.Node, pad []byte) (*Statement, time.Duration, error) {
	n := nonce()
	body, _ := json.Marshal(ProbeRequest{From: self.ID, Nonce: n, Pad: pad})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+string(peer.ID)+cluster.PeerPathPrefix+ProbePath, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	start := time.Now()
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	d := time.Since(start)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("%s answered %d (an older HardyOS?)", peer.ID, resp.StatusCode)
	}
	var a ProbeAnswer
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, 0, errors.New("unreadable answer")
	}
	st, err := Verify(peer.PublicKey, &a)
	if err != nil {
		return nil, 0, err
	}
	sum := sha256.Sum256(pad)
	if st.Node != peer.ID || st.Peer != self.ID || st.Nonce != n || st.Sum != hex.EncodeToString(sum[:]) {
		return nil, 0, errors.New("the answer isn't for this probe")
	}
	return st, d, nil
}

func short(err error) string {
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
