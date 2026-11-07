package cluster

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"golang.org/x/net/http2"
)

// Joining (docs/plans/cluster.md 3.2): an administrator on a member makes a
// one-time code (128 bits, 30 minutes, 5 wrong tries in all, 3 per
// address) for one role. The new server connects to the member, learns
// its key on that TLS connection and proves it knows the code with an HMAC
// over both keys; the member proves it back over both keys, the cluster id
// and the node id. Someone in the middle learns nothing and can't swap
// keys. The member proposes member.add; the new node catches up as a
// non-voter and says member.ready (the witness: witness.hello).

// Join code limits.
const (
	JoinCodeTTL          = 30 * time.Minute
	MaxJoinFailures      = 5
	MaxJoinFailuresPerIP = 3
)

// JoinCode is an open join code as stored (sealed by the store).
type JoinCode struct {
	ID       string    `json:"id"`
	Code     []byte    `json:"-"`
	Role     Role      `json:"role"`
	Expires  time.Time `json:"expires"`
	Failures int       `json:"failures"`
	// CreatedBy is the administrator who made it (audit, actor of
	// member.add).
	CreatedBy string `json:"createdBy"`
}

// JoinCodes keeps open join codes.
type JoinCodes interface {
	// JoinCodes lists the open codes (expired ones are not returned).
	JoinCodes(ctx context.Context, now time.Time) ([]JoinCode, error)
	AddJoinCode(ctx context.Context, c JoinCode) error
	// TakeJoinCode deletes a code (used, cancelled or failed too often).
	TakeJoinCode(ctx context.Context, id string) error
	// JoinCodeFailed counts a wrong try and returns the failures so far.
	JoinCodeFailed(ctx context.Context, id string) (int, error)
}

var codeEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// FormatCode shows a code as groups of five (like replication's).
func FormatCode(b []byte) string {
	s := codeEnc.EncodeToString(b)
	var parts []string
	for i := 0; i < len(s); i += 5 {
		j := min(i+5, len(s))
		if len(s)-j < 5 && len(s)-j > 0 {
			j = len(s)
		}
		parts = append(parts, s[i:j])
		if j == len(s) {
			break
		}
	}
	return strings.Join(parts, "-")
}

// ParseCode reads a code as typed or pasted.
func ParseCode(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "").Replace(strings.TrimSpace(s)))
	b, err := codeEnc.DecodeString(s)
	if err != nil || len(b) != 16 {
		return nil, errors.New("that isn't a join code: copy it from Cluster › Add server on a member")
	}
	return b, nil
}

func joinerProof(code []byte, joinerPin, memberPin string) []byte {
	m := hmac.New(sha256.New, code)
	m.Write([]byte("hardyos-cluster-join-v1 joiner\x00" + joinerPin + "\x00" + memberPin))
	return m.Sum(nil)
}

func memberProof(code []byte, joinerPin, memberPin string, cluster ClusterID, node NodeID) []byte {
	m := hmac.New(sha256.New, code)
	m.Write([]byte("hardyos-cluster-join-v1 member\x00" + memberPin + "\x00" + joinerPin + "\x00" + string(cluster) + "\x00" + string(node)))
	return m.Sum(nil)
}

// JoinRequest is what a new node sends.
type JoinRequest struct {
	Proof    string   `json:"proof"`
	Node     Node     `json:"node"`
	Version  string   `json:"version"`
	Features []string `json:"features"`
}

// JoinAnswer is the member's answer.
type JoinAnswer struct {
	Cluster  ClusterID `json:"cluster"`
	Name     string    `json:"name"`
	Members  []Node    `json:"members"`
	Index    uint64    `json:"index"`
	Proof    string    `json:"proof"`
	Warnings []string  `json:"warnings"`
}

// JoinEvent is a join attempt, for the audit log.
type JoinEvent struct {
	Node    NodeID
	Name    string
	Role    Role
	IP      string
	OK      bool
	Detail  string
	CodeBy  string
	Problem string
}

// OpenJoinCode makes a one-time code admitting role.
func (n *Core) OpenJoinCode(ctx context.Context, role Role, by string) (*JoinOffer, error) {
	if n.Info() == nil {
		return nil, ErrNotMember
	}
	self, err := n.Self()
	if err != nil {
		return nil, err
	}
	if self.State != NodeActive || self.Role == RoleWitness {
		return nil, errors.New("only an active server can add members")
	}
	switch role {
	case RoleCompute, RoleStorage, RoleWitness:
	default:
		return nil, fmt.Errorf("unknown role %q", role)
	}
	snap := n.cfg.Machine.Snapshot()
	for _, m := range snap.Nodes {
		if role == RoleStorage && m.Role == RoleStorage {
			return nil, errors.New("the cluster already has its storage node")
		}
		if role == RoleWitness && m.Role == RoleWitness {
			return nil, errors.New("the cluster already has a witness")
		}
	}
	if role == RoleWitness && !self.Addresses.NetBird.IsValid() {
		return nil, errors.New("this server isn't on NetBird: the witness is reached over NetBird only (Control Panel › Remote Access)")
	}
	code := make([]byte, 16)
	_, _ = rand.Read(code)
	idb := make([]byte, 6)
	_, _ = rand.Read(idb)
	jc := JoinCode{ID: hex.EncodeToString(idb), Code: code, Role: role, Expires: time.Now().Add(JoinCodeTTL).UTC(), CreatedBy: by}
	n.codesMu.Lock()
	defer n.codesMu.Unlock()
	if err := n.cfg.Store.AddJoinCode(ctx, jc); err != nil {
		return nil, err
	}
	n.joinLimits.reset()
	off := &JoinOffer{Code: FormatCode(code), Role: role, Expires: jc.Expires}
	for _, a := range []netip.Addr{self.Addresses.LAN, self.Addresses.NetBird} {
		if a.IsValid() {
			off.Addresses = append(off.Addresses, netip.AddrPortFrom(a, uint16(n.tr.port())))
		}
	}
	return off, nil
}

// joinLimiter counts wrong tries per address.
type joinLimiter struct {
	mu sync.Mutex
	m  map[string]int
}

func (l *joinLimiter) reset() {
	l.mu.Lock()
	l.m = nil
	l.mu.Unlock()
}

func (l *joinLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.m[ip] >= MaxJoinFailuresPerIP
}

func (l *joinLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]int{}
	}
	l.m[ip]++
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// versionWindow: members may differ by one release (major.minor).
func versionWindow(a, b string) bool {
	pa, oka := majorMinor(a)
	pb, okb := majorMinor(b)
	if !oka || !okb {
		return true // development builds
	}
	if pa[0] != pb[0] {
		return false
	}
	d := pa[1] - pb[1]
	return d >= -1 && d <= 1
}

func majorMinor(v string) ([2]int, bool) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 || strings.Contains(v, "dev") {
		return [2]int{}, false
	}
	a, e1 := strconv.Atoi(parts[0])
	b, e2 := strconv.Atoi(parts[1])
	return [2]int{a, b}, e1 == nil && e2 == nil
}

// checkJoin lists every reason a node can't join (all at once) and
// warnings.
func (n *Core) checkJoin(req *JoinRequest, role Role) (problems, warnings []string) {
	snap := n.cfg.Machine.Snapshot()
	nd := req.Node
	if nd.Role != role {
		problems = append(problems, fmt.Sprintf("this code admits a %s node, not a %s node", role, nd.Role))
	}
	if !versionWindow(req.Version, n.cfg.Version) {
		problems = append(problems, fmt.Sprintf("HardyOS %s is too far from this cluster's %s: update first", req.Version, n.cfg.Version))
	}
	if PinOfKey(nd.PublicKey) != nd.Pin {
		problems = append(problems, "the new server's key doesn't match its pin")
	}
	for _, m := range snap.Nodes {
		if m.ID == nd.ID {
			problems = append(problems, fmt.Sprintf("a member is already called %s", nd.ID))
		}
		if strings.EqualFold(m.Name, nd.Name) {
			problems = append(problems, fmt.Sprintf("a member already has the hostname %s", nd.Name))
		}
		if m.Role == RoleStorage && nd.Role == RoleStorage {
			problems = append(problems, "the cluster already has its storage node")
		}
	}
	switch nd.Role {
	case RoleWitness:
		if !nd.Addresses.NetBird.IsValid() {
			problems = append(problems, "the witness needs a NetBird address")
		}
	default:
		if !nd.Addresses.LAN.IsValid() {
			problems = append(problems, "the new server has no LAN address")
		}
		if nd.Role == RoleCompute && snap.StorageSubnet.IsValid() && !snap.StorageSubnet.Contains(nd.Addresses.Storage) {
			problems = append(problems, fmt.Sprintf("the new server needs an address on the storage network %s", snap.StorageSubnet))
		}
		anyNB := false
		for _, m := range snap.Nodes {
			anyNB = anyNB || m.Addresses.NetBird.IsValid()
		}
		if anyNB && !nd.Addresses.NetBird.IsValid() {
			warnings = append(warnings, "the new server isn't on NetBird: it has no failover path if the LAN fails")
		}
	}
	return problems, warnings
}

func (n *Core) handleJoin(w http.ResponseWriter, r *http.Request) {
	ip := remoteIP(r)
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		peerError(w, http.StatusUnauthorized, "a client certificate is required")
		return
	}
	callerPin := PinOfCert(r.TLS.PeerCertificates[0])
	if _, ok := n.ByPin(callerPin); ok {
		peerError(w, http.StatusConflict, "this server is a member already")
		return
	}
	var req JoinRequest
	if err := decodePeer(r, &req); err != nil {
		peerError(w, http.StatusBadRequest, "invalid join request")
		return
	}
	proof, err := hex.DecodeString(req.Proof)
	if err != nil || len(proof) != sha256.Size {
		peerError(w, http.StatusBadRequest, "invalid proof")
		return
	}
	ctx := r.Context()
	n.codesMu.Lock()
	defer n.codesMu.Unlock()
	if n.joinLimits.blocked(ip) {
		peerErrorCode(w, http.StatusTooManyRequests, "too_many", "too many wrong join codes from this address")
		return
	}
	codes, err := n.cfg.Store.JoinCodes(ctx, time.Now())
	if err != nil {
		peerError(w, http.StatusInternalServerError, "join codes unavailable")
		return
	}
	if len(codes) == 0 {
		peerErrorCode(w, http.StatusForbidden, "no_code", "no join code is open on this member: make one in Cluster › Add server")
		return
	}
	self := n.cfg.Identity.Pin
	var code *JoinCode
	for i := range codes {
		if hmac.Equal(proof, joinerProof(codes[i].Code, callerPin, self)) {
			code = &codes[i]
			break
		}
	}
	report := func(e JoinEvent) {
		if n.cfg.OnJoin != nil {
			n.cfg.OnJoin(context.WithoutCancel(ctx), e)
		}
	}
	ev := JoinEvent{Node: req.Node.ID, Name: req.Node.Name, Role: req.Node.Role, IP: ip}
	if code == nil {
		n.joinLimits.fail(ip)
		for _, c := range codes {
			if f, err := n.cfg.Store.JoinCodeFailed(ctx, c.ID); err == nil && f >= MaxJoinFailures {
				_ = n.cfg.Store.TakeJoinCode(ctx, c.ID)
			}
		}
		ev.Problem = "wrong join code"
		report(ev)
		peerErrorCode(w, http.StatusForbidden, "wrong_code", "the join code doesn't match (or a connection in between changed it)")
		return
	}
	ev.CodeBy = code.CreatedBy
	req.Node.Pin = callerPin
	if problems, _ := n.checkJoin(&req, code.Role); len(problems) > 0 {
		ev.Problem = strings.Join(problems, "; ")
		report(ev)
		peerJSON(w, http.StatusConflict, map[string]any{"message": "the server can't join", "problems": problems})
		return
	}
	_, warnings := n.checkJoin(&req, code.Role)
	// One time: the code is gone before anything is committed.
	if err := n.cfg.Store.TakeJoinCode(ctx, code.ID); err != nil {
		peerError(w, http.StatusInternalServerError, "join codes unavailable")
		return
	}
	nd := req.Node
	nd.State, nd.Suffrage, nd.Version, nd.Features = NodeJoining, NonVoter, req.Version, req.Features
	nd.Compute, nd.BootID, nd.FenceEpoch = nil, "", 0
	idx, err := n.Propose(ctx, CmdMemberAdd, struct {
		Node Node `json:"node"`
	}{nd}, Actor{Kind: "local", Name: code.CreatedBy})
	if err != nil {
		ev.Problem = err.Error()
		report(ev)
		peerError(w, http.StatusConflict, "the cluster refused the new server: "+err.Error())
		return
	}
	if err := n.WaitApplied(ctx, idx); err != nil {
		peerError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	info := n.Info()
	ans := JoinAnswer{Cluster: info.Cluster, Name: n.cfg.Machine.Snapshot().Name, Index: idx, Warnings: warnings,
		Proof: hex.EncodeToString(memberProof(code.Code, callerPin, self, info.Cluster, nd.ID))}
	if ans.Warnings == nil {
		ans.Warnings = []string{}
	}
	for _, m := range n.peers() {
		if m.ID != nd.ID {
			ans.Members = append(ans.Members, m)
		}
	}
	ev.OK = true
	report(ev)
	n.log.Info("cluster: a server joined", "node", nd.ID, "role", nd.Role, "ip", ip)
	peerJSON(w, http.StatusOK, ans)
}

// JoinParams is what the joining node says about itself.
type JoinParams struct {
	Address string // the member's host or host:port
	Code    string
	Node    NodeID
	Name    string
	Role    Role
	// Pins, when set, are the only keys the member may have (the witness
	// script pins the members it was given).
	Pins []string
}

// Join joins a cluster through a member and starts this node.
func (n *Core) Join(ctx context.Context, p JoinParams) (*JoinAnswer, error) {
	if n.Info() != nil {
		return nil, errors.New("this server is in a cluster already")
	}
	code, err := ParseCode(p.Code)
	if err != nil {
		return nil, err
	}
	addr := p.Address
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), strconv.Itoa(n.tr.port()))
	}
	me := Node{ID: p.Node, Name: p.Name, Role: p.Role, Pin: n.cfg.Identity.Pin, PublicKey: n.cfg.Identity.PublicKey,
		Addresses: n.cfg.Addresses()}
	var memberPin string
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := n.tr.DialAddr(dctx, addr, ALPNPeer, "", &memberPin)
	if err != nil {
		return nil, fmt.Errorf("can't reach %s: %w", p.Address, err)
	}
	defer conn.Close()
	if len(p.Pins) > 0 && !slices.Contains(p.Pins, memberPin) {
		return nil, errors.New("the member's key isn't the one the install script pinned")
	}
	cc, err := (&http2.Transport{}).NewClientConn(conn)
	if err != nil {
		return nil, err
	}
	defer cc.Close()
	body, _ := json.Marshal(JoinRequest{Proof: hex.EncodeToString(joinerProof(code, me.Pin, memberPin)), Node: me,
		Version: n.cfg.Version, Features: n.cfg.Features})
	req, _ := http.NewRequestWithContext(dctx, http.MethodPost, "https://member"+PeerPathPrefix+"join", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("can't reach %s: %w", p.Address, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Message  string   `json:"message"`
			Problems []string `json:"problems"`
		}
		_ = json.Unmarshal(raw, &e)
		if len(e.Problems) > 0 {
			return nil, &JoinRefused{Problems: e.Problems}
		}
		if e.Message == "" {
			e.Message = resp.Status
		}
		return nil, errors.New(e.Message)
	}
	var ans JoinAnswer
	if err := json.Unmarshal(raw, &ans); err != nil {
		return nil, err
	}
	got, err := hex.DecodeString(ans.Proof)
	if err != nil || !hmac.Equal(got, memberProof(code, me.Pin, memberPin, ans.Cluster, me.ID)) {
		return nil, errors.New("the member couldn't prove it made that join code: check the address and code")
	}
	found := false
	for _, m := range ans.Members {
		if m.Pin == memberPin {
			found = true
		}
		if PinOfKey(m.PublicKey) != m.Pin {
			return nil, errors.New("the member sent a key that doesn't match its pin")
		}
	}
	if !found {
		return nil, errors.New("the member isn't in the member list it sent")
	}
	info := &Info{Cluster: ans.Cluster, Name: ans.Name, Node: me.ID, Role: me.Role, Peers: ans.Members, JoinIndex: ans.Index}
	if err := n.cfg.Store.SetInfo(ctx, info); err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.info = info
	err = n.startLocked(ctx, nil)
	n.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &ans, nil
}

// JoinRefused lists why the member refused a join.
type JoinRefused struct{ Problems []string }

func (e *JoinRefused) Error() string {
	return "the server can't join: " + strings.Join(e.Problems, "; ")
}

// FinishJoin waits until this node has caught up with its own member.add
// and announces it is ready (member.ready; the witness: witness.hello).
func (n *Core) FinishJoin(ctx context.Context, hello any) error {
	info := n.Info()
	if info == nil {
		return ErrNotMember
	}
	for {
		if self, ok := n.cfg.Machine.Node(info.Node); ok && self.State != NodeJoining {
			return n.savePeers(ctx)
		}
		if self, ok := n.cfg.Machine.Node(info.Node); ok && self.State == NodeJoining {
			var err error
			var idx uint64
			if info.Role == RoleWitness {
				idx, err = n.Propose(ctx, CmdWitnessHello, hello, Actor{Kind: "system", Name: "witness"})
			} else {
				idx, err = n.Propose(ctx, CmdMemberReady, struct{}{}, Actor{Kind: "system", Name: "join"})
			}
			if err == nil {
				if err := n.WaitApplied(ctx, idx); err != nil {
					return err
				}
				continue
			}
			var re *ErrRefused
			if errors.As(err, &re) {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// savePeers records the members as the state has them, so a restarted
// node can reach them before Raft has replayed its log.
func (n *Core) savePeers(ctx context.Context) error {
	peers := []Node{}
	for _, m := range n.cfg.Machine.PinIndex() {
		peers = append(peers, m)
	}
	if len(peers) == 0 {
		return nil
	}
	slices.SortFunc(peers, func(a, b Node) int { return strings.Compare(string(a.ID), string(b.ID)) })
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.info == nil {
		return nil
	}
	c := *n.info
	c.Peers = peers
	if err := n.cfg.Store.SetInfo(ctx, &c); err != nil {
		return err
	}
	n.info = &c
	return nil
}

// CreateParams describes a new cluster.
type CreateParams struct {
	Name          string
	Node          NodeID
	NodeName      string
	Role          Role
	StorageSubnet netip.Prefix
}

// Create makes a new cluster with this node as its only voter.
func (n *Core) Create(ctx context.Context, p CreateParams, actor Actor) (ClusterID, error) {
	if n.Info() != nil {
		return "", errors.New("this server is in a cluster already")
	}
	if p.Role != RoleCompute && p.Role != RoleStorage {
		return "", errors.New("a server is a compute or a storage node")
	}
	id := NewClusterID()
	info := &Info{Cluster: id, Name: p.Name, Node: p.Node, Role: p.Role}
	if err := n.cfg.Store.SetInfo(ctx, info); err != nil {
		return "", err
	}
	n.mu.Lock()
	n.info = info
	boot := raft.Configuration{Servers: []raft.Server{{Suffrage: raft.Voter, ID: raft.ServerID(p.Node), Address: raft.ServerAddress(p.Node)}}}
	err := n.startLocked(ctx, &boot)
	n.mu.Unlock()
	if err != nil {
		n.mu.Lock()
		n.info = nil
		n.mu.Unlock()
		_ = n.cfg.Store.ClearInfo(ctx)
		return "", err
	}
	me := Node{ID: p.Node, Name: p.NodeName, Role: p.Role, Pin: n.cfg.Identity.Pin, PublicKey: n.cfg.Identity.PublicKey,
		Addresses: n.cfg.Addresses(), Version: n.cfg.Version, Features: n.cfg.Features, BootID: n.cfg.BootID}
	body := struct {
		Cluster       ClusterID    `json:"cluster"`
		Name          string       `json:"name"`
		Node          Node         `json:"node"`
		StorageSubnet netip.Prefix `json:"storageSubnet"`
	}{id, p.Name, me, p.StorageSubnet}
	idx, err := n.Propose(ctx, CmdClusterCreate, body, actor)
	if err != nil {
		return "", err
	}
	return id, n.WaitApplied(ctx, idx)
}

// Leave takes this node out of the cluster: it hands leadership over,
// commits member.remove for itself, waits until it is out of the log's
// configuration, then stops and forgets its cluster state. The caller
// removes the identity.
func (n *Core) Leave(ctx context.Context, actor Actor) error {
	info := n.Info()
	if info == nil {
		return ErrNotMember
	}
	snap := n.cfg.Machine.Snapshot()
	for _, p := range snap.Placements {
		if p.Owner == info.Node || p.Target == info.Node {
			return fmt.Errorf("cluster workloads still run here (%s): drain this server first", p.Workload.ID)
		}
	}
	hardy := 0
	for _, m := range snap.Nodes {
		if m.Role != RoleWitness && m.ID != info.Node {
			hardy++
		}
	}
	if hardy == 0 && info.Role != RoleWitness {
		return errors.New("this is the cluster's last server: dissolve the cluster instead")
	}
	if n.IsLeader() {
		if r := n.r(); r != nil {
			_ = r.LeadershipTransfer().Error()
		}
	}
	if _, err := n.Propose(ctx, CmdMemberRemove, struct {
		Node NodeID `json:"node"`
	}{info.Node}, actor); err != nil {
		return err
	}
	// Wait (bounded) for the leader to take this node out of the
	// configuration, so the remaining voters don't count it.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		r := n.r()
		if r == nil {
			break
		}
		f := r.GetConfiguration()
		in := false
		if f.Error() == nil {
			for _, s := range f.Configuration().Servers {
				in = in || NodeID(s.ID) == info.Node
			}
		}
		if !in {
			break
		}
		select {
		case <-ctx.Done():
			deadline = time.Now()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return n.Wipe(ctx)
}

// Dissolve ends a cluster from its last server: confirm must be the
// cluster's name.
func (n *Core) Dissolve(ctx context.Context, confirm string) error {
	info := n.Info()
	if info == nil {
		return ErrNotMember
	}
	snap := n.cfg.Machine.Snapshot()
	if confirm != snap.Name {
		return errors.New("type the cluster's name to confirm")
	}
	for _, m := range snap.Nodes {
		if m.Role != RoleWitness && m.ID != info.Node {
			return fmt.Errorf("%s is still a member: every other server leaves (or is removed) first", m.ID)
		}
	}
	return n.Wipe(ctx)
}

// Remove commits member.remove for another (dead or gone) member;
// confirm must be its name.
func (n *Core) Remove(ctx context.Context, id NodeID, confirm string, actor Actor) error {
	m, ok := n.cfg.Machine.Node(id)
	if !ok {
		return fmt.Errorf("%s: %w", id, ErrNotMember)
	}
	if confirm != m.Name && confirm != string(m.ID) {
		return errors.New("type the server's name to confirm")
	}
	if id == n.ID() {
		return errors.New("use Leave on this server")
	}
	idx, err := n.Propose(ctx, CmdMemberRemove, struct {
		Node NodeID `json:"node"`
	}{id}, actor)
	if err != nil {
		return err
	}
	return n.WaitApplied(ctx, idx)
}

// Wipe stops the node and forgets its cluster state (Raft's data, the
// membership). The identity is the caller's to delete.
func (n *Core) Wipe(ctx context.Context) error {
	n.Stop()
	if n.cfg.Dir != "" {
		if err := os.RemoveAll(filepath.Join(n.cfg.Dir, "raft")); err != nil {
			return err
		}
	}
	if err := n.cfg.Store.ClearInfo(ctx); err != nil {
		return err
	}
	if codes, err := n.cfg.Store.JoinCodes(ctx, time.Now()); err == nil {
		for _, c := range codes {
			_ = n.cfg.Store.TakeJoinCode(ctx, c.ID)
		}
	}
	n.mu.Lock()
	n.info, n.halted = nil, nil
	n.mu.Unlock()
	_ = n.cfg.Machine.Restore([]byte(`{"nodes":{},"fences":{},"seq":{}}`))
	return nil
}

// ---- the witness binary for the install script --------------------------------------

// WitnessCodeOpen reports whether a witness join code is open.
func (n *Core) WitnessCodeOpen(ctx context.Context) bool {
	codes, err := n.cfg.Store.JoinCodes(ctx, time.Now())
	if err != nil {
		return false
	}
	return slices.ContainsFunc(codes, func(c JoinCode) bool { return c.Role == RoleWitness })
}

// BootstrapHandler serves GET /cluster/v1/witness/binary without a client
// certificate while a witness join code is open (the install script's
// curl pins this node's key).
func (n *Core) BootstrapHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != PeerPathPrefix+"witness/binary" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if n.cfg.WitnessBinary == nil || !n.WitnessCodeOpen(r.Context()) {
			http.Error(w, "no witness join code is open", http.StatusForbidden)
			return
		}
		f, err := n.cfg.WitnessBinary()
		if err != nil {
			http.Error(w, "the witness binary isn't available", http.StatusServiceUnavailable)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, "hardyos-witness", time.Time{}, f)
	})
}
