// Package netcheck is the cluster's local-network check (decisions
// 490-492, docs/plans/cluster-gaps.md): do the servers that hold and run
// workloads (the compute servers and the storage server) reach each other
// directly on the LAN and on the storage network, with low latency and, on
// the storage network, the same MTU? The cluster works without it (over
// NetBird); turning high availability on and live moves need it.
//
// Every server probes every other one on both paths with signed probes
// over the cluster port (probe.go) and keeps its latest Report (monitor.go).
// Status collects every member's report and judges them (Evaluate).
package netcheck

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// The rules (decision 490).
// MaxRTT is the most a LAN or storage path's round trip may be (the best
// of Samples, so a busy moment doesn't count; a WAN's best is still far
// above it). A variable for tests on slow fakes only.
var MaxRTT = 5 * time.Millisecond

const (
	// Samples small probes are timed per path; BulkSize is the padding of
	// the one large probe (jumbo frames the switch drops stall it).
	Samples  = 5
	BulkSize = 64 << 10
	// MaxAge is how old a member's report may be.
	MaxAge = 2 * time.Minute
)

// Paths are the paths the check covers, in the transport's order (NetBird
// is never a local network).
var Paths = []cluster.Path{cluster.PathLAN, cluster.PathStorage}

// PathResult is one server's probe of one peer over one path.
type PathResult struct {
	Peer cluster.NodeID `json:"peer"`
	Path cluster.Path   `json:"path"`
	OK   bool           `json:"ok"`
	// Reason says what failed, in plain words ("" when OK).
	Reason string `json:"reason,omitempty"`
	// Answered: the probes were answered (signed by the peer).
	Answered bool `json:"answered"`
	// RTT is the best round trip of the small probes.
	RTT time.Duration `json:"rtt"`
	// Addr is this server's address on the path, PeerAddr the peer's;
	// Local is the address the connection actually left from and SeenAs
	// the one the peer saw it come from.
	Addr     netip.Addr `json:"addr,omitzero"`
	PeerAddr netip.Addr `json:"peerAddr,omitzero"`
	Local    netip.Addr `json:"local,omitzero"`
	SeenAs   netip.Addr `json:"seenAs,omitzero"`
	// Arrived is where the peer received it (its own address on the path).
	Arrived netip.Addr `json:"arrived,omitzero"`
	// SameSubnet: the peer's address is in this server's interface subnet
	// (else the path is routed).
	SameSubnet bool `json:"sameSubnet"`
	// Interface is this server's interface on the path; MTU its MTU and
	// PeerMTU the peer's receiving interface's (0: unknown).
	Interface string `json:"interface,omitempty"`
	MTU       int    `json:"mtu"`
	PeerMTU   int    `json:"peerMtu"`
	// Bulk: the large probe got through.
	Bulk bool `json:"bulk"`
	// Problem is the transport error, when the probes weren't answered.
	Problem string `json:"problem,omitempty"`
}

// Report is one server's latest probes of every other one.
type Report struct {
	Node    cluster.NodeID `json:"node"`
	Checked time.Time      `json:"checked"`
	Paths   []PathResult   `json:"paths"`
}

// MemberResult is one server's part of the result.
type MemberResult struct {
	Node cluster.NodeID `json:"node"`
	Name string         `json:"name"`
	Role cluster.Role   `json:"role"`
	OK   bool           `json:"ok"`
	// Reason is the first problem of this server's probes ("" when OK).
	Reason string `json:"reason,omitempty"`
	// Skipped: not checked (dead, fenced or still joining).
	Skipped bool         `json:"skipped,omitempty"`
	Checked time.Time    `json:"checked,omitzero"`
	Paths   []PathResult `json:"paths"`
}

// Result is the cluster's local-network check. OK: every pair of compute
// and storage servers shares the LAN and the storage network.
type Result struct {
	OK        bool           `json:"ok"`
	Reason    string         `json:"reason,omitempty"`
	PerMember []MemberResult `json:"perMember"`
}

// Source is where Status gets the members and their reports (the Monitor
// in hardyd; fakes in tests).
type Source interface {
	// Snapshot is the cluster's applied state; nil outside a cluster.
	Snapshot() *cluster.Snapshot
	// Reports fetches the latest report of each listed member (this
	// server's own locally); a member whose report can't be had is in errs.
	Reports(ctx context.Context, nodes []cluster.NodeID) (map[cluster.NodeID]*Report, map[cluster.NodeID]error)
}

// Status is the cluster's local-network check now. Outside a cluster it is
// OK with nothing to check.
func Status(ctx context.Context, src Source) Result {
	if src == nil {
		return Result{OK: false, Reason: "the local-network check isn't running on this server", PerMember: []MemberResult{}}
	}
	s := src.Snapshot()
	if s == nil {
		return Result{OK: true, PerMember: []MemberResult{}}
	}
	ids := []cluster.NodeID{}
	for _, n := range Checked(s) {
		ids = append(ids, n.ID)
	}
	reps, errs := src.Reports(ctx, ids)
	return Evaluate(s, reps, errs, time.Now())
}

// Checked lists the servers the check covers: compute and storage, not
// removed, dead, fenced or joining, by id.
func Checked(s *cluster.Snapshot) []*cluster.Node {
	var out []*cluster.Node
	for _, n := range s.Nodes {
		if covered(n) && checkable(n) {
			out = append(out, n)
		}
	}
	slices.SortFunc(out, func(a, b *cluster.Node) int { return strings.Compare(string(a.ID), string(b.ID)) })
	return out
}

func covered(n *cluster.Node) bool {
	return n != nil && (n.Role == cluster.RoleCompute || n.Role == cluster.RoleStorage) && n.State != cluster.NodeRemoved
}

func checkable(n *cluster.Node) bool {
	switch n.State {
	case cluster.NodeDead, cluster.NodeFenced, cluster.NodeJoining, cluster.NodeRemoved:
		return false
	}
	return true
}

// Evaluate judges every member's report with the rules (decision 490).
func Evaluate(s *cluster.Snapshot, reps map[cluster.NodeID]*Report, errs map[cluster.NodeID]error, now time.Time) Result {
	out := Result{OK: true, PerMember: []MemberResult{}}
	if s == nil {
		return out
	}
	var all []*cluster.Node
	for _, n := range s.Nodes {
		if covered(n) {
			all = append(all, n)
		}
	}
	slices.SortFunc(all, func(a, b *cluster.Node) int { return strings.Compare(string(a.ID), string(b.ID)) })
	peers := Checked(s)
	for _, n := range all {
		mr := MemberResult{Node: n.ID, Name: n.Name, Role: n.Role, OK: true, Paths: []PathResult{}}
		if !checkable(n) {
			mr.Skipped, mr.Reason = true, "not checked while it is "+string(n.State)
			out.PerMember = append(out.PerMember, mr)
			continue
		}
		rep := reps[n.ID]
		switch {
		case rep == nil:
			why := "no report yet"
			if err := errs[n.ID]; err != nil {
				why = err.Error()
			}
			mr.OK, mr.Reason = false, fmt.Sprintf("couldn't get %s's check: %s", label(n), why)
		case rep.Node != n.ID:
			mr.OK, mr.Reason = false, fmt.Sprintf("%s answered with another server's check", label(n))
		case now.Sub(rep.Checked) > MaxAge:
			mr.OK, mr.Reason = false, fmt.Sprintf("%s's check is %s old", label(n), now.Sub(rep.Checked).Round(time.Second))
		}
		if rep != nil && rep.Node == n.ID {
			mr.Checked = rep.Checked
		}
		for _, p := range peers {
			if p.ID == n.ID {
				continue
			}
			for _, path := range Paths {
				var pr PathResult
				found := false
				if rep != nil && rep.Node == n.ID {
					for _, x := range rep.Paths {
						if x.Peer == p.ID && x.Path == path {
							pr, found = x, true
							break
						}
					}
				}
				if !found {
					pr = PathResult{Peer: p.ID, Path: path, Addr: pathAddr(n.Addresses, path), PeerAddr: pathAddr(p.Addresses, path)}
					if rep != nil && mr.OK {
						pr.Problem = "not probed yet"
					}
				}
				// The same rules for every report (an older member's too).
				Judge(&pr, n, p)
				if mr.OK && !pr.OK && mr.Reason == "" {
					mr.OK, mr.Reason = false, pr.Reason
				}
				mr.Paths = append(mr.Paths, pr)
			}
		}
		if rep != nil && !mr.OK && mr.Reason == "" {
			mr.Reason = "its check failed"
		}
		if !mr.OK {
			out.OK = false
			if out.Reason == "" {
				out.Reason = mr.Reason
			}
		}
		out.PerMember = append(out.PerMember, mr)
	}
	return out
}

func label(n *cluster.Node) string {
	if n.Name != "" {
		return n.Name
	}
	return string(n.ID)
}

// PathName is a path in words.
func PathName(p cluster.Path) string {
	switch p {
	case cluster.PathLAN:
		return "the LAN"
	case cluster.PathStorage:
		return "the storage network"
	case cluster.PathNetBird:
		return "NetBird"
	}
	return string(p)
}

func pathAddr(a cluster.Addresses, p cluster.Path) netip.Addr {
	switch p {
	case cluster.PathLAN:
		return a.LAN
	case cluster.PathStorage:
		return a.Storage
	case cluster.PathNetBird:
		return a.NetBird
	}
	return netip.Addr{}
}

// Judge sets pr.OK and pr.Reason from what was measured: the rules of
// decision 490, checked in order, the first failure named.
func Judge(pr *PathResult, self, peer *cluster.Node) {
	who := fmt.Sprintf("%s → %s on %s", label(self), label(peer), PathName(pr.Path))
	addr, paddr := pathAddr(self.Addresses, pr.Path), pathAddr(peer.Addresses, pr.Path)
	nb := self.Addresses.NetBird
	fail := func(f string, a ...any) {
		pr.OK, pr.Reason = false, who+": "+fmt.Sprintf(f, a...)
	}
	pr.OK, pr.Reason = true, ""
	switch {
	case !addr.IsValid():
		fail("%s has no address on it", label(self))
	case !paddr.IsValid():
		fail("%s has no address on it", label(peer))
	case !pr.Answered:
		why := pr.Problem
		if why == "" {
			why = "no answer"
		}
		if pr.MTU > 1500 {
			// The TLS handshake alone is larger than 1500 bytes (its key
			// shares): behind a switch without jumbo frames it never ends.
			fail("not reachable (%s); the MTU here is %d: check that the switch allows jumbo frames", why, pr.MTU)
		} else {
			fail("not reachable (%s)", why)
		}
	case pr.Local.IsValid() && nb.IsValid() && pr.Local == nb:
		fail("the connection goes over NetBird, not directly")
	case pr.Local != addr:
		fail("the connection leaves from %s, not from this server's address %s (another route or interface)", show(pr.Local), addr)
	case pr.SeenAs != addr:
		fail("%s sees it coming from %s, not from %s (NAT or a detour)", label(peer), show(pr.SeenAs), addr)
	case pr.Arrived.IsValid() && pr.Arrived != paddr:
		fail("it arrives at %s, not at %s's address %s", pr.Arrived, label(peer), paddr)
	case pr.RTT > MaxRTT:
		fail("round trip %s, more than %s: not a local network", pr.RTT.Round(10*time.Microsecond), MaxRTT)
	case !pr.Bulk:
		if pr.Path == cluster.PathStorage && pr.MTU > 1500 {
			fail("large packets don't get through (MTU %d here): check that the switch allows jumbo frames", pr.MTU)
		} else {
			fail("large packets don't get through: check the MTU of the switch and both servers")
		}
	case pr.Path == cluster.PathStorage && pr.MTU != 0 && pr.PeerMTU != 0 && pr.MTU != pr.PeerMTU:
		fail("MTU %d here but %d on %s: set the same MTU on every server's storage port", pr.MTU, pr.PeerMTU, label(peer))
	}
}

func show(a netip.Addr) string {
	if !a.IsValid() {
		return "an unknown address"
	}
	return a.String()
}
