package state

import (
	"net/netip"
	"testing"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Addresses are checked against the storage network and the other members
// (decision 374), and the witness can't claim more than NetBird.
func TestMemberAddressRules(t *testing.T) {
	h := &fsmHarness{t: t, f: New()}
	nas := newTNode(t, "nas", cluster.RoleStorage, "192.168.1.105")
	nas.node.Addresses.Storage = netip.MustParseAddr("10.77.0.10")
	c1 := newTNode(t, "c1", cluster.RoleCompute, "192.168.1.21")
	w := newTNode(t, "witness", cluster.RoleWitness, "100.64.0.9")
	h.mustApply(nas.sign(t, cluster.CmdClusterCreate, CreateBody{Cluster: testCluster, Name: "home", Node: nas.node,
		StorageSubnet: netip.MustParsePrefix("10.77.0.0/24")}))

	// A new member with another member's LAN address.
	dup := c1.node
	dup.Addresses.LAN = nas.node.Addresses.LAN
	h.mustRefuse(nas.sign(t, cluster.CmdMemberAdd, MemberAddBody{Node: dup}), "is nas's address")
	h.mustApply(nas.sign(t, cluster.CmdMemberAdd, MemberAddBody{Node: c1.node}))
	h.mustApply(c1.sign(t, cluster.CmdMemberReady, MemberReadyBody{}))

	set := func(n *tnode, a cluster.Addresses) []byte {
		return n.sign(t, cluster.CmdMemberUpdate, MemberUpdateBody{Addresses: &a})
	}
	a := c1.node.Addresses
	a.Storage = netip.MustParseAddr("10.88.0.21")
	h.mustRefuse(set(c1, a), "isn't on the storage network")
	a.Storage = netip.MustParseAddr("10.77.0.10")
	h.mustRefuse(set(c1, a), "is nas's address")
	a.Storage = netip.MustParseAddr("10.77.0.21")
	a.Portals = []netip.AddrPort{netip.MustParseAddrPort("10.77.0.21:3260")}
	h.mustRefuse(set(c1, a), "only the storage node")
	a.Portals = nil
	h.mustApply(set(c1, a))

	// The witness: NetBird only, never another member's address.
	h.mustApply(nas.sign(t, cluster.CmdMemberAdd, MemberAddBody{Node: w.node}))
	h.mustRefuse(w.sign(t, cluster.CmdWitnessHello, WitnessHelloBody{Addresses: cluster.Addresses{NetBird: w.node.Addresses.NetBird,
		Storage: netip.MustParseAddr("10.77.0.99")}, Version: "1"}), "NetBird address only")
	h.mustRefuse(w.sign(t, cluster.CmdWitnessHello, WitnessHelloBody{Addresses: cluster.Addresses{NetBird: w.node.Addresses.NetBird,
		LAN: netip.MustParseAddr("192.168.1.99")}, Version: "1"}), "NetBird address only")
	h.mustRefuse(w.sign(t, cluster.CmdWitnessHello, WitnessHelloBody{Addresses: cluster.Addresses{NetBird: nas.node.Addresses.LAN},
		Version: "1"}), "is nas's address")
	hello := WitnessHelloBody{Addresses: w.node.Addresses, Version: "1"}
	h.mustApply(w.sign(t, cluster.CmdWitnessHello, hello))
	// The same hello again is refused (no log growth from a chatty witness).
	h.mustRefuse(w.sign(t, cluster.CmdWitnessHello, hello), "changes nothing")
	hello.Version = "2"
	h.mustApply(w.sign(t, cluster.CmdWitnessHello, hello))
}
