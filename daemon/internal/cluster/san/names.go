// Package san is the storage node's iSCSI target (LIO) and its storage
// firewall, configured by hardyd-priv (docs/plans/cluster.md section 5).
//
// LIO is driven through configfs (/sys/kernel/config/target), the kernel
// interface targetcli itself writes. Root keeps the desired configuration
// in its own file and rebuilds LIO from it at boot and on every change
// (Reconcile is idempotent). There is one iSCSI target per compute node,
// with mutual CHAP and exactly one ACL (that node's initiator); a workload's
// zvol is mapped as a LUN into the target of the node its grant names (two
// during a live migration). Fencing a node disables its target, which
// drops its sessions at once.
//
// Names and the desired-state model are pure Go so hardyd can build a
// desired state from the replicated cluster state; root validates it again
// (Desired.Validate plus the dataset checks in Root) before acting.
package san

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Ports of the storage network.
const (
	ISCSIPort = 3260
	NFSPort   = 2049
	// MigrateFirst..MigrateLast is the live-migration memory range compute
	// nodes open to members' storage addresses (QEMU's default 49152+).
	MigrateFirst = 49152
	MigrateLast  = 49215
)

// HBA is the iblock HBA HardyOS's backstores live in
// (core/iblock_<HBA>), so LIO objects made by hand elsewhere are never
// touched.
const HBA = 77

// TPGTag is the one target portal group of every HardyOS target.
const TPGTag = 1

var (
	nodeRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	idRE      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)
	poolRE    = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.:-]{0,63}$`)
	diskRE    = regexp.MustCompile(`^disk[0-9]$`)
	clusterRE = regexp.MustCompile(`^[a-z2-7]{8,32}$`)
	bsRE      = regexp.MustCompile(`^hc[av]_[a-z0-9_-]{1,60}$`)
	serialRE  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// ValidNode checks a node id.
func ValidNode(n cluster.NodeID) error {
	if !nodeRE.MatchString(string(n)) {
		return fmt.Errorf("node %q isn't a valid node id", n)
	}
	return nil
}

// ValidCluster checks a cluster id.
func ValidCluster(c cluster.ClusterID) error {
	if !clusterRE.MatchString(string(c)) {
		return fmt.Errorf("cluster id %q isn't valid", c)
	}
	return nil
}

// ShortCluster is the first 8 characters of the cluster id, used in IQNs.
func ShortCluster(c cluster.ClusterID) string {
	s := string(c)
	if len(s) > 8 {
		s = s[:8]
	}
	return s
}

// TargetIQN is a compute node's target on the storage node.
func TargetIQN(c cluster.ClusterID, node cluster.NodeID) string {
	return cluster.IQNPrefix + "." + ShortCluster(c) + "." + string(node)
}

// InitiatorIQN is a compute node's initiator name.
func InitiatorIQN(c cluster.ClusterID, node cluster.NodeID) string {
	return TargetIQN(c, node) + ".init"
}

// ClusterIQNPrefix starts every target of cluster c (with the final dot).
func ClusterIQNPrefix(c cluster.ClusterID) string {
	return cluster.IQNPrefix + "." + ShortCluster(c) + "."
}

// NodeOfTarget returns the node a HardyOS target IQN belongs to.
func NodeOfTarget(c cluster.ClusterID, iqn string) (cluster.NodeID, bool) {
	rest, ok := strings.CutPrefix(iqn, ClusterIQNPrefix(c))
	if !ok || ValidNode(cluster.NodeID(rest)) != nil {
		return "", false
	}
	return cluster.NodeID(rest), true
}

// VMDisk is a VM disk's zvol on the storage node.
func VMDisk(pool, vm, disk string) string { return pool + "/vms/" + vm + "/" + disk }

// AppBlock is an app's block-mode zvol on the storage node.
func AppBlock(pool, app string) string { return pool + "/apps/" + app + "/block" }

// BackstoreName names a workload volume's backstore: hcv_<vm>_<disk> for VM
// disks, hca_<app>_block for an app's block volume. Ids can't hold '_', so
// names never collide; a VM and an app may share an id, hence the kind.
func BackstoreName(w cluster.WorkloadRef, disk string) string {
	k := "hcv_"
	if w.Kind == cluster.KindApp {
		k = "hca_"
	}
	n := k + w.ID + "_" + disk
	if len(n) > 63 {
		sum := sha256.Sum256([]byte(n))
		n = k + hex.EncodeToString(sum[:])[:40]
	}
	return n
}

// ValidBackstoreName checks a backstore name.
func ValidBackstoreName(n string) error {
	if !bsRE.MatchString(n) {
		return fmt.Errorf("backstore name %q isn't one of HardyOS's", n)
	}
	return nil
}

// Serial derives a LUN's unit serial (UUID-formatted) from the zvol's GUID
// and the cluster, so it stays the same across reboots, rebuilds and
// re-exports, and differs between clusters.
func Serial(c cluster.ClusterID, guid string) string {
	sum := sha256.Sum256([]byte("hardyos-lun\x00" + string(c) + "\x00" + guid))
	h := hex.EncodeToString(sum[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// WWN is the NAA identifier LIO reports for a unit serial (NAA 6, LIO's
// IEEE company id 001405, then the serial's first 25 hex digits), which a
// compute node sees as /dev/disk/by-id/wwn-0x<WWN>.
func WWN(serial string) string {
	var b strings.Builder
	b.WriteString("6001405")
	for _, r := range serial {
		if b.Len() == 32 {
			break
		}
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ByIDPath is where a compute node finds a LUN.
func ByIDPath(wwn string) string { return "/dev/disk/by-id/wwn-0x" + wwn }

// portalDir is a portal's configfs directory name: ip:port, IPv6 in
// brackets.
func portalDir(p netip.AddrPort) string {
	if p.Addr().Is6() {
		return "[" + p.Addr().String() + "]:" + fmt.Sprint(p.Port())
	}
	return p.String()
}
