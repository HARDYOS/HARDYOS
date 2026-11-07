package vms

// VMs on cluster storage (Phase 8 part C, docs/plans/cluster.md section
// 6.2): a VM whose state folder is an NFS mount of the storage server and
// whose disks are iSCSI LUNs. The Backend (part B's sanclient) says what is
// attached here and under which placement generation; the cluster starts
// such a VM only with that generation (decision 326) and never through the
// plain start operation.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// ErrClusterPlaced: a cluster VM is started and stopped by the cluster on
// the server it is placed on.
var ErrClusterPlaced = errors.New("this virtual machine is on cluster storage: the cluster starts it on the server it is placed on (Cluster › Workloads)")

// ErrGeneration: the storage attached here is of another placement
// generation than the cluster asked for.
var ErrGeneration = errors.New("this server's attachment of the VM's storage is of another placement generation")

// clusterDiskRE are the only devices a cluster VM's disk may be: a LUN by
// its WWN, or its multipath device.
var clusterDiskRE = regexp.MustCompile(`^(/dev/disk/by-id/wwn-0x[0-9a-f]{16,32}|/dev/mapper/[0-9a-f]{17,33})$`)

// ClusterDiskPath reports whether dev may be a cluster VM's disk.
func ClusterDiskPath(dev string) bool { return clusterDiskRE.MatchString(dev) }

// ClusterStateRoot is where cluster VMs' state folders are mounted
// (cluster.RemoteMountRoot; not imported to keep vms free of the cluster).
const ClusterStateRoot = "/mnt/hc"

// clusterStored reads the VMs whose cluster storage is attached here.
func (m *Manager) clusterStored(ctx context.Context) []*stored {
	if m.Backend == nil {
		return nil
	}
	ids, err := m.Backend.List(ctx)
	if err != nil {
		m.log().Warn("vms: listing VMs on cluster storage", "err", err)
		return nil
	}
	slices.Sort(ids)
	var out []*stored
	for _, id := range ids {
		if ValidID(id) != nil {
			continue
		}
		a, err := m.Backend.Locate(ctx, id)
		if err != nil {
			m.log().Warn("vms: a cluster VM's storage", "id", id, "err", err)
			continue
		}
		st, err := m.readCluster(id, a)
		if err != nil {
			m.log().Warn("vms: skipping a cluster VM that can't be read", "id", id, "err", err)
			continue
		}
		out = append(out, st)
	}
	return out
}

// readCluster reads a cluster VM's spec from its attached state folder.
func (m *Manager) readCluster(id string, a *AttachedStorage) (*stored, error) {
	if a.Backend != BackendCluster {
		return nil, errors.New("not cluster storage")
	}
	dir := filepath.Clean(a.StateDir)
	if !filepath.IsAbs(a.StateDir) || dir != a.StateDir || !strings.HasPrefix(dir, ClusterStateRoot+"/") {
		return nil, fmt.Errorf("its state folder %q isn't under %s", a.StateDir, ClusterStateRoot)
	}
	b, err := rootfile.ReadFile(filepath.Join(m.sys(dir), specFile))
	if err != nil {
		return nil, err
	}
	var s Spec
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", specFile, err)
	}
	if s.ID != id {
		return nil, fmt.Errorf("%s describes %s, not %s", specFile, s.ID, id)
	}
	s.Normalize()
	if err := m.checkStored(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", specFile, err)
	}
	for _, d := range s.Disks {
		if !ClusterDiskPath(a.Disks[d.Name]) {
			return nil, fmt.Errorf("its disk %s isn't attached", d.Name)
		}
	}
	att := *a
	return &stored{spec: s, dataset: Dataset(s.Pool, s.ID), dir: dir, cluster: &att}, nil
}

// localOnly refuses storage operations on a cluster VM: they are the
// storage server's (hardyd routes them there).
func localOnly(st *stored) error {
	if st.cluster != nil {
		return ErrClusterStorage
	}
	return nil
}

// clusterUpdate checks a settings change of a cluster VM: disks and pool
// are the storage server's.
func clusterUpdate(st *stored, prev, next *Spec) error {
	if st.cluster == nil {
		return nil
	}
	if next.Pool != prev.Pool || len(next.Disks) != len(prev.Disks) {
		return ErrClusterStorage
	}
	for i := range next.Disks {
		if next.Disks[i].Name != prev.Disks[i].Name || next.Disks[i].SizeGB != prev.Disks[i].SizeGB || next.Disks[i].Import != nil {
			return ErrClusterStorage
		}
	}
	return nil
}

// ClusterStartArgs starts a cluster VM placed here.
type ClusterStartArgs struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation"`
	// SpecHash is the approved settings' hash in the replicated placement
	// (decision 386): root starts the VM only when the stored spec on
	// cluster storage hashes the same.
	SpecHash string `json:"specHash"`
}

// ClusterStart starts a cluster VM, only when its storage is attached here
// under the generation hardyd names (the one of the applied grant).
func (m *Manager) ClusterStart(ctx context.Context, a ClusterStartArgs) (*Result, error) {
	unlock, err := m.lockValid(a.ID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := m.findCluster(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	if a.Generation == 0 || st.cluster.Generation != a.Generation {
		return nil, fmt.Errorf("%w (attached %d, asked %d)", ErrGeneration, st.cluster.Generation, a.Generation)
	}
	if err := checkSpecHash(&st.spec, a.SpecHash); err != nil {
		m.log().Warn("vms: refused to start a cluster VM whose settings changed", "id", a.ID, "err", err)
		return nil, err
	}
	return m.startStored(ctx, st)
}

// ClusterStopArgs stops a cluster VM.
type ClusterStopArgs struct {
	ID    string `json:"id"`
	Force bool   `json:"force"`
	// Undefine removes the libvirt definition after a forced stop (the VM
	// moves away or the node fences itself).
	Undefine bool `json:"undefine,omitempty"`
}

// ClusterStop stops a cluster VM (gracefully, or at once with Force).
func (m *Manager) ClusterStop(ctx context.Context, a ClusterStopArgs) (*VM, error) {
	if err := ValidID(a.ID); err != nil {
		return nil, ErrNotFound
	}
	st, err := m.findCluster(ctx, a.ID)
	if err != nil && a.Force {
		// Storage already gone (fenced, detached) or unreadable: stop the
		// domain anyway, by killing QEMU if libvirt can't.
		if err := m.forceDestroy(ctx, a.ID); err != nil {
			return nil, err
		}
		if a.Undefine {
			m.undefine(ctx, a.ID)
		}
		m.setRunning(a.ID, false)
		return &VM{Spec: Spec{ID: a.ID}, State: "stopped", Backend: BackendCluster}, nil
	}
	if err != nil {
		return nil, err
	}
	v, err := m.Stop(ctx, StopArgs{ID: st.spec.ID, Force: a.Force})
	if err != nil && a.Force {
		// libvirt didn't stop it (polkitd down, libvirtd hung): QEMU goes.
		if kerr := m.forceDestroy(ctx, a.ID); kerr != nil {
			return nil, fmt.Errorf("%v; %w", err, kerr)
		}
		m.setRunning(a.ID, false)
		v, err = &VM{Spec: st.spec, State: "stopped", Backend: BackendCluster}, nil
	}
	if err == nil && a.Force && a.Undefine {
		m.undefine(ctx, a.ID)
	}
	return v, err
}

func (m *Manager) undefine(ctx context.Context, id string) {
	if _, err := m.virsh(ctx, "undefine", id, "--nvram", "--keep-tpm"); err != nil && !notDefined(err) {
		if _, err := m.virsh(ctx, "undefine", id); err != nil && !notDefined(err) {
			m.log().Warn("vms: undefining a cluster VM", "id", id, "err", err)
		}
	}
}

// ClusterVM is a cluster VM's state on this server.
type ClusterVM struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Generation uint64 `json:"generation"`
	// Attached: its storage is attached here (otherwise a domain of that
	// name runs without it: stale).
	Attached bool `json:"attached"`
}

// ClusterStatus lists the cluster VMs attached or running here. A running
// domain whose storage isn't attached is listed too (Attached false), so
// a rejoining server stops it.
func (m *Manager) ClusterStatus(ctx context.Context) ([]ClusterVM, error) {
	out := []ClusterVM{}
	stats := m.stats(ctx)
	seen := map[string]bool{}
	for _, st := range m.clusterStored(ctx) {
		seen[st.spec.ID] = true
		state := "stopped"
		if s, ok := stats[st.spec.ID]; ok {
			state = s.State
		}
		out = append(out, ClusterVM{ID: st.spec.ID, State: state, Generation: st.cluster.Generation, Attached: true})
	}
	if m.Backend == nil {
		return out, nil
	}
	// Domains running here that are neither local nor attached: HardyOS's
	// own cluster VMs whose storage was taken away (a fence).
	local, err := m.datasets(ctx)
	if err != nil {
		return out, err
	}
	localIDs := map[string]bool{}
	for ds := range local {
		localIDs[ds[strings.LastIndex(ds, "/")+1:]] = true
	}
	for id, s := range stats {
		if seen[id] || localIDs[id] || ValidID(id) != nil {
			continue
		}
		if s.State == "running" || s.State == "paused" {
			out = append(out, ClusterVM{ID: id, State: s.State})
		}
	}
	slices.SortFunc(out, func(a, b ClusterVM) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// HostCPU is what this server's libvirt says about its CPU, for the
// cluster's baseline (vms.cpu.baseline).
type HostCPU struct {
	Arch string `json:"arch"`
	// HostModel is libvirt's name for this CPU (host-model).
	HostModel string `json:"hostModel"`
	// Usable are the named models this server can run as they are.
	Usable []string `json:"usable"`
	// Signature identifies this exact CPU for host-passthrough VMs: the
	// host model, its vendor and the features libvirt adds or removes
	// ("Skylake-Client-IBRS/Intel/<hash>"). Two servers with the same
	// signature run a host-passthrough VM alike (decision 393).
	Signature string `json:"signature,omitempty"`
}

type domCapsXML struct {
	Arch string `xml:"arch"`
	CPU  struct {
		Modes []struct {
			Name      string `xml:"name,attr"`
			Supported string `xml:"supported,attr"`
			Models    []struct {
				Usable string `xml:"usable,attr"`
				Name   string `xml:",chardata"`
			} `xml:"model"`
			Vendor   string `xml:"vendor"`
			Features []struct {
				Policy string `xml:"policy,attr"`
				Name   string `xml:"name,attr"`
			} `xml:"feature"`
		} `xml:"mode"`
	} `xml:"cpu"`
}

// ParseDomainCapabilities reads `virsh domcapabilities`.
func ParseDomainCapabilities(b []byte) (*HostCPU, error) {
	var d domCapsXML
	if err := xml.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	h := &HostCPU{Arch: strings.TrimSpace(d.Arch), Usable: []string{}}
	for _, mode := range d.CPU.Modes {
		if mode.Supported != "yes" {
			continue
		}
		for _, mo := range mode.Models {
			name := strings.TrimSpace(mo.Name)
			if !cpuModelRE.MatchString(name) {
				continue
			}
			switch mode.Name {
			case "host-model":
				h.HostModel = name
				var fs []string
				for _, f := range mode.Features {
					fs = append(fs, f.Policy+":"+f.Name)
				}
				slices.Sort(fs)
				sum := sha256.Sum256([]byte(strings.Join(fs, ",")))
				h.Signature = name + "/" + strings.TrimSpace(mode.Vendor) + "/" + hex.EncodeToString(sum[:6])
			case "custom":
				if mo.Usable == "yes" {
					h.Usable = append(h.Usable, name)
				}
			}
		}
	}
	return h, nil
}

// HostCPUInfo asks libvirt about this server's CPU.
func (m *Manager) HostCPUInfo(ctx context.Context) (*HostCPU, error) {
	out, err := m.virsh(ctx, "domcapabilities", "--virttype", "kvm")
	if err != nil {
		return nil, err
	}
	return ParseDomainCapabilities(out)
}

// abiLevels are generic CPU models, newest first, preferred as a baseline
// when every server can run them (the same features everywhere, no vendor
// specifics). Plain data: servers of other architectures simply have none.
var abiLevels = []string{"x86-64-v4", "x86-64-v3", "x86-64-v2-AES", "x86-64-v2", "x86-64-v1"}

// ChooseBaseline picks the named CPU model every server can run: the
// newest generic level they share, else the shared model that comes last
// in the first server's list (libvirt lists models oldest first). "" when
// they share none (VMs then use host-passthrough and migrate only between
// identical CPUs).
func ChooseBaseline(hosts []HostCPU) string {
	if len(hosts) == 0 {
		return ""
	}
	common := map[string]int{}
	for _, h := range hosts {
		seen := map[string]bool{}
		for _, m := range h.Usable {
			if !seen[m] {
				seen[m] = true
				common[m]++
			}
		}
	}
	shared := func(m string) bool { return common[m] == len(hosts) }
	for _, l := range abiLevels {
		if shared(l) {
			return l
		}
	}
	first := hosts[0].Usable
	for i := len(first) - 1; i >= 0; i-- {
		if shared(first[i]) {
			return first[i]
		}
	}
	return ""
}

func (m *Manager) findCluster(ctx context.Context, id string) (*stored, error) {
	if m.Backend == nil {
		return nil, ErrNotFound
	}
	st, err := m.find(ctx, id)
	if err != nil {
		return nil, err
	}
	if st.cluster == nil {
		return nil, Problems{fmt.Sprintf("%s is on this server's own pool, not on cluster storage", st.spec.Name)}
	}
	return st, nil
}
