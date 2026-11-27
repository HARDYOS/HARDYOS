package vms

// "Make highly available" and "Make local again" (docs/plans/make-ha.md,
// decisions 480-486): what the VM engine checks and rewrites when a VM's
// storage moves between this server's pool and cluster storage. Copying
// the datasets is root's hacopy (outside this package, which stays free
// of the cluster); here are the VM's own rules: what may become a cluster
// VM, the approved settings' hash of the converted spec, letting go of a
// stopped VM before its datasets are parked, and the pool written into
// vm.json wherever it lands.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"regexp"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
	"github.com/hardyos/hardyos/daemon/internal/snapshots"
)

// Cluster storage's marks (san.PropRole, san.RoleCluster; repeated so
// this package stays free of the cluster).
const (
	propRole    = "org.hardyos:role"
	roleCluster = "cluster"
)

var poolRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.:-]{0,63}$`)

// HACheckArgs asks whether a local VM can move to cluster storage.
type HACheckArgs struct {
	ID string `json:"id"`
	// Pool is the storage server's pool (it goes into vm.json).
	Pool string `json:"pool"`
	// CPUModel, with SetCPU, becomes the VM's CPU model (the cluster's
	// baseline, or "" for the host's own CPU).
	SetCPU   bool   `json:"setCPU,omitempty"`
	CPUModel string `json:"cpuModel,omitempty"`
}

// HADisk is one of the VM's disks.
type HADisk struct {
	Name   string `json:"name"`
	SizeGB int    `json:"sizeGB"`
}

// HACheckResult is what the conversion needs to know.
type HACheckResult struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	LocalPool string `json:"localPool"`
	State     string `json:"state"`
	MemoryMB  int    `json:"memoryMB"`
	VCPUs     int    `json:"vcpus"`
	// CPUModel is the converted spec's CPU model ("" host-passthrough).
	CPUModel string   `json:"cpuModel"`
	Disks    []HADisk `json:"disks"`
	// Hash is the approved settings' hash of the converted spec: what
	// workload.add records and the cluster checks at every start.
	Hash string `json:"hash"`
	// Problems are why it can't be converted now (empty: it can).
	Problems []string `json:"problems"`
}

// converted is a cluster copy of a local VM's spec.
func converted(s Spec, a HACheckArgs) Spec {
	c := s
	c.Pool = a.Pool
	if a.SetCPU {
		c.CPUModel = a.CPUModel
	}
	return c
}

// HACheck says whether a local VM can become a cluster VM, and the hash
// of its settings once it is one.
func (m *Manager) HACheck(ctx context.Context, a HACheckArgs) (*HACheckResult, error) {
	if err := ValidID(a.ID); err != nil {
		return nil, ErrNotFound
	}
	if !poolRE.MatchString(a.Pool) {
		return nil, Problems{fmt.Sprintf("%q isn't a pool name", a.Pool)}
	}
	if a.SetCPU && a.CPUModel != "" && !cpuModelRE.MatchString(a.CPUModel) {
		return nil, Problems{fmt.Sprintf("%q isn't a CPU model", a.CPUModel)}
	}
	st, err := m.find(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	s := st.spec
	res := &HACheckResult{ID: s.ID, Name: s.Name, LocalPool: s.Pool, State: m.state(ctx, s.ID), MemoryMB: s.Memory.MB,
		VCPUs: s.CPU.VCPUs(), Disks: []HADisk{}, Problems: []string{}}
	if st.cluster != nil {
		res.Problems = append(res.Problems, s.Name+" is on cluster storage already")
		return res, nil
	}
	if len(s.Devices) > 0 {
		res.Problems = append(res.Problems, "it has passthrough devices, which keep it on this server (remove them in Hardware first)")
	}
	if files := s.Files(); len(files) > 0 {
		res.Problems = append(res.Problems, "it uses discs from this server's ISO library ("+strings.Join(files, ", ")+"); take them out first")
	}
	if s.InstallPending() {
		res.Problems = append(res.Problems, "its Windows install isn't finished yet")
	}
	for _, d := range s.Disks {
		res.Disks = append(res.Disks, HADisk{Name: d.Name, SizeGB: d.SizeGB})
	}
	if len(res.Disks) == 0 {
		res.Problems = append(res.Problems, "it has no disks")
	}
	c := converted(s, a)
	res.CPUModel = c.CPUModel
	if err := m.checkStored(&c); err != nil {
		res.Problems = append(res.Problems, "its settings wouldn't be valid on cluster storage: "+err.Error())
	}
	if res.Hash, err = SpecHash(&c); err != nil {
		return nil, err
	}
	return res, nil
}

// HARelease lets go of a stopped local VM (its libvirt definition, kept
// firmware variables and TPM state stay in its dataset) and runs park,
// which moves its datasets away, under the VM's lock. If park fails the
// VM is defined again as it was.
func (m *Manager) HARelease(ctx context.Context, id string, park func() error) error {
	unlock, err := m.lockValid(id)
	if err != nil {
		return err
	}
	defer unlock()
	st, err := m.find(ctx, id)
	if err != nil {
		return err
	}
	if st.cluster != nil {
		return Problems{st.spec.Name + " is on cluster storage"}
	}
	if s := m.state(ctx, id); s != "stopped" && s != "crashed" {
		return Problems{fmt.Sprintf("%s is %s; it must be shut down first", st.spec.Name, s)}
	}
	if len(st.spec.Devices) > 0 {
		return Problems{st.spec.Name + " has passthrough devices"}
	}
	if err := m.undefineKeep(ctx, id); err != nil {
		return err
	}
	m.setRunning(id, false)
	if err := park(); err != nil {
		if derr := m.define(context.WithoutCancel(ctx), st, nil); derr != nil {
			m.log().Error("vms: defining a VM again after parking failed", "id", id, "err", derr)
		}
		return err
	}
	m.kickStreaming()
	m.log().Warn("vms: let go of a VM whose storage moves", "id", id)
	return nil
}

// undefineKeep removes a domain's definition, keeping its firmware
// variables and TPM state (they are files in its dataset, which moves).
func (m *Manager) undefineKeep(ctx context.Context, id string) error {
	var last error
	for _, flags := range [][]string{{"--keep-nvram", "--keep-tpm"}, {"--keep-nvram"}, nil} {
		_, err := m.virsh(ctx, append([]string{"undefine", id}, flags...)...)
		if err == nil || notDefined(err) {
			return nil
		}
		last = err
	}
	return fmt.Errorf("removing %s's definition: %w", id, last)
}

// HAPutBack defines a local VM again after its parked datasets were put
// back (an undone conversion).
func (m *Manager) HAPutBack(ctx context.Context, id string) error {
	unlock, err := m.lockValid(id)
	if err != nil {
		return err
	}
	defer unlock()
	st, err := m.find(ctx, id)
	if err != nil {
		return err
	}
	if st.cluster != nil {
		return Problems{st.spec.Name + " is on cluster storage"}
	}
	return m.define(ctx, st, nil)
}

// ClusterAdoptArgs rewrites a newly converted cluster VM's vm.json on the
// cluster storage attached here.
type ClusterAdoptArgs struct {
	HACheckArgs
	// Hash is the hash workload.add recorded: the rewritten spec must hash
	// the same, or nothing is written.
	Hash string `json:"hash"`
}

// ClusterAdopt writes the storage server's pool (and the chosen CPU
// model) into a converted VM's spec on cluster storage, only when the
// result is the spec whose hash the cluster recorded.
func (m *Manager) ClusterAdopt(ctx context.Context, a ClusterAdoptArgs) (string, error) {
	unlock, err := m.lockValid(a.ID)
	if err != nil {
		return "", err
	}
	defer unlock()
	if !poolRE.MatchString(a.Pool) || (a.SetCPU && a.CPUModel != "" && !cpuModelRE.MatchString(a.CPUModel)) {
		return "", Problems{"bad pool or CPU model"}
	}
	st, err := m.findCluster(ctx, a.ID)
	if err != nil {
		return "", err
	}
	c := converted(st.spec, a.HACheckArgs)
	if err := m.checkStored(&c); err != nil {
		return "", err
	}
	if err := checkSpecHash(&c, a.Hash); err != nil {
		return "", err
	}
	st.spec = c
	if err := m.saveSpec(st); err != nil {
		return "", err
	}
	m.log().Info("vms: converted VM's settings written on cluster storage", "id", a.ID, "pool", a.Pool)
	return a.Hash, nil
}

// HALocalSpec writes this server's pool into the vm.json of a VM that
// just came back from cluster storage (adopted at <pool>/vms/<id>), and
// defines it. Its spec still names the storage server's pool, so the
// engine doesn't list it until this runs.
func (m *Manager) HALocalSpec(ctx context.Context, id, pool string) error {
	unlock, err := m.lockValid(id)
	if err != nil {
		return err
	}
	defer unlock()
	if !poolRE.MatchString(pool) {
		return Problems{"bad pool"}
	}
	ds := Dataset(pool, id)
	st, err := m.mounted(ctx, ds)
	if err != nil {
		return err
	}
	path := filepath.Join(m.sys(st.dir), specFile)
	b, err := rootfile.ReadFile(path)
	if err != nil {
		return err
	}
	var s Spec
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("%s: %w", specFile, err)
	}
	if s.ID != id {
		return fmt.Errorf("%s describes %s, not %s", specFile, s.ID, id)
	}
	s.Pool = pool
	s.Normalize()
	if err := m.checkStored(&s); err != nil {
		return err
	}
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(path, append(out, '\n'), 0o600); err != nil {
		return err
	}
	st2, err := m.find(ctx, id)
	if err != nil {
		return err
	}
	if st2.cluster != nil {
		return errors.New("the VM is still attached from cluster storage here")
	}
	return m.define(ctx, st2, nil)
}

// ---- schedules of cluster VMs on the storage server ------------------------------

// ClusterSchedule is a cluster VM's snapshot schedule, read on the storage
// server from its state dataset (decision 485).
type ClusterSchedule struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Pool     string    `json:"pool"`
	Schedule *Schedule `json:"schedule"`
}

// ClusterSchedules lists the schedules of the cluster VMs whose datasets
// are on this server's pools (org.hardyos:role=cluster).
func (m *Manager) ClusterSchedules(ctx context.Context) ([]ClusterSchedule, error) {
	out, err := m.zfs(ctx, "list", "-H", "-p", "-t", "filesystem", "-o", "name,mountpoint,mounted,"+PropVM+","+propRole)
	if err != nil {
		return nil, err
	}
	res := []ClusterSchedule{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 5 || f[4] != roleCluster || f[2] != "yes" || ValidID(f[3]) != nil {
			continue
		}
		pool, _, _ := strings.Cut(f[0], "/")
		if f[0] != Dataset(pool, f[3]) || !filepath.IsAbs(f[1]) || filepath.Clean(f[1]) != f[1] {
			continue
		}
		b, err := rootfile.ReadFile(filepath.Join(m.sys(f[1]), specFile))
		if err != nil {
			continue
		}
		var s struct {
			ID       string    `json:"id"`
			Name     string    `json:"name"`
			Schedule *Schedule `json:"schedule"`
		}
		if json.Unmarshal(b, &s) != nil || s.ID != f[3] || s.Schedule.Off() || len(s.Schedule.problems()) > 0 {
			continue
		}
		res = append(res, ClusterSchedule{ID: s.ID, Name: s.Name, Pool: pool, Schedule: s.Schedule})
	}
	return res, nil
}

// ScheduleStep says, for a schedule and the names of the snapshots a VM
// has, which automatic snapshots are due at now and which ones it keeps no
// longer once they are taken (the storage server's scheduler for cluster
// VMs runs the same rules as TickSchedules).
func ScheduleStep(sc *Schedule, have []string, now time.Time) (due, prune []string) {
	if sc.Off() {
		return nil, nil
	}
	seen := map[string]bool{}
	l := make([]Snapshot, 0, len(have))
	for _, n := range have {
		seen[n] = true
		l = append(l, Snapshot{Name: n})
	}
	for _, k := range snapshots.Kinds {
		if sc.keep(k) <= 0 {
			continue
		}
		if name := AutoSnapName(k, now.UTC()); !seen[name] {
			due = append(due, name)
			seen[name] = true
			l = append(l, Snapshot{Name: name})
		}
	}
	return due, pruneAuto(l, sc)
}

// ---- unattended installs that end on a cluster VM ------------------------------

// InstallDone is root's own change of a cluster VM's spec at the end of an
// unattended install: hardyd records exactly that change as approved
// (decision 486).
type InstallDone struct {
	ID     string `json:"id"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// InstalledArgs is vms.cluster.installed: Ack forgets the ids hardyd
// handled.
type InstalledArgs struct {
	Ack []string `json:"ack,omitempty"`
}

// ClusterInstalled lists cluster VMs whose install ended here, forgetting
// the acknowledged ones.
func (m *Manager) ClusterInstalled(a InstalledArgs) []InstallDone {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	for _, id := range a.Ack {
		delete(m.installDone, id)
	}
	out := []InstallDone{}
	for _, d := range m.installDone {
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b InstallDone) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func (m *Manager) recordInstallDone(id, before, after string) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	if m.installDone == nil {
		m.installDone = map[string]InstallDone{}
	}
	m.installDone[id] = InstallDone{ID: id, Before: before, After: after}
}
