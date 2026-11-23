package san

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
)

// Resolved is what root found out about a backstore's zvol itself.
type Resolved struct {
	// Device is /dev/zvol/<dataset>.
	Device string `json:"device"`
	// GUID is the zvol's ZFS GUID; Serial and WWN derive from it.
	GUID   string `json:"guid"`
	Serial string `json:"serial"`
	WWN    string `json:"wwn"`
	// WriteCache: the zvol's sync property isn't "always", so the LUN
	// reports a volatile write cache and initiators send flushes.
	WriteCache bool `json:"writeCache"`
}

// Plan is everything Reconcile needs: the validated desired state, what
// root resolved for each backstore, and each node's CHAP secrets.
type Plan struct {
	Desired  Desired
	Resolved map[string]Resolved
	CHAP     map[cluster.NodeID]Secrets
	// Discovery is the random credential that keeps SendTargets discovery
	// closed (compute nodes never discover: they are told their target).
	Discovery Secrets
}

func hbaDir() string { return fmt.Sprintf("core/iblock_%d", HBA) }

// tpgDir is a target's portal group.
func tpgDir(iqn string) string { return "iscsi/" + iqn + "/tpgt_" + strconv.Itoa(TPGTag) }

// Reconcile makes LIO match p. It is idempotent: run at boot (from root's
// saved state) and on every change. Fenced targets are disabled before
// anything else, so a fence takes effect even if a later step fails.
func Reconcile(fsys FS, p Plan) error {
	d := p.Desired
	if err := d.Validate(); err != nil {
		return err
	}
	for _, b := range d.Backstores {
		if r, ok := p.Resolved[b.Name]; !ok || r.Device == "" || !serialRE.MatchString(r.Serial) {
			return fmt.Errorf("backstore %s wasn't resolved", b.Name)
		}
	}
	for _, t := range d.Targets {
		if _, ok := p.CHAP[t.Node]; !ok {
			return fmt.Errorf("no CHAP secrets for %s", t.Node)
		}
	}
	if !fsys.Exists("core") {
		return errors.New("LIO isn't loaded (no core in configfs)")
	}
	if !fsys.Exists("iscsi") {
		// mkdir of the fabric group loads iscsi_target_mod.
		if err := fsys.Mkdir("iscsi"); err != nil && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("loading the iSCSI target: %w", err)
		}
	}
	// 1. Fences first.
	for _, t := range d.Targets {
		tpg := tpgDir(TargetIQN(d.Cluster, t.Node))
		if !t.Enabled && fsys.Exists(tpg) {
			if err := setAttr(fsys, tpg+"/enable", "0"); err != nil {
				return fmt.Errorf("disabling %s's target: %w", t.Node, err)
			}
		}
	}
	// 2. Targets that shouldn't exist (removed nodes, other clusters'
	// HardyOS targets).
	want := map[string]Target{}
	for _, t := range d.Targets {
		want[TargetIQN(d.Cluster, t.Node)] = t
	}
	ents, err := fsys.List("iscsi")
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range ents {
		if !e.Dir || !strings.HasPrefix(e.Name, cluster.IQNPrefix+".") {
			continue
		}
		if _, ok := want[e.Name]; !ok {
			if err := teardownTarget(fsys, e.Name); err != nil {
				errs = append(errs, err)
			}
		}
	}
	// 3. Backstores (created or re-created when the device or serial
	// changed; LUNs pointing at a re-created one are removed first).
	hba := hbaDir()
	if !fsys.Exists(hba) {
		if err := fsys.Mkdir(hba); err != nil {
			return fmt.Errorf("creating the HardyOS HBA: %w", err)
		}
	}
	for _, b := range d.Backstores {
		if err := ensureBackstore(fsys, d, b, p.Resolved[b.Name]); err != nil {
			errs = append(errs, err)
		}
	}
	// 4. Targets.
	for _, t := range d.Targets {
		if err := ensureTarget(fsys, d, t, p.CHAP[t.Node]); err != nil {
			errs = append(errs, fmt.Errorf("%s's target: %w", t.Node, err))
		}
	}
	// 5. Backstores nobody wants.
	keep := map[string]bool{}
	for _, b := range d.Backstores {
		keep[b.Name] = true
	}
	if bes, err := fsys.List(hba); err == nil {
		for _, e := range bes {
			if e.Dir && !keep[e.Name] {
				if err := removeBackstore(fsys, e.Name); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	// 6. Discovery stays closed.
	if fsys.Exists("iscsi/discovery_auth") {
		if v, _ := fsys.Read("iscsi/discovery_auth/userid"); v != p.Discovery.User && p.Discovery.User != "" {
			if err := setAttr(fsys, "iscsi/discovery_auth/userid", p.Discovery.User); err != nil {
				errs = append(errs, err)
			} else if err := setAttr(fsys, "iscsi/discovery_auth/password", p.Discovery.Password); err != nil {
				errs = append(errs, err)
			}
		}
		if err := setAttr(fsys, "iscsi/discovery_auth/enforce_discovery_auth", "1"); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// setAttr writes an attribute when its value differs.
func setAttr(fsys FS, p, v string) error {
	if cur, err := fsys.Read(p); err == nil && cur == v {
		return nil
	}
	return fsys.Write(p, v)
}

func boolAttr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func ensureBackstore(fsys FS, d Desired, b Backstore, r Resolved) error {
	dir := hbaDir() + "/" + b.Name
	if fsys.Exists(dir) {
		dev, _ := fsys.Read(dir + "/udev_path")
		serial, _ := fsys.Read(dir + "/wwn/vpd_unit_serial")
		serial = strings.TrimPrefix(serial, "T10 VPD Unit Serial Number: ")
		if dev == r.Device && serial == r.Serial {
			return setBackstoreAttrs(fsys, dir, b, r)
		}
		if err := unmapEverywhere(fsys, dir); err != nil {
			return err
		}
		if err := removeBackstore(fsys, b.Name); err != nil {
			return err
		}
	}
	if err := fsys.Mkdir(dir); err != nil {
		return fmt.Errorf("backstore %s: %w", b.Name, err)
	}
	steps := []struct{ p, v string }{
		{dir + "/control", "udev_path=" + r.Device},
		{dir + "/udev_path", r.Device},
		{dir + "/enable", "1"},
		{dir + "/wwn/vpd_unit_serial", r.Serial},
	}
	for _, s := range steps {
		if s.p == dir+"/udev_path" && !fsys.Exists(s.p) {
			continue
		}
		if err := fsys.Write(s.p, s.v); err != nil {
			if s.p == dir+"/udev_path" {
				continue // informational on some kernels
			}
			_ = fsys.Rmdir(dir)
			return fmt.Errorf("backstore %s: %w", b.Name, err)
		}
	}
	return setBackstoreAttrs(fsys, dir, b, r)
}

func setBackstoreAttrs(fsys FS, dir string, b Backstore, r Resolved) error {
	for _, a := range []struct{ n, v string }{
		{"emulate_tpu", "1"}, // discard -> zvol frees the blocks
		{"is_nonrot", boolAttr(b.NonRot)},
	} {
		if err := setAttr(fsys, dir+"/attrib/"+a.n, a.v); err != nil {
			return fmt.Errorf("backstore %s: %s: %w", b.Name, a.n, err)
		}
	}
	// iblock backstores report the block device's own write cache (the
	// kernel refuses emulate_write_cache=1 with EINVAL when the backend has
	// one, as iblock does): a zvol announces its cache itself and honours
	// flushes. The attribute is set only where the kernel lets it be.
	_ = setAttr(fsys, dir+"/attrib/emulate_write_cache", boolAttr(r.WriteCache))
	return nil
}

// removeBackstore removes a backstore of HardyOS's HBA (nothing may link to
// it any more).
func removeBackstore(fsys FS, name string) error {
	if err := ValidBackstoreName(name); err != nil {
		return nil // not ours; never touched
	}
	if err := fsys.Rmdir(hbaDir() + "/" + name); err != nil {
		return fmt.Errorf("removing backstore %s: %w", name, err)
	}
	return nil
}

// unmapEverywhere removes every HardyOS LUN that points at a backstore.
func unmapEverywhere(fsys FS, bsDir string) error {
	ents, err := fsys.List("iscsi")
	if err != nil {
		return err
	}
	for _, e := range ents {
		if !e.Dir || !strings.HasPrefix(e.Name, cluster.IQNPrefix+".") {
			continue
		}
		tpg := tpgDir(e.Name)
		luns, _ := tpgLUNs(fsys, tpg)
		for n, target := range luns {
			if target == bsDir {
				if err := removeLUN(fsys, tpg, n); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// tpgLUNs maps a TPG's LUN numbers to the backstore directory each links.
func tpgLUNs(fsys FS, tpg string) (map[int]string, error) {
	out := map[int]string{}
	ents, err := fsys.List(tpg + "/lun")
	if err != nil {
		return out, err
	}
	for _, e := range ents {
		n, ok := lunNumber(e.Name)
		if !e.Dir || !ok {
			continue
		}
		out[n] = ""
		inner, _ := fsys.List(tpg + "/lun/" + e.Name)
		for _, i := range inner {
			if i.Link {
				t, err := fsys.Readlink(tpg + "/lun/" + e.Name + "/" + i.Name)
				if err == nil {
					out[n] = t
				}
			}
		}
	}
	return out, nil
}

func lunNumber(name string) (int, bool) {
	s, ok := strings.CutPrefix(name, "lun_")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil && n >= 0 && n < 16384
}

// removeLUN takes a LUN out of every ACL of the TPG, then out of the TPG.
func removeLUN(fsys FS, tpg string, n int) error {
	lun := fmt.Sprintf("%s/lun/lun_%d", tpg, n)
	acls, _ := fsys.List(tpg + "/acls")
	for _, a := range acls {
		if !a.Dir {
			continue
		}
		mapped, _ := fsys.List(tpg + "/acls/" + a.Name)
		for _, m := range mapped {
			if _, ok := lunNumber(m.Name); !ok || !m.Dir {
				continue
			}
			mdir := tpg + "/acls/" + a.Name + "/" + m.Name
			inner, _ := fsys.List(mdir)
			points := false
			for _, i := range inner {
				if i.Link {
					if t, _ := fsys.Readlink(mdir + "/" + i.Name); t == lun {
						points = true
						if err := fsys.Unlink(mdir + "/" + i.Name); err != nil {
							return err
						}
					}
				}
			}
			if points {
				if err := fsys.Rmdir(mdir); err != nil {
					return err
				}
			}
		}
	}
	inner, _ := fsys.List(lun)
	for _, i := range inner {
		if i.Link {
			if err := fsys.Unlink(lun + "/" + i.Name); err != nil {
				return err
			}
		}
	}
	return fsys.Rmdir(lun)
}

func teardownTarget(fsys FS, iqn string) error {
	tdir := "iscsi/" + iqn
	tpgs, err := fsys.List(tdir)
	if err != nil {
		return err
	}
	for _, t := range tpgs {
		if !t.Dir || !strings.HasPrefix(t.Name, "tpgt_") {
			continue
		}
		tpg := tdir + "/" + t.Name
		_ = setAttr(fsys, tpg+"/enable", "0")
		luns, _ := tpgLUNs(fsys, tpg)
		for n := range luns {
			if err := removeLUN(fsys, tpg, n); err != nil {
				return fmt.Errorf("removing %s: %w", iqn, err)
			}
		}
		if err := removeChildren(fsys, tpg+"/acls"); err != nil {
			return fmt.Errorf("removing %s: %w", iqn, err)
		}
		if err := removeChildren(fsys, tpg+"/np"); err != nil {
			return fmt.Errorf("removing %s: %w", iqn, err)
		}
		if err := fsys.Rmdir(tpg); err != nil {
			return fmt.Errorf("removing %s: %w", iqn, err)
		}
	}
	if err := fsys.Rmdir(tdir); err != nil {
		return fmt.Errorf("removing %s: %w", iqn, err)
	}
	return nil
}

// removeChildren removes the user-made directories under dir (ACLs with
// their mapped LUNs, portals).
func removeChildren(fsys FS, dir string) error {
	ents, err := fsys.List(dir)
	if err != nil {
		return nil
	}
	for _, e := range ents {
		if !e.Dir {
			continue
		}
		sub := dir + "/" + e.Name
		inner, _ := fsys.List(sub)
		for _, i := range inner {
			if _, ok := lunNumber(i.Name); ok && i.Dir {
				in2, _ := fsys.List(sub + "/" + i.Name)
				for _, l := range in2 {
					if l.Link {
						_ = fsys.Unlink(sub + "/" + i.Name + "/" + l.Name)
					}
				}
				if err := fsys.Rmdir(sub + "/" + i.Name); err != nil {
					return err
				}
			}
		}
		if err := fsys.Rmdir(sub); err != nil {
			return err
		}
	}
	return nil
}

func ensureTarget(fsys FS, d Desired, t Target, chap Secrets) error {
	iqn := TargetIQN(d.Cluster, t.Node)
	init := InitiatorIQN(d.Cluster, t.Node)
	tdir := "iscsi/" + iqn
	tpg := tpgDir(iqn)
	for _, dir := range []string{tdir, tpg} {
		if !fsys.Exists(dir) {
			if err := fsys.Mkdir(dir); err != nil {
				return err
			}
		}
	}
	if !t.Enabled {
		if err := setAttr(fsys, tpg+"/enable", "0"); err != nil {
			return err
		}
	}
	for _, a := range []struct{ p, v string }{
		{tpg + "/attrib/authentication", "1"},
		{tpg + "/attrib/generate_node_acls", "0"},
		{tpg + "/attrib/cache_dynamic_acls", "0"},
		{tpg + "/attrib/demo_mode_write_protect", "1"},
		{tpg + "/param/AuthMethod", "CHAP"},
	} {
		if err := setAttr(fsys, a.p, a.v); err != nil {
			return err
		}
	}
	// Portals.
	wantNP := map[string]bool{}
	for _, p := range d.Portals {
		wantNP[portalDir(p)] = true
	}
	nps, _ := fsys.List(tpg + "/np")
	for _, e := range nps {
		if e.Dir && !wantNP[e.Name] {
			if err := fsys.Rmdir(tpg + "/np/" + e.Name); err != nil {
				return err
			}
		}
		delete(wantNP, e.Name)
	}
	for _, p := range d.Portals {
		if wantNP[portalDir(p)] {
			if err := fsys.Mkdir(tpg + "/np/" + portalDir(p)); err != nil {
				return fmt.Errorf("portal %s: %w", p, err)
			}
		}
	}
	// Exactly one ACL: the node's initiator.
	acls, _ := fsys.List(tpg + "/acls")
	for _, a := range acls {
		if a.Dir && a.Name != init {
			if err := removeChildren(fsys, tpg+"/acls"); err != nil {
				return err
			}
			break
		}
	}
	acl := tpg + "/acls/" + init
	if !fsys.Exists(acl) {
		if err := fsys.Mkdir(acl); err != nil {
			return err
		}
	}
	// The kernel names an ACL's mutual CHAP attributes userid_mutual and
	// password_mutual (discovery_auth's are userid_mut and password_mut),
	// and sets the read-only authenticate_target once both are set.
	for _, a := range []struct{ n, v string }{
		{"userid", chap.User}, {"password", chap.Password},
		{"userid_mutual", chap.MutualUser}, {"password_mutual", chap.MutualPassword},
	} {
		if err := setAttr(fsys, acl+"/auth/"+a.n, a.v); err != nil {
			if errors.Is(err, fs.ErrNotExist) && strings.HasSuffix(a.n, "_mutual") {
				return fmt.Errorf("CHAP: this kernel's iSCSI target has no mutual CHAP for initiators (%s missing); HardyOS doesn't fall back to one-way CHAP", a.n)
			}
			return fmt.Errorf("CHAP: %w", err)
		}
	}
	if v, err := fsys.Read(acl + "/auth/authenticate_target"); err != nil || strings.TrimSpace(v) != "1" {
		return fmt.Errorf("CHAP: the kernel didn't turn on mutual authentication for %s (authenticate_target %q)", init, strings.TrimSpace(v))
	}
	// LUNs.
	cur, err := tpgLUNs(fsys, tpg)
	if err != nil {
		return err
	}
	wantLUN := map[string]bool{}
	if t.Enabled {
		for _, l := range t.LUNs {
			wantLUN[hbaDir()+"/"+l] = true
		}
	}
	have := map[string]int{}
	nums := make([]int, 0, len(cur))
	for n := range cur {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	for _, n := range nums {
		target := cur[n]
		if !wantLUN[target] {
			if err := removeLUN(fsys, tpg, n); err != nil {
				return err
			}
			delete(cur, n)
			continue
		}
		have[target] = n
	}
	names := slices.Clone(t.LUNs)
	slices.Sort(names)
	for _, l := range names {
		if !t.Enabled {
			break
		}
		bs := hbaDir() + "/" + l
		n, ok := have[bs]
		if !ok {
			n = 0
			for {
				if _, used := cur[n]; !used {
					break
				}
				n++
			}
			lun := fmt.Sprintf("%s/lun/lun_%d", tpg, n)
			if err := fsys.Mkdir(lun); err != nil {
				return err
			}
			if err := fsys.Symlink(bs, lun+"/"+l); err != nil {
				_ = fsys.Rmdir(lun)
				return fmt.Errorf("mapping %s: %w", l, err)
			}
			cur[n] = bs
		}
		// The ACL's mapped LUN (same number).
		mdir := fmt.Sprintf("%s/lun_%d", acl, n)
		if !fsys.Exists(mdir) {
			if err := fsys.Mkdir(mdir); err != nil {
				return err
			}
		}
		if !fsys.Exists(mdir + "/map") {
			if err := fsys.Symlink(fmt.Sprintf("%s/lun/lun_%d", tpg, n), mdir+"/map"); err != nil {
				return fmt.Errorf("mapping %s for the initiator: %w", l, err)
			}
		}
	}
	if t.Enabled {
		return setAttr(fsys, tpg+"/enable", "1")
	}
	return nil
}

// Sessions counts the logged-in sessions of each HardyOS target of cluster
// c (from each ACL's info).
func Sessions(fsys FS, c cluster.ClusterID) map[cluster.NodeID]int {
	out := map[cluster.NodeID]int{}
	ents, err := fsys.List("iscsi")
	if err != nil {
		return out
	}
	for _, e := range ents {
		node, ok := NodeOfTarget(c, e.Name)
		if !ok {
			continue
		}
		acl := tpgDir(e.Name) + "/acls/" + InitiatorIQN(c, node) + "/info"
		info, err := fsys.Read(acl)
		if err != nil {
			continue
		}
		out[node] = strings.Count(info, "LIO Session ID:")
	}
	return out
}

// Current reads which backstores are mapped into which node's target now,
// and whether each target is enabled (status and tests).
func Current(fsys FS, c cluster.ClusterID) map[cluster.NodeID]Target {
	out := map[cluster.NodeID]Target{}
	ents, err := fsys.List("iscsi")
	if err != nil {
		return out
	}
	for _, e := range ents {
		node, ok := NodeOfTarget(c, e.Name)
		if !ok {
			continue
		}
		tpg := tpgDir(e.Name)
		en, _ := fsys.Read(tpg + "/enable")
		t := Target{Node: node, Enabled: en == "1", LUNs: []string{}}
		luns, _ := tpgLUNs(fsys, tpg)
		for _, bs := range luns {
			if bs != "" {
				t.LUNs = append(t.LUNs, path.Base(bs))
			}
		}
		slices.Sort(t.LUNs)
		out[node] = t
	}
	return out
}
