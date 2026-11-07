package sanclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/cluster"
	"github.com/hardyos/hardyos/daemon/internal/cluster/san"
	"github.com/hardyos/hardyos/daemon/internal/nfs"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// NFSMountOptions are the options of every cluster NFS mount: NFSv4.2,
// hard (never silently fail writes), long timeouts, several connections,
// and no setuid binaries or device files from the storage node.
const NFSMountOptions = "vers=4.2,hard,proto=tcp,timeo=600,retrans=2,nconnect=4,nosuid,nodev"

// Record is one workload's attachment (cluster.Attachment plus what root
// needs to undo it).
type Record struct {
	cluster.Attachment
	// Mounts are this workload's mount points, innermost last.
	Mounts []string `json:"mounts"`
	// WWNs of its LUNs (to remove the SCSI devices on detach).
	WWNs []string `json:"wwns,omitempty"`
	// Dataset is its dataset on the storage node.
	Dataset string `json:"dataset"`
	// Mode is an app's data mode.
	Mode cluster.StorageMode `json:"mode,omitempty"`
	At   time.Time           `json:"at"`
}

// ShareMount is a cluster shared folder mounted here.
type ShareMount struct {
	ID        string `json:"id"`
	Dataset   string `json:"dataset"`
	MountPath string `json:"mountPath"`
}

// Records is the attachment file (/run/hardyos/cluster/attached.json):
// root writes it, the engines' storage backends read it. It is in /run,
// so a reboot starts with nothing attached, as iSCSI does.
type Records struct {
	Workloads map[string]Record     `json:"workloads"`
	Shares    map[string]ShareMount `json:"shares"`
}

func recordKey(w cluster.WorkloadRef) string { return string(w.Kind) + "/" + w.ID }

func (c *Client) loadRecords() (*Records, error) {
	r := &Records{Workloads: map[string]Record{}, Shares: map[string]ShareMount{}}
	b, err := rootfile.ReadFile(c.sys(AttachedFile))
	if errors.Is(err, fs.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, r); err != nil {
		return nil, fmt.Errorf("reading the attachments: %w", err)
	}
	if r.Workloads == nil {
		r.Workloads = map[string]Record{}
	}
	if r.Shares == nil {
		r.Shares = map[string]ShareMount{}
	}
	return r, nil
}

func (c *Client) saveRecords(r *Records) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	p := c.sys(AttachedFile)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return rootfile.WriteAtomic(p, b, 0o644)
}

// MountPath is where a dataset of the storage node is mounted here:
// RemoteMountRoot/<pool>/{vms,apps,shares}/<id>.
func MountPath(dataset string) (string, error) {
	parts := strings.Split(dataset, "/")
	if len(parts) != 3 || !poolRE.MatchString(parts[0]) {
		return "", bad("%q isn't a cluster dataset", dataset)
	}
	switch parts[1] {
	case "vms", "apps":
		if !idRE.MatchString(parts[2]) {
			return "", bad("%q isn't a cluster dataset", dataset)
		}
	case "shares":
		if !shRE.MatchString(parts[2]) {
			return "", bad("%q isn't a cluster dataset", dataset)
		}
	default:
		return "", bad("%q isn't a cluster dataset", dataset)
	}
	return cluster.RemoteMountRoot + "/" + dataset, nil
}

// MountArgs is sanclient.nfs.mount.
type MountArgs struct {
	// Server is the storage node's storage address; Interface this node's
	// storage interface (route-checked).
	Server    netip.Addr `json:"server"`
	Interface string     `json:"interface"`
	// Dataset is <pool>/{vms,apps,shares}/<id>; ExportPath its path on the
	// storage node.
	Dataset    string `json:"dataset"`
	ExportPath string `json:"exportPath"`
	// NoExec for VM state.
	NoExec bool `json:"noExec,omitempty"`
	// Share records the mount as a cluster share (id).
	Share string `json:"share,omitempty"`
}

// MountNFS mounts one export at its fixed place (idempotent).
func (c *Client) MountNFS(ctx context.Context, a MountArgs) (string, error) {
	mp, err := MountPath(a.Dataset)
	if err != nil {
		return "", err
	}
	if err := nfs.ValidPath(a.ExportPath); err != nil {
		return "", &ValidationError{err}
	}
	if err := c.RouteCheck(ctx, a.Interface, a.Server); err != nil {
		return "", err
	}
	if a.Share != "" && (!shRE.MatchString(a.Share) || !strings.HasSuffix(a.Dataset, "/shares/"+a.Share)) {
		return "", bad("share %q doesn't match %s", a.Share, a.Dataset)
	}
	if c.mounted(mp) {
		if a.Share != "" {
			if err := c.recordShare(a.Share, a.Dataset, mp); err != nil {
				return "", err
			}
		}
		return mp, nil
	}
	if err := os.MkdirAll(c.sys(mp), 0o755); err != nil {
		return "", err
	}
	opts := NFSMountOptions
	if a.NoExec {
		opts += ",noexec"
	}
	if _, err := c.run(ctx, "mount", "-t", "nfs4", "-o", opts, a.Server.String()+":"+a.ExportPath, mp); err != nil {
		return "", fmt.Errorf("mounting %s: %w", a.Dataset, err)
	}
	if a.Share != "" {
		if err := c.recordShare(a.Share, a.Dataset, mp); err != nil {
			return "", err
		}
	}
	return mp, nil
}

func (c *Client) recordShare(id, ds, mp string) error {
	c.recsMu.Lock()
	defer c.recsMu.Unlock()
	r, err := c.loadRecords()
	if err != nil {
		return err
	}
	r.Shares[id] = ShareMount{ID: id, Dataset: ds, MountPath: mp}
	return c.saveRecords(r)
}

// UmountArgs is sanclient.nfs.umount.
type UmountArgs struct {
	Dataset string `json:"dataset"`
	// Force: lazy, forced unmount (self-fencing, a lost storage node).
	Force bool   `json:"force,omitempty"`
	Share string `json:"share,omitempty"`
}

// Umount unmounts one dataset's mount.
func (c *Client) Umount(ctx context.Context, a UmountArgs) error {
	mp, err := MountPath(a.Dataset)
	if err != nil {
		return err
	}
	if err := c.umount(ctx, mp, a.Force); err != nil {
		return err
	}
	if a.Share != "" {
		c.recsMu.Lock()
		defer c.recsMu.Unlock()
		r, err := c.loadRecords()
		if err != nil {
			return err
		}
		delete(r.Shares, a.Share)
		return c.saveRecords(r)
	}
	return nil
}

func (c *Client) umount(ctx context.Context, mp string, force bool) error {
	if !c.mounted(mp) {
		return nil
	}
	args := []string{mp}
	if force {
		args = []string{"-f", "-l", mp}
	}
	if _, err := c.run(ctx, "umount", args...); err != nil {
		return fmt.Errorf("unmounting %s: %w", mp, err)
	}
	return nil
}

// mounted reads /proc/self/mountinfo for an exact mount point.
func (c *Client) mounted(mp string) bool {
	return slices.Contains(c.allMounts(), mp)
}

func (c *Client) allMounts() []string {
	b, err := os.ReadFile(c.sys("/proc/self/mountinfo"))
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) > 4 {
			out = append(out, strings.ReplaceAll(f[4], `\040`, " "))
		}
	}
	return out
}

func (c *Client) clusterMounts() []string {
	out := []string{}
	for _, m := range c.allMounts() {
		if strings.HasPrefix(m, cluster.RemoteMountRoot+"/") {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

func (c *Client) exists(p string) bool {
	_, err := os.Stat(c.sys(p))
	return err == nil
}

// answers stats a folder with a deadline (a hard NFS mount of a lost
// server blocks forever; the goroutine is left behind then, once).
func (c *Client) answers(p string, d time.Duration) bool {
	done := make(chan bool, 1)
	go func() {
		_, err := os.Stat(c.sys(p))
		done <- err == nil
	}()
	select {
	case ok := <-done:
		return ok
	case <-time.After(d):
		return false
	}
}

// AttachArgs is sanclient.attach: after hardyd logged in (or rescanned),
// wait for the workload's LUNs, mount its state or data, and record the
// attachment for the engines.
type AttachArgs struct {
	Workload   cluster.WorkloadRef     `json:"workload"`
	Generation uint64                  `json:"generation"`
	Storage    cluster.WorkloadStorage `json:"storage"`
	Server     netip.Addr              `json:"server"`
	Interface  string                  `json:"interface"`
	Multipath  bool                    `json:"multipath,omitempty"`
	// GrowFS grows a block volume's file system to the LUN's size.
	GrowFS bool `json:"growFS,omitempty"`
}

// Attach makes a workload's storage usable here and records it.
func (c *Client) Attach(ctx context.Context, a AttachArgs) (*Record, error) {
	w := a.Workload
	if !idRE.MatchString(w.ID) || (w.Kind != cluster.KindVM && w.Kind != cluster.KindApp) {
		return nil, bad("workload %s/%s isn't valid", w.Kind, w.ID)
	}
	if !poolRE.MatchString(a.Storage.Pool) {
		return nil, bad("pool %q isn't valid", a.Storage.Pool)
	}
	rec := Record{Attachment: cluster.Attachment{Workload: w, Generation: a.Generation, Disks: map[string]string{}, Multipath: a.Multipath},
		Mode: a.Storage.Mode, At: time.Now().UTC()}
	if w.Kind == cluster.KindVM {
		rec.Dataset = a.Storage.Pool + "/vms/" + w.ID
	} else {
		rec.Dataset = a.Storage.Pool + "/apps/" + w.ID
	}
	// LUNs.
	for _, v := range a.Storage.Volumes {
		wantDS := san.VMDisk(a.Storage.Pool, w.ID, v.Disk)
		if w.Kind == cluster.KindApp {
			wantDS = san.AppBlock(a.Storage.Pool, w.ID)
		}
		if v.Dataset != wantDS || (w.Kind == cluster.KindVM && !diskRE.MatchString(v.Disk)) {
			return nil, bad("volume %q isn't %s's", v.Dataset, w.ID)
		}
		if !wwnRE.MatchString(v.WWN) {
			return nil, bad("volume %s has no valid WWN", v.Dataset)
		}
		dev, err := c.waitLUN(ctx, v.WWN, a.Multipath)
		if err != nil {
			return nil, err
		}
		rec.Disks[v.Disk] = dev
		rec.WWNs = append(rec.WWNs, v.WWN)
	}
	mp, err := MountPath(rec.Dataset)
	if err != nil {
		return nil, err
	}
	switch {
	case w.Kind == cluster.KindApp && a.Storage.Mode == cluster.StorageBlock:
		dev := rec.Disks["block"]
		if dev == "" {
			return nil, bad("an app in block mode needs its block volume")
		}
		if a.Storage.BlockFS != san.BlockExt4 && a.Storage.BlockFS != san.BlockXFS {
			return nil, bad("block file system %q isn't ext4 or xfs", a.Storage.BlockFS)
		}
		if !c.mounted(mp) {
			if err := os.MkdirAll(c.sys(mp), 0o755); err != nil {
				return nil, err
			}
			if _, err := c.run(ctx, "mount", "-t", a.Storage.BlockFS, "-o", "nosuid,nodev,noatime", dev, mp); err != nil {
				return nil, fmt.Errorf("mounting %s's block volume: %w", w.ID, err)
			}
		}
		if a.GrowFS {
			if a.Storage.BlockFS == san.BlockExt4 {
				_, err = c.run(ctx, "resize2fs", dev)
			} else {
				_, err = c.run(ctx, "xfs_growfs", mp)
			}
			if err != nil {
				c.log().Warn("sanclient: growing the block volume's file system", "app", w.ID, "err", err)
			}
		}
		rec.Mounts = append(rec.Mounts, mp)
		rec.StateDir = mp
	default:
		var exp *cluster.Export
		for i := range a.Storage.Exports {
			e := a.Storage.Exports[i]
			if e.Dataset == rec.Dataset {
				exp = &e
			}
		}
		if exp == nil {
			return nil, bad("%s has no export of %s", w.ID, rec.Dataset)
		}
		if _, err := c.MountNFS(ctx, MountArgs{Server: a.Server, Interface: a.Interface, Dataset: exp.Dataset,
			ExportPath: exp.Path, NoExec: w.Kind == cluster.KindVM}); err != nil {
			return nil, err
		}
		rec.Mounts = append(rec.Mounts, mp)
		rec.StateDir = mp
	}
	c.recsMu.Lock()
	defer c.recsMu.Unlock()
	recs, err := c.loadRecords()
	if err != nil {
		return nil, err
	}
	recs.Workloads[recordKey(w)] = rec
	if err := c.saveRecords(recs); err != nil {
		return nil, err
	}
	c.log().Info("sanclient: attached", "workload", recordKey(w), "generation", a.Generation, "disks", len(rec.Disks))
	return &rec, nil
}

// waitLUN waits for a LUN's device by its WWN (never by LUN number).
func (c *Client) waitLUN(ctx context.Context, wwn string, multipath bool) (string, error) {
	dev := san.ByIDPath(wwn)
	if multipath {
		dev = "/dev/mapper/3" + wwn
	}
	wait := c.DeviceWait
	if wait == 0 {
		wait = 10 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		if c.exists(dev) {
			return dev, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("the disk %s didn't appear (is it granted to this server?)", wwn)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// DetachArgs is sanclient.detach.
type DetachArgs struct {
	Workload cluster.WorkloadRef `json:"workload"`
	Force    bool                `json:"force,omitempty"`
}

// Detach unmounts a workload's storage and removes its SCSI devices (the
// storage node unmaps them next). Force unmounts lazily and doesn't wait
// for a lost server.
func (c *Client) Detach(ctx context.Context, a DetachArgs) error {
	c.recsMu.Lock()
	defer c.recsMu.Unlock()
	recs, err := c.loadRecords()
	if err != nil {
		return err
	}
	rec, ok := recs.Workloads[recordKey(a.Workload)]
	if !ok {
		return nil
	}
	var errs []error
	for i := len(rec.Mounts) - 1; i >= 0; i-- {
		if !strings.HasPrefix(rec.Mounts[i], cluster.RemoteMountRoot+"/") {
			continue
		}
		if err := c.umount(ctx, rec.Mounts[i], a.Force); err != nil {
			errs = append(errs, err)
		}
	}
	for _, wwn := range rec.WWNs {
		if !wwnRE.MatchString(wwn) {
			continue
		}
		if rec.Multipath {
			if _, err := c.run(ctx, "multipath", "-f", "3"+wwn); err != nil && !a.Force {
				errs = append(errs, err)
			}
		}
		if err := c.deleteSCSI(wwn); err != nil && !a.Force {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 && !a.Force {
		return errors.Join(errs...)
	}
	delete(recs.Workloads, recordKey(a.Workload))
	if err := c.saveRecords(recs); err != nil {
		return err
	}
	c.log().Info("sanclient: detached", "workload", recordKey(a.Workload), "force", a.Force)
	return errors.Join(errs...)
}

// deleteSCSI removes every SCSI disk with that WWN (each path of it).
func (c *Client) deleteSCSI(wwn string) error {
	blocks, err := os.ReadDir(c.sys("/sys/block"))
	if err != nil {
		return err
	}
	var errs []error
	for _, b := range blocks {
		if !strings.HasPrefix(b.Name(), "sd") {
			continue
		}
		id, err := os.ReadFile(c.sys(filepath.Join("/sys/block", b.Name(), "device/wwid")))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(id)) != "naa."+wwn {
			continue
		}
		if err := os.WriteFile(c.sys(filepath.Join("/sys/block", b.Name(), "device/delete")), []byte("1"), 0); err != nil {
			errs = append(errs, fmt.Errorf("removing %s: %w", b.Name(), err))
		}
	}
	return errors.Join(errs...)
}

// Attached lists the attachments.
func (c *Client) Attached() ([]Record, error) {
	r, err := c.loadRecords()
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(r.Workloads))
	for _, x := range r.Workloads {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return recordKey(out[i].Workload) < recordKey(out[j].Workload) })
	return out, nil
}

// MultipathArgs is sanclient.multipath.apply: the WWNs to multipath.
type MultipathArgs struct {
	WWNs []string `json:"wwns"`
}

// RenderMultipath renders the allow list: everything blacklisted except
// cluster LUNs, find_multipaths strict, and a bounded no_path_retry so I/O
// fails (and QEMU pauses the VM) instead of queueing forever, which would
// hang self-fencing.
func RenderMultipath(wwns []string) (string, error) {
	l := slices.Clone(wwns)
	slices.Sort(l)
	l = slices.Compact(l)
	var b strings.Builder
	b.WriteString("# Generated by HardyOS (hardyd-priv): cluster LUNs only.\n")
	b.WriteString("defaults {\n\tfind_multipaths strict\n\tuser_friendly_names no\n\tno_path_retry 3\n}\n")
	b.WriteString("blacklist {\n\twwid \".*\"\n}\n")
	b.WriteString("blacklist_exceptions {\n")
	for _, w := range l {
		if !wwnRE.MatchString(w) {
			return "", fmt.Errorf("%q isn't a cluster LUN's WWN", w)
		}
		fmt.Fprintf(&b, "\twwid \"3%s\"\n", w)
	}
	b.WriteString("}\n")
	return b.String(), nil
}

// ApplyMultipath writes the allow list, adds the WWIDs and reloads
// multipathd.
func (c *Client) ApplyMultipath(ctx context.Context, a MultipathArgs) error {
	content, err := RenderMultipath(a.WWNs)
	if err != nil {
		return &ValidationError{err}
	}
	p := c.sys(MultipathConf)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := rootfile.WriteAtomic(p, []byte(content), 0o644); err != nil {
		return err
	}
	for _, w := range a.WWNs {
		if _, err := c.run(ctx, "multipath", "-a", "3"+w); err != nil {
			c.log().Warn("sanclient: adding a WWID to multipath", "wwid", w, "err", err)
		}
	}
	if _, err := c.run(ctx, "multipathd", "reconfigure"); err != nil {
		return fmt.Errorf("reloading multipathd: %w", err)
	}
	return nil
}

// ---- freeze and dump forwarded by the storage node ---------------------------

// FreezeArgs is sanclient.vm.freeze / .thaw.
type FreezeArgs struct {
	VM string `json:"vm"`
}

// Freeze freezes an attached cluster VM's guest file systems with its
// guest agent; it is thawed by Thaw or automatically after ThawAfter.
func (c *Client) Freeze(ctx context.Context, a FreezeArgs) (bool, error) {
	if !idRE.MatchString(a.VM) {
		return false, bad("%q isn't a VM", a.VM)
	}
	recs, err := c.loadRecords()
	if err != nil {
		return false, err
	}
	if _, ok := recs.Workloads[recordKey(cluster.WorkloadRef{Kind: cluster.KindVM, ID: a.VM})]; !ok {
		return false, bad("%s isn't a cluster VM attached here", a.VM)
	}
	fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := c.run(fctx, "virsh", "-c", "qemu:///system", "domfsfreeze", a.VM); err != nil {
		c.thaw(a.VM) // a timed-out freeze may still happen in the guest
		return false, nil
	}
	after := c.ThawAfter
	if after == 0 {
		after = 60 * time.Second
	}
	c.mu.Lock()
	if c.thaws == nil {
		c.thaws = map[string]*time.Timer{}
	}
	if t := c.thaws[a.VM]; t != nil {
		t.Stop()
	}
	vm := a.VM
	c.thaws[vm] = time.AfterFunc(after, func() {
		c.log().Warn("sanclient: thawing a VM the storage node didn't thaw in time", "vm", vm)
		c.thaw(vm)
	})
	c.mu.Unlock()
	return true, nil
}

// Thaw thaws a VM frozen by Freeze.
func (c *Client) Thaw(ctx context.Context, a FreezeArgs) error {
	if !idRE.MatchString(a.VM) {
		return bad("%q isn't a VM", a.VM)
	}
	c.thaw(a.VM)
	return nil
}

func (c *Client) thaw(vm string) {
	c.mu.Lock()
	if t := c.thaws[vm]; t != nil {
		t.Stop()
		delete(c.thaws, vm)
	}
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _ = c.run(ctx, "virsh", "-c", "qemu:///system", "domfsthaw", vm)
}

// DumpArgs is sanclient.app.dump.
type DumpArgs struct {
	App string `json:"app"`
}

// AppDump runs an attached cluster app's backup dump here (before the
// storage node snapshots its data).
func (c *Client) AppDump(ctx context.Context, a DumpArgs) (bool, error) {
	if !idRE.MatchString(a.App) {
		return false, bad("%q isn't an app", a.App)
	}
	recs, err := c.loadRecords()
	if err != nil {
		return false, err
	}
	if _, ok := recs.Workloads[recordKey(cluster.WorkloadRef{Kind: cluster.KindApp, ID: a.App})]; !ok {
		return false, bad("%s isn't a cluster app attached here", a.App)
	}
	if c.Dump == nil {
		return false, errors.New("apps aren't available here")
	}
	return c.Dump(ctx, a.App)
}
