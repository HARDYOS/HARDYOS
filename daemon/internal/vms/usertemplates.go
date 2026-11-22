package vms

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/devices"
	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// Saved templates, "make template from VM" (decision 414). A stopped VM is
// copied, disk by disk (ZFS send and receive), to
//
//	<pool>/vm-templates/<id>          root only: template.json
//	<pool>/vm-templates/<id>/<disk>   a zvol, with the snapshot @template
//
// with its settings minus everything that makes it one particular
// computer: UUID, MAC addresses, the cloud-init password, the Windows
// answer disc, TPM and firmware variables, passed-through devices,
// schedules. A new VM from it gets full copies of the disks (never ZFS
// clones), so the template and the VMs can be deleted in any order.

// PropTemplate marks a saved template's dataset (its id).
const PropTemplate = "org.hardyos:vm-template"

const templateFile = "template.json"

// templateSnapPrefix is the VM snapshot a template is copied from.
const templateSnapPrefix = "hardyos-tpl-"

var userTemplateRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)

// UserTemplate is a saved template.
type UserTemplate struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Pool        string    `json:"pool"`
	Created     time.Time `json:"created"`
	// From is the VM it was made from.
	From string `json:"from"`
	// Spec is the VM's settings without its identity; Spec.Template is the
	// built-in template it goes back to.
	Spec Spec `json:"spec"`
	// Bytes is the space the template takes on the pool.
	Bytes int64 `json:"bytes"`
}

// templateLock is a template's lock name (never a VM name: VM names have
// no colon).
func templateLock(id string) string { return "template:" + id }

// TemplateDataset is a saved template's dataset.
func TemplateDataset(pool, id string) string { return pool + "/vm-templates/" + id }

// Generalize takes a VM's identity out of its settings.
func Generalize(s Spec) Spec {
	g := s
	g.ID, g.Name, g.UUID, g.Description = "", "", "", ""
	g.Schedule, g.Unattend, g.Streaming = nil, nil, nil
	g.FromTemplate = ""
	g.Autostart = Autostart{}
	g.Devices = []devices.Device{}
	g.NICs = append([]NIC(nil), s.NICs...)
	for i := range g.NICs {
		g.NICs[i].MAC = ""
	}
	g.Disks = append([]Disk(nil), s.Disks...)
	for i := range g.Disks {
		g.Disks[i].Import, g.Disks[i].Clone = nil, nil
	}
	if s.CloudInit != nil {
		ci := *s.CloudInit
		ci.PasswordHash = ""
		ci.SSHKeys = append([]string(nil), s.CloudInit.SSHKeys...)
		g.CloudInit = &ci
	}
	// Installer discs and the answer disc stay behind; the drivers disc
	// and the cloud-init disc come along.
	g.Media = []Media{}
	for _, md := range s.Media {
		if md.Kind == MediaVirtio || md.Kind == MediaCloudInit {
			g.Media = append(g.Media, md)
		}
	}
	return g
}

// templateDatasets lists saved templates: dataset -> mountpoint.
func (m *Manager) templateDatasets(ctx context.Context) (map[string]string, error) {
	out, err := m.zfs(ctx, "list", "-H", "-p", "-t", "filesystem", "-o", "name,mountpoint,"+PropTemplate)
	if err != nil {
		return nil, fmt.Errorf("listing templates: %w", err)
	}
	res := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 || f[2] == "-" || f[2] == "" {
			continue
		}
		pool, _, _ := strings.Cut(f[0], "/")
		if !userTemplateRE.MatchString(f[2]) || f[0] != TemplateDataset(pool, f[2]) {
			continue
		}
		res[f[0]] = f[1]
	}
	return res, nil
}

func (m *Manager) readTemplate(ds, mp string) (*UserTemplate, error) {
	if !filepath.IsAbs(mp) || filepath.Clean(mp) != mp {
		return nil, fmt.Errorf("%s isn't mounted", ds)
	}
	if _, err := m.mounts().VerifyMount(mp, ds); err != nil {
		return nil, err
	}
	b, err := rootfile.ReadFile(filepath.Join(m.sys(mp), templateFile))
	if err != nil {
		return nil, err
	}
	var t UserTemplate
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("%s: %w", templateFile, err)
	}
	pool, _, _ := strings.Cut(ds, "/")
	if t.Pool != pool || TemplateDataset(pool, t.ID) != ds {
		return nil, fmt.Errorf("%s describes %s, not this dataset", templateFile, t.ID)
	}
	if _, ok := TemplateByID(t.Spec.Template); !ok {
		return nil, fmt.Errorf("%s names no built-in template", templateFile)
	}
	return &t, nil
}

// UserTemplates lists the saved templates by name.
func (m *Manager) UserTemplates(ctx context.Context) ([]UserTemplate, error) {
	l, err := m.templateDatasets(ctx)
	if err != nil {
		return nil, err
	}
	out := []UserTemplate{}
	for ds, mp := range l {
		t, err := m.readTemplate(ds, mp)
		if err != nil {
			m.log().Warn("vms: skipping a template that can't be read", "dataset", ds, "err", err)
			continue
		}
		if o, err := m.zfs(ctx, "get", "-H", "-p", "-o", "value", "used", ds); err == nil {
			t.Bytes, _ = strconv.ParseInt(strings.TrimSpace(string(o)), 10, 64)
		}
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Manager) findTemplate(ctx context.Context, id string) (*UserTemplate, string, error) {
	if !userTemplateRE.MatchString(id) {
		return nil, "", Problems{fmt.Sprintf("there's no saved template called %q", id)}
	}
	l, err := m.UserTemplates(ctx)
	if err != nil {
		return nil, "", err
	}
	for _, t := range l {
		if t.ID == id {
			return &t, TemplateDataset(t.Pool, t.ID), nil
		}
	}
	return nil, "", Problems{fmt.Sprintf("there's no saved template called %q", id)}
}

// MakeTemplateArgs saves a stopped VM as a template.
type MakeTemplateArgs struct {
	VM          string `json:"vm"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// MakeTemplate starts copying a stopped VM into a new template.
func (m *Manager) MakeTemplate(ctx context.Context, a MakeTemplateArgs) (*Task, error) {
	a.Name, a.Description = strings.TrimSpace(a.Name), strings.TrimSpace(a.Description)
	var p Problems
	if !userTemplateRE.MatchString(a.ID) || strings.Contains(a.ID, "--") {
		p = append(p, fmt.Sprintf("%q isn't a valid template name: use 2-32 lowercase letters, digits and dashes", a.ID))
	}
	if a.Name == "" || len(a.Name) > 64 || strings.ContainsAny(a.Name, "\x00\n\r\t") {
		p = append(p, "the template's display name must be 1 to 64 characters on one line")
	}
	if len(a.Description) > MaxDescLength || strings.ContainsRune(a.Description, 0) {
		p = append(p, fmt.Sprintf("the description must be at most %d characters", MaxDescLength))
	}
	if len(p) > 0 {
		return nil, p
	}
	unlock, err := m.lockValid(a.VM)
	if err != nil {
		return nil, err
	}
	st, err := m.find(ctx, a.VM)
	if err != nil {
		unlock()
		return nil, err
	}
	if s := m.state(ctx, a.VM); s != "stopped" && s != "crashed" {
		unlock()
		return nil, Problems{"shut the VM down before making a template from it"}
	}
	if _, _, err := m.findTemplate(ctx, a.ID); err == nil {
		unlock()
		return nil, Problems{fmt.Sprintf("there's already a template called %s", a.ID)}
	}
	ds := TemplateDataset(st.spec.Pool, a.ID)
	if _, err := m.zfs(ctx, "list", "-H", "-o", "name", ds); err == nil {
		unlock()
		return nil, Problems{fmt.Sprintf("%s already exists", ds)}
	}
	if err := m.checkSpace(ctx, st.spec.Pool, diskBytes(&st.spec)/4, false); err != nil {
		unlock()
		return nil, err
	}
	unlockTpl, ok := m.tryLock(templateLock(a.ID))
	if !ok {
		unlock()
		return nil, Problems{fmt.Sprintf("the template %s is busy", a.ID)}
	}
	t, err := m.tasks.start("template", a.VM, a.ID)
	if err != nil {
		unlockTpl()
		unlock()
		return nil, err
	}
	spec := st.spec
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
		defer cancel()
		// The VM stays off and unchanged while it's copied. Its lock and
		// the template's are given back before the task says it's done,
		// so whatever follows "done" (deleting the template, starting
		// the VM) never finds them still held.
		err := m.copyToTemplate(bg, t, st, spec, a)
		unlockTpl()
		unlock()
		m.tasks.finish(t.ID, err)
		if err != nil {
			m.log().Warn("vms: making a template failed", "vm", a.VM, "template", a.ID, "err", err)
		} else {
			m.log().Info("vms: template made", "vm", a.VM, "template", a.ID)
		}
	}()
	return m.tasks.get(t.ID), nil
}

func (m *Manager) copyToTemplate(ctx context.Context, t *Task, st *stored, spec Spec, a MakeTemplateArgs) (err error) {
	pool := spec.Pool
	snap := templateSnapPrefix + randomHex(6)
	if _, err := m.zfs(ctx, "snapshot", "-r", st.dataset+"@"+snap); err != nil {
		return fmt.Errorf("snapshotting the VM: %w", err)
	}
	defer func() {
		if _, derr := m.zfs(context.WithoutCancel(ctx), "destroy", "-r", st.dataset+"@"+snap); derr != nil {
			m.log().Warn("vms: removing the template's source snapshot", "vm", spec.ID, "err", derr)
		}
	}()
	parent := pool + "/vm-templates"
	if _, err := m.zfs(ctx, "list", "-H", "-o", "name", parent); err != nil {
		if _, err := m.zfs(ctx, "create", "-o", "devices=off", "-o", "setuid=off", "-o", "exec=off", parent); err != nil {
			return fmt.Errorf("creating %s: %w", parent, err)
		}
	}
	ds := TemplateDataset(pool, a.ID)
	// Bounded like a VM (decision 135): a template can't fill the pool.
	if _, err := m.zfs(ctx, "create", "-o", PropTemplate+"="+a.ID, "-o", "canmount=on", "-o", "devices=off", "-o", "setuid=off", "-o", "exec=off",
		"-o", "quota="+strconv.FormatInt(quotaBytes(&spec), 10), ds); err != nil {
		return fmt.Errorf("creating the template's dataset: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			if _, derr := m.zfs(context.WithoutCancel(ctx), "destroy", "-r", ds); derr != nil {
				m.log().Warn("vms: removing a template that couldn't be made", "dataset", ds, "err", derr)
			}
		}
	}()
	tst, err := m.mounted(ctx, ds)
	if err != nil {
		return err
	}
	if err := os.Chmod(m.sys(tst.dir), 0o700); err != nil {
		return err
	}
	for i, d := range spec.Disks {
		m.tasks.progress(t.ID, 100*float64(i)/float64(len(spec.Disks)), fmt.Sprintf("Copying %s (%d GB)", d.Name, d.SizeGB))
		to := ds + "/" + d.Name
		if err := m.sendRecv(ctx, DiskDataset(pool, spec.ID, d.Name)+"@"+snap, to); err != nil {
			return fmt.Errorf("copying %s: %w", d.Name, err)
		}
		if _, err := m.zfs(ctx, "rename", to+"@"+snap, to+"@template"); err != nil {
			return fmt.Errorf("naming %s's snapshot: %w", d.Name, err)
		}
		// Thin, like the VM's own disks.
		if _, err := m.zfs(ctx, "set", "refreservation=none", to); err != nil {
			return fmt.Errorf("making %s thin: %w", d.Name, err)
		}
	}
	ut := UserTemplate{ID: a.ID, Name: a.Name, Description: a.Description, Pool: pool, Created: m.now().UTC(), From: spec.ID, Spec: Generalize(spec)}
	b, err := json.MarshalIndent(ut, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(m.sys(tst.dir), templateFile), append(b, '\n'), 0o600); err != nil {
		return err
	}
	ok = true
	return nil
}

// DeleteTemplateArgs deletes a saved template; Confirm is its id or name.
type DeleteTemplateArgs struct {
	ID      string `json:"id"`
	Confirm string `json:"confirm"`
}

// DeleteTemplate destroys a saved template (VMs made from it keep their
// own disks).
func (m *Manager) DeleteTemplate(ctx context.Context, a DeleteTemplateArgs) error {
	if !userTemplateRE.MatchString(a.ID) {
		return Problems{fmt.Sprintf("there's no saved template called %q", a.ID)}
	}
	unlock, ok := m.tryLock(templateLock(a.ID))
	if !ok {
		return Problems{"a VM is being made from this template (or it's being made) right now; wait for it to finish"}
	}
	defer unlock()
	t, ds, err := m.findTemplate(ctx, a.ID)
	if err != nil {
		return err
	}
	c := strings.TrimSpace(a.Confirm)
	if c == "" || (c != t.ID && c != t.Name) {
		return Problems{fmt.Sprintf("type the template's name (%s) to confirm", t.Name)}
	}
	if _, err := m.zfs(ctx, "destroy", "-r", ds); err != nil {
		return fmt.Errorf("deleting the template: %w", err)
	}
	m.log().Info("vms: template deleted", "template", t.ID)
	return nil
}

// Clone fills a new VM's disk from a saved template's disk of the same
// name.
type Clone struct {
	Template string `json:"template"`
}

// checkClones makes sure the templates a new VM's disks come from exist
// and fit.
func (m *Manager) checkClones(ctx context.Context, s *Spec) error {
	var p Problems
	for _, d := range s.Disks {
		if d.Clone == nil {
			continue
		}
		t, ds, err := m.findTemplate(ctx, d.Clone.Template)
		if err != nil {
			p = append(p, fmt.Sprintf("%s: %v", d.Name, err))
			continue
		}
		size := 0
		for _, td := range t.Spec.Disks {
			if td.Name == d.Name {
				size = td.SizeGB
			}
		}
		if size == 0 {
			p = append(p, fmt.Sprintf("%s: the template %s has no disk %s", d.Name, t.Name, d.Name))
			continue
		}
		if d.SizeGB < size {
			p = append(p, fmt.Sprintf("%s must be at least %d GB, the template's size", d.Name, size))
		}
		if _, err := m.zfs(ctx, "list", "-H", "-o", "name", "-t", "snapshot", ds+"/"+d.Name+"@template"); err != nil {
			p = append(p, fmt.Sprintf("%s: the template's copy of %s is missing", d.Name, d.Name))
		}
	}
	if len(p) > 0 {
		return p
	}
	return nil
}

// StartClone copies a saved template's disk into a new VM's disk in the
// background (the VM must be off; the disk isn't made by Create).
func (m *Manager) StartClone(ctx context.Context, a ImportArgs) (*Task, error) {
	st, err := m.find(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	var disk *Disk
	for i := range st.spec.Disks {
		if st.spec.Disks[i].Name == a.Disk {
			disk = &st.spec.Disks[i]
		}
	}
	if disk == nil || disk.Clone == nil {
		return nil, Problems{fmt.Sprintf("%s has no disk %s to copy from a template", st.spec.Name, a.Disk)}
	}
	if m.state(ctx, a.ID) != "stopped" {
		return nil, Problems{"the VM must be off while its disk is copied"}
	}
	target := DiskDataset(st.spec.Pool, st.spec.ID, disk.Name)
	if _, err := m.zfs(ctx, "list", "-H", "-o", "name", target); err == nil {
		return nil, Problems{fmt.Sprintf("%s already has its disk %s", st.spec.Name, disk.Name)}
	}
	_, ds, err := m.findTemplate(ctx, disk.Clone.Template)
	if err != nil {
		return nil, err
	}
	// The template's lock: it can't be deleted while it's copied from.
	unlockTpl, ok := m.tryLock(templateLock(disk.Clone.Template))
	if !ok {
		return nil, Problems{"the template is busy (being made or deleted); try again in a moment"}
	}
	t, err := m.tasks.start("clone", a.ID, disk.Clone.Template)
	if err != nil {
		unlockTpl()
		return nil, err
	}
	d := *disk
	go func() {
		bg, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
		defer cancel()
		unlock := m.lock(a.ID)
		m.tasks.progress(t.ID, 5, fmt.Sprintf("Copying %s from the template", d.Name))
		err := m.cloneDisk(bg, &st.spec, d, ds)
		// Locks first, then "done" (see MakeTemplate).
		unlock()
		unlockTpl()
		m.tasks.finish(t.ID, err)
		if err != nil {
			m.log().Warn("vms: copying a disk from a template failed", "id", a.ID, "disk", d.Name, "err", err)
		}
	}()
	return m.tasks.get(t.ID), nil
}

func (m *Manager) cloneDisk(ctx context.Context, s *Spec, d Disk, tplDataset string) error {
	to := DiskDataset(s.Pool, s.ID, d.Name)
	if err := m.sendRecv(ctx, tplDataset+"/"+d.Name+"@template", to); err != nil {
		_, _ = m.zfs(context.WithoutCancel(ctx), "destroy", "-r", to)
		return err
	}
	steps := [][]string{
		{"destroy", to + "@template"},
		{"set", PropVM + "=" + s.ID, to},
		{"set", "refreservation=none", to},
		{"set", "volsize=" + strconv.Itoa(d.SizeGB) + "G", to},
	}
	for _, a := range steps {
		if _, err := m.zfs(ctx, a...); err != nil {
			return fmt.Errorf("setting up %s: %w", d.Name, err)
		}
	}
	return nil
}

// SendRecv copies a snapshot to a new dataset (zfs send | zfs receive).
type SendRecv func(ctx context.Context, from, to string) error

func (m *Manager) sendRecv(ctx context.Context, from, to string) error {
	if m.SendRecvFunc != nil {
		return m.SendRecvFunc(ctx, from, to)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	var sendErr, recvErr bytes.Buffer
	send := command(ctx, "zfs", "send", from)
	send.Stdout, send.Stderr = w, &limitedBuffer{b: &sendErr, n: 4096}
	recv := command(ctx, "zfs", "receive", "-u", to)
	recv.Stdin, recv.Stderr = r, &limitedBuffer{b: &recvErr, n: 4096}
	if err := recv.Start(); err != nil {
		r.Close()
		w.Close()
		return err
	}
	if err := send.Start(); err != nil {
		r.Close()
		w.Close()
		_ = recv.Wait()
		return err
	}
	r.Close()
	w.Close()
	se := send.Wait()
	re := recv.Wait()
	if se != nil {
		return fmt.Errorf("zfs send: %v: %s", se, strings.TrimSpace(sendErr.String()))
	}
	if re != nil {
		return fmt.Errorf("zfs receive: %v: %s", re, strings.TrimSpace(recvErr.String()))
	}
	return nil
}
