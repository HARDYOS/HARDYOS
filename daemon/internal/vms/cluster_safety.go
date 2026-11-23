package vms

// Part C safety fixes for cluster VMs (decisions 385-392): the approved
// settings' hash, a forced stop that doesn't depend on libvirt answering,
// the memory stream's route, and closing the migration user's libvirt
// connections when an admission ends.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrSpecChanged: the VM's spec on cluster storage isn't what an
// administrator approved (the hash in the replicated placement differs).
var ErrSpecChanged = errors.New("the VM's settings on cluster storage aren't the ones an administrator approved; refusing to start it")

// SpecHash is the hash of a cluster VM's approved settings: everything in
// the spec except what only labels it (name, description, labels,
// template, autostart). Placement records it (workload.add,
// workload.spec); a node starts or admits the VM only with the same hash.
func SpecHash(s *Spec) (string, error) {
	c := *s
	c.Name, c.Description, c.Template = "", "", ""
	c.Labels = nil
	c.Autostart = Autostart{}
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func checkSpecHash(s *Spec, want string) error {
	if want == "" {
		return Problems{"the cluster holds no approved settings for this VM"}
	}
	have, err := SpecHash(s)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(have), []byte(want)) != 1 {
		return ErrSpecChanged
	}
	return nil
}

// ClusterHash is the hash of the approved settings of a cluster VM
// attached here (hardyd records it after the administrator's change).
func (m *Manager) ClusterHash(ctx context.Context, id string) (string, error) {
	st, err := m.findCluster(ctx, id)
	if err != nil {
		return "", err
	}
	if err := liveSpecOK(&st.spec); err != nil {
		return "", err
	}
	return SpecHash(&st.spec)
}

// liveSpecOK: a spec that passed checkStored when it was read.
func liveSpecOK(s *Spec) error {
	if s.UUID == "" {
		return Problems{"the VM has no UUID yet"}
	}
	return nil
}

// recordDefined remembers the XML root defined for a cluster VM: the
// hook compares a start of that VM with it.
func (m *Manager) recordDefined(st *stored, x []byte) {
	if st.cluster == nil {
		return
	}
	mg := m.migs()
	mg.mu.Lock()
	mg.starting[st.spec.ID] = bytes.Clone(x)
	mg.mu.Unlock()
}

// ---- a forced stop that works when libvirt doesn't -----------------------------

// qemuPIDDir is where libvirt keeps QEMU's pid files.
const qemuPIDDir = "/run/libvirt/qemu"

// forceDestroy stops a domain at once: virsh destroy, and when libvirt
// can't (polkitd down with the polkit access driver, libvirtd hung), its
// QEMU process killed by pid (decision 390). nil when nothing runs.
func (m *Manager) forceDestroy(ctx context.Context, id string) error {
	_, err := m.virsh(ctx, "destroy", id)
	if err == nil || notDefined(err) || strings.Contains(err.Error(), "domain is not running") {
		// Only libvirt's own "nothing runs" counts: any other refusal
		// (polkit unavailable, a hung daemon) goes on to QEMU's pid.
		return nil
	}
	m.log().Warn("vms: libvirt couldn't stop a cluster VM; killing its QEMU", "id", id, "err", err)
	if kerr := m.killQEMU(id); kerr != nil {
		return fmt.Errorf("stopping %s: %v; killing its QEMU: %w", id, err, kerr)
	}
	return nil
}

// killQEMU kills a domain's QEMU process found by libvirt's pid file, only
// when that process is QEMU running that guest.
func (m *Manager) killQEMU(id string) error {
	if ValidID(id) != nil {
		return ErrNotFound
	}
	b, err := os.ReadFile(m.sys(filepath.Join(qemuPIDDir, id+".pid")))
	if errors.Is(err, os.ErrNotExist) {
		return nil // libvirt has no process for it
	}
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return fmt.Errorf("the pid file of %s is unreadable", id)
	}
	proc := m.sys(filepath.Join("/proc", strconv.Itoa(pid)))
	cmd, err := os.ReadFile(filepath.Join(proc, "cmdline"))
	if errors.Is(err, os.ErrNotExist) {
		return nil // already gone
	}
	if err != nil {
		return err
	}
	args := strings.Split(strings.TrimRight(string(cmd), "\x00"), "\x00")
	if len(args) == 0 || !strings.HasPrefix(filepath.Base(args[0]), "qemu-system-") {
		return fmt.Errorf("process %d isn't QEMU", pid)
	}
	guest := false
	for i, a := range args {
		if a == "-name" && i+1 < len(args) {
			for _, f := range strings.Split(args[i+1], ",") {
				if f == "guest="+id || f == id {
					guest = true
				}
			}
		}
	}
	if !guest {
		return fmt.Errorf("process %d isn't %s's QEMU", pid, id)
	}
	kill := m.killPID
	if kill == nil {
		kill = killProcess
	}
	return kill(pid)
}

// ---- the memory stream's route ------------------------------------------------

type ipRoute struct {
	Dst     string `json:"dst"`
	Dev     string `json:"dev"`
	Gateway string `json:"gateway"`
	Type    string `json:"type"`
}

// storageRoute checks, as root, that the memory stream's address is
// reached directly on a local network that isn't NetBird or loopback
// (decision 392): hardyd chose the URI, root checks where it goes.
func (m *Manager) storageRoute(ctx context.Context, uri string) error {
	rest := strings.TrimPrefix(uri, "tcp://")
	host := rest
	if h, _, err := net.SplitHostPort(rest); err == nil {
		host = h
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(rest, "["), "]")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return Problems{"the migration address must be an IP address"}
	}
	out, err := m.run(ctx, "ip", "-j", "route", "get", ip.Unmap().String())
	if err != nil {
		return fmt.Errorf("finding the route to %s: %w", ip, err)
	}
	var rs []ipRoute
	if err := json.Unmarshal(out, &rs); err != nil || len(rs) == 0 {
		return fmt.Errorf("finding the route to %s: unreadable answer", ip)
	}
	r := rs[0]
	switch {
	case r.Type != "" && r.Type != "unicast":
		return Problems{fmt.Sprintf("%s isn't another server (%s route)", ip, r.Type)}
	case r.Gateway != "":
		return Problems{fmt.Sprintf("%s is reached through a router (%s), not on the storage network", ip, r.Gateway)}
	case r.Dev == "" || r.Dev == "lo" || strings.HasPrefix(r.Dev, "wt") || strings.HasPrefix(r.Dev, "netbird"):
		return Problems{fmt.Sprintf("%s is reached through %s, not the storage network", ip, r.Dev)}
	}
	return nil
}

// ---- closing the migration user's connections ----------------------------------

// libvirtServers are the daemons (admin URI, server name) a migration
// connection can be open on: monolithic libvirtd, or the modular
// virtqemud and virtproxyd.
var libvirtServers = [][2]string{{"libvirtd:///system", "libvirtd"}, {"virtqemud:///system", "virtqemud"}, {"virtproxyd:///system", "virtproxyd"}}

// disconnectMigrateClients closes every libvirt connection of the
// migration user (best effort: the polkit rule is gone already, so such
// a connection can't do anything any more).
func (m *Manager) disconnectMigrateClients(ctx context.Context) {
	for _, s := range libvirtServers {
		out, err := m.run(ctx, "virt-admin", "-c", s[0], "srv-clients-list", s[1])
		if err != nil {
			continue
		}
		for _, id := range parseClientIDs(out) {
			info, err := m.run(ctx, "virt-admin", "-c", s[0], "client-info", s[1], id)
			if err != nil || clientUser(info) != MigrateUser {
				continue
			}
			if _, err := m.run(ctx, "virt-admin", "-c", s[0], "client-disconnect", s[1], id); err != nil {
				m.log().Warn("vms: closing the migration user's libvirt connection", "server", s[1], "client", id, "err", err)
			}
		}
	}
}

// parseClientIDs reads `virt-admin srv-clients-list`.
func parseClientIDs(out []byte) []string {
	var ids []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && digits(f[0]) {
			ids = append(ids, f[0])
		}
	}
	return ids
}

// clientUser reads the unix user of `virt-admin client-info`.
func clientUser(out []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok && strings.TrimSpace(k) == "unix_user_name" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
