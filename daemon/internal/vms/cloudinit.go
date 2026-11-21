package vms

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// cloud-init's NoCloud data source: a small disc labelled "cidata" with
// user-data and meta-data. HardyOS writes both as JSON (which is YAML), so
// nothing a person types can change their structure.

// UserData builds the #cloud-config for a VM.
func UserData(s *Spec) ([]byte, error) {
	ci := s.CloudInit
	if ci == nil {
		return nil, fmt.Errorf("%s has no cloud-init settings", s.ID)
	}
	u := map[string]any{
		"name":        ci.User,
		"groups":      []string{"sudo"},
		"shell":       "/bin/bash",
		"sudo":        "ALL=(ALL) NOPASSWD:ALL",
		"lock_passwd": ci.PasswordHash == "",
	}
	if len(ci.SSHKeys) > 0 {
		u["ssh_authorized_keys"] = ci.SSHKeys
	}
	if ci.PasswordHash != "" {
		u["passwd"] = ci.PasswordHash
	}
	host := ci.Hostname
	if host == "" {
		host = s.ID
	}
	cfg := map[string]any{
		"hostname":          host,
		"preserve_hostname": false,
		"users":             []any{u},
		"ssh_pwauth":        ci.PasswordHash != "",
		"disable_root":      true,
		"growpart":          map[string]any{"mode": "auto", "devices": []string{"/"}},
		"resize_rootfs":     true,
	}
	if ci.InstallAgent {
		cfg["packages"] = []string{"qemu-guest-agent"}
		cfg["runcmd"] = [][]string{{"systemctl", "enable", "--now", "qemu-guest-agent"}}
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte("#cloud-config\n"), append(b, '\n')...), nil
}

// MetaData builds the meta-data file.
func MetaData(s *Spec) []byte {
	host := s.ID
	if s.CloudInit != nil && s.CloudInit.Hostname != "" {
		host = s.CloudInit.Hostname
	}
	b, _ := json.Marshal(map[string]string{"instance-id": s.UUID, "local-hostname": host})
	return append(b, '\n')
}

// writeSeed makes the VM's cloud-init disc in its folder.
func (m *Manager) writeSeed(ctx context.Context, st *stored) error {
	ud, err := UserData(&st.spec)
	if err != nil {
		return err
	}
	// Everything is made inside a 0700 folder (the files and the disc
	// xorriso writes with its own mode), so the password hash and keys are
	// never readable by anyone else, even for a moment.
	stage := filepath.Join(m.sys(st.dir), "cloud-init.stage")
	_ = os.RemoveAll(stage)
	if err := os.Mkdir(stage, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	in := filepath.Join(stage, "in")
	if err := os.Mkdir(in, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(in, "user-data"), ud, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(in, "meta-data"), MetaData(&st.spec), 0o600); err != nil {
		return err
	}
	rel := filepath.Join(st.dir, "cloud-init.stage") // as xorriso sees it
	if _, err := m.run(ctx, "xorriso", "-as", "mkisofs", "-quiet", "-volid", "cidata", "-joliet", "-rock",
		"-output", filepath.Join(rel, "out.iso"), filepath.Join(rel, "in")); err != nil {
		return fmt.Errorf("making the cloud-init disc: %w", err)
	}
	// Only QEMU (and root) can read the seed: it has the user's password
	// hash and SSH keys.
	out := filepath.Join(stage, "out.iso")
	if err := m.ownSeed(out); err != nil {
		return err
	}
	return os.Rename(out, filepath.Join(m.sys(st.dir), seedFile))
}

// qemuOwned reports whether a state file may belong to QEMU's user: the
// generated discs only QEMU reads (decision 141).
func (m *Manager) qemuOwned(name string, uid uint32) bool {
	if name != seedFile {
		return false
	}
	q, err := m.qemuUID()
	return err == nil && q == uid
}

// ownSeed makes the seed QEMU's own, mode 0600 (decision 141).
func (m *Manager) ownSeed(path string) error {
	uid, err := m.qemuUID()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("the cloud-init disc %s isn't a file", path)
	}
	if err := f.Chown(int(uid), -1); err != nil {
		return err
	}
	return f.Chmod(0o600)
}
