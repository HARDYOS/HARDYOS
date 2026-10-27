package vms

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	dir := filepath.Join(m.sys(st.dir), "cloud-init")
	_ = os.RemoveAll(dir)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "user-data"), ud, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "meta-data"), MetaData(&st.spec), 0o600); err != nil {
		return err
	}
	tmp := filepath.Join(st.dir, seedFile+".new")
	if _, err := m.run(ctx, "xorriso", "-as", "mkisofs", "-quiet", "-volid", "cidata", "-joliet", "-rock",
		"-output", tmp, filepath.Join(st.dir, "cloud-init")); err != nil {
		return fmt.Errorf("making the cloud-init disc: %w", err)
	}
	// QEMU reads the seed as its own user; the password in it is hashed.
	if err := os.Chmod(m.sys(tmp), 0o644); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(m.sys(tmp), filepath.Join(m.sys(st.dir), seedFile)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
