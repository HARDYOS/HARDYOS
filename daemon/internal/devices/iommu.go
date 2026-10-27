package devices

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hardyos/hardyos/daemon/internal/boot"
)

// IOMMUResult is what "Turn on IOMMU" did.
type IOMMUResult struct {
	// Args are all the extra kernel arguments now configured.
	Args []string `json:"args"`
	// Added are the flags this call added.
	Added         []string `json:"added"`
	RestartNeeded bool     `json:"restartNeeded"`
	Message       string   `json:"message"`
	// Warning: some boot disks couldn't be updated (the others were).
	Warning string `json:"warning,omitempty"`
}

// EnableIOMMU adds the IOMMU kernel flags for this CPU (intel_iommu=on or
// amd_iommu=on, plus iommu=pt) to the boot configuration and rewrites the
// boot menu on every boot disk. It takes effect after a restart. Flags
// that would fight them (iommu=off, the other vendor's flag) are removed.
func (h *Host) EnableIOMMU(ctx context.Context) (*IOMMUResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, flags := h.iommuFlags()
	if len(flags) == 0 {
		return &IOMMUResult{Args: []string{}, Added: []string{}, Message: "This server needs no kernel flags for IOMMU; switch it on in the firmware settings if it's off."}, nil
	}
	cfg, err := boot.LoadConfig(h.path(boot.ConfigPath))
	if errors.Is(err, boot.ErrNoConfig) {
		return nil, errors.New("the boot settings can only be changed on a system installed with the HardyOS installer")
	}
	if err != nil {
		return nil, err
	}
	env := h.bootEnv()
	have, err := boot.LoadKernelArgs(env)
	if err != nil {
		return nil, fmt.Errorf("the current kernel arguments can't be read: %w", err)
	}
	var added []string
	for _, f := range flags {
		if !contains(have, f) {
			added = append(added, f)
		}
	}
	args := boot.RemoveKernelArgs(have, "intel_iommu", "amd_iommu", "iommu")
	args = boot.MergeKernelArgs(args, flags)
	if err := boot.SaveKernelArgs(env, args); err != nil {
		return nil, err
	}
	res := &IOMMUResult{Args: args, Added: added, RestartNeeded: true}
	if added == nil {
		res.Added = []string{}
	}
	if _, err := boot.Sync(ctx, env, cfg, boot.SyncOptions{}); err != nil {
		var pe *boot.PartialError
		if !errors.As(err, &pe) {
			return nil, fmt.Errorf("the boot menu couldn't be updated: %w", err)
		}
		res.Warning = err.Error()
	}
	cmdline := " " + h.readTrim("/proc/cmdline") + " "
	active := true
	for _, f := range flags {
		if !containsWord(cmdline, f) {
			active = false
		}
	}
	res.RestartNeeded = !active
	if res.RestartNeeded {
		res.Message = "IOMMU will be on after the next restart. Make sure it's also enabled in the BIOS (VT-d or AMD-Vi)."
	} else {
		res.Message = "The IOMMU boot settings are in place and already in use."
	}
	h.log().Info("IOMMU kernel flags configured", "args", args)
	return res, nil
}

// containsWord: padded is " a b c " and w one of the words.
func containsWord(padded, w string) bool { return strings.Contains(padded, " "+w+" ") }
