package boot

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// FirmwareLabel prefixes the UEFI boot entries HardyOS creates.
const FirmwareLabel = "HardyOS"

// SetFirmwareEntries registers each boot disk with the UEFI firmware, first
// disk first, replacing earlier HardyOS entries. GRUB also sits at the
// removable path that firmware falls back to, so this is best effort: some
// firmware only boots listed entries.
func SetFirmwareEntries(ctx context.Context, env Env, disks []string) {
	if _, err := os.Stat(env.path("/sys/firmware/efi")); err != nil {
		return // booted in BIOS mode: there is no boot entry list
	}
	res, err := env.Runner.Run(ctx, nil, "efibootmgr")
	if err != nil || res.ExitCode != 0 {
		return
	}
	for _, num := range staleEntries(string(res.Stdout)) {
		_, _ = env.Runner.Run(ctx, nil, "efibootmgr", "-q", "-b", num, "-B")
	}
	// efibootmgr -c puts the new entry first in BootOrder, so add the
	// last disk first and the first disk ends up on top.
	for i := len(disks) - 1; i >= 0; i-- {
		label := FirmwareLabel
		if len(disks) > 1 {
			label = fmt.Sprintf("%s (disk %d)", FirmwareLabel, i+1)
		}
		_, _ = env.Runner.Run(ctx, nil, "efibootmgr", "-q", "-c", "-d", disks[i], "-p", "2", "-L", label, "-l", `\EFI\BOOT\BOOTX64.EFI`)
	}
}

// staleEntries returns the boot entry numbers labeled HardyOS in efibootmgr output.
func staleEntries(out string) []string {
	var nums []string
	for _, line := range strings.Split(out, "\n") {
		// "Boot0003* HardyOS (disk 1)\tHD(...)"
		if !strings.HasPrefix(line, "Boot") || len(line) < 10 {
			continue
		}
		num, rest := line[4:8], strings.TrimLeft(line[8:], "* ")
		if strings.HasPrefix(rest, FirmwareLabel) {
			nums = append(nums, num)
		}
	}
	return nums
}
