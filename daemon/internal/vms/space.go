package vms

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Space (decision 135). VM disks are thin zvols, so a VM only takes what
// its guest writes, and a guest that writes everything could fill the
// pool for every other dataset. Each VM's dataset gets a quota: the sum of
// its disks' sizes plus a margin (raidz padding, metadata, some snapshot
// history), kept up to date when disks are added, grown, removed or
// rolled back. New space (a new VM, more or bigger disks) must fit in what
// the pool has free unless the person allows overcommitting.

// spaceReserve stays free on a pool for everything else.
const spaceReserve = 1 << 30

// quotaBytes is a VM's space limit for its disks: their sizes, a quarter
// more and 2 GiB.
func quotaBytes(s *Spec) int64 {
	var sum int64
	for _, d := range s.Disks {
		sum += int64(d.SizeGB) << 30
	}
	return sum + sum/4 + 2<<30
}

// diskBytes is the space a spec's disks can take.
func diskBytes(s *Spec) int64 {
	var sum int64
	for _, d := range s.Disks {
		sum += int64(d.SizeGB) << 30
	}
	return sum
}

// available is the space free on a pool (its root dataset).
func (m *Manager) available(ctx context.Context, pool string) (int64, error) {
	out, err := m.zfs(ctx, "get", "-H", "-p", "-o", "value", "available", pool)
	if err != nil {
		return 0, fmt.Errorf("reading the free space of %s: %w", pool, err)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("reading the free space of %s: %q", pool, out)
	}
	return n, nil
}

// checkSpace refuses adding bytes of disk to a pool that doesn't have
// them free, unless overcommitting is allowed.
func (m *Manager) checkSpace(ctx context.Context, pool string, add int64, allowOvercommit bool) error {
	if add <= 0 || allowOvercommit {
		return nil
	}
	free, err := m.available(ctx, pool)
	if err != nil {
		return err
	}
	if add > free-spaceReserve {
		return Problems{fmt.Sprintf("the new disk space (%s) is more than %s has free (%s). Disks are thin, so this only fills up as the VM writes; allow overcommitting to go ahead anyway, or choose smaller disks", human(add), pool, human(max(free-spaceReserve, 0)))}
	}
	return nil
}

// setQuota sets a VM dataset's space limit from its spec, with extra
// room (an import's private copy) while that lasts.
func (m *Manager) setQuota(ctx context.Context, dataset string, s *Spec, extra int64) error {
	q := quotaBytes(s) + max(extra, 0)
	if _, err := m.zfs(ctx, "set", "quota="+strconv.FormatInt(q, 10), dataset); err != nil {
		return fmt.Errorf("setting the VM's space limit: %w", err)
	}
	return nil
}
