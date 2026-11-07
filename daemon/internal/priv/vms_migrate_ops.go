package priv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// Live migration operations (Phase 8 part C, decision 351). The two that
// hand hardyd a connection are the destination's libvirt connection as
// the migration user (accept) and the source's one-shot listening socket
// (listen); neither gives hardyd root's libvirt.
const (
	OpVMsMigrateSetup  = "vms.migrate.setup"
	OpVMsMigrateAccept = "vms.migrate.accept"
	OpVMsMigrateListen = "vms.migrate.listen"
	OpVMsMigrateSend   = "vms.migrate.send"
	OpVMsMigrateCheck  = "vms.migrate.check"
	OpVMsMigrateEnd    = "vms.migrate.end"
	OpVMsCPUBaseline   = "vms.cpu.baseline"
)

// RegisterVMsMigrate adds the live migration operations.
func RegisterVMsMigrate(s *Server, m *vms.Manager) {
	s.Handle(OpVMsMigrateSetup, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return vmDone(vmsErr(m.MigrateSetup(ctx)))
	})
	s.Handle(OpVMsMigrateAccept, typed(func(ctx context.Context, a vms.MigrateAcceptArgs) (any, error) {
		f, err := m.MigrateAccept(ctx, a)
		if err != nil {
			return nil, migrateErr(err)
		}
		return &FileResult{Data: map[string]bool{"ok": true}, File: f}, nil
	}))
	s.Handle(OpVMsMigrateListen, typed(func(ctx context.Context, a vms.MigrateListenArgs) (any, error) {
		f, err := m.MigrateListen(ctx, a)
		if err != nil {
			return nil, migrateErr(err)
		}
		return &FileResult{Data: map[string]bool{"ok": true}, File: f}, nil
	}))
	s.Handle(OpVMsMigrateSend, typed(func(ctx context.Context, a vms.MigrateSendArgs) (any, error) {
		return vmDone(migrateErr(m.MigrateSend(ctx, a)))
	}))
	s.Handle(OpVMsMigrateCheck, typed(func(ctx context.Context, a vms.MigrateCheckArgs) (any, error) {
		return vmDone(migrateErr(m.MigrateCheck(ctx, a)))
	}))
	s.Handle(OpVMsMigrateEnd, typed(func(ctx context.Context, a vms.MigrateEndArgs) (any, error) {
		return vmDone(migrateErr(m.MigrateEnd(ctx, a)))
	}))
	s.Handle(OpVMsCPUBaseline, func(ctx context.Context, _ json.RawMessage) (any, error) {
		h, err := m.HostCPUInfo(ctx)
		return h, vmsErr(err)
	})
}

func migrateErr(err error) error {
	if errors.Is(err, vms.ErrGeneration) || errors.Is(err, vms.ErrClusterPlaced) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	return vmsErr(err)
}

// MigrateOpTimeouts are the migration operations' time limits.
func MigrateOpTimeouts() map[string]time.Duration {
	return map[string]time.Duration{OpVMsMigrateSend: 65 * time.Minute, OpVMsMigrateSetup: 3 * time.Minute, OpVMsMigrateCheck: 20 * time.Second}
}

// ---- the libvirt hook -----------------------------------------------------------

// LibvirtHookArg is hardyd-priv's subcommand libvirt's qemu hook runs
// (packaging/libvirt/hooks/qemu): hardyd-priv libvirt-hook <domain> <op>
// <subop> <extra>, the domain XML on stdin.
const LibvirtHookArg = "libvirt-hook"

// LibvirtHookMain answers libvirt's qemu hook. Only the "migrate"
// operation (an incoming migration, before QEMU starts) is checked: the
// XML must match what root admitted; any other operation passes. Exit 0
// accepts, anything else refuses.
func LibvirtHookMain(args []string, stdin io.Reader, stderr io.Writer, socket string) int {
	if len(args) < 2 {
		return 0
	}
	vm, op := args[0], args[1]
	if op != "migrate" {
		return 0
	}
	b, err := io.ReadAll(io.LimitReader(stdin, 1<<20+1))
	if err != nil || len(b) > 1<<20 {
		fmt.Fprintln(stderr, "HardyOS: the incoming domain XML couldn't be read")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := NewClient(socket).Call(ctx, OpVMsMigrateCheck, vms.MigrateCheckArgs{VM: vm, XML: string(b)}, nil); err != nil {
		fmt.Fprintf(stderr, "HardyOS refused the incoming migration of %s: %v\n", vm, err)
		return 1
	}
	return 0
}

// RunLibvirtHook is LibvirtHookMain with the process's stdin and stderr.
func RunLibvirtHook(args []string) int {
	return LibvirtHookMain(args, os.Stdin, os.Stderr, DefaultSocket)
}
