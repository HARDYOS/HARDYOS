package priv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	// OpVMsMigrateHealth reports whether polkitd runs (every libvirt call
	// needs it once the access driver is on).
	OpVMsMigrateHealth = "vms.migrate.health"
	// OpVMsClusterHash is the hash of a cluster VM's approved settings.
	OpVMsClusterHash = "vms.cluster.hash"
)

// RegisterVMsMigrate adds the live migration operations.
func RegisterVMsMigrate(s *Server, m *vms.Manager) {
	s.Handle(OpVMsMigrateSetup, func(ctx context.Context, raw json.RawMessage) (any, error) {
		var a vms.MigrateSetupArgs
		if len(raw) > 0 && string(raw) != "null" {
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, Errorf(CodeBadArgs, "bad arguments: %v", err)
			}
		}
		return vmDone(vmsErr(m.MigrateSetup(ctx, a)))
	})
	s.Handle(OpVMsMigrateHealth, func(ctx context.Context, _ json.RawMessage) (any, error) {
		if err := m.PolkitHealth(ctx); err != nil {
			return map[string]any{"ok": false, "problem": err.Error()}, nil
		}
		return map[string]any{"ok": true}, nil
	})
	s.Handle(OpVMsClusterHash, typed(func(ctx context.Context, a VMRef) (any, error) {
		h, err := m.ClusterHash(ctx, a.ID)
		return SpecHashResult{Hash: h}, migrateErr(err)
	}))
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

// SpecHashResult is a cluster workload's approved-settings hash.
type SpecHashResult struct {
	Hash string `json:"hash"`
}

func migrateErr(err error) error {
	if errors.Is(err, vms.ErrGeneration) || errors.Is(err, vms.ErrClusterPlaced) || errors.Is(err, vms.ErrSpecChanged) {
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

// hookChecked are the qemu hook operations root checks: an incoming
// migration and every start of QEMU (decision 385).
var hookChecked = map[string]bool{vms.HookMigrate: true, vms.HookPrepare: true, vms.HookStart: true, vms.HookRestore: true}

// LibvirtHookMain answers libvirt's qemu hook. An incoming migration
// ("migrate") and every start of QEMU ("prepare", "start", "restore") are
// checked by root: a cluster VM, or one with an open admission, must match
// root's own rendering; other VMs pass. When hardyd-priv can't be asked,
// a start is refused only if the XML names cluster storage or the VM has
// an open admission (so this server's own VMs still start at boot). Exit
// 0 accepts, anything else refuses.
func LibvirtHookMain(args []string, stdin io.Reader, stderr io.Writer, socket string) int {
	return libvirtHook(args, stdin, stderr, socket, "/")
}

func libvirtHook(args []string, stdin io.Reader, stderr io.Writer, socket, root string) int {
	if len(args) < 2 {
		return 0
	}
	vm, op := args[0], args[1]
	if !hookChecked[op] {
		return 0
	}
	b, err := io.ReadAll(io.LimitReader(stdin, 1<<20+1))
	if err != nil || len(b) > 1<<20 {
		fmt.Fprintln(stderr, "HardyOS: the domain XML couldn't be read")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = NewClient(socket).Call(ctx, OpVMsMigrateCheck, vms.MigrateCheckArgs{VM: vm, XML: string(b), Op: op}, nil)
	if err == nil {
		return 0
	}
	var pe *Error
	if !errors.As(err, &pe) || pe.Code == CodeUnavailable {
		// hardyd-priv didn't answer: decide from what root can see alone.
		admitted := false
		if vms.ValidID(vm) == nil {
			_, serr := os.Stat(filepath.Join(root, vms.MigrateAdmittedDir, vm))
			admitted = serr == nil
		}
		if op != vms.HookMigrate && !admitted && !vms.LooksClustered(b) {
			return 0
		}
	}
	fmt.Fprintf(stderr, "HardyOS refused to start %s (%s): %v\n", vm, op, err)
	return 1
}

// RunLibvirtHook is LibvirtHookMain with the process's stdin and stderr.
func RunLibvirtHook(args []string) int {
	return LibvirtHookMain(args, os.Stdin, os.Stderr, DefaultSocket)
}
