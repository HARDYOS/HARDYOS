package priv

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/hardyos/hardyos/daemon/internal/devices"
	"github.com/hardyos/hardyos/daemon/internal/network"
	"github.com/hardyos/hardyos/daemon/internal/shares"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// Virtual machine operation names (docs/plans/vms.md section 1). hardyd
// never sends libvirt XML: it sends a VM spec, which hardyd-priv checks and
// turns into XML itself.
const (
	OpVMsList           = "vms.list"
	OpVMsGet            = "vms.get"
	OpVMsCreate         = "vms.create"
	OpVMsUpdate         = "vms.update"
	OpVMsStart          = "vms.start"
	OpVMsStop           = "vms.stop"
	OpVMsRestart        = "vms.restart"
	OpVMsDelete         = "vms.delete"
	OpVMsDeleteKept     = "vms.kept.delete"
	OpVMsSnapshot       = "vms.snapshot"
	OpVMsSnapshots      = "vms.snapshots"
	OpVMsSnapshotDelete = "vms.snapshot.delete"
	OpVMsRollback       = "vms.rollback"
	OpVMsConsole        = "vms.console"
	OpVMsConsoleOpen    = "vms.console.open"
	OpVMsLogs           = "vms.logs"
	OpVMsISOList        = "vms.iso.list"
	OpVMsISODownload    = "vms.iso.download"
	OpVMsISODelete      = "vms.iso.delete"
	OpVMsISOVirtio      = "vms.iso.virtio"
	OpVMsImport         = "vms.import"
	OpVMsTask           = "vms.task"
	OpVMsCapabilities   = "vms.capabilities"
	OpVMsBridge         = "vms.bridge"
)

// VMRef names a VM.
type VMRef struct {
	ID string `json:"id"`
}

// VMLogsArgs asks for the end of a VM's log.
type VMLogsArgs struct {
	ID    string `json:"id"`
	Lines int    `json:"lines"`
}

// VMLogsResult is a VM's recent log.
type VMLogsResult struct {
	Logs string `json:"logs"`
}

// VMVirtioArgs downloads the VirtIO drivers disc (Pool: for the ISOs
// shared folder when there's none yet).
type VMVirtioArgs struct {
	Pool string `json:"pool"`
}

// VMTaskResult is a background download or import; Task is nil when there
// was nothing to do.
type VMTaskResult struct {
	Task *vms.Task `json:"task"`
}

// VMSnapshotsResult lists a VM's snapshots.
type VMSnapshotsResult struct {
	Snapshots []vms.Snapshot `json:"snapshots"`
}

// VMBridgeResult names the bridge VMs use.
type VMBridgeResult struct {
	Bridge string `json:"bridge"`
}

// RegisterVMs adds the virtual machine operations.
func RegisterVMs(s *Server, m *vms.Manager) {
	s.Handle(OpVMsList, func(ctx context.Context, _ json.RawMessage) (any, error) {
		o, err := m.List(ctx)
		return o, vmsErr(err)
	})
	s.Handle(OpVMsGet, typed(func(ctx context.Context, a VMRef) (any, error) {
		v, err := m.Get(ctx, a.ID)
		return v, vmsErr(err)
	}))
	s.Handle(OpVMsCreate, typed(func(ctx context.Context, a vms.CreateArgs) (any, error) {
		r, err := m.Create(ctx, a)
		return r, vmsErr(err)
	}))
	s.Handle(OpVMsUpdate, typed(func(ctx context.Context, a vms.UpdateArgs) (any, error) {
		r, err := m.Update(ctx, a)
		return r, vmsErr(err)
	}))
	s.Handle(OpVMsStart, typed(func(ctx context.Context, a VMRef) (any, error) {
		r, err := m.Start(ctx, a.ID)
		return r, vmsErr(err)
	}))
	s.Handle(OpVMsStop, typed(func(ctx context.Context, a vms.StopArgs) (any, error) {
		v, err := m.Stop(ctx, a)
		return v, vmsErr(err)
	}))
	s.Handle(OpVMsRestart, typed(func(ctx context.Context, a vms.RestartArgs) (any, error) {
		r, err := m.Restart(ctx, a)
		return r, vmsErr(err)
	}))
	s.Handle(OpVMsDelete, typed(func(ctx context.Context, a vms.DeleteArgs) (any, error) {
		return vmDone(vmsErr(m.Delete(ctx, a)))
	}))
	s.Handle(OpVMsDeleteKept, typed(func(ctx context.Context, a vms.DeleteKeptArgs) (any, error) {
		return vmDone(vmsErr(m.DeleteKept(ctx, a)))
	}))
	s.Handle(OpVMsSnapshot, typed(func(ctx context.Context, a vms.SnapshotArgs) (any, error) {
		sn, err := m.TakeSnapshot(ctx, a)
		return sn, vmsErr(err)
	}))
	s.Handle(OpVMsSnapshots, typed(func(ctx context.Context, a VMRef) (any, error) {
		l, err := m.Snapshots(ctx, a.ID)
		return VMSnapshotsResult{Snapshots: l}, vmsErr(err)
	}))
	s.Handle(OpVMsSnapshotDelete, typed(func(ctx context.Context, a vms.DeleteSnapshotArgs) (any, error) {
		return vmDone(vmsErr(m.DeleteSnapshot(ctx, a)))
	}))
	s.Handle(OpVMsRollback, typed(func(ctx context.Context, a vms.RollbackArgs) (any, error) {
		v, err := m.Rollback(ctx, a)
		return v, vmsErr(err)
	}))
	s.Handle(OpVMsConsole, typed(func(ctx context.Context, a vms.ConsoleArgs) (any, error) {
		t, err := m.Console(ctx, a)
		return t, vmsErr(err)
	}))
	// The one VM operation that hands hardyd a connection: to the VM's
	// screen, for a token root issued a moment ago (see internal/vms).
	s.Handle(OpVMsConsoleOpen, typed(func(ctx context.Context, a vms.ConsoleOpenArgs) (any, error) {
		f, err := m.ConsoleOpen(ctx, a)
		if err != nil {
			return nil, vmsErr(err)
		}
		return &FileResult{Data: map[string]bool{"ok": true}, File: f}, nil
	}))
	s.Handle(OpVMsLogs, typed(func(ctx context.Context, a VMLogsArgs) (any, error) {
		l, err := m.Logs(ctx, a.ID, a.Lines)
		return VMLogsResult{Logs: l}, vmsErr(err)
	}))
	s.Handle(OpVMsISOList, func(ctx context.Context, _ json.RawMessage) (any, error) {
		l, err := m.ListLibrary(ctx)
		return l, vmsErr(err)
	})
	s.Handle(OpVMsISODownload, typed(func(ctx context.Context, a vms.DownloadArgs) (any, error) {
		t, err := m.StartDownload(ctx, a)
		return VMTaskResult{Task: t}, vmsErr(err)
	}))
	s.Handle(OpVMsISODelete, typed(func(ctx context.Context, a vms.DeleteFileArgs) (any, error) {
		return vmDone(vmsErr(m.DeleteFile(ctx, a)))
	}))
	s.Handle(OpVMsISOVirtio, typed(func(ctx context.Context, a VMVirtioArgs) (any, error) {
		t, err := m.EnsureVirtio(ctx, a.Pool)
		return VMTaskResult{Task: t}, vmsErr(err)
	}))
	s.Handle(OpVMsImport, typed(func(ctx context.Context, a vms.ImportArgs) (any, error) {
		t, err := m.StartImport(ctx, a)
		return VMTaskResult{Task: t}, vmsErr(err)
	}))
	s.Handle(OpVMsTask, typed(func(ctx context.Context, a vms.TaskArgs) (any, error) {
		t, err := m.TaskStatus(a)
		return VMTaskResult{Task: t}, vmsErr(err)
	}))
	s.Handle(OpVMsCapabilities, func(ctx context.Context, _ json.RawMessage) (any, error) {
		return m.Capabilities(ctx), nil
	})
	s.Handle(OpVMsBridge, func(ctx context.Context, _ json.RawMessage) (any, error) {
		if m.Network == nil {
			return nil, Errorf(CodeBadArgs, "this server can't make a network bridge")
		}
		name, err := m.Network.EnsureBridge(ctx)
		return VMBridgeResult{Bridge: name}, vmsErr(err)
	})
}

func vmDone(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	return map[string]bool{"ok": true}, nil
}

// vmsErr maps VM errors: the caller's mistakes (and conditions the person
// can fix) are bad_args, anything else failed.
func vmsErr(err error) error {
	if err == nil {
		return nil
	}
	var p vms.Problems
	var dp devices.Problems
	var ve *network.ValidationError
	if errors.As(err, &p) || errors.As(err, &dp) || errors.As(err, &ve) || errors.Is(err, vms.ErrNotFound) ||
		errors.Is(err, network.ErrPending) || errors.Is(err, network.ErrNoUplink) {
		return Errorf(CodeBadArgs, "%v", err)
	}
	var pe *Error
	if errors.As(err, &pe) {
		return pe
	}
	return Errorf(CodeFailed, "%v", err)
}

// VMLibrary is the ISOs shared folder for the VM engine, kept by the
// shared folders code (so file sharing follows when it's created).
func VMLibrary(m *shares.Manager, hooks ...ShareHook) vms.Library {
	return vms.ShareLibrary{Shares: vmShares{m: m, hooks: hooks}}
}

type vmShares struct {
	m     *shares.Manager
	hooks []ShareHook
}

func (v vmShares) Lookup(ctx context.Context, id string) (string, string, uint64, error) {
	sh, err := v.m.Get(ctx, id)
	if errors.Is(err, shares.ErrNotFound) {
		return "", "", 0, os.ErrNotExist
	}
	if err != nil {
		return "", "", 0, err
	}
	if !sh.Usable() {
		return sh.Pool, sh.Path, 0, nil
	}
	return sh.Pool, sh.Path, sh.RootDev, nil
}

func (v vmShares) CreateLibrary(ctx context.Context, pool string) error {
	// Shared over SMB (copy discs in from Windows), without snapshots:
	// installers don't change, and snapshots would keep deleted ones.
	sv := shares.Services{SMB: shares.SMB{Enabled: true}, NFS: shares.NFS{Clients: []shares.NFSRule{}}}
	_, err := v.m.Create(ctx, shares.NewShare{
		Pool: pool, ID: vms.LibraryShareID, Name: "ISOs",
		Description: "Installer discs and disk images for virtual machines",
		Services:    &sv,
	})
	runChanged(ctx, v.hooks)
	return err
}
