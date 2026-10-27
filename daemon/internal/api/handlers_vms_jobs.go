package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/jobs"
	"github.com/hardyos/hardyos/daemon/internal/priv"
	"github.com/hardyos/hardyos/daemon/internal/vms"
)

// VM job kinds.
const (
	JobKindVMCreate         = "vms.create"
	JobKindVMUpdate         = "vms.update"
	JobKindVMStart          = "vms.start"
	JobKindVMStop           = "vms.stop"
	JobKindVMForceStop      = "vms.force-stop"
	JobKindVMRestart        = "vms.restart"
	JobKindVMReset          = "vms.reset"
	JobKindVMDelete         = "vms.delete"
	JobKindVMKeptDelete     = "vms.kept.delete"
	JobKindVMSnapshot       = "vms.snapshot"
	JobKindVMSnapshotDelete = "vms.snapshot.delete"
	JobKindVMRollback       = "vms.rollback"
	JobKindVMDownload       = "vms.iso.download"
	JobKindVMFileDelete     = "vms.iso.delete"
	JobKindVMBridge         = "vms.bridge"
)

// vmCreateParams are a create job's parameters; the password waits in
// jobSecrets (job parameters are kept in the job history).
type vmCreateParams struct {
	Spec        vms.Spec           `json:"spec"`
	Start       bool               `json:"start"`
	Downloads   []vms.DownloadArgs `json:"downloads,omitempty"`
	PasswordRef string             `json:"passwordRef,omitempty"`
}

type vmUpdateParams struct {
	vms.UpdateArgs
	PasswordRef string `json:"passwordRef,omitempty"`
}

// VMJobResult is what VM jobs return.
type VMJobResult struct {
	VM       *vms.VM  `json:"vm,omitempty"`
	Warnings []string `json:"warnings"`
	Message  string   `json:"message,omitempty"`
}

func vmLock(raw json.RawMessage) string {
	var p struct {
		ID   string   `json:"id"`
		Spec vms.Spec `json:"spec"`
	}
	_ = json.Unmarshal(raw, &p)
	if p.ID == "" {
		p.ID = p.Spec.ID
	}
	return "vm:" + p.ID
}

func call(jc *jobs.Context, pc *priv.Client, d time.Duration, op string, args, out any) error {
	ctx, cancel := context.WithTimeout(jc, d)
	defer cancel()
	return pc.Call(ctx, op, args, out)
}

// followVMTask reports a download or import running in hardyd-priv until
// it's over, scaled into from..to percent.
func followVMTask(jc *jobs.Context, pc *priv.Client, t *vms.Task, from, to float64) error {
	if t == nil {
		return nil
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		var res priv.VMTaskResult
		if err := call(jc, pc, 15*time.Second, priv.OpVMsTask, vms.TaskArgs{ID: t.ID}, &res); err != nil {
			return err
		}
		if res.Task == nil {
			return fmt.Errorf("lost track of %s", t.File)
		}
		jc.Progress(from+(to-from)*res.Task.Progress/100, res.Task.Message)
		if res.Task.Done {
			if res.Task.Error != "" {
				return fmt.Errorf("%s", res.Task.Error)
			}
			return nil
		}
		select {
		case <-jc.Done():
			return jc.Err()
		case <-tick.C:
		}
	}
}

// waitStopped follows a graceful shutdown for up to limit.
func waitStopped(jc *jobs.Context, pc *priv.Client, id string, limit time.Duration) (*vms.VM, bool, error) {
	deadline := time.Now().Add(limit)
	for {
		var v vms.VM
		if err := call(jc, pc, 30*time.Second, priv.OpVMsGet, priv.VMRef{ID: id}, &v); err != nil {
			return nil, false, err
		}
		if v.State == "stopped" || v.State == "crashed" {
			return &v, true, nil
		}
		if time.Now().After(deadline) {
			return &v, false, nil
		}
		select {
		case <-jc.Done():
			return nil, false, jc.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func registerVMJobs(m *jobs.Manager, pc *priv.Client) {
	reg := func(name string, lock bool, run jobs.RunFunc) {
		k := jobs.Kind{Name: name, AdminOnly: true, Run: run}
		if lock {
			k.LockKey = vmLock
		}
		m.Register(k)
	}

	reg(JobKindVMCreate, true, func(jc *jobs.Context) (any, error) {
		var p vmCreateParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		password := ""
		if p.PasswordRef != "" {
			pw, ok := jobSecrets.take(p.PasswordRef)
			if !ok {
				return nil, fmt.Errorf("the password for this VM was lost (HardyOS restarted); start again")
			}
			password = pw
		}
		s := p.Spec
		// 1. Downloads into the ISO library (made on the VM's pool if
		// there's none yet).
		for i, d := range p.Downloads {
			d.Pool = s.Pool
			jc.Progress(2, "Starting the download of "+lastSegment(d.URL))
			var res priv.VMTaskResult
			if err := call(jc, pc, time.Minute, priv.OpVMsISODownload, d, &res); err != nil {
				return nil, err
			}
			step := 50.0 / float64(len(p.Downloads))
			if err := followVMTask(jc, pc, res.Task, 2+step*float64(i), 2+step*float64(i+1)); err != nil {
				return nil, err
			}
		}
		// 2. The home network's bridge, the first time a VM needs it.
		if s.NeedsBridge() {
			var caps vms.Capabilities
			if err := call(jc, pc, time.Minute, priv.OpVMsCapabilities, nil, &caps); err != nil {
				return nil, err
			}
			if caps.Bridge == "" {
				jc.Progress(52, "Putting the server's network on a bridge for VMs (the network restarts for a moment)")
				if err := call(jc, pc, 5*time.Minute, priv.OpVMsBridge, nil, nil); err != nil {
					return nil, err
				}
			}
		}
		// 3. The VirtIO drivers disc for Windows.
		if s.NeedsVirtio() {
			jc.Progress(55, "Getting the VirtIO drivers disc")
			var res priv.VMTaskResult
			if err := call(jc, pc, time.Minute, priv.OpVMsISOVirtio, priv.VMVirtioArgs{Pool: s.Pool}, &res); err != nil {
				return nil, err
			}
			if err := followVMTask(jc, pc, res.Task, 55, 75); err != nil {
				return nil, fmt.Errorf("downloading the VirtIO drivers disc: %w", err)
			}
		}
		// 4. The VM itself.
		jc.Progress(76, "Creating "+s.Name)
		var created vms.Result
		if err := call(jc, pc, 5*time.Minute, priv.OpVMsCreate, vms.CreateArgs{Spec: s, Password: password}, &created); err != nil {
			return nil, err
		}
		// 5. Disk images.
		for _, d := range s.Disks {
			if d.Import == nil {
				continue
			}
			jc.Progress(80, "Copying "+d.Import.File+" into "+d.Name)
			var res priv.VMTaskResult
			if err := call(jc, pc, time.Minute, priv.OpVMsImport, vms.ImportArgs{ID: s.ID, Disk: d.Name}, &res); err != nil {
				return nil, err
			}
			if err := followVMTask(jc, pc, res.Task, 80, 97); err != nil {
				return nil, &jobs.FailedWith{Err: fmt.Errorf("the VM was created, but importing its disk failed: %w", err), Result: VMJobResult{VM: created.VM, Warnings: created.Warnings}}
			}
		}
		out := VMJobResult{VM: created.VM, Warnings: created.Warnings}
		if p.Start {
			jc.Progress(98, "Starting "+s.Name)
			var started vms.Result
			if err := call(jc, pc, 5*time.Minute, priv.OpVMsStart, priv.VMRef{ID: s.ID}, &started); err != nil {
				return nil, &jobs.FailedWith{Err: fmt.Errorf("the VM was created but didn't start: %w", err), Result: out}
			}
			out.VM = started.VM
			out.Warnings = append(out.Warnings, started.Warnings...)
		}
		return out, nil
	})

	reg(JobKindVMUpdate, true, func(jc *jobs.Context) (any, error) {
		var p vmUpdateParams
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		args := p.UpdateArgs
		if p.PasswordRef != "" {
			pw, ok := jobSecrets.take(p.PasswordRef)
			if !ok {
				return nil, fmt.Errorf("the new password was lost (HardyOS restarted); enter it again")
			}
			args.Password = pw
		}
		if args.Spec.NeedsBridge() {
			var caps vms.Capabilities
			if err := call(jc, pc, time.Minute, priv.OpVMsCapabilities, nil, &caps); err != nil {
				return nil, err
			}
			if caps.Bridge == "" {
				jc.Progress(20, "Putting the server's network on a bridge for VMs (the network restarts for a moment)")
				if err := call(jc, pc, 5*time.Minute, priv.OpVMsBridge, nil, nil); err != nil {
					return nil, err
				}
			}
		}
		if args.Spec.NeedsVirtio() {
			var res priv.VMTaskResult
			if err := call(jc, pc, time.Minute, priv.OpVMsISOVirtio, priv.VMVirtioArgs{Pool: args.Spec.Pool}, &res); err != nil {
				return nil, err
			}
			if err := followVMTask(jc, pc, res.Task, 25, 80); err != nil {
				return nil, err
			}
		}
		jc.Progress(85, "Saving the changes")
		var r vms.Result
		if err := call(jc, pc, 5*time.Minute, priv.OpVMsUpdate, args, &r); err != nil {
			return nil, err
		}
		return VMJobResult{VM: r.VM, Warnings: r.Warnings}, nil
	})

	reg(JobKindVMStart, true, func(jc *jobs.Context) (any, error) {
		var p priv.VMRef
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(30, "Starting")
		var r vms.Result
		if err := call(jc, pc, 5*time.Minute, priv.OpVMsStart, p, &r); err != nil {
			return nil, err
		}
		return VMJobResult{VM: r.VM, Warnings: r.Warnings}, nil
	})

	reg(JobKindVMStop, true, func(jc *jobs.Context) (any, error) {
		var p priv.VMRef
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(10, "Asking the guest to shut down")
		if err := call(jc, pc, time.Minute, priv.OpVMsStop, vms.StopArgs{ID: p.ID}, nil); err != nil {
			return nil, err
		}
		v, done, err := waitStopped(jc, pc, p.ID, 3*time.Minute)
		if err != nil {
			return nil, err
		}
		if !done {
			return VMJobResult{VM: v, Warnings: []string{"The VM is still shutting down. If it doesn't, use Turn off."},
				Message: "still shutting down"}, nil
		}
		return VMJobResult{VM: v, Warnings: []string{}}, nil
	})

	simple := func(name, op string, mk func(id string) any, msg string) {
		reg(name, true, func(jc *jobs.Context) (any, error) {
			var p priv.VMRef
			if err := jc.Params(&p); err != nil {
				return nil, err
			}
			jc.Progress(30, msg)
			var raw json.RawMessage
			if err := call(jc, pc, 3*time.Minute, op, mk(p.ID), &raw); err != nil {
				return nil, err
			}
			var v vms.VM
			if call(jc, pc, 30*time.Second, priv.OpVMsGet, p, &v) == nil {
				return VMJobResult{VM: &v, Warnings: []string{}}, nil
			}
			return VMJobResult{Warnings: []string{}}, nil
		})
	}
	simple(JobKindVMForceStop, priv.OpVMsStop, func(id string) any { return vms.StopArgs{ID: id, Force: true} }, "Turning it off")
	simple(JobKindVMRestart, priv.OpVMsRestart, func(id string) any { return vms.RestartArgs{ID: id} }, "Restarting")
	simple(JobKindVMReset, priv.OpVMsRestart, func(id string) any { return vms.RestartArgs{ID: id, Force: true} }, "Resetting")

	reg(JobKindVMDelete, true, func(jc *jobs.Context) (any, error) {
		var p vms.DeleteArgs
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(30, "Deleting")
		if err := call(jc, pc, 10*time.Minute, priv.OpVMsDelete, p, nil); err != nil {
			return nil, err
		}
		return VMJobResult{Warnings: []string{}}, nil
	})
	reg(JobKindVMKeptDelete, false, func(jc *jobs.Context) (any, error) {
		var p vms.DeleteKeptArgs
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		return VMJobResult{Warnings: []string{}}, call(jc, pc, 10*time.Minute, priv.OpVMsDeleteKept, p, nil)
	})
	reg(JobKindVMSnapshot, true, func(jc *jobs.Context) (any, error) {
		var p vms.SnapshotArgs
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(30, "Taking the snapshot")
		var sn vms.Snapshot
		if err := call(jc, pc, 2*time.Minute, priv.OpVMsSnapshot, p, &sn); err != nil {
			return nil, err
		}
		w := []string{}
		if !sn.Consistent {
			w = append(w, "The VM was running without the guest agent, so this snapshot is like pulling the plug: fine for most systems, but databases may need to recover.")
		}
		return map[string]any{"snapshot": sn, "warnings": w}, nil
	})
	reg(JobKindVMSnapshotDelete, true, func(jc *jobs.Context) (any, error) {
		var p vms.DeleteSnapshotArgs
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		return VMJobResult{Warnings: []string{}}, call(jc, pc, 5*time.Minute, priv.OpVMsSnapshotDelete, p, nil)
	})
	reg(JobKindVMRollback, true, func(jc *jobs.Context) (any, error) {
		var p vms.RollbackArgs
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		jc.Progress(30, "Going back to "+p.Snapshot)
		var v vms.VM
		if err := call(jc, pc, 10*time.Minute, priv.OpVMsRollback, p, &v); err != nil {
			return nil, err
		}
		return VMJobResult{VM: &v, Warnings: []string{}}, nil
	})
	m.Register(jobs.Kind{Name: JobKindVMDownload, AdminOnly: true, Run: func(jc *jobs.Context) (any, error) {
		var p vms.DownloadArgs
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		var res priv.VMTaskResult
		if err := call(jc, pc, time.Minute, priv.OpVMsISODownload, p, &res); err != nil {
			return nil, err
		}
		if err := followVMTask(jc, pc, res.Task, 0, 100); err != nil {
			return nil, err
		}
		file := ""
		if res.Task != nil {
			file = res.Task.File
		}
		return map[string]string{"file": file}, nil
	}})
	m.Register(jobs.Kind{Name: JobKindVMFileDelete, AdminOnly: true, Run: func(jc *jobs.Context) (any, error) {
		var p vms.DeleteFileArgs
		if err := jc.Params(&p); err != nil {
			return nil, err
		}
		return map[string]bool{"deleted": true}, call(jc, pc, time.Minute, priv.OpVMsISODelete, p, nil)
	}})
	m.Register(jobs.Kind{Name: JobKindVMBridge, AdminOnly: true, LockKey: func(json.RawMessage) string { return "network" },
		Run: func(jc *jobs.Context) (any, error) {
			jc.Progress(20, "Putting the server's network on a bridge (the network restarts for a moment)")
			var res priv.VMBridgeResult
			if err := call(jc, pc, 5*time.Minute, priv.OpVMsBridge, nil, &res); err != nil {
				return nil, err
			}
			return res, nil
		}})
}
