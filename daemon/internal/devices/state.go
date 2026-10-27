package devices

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/hardyos/hardyos/daemon/internal/rootfile"
)

// state records which devices are lent to which VM, so they can be given
// back after the VM stops, and after hardyd-priv itself restarts. It is
// kept in /run (root's directory): bindings and vGPU instances end with
// the boot, and so does the file. A file from another boot is void.
type state struct {
	BootID string              `json:"bootId"`
	VMs    map[string]*vmState `json:"vms"`
	Stuck  []StuckDevice       `json:"stuck"`
}

// Phases of a VM's devices.
const (
	phasePreparing = "preparing" // being set up; undone if hardyd-priv stops half way
	phaseReady     = "ready"
)

type vmState struct {
	Phase   string     `json:"phase"`
	Devices []Device   `json:"devices"`
	Bound   []boundDev `json:"bound"`   // PCI functions HardyOS moved to vfio-pci
	GPUs    []string   `json:"gpus"`    // whole GPUs (first function)
	Mdevs   []mdevInst `json:"mdevs"`   // vGPU instances created
	VFTypes []string   `json:"vfTypes"` // NVIDIA virtual functions given a vGPU type
	USB     []string   `json:"usb"`     // USB devices (vendor:product or port)
	// Helpers are services stopped while a GPU changed hands, to start again.
	Helpers []string `json:"helpers"`
	// ReadyAt: when Prepare finished (the VM should be running soon after).
	ReadyAt time.Time `json:"readyAt"`
}

type boundDev struct {
	Address string `json:"address"`
	// Driver is the one it had before ("" for none).
	Driver string `json:"driver"`
	// Companion: in the IOMMU group of a device the VM asked for, held
	// away from the server but not given to the VM.
	Companion bool `json:"companion,omitempty"`
}

type mdevInst struct {
	UUID   string `json:"uuid"`
	Parent string `json:"parent"`
	Type   string `json:"type"`
}

func (h *Host) stateFile() string { return h.path(filepath.Join(h.stateDir(), "state.json")) }

// loadState reads the state; a missing, foreign or other-boot file is empty.
func (h *Host) loadState() *state {
	st := &state{BootID: h.bootID(), VMs: map[string]*vmState{}}
	b, err := rootfile.ReadFile(h.stateFile())
	if err != nil {
		return st
	}
	var old state
	if json.Unmarshal(b, &old) != nil || old.BootID != st.BootID {
		return st
	}
	if old.VMs != nil {
		st.VMs = old.VMs
	}
	st.Stuck = old.Stuck
	return st
}

func (h *Host) saveState(st *state) error {
	if err := os.MkdirAll(filepath.Dir(h.stateFile()), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := h.stateFile() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.stateFile())
}

// owners maps everything lent out (PCI addresses, mdev UUIDs, USB IDs) to
// the VM that has it.
func (st *state) owners() map[string]string {
	out := map[string]string{}
	for vm, v := range st.VMs {
		for _, b := range v.Bound {
			out[b.Address] = vm
		}
		for _, g := range v.GPUs {
			out[g] = vm
		}
		for _, m := range v.Mdevs {
			out[m.UUID] = vm
		}
		for _, a := range v.VFTypes {
			out[a] = vm
		}
		for _, u := range v.USB {
			out[u] = vm
		}
	}
	return out
}
