// Package devices hands PCI, USB and GPU devices (whole or as vGPU slices) to
// virtual machines and back to the host. It runs inside hardyd-priv. See
// docs/plans/vms.md section 2. This file is the contract the VM engine
// (internal/vms) codes against; the behaviour lives in the other files
// (Host implements Manager).
package devices

import (
	"context"
	"errors"
	"strings"
)

// ErrNotImplemented marks contract operations not built yet.
var ErrNotImplemented = errors.New("not implemented yet")

// Kinds of device a VM can be given.
const (
	KindPCI  = "pci"  // a whole PCI device (and, if needed, its IOMMU group)
	KindUSB  = "usb"  // a USB device by vendor:product or by port
	KindGPU  = "gpu"  // a whole GPU (with its audio function)
	KindVGPU = "vgpu" // a vGPU slice of a GPU
)

// Device is one device in a VM's spec.
type Device struct {
	Kind string `json:"kind"`
	// ID: PCI address "0000:01:00.0" (pci, gpu, vgpu parent), or USB
	// "vendor:product" ("1234:abcd") or "bus-port" ("1-4.2").
	ID string `json:"id"`
	// VGPUType: the slice type for vgpu, as listed in the inventory
	// (GPU.VGPU.Types[].ID), e.g. "nvidia-256".
	VGPUType string `json:"vgpuType,omitempty"`
	// ROMFile: an optional GPU ROM file name from the device ROM library
	// (RomDir).
	ROMFile string `json:"romFile,omitempty"`
	// Primary: a GPU that is the VM's main display. The VM engine then
	// gives the VM no emulated display (video model none); the fragment
	// itself is the same.
	Primary bool `json:"primary,omitempty"`
}

// Prepared is what Prepare set up for one device, for the domain XML.
type Prepared struct {
	Device Device `json:"device"`
	// XML is the libvirt <hostdev> fragment for the device (several, one
	// per function, for a GPU), indented by two spaces, ready to go inside
	// <devices>.
	XML string `json:"xml"`
	// MdevUUID is the vGPU instance created for a vgpu device (mdev mode).
	MdevUUID string `json:"mdevUuid,omitempty"`
	// Addresses are the host PCI addresses the VM actually gets (a GPU's
	// functions, or the virtual function chosen for an SR-IOV slice).
	Addresses []string `json:"addresses,omitempty"`
}

// Manager prepares devices for a VM and gives them back afterwards.
type Manager interface {
	// Check validates devices for a VM without changing anything (wrong IDs,
	// devices the host needs, IOMMU off, GPU in use by an app...). A
	// Problems error lists every reason in plain words.
	Check(ctx context.Context, vm string, ds []Device) error
	// Prepare binds devices to vfio-pci / creates vGPU instances just before
	// the VM starts and returns the XML fragments to put in its domain.
	// On failure nothing stays changed.
	Prepare(ctx context.Context, vm string, ds []Device) ([]Prepared, error)
	// Release gives a stopped VM's devices back (GPUs return to the host
	// driver and Docker apps; vGPU instances are removed). Releasing a VM
	// that holds nothing is a no-op. A device that couldn't be given back
	// is reported in the error and shows as "needs a restart" in the
	// inventory.
	Release(ctx context.Context, vm string) error
}

// Reconciler is implemented by Host. hardyd-priv calls Reconcile at start
// (and the Devices view can ask for it): devices held for VMs that aren't
// running any more (hardyd-priv or a VM crashed) are given back. If the
// list of running VMs can't be read, nothing is released.
type Reconciler interface {
	Reconcile(ctx context.Context) error
}

// RunningFunc lists the names of the VMs running now (libvirt's view).
// Host.Running defaults to asking virsh; the VM engine may set its own.
type RunningFunc func(ctx context.Context) ([]string, error)

// AssignmentsFunc returns every VM's configured devices (running or not),
// so the inventory can show "assigned to Gaming PC" for a GPU that's with
// Docker apps while the VM is off. Optional (Host.Assignments).
type AssignmentsFunc func(ctx context.Context) (map[string][]Device, error)

// Problem is one reason a device can't be given to a VM.
type Problem struct {
	Device  string `json:"device"` // the Device.ID it's about ("" for the VM as a whole)
	Message string `json:"message"`
}

// Problems is the error Check and Prepare return when the devices can't be
// used as asked. Every problem is listed.
type Problems []Problem

func (p Problems) Error() string {
	msgs := make([]string, len(p))
	for i, x := range p {
		msgs[i] = x.Message
	}
	return strings.Join(msgs, "; ")
}
