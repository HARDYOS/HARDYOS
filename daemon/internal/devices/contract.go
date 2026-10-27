// Package devices hands PCI, USB and GPU devices (whole or as vGPU slices) to
// virtual machines and back to the host. It runs inside hardyd-priv. See
// docs/plans/vms.md section 2. This file is the contract the VM engine
// (internal/vms) codes against; the behaviour lives in the other files.
package devices

import (
	"context"
	"errors"
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
	// VGPUType: the slice type for vgpu, e.g. "nvidia-256".
	VGPUType string `json:"vgpuType,omitempty"`
	// ROMFile: an optional GPU ROM file name from the device ROM library.
	ROMFile string `json:"romFile,omitempty"`
	// Primary: a GPU that is the VM's main display (x-vga).
	Primary bool `json:"primary,omitempty"`
}

// Prepared is what Prepare set up for one device, for the domain XML.
type Prepared struct {
	Device Device `json:"device"`
	// XML is the libvirt <hostdev> (or similar) fragment for the device.
	XML string `json:"xml"`
	// MdevUUID is the vGPU instance created for a vgpu device.
	MdevUUID string `json:"mdevUuid,omitempty"`
}

// Manager prepares devices for a VM and gives them back afterwards.
type Manager interface {
	// Check validates devices for a VM without changing anything (wrong IDs,
	// devices the host needs, IOMMU off, GPU in use by an app...).
	Check(ctx context.Context, vm string, ds []Device) error
	// Prepare binds devices to vfio-pci / creates vGPU instances just before
	// the VM starts and returns the XML fragments to put in its domain.
	Prepare(ctx context.Context, vm string, ds []Device) ([]Prepared, error)
	// Release gives a stopped VM's devices back (GPUs return to the host
	// driver and Docker apps; vGPU instances are removed).
	Release(ctx context.Context, vm string) error
}
