# Virtual machines and GPUs (build contract)

Cade's decisions (2026-10-26):

- A **super nice, easy UI** to build VMs and to add/edit PCI devices.
- Templates: Windows 10/11, Linux servers (cloud-init), gaming/GPU desktops,
  other OSes/appliances (Home Assistant OS, OPNsense/pfSense, TrueNAS, from ISO or
  disk image).
- VMs are **bridged onto the home network** by default (own address from the
  router); NAT and VLANs per VM as options.
- Console in a **desktop window**, plus **Moonlight/Sunshine** streaming for GPU
  gaming VMs.
- VM disks are ZFS volumes on the **pool of choice**; installer ISOs live in an
  **ISOs shared folder** (copy from Windows, or download by URL).
- GPUs: whole-GPU passthrough for any card; when a VM that owns a GPU is off, the
  GPU **goes back to Docker apps** automatically (and is taken back when the VM
  starts; refused while an app uses it). Docker apps share a GPU that stays with
  the host (NVIDIA container toolkit, `/dev/dri`).
- **vGPU slices "like Proxmox"**: officially supported vGPU cards with NVIDIA's own
  vGPU host driver, which **the user supplies** (never shipped or downloaded by
  HardyOS). *(Update 2026-10-27: the community vGPU mode for consumer/workstation
  cards first planned here was dropped from this phase; see section 2.)* No
  licence workarounds of any kind. Kernel updates rebuild the driver
  inside the new boot environment before switching; if the build fails, the
  update isn't activated.
- Built before the cluster; the cluster (decision 54) later adds live migration.

## 1. VM engine (part C)

- QEMU/KVM through **libvirt** (`libvirt-daemon-system`, `qemu-system-x86`,
  `ovmf`, `swtpm`, `qemu-utils`; arch-neutral code: firmware and machine types are
  chosen per architecture at runtime). hardyd-priv owns libvirt (root); named ops
  only: `vms.list`, `vms.get`, `vms.create`, `vms.update`, `vms.start`, `vms.stop`
  (graceful / force), `vms.restart`, `vms.delete` (confirm, keep or delete disks),
  `vms.snapshot`, `vms.snapshots`, `vms.rollback` (confirm), `vms.console`
  (returns a one-time token for the console socket), `vms.iso.*`, `vms.capabilities`.
- HardyOS builds the libvirt domain XML itself from a validated VM spec (never
  accepts XML from hardyd): CPU (host-passthrough, cores/threads), memory (fixed
  or with balloon), firmware (UEFI default; Secure Boot + TPM 2.0 via swtpm for
  Windows 11), machine q35, disks (virtio-scsi/virtio-blk, SATA for appliances),
  NICs (virtio/e1000e), cloud-init seed ISO for Linux templates, ISOs as CD-ROMs,
  VirtIO drivers ISO for Windows (downloaded once from Fedora's virtio-win, checked
  by hash), boot order, autostart with order and delay.
- Storage: each disk is a zvol `<pool>/vms/<vm>/<disk>` (volblocksize sensible
  default, thin by default); import a qcow2/raw/vmdk image into a zvol (`qemu-img
  convert` as a job with progress); snapshots are ZFS snapshots of the VM's
  datasets (crash-consistent; with the QEMU guest agent, fs-freeze first).
- ISO library: shared folder `isos` (created on demand on the chosen pool);
  download by URL as a job (https only, size limit, optional sha256), listing.
- Networking: a host bridge `br0` over the LAN interface (or bond), created by the
  network code (`internal/network`) as a first-class config option, migrating the
  host's address to the bridge safely (apply with rollback like other network
  changes); the DC's macvlan moves onto the bridge. VMs attach to the bridge
  (default), to a NAT network (libvirt `default`), or a VLAN on the bridge.
- Console: hardyd proxies the VM's VNC/SPICE over a WebSocket (one-time token from
  root, per VM, admin-only), shown in a desktop window with noVNC (or spice-html5):
  keyboard, mouse, clipboard, Ctrl+Alt+Del, fullscreen.
- Moonlight: for GPU VMs, a "Game streaming" panel: explains installing Sunshine
  in the guest (link), shows the VM's address, and optionally publishes
  Sunshine's ports through NetBird for away-from-home play (needs part A).
- Jobs + audit for every change; resource checks (memory overcommit warning, CPU).

## 2. Devices and GPUs (part D)

- `vms.capabilities`: IOMMU on/off (with the exact kernel flags to add, and a
  button that adds them to the boot config: `intel_iommu=on`/`amd_iommu=on`,
  `iommu=pt` — applied to GRUB on every boot disk via the existing boot code and
  takes effect after a restart), IOMMU groups, PCI devices (vendor, name, class,
  driver in use, group members, reset support), USB devices, GPUs.
- PCI passthrough: assign a device (or its whole IOMMU group, explained in plain
  words) to a VM; HardyOS binds it to `vfio-pci` when the VM starts and gives it
  back to its host driver when the VM stops (for GPUs: the hand-back to Docker
  apps). Refuse devices the host needs (boot disk controllers, the LAN port in
  use, the GPU driving the console if it's the only one).
- USB passthrough by vendor:product or port.
- GPUs:
  - Ownership: per GPU, "Docker apps" (host driver) or a VM; switching happens on
    VM start/stop; refused if an app container is using the GPU (check
    `nvidia-smi`/device users), with a clear message.
  - NVIDIA host driver + container toolkit for Docker apps: Debian's `nvidia-driver`
    (non-free, DKMS) installed on demand when an NVIDIA GPU is present and the
    admin agrees (licence shown), plus `nvidia-container-toolkit`; the apps engine
    (`internal/apps` GPU support) then uses it.
  - vGPU (mdev / SR-IOV): list types (`mdev_supported_types` or NVIDIA's vGPU
    SR-IOV types on Ampere+), create/remove instances, assign to VMs, show
    capacity. Works with NVIDIA's official vGPU host driver on supported cards.
  - ~~Community vGPU mode~~: **dropped from this phase** (2026-10-27). HardyOS
    supports vGPU only with NVIDIA's official vGPU host driver on cards NVIDIA
    supports for vGPU; the admin uploads that driver, HardyOS checks its hash and
    version, builds it with DKMS and manages the slices. Cards without official
    vGPU support (GeForce, Quadro RTX 4000) go to VMs as whole cards.
  - Updates: the update installer builds the vGPU (and NVIDIA) DKMS modules in the
    new boot environment; failure keeps the current version active and says why.
  - Never ship NVIDIA's driver; never build licence workarounds.
- AMD/Intel: whole-GPU passthrough (vendor-reset hint for AMD reset bugs);
  Intel SR-IOV iGPU slices when the driver supports it (detect; optional).

## 3. Web UI (parts C and D)

- **Virtual Machines** desktop app: list with status, CPU/RAM graphs, start/stop,
  console button; **New VM** wizard: 1 choose a template (Windows 11, Windows 10,
  Ubuntu/Debian server, gaming desktop, Home Assistant OS, OPNsense, other ISO,
  import a disk image), 2 name + resources with friendly presets, 3 disks (pool,
  size), 4 install media (ISO from the library, upload, URL, cloud-init user/SSH
  key), 5 network, 6 devices (GPU, PCI, USB) with plain-words explanations,
  7 review. VM page: overview, console, hardware (add/edit/remove disks, NICs,
  devices; changes needing a stop are marked), snapshots, settings (autostart,
  boot order, firmware), logs.
- **Devices** view (Control Panel or in the VMs app): GPUs with their owner
  (Docker apps / VM name / vGPU slices), IOMMU groups, USB; the NVIDIA driver
  setup flow with NVIDIA's licence, and the official vGPU host driver upload
  (the community vGPU flow was dropped from this phase).
- Follows CLAUDE.md UI rules; component tests; screenshots in `docs/images/vms/`.

## 4. Ownership and decisions

| Part | Owns | Decisions |
| --- | --- | --- |
| C VM engine, storage, network bridge, console, VMs app | `internal/vms/`, `internal/network/` bridge parts, `priv/vms_ops.go`, `api/handlers_vms*.go`, `api/vmconsole*.go`, web `apps/vms/` | 120-125 |
| D devices, GPUs, vGPU, IOMMU boot flags | `internal/devices/`, `internal/gpu/`, `priv/devices_ops.go`, `api/handlers_devices*.go`, web `apps/vms/devices/` (+ Devices view), boot flag changes in `internal/boot` (new file) | 126-130 |

Contract between C and D: a VM spec has `devices: [{kind: "pci"|"usb"|"gpu"|"vgpu",
id, ...}]`; D provides `devices.Manager` with `Prepare(ctx, vm, []Device) error`
(bind to vfio, create vGPU instances) before start and `Release(ctx, vm)` after
stop, plus `XML(device) (string, error)` fragments for the domain XML that C
inserts (C still validates the whole spec). Define these Go types first in
`internal/devices/contract.go` (part D owns the file; part C codes against it with
a fake).
