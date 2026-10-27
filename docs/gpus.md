# Graphics cards and devices for VMs

HardyOS shares the server's graphics cards between **Docker apps** (Jellyfin,
Plex, Immich, AI apps) and **virtual machines**, and can hand PCI and USB
devices to VMs. Everything is in **Control Panel › Devices & GPUs**; the New
VM wizard has the same choices on its *Devices* step.

## The one rule: a card is with apps or with one VM

- A graphics card normally stays with the server, on its own driver, so
  Docker apps can use it.
- When a VM that was given the card **starts**, HardyOS takes the card (and
  its other parts, like HDMI audio) away from the server and gives it to the
  VM.
- When that VM **stops**, the card goes straight back to Docker apps.
- If an app is using the card right now, the VM doesn't start, and HardyOS
  tells you which app: stop the app (App Store › Stop), then start the VM.
- Only one running VM can have a whole card. Several VMs can share a card
  only as vGPU slices (below).

The card's badge in the Devices view says who has it: *Docker apps*, *VM
Gaming PC*, *vGPU slices*, *No driver loaded*, or *Needs a restart to come
back*.

## Turn on passthrough (IOMMU)

Handing PCI devices and graphics cards to VMs needs the processor's IOMMU
(Intel VT-d, AMD-Vi).

1. In the server's BIOS/UEFI settings, enable **VT-d** (Intel) or **AMD-Vi /
   IOMMU** (AMD), and virtualization (VT-x / SVM).
2. In Devices & GPUs, click **Turn on IOMMU**. HardyOS adds
   `intel_iommu=on iommu=pt` (Intel) or `amd_iommu=on iommu=pt` (AMD) to the
   boot settings on every boot disk. These settings are kept through updates.
3. Restart the server.

If the card still says IOMMU is off after the restart, the BIOS setting is
off. USB devices can go to VMs without IOMMU.

## IOMMU groups, in plain words

The hardware puts devices in groups it can't keep apart. A device can only go
to a VM together with everything else in its group:

- A graphics card and its HDMI audio are usually one group: they go to the VM
  together. That's normal.
- Sometimes a group also holds an unrelated device (a second network port, a
  USB controller). While the VM runs, that device is taken from the server
  too (it's not given to the VM, just held). The Devices view explains each
  group.
- If a group holds something the server needs (its boot disk controller, its
  network port), nothing in that group can go to a VM. Moving the card to
  another slot often puts it in a group of its own.

## Devices HardyOS keeps for itself

These are never given to a VM, and the pickers say why:

- The controller of the boot disks, of disks in your storage pools, and of
  disks with a filesystem the server has mounted or with its swap. HardyOS
  looks through every layer: encrypted (LUKS) disks, software RAID (md),
  multipath and LVM devices, and NVMe drives with more than one path, so
  every controller such a disk is reached through stays with the server.
- The network port the server's own address uses (also under a bridge,
  bond or VLAN).
- USB devices on those paths (a boot USB stick, a USB network adapter), and
  USB hubs (pick the devices on the hub instead).
- The server's only graphics card (it shows the console). With two cards,
  either can go; the console just goes blank while a VM has the card that
  drives it.

## USB devices

Pick a device and choose how the VM finds it:

- **This device, in any port**: by its vendor and product ID. The VM still
  starts when it's unplugged and gets it when it's plugged in. If two
  devices with the same ID are plugged in, or the server itself uses one
  with that ID (a boot stick), pick by port instead.
- **Whatever is plugged into port 1-4.2**: handy for two identical sticks.

## NVIDIA cards for Docker apps

Docker apps need NVIDIA's driver to use an NVIDIA card. HardyOS can install
it for you (it doesn't come with HardyOS because of NVIDIA's licence):

1. **Get the NVIDIA driver**: HardyOS adds Debian's *non-free* packages and
   NVIDIA's container toolkit repository, then downloads the packages
   (about 400 MB). Nothing is installed yet.
2. **Read NVIDIA's licence**: the text comes from the downloaded packages.
   Tick *I have read NVIDIA's licence and agree to it* and click **Agree and
   install**. HardyOS records who agreed, when and to which driver version
   (also in the audit log).
3. Exactly the packages that were downloaded and shown are installed (the
   same versions, nothing fetched again) and built for the server's kernel
   (a few minutes; the log is shown). Restart if asked (the basic
   open-source driver was running).

Only NVIDIA's container toolkit is taken from NVIDIA's repository; HardyOS
pins everything else there away, so it can never replace one of Debian's
packages.

Updates rebuild the driver inside the new version before it's offered. If
that fails (for example the server is offline), the update isn't installed
and HardyOS stays on the current version, with the reason on the Updates
page. Two more cases:

- **The new version would bring another driver version.** Your agreement
  covers the version you agreed to, so the update stops and says so. Click
  **Get the NVIDIA driver** again, read and agree to the new licence (that
  installs the new driver here too), then install the update.
- **The driver can't be built for the new version.** Click **Update without
  the NVIDIA driver this time** and confirm (it's recorded in the audit
  log). The next update then goes ahead without the NVIDIA drivers; on the
  new version the card says *Install the NVIDIA driver again*. Until then
  Docker apps can't use NVIDIA cards and vGPU slices don't work.

**Remove the driver** in the same card undoes it.

A card lent to a VM uses the VM's own driver; that's unaffected.

## vGPU slices (NVIDIA's official vGPU software)

Some NVIDIA cards can be split into slices so several VMs each get part of
the card. HardyOS supports this only with **NVIDIA's own vGPU software**,
which you license from NVIDIA:

- Which cards: the ones NVIDIA supports for vGPU (data-center cards like the
  A16/A40/L4, and some workstation cards like the Quadro RTX 6000/8000 and
  RTX A5000/A6000). GeForce cards and the Quadro RTX 4000 aren't supported
  for vGPU by NVIDIA; they go to VMs as whole cards.
- Get NVIDIA's **KVM host driver** (`NVIDIA-Linux-x86_64-<version>-vgpu-kvm.run`)
  from NVIDIA's licensing portal (R535 or newer). The guest driver goes
  inside each VM; licensing the guests is between you and NVIDIA.
- In **vGPU slices with NVIDIA's vGPU software**, upload the file. The
  server works out its SHA-256 while receiving it; compare it with the one
  on NVIDIA's licensing portal. If the checksum isn't in HardyOS's list of
  checked NVIDIA drivers (the list is empty unless HardyOS's maintainers
  have added NVIDIA's checksums), you're warned: the file runs as root now
  and again on every update. Type the driver's version to confirm, confirm
  you have the licence, and it's installed and built for the kernel. Who
  installed which file (name, version, SHA-256) is written to the system
  journal and to an install log that is only ever added to
  (`/var/lib/hardyos-gpu/vgpu-install.log`). It replaces the NVIDIA driver
  for Docker apps (the two can't be installed together).
- Each supported card then lists its slice types with how many are free
  (*GRID RTX6000-4Q · 4 GB each · 5 of 6 free*). On newer cards, click
  **Turn on slices** first.
- In the VM wizard pick **A slice (vGPU)** and a size. The slice is made when
  the VM starts and removed when it stops; the VM gets the same slice ID
  every time.

## AMD and Intel graphics

- **AMD Radeon** cards go to VMs whole. Some generations (RX 400/500, Vega,
  RX 5000) can't reset themselves after a VM stops, so the card may only come
  back after a server restart. HardyOS warns on those models; the
  *vendor-reset* kernel module fixes it. If a card doesn't come back, the
  Devices view says so and **Try again** retries.
- **Intel** integrated graphics can be split into virtual GPUs when its
  driver supports SR-IOV (newer chips with i915/xe SR-IOV). HardyOS detects
  it and offers **Turn on slices**; otherwise the iGPU stays with Docker apps.
  The new slices come up without a host driver, so they only ever go to
  VMs. Slices can't be switched while a VM or the server's own driver uses
  one, or on a card the server needs.

## GPU ROM files

Some cards need a ROM file to start inside a VM. Put it, as root, in
`/var/lib/hardyos/root/vm-roms/` (named `something.rom` or `.bin`, at most
8 MB) and choose it for the card in the VM's devices. HardyOS only uses
regular files root put there, and gives the VM a checked copy.

## Cade's cards

| Card | Docker apps | Whole card to a VM | vGPU slices |
| --- | --- | --- | --- |
| NVIDIA GeForce | With the NVIDIA driver | Yes | No (not supported by NVIDIA) |
| NVIDIA Quadro RTX 4000 | With the NVIDIA driver | Yes (with its audio and USB-C parts) | No (not supported by NVIDIA) |
| AMD Radeon | Yes (built-in driver) | Yes; may need vendor-reset | No |

## If something goes wrong

- **"in use by the app …"**: stop that app, then start the VM.
- **"shares IOMMU group … with …"**: try another PCIe slot, or give the VM
  that device too if it's not needed by the server.
- **A card shows "Needs a restart to come back"**: restart the server (or
  install vendor-reset for AMD cards), then **Try again**.
- **The NVIDIA install failed**: open *Show the log* in the card; most often
  the server was offline or the kernel headers were missing.
- **"another system task is running"**: an update, a boot menu change or a
  driver install is in progress; they take turns. Try again when it's done.
- **A device "is still hanging in the kernel"**: its driver didn't let go of
  it. Restart the server to get it back.
