# VM polish (phase 9, build contract)

Cade's choices (2026-11-21): all four VM polish items. Builds on the VM engine
(`internal/vms`, decisions 120-143), part D devices (`internal/devices`) and
the cloud backup / replication code. Decisions 410-419. No new listener
ports; no database migration (everything new lives in root-owned state on
the pool, like the rest of a VM).

## 1. Templates and cloud-init

- **Verified image catalog** (`internal/vms/catalog.go`): named images only
  (`debian-13`, `ubuntu-24.04`, `haos`, `virtio-win`), per architecture. One
  new op `vms.catalog.fetch {image, pool}`: hardyd names an image, never a
  URL. Root downloads with a client that only talks to the image's own hosts
  (redirects included, https only, the usual "internet only" dial guard).
  Checksums come from the distribution: Ubuntu's `SHA256SUMS` with its
  detached OpenPGP signature, checked against the pinned Ubuntu cloud image
  key (fingerprint in the code); Debian's `SHA512SUMS` (Debian publishes no
  signature for cloud images, so the TLS connection to cloud.debian.org is
  the anchor); Home Assistant OS and VirtIO drivers by SHA-256 and size pinned
  in the code. A copy already in the ISO library is hashed again and reused
  when it still matches ("cached on the pool"); otherwise it's replaced.
- **One-click Linux**: templates `debian13` and `ubuntu2404` (cloud install,
  catalog image, cloud-init NoCloud seed with user, password and/or SSH keys,
  host name, CPU/RAM/disk from the wizard). The older `linux` template stays
  for existing VMs.
- **Home Assistant OS**: the `haos` template now uses the catalog (UEFI,
  official qcow2.xz).
- **Windows 11 / Windows Server 2025 unattended**: the person picks their own
  ISO (no licence handling, no product key). Root writes `autounattend.xml`
  (user, password, locale, keyboard, time zone, edition, computer name) on a
  small extra disc (`unattend` media, QEMU-owned 0600, like the cloud-init
  seed); the password is only on that disc, never in `vm.json`. The VirtIO
  drivers disc is attached and its storage/network drivers are loaded in
  Windows PE; first logon installs the VirtIO guest tools. Extra first-logon
  steps come from named hooks registered in Go (`RegisterFirstLogonHook`),
  so a later feature (Sunshine) adds its own steps without a new format.
  The installer's "press any key to boot from CD" is answered by root
  (`virsh send-key`) on the first start only.
- **Make template from VM**: a stopped VM is copied (ZFS send/receive) to
  `<pool>/vm-templates/<id>` with its spec minus identity (UUID, MACs,
  cloud-init password, TPM and NVRAM). New VMs from it get full copies of its
  disks. Ops `vms.usertemplates.{list,create,delete}`; delete needs the name.

## 2. Windows helpers

TPM 2.0 (swtpm), Secure Boot (OVMF enrolled keys) and Hyper-V enlightenments
already exist (decision 120); the Server 2025 template gets them too, and the
unattended install attaches the VirtIO disc on its own.

## 3. Snapshots and backups

- Snapshot / rollback / delete buttons exist; rollback keeps its typed-name
  confirmation.
- **Scheduled snapshots**: a per-VM schedule (hourly/daily/weekly/monthly,
  how many of each to keep) in `vm.json`, changed with its own op
  (`vms.schedule.set`, a job) and kept by every other update. hardyd-priv
  takes due snapshots every minute (`vm-auto-<kind>-<slot>`), frozen through
  the guest agent when it runs, else crash-consistent and marked, and prunes
  each kind to its count. Manual snapshots are never pruned.
- Cloud backups and replication already include VMs (fsfreeze or
  crash-consistent); the VM page shows how protected it is and the note.

## 4. Console and USB

- Console (noVNC, extended): clipboard both ways (QEMU's `qemu-vdagent`
  channel, VNC extended clipboard; the guest needs spice-vdagent), audio
  (QEMU's VNC audio extension, decoded by a small RFB subclass and played
  with Web Audio), full screen with keyboard lock.
- USB hot-plug by vendor:product on a running VM (`vms.usb.attach`,
  `vms.usb.detach`), through part D's checks (`devices.HotPlugger`), with
  "keep it for next start" adding it to the spec.
- USB controllers: the inventory says which controller each USB device is
  on; a controller passes through as a PCI device (existing path, refused
  while it holds something the server needs).

## Tests

Go unit tests with fakes (catalog against a TLS test server and the real
Ubuntu signature, unattend XML, schedules and pruning, user templates, USB
hot-plug, XML), vitest for the wizard, console audio parser and VM page. The
KVM CI job gains a second test: catalog fetch of the real Debian image, a
cloud-init VM with sound and clipboard, a scheduled snapshot, make template,
a VM from the template that boots.
