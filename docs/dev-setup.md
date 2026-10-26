# Developer setup: Windows laptop with WSL2 and VMware Workstation

This is how to build HardyOS and test it in a VM on the laptop.

## 1. One-time setup in WSL2

1. Install WSL2 with Ubuntu 24.04 (PowerShell as admin): `wsl --install -d Ubuntu-24.04`
2. Install Docker: either Docker Desktop for Windows with "WSL integration"
   turned on for Ubuntu, or Docker Engine inside WSL
   (`sudo apt install docker.io && sudo usermod -aG docker $USER`, then restart WSL).
3. Inside Ubuntu, install the build tools:

   ```sh
   sudo apt update && sudo apt install -y make git curl
   # Go 1.26+
   curl -fsSL https://go.dev/dl/go1.26.0.linux-amd64.tar.gz | sudo tar -C /usr/local -xz
   echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
   # Node 22 + pnpm
   curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - && sudo apt install -y nodejs
   sudo corepack enable
   ```

4. Clone the repo **inside the WSL filesystem** (not under `/mnt/c`, which is much slower):

   ```sh
   git clone https://github.com/HARDYOS/HARDYOS.git ~/hardyos && cd ~/hardyos
   ```

## 2. Build

```sh
make test     # Go + web tests
make iso      # builds dist/hardyos-<version>-amd64.iso (15-40 min the first time)
```

The ISO is in `~/hardyos/dist/`. From Windows it's at
`\\wsl$\Ubuntu-24.04\home\<you>\hardyos\dist\`.

## 3. Test VM in VMware Workstation

Create a new VM ("Custom" wizard):

| Setting | Value |
| --- | --- |
| Guest OS | Linux, Debian 12.x 64-bit (closest match) |
| Firmware | **UEFI** (VM settings > Options > Advanced) |
| CPU | 4 cores; tick "Virtualize Intel VT-x/EPT or AMD-V/RVI" for testing VMs later |
| Memory | 8 GB (ZFS likes RAM; 4 GB minimum) |
| Network | Bridged, so the VM gets an address on your home network |
| Disks 1-2 | 2 × 32 GB NVMe (mirrored boot drives) |
| Disks 3-6 | 4 × 20 GB **SATA** (data pool) |
| Disks 7-8 | optional: 2 × 8 GB NVMe to test special vdev / SLOG |
| CD/DVD | the HardyOS ISO |

Use SATA or NVMe for the virtual disks. VMware's SCSI disks have no serial
number unless you add `disk.EnableUUID = "TRUE"` to the .vmx file, so they get
no stable `/dev/disk/by-id` name and storage pools can't use them.

### Install

1. Boot the VM from the ISO. The console shows an address like
   `https://192.168.1.57` and a code like `K7QM-4TXP`.
2. Open the address in a browser on the laptop. The browser warns about the
   certificate the first time (HardyOS makes its own); accept it.
3. Enter the code, then follow the installer: it suggests the two NVMe disks
   as a mirror. Choose a name, time zone and network, create the
   administrator, type ERASE and install.
4. When it finishes, disconnect the CD/DVD (VM settings) and click
   **Restart now**. The page switches to the sign-in screen when the
   installed system is up.

The installed system boots from GRUB on every boot disk (UEFI and BIOS), with
a menu entry per boot environment. The serial console is enabled too, which
helps with headless servers.

Locked out? On the VM console (or over SSH) as root:
`hardyctl reset-password <username>` or `hardyctl create-admin <username>`.

Tip: take a VMware snapshot right after creating the VM (before first boot)
so you can reset it between installer test runs.

Boot problems? `hardyctl boot-list` shows the boot environments and
`hardyctl boot-sync --reinstall` rewrites the boot loader and kernels on every
boot disk.

## 4. Releases and updates

Once, on the laptop that builds releases:

```sh
make release-key   # writes ~/.config/hardyos/release.key and daemon/internal/update/keys/release.pub
git add daemon/internal/update/keys/release.pub && git commit -m "Add the release signing key"
```

Back up `~/.config/hardyos/release.key` (a password manager or a USB stick in a
drawer). If it's lost, servers can't verify new updates until they get an ISO
with a new key. Never commit it.

For each release, from a clean tree:

```sh
make release       # dist/hardyos-<version>-amd64.iso and .hupd (+ .sha256)
```

Install the `.hupd` on a server from Control Panel > Updates (upload, or an
https address). It installs next to the running version and switches on the
next restart; if the new version doesn't start, the server goes back by
itself. The first server with the key must be installed from an ISO built
after the key was committed.

## 5. Fast loop without an ISO

For desktop and API work you don't need a VM:

```sh
make dev-priv     # terminal 1: root helper (as you; privileged ops need root)
make dev-daemon   # terminal 2: hardyd on :8080, state in .dev/
make dev-web      # terminal 3: desktop on http://localhost:5173 with hot reload
```
