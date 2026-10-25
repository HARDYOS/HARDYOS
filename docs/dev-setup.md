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
   # Go 1.24+
   curl -fsSL https://go.dev/dl/go1.24.7.linux-amd64.tar.gz | sudo tar -C /usr/local -xz
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
| Disk 1 | 32 GB NVMe (boot drive) |
| Disks 2-5 | 4 × 20 GB SATA or SCSI (data pool) |
| Disks 6-7 | optional: 2 × 8 GB NVMe to test special vdev / SLOG |
| CD/DVD | the HardyOS ISO |

Boot the VM. The console shows an address like `http://192.168.1.57:8080`.
Open it in a browser on the laptop to reach the web desktop.

Tip: take a VMware snapshot right after creating the VM (before first boot)
so you can reset it between installer test runs.

## 4. Fast loop without an ISO

For desktop and API work you don't need a VM:

```sh
make dev-daemon   # terminal 1: hardyd on :8080
make dev-web      # terminal 2: desktop on http://localhost:5173 with hot reload
```
