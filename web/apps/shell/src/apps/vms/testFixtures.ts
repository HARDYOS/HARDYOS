import type { VMCapabilities, VMTemplate } from "@hardy/api-client";

// Templates and capabilities for the Virtual Machines tests.

export const presets = [
  { id: "light", name: "Light", summary: "", cores: 2, threads: 1, memoryMB: 4096, diskGB: 64 },
  { id: "standard", name: "Standard", summary: "", cores: 4, threads: 1, memoryMB: 8192, diskGB: 96 },
  { id: "power", name: "Power", summary: "", cores: 8, threads: 1, memoryMB: 16384, diskGB: 160 },
];

export const win11: VMTemplate = {
  id: "windows11", name: "Windows 11", summary: "With Secure Boot and a TPM.", group: "windows", os: "windows", install: "iso",
  firmware: { type: "uefi", secureBoot: true, tpm: true }, diskBus: "virtio-scsi", nicModel: "virtio", nics: 1, allowSpoofing: false, video: "vga",
  virtio: true, cloudInit: false, balloon: true, gpu: false, presets, defaultPreset: "standard", minMemoryMB: 4096, minDiskGB: 64,
  images: [{ name: "Windows 11", kind: "iso", urls: null, page: "https://www.microsoft.com/software-download/windows11" }], notes: [],
};

export const linux: VMTemplate = {
  id: "linux", name: "Linux server", summary: "Ubuntu or Debian with cloud-init.", group: "linux", os: "linux", install: "cloud",
  firmware: { type: "uefi", secureBoot: false, tpm: false }, diskBus: "virtio-scsi", nicModel: "virtio", nics: 1, allowSpoofing: false, video: "virtio",
  virtio: false, cloudInit: true, balloon: true, gpu: false,
  presets: [
    { id: "light", name: "Light", summary: "", cores: 1, threads: 1, memoryMB: 1024, diskGB: 16 },
    { id: "standard", name: "Standard", summary: "", cores: 2, threads: 1, memoryMB: 4096, diskGB: 32 },
    { id: "power", name: "Power", summary: "", cores: 8, threads: 1, memoryMB: 16384, diskGB: 128 },
  ],
  defaultPreset: "standard", minMemoryMB: 512, minDiskGB: 8,
  images: [{ name: "Ubuntu Server 24.04 LTS", kind: "disk", urls: { x86_64: "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img" } }],
  notes: [],
};

export const opnsense: VMTemplate = { ...win11, id: "opnsense", name: "OPNsense or pfSense", group: "appliance", os: "other", nics: 2, allowSpoofing: true, virtio: false, firmware: { type: "uefi", secureBoot: false, tpm: false }, minMemoryMB: 1024, minDiskGB: 8, images: [] };

export const caps: VMCapabilities = {
  supported: true, problem: "", kvm: true, arch: { arch: "x86_64", machine: "q35", sata: true, legacyBios: true },
  cpus: 16, memoryMB: 65536, pools: ["tank", "fast"], uefi: true, secureBoot: true, tpm: true, libvirt: "11.3.0",
  bridge: "", library: "tank", virtio: false, devices: null, committedMB: 0, security: "apparmor", spoofingFilter: true,
};
