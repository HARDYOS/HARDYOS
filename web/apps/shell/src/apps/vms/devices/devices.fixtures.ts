import type { DeviceInventory, NvidiaStatus } from "@hardy/api-client";
import { vi } from "vitest";

/** Cade's kind of server: Intel graphics (console), a Quadro RTX 4000, an RX 580. */
export function inventory(over: Partial<DeviceInventory> = {}): DeviceInventory {
  const pci = (address: string, kind: string, name: string, extra: Partial<DeviceInventory["pci"][number]> = {}) => ({
    address,
    vendorId: "8086",
    deviceId: "0000",
    vendor: "Intel Corporation",
    name,
    class: "0x000000",
    kind,
    driver: "",
    iommuGroup: 4,
    resetMethods: [],
    resettable: true,
    bridge: false,
    bootVga: false,
    critical: "",
    owner: "",
    assigned: [],
    ...extra,
  });
  return {
    iommu: {
      enabled: true,
      groups: 20,
      cpuVendor: "intel",
      firmwareTable: true,
      flags: ["intel_iommu=on", "iommu=pt"],
      configured: false,
      active: false,
      restartNeeded: false,
      canTurnOn: true,
      kernelArgs: [],
      message: "IOMMU is on: 20 groups. Devices can be handed to virtual machines.",
    },
    groups: [
      { id: 4, devices: ["0000:00:17.0"], explanation: "Group 4 holds one device." },
      { id: 13, devices: ["0000:02:00.0", "0000:02:00.1", "0000:03:00.0"], explanation: "Group 13 holds 3 devices (…). The hardware can't keep them apart." },
    ],
    pci: [
      pci("0000:00:17.0", "SATA controller", "Cannon Lake PCH SATA AHCI Controller", { critical: "Holds the boot disk (sda), which the server runs from." }),
      pci("0000:03:00.0", "Ethernet network port", "I210 Gigabit Network Connection", { iommuGroup: 13 }),
    ],
    usb: [
      { port: "1-2", bus: 1, dev: 3, vendorId: "046d", productId: "c52b", manufacturer: "Logitech, Inc.", product: "USB Receiver", speed: "12", hub: false, critical: "", owner: "", assigned: [] },
      { port: "1-3", bus: 1, dev: 4, vendorId: "05e3", productId: "0610", manufacturer: "", product: "USB2.0 Hub", speed: "480", hub: true, critical: "", owner: "", assigned: [] },
    ],
    gpus: [
      {
        address: "0000:00:02.0",
        vendor: "intel",
        vendorName: "Intel Corporation",
        model: "CoffeeLake-S GT2 [UHD Graphics 630]",
        vramBytes: 0,
        sharedMemory: true,
        functions: [{ address: "0000:00:02.0", kind: "Graphics card", driver: "i915" }],
        driver: "i915",
        bootVga: true,
        iommuGroup: 2,
        owner: { kind: "apps", label: "Docker apps" },
        users: [],
        assigned: [],
        problem: "",
        hints: [],
        vgpu: null,
      },
      {
        address: "0000:01:00.0",
        vendor: "nvidia",
        vendorName: "NVIDIA Corporation",
        model: "TU104GL [Quadro RTX 4000]",
        vramBytes: 8 * 2 ** 30,
        sharedMemory: false,
        functions: [
          { address: "0000:01:00.0", kind: "Graphics card", driver: "nvidia" },
          { address: "0000:01:00.1", kind: "Audio (HDMI/DisplayPort)", driver: "snd_hda_intel" },
        ],
        driver: "nvidia",
        bootVga: false,
        iommuGroup: 12,
        owner: { kind: "apps", label: "Docker apps" },
        users: [{ pid: 42, process: "jellyfin", app: "jellyfin", container: true }],
        assigned: ["gaming"],
        problem: "",
        hints: [],
        vgpu: null,
      },
      {
        address: "0000:05:00.0",
        vendor: "nvidia",
        vendorName: "NVIDIA Corporation",
        model: "TU102GL [Quadro RTX 6000/8000]",
        vramBytes: 24 * 2 ** 30,
        sharedMemory: false,
        functions: [{ address: "0000:05:00.0", kind: "Graphics card", driver: "nvidia" }],
        driver: "nvidia",
        bootVga: false,
        iommuGroup: 20,
        owner: { kind: "vgpu", label: "vGPU slices (1 in use)" },
        users: [],
        assigned: [],
        problem: "",
        hints: [],
        vgpu: {
          mode: "mdev",
          hostDriver: true,
          vfs: 0,
          maxVfs: 0,
          types: [{ id: "nvidia-256", name: "GRID RTX6000-4Q", description: "", available: 5, framebufferMb: 4096, maxInstances: 6 }],
          instances: [
            { id: "11111111-2222-5333-8444-555555555555", type: "nvidia-256", parent: "0000:05:00.0", vm: "office" },
            { id: "21111111-2222-5333-8444-555555555555", type: "nvidia-256", parent: "0000:05:00.0", vm: "" },
          ],
        },
      },
    ],
    stuck: [],
    ...over,
  };
}

export function nvidiaStatus(over: Partial<NvidiaStatus> = {}): NvidiaStatus {
  return {
    nvidiaGpus: 2,
    installed: false,
    loaded: false,
    version: "",
    toolkit: false,
    nouveau: true,
    restartNeeded: false,
    packages: ["nvidia-driver", "nvidia-container-toolkit"],
    consent: null,
    licence: null,
    vgpu: null,
    vgpuHostDriver: false,
    task: null,
    ...over,
  };
}

export type Call = { method: string; path: string; body: unknown };

/** Stubs fetch with handlers keyed by "METHOD /path" (or "/path" for GET). */
export function serve(routes: Record<string, unknown | ((body: unknown) => unknown)>, calls: Call[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request) => {
      const url = new URL(input.url);
      const path = url.pathname.replace("/api/v1", "");
      const body = input.method !== "GET" ? await input.clone().json().catch(() => null) : null;
      calls.push({ method: input.method, path, body });
      const h = routes[`${input.method} ${path}`] ?? (input.method === "GET" ? routes[path] : undefined);
      if (h === undefined) return new Response(JSON.stringify({ code: "not_found", message: path }), { status: 404 });
      const data = typeof h === "function" ? (h as (b: unknown) => unknown)(body) : h;
      const status = (data as { job?: unknown })?.job ? 202 : 200;
      return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
    }),
  );
}
