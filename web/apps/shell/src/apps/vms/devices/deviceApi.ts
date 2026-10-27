import type { DeviceInventory, DevicesCheckResult, GPUInfo, NvidiaStatus, VGPUUpload, VMDevice } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { ApiFailure, api, unwrap } from "../../../api";

/** The device inventory (IOMMU, PCI, USB, GPUs). */
export function useDevices() {
  return useQuery({ queryKey: ["devices"], queryFn: () => unwrap(api.GET("/devices")), refetchInterval: 15_000 });
}

/** The NVIDIA driver, toolkit and vGPU driver state, with the current task. */
export function useNvidia(fast = false) {
  return useQuery({
    queryKey: ["devices-nvidia"],
    queryFn: () => unwrap(api.GET("/devices/nvidia")),
    refetchInterval: fast ? 2_000 : 30_000,
  });
}

/**
 * Asks hardyd whether these devices can go to the VM (nothing changes) and
 * returns the problems in plain words. Re-checks when the list changes.
 */
export function useDeviceCheck(vm: string, devices: VMDevice[]) {
  const key = JSON.stringify(devices);
  const [result, setResult] = useState<DevicesCheckResult | null>(null);
  useEffect(() => {
    let live = true;
    if (devices.length === 0) {
      setResult({ ok: true, problems: [] });
      return;
    }
    const t = setTimeout(() => {
      unwrap(api.POST("/devices/check", { body: { vm: vm || "new-vm", devices } }))
        .then((r) => live && setResult(r))
        .catch(() => live && setResult(null));
    }, 250);
    return () => {
      live = false;
      clearTimeout(t);
    };
    // `key` stands for `devices` (a new array each render).
  }, [vm, key]);
  return result;
}

/** A GPU's display name: "NVIDIA Quadro RTX 4000". */
export function gpuName(g: GPUInfo): string {
  const vendor = { nvidia: "NVIDIA", amd: "AMD", intel: "Intel", other: g.vendorName || "" }[g.vendor];
  // pci.ids names read "TU104GL [Quadro RTX 4000]": the part in brackets is the product.
  const model = g.model.replace(/^.*\[(.+)\]$/, "$1");
  return `${vendor} ${model}`.trim();
}

/** "8 GB" for a VRAM size, "" when unknown. */
export function vram(g: GPUInfo): string {
  if (g.sharedMemory) return "Shared memory";
  if (!g.vramBytes) return "";
  const gb = g.vramBytes / 2 ** 30;
  return `${gb >= 10 ? Math.round(gb) : Math.round(gb * 10) / 10} GB`;
}

/** Uploads NVIDIA's vGPU host driver, reporting progress. */
export function uploadVGPUDriver(file: File, onProgress: (pct: number) => void): Promise<VGPUUpload> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v1/devices/vgpu-driver/upload");
    xhr.setRequestHeader("X-HardyOS-Request", "1");
    xhr.setRequestHeader("X-HardyOS-Filename", file.name);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress((e.loaded / e.total) * 100);
    xhr.onload = () => {
      let body: Partial<VGPUUpload> & { code?: string; message?: string } = {};
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        // not JSON
      }
      if (xhr.status === 200 && body.sha256) resolve(body as VGPUUpload);
      else reject(new ApiFailure(xhr.status, body.code ?? "error", body.message ?? `Upload failed (${xhr.status})`));
    };
    xhr.onerror = () => reject(new ApiFailure(0, "network", "The upload was interrupted. Check the connection and try again."));
    xhr.send(file);
  });
}

export type { DeviceInventory, NvidiaStatus };
