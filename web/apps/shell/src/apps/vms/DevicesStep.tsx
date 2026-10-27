import type { VMDevice, VMTemplate } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { CpuIcon, GamepadIcon, InfoIcon } from "../../icons";
import { Alert, Badge, EmptyState, Loading } from "../../ui";

/**
 * Devices (GPUs, PCI and USB) are part D's (internal/devices, web
 * apps/vms/devices/). Until its picker lands, this step reads its /devices
 * endpoint if it's there and lets a device be ticked; without it, it says
 * devices can be added later.
 */

export interface DeviceInfo {
  id: string;
  kind: VMDevice["kind"];
  name: string;
  detail?: string;
  /** Why it can't be given to a VM, in plain words. */
  blocked?: string;
}

interface DevicesResponse {
  gpus?: { id?: string; address?: string; name?: string; vendor?: string; owner?: string; blocked?: string }[];
  pci?: { id?: string; address?: string; name?: string; vendor?: string; group?: number | string; blocked?: string }[];
  usb?: { id?: string; name?: string; vendor?: string; blocked?: string }[];
}

/** Reads part D's device list, tolerating fields it may add or name differently. */
export function parseDevices(r: DevicesResponse): DeviceInfo[] {
  const out: DeviceInfo[] = [];
  for (const g of r.gpus ?? []) {
    const id = g.id ?? g.address;
    if (id) out.push({ id, kind: "gpu", name: g.name ?? "Graphics card", detail: g.owner ? `Now with ${g.owner}` : g.vendor, blocked: g.blocked });
  }
  for (const p of r.pci ?? []) {
    const id = p.id ?? p.address;
    if (id) out.push({ id, kind: "pci", name: p.name ?? "PCI device", detail: p.group !== undefined ? `IOMMU group ${p.group}` : p.vendor, blocked: p.blocked });
  }
  for (const u of r.usb ?? []) {
    if (u.id) out.push({ id: u.id, kind: "usb", name: u.name ?? "USB device", detail: u.vendor, blocked: u.blocked });
  }
  return out;
}

async function fetchDevices(): Promise<DeviceInfo[] | null> {
  const r = await fetch("/api/v1/devices", { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`The device list isn't available (${r.status}).`);
  return parseDevices((await r.json()) as DevicesResponse);
}

export function DevicesStep({ template, devices, onChange }: { template: VMTemplate; devices: VMDevice[]; onChange: (d: VMDevice[]) => void }) {
  const q = useQuery({ queryKey: ["devices-for-vms"], queryFn: fetchDevices, retry: false, staleTime: 10_000 });
  const has = (d: DeviceInfo) => devices.some((x) => x.kind === d.kind && x.id === d.id);
  const toggle = (d: DeviceInfo) =>
    onChange(has(d) ? devices.filter((x) => !(x.kind === d.kind && x.id === d.id)) : [...devices, { kind: d.kind, id: d.id, ...(d.kind === "gpu" && template.gpu ? { primary: false } : {}) }]);
  return (
    <>
      <h2 className="wiz__title">Devices</h2>
      <p className="wiz__lead">
        Give the VM a whole graphics card, a USB stick or another device. {template.gpu ? "A gaming VM wants its own graphics card." : "Most VMs don't need any."}
      </p>
      {q.isPending ? (
        <Loading label="Looking for devices…" />
      ) : q.isError ? (
        <Alert tone="warn">{(q.error as Error).message}</Alert>
      ) : q.data === null ? (
        <EmptyState icon={<CpuIcon size={28} />} title="Device passthrough comes with the Devices update">
          You can create the VM now and add a graphics card or USB device from its Hardware tab later.
        </EmptyState>
      ) : q.data.length === 0 ? (
        <EmptyState icon={<CpuIcon size={28} />} title="No devices to pass through">
          HardyOS didn't find devices that can be given to a VM.
        </EmptyState>
      ) : (
        <div className="file-list" role="group" aria-label="Devices">
          {q.data.map((d) => (
            <button
              key={`${d.kind}:${d.id}`}
              type="button"
              className={`file-row ${has(d) ? "is-selected" : ""}`}
              aria-pressed={has(d)}
              disabled={!!d.blocked}
              onClick={() => toggle(d)}
              title={d.blocked}
            >
              {d.kind === "gpu" ? <GamepadIcon size={16} /> : <CpuIcon size={16} />}
              <span className="file-row__name">
                {d.name} <span className="small muted mono">{d.id}</span>
              </span>
              {d.blocked ? <Badge tone="warn">{d.blocked}</Badge> : d.detail && <span className="small muted">{d.detail}</span>}
            </button>
          ))}
        </div>
      )}
      <div className="tip">
        <InfoIcon size={16} />
        <span>A graphics card given to a VM goes back to Docker apps whenever the VM is off.</span>
      </div>
    </>
  );
}
