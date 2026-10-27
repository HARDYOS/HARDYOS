import type { DeviceInventory, DeviceProblem, GPUInfo, USBDeviceInfo, VMDevice } from "@hardy/api-client";
import { type ReactNode, useId } from "react";
import { Alert, Badge, ErrorBox, Loading, Select, Toggle, type Tone } from "../../../ui";
import { gpuName, useDeviceCheck, useDevices, vram } from "./deviceApi";
import "./devices.css";

/**
 * Device pickers for the New VM wizard and the VM's hardware page.
 * `value` is the VM's device list (VMDevice[]); every picker only adds or
 * removes the entries of its own kind. Problems come from hardyd's check
 * (nothing changes until the VM starts).
 */
export interface DevicePickerProps {
  /** The VM's name (for "in use by another VM" checks). */
  vm: string;
  value: VMDevice[];
  onChange: (devices: VMDevice[]) => void;
}

/** Every kind of device: GPUs first, then USB, then other PCI devices. */
export function DevicePicker({ vm, value, onChange }: DevicePickerProps) {
  const inv = useDevices();
  const check = useDeviceCheck(vm, value);
  if (inv.isPending) return <Loading label="Looking for devices…" />;
  if (inv.isError) return <ErrorBox error={inv.error} onRetry={() => inv.refetch()} />;
  return (
    <div className="stack devpick">
      {!inv.data.iommu.enabled && (
        <Alert tone="warn" title="Passthrough isn't on yet">
          {inv.data.iommu.message} You can still add USB devices. Turn it on in Control Panel › Devices.
        </Alert>
      )}
      <section aria-label="Graphics">
        <h4 className="section-label">Graphics</h4>
        <GPUPicker inventory={inv.data} value={value} onChange={onChange} />
      </section>
      <section aria-label="USB devices">
        <h4 className="section-label">USB devices</h4>
        <USBPicker inventory={inv.data} value={value} onChange={onChange} />
      </section>
      <details className="devpick__more">
        <summary>Other PCI devices (network cards, controllers…)</summary>
        <PCIPicker inventory={inv.data} value={value} onChange={onChange} />
      </details>
      {check && <DeviceProblems problems={check.problems} />}
    </div>
  );
}

/** Problems with the chosen devices, in plain words. */
export function DeviceProblems({ problems }: { problems: DeviceProblem[] }) {
  if (problems.length === 0) return null;
  return (
    <Alert tone="bad" title={problems.length === 1 ? "This VM can't start with these devices" : `${problems.length} problems with these devices`}>
      <ul className="devpick__problems">
        {problems.map((p, i) => (
          <li key={i}>{p.message}</li>
        ))}
      </ul>
    </Alert>
  );
}

interface PartProps {
  inventory: DeviceInventory;
  value: VMDevice[];
  onChange: (devices: VMDevice[]) => void;
}

/** The owner of a GPU as a badge. */
export function OwnerBadge({ gpu }: { gpu: GPUInfo }) {
  const tone: Record<string, Tone> = { apps: "good", vm: "accent", vgpu: "info", none: "neutral", stuck: "warn" };
  return <Badge tone={tone[gpu.owner.kind] ?? "neutral"}>{gpu.owner.label}</Badge>;
}

type GPUChoice = "none" | "whole" | "slice";

/** Each graphics card: not used, the whole card, or a vGPU slice. */
export function GPUPicker({ inventory, value, onChange }: PartProps) {
  if (inventory.gpus.length === 0) return <p className="muted small">This server has no graphics card to give a VM.</p>;
  const others = (g: GPUInfo) => value.filter((d) => !((d.kind === "gpu" || d.kind === "vgpu") && d.id === g.address));
  return (
    <div className="stack" style={{ gap: 10 }}>
      {inventory.gpus.map((g) => {
        const mine = value.filter((d) => (d.kind === "gpu" || d.kind === "vgpu") && d.id === g.address);
        const whole = mine.find((d) => d.kind === "gpu");
        const slice = mine.find((d) => d.kind === "vgpu");
        const choice: GPUChoice = whole ? "whole" : slice ? "slice" : "none";
        const types = g.vgpu?.types.filter((t) => t.available > 0 || t.id === slice?.vgpuType) ?? [];
        const set = (c: GPUChoice, type?: string) => {
          if (c === "none") onChange(others(g));
          if (c === "whole") onChange([...others(g), { kind: "gpu", id: g.address }]);
          if (c === "slice") onChange([...others(g), { kind: "vgpu", id: g.address, vgpuType: type ?? types[0]?.id ?? "" }]);
        };
        return (
          <GPUChoiceCard
            key={g.address}
            gpu={g}
            choice={choice}
            canSlice={types.length > 0}
            onChoose={set}
            slice={
              choice === "slice" && (
                <Select aria-label={`Slice size for ${gpuName(g)}`} value={slice?.vgpuType} onChange={(e) => set("slice", e.target.value)}>
                  {types.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                      {t.framebufferMb ? ` · ${Math.round(t.framebufferMb / 1024)} GB` : ""} · {t.available} left
                    </option>
                  ))}
                </Select>
              )
            }
            primary={
              whole && (
                <Toggle
                  label="Use as the VM's screen"
                  description="The VM shows its desktop on this card's outputs (or through game streaming) instead of the console window."
                  checked={!!whole.primary}
                  onChange={(v) => onChange([...others(g), { ...whole, primary: v || undefined }])}
                />
              )
            }
          />
        );
      })}
    </div>
  );
}

function GPUChoiceCard({
  gpu: g,
  choice,
  canSlice,
  onChoose,
  slice,
  primary,
}: {
  gpu: GPUInfo;
  choice: GPUChoice;
  canSlice: boolean;
  onChoose: (c: GPUChoice) => void;
  slice: ReactNode;
  primary: ReactNode;
}) {
  const name = useId();
  const blocked = g.problem !== "";
  const sliced = (g.vgpu?.instances.length ?? 0) > 0;
  return (
    <div className={`devcard ${choice !== "none" ? "devcard--on" : ""} ${blocked ? "devcard--blocked" : ""}`}>
      <div className="row row--between">
        <div>
          <strong>{gpuName(g)}</strong>
          <span className="small muted"> {[vram(g), g.address].filter(Boolean).join(" · ")}</span>
        </div>
        <OwnerBadge gpu={g} />
      </div>
      {blocked ? (
        <p className="small muted" style={{ margin: 0 }}>
          {g.problem}
        </p>
      ) : (
        <div className="devcard__choices" role="radiogroup" aria-label={gpuName(g)}>
          <label>
            <input type="radio" name={name} checked={choice === "none"} onChange={() => onChoose("none")} /> Not used
          </label>
          <label>
            <input type="radio" name={name} checked={choice === "whole"} disabled={sliced} onChange={() => onChoose("whole")} /> The whole card
          </label>
          {(canSlice || choice === "slice") && (
            <label>
              <input type="radio" name={name} checked={choice === "slice"} onChange={() => onChoose("slice")} /> A slice (vGPU)
            </label>
          )}
        </div>
      )}
      {slice}
      {primary}
      {choice === "whole" && g.owner.kind === "apps" && (
        <p className="small muted" style={{ margin: 0 }}>
          While this VM runs, Docker apps can't use this card. It goes back to them as soon as the VM is off.
          {g.functions.length > 1 && ` Its ${g.functions.length - 1} other part${g.functions.length > 2 ? "s" : ""} (like HDMI audio) go with it.`}
        </p>
      )}
      {choice === "whole" && g.users.length > 0 && (
        <Alert tone="warn">
          {[...new Set(g.users.map((u) => u.app || u.process))].join(", ")} {g.users.length === 1 ? "is" : "are"} using this card right now. Stop{" "}
          {g.users.length === 1 ? "it" : "them"} before starting the VM.
        </Alert>
      )}
      {choice !== "none" && g.hints.length > 0 && (
        <ul className="devcard__hints small">
          {g.hints.map((h) => (
            <li key={h}>{h}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** USB devices: by the device itself, or by the port it's plugged into. */
export function USBPicker({ inventory, value, onChange }: PartProps) {
  const devices = inventory.usb.filter((u) => !u.hub);
  const chosenID = (u: USBDeviceInfo) => `${u.vendorId}:${u.productId}`;
  const current = (u: USBDeviceInfo) => value.find((d) => d.kind === "usb" && (d.id === chosenID(u) || d.id === u.port));
  const without = (u: USBDeviceInfo) => value.filter((d) => !(d.kind === "usb" && (d.id === chosenID(u) || d.id === u.port)));
  const missing = value.filter((d) => d.kind === "usb" && !devices.some((u) => d.id === chosenID(u) || d.id === u.port));
  if (devices.length === 0 && missing.length === 0) return <p className="muted small">No USB devices are plugged in.</p>;
  return (
    <ul className="devlist">
      {devices.map((u) => {
        const cur = current(u);
        const label = u.product || `USB device ${chosenID(u)}`;
        return (
          <li key={u.port} className={u.critical ? "is-blocked" : ""}>
            <label className="row" style={{ flexWrap: "nowrap" }}>
              <input
                type="checkbox"
                checked={!!cur}
                disabled={!!u.critical}
                onChange={(e) => onChange(e.target.checked ? [...without(u), { kind: "usb", id: chosenID(u) }] : without(u))}
              />
              <span className="grow">
                {label}
                <span className="cell-sub">
                  {[u.manufacturer, `port ${u.port}`].filter(Boolean).join(" · ")}
                  {u.owner && ` · in use by ${u.owner}`}
                </span>
              </span>
            </label>
            {u.critical && <span className="small muted">{u.critical}</span>}
            {cur && (
              <Select
                aria-label={`How to find ${label}`}
                value={cur.id === u.port ? "port" : "device"}
                onChange={(e) => onChange([...without(u), { kind: "usb", id: e.target.value === "port" ? u.port : chosenID(u) }])}
              >
                <option value="device">This device, in any port</option>
                <option value="port">Whatever is plugged into port {u.port}</option>
              </Select>
            )}
          </li>
        );
      })}
      {missing.map((d) => (
        <li key={d.id}>
          <label className="row">
            <input type="checkbox" checked onChange={() => onChange(value.filter((x) => x !== d))} />
            <span className="grow">
              USB {d.id}
              <span className="cell-sub">Not plugged in now; the VM gets it when it is.</span>
            </span>
          </label>
        </li>
      ))}
    </ul>
  );
}

/** Other PCI devices, with their IOMMU group explained. */
export function PCIPicker({ inventory, value, onChange }: PartProps) {
  const gpuParts = new Set(inventory.gpus.flatMap((g) => g.functions.map((f) => f.address)));
  const devices = inventory.pci.filter((p) => !p.bridge && !gpuParts.has(p.address) && !p.physFn);
  const groupOf = (id: number | null) => inventory.groups.find((g) => g.id === id);
  return (
    <ul className="devlist">
      {devices.map((p) => {
        const on = value.some((d) => d.kind === "pci" && d.id === p.address);
        const group = groupOf(p.iommuGroup);
        const shared = group && group.devices.filter((a) => !inventory.pci.find((x) => x.address === a)?.bridge).length > 1;
        return (
          <li key={p.address} className={p.critical ? "is-blocked" : ""}>
            <label className="row" style={{ flexWrap: "nowrap" }}>
              <input
                type="checkbox"
                checked={on}
                disabled={!!p.critical || p.iommuGroup == null}
                onChange={(e) =>
                  onChange(e.target.checked ? [...value, { kind: "pci", id: p.address }] : value.filter((d) => !(d.kind === "pci" && d.id === p.address)))
                }
              />
              <span className="grow">
                {p.name || p.kind}
                <span className="cell-sub">
                  {[p.kind, p.vendor, p.address].filter(Boolean).join(" · ")}
                  {p.owner && ` · in use by ${p.owner}`}
                </span>
              </span>
            </label>
            {p.critical && <span className="small muted">{p.critical}</span>}
            {!p.critical && shared && (on || p.owner) && <span className="small muted">{group!.explanation}</span>}
          </li>
        );
      })}
    </ul>
  );
}
