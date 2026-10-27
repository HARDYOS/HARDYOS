import type { Job, VM, VMSpec, VMTemplate } from "@hardy/api-client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type ReactNode, useEffect, useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes, dateTime, relativeTime } from "../../format";
import { useJob } from "../../hooks/queries";
import {
  CameraIcon,
  DiscIcon,
  ExternalIcon,
  GamepadIcon,
  PlayIcon,
  PlusIcon,
  PowerIcon,
  RefreshIcon,
  RestartIcon,
  ScreenIcon,
  StopIcon,
  TrashIcon,
} from "../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, IconButton, Loading, Select, Stat, TextInput, Toggle } from "../../ui";
import { AreaChart } from "../../ui/Chart";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { DevicesStep } from "./DevicesStep";
import { Meter, StateBadge, VMGlyph } from "./parts";
import { type VMAction, diskSize, isOn, memory, osLabel, pushSample, useLibrary, useSnapshots, useVM, vmAction, vmKeys } from "./vmApi";

export type VMTab = "overview" | "console" | "hardware" | "snapshots" | "settings" | "logs";

const TABS: { id: VMTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "console", label: "Screen" },
  { id: "hardware", label: "Hardware" },
  { id: "snapshots", label: "Snapshots" },
  { id: "settings", label: "Settings" },
  { id: "logs", label: "Logs" },
];

/** Follows a job and refreshes the VM when it's done. */
function useVMJob(id: string) {
  const [jobId, setJobId] = useState<string | null>(null);
  const job = useJob(jobId);
  const qc = useQueryClient();
  useEffect(() => {
    const j = job.data;
    if (!j || !jobId) return;
    if (j.state === "succeeded" || j.state === "failed" || j.state === "cancelled") {
      void qc.invalidateQueries({ queryKey: vmKeys.all });
      void qc.invalidateQueries({ queryKey: vmKeys.snapshots(id) });
      if (j.state === "failed") toast("error", j.title, j.error);
      else {
        const warnings = ((j.result as { warnings?: string[] } | null)?.warnings ?? []).filter(Boolean);
        if (warnings.length) toast("warning", j.title, warnings.join(" "));
      }
      setJobId(null);
    }
  }, [job.data, jobId, id, qc]);
  return { running: jobId !== null ? (job.data ?? null) : null, start: (j: Job) => setJobId(j.id) };
}

export function VMPage({
  id,
  templates,
  tab,
  onTab,
  onBack,
  onOpenConsole,
}: {
  id: string;
  templates: VMTemplate[];
  tab: VMTab;
  onTab: (t: VMTab) => void;
  onBack: () => void;
  onOpenConsole: (vm: VM) => void;
}) {
  const q = useVM(id);
  const jobs = useVMJob(id);
  const [deleting, setDeleting] = useState(false);
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const vm = q.data;
  const on = isOn(vm);
  const busy = jobs.running !== null;
  const act = async (a: VMAction) => {
    try {
      jobs.start(await vmAction(vm.id, a));
    } catch (e) {
      toast("error", "That didn't work", errorMessage(e));
    }
  };

  return (
    <div className="stack" style={{ gap: 14 }}>
      <div>
        <Button variant="ghost" size="sm" onClick={onBack}>
          ← All virtual machines
        </Button>
      </div>
      <header className="vm-hero">
        <VMGlyph template={vm.template} on={vm.state === "running"} large />
        <div className="vm-hero__text">
          <h1 className="vm-hero__name">
            {vm.name} <StateBadge state={vm.state} />
            {vm.restartNeeded && <Badge tone="warn">Restart to apply changes</Badge>}
          </h1>
          <div className="small muted">
            {osLabel(vm, templates)} · {vm.cpu.cores * vm.cpu.threads} CPU · {memory(vm.memory.mb)}
            {vm.addresses.length > 0 && (
              <>
                {" "}
                · <span className="mono">{vm.addresses[0]}</span>
              </>
            )}
          </div>
        </div>
        <div className="row" style={{ gap: 6 }}>
          {on ? (
            <>
              <Button onClick={() => onOpenConsole(vm)}>
                <ScreenIcon size={15} /> Open screen
              </Button>
              <Button onClick={() => act("restart")} disabled={busy} title="Ask the system to restart">
                <RestartIcon size={15} /> Restart
              </Button>
              <Button onClick={() => act("stop")} disabled={busy} title="Ask the system to shut down">
                <PowerIcon size={15} /> Shut down
              </Button>
              <IconButton label="Turn off now (like pulling the plug)" onClick={() => act("force-stop")} disabled={busy}>
                <StopIcon size={15} />
              </IconButton>
            </>
          ) : (
            <Button variant="primary" onClick={() => act("start")} busy={busy}>
              <PlayIcon size={15} /> Start
            </Button>
          )}
        </div>
      </header>
      {jobs.running && (
        <Alert tone="info" title={jobs.running.title}>
          {jobs.running.message || "Working…"}
        </Alert>
      )}
      <div className="vm-tabs" role="tablist" aria-label="VM sections">
        {TABS.map((t) => (
          <button key={t.id} type="button" role="tab" aria-selected={tab === t.id} onClick={() => onTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>
      {tab === "overview" && <Overview vm={vm} onOpenConsole={() => onOpenConsole(vm)} />}
      {tab === "console" && <ScreenTab vm={vm} onOpen={() => onOpenConsole(vm)} onStart={() => act("start")} />}
      {tab === "hardware" && <HardwareTab vm={vm} onJob={jobs.start} />}
      {tab === "snapshots" && <SnapshotsTab vm={vm} onJob={jobs.start} />}
      {tab === "settings" && <SettingsTab vm={vm} onJob={jobs.start} onDelete={() => setDeleting(true)} />}
      {tab === "logs" && <LogsTab vm={vm} />}
      {deleting && <DeleteDialog vm={vm} onClose={() => setDeleting(false)} onDeleted={onBack} />}
    </div>
  );
}

function Overview({ vm, onOpenConsole }: { vm: VM; onOpenConsole: () => void }) {
  const [cpu, setCpu] = useState<number[]>([]);
  const [mem, setMem] = useState<number[]>([]);
  useEffect(() => {
    if (vm.state !== "running") return;
    setCpu((h) => pushSample(h, vm.cpuPercent));
    setMem((h) => pushSample(h, vm.memoryUsedMB));
  }, [vm.cpuPercent, vm.memoryUsedMB, vm.state]);
  const gpu = vm.devices.some((d) => d.kind === "gpu" || d.kind === "vgpu") || vm.template === "gaming";
  const usedTotal = Object.values(vm.diskUsage).reduce((a, b) => a + b, 0);
  return (
    <div className="stack">
      <div className="grid-4">
        <Stat label="CPU" value={<span className="mono">{vm.state === "running" ? `${Math.round(vm.cpuPercent)}%` : "—"}</span>} sub={`${vm.cpu.cores * vm.cpu.threads} virtual CPUs`} />
        <Stat label="Memory" value={<span className="mono">{vm.state === "running" && vm.memoryUsedMB ? memory(vm.memoryUsedMB) : "—"}</span>} sub={`of ${memory(vm.memory.mb)}`} />
        <Stat label="Disks" value={<span className="mono">{bytes(usedTotal)}</span>} sub={`used of ${diskSize(vm.disks.reduce((a, d) => a + d.sizeGB, 0))} on ${vm.pool}`} />
        <Stat label="Address" value={<span className="mono">{vm.addresses[0] ?? "—"}</span>} sub={vm.state === "running" ? (vm.addresses.length ? "from the guest agent or network" : "waiting for the guest") : "when it runs"} />
      </div>
      <div className="grid-2">
        <Card title="CPU">
          <AreaChart values={cpu.length > 1 ? cpu : [0, 0]} max={100} label="CPU use over the last minutes" />
        </Card>
        <Card title="Memory">
          <AreaChart values={mem.length > 1 ? mem : [0, 0]} max={vm.memory.mb} color="var(--hos-violet)" label="Memory use over the last minutes" />
        </Card>
      </div>
      <Card title="Disks">
        <div className="stack">
          {vm.disks.map((d) => (
            <Meter
              key={d.name}
              label={`${d.name} · ${d.bus}`}
              value={`${bytes(vm.diskUsage[d.name] ?? 0)} of ${diskSize(d.sizeGB)}`}
              percent={((vm.diskUsage[d.name] ?? 0) / (d.sizeGB * 1024 ** 3)) * 100}
            />
          ))}
        </div>
      </Card>
      {gpu && <GameStreaming vm={vm} />}
      {vm.state === "running" && (
        <div>
          <Button onClick={onOpenConsole}>
            <ScreenIcon size={15} /> Open its screen in a window
          </Button>
        </div>
      )}
    </div>
  );
}

/** Moonlight/Sunshine for GPU VMs: plain steps, the address to use. */
function GameStreaming({ vm }: { vm: VM }) {
  const addr = vm.addresses[0];
  return (
    <Card title={<span className="row" style={{ gap: 8 }}><GamepadIcon size={16} /> Game streaming</span>}>
      <div className="stack">
        <p className="small" style={{ margin: 0 }}>
          Play this VM's games on a TV, laptop or phone with Moonlight, streamed from Sunshine inside the VM.
        </p>
        <ol className="small" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7 }}>
          <li>
            In the VM, install the graphics card's driver, then{" "}
            <a href="https://github.com/LizardByte/Sunshine/releases" target="_blank" rel="noreferrer">
              Sunshine <ExternalIcon size={11} />
            </a>
            .
          </li>
          <li>Open Sunshine's page in the VM (https://localhost:47990) and set a user name and password.</li>
          <li>
            Install{" "}
            <a href="https://moonlight-stream.org" target="_blank" rel="noreferrer">
              Moonlight <ExternalIcon size={11} />
            </a>{" "}
            on the device you play on and add the VM by its address: <strong className="mono">{addr ?? "(start the VM to see it)"}</strong>
          </li>
        </ol>
        <Alert tone="info">
          Playing away from home goes through HardyOS's VPN once remote access is set up; Sunshine's ports are then published only to your VPN devices.
        </Alert>
      </div>
    </Card>
  );
}

function ScreenTab({ vm, onOpen, onStart }: { vm: VM; onOpen: () => void; onStart: () => void }) {
  const on = isOn(vm);
  return (
    <div className="stack">
      <div className="screen-preview">
        <div className="stack" style={{ alignItems: "center", gap: 10 }}>
          <ScreenIcon size={36} />
          {on ? (
            <>
              <div>The screen opens in its own window, with keyboard, mouse and clipboard.</div>
              <Button variant="primary" onClick={onOpen}>
                Open the screen
              </Button>
            </>
          ) : (
            <>
              <div>The VM is off.</div>
              <Button variant="primary" onClick={onStart}>
                <PlayIcon size={15} /> Start it
              </Button>
            </>
          )}
        </div>
      </div>
      <div className="tip">
        <span>
          The toolbar sends Ctrl+Alt+Del and pastes text into the VM. Installing the guest tools (Windows: virtio-win-guest-tools.exe on the drivers disc; Linux:
          qemu-guest-agent) lets HardyOS shut it down cleanly and show its address.
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------- hardware

function cloneSpec(vm: VM): VMSpec {
  const s: VMSpec = {
    id: vm.id,
    name: vm.name,
    description: vm.description,
    template: vm.template,
    os: vm.os,
    pool: vm.pool,
    uuid: vm.uuid,
    cpu: { ...vm.cpu },
    memory: { ...vm.memory },
    firmware: { ...vm.firmware },
    disks: vm.disks.map((d) => ({ ...d })),
    media: vm.media.map((m) => ({ ...m })),
    nics: vm.nics.map((n) => ({ ...n })),
    video: vm.video,
    guestAgent: vm.guestAgent,
    boot: [...vm.boot],
    autostart: { ...vm.autostart },
    devices: vm.devices.map((d) => ({ ...d })),
  };
  if (vm.cloudInit) s.cloudInit = { ...vm.cloudInit, sshKeys: [...vm.cloudInit.sshKeys] };
  if (vm.streaming) s.streaming = { ...vm.streaming };
  if (vm.labels) s.labels = { ...vm.labels };
  return s;
}

async function saveSpec(spec: VMSpec, removeDisks: string[] = []): Promise<Job> {
  const r = await unwrap(api.PUT("/vms/{id}", { params: { path: { id: spec.id } }, body: { spec, ...(removeDisks.length ? { removeDisks } : {}) } }));
  return r.job;
}

function HardwareTab({ vm, onJob }: { vm: VM; onJob: (j: Job) => void }) {
  const [spec, setSpec] = useState<VMSpec>(() => cloneSpec(vm));
  const [remove, setRemove] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [picking, setPicking] = useState(false);
  const library = useLibrary();
  const on = isOn(vm);
  const dirty = JSON.stringify(spec) !== JSON.stringify(cloneSpec(vm)) || remove.length > 0;
  const set = (p: Partial<VMSpec>) => setSpec((s) => ({ ...s, ...p }));
  const isos = (library.data?.files ?? []).filter((f) => f.kind === "iso");
  const save = async () => {
    setBusy(true);
    try {
      onJob(await saveSpec(spec, remove));
      setRemove([]);
    } catch (e) {
      toast("error", "The changes weren't saved", errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const later = on ? <Badge tone="warn">at next start</Badge> : null;
  return (
    <div className="stack">
      {on && <Alert tone="info">The VM is running: CPU, memory and device changes apply the next time it starts. Disks can grow now.</Alert>}
      <Card title={<>Processor and memory {later}</>}>
        <div className="grid-3">
          <Field label="CPU cores">
            {(id) => <TextInput id={id} type="number" min={1} className="input mono" value={spec.cpu.cores} onChange={(e) => set({ cpu: { ...spec.cpu, cores: Number(e.target.value) } })} />}
          </Field>
          <Field label="Threads per core">
            {(id) => (
              <Select id={id} value={String(spec.cpu.threads)} onChange={(e) => set({ cpu: { ...spec.cpu, threads: Number(e.target.value) as 1 | 2 } })}>
                <option value="1">1</option>
                <option value="2">2</option>
              </Select>
            )}
          </Field>
          <Field label="Memory (MB)" hint={memory(spec.memory.mb)}>
            {(id) => <TextInput id={id} type="number" min={128} step={256} className="input mono" value={spec.memory.mb} onChange={(e) => set({ memory: { ...spec.memory, mb: Number(e.target.value) } })} />}
          </Field>
        </div>
        <div style={{ marginTop: 10 }}>
          <Toggle
            label="Memory ballooning"
            description="The guest gives memory it doesn't use back to the server (needs its VirtIO drivers)."
            checked={spec.memory.balloon}
            onChange={(v) => set({ memory: { ...spec.memory, balloon: v } })}
          />
        </div>
      </Card>
      <Card
        title="Disks"
        actions={
          spec.disks.length < 8 && (
            <Button
              size="sm"
              onClick={() => {
                const used = new Set(spec.disks.map((d) => d.name));
                let n = 1;
                while (used.has(`disk${n}`)) n++;
                set({ disks: [...spec.disks, { name: `disk${n}`, sizeGB: 100, bus: "virtio-scsi" }] });
              }}
            >
              <PlusIcon size={14} /> Add a disk
            </Button>
          )
        }
      >
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Disk</th>
                <th>Size (GB)</th>
                <th>Type</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {spec.disks.map((d, i) => {
                const old = vm.disks.find((x) => x.name === d.name);
                return (
                  <tr key={d.name}>
                    <td className="mono">
                      {d.name} {!old && <Badge tone="accent">new</Badge>}
                    </td>
                    <td>
                      <TextInput
                        aria-label={`${d.name} size`}
                        type="number"
                        min={old?.sizeGB ?? 1}
                        className="input mono"
                        style={{ width: 110 }}
                        value={d.sizeGB}
                        onChange={(e) => set({ disks: spec.disks.map((x, j) => (j === i ? { ...x, sizeGB: Number(e.target.value) } : x)) })}
                      />
                      {old && d.sizeGB < old.sizeGB && <div className="field__error">Disks can grow, not shrink</div>}
                    </td>
                    <td>
                      <Select aria-label={`${d.name} type`} value={d.bus} onChange={(e) => set({ disks: spec.disks.map((x, j) => (j === i ? { ...x, bus: e.target.value as typeof d.bus } : x)) })}>
                        <option value="virtio-scsi">VirtIO SCSI</option>
                        <option value="virtio-blk">VirtIO block</option>
                        <option value="sata">SATA</option>
                      </Select>
                    </td>
                    <td className="actions">
                      {spec.disks.length > 1 && (
                        <IconButton
                          label={`Remove ${d.name}`}
                          disabled={on && !!old}
                          title={on && old ? "Turn the VM off to remove a disk" : undefined}
                          onClick={() => {
                            set({ disks: spec.disks.filter((_, j) => j !== i) });
                            if (old) setRemove((r) => [...r, d.name]);
                          }}
                        >
                          <TrashIcon size={15} />
                        </IconButton>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {remove.length > 0 && <Alert tone="warn">Saving deletes {remove.join(", ")} and everything on it, including its snapshots.</Alert>}
      </Card>
      <Card title={<>CD/DVD drives {later}</>}>
        <div className="stack">
          {spec.media.map((m, i) => (
            <div key={i} className="row" style={{ gap: 8 }}>
              <DiscIcon size={16} />
              {m.kind === "iso" || m.kind === "empty" ? (
                <Select
                  aria-label={`Drive ${i + 1}`}
                  value={m.kind === "iso" ? (m.iso ?? "") : ""}
                  onChange={(e) =>
                    set({ media: spec.media.map((x, j) => (j === i ? (e.target.value ? { kind: "iso", iso: e.target.value } : { kind: "empty" }) : x)) })
                  }
                  style={{ maxWidth: 380 }}
                >
                  <option value="">Empty</option>
                  {m.kind === "iso" && m.iso && !isos.some((f) => f.name === m.iso) && <option value={m.iso}>{m.iso}</option>}
                  {isos.map((f) => (
                    <option key={f.name} value={f.name}>
                      {f.name}
                    </option>
                  ))}
                </Select>
              ) : (
                <span>{m.kind === "virtio" ? "VirtIO drivers disc" : "Cloud-init settings disc"}</span>
              )}
              <IconButton label={`Remove drive ${i + 1}`} onClick={() => set({ media: spec.media.filter((_, j) => j !== i) })}>
                <TrashIcon size={15} />
              </IconButton>
            </div>
          ))}
          <div className="row" style={{ gap: 8 }}>
            {spec.media.length < 4 && (
              <Button size="sm" onClick={() => set({ media: [...spec.media, { kind: "empty" }] })}>
                <PlusIcon size={14} /> Add a drive
              </Button>
            )}
            {vm.os === "windows" && !spec.media.some((m) => m.kind === "virtio") && spec.media.length < 4 && (
              <Button size="sm" onClick={() => set({ media: [...spec.media, { kind: "virtio" }] })}>
                <PlusIcon size={14} /> VirtIO drivers disc
              </Button>
            )}
          </div>
        </div>
      </Card>
      <Card
        title={<>Network cards {later}</>}
        actions={
          spec.nics.length < 8 && (
            <Button size="sm" onClick={() => set({ nics: [...spec.nics, { mode: "bridge", model: "virtio" }] })}>
              <PlusIcon size={14} /> Add a card
            </Button>
          )
        }
      >
        <div className="stack">
          {spec.nics.map((n, i) => (
            <div key={i} className="row" style={{ gap: 8, flexWrap: "wrap" }}>
              <Select
                aria-label={`Card ${i + 1} network`}
                value={n.mode}
                onChange={(e) => set({ nics: spec.nics.map((x, j) => (j === i ? { ...x, mode: e.target.value as typeof n.mode, vlan: e.target.value === "vlan" ? (x.vlan ?? 10) : undefined } : x)) })}
                style={{ width: 190 }}
              >
                <option value="bridge">Home network</option>
                <option value="nat">Private (NAT)</option>
                <option value="vlan">VLAN</option>
              </Select>
              {n.mode === "vlan" && (
                <TextInput
                  aria-label={`Card ${i + 1} VLAN`}
                  type="number"
                  min={1}
                  max={4094}
                  className="input mono"
                  style={{ width: 90 }}
                  value={n.vlan ?? 10}
                  onChange={(e) => set({ nics: spec.nics.map((x, j) => (j === i ? { ...x, vlan: Number(e.target.value) } : x)) })}
                />
              )}
              <Select aria-label={`Card ${i + 1} model`} value={n.model} onChange={(e) => set({ nics: spec.nics.map((x, j) => (j === i ? { ...x, model: e.target.value as typeof n.model } : x)) })} style={{ width: 150 }}>
                <option value="virtio">VirtIO</option>
                <option value="e1000e">Intel e1000e</option>
              </Select>
              <span className="small muted mono">{n.mac || "new"}</span>
              <IconButton label={`Remove card ${i + 1}`} onClick={() => set({ nics: spec.nics.filter((_, j) => j !== i) })}>
                <TrashIcon size={15} />
              </IconButton>
            </div>
          ))}
        </div>
      </Card>
      <Card title={<>Devices {later}</>} actions={<Button size="sm" onClick={() => setPicking(true)}>Choose devices…</Button>}>
        {spec.devices.length === 0 ? (
          <span className="small muted">No passed-through devices.</span>
        ) : (
          <div className="row" style={{ flexWrap: "wrap", gap: 6 }}>
            {spec.devices.map((d) => (
              <Badge key={`${d.kind}:${d.id}`} tone="accent">
                {d.kind.toUpperCase()} <span className="mono">{d.id}</span>
              </Badge>
            ))}
          </div>
        )}
      </Card>
      <div className="row">
        <Button variant="primary" disabled={!dirty} busy={busy} onClick={save}>
          Save changes
        </Button>
        {dirty && (
          <Button
            variant="ghost"
            onClick={() => {
              setSpec(cloneSpec(vm));
              setRemove([]);
            }}
          >
            Undo changes
          </Button>
        )}
      </div>
      {picking && (
        <Dialog title="Devices" onClose={() => setPicking(false)} width={640} footer={<Button variant="primary" onClick={() => setPicking(false)}>Done</Button>}>
          <DevicesStep
            template={{ gpu: vm.template === "gaming" } as VMTemplate}
            devices={spec.devices}
            onChange={(devices) => set({ devices })}
          />
        </Dialog>
      )}
    </div>
  );
}

// --------------------------------------------------------------- snapshots

function SnapshotsTab({ vm, onJob }: { vm: VM; onJob: (j: Job) => void }) {
  const q = useSnapshots(vm.id);
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [rollback, setRollback] = useState<string | null>(null);
  const take = async () => {
    setBusy(true);
    try {
      const r = await unwrap(api.POST("/vms/{id}/snapshots", { params: { path: { id: vm.id } }, body: { label } }));
      onJob(r.job);
      setLabel("");
    } catch (e) {
      toast("error", "No snapshot", errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="stack">
      <Card title="Take a snapshot">
        <div className="row" style={{ gap: 8, alignItems: "flex-end" }}>
          <div className="grow">
            <Field label="What's it for? (optional)" hint={vm.state === "running" ? "With the guest agent, the guest's files are frozen for a moment first." : undefined}>
              {(id) => <TextInput id={id} value={label} maxLength={80} placeholder="Before installing updates" onChange={(e) => setLabel(e.target.value)} />}
            </Field>
          </div>
          <Button variant="primary" busy={busy} onClick={take}>
            <CameraIcon size={15} /> Take snapshot
          </Button>
        </div>
      </Card>
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : q.data.length === 0 ? (
        <EmptyState icon={<CameraIcon size={28} />} title="No snapshots yet">
          A snapshot keeps the whole VM as it is now: its disks, settings and firmware. Go back to it if an update goes wrong.
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Taken</th>
                <th>Description</th>
                <th className="mono">Space</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {q.data.map((s) => (
                <tr key={s.name}>
                  <td title={dateTime(s.created)}>
                    {relativeTime(s.created)}
                    <span className="cell-sub mono">{s.name}</span>
                  </td>
                  <td>
                    {s.label || <span className="muted">—</span>}
                    {!s.consistent && <span className="cell-sub">Taken while running without the guest agent</span>}
                  </td>
                  <td className="mono">{bytes(s.bytes)}</td>
                  <td className="actions">
                    <Button size="sm" disabled={isOn(vm)} title={isOn(vm) ? "Turn the VM off first" : undefined} onClick={() => setRollback(s.name)}>
                      <RefreshIcon size={14} /> Go back
                    </Button>
                    <IconButton
                      label={`Delete snapshot ${s.name}`}
                      onClick={async () => {
                        try {
                          const r = await unwrap(api.DELETE("/vms/{id}/snapshots/{name}", { params: { path: { id: vm.id, name: s.name } } }));
                          onJob(r.job);
                        } catch (e) {
                          toast("error", "Not deleted", errorMessage(e));
                        }
                      }}
                    >
                      <TrashIcon size={15} />
                    </IconButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {rollback && (
        <ConfirmDialog
          title={`Go back to ${rollback}?`}
          confirmLabel="Go back"
          typeToConfirm={vm.name}
          onClose={() => setRollback(null)}
          onConfirm={async () => {
            const r = await unwrap(api.POST("/vms/{id}/rollback", { params: { path: { id: vm.id } }, body: { snapshot: rollback, confirm: vm.name } }));
            onJob(r.job);
          }}
        >
          <p>The VM's disks, settings and firmware go back to that moment. Everything since, and later snapshots, are lost.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}

// ---------------------------------------------------------------- settings

const BOOT_LABEL: Record<string, string> = { disk: "Disk", cdrom: "CD/DVD", network: "Network (PXE)" };

function SettingsTab({ vm, onJob, onDelete }: { vm: VM; onJob: (j: Job) => void; onDelete: () => void }) {
  const [spec, setSpec] = useState<VMSpec>(() => cloneSpec(vm));
  const [busy, setBusy] = useState(false);
  const dirty = JSON.stringify(spec) !== JSON.stringify(cloneSpec(vm));
  const set = (p: Partial<VMSpec>) => setSpec((s) => ({ ...s, ...p }));
  const move = (i: number, d: -1 | 1) => {
    const b = [...spec.boot];
    const j = i + d;
    if (j < 0 || j >= b.length) return;
    [b[i], b[j]] = [b[j]!, b[i]!];
    set({ boot: b });
  };
  return (
    <div className="stack">
      <Card title="General">
        <div className="grid-2">
          <Field label="Name">{(id) => <TextInput id={id} value={spec.name} onChange={(e) => set({ name: e.target.value })} />}</Field>
          <Field label="Notes">{(id) => <TextInput id={id} value={spec.description ?? ""} onChange={(e) => set({ description: e.target.value })} />}</Field>
        </div>
      </Card>
      <Card title="Starting with the server">
        <div className="stack">
          <Toggle
            label="Start with the server"
            description="After a restart or power cut. VMs start in order, lowest number first."
            checked={spec.autostart.enabled}
            onChange={(v) => set({ autostart: { ...spec.autostart, enabled: v } })}
          />
          {spec.autostart.enabled && (
            <div className="grid-2">
              <Field label="Order" hint="0 starts first, like a router or DNS server.">
                {(id) => <TextInput id={id} type="number" min={0} max={999} className="input mono" value={spec.autostart.order} onChange={(e) => set({ autostart: { ...spec.autostart, order: Number(e.target.value) } })} />}
              </Field>
              <Field label="Then wait (seconds)" hint="Before starting the next VM.">
                {(id) => <TextInput id={id} type="number" min={0} max={600} className="input mono" value={spec.autostart.delaySec} onChange={(e) => set({ autostart: { ...spec.autostart, delaySec: Number(e.target.value) } })} />}
              </Field>
            </div>
          )}
        </div>
      </Card>
      <Card title="Boot order">
        <div className="stack" style={{ gap: 6 }}>
          {spec.boot.map((b, i) => (
            <div key={b} className="row" style={{ gap: 8 }}>
              <span className="mono muted">{i + 1}.</span>
              <span className="grow">{BOOT_LABEL[b] ?? b}</span>
              <Button size="sm" variant="ghost" disabled={i === 0} onClick={() => move(i, -1)} aria-label={`Move ${BOOT_LABEL[b]} up`}>
                ↑
              </Button>
              <Button size="sm" variant="ghost" disabled={i === spec.boot.length - 1} onClick={() => move(i, 1)} aria-label={`Move ${BOOT_LABEL[b]} down`}>
                ↓
              </Button>
              {spec.boot.length > 1 && (
                <IconButton label={`Don't boot from ${BOOT_LABEL[b]}`} onClick={() => set({ boot: spec.boot.filter((x) => x !== b) })}>
                  <TrashIcon size={14} />
                </IconButton>
              )}
            </div>
          ))}
          <div className="row" style={{ gap: 8 }}>
            {(["disk", "cdrom", "network"] as const)
              .filter((b) => !spec.boot.includes(b))
              .map((b) => (
                <Button key={b} size="sm" onClick={() => set({ boot: [...spec.boot, b] })}>
                  <PlusIcon size={14} /> {BOOT_LABEL[b]}
                </Button>
              ))}
          </div>
        </div>
      </Card>
      <Card title="Firmware and guest">
        <div className="stack">
          <Field label="Firmware" hint="Changing it on an installed system usually stops it from starting.">
            {(id) => (
              <Select id={id} value={spec.firmware.type} onChange={(e) => set({ firmware: { ...spec.firmware, type: e.target.value as "uefi" | "bios" } })} style={{ maxWidth: 240 }}>
                <option value="uefi">UEFI</option>
                <option value="bios">BIOS (legacy)</option>
              </Select>
            )}
          </Field>
          <Toggle label="Secure Boot" checked={spec.firmware.secureBoot} disabled={spec.firmware.type !== "uefi"} onChange={(v) => set({ firmware: { ...spec.firmware, secureBoot: v } })} />
          <Toggle label="TPM 2.0" checked={spec.firmware.tpm} onChange={(v) => set({ firmware: { ...spec.firmware, tpm: v } })} />
          <Toggle
            label="QEMU guest agent"
            description="Clean shutdowns, the VM's address and consistent snapshots, once the agent runs in the guest."
            checked={spec.guestAgent}
            onChange={(v) => set({ guestAgent: v })}
          />
        </div>
      </Card>
      <div className="row">
        <Button
          variant="primary"
          disabled={!dirty}
          busy={busy}
          onClick={async () => {
            setBusy(true);
            try {
              onJob(await saveSpec(spec));
            } catch (e) {
              toast("error", "Not saved", errorMessage(e));
            } finally {
              setBusy(false);
            }
          }}
        >
          Save settings
        </Button>
      </div>
      <Card title="Delete">
        <div className="row row--between">
          <span className="small muted">Delete the VM, and its disks unless you keep them.</span>
          <Button variant="danger" onClick={onDelete} disabled={isOn(vm)} title={isOn(vm) ? "Turn the VM off first" : undefined}>
            <TrashIcon size={15} /> Delete VM…
          </Button>
        </div>
      </Card>
    </div>
  );
}

function DeleteDialog({ vm, onClose, onDeleted }: { vm: VM; onClose: () => void; onDeleted: () => void }) {
  const [keep, setKeep] = useState(false);
  const qc = useQueryClient();
  return (
    <ConfirmDialog
      title={`Delete ${vm.name}?`}
      confirmLabel={keep ? "Delete, keep disks" : "Delete everything"}
      typeToConfirm={vm.name}
      onClose={onClose}
      onConfirm={async () => {
        await unwrap(api.DELETE("/vms/{id}", { params: { path: { id: vm.id } }, body: { confirm: vm.name, keepDisks: keep } }));
        void qc.invalidateQueries({ queryKey: vmKeys.all });
        onDeleted();
      }}
    >
      <div className="stack">
        <p>{keep ? "The VM goes; its disks stay on the pool and can be deleted later." : "The VM, its disks and every snapshot of it are deleted for good."}</p>
        <Toggle label="Keep its disks" checked={keep} onChange={setKeep} />
      </div>
    </ConfirmDialog>
  );
}

function LogsTab({ vm }: { vm: VM }) {
  const q = useQuery({
    queryKey: vmKeys.logs(vm.id),
    queryFn: () => unwrap(api.GET("/vms/{id}/logs", { params: { path: { id: vm.id }, query: { lines: 400 } } })),
  });
  return (
    <Card title="QEMU's log" actions={<Button size="sm" onClick={() => q.refetch()}>Refresh</Button>}>
      {q.isPending ? <Loading /> : q.isError ? <ErrorBox error={q.error} /> : <pre className="logs">{q.data.logs || "Nothing logged yet."}</pre>}
    </Card>
  );
}

export function Section({ children }: { children: ReactNode }) {
  return <div className="stack">{children}</div>;
}
