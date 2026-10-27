import type { Job, VMCapabilities, VMDevice, VMLibraryFile, VMTemplate } from "@hardy/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { type ReactNode, useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes } from "../../format";
import { CheckIcon, CpuIcon, DiscIcon, DownloadIcon, ExternalIcon, FolderIcon, MemoryIcon, NetworkIcon, PlusIcon, StorageIcon, TrashIcon } from "../../icons";
import { Alert, Button, Card, EmptyState, ErrorBox, Field, IconButton, Loading, Select, TextInput, Toggle } from "../../ui";
import { JobProgress } from "../shared";
import { DevicesStep } from "./DevicesStep";
import { templateGlyph } from "./parts";
import { diskSize, memory, useCapabilities, useLibrary, useTemplates, useVMs, vmKeys } from "./vmApi";
import {
  STEPS,
  type StepId,
  type WizardState,
  applyPreset,
  chosenFile,
  idFromName,
  initialState,
  installsFromISO,
  isISO,
  isImage,
  stepProblems,
  toRequest,
} from "./wizard";

const GROUPS: { id: VMTemplate["group"]; label: string }[] = [
  { id: "windows", label: "Windows" },
  { id: "linux", label: "Linux" },
  { id: "gaming", label: "Gaming" },
  { id: "appliance", label: "Home and network appliances" },
  { id: "other", label: "Something else" },
];

const MEMORY_STEPS = [512, 1024, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072];

/** The New VM wizard: seven short steps with sensible choices made. */
export function NewVM({ onCancel, onCreated, openFiles }: { onCancel: () => void; onCreated: (id: string) => void; openFiles?: () => void }) {
  const templates = useTemplates();
  const caps = useCapabilities();
  const library = useLibrary();
  const list = useVMs();
  const [state, setState] = useState<WizardState | null>(null);
  const [step, setStep] = useState<StepId>("template");
  const [job, setJob] = useState<{ id: string; vm: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();

  if (templates.isPending || caps.isPending) return <Loading />;
  if (templates.isError) return <ErrorBox error={templates.error} onRetry={() => templates.refetch()} />;
  if (caps.isError) return <ErrorBox error={caps.error} onRetry={() => caps.refetch()} />;
  const all = templates.data;
  const c = caps.data;
  const t = state ? all.find((x) => x.id === state.templateId) : undefined;
  const ctx = { template: t, caps: c, taken: (list.data?.vms ?? []).map((v) => v.id), library: library.data?.files ?? [] };
  const index = STEPS.findIndex((s) => s.id === step);
  const problems = state ? stepProblems(state, step, ctx) : step === "template" ? ["Choose a template"] : [];
  const set = (patch: Partial<WizardState>) => setState((s) => (s ? { ...s, ...patch } : s));

  async function create() {
    if (!state || !t) return;
    setBusy(true);
    setError(null);
    try {
      const r = await unwrap(api.POST("/vms", { body: toRequest(state, t) }));
      setJob({ id: r.job.id, vm: state.id });
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  if (job) {
    return (
      <div className="wiz__body" style={{ maxWidth: 640, margin: "40px auto" }}>
        <h2 className="wiz__title">Creating {state?.name}</h2>
        <p className="wiz__lead">This can take a while for big downloads. You can close this window: the job carries on and shows up in Log Center.</p>
        <JobProgress
          id={job.id}
          onDone={(j: Job) => {
            void qc.invalidateQueries({ queryKey: vmKeys.all });
            void qc.invalidateQueries({ queryKey: vmKeys.library });
            if (j.state === "succeeded") onCreated(job.vm);
          }}
        />
        <div className="row">
          <Button onClick={() => onCreated(job.vm)}>Go to the VM</Button>
          <Button variant="ghost" onClick={onCancel}>
            Back to the list
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="wiz">
      <nav className="wiz__steps" aria-label="New VM steps">
        {STEPS.map((s, i) => {
          const done = i < index;
          return (
            <button
              key={s.id}
              type="button"
              className={`wiz__step ${s.id === step ? "is-current" : ""} ${done ? "is-done" : ""}`}
              aria-current={s.id === step ? "step" : undefined}
              disabled={!done}
              onClick={() => done && setStep(s.id)}
            >
              <span className="wiz__num">{done ? <CheckIcon size={12} /> : i + 1}</span>
              {s.label}
            </button>
          );
        })}
      </nav>
      <div className="wiz__body">
        {!c.supported && (
          <Alert tone="warn" title="This server can't run VMs yet">
            {c.problem}
          </Alert>
        )}
        {step === "template" && (
          <TemplateStep
            templates={all}
            selected={state?.templateId}
            onPick={(tp) => {
              setState(initialState(tp, c, c.arch.arch));
              setStep("resources");
            }}
          />
        )}
        {state && t && step === "resources" && <ResourcesStep s={state} t={t} caps={c} set={set} setState={setState} />}
        {state && t && step === "disks" && <DisksStep s={state} t={t} caps={c} set={set} />}
        {state && t && step === "media" && <MediaStep s={state} t={t} arch={c.arch.arch} files={library.data?.files ?? []} set={set} openFiles={openFiles} />}
        {state && t && step === "network" && <NetworkStep s={state} caps={c} set={set} />}
        {state && t && step === "devices" && <DevicesStep vm={state.id} gpu={t.gpu} devices={state.devices} onChange={(devices: VMDevice[]) => set({ devices })} />}
        {state && t && step === "review" && <ReviewStep s={state} t={t} caps={c} set={set} />}
        {error && (
          <Alert tone="bad" title="The VM couldn't be created">
            {error}
          </Alert>
        )}
        {step !== "template" && (
          <footer className="wiz__foot">
            <Button variant="ghost" onClick={onCancel}>
              Cancel
            </Button>
            <span className="grow" />
            {problems.length > 0 && <span className="small muted" role="status">{problems[0]}</span>}
            <Button onClick={() => setStep(STEPS[index - 1]!.id)}>Back</Button>
            {step === "review" ? (
              <Button variant="primary" busy={busy} disabled={problems.length > 0 || !c.supported} onClick={create}>
                Create VM
              </Button>
            ) : (
              <Button variant="primary" disabled={problems.length > 0} onClick={() => setStep(STEPS[index + 1]!.id)}>
                Next
              </Button>
            )}
          </footer>
        )}
        {step === "template" && (
          <footer className="wiz__foot">
            <Button variant="ghost" onClick={onCancel}>
              Cancel
            </Button>
          </footer>
        )}
      </div>
    </div>
  );
}

function StepHead({ title, lead }: { title: string; lead?: ReactNode }) {
  return (
    <>
      <h2 className="wiz__title">{title}</h2>
      {lead && <p className="wiz__lead">{lead}</p>}
    </>
  );
}

function TemplateStep({ templates, selected, onPick }: { templates: VMTemplate[]; selected?: string; onPick: (t: VMTemplate) => void }) {
  return (
    <>
      <StepHead title="What would you like to run?" lead="Pick a starting point. Everything can be changed later." />
      {GROUPS.map((g) => {
        const items = templates.filter((t) => t.group === g.id);
        if (items.length === 0) return null;
        return (
          <section key={g.id} className="stack" style={{ gap: 10 }}>
            <div className="tmpl-group">{g.label}</div>
            <div className="tmpl-grid">
              {items.map((t) => (
                <button key={t.id} type="button" className={`choice ${selected === t.id ? "is-selected" : ""}`} onClick={() => onPick(t)} aria-label={t.name}>
                  <span className="vm-glyph">{templateGlyph(t.id)}</span>
                  <span className="stack" style={{ gap: 3 }}>
                    <span className="choice__title">{t.name}</span>
                    <span className="choice__desc">{t.summary}</span>
                  </span>
                </button>
              ))}
            </div>
          </section>
        );
      })}
    </>
  );
}

function ResourcesStep({
  s,
  t,
  caps,
  set,
  setState,
}: {
  s: WizardState;
  t: VMTemplate;
  caps: VMCapabilities;
  set: (p: Partial<WizardState>) => void;
  setState: (fn: (s: WizardState | null) => WizardState | null) => void;
}) {
  const [advanced, setAdvanced] = useState(false);
  const maxCores = Math.max(1, caps.cpus || 32);
  const maxMem = caps.memoryMB > 0 ? caps.memoryMB : 131072;
  const memSteps = MEMORY_STEPS.filter((m) => m <= maxMem && m >= Math.min(t.minMemoryMB, 512));
  const memIndex = Math.max(0, memSteps.findIndex((m) => m >= s.memoryMB));
  return (
    <>
      <StepHead title={`Name your ${t.name} VM`} lead="Then pick a size. You can change it later when the VM is off." />
      <div className="grid-2">
        <Field label="Name" hint="Shown everywhere in HardyOS.">
          {(id) => (
            <TextInput
              id={id}
              value={s.name}
              placeholder={t.group === "gaming" ? "Gaming PC" : t.name}
              autoFocus
              onChange={(e) => {
                const name = e.target.value;
                set({ name, ...(s.idTouched ? {} : { id: idFromName(name) }) });
              }}
            />
          )}
        </Field>
        <Field label="Short name" hint="Used for its disks and in logs.">
          {(id) => <TextInput id={id} value={s.id} className="input mono" onChange={(e) => set({ id: e.target.value.toLowerCase(), idTouched: true })} />}
        </Field>
      </div>
      <div className="preset-grid" role="radiogroup" aria-label="Size">
        {t.presets.map((p) => (
          <button
            key={p.id}
            type="button"
            role="radio"
            aria-checked={s.preset === p.id}
            className={`choice ${s.preset === p.id ? "is-selected" : ""}`}
            onClick={() => setState((x) => (x ? applyPreset(x, t, p.id) : x))}
          >
            <span className="choice__title">{p.name}</span>
            <span className="choice__desc">{p.summary}</span>
            <span className="choice__specs">
              {p.cores * p.threads} CPU · {memory(p.memoryMB)} · {diskSize(p.diskGB)}
            </span>
          </button>
        ))}
      </div>
      <Card>
        <div className="stack">
          <div className="range-row">
            <label htmlFor="vm-cores">
              <CpuIcon size={14} /> CPU cores
            </label>
            <input
              id="vm-cores"
              className="range"
              type="range"
              min={1}
              max={Math.max(1, Math.floor(maxCores / s.threads))}
              value={s.cores}
              onChange={(e) => set({ cores: Number(e.target.value), preset: "custom" })}
            />
            <output htmlFor="vm-cores">
              {s.cores * s.threads} of {caps.cpus || "?"}
            </output>
          </div>
          <div className="range-row">
            <label htmlFor="vm-mem">
              <MemoryIcon size={14} /> Memory
            </label>
            <input
              id="vm-mem"
              className="range"
              type="range"
              min={0}
              max={Math.max(0, memSteps.length - 1)}
              value={memIndex}
              onChange={(e) => set({ memoryMB: memSteps[Number(e.target.value)] ?? s.memoryMB, preset: "custom" })}
            />
            <output htmlFor="vm-mem">{memory(s.memoryMB)}</output>
          </div>
          {caps.memoryMB > 0 && caps.committedMB + s.memoryMB > caps.memoryMB * 0.85 && (
            <Alert tone="warn">
              Running VMs would use {memory(caps.committedMB + s.memoryMB)} of the server's {memory(caps.memoryMB)}. The server, its storage cache and apps
              may slow down while they all run.
            </Alert>
          )}
        </div>
      </Card>
      <div>
        <Button variant="ghost" size="sm" onClick={() => setAdvanced(!advanced)} aria-expanded={advanced}>
          {advanced ? "Hide" : "Show"} advanced settings
        </Button>
      </div>
      {advanced && (
        <Card title="Advanced">
          <div className="grid-2">
            <Field label="Firmware" hint="UEFI suits nearly everything; BIOS is for old systems.">
              {(id) => (
                <Select id={id} value={s.firmware} onChange={(e) => set({ firmware: e.target.value as WizardState["firmware"] })}>
                  <option value="uefi">UEFI</option>
                  {caps.arch.legacyBios && <option value="bios">BIOS (legacy)</option>}
                </Select>
              )}
            </Field>
            <Field label="Threads per core" hint="2 gives each core a sibling thread, like the server's CPU.">
              {(id) => (
                <Select id={id} value={String(s.threads)} onChange={(e) => set({ threads: Number(e.target.value), preset: "custom" })}>
                  <option value="1">1</option>
                  <option value="2">2</option>
                </Select>
              )}
            </Field>
          </div>
          <div className="stack" style={{ marginTop: 12 }}>
            <Toggle
              label="Secure Boot"
              description={caps.secureBoot ? "Only signed systems start (Windows 11 needs it)." : "This server has no Secure Boot firmware for VMs."}
              checked={s.secureBoot && s.firmware === "uefi"}
              disabled={!caps.secureBoot || s.firmware !== "uefi"}
              onChange={(v) => set({ secureBoot: v })}
            />
            <Toggle
              label="TPM 2.0"
              description={caps.tpm ? "A virtual security chip (Windows 11 needs it)." : "This server has no virtual TPM."}
              checked={s.tpm}
              disabled={!caps.tpm}
              onChange={(v) => set({ tpm: v })}
            />
          </div>
        </Card>
      )}
    </>
  );
}

function DisksStep({ s, t, caps, set }: { s: WizardState; t: VMTemplate; caps: VMCapabilities; set: (p: Partial<WizardState>) => void }) {
  const setDisk = (i: number, patch: Partial<WizardState["disks"][number]>) => set({ disks: s.disks.map((d, j) => (j === i ? { ...d, ...patch } : d)) });
  const imported = !installsFromISO(t);
  return (
    <>
      <StepHead title="Disks" lead="Each disk is a ZFS volume on the pool you choose: it only takes the space it really uses, and snapshots cover it." />
      <Field label="Pool" hint={caps.pools.length === 0 ? "Create a storage pool first in Storage Manager." : "Fast pools (SSDs) make VMs feel quicker."}>
        {(id) => (
          <Select id={id} value={s.pool} onChange={(e) => set({ pool: e.target.value })}>
            {caps.pools.length === 0 && <option value="">No pools</option>}
            {caps.pools.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </Select>
        )}
      </Field>
      <div className="stack">
        {s.disks.map((d, i) => (
          <div key={d.name} className="row" style={{ gap: 10, alignItems: "flex-end" }}>
            <span className="vm-glyph" style={{ width: 34, height: 34 }}>
              <StorageIcon size={16} />
            </span>
            <Field label={i === 0 ? (imported ? "System disk (the image goes here)" : "System disk") : `Disk ${i + 1}`}>
              {(id) => (
                <div className="row" style={{ gap: 6 }}>
                  <TextInput
                    id={id}
                    type="number"
                    min={1}
                    className="input mono"
                    style={{ width: 110 }}
                    value={d.sizeGB}
                    onChange={(e) => setDisk(i, { sizeGB: Number(e.target.value) })}
                  />
                  <span className="muted small">GB</span>
                </div>
              )}
            </Field>
            <Field label="Type">
              {(id) => (
                <Select id={id} value={d.bus} onChange={(e) => setDisk(i, { bus: e.target.value as WizardState["disks"][number]["bus"] })}>
                  <option value="virtio-scsi">VirtIO SCSI (fast)</option>
                  <option value="virtio-blk">VirtIO block</option>
                  {caps.arch.sata && <option value="sata">SATA (most compatible)</option>}
                </Select>
              )}
            </Field>
            {i > 0 && (
              <IconButton label={`Remove disk ${i + 1}`} onClick={() => set({ disks: s.disks.filter((_, j) => j !== i) })}>
                <TrashIcon size={16} />
              </IconButton>
            )}
          </div>
        ))}
      </div>
      {s.disks.length < 8 && (
        <div>
          <Button
            size="sm"
            onClick={() => {
              const used = new Set(s.disks.map((d) => d.name));
              let n = 1;
              while (used.has(`disk${n}`)) n++;
              set({ disks: [...s.disks, { name: `disk${n}`, sizeGB: 100, bus: s.disks[0]?.bus ?? "virtio-scsi" }] });
            }}
          >
            <PlusIcon size={14} /> Add a disk
          </Button>
        </div>
      )}
      <Toggle
        label="Allow more than the pool has free"
        description="Disks are thin and only fill up as the VM writes. Without this, the disks must fit in the pool's free space."
        checked={s.allowOvercommit}
        onChange={(v) => set({ allowOvercommit: v })}
      />
      {t.os === "windows" && s.disks[0]?.bus !== "sata" && (
        <div className="tip">
          <DiscIcon size={16} />
          <span>Windows Setup needs a driver to see VirtIO disks: choose Load driver and open the VirtIO drivers disc (it's attached for you).</span>
        </div>
      )}
    </>
  );
}

function MediaStep({
  s,
  t,
  arch,
  files,
  set,
  openFiles,
}: {
  s: WizardState;
  t: VMTemplate;
  arch: string;
  files: VMLibraryFile[];
  set: (p: Partial<WizardState>) => void;
  openFiles?: () => void;
}) {
  const iso = installsFromISO(t);
  const usable = files.filter((f) => (iso ? isISO(f.name) : isImage(f.name)));
  const suggestions = (t.images ?? []).filter((i) => (iso ? i.kind === "iso" : i.kind === "disk"));
  const file = chosenFile(s);
  return (
    <>
      <StepHead
        title={iso ? "Installer disc" : t.install === "cloud" ? "Cloud image and sign-in" : "Disk image"}
        lead={
          iso
            ? "The VM starts from this disc to install the system."
            : "The image is copied into the system disk. Images come from the ISO library or a download link."
        }
      />
      <div className="seg" role="group" aria-label="Where it comes from">
        <button type="button" aria-pressed={s.source === "library"} onClick={() => set({ source: "library" })}>
          <FolderIcon size={14} /> From the ISO library
        </button>
        <button type="button" aria-pressed={s.source === "url"} onClick={() => set({ source: "url" })}>
          <DownloadIcon size={14} /> Download by link
        </button>
      </div>
      {s.source === "library" ? (
        usable.length === 0 ? (
          <EmptyState
            icon={<DiscIcon size={28} />}
            title={iso ? "No installer discs yet" : "No disk images yet"}
            action={
              openFiles && (
                <Button onClick={openFiles}>
                  <FolderIcon size={14} /> Open the ISOs folder
                </Button>
              )
            }
          >
            Copy {iso ? "an .iso" : "an image"} into the ISOs shared folder from your computer (over the network or with the File Manager), or download one by link.
          </EmptyState>
        ) : (
          <div className="file-list" role="listbox" aria-label={iso ? "Installer discs" : "Disk images"}>
            {usable.map((f) => (
              <button
                key={f.name}
                type="button"
                role="option"
                aria-selected={s.file === f.name}
                className={`file-row ${s.file === f.name ? "is-selected" : ""}`}
                onClick={() => set({ file: f.name })}
              >
                <DiscIcon size={16} />
                <span className="file-row__name">{f.name}</span>
                <span className="small muted mono">{bytes(f.size)}</span>
              </button>
            ))}
          </div>
        )
      ) : (
        <div className="stack">
          <Field label="Download link" hint={file ? `Saved in the ISO library as ${file}` : "An https:// link to the file."}>
            {(id) => <TextInput id={id} value={s.url} placeholder="https://…" spellCheck={false} onChange={(e) => set({ url: e.target.value })} />}
          </Field>
          <Field label="SHA-256 checksum (optional)" hint="From the download page: the file is checked and deleted if it doesn't match.">
            {(id) => <TextInput id={id} className="input mono" value={s.sha256} spellCheck={false} onChange={(e) => set({ sha256: e.target.value })} />}
          </Field>
        </div>
      )}
      {suggestions.length > 0 && (
        <div className="stack" style={{ gap: 6 }}>
          <span className="small muted">Where to get it</span>
          <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
            {suggestions.map((im) => {
              const url = im.urls?.[arch];
              return url ? (
                <Button key={im.name} size="sm" onClick={() => set({ source: "url", url })}>
                  <DownloadIcon size={14} /> {im.name}
                </Button>
              ) : im.page ? (
                <a key={im.name} className="btn btn--secondary btn--sm" href={im.page} target="_blank" rel="noreferrer">
                  <ExternalIcon size={14} /> {im.name}
                </a>
              ) : null;
            })}
          </div>
        </div>
      )}
      {t.virtio && (
        <Toggle
          label="Add the VirtIO drivers disc"
          description="Drivers for fast disks and networking in Windows. Downloaded once from Fedora and checked."
          checked={s.virtio}
          onChange={(v) => set({ virtio: v })}
        />
      )}
      {t.cloudInit && (
        <Card title="Sign-in">
          <div className="stack">
            <div className="grid-2">
              <Field label="User name">{(id) => <TextInput id={id} value={s.user} className="input mono" onChange={(e) => set({ user: e.target.value })} />}</Field>
              <Field label="Password (optional)" hint="At least 8 characters. An SSH key is safer.">
                {(id) => <TextInput id={id} type="password" autoComplete="new-password" value={s.password} onChange={(e) => set({ password: e.target.value })} />}
              </Field>
            </div>
            <Field label="SSH public keys" hint="One per line, like ssh-ed25519 AAAA… you@laptop">
              {(id) => (
                <textarea id={id} className="input mono" rows={3} value={s.sshKeys} spellCheck={false} onChange={(e) => set({ sshKeys: e.target.value })} />
              )}
            </Field>
          </div>
        </Card>
      )}
      {(t.notes ?? []).map((n) => (
        <div key={n} className="tip">
          <span>{n}</span>
        </div>
      ))}
    </>
  );
}

const NET_CHOICES = [
  { mode: "bridge" as const, title: "Home network", desc: "Gets its own address from your router, like any computer. Recommended." },
  { mode: "nat" as const, title: "Private (NAT)", desc: "Reaches the internet through the server; other devices can't reach it." },
  { mode: "vlan" as const, title: "A VLAN", desc: "On a tagged VLAN of your network, for routers and separated networks." },
];

function NetworkStep({ s, caps, set }: { s: WizardState; caps: VMCapabilities; set: (p: Partial<WizardState>) => void }) {
  const setNIC = (i: number, patch: Partial<WizardState["nics"][number]>) => set({ nics: s.nics.map((n, j) => (j === i ? { ...n, ...patch } : n)) });
  const bridged = s.nics.some((n) => n.mode !== "nat");
  return (
    <>
      <StepHead title="Network" lead={s.nics.length > 1 ? "This VM has a network card for each side, like a router." : "How the VM connects."} />
      {s.nics.map((n, i) => (
        <div key={i} className="stack" style={{ gap: 8 }}>
          {s.nics.length > 1 && <span className="tmpl-group">{i === 0 ? "First card (WAN)" : `Card ${i + 1} (LAN)`}</span>}
          <div className="tmpl-grid" role="radiogroup" aria-label={`Network card ${i + 1}`}>
            {NET_CHOICES.map((ch) => (
              <button
                key={ch.mode}
                type="button"
                role="radio"
                aria-checked={n.mode === ch.mode}
                className={`choice ${n.mode === ch.mode ? "is-selected" : ""}`}
                onClick={() => setNIC(i, { mode: ch.mode, vlan: ch.mode === "vlan" && !n.vlan ? 10 : n.vlan })}
              >
                <NetworkIcon size={18} />
                <span className="stack" style={{ gap: 3 }}>
                  <span className="choice__title">{ch.title}</span>
                  <span className="choice__desc">{ch.desc}</span>
                </span>
              </button>
            ))}
          </div>
          {n.mode === "vlan" && (
            <Field label="VLAN ID">
              {(id) => <TextInput id={id} type="number" min={1} max={4094} className="input mono" style={{ width: 120 }} value={n.vlan} onChange={(e) => setNIC(i, { vlan: Number(e.target.value) })} />}
            </Field>
          )}
          {n.mode !== "nat" && (
            <Toggle
              label="Allow address spoofing"
              description="Lets the card use MAC and IP addresses other than its own. Only routers and firewalls (OPNsense, pfSense) need this."
              checked={n.allowSpoofing}
              onChange={(v) => setNIC(i, { allowSpoofing: v })}
            />
          )}
        </div>
      ))}
      <Field label="Network card model" hint="VirtIO is fastest; Intel e1000e works without drivers.">
        {(id) => (
          <Select id={id} value={s.nicModel} onChange={(e) => set({ nicModel: e.target.value as WizardState["nicModel"] })} style={{ maxWidth: 280 }}>
            <option value="virtio">VirtIO</option>
            <option value="e1000e">Intel e1000e</option>
          </Select>
        )}
      </Field>
      {bridged && !caps.bridge && (
        <Alert tone="info" title="The first VM on your network sets up a bridge">
          The server's network restarts for a few seconds and keeps its address. If the server can't be reached that way, HardyOS puts everything back by
          itself.
        </Alert>
      )}
    </>
  );
}

function ReviewStep({ s, t, caps, set }: { s: WizardState; t: VMTemplate; caps: VMCapabilities; set: (p: Partial<WizardState>) => void }) {
  const file = chosenFile(s);
  const iso = installsFromISO(t);
  const nets = s.nics.map((n) => (n.mode === "bridge" ? "Home network" : n.mode === "nat" ? "Private (NAT)" : `VLAN ${n.vlan}`)).join(", ");
  const total = s.disks.reduce((a, d) => a + d.sizeGB, 0);
  const rows: [string, ReactNode][] = [
    ["Template", t.name],
    ["Name", `${s.name} (${s.id})`],
    ["CPU", `${s.cores * s.threads} virtual CPUs`],
    ["Memory", memory(s.memoryMB)],
    ["Firmware", `${s.firmware === "uefi" ? "UEFI" : "BIOS"}${s.secureBoot && s.firmware === "uefi" ? " · Secure Boot" : ""}${s.tpm ? " · TPM 2.0" : ""}`],
    ["Disks", `${s.disks.length} on ${s.pool}, ${diskSize(total)} in all (thin)`],
    [iso ? "Installer" : "Image", `${file || "none"}${s.source === "url" ? " (downloaded first)" : ""}`],
    ["Network", nets],
    ["Devices", s.devices.length === 0 ? "None" : s.devices.map((d) => `${d.kind.toUpperCase()} ${d.id}`).join(", ")],
  ];
  return (
    <>
      <StepHead title="Ready to create" lead="Check the details. Anything can be changed later from the VM's page." />
      <Card>
        <dl className="kv">
          {rows.map(([k, v]) => (
            <div key={k} style={{ display: "contents" }}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
      </Card>
      <div className="stack">
        <Toggle label="Start it when it's ready" description={iso ? "Then open its screen to install the system." : undefined} checked={s.start} onChange={(v) => set({ start: v })} />
        <Toggle label="Start with the server" description="After a power cut or restart, the VM starts by itself." checked={s.autostart} onChange={(v) => set({ autostart: v })} />
      </div>
      {!caps.kvm && <Alert tone="warn">Hardware virtualization is off: the VM won't start until it's turned on in the server's BIOS.</Alert>}
    </>
  );
}
