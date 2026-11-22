import type { Job, VM, VMSchedule } from "@hardy/api-client";
import { useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { TemplateIcon, TrashIcon, UsbIcon } from "../../icons";
import { Alert, Badge, Button, Card, Field, IconButton, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { useDevices } from "./devices/deviceApi";

// VM polish (decisions 410-419): snapshot schedules, saved templates, USB
// hot-plug, the Windows answer disc and how protected a VM is.

export const SCHEDULE_LIMITS: Record<keyof VMSchedule, number> = { hourly: 48, daily: 62, weekly: 52, monthly: 36 };
const SCHEDULE_LABEL: Record<keyof VMSchedule, string> = { hourly: "Hourly", daily: "Daily", weekly: "Weekly", monthly: "Monthly" };
const EMPTY: VMSchedule = { hourly: 0, daily: 0, weekly: 0, monthly: 0 };

/** Problems with a schedule, for the form. */
export function scheduleProblems(s: VMSchedule): string[] {
  const out: string[] = [];
  for (const k of Object.keys(SCHEDULE_LIMITS) as (keyof VMSchedule)[]) {
    const n = s[k];
    if (!Number.isInteger(n) || n < 0 || n > SCHEDULE_LIMITS[k]) out.push(`${SCHEDULE_LABEL[k]}: keep 0 to ${SCHEDULE_LIMITS[k]}`);
  }
  return out;
}

/** Plain words for a schedule: "7 daily, 4 weekly" or "Off". */
export function scheduleSummary(s?: VMSchedule | null): string {
  if (!s) return "Off";
  const parts = (Object.keys(SCHEDULE_LABEL) as (keyof VMSchedule)[]).filter((k) => s[k] > 0).map((k) => `${s[k]} ${k}`);
  return parts.length ? `Keeps ${parts.join(", ")}` : "Off";
}

export function ScheduleCard({ vm, onJob }: { vm: VM; onJob: (j: Job) => void }) {
  const [s, setS] = useState<VMSchedule>(() => ({ ...EMPTY, ...(vm.schedule ?? {}) }));
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState<string | null>(null);
  const problems = scheduleProblems(s);
  const dirty = JSON.stringify(s) !== JSON.stringify({ ...EMPTY, ...(vm.schedule ?? {}) });
  const put = async (confirm?: string) => {
    const r = await unwrap(api.PUT("/vms/{id}/schedule", { params: { path: { id: vm.id } }, body: { schedule: s, ...(confirm ? { confirm } : {}) } }));
    onJob(r.job);
  };
  const save = async () => {
    setBusy(true);
    try {
      await put();
    } catch (e) {
      // Fewer of a kind would delete automatic snapshots there are now.
      if (e instanceof ApiFailure && e.code === "confirm_required") setConfirming(e.message);
      else toast("error", "Schedule not saved", errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Automatic snapshots" actions={<Badge tone={vm.schedule ? "accent" : "neutral"}>{scheduleSummary(vm.schedule)}</Badge>}>
      <div className="stack">
        <p className="small muted" style={{ margin: 0 }}>
          How many of each to keep. Hourly ones are taken on the hour, daily at midnight (UTC), weekly on Mondays, monthly on the 1st. Snapshots you take yourself are never
          deleted by the schedule; setting a kind to 0 removes its automatic snapshots.
        </p>
        <div className="grid-4">
          {(Object.keys(SCHEDULE_LABEL) as (keyof VMSchedule)[]).map((k) => (
            <Field key={k} label={SCHEDULE_LABEL[k]}>
              {(id) => (
                <TextInput
                  id={id}
                  type="number"
                  min={0}
                  max={SCHEDULE_LIMITS[k]}
                  className="input mono"
                  value={s[k]}
                  onChange={(e) => setS({ ...s, [k]: Number(e.target.value) })}
                />
              )}
            </Field>
          ))}
        </div>
        {vm.snapshotsBehind && (
          <Alert tone="warn" title="Automatic snapshots are late">
            A scheduled snapshot has been waiting: the VM is busy with something long (an import, a copy) or snapshots fail. See Log Center if it stays like this.
          </Alert>
        )}
        {problems.length > 0 && <span className="small" role="alert">{problems[0]}</span>}
        <div className="row">
          <Button variant="primary" disabled={!dirty || problems.length > 0} busy={busy} onClick={save}>
            Save schedule
          </Button>
        </div>
      </div>
      {confirming && (
        <ConfirmDialog
          title="Delete automatic snapshots?"
          confirmLabel="Save and delete"
          typeToConfirm={vm.name}
          onClose={() => setConfirming(null)}
          onConfirm={() => put(vm.name)}
        >
          <p>{confirming}</p>
        </ConfirmDialog>
      )}
    </Card>
  );
}

/** How snapshots and backups of the VM come out, in plain words. */
export function ProtectionNote({ vm }: { vm: VM }) {
  return vm.guestAgent ? (
    <div className="tip">
      <span>
        Snapshots, cloud backups and replication of this VM freeze the guest's files for a moment through the QEMU guest agent, so they're consistent. If the agent isn't
        running in the guest, they're taken like pulling the plug (crash-consistent) and marked so.
      </span>
    </div>
  ) : (
    <Alert tone="warn" title="Crash-consistent">
      Without the QEMU guest agent, snapshots, cloud backups and replication of the running VM are like pulling the plug: fine for most systems, but databases may need to
      recover. Turn on the guest agent in Settings and install it in the guest.
    </Alert>
  );
}

const TEMPLATE_ID = /^[a-z][a-z0-9-]{0,30}[a-z0-9]$/;

/** A short template name from a display name. */
export function templateIdFrom(name: string): string {
  const id = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 32)
    .replace(/-+$/, "");
  return /^[a-z]/.test(id) ? id : id ? `t-${id}`.slice(0, 32) : "";
}

export function MakeTemplateCard({ vm, onJob }: { vm: VM; onJob: (j: Job) => void }) {
  const [open, setOpen] = useState(false);
  const off = vm.state === "stopped" || vm.state === "crashed";
  return (
    <Card title="Make a template">
      <div className="row row--between" style={{ gap: 12 }}>
        <span className="small muted">
          Save this VM as a starting point for new ones: its disks are copied, its identity (addresses, passwords, TPM) left out.
          {vm.os === "windows" ? " Run Sysprep in Windows first so copies get their own identity." : vm.os === "linux" ? " Run `sudo cloud-init clean` in the guest first." : ""}
        </span>
        <Button onClick={() => setOpen(true)} disabled={!off} title={off ? undefined : "Shut the VM down first"}>
          <TemplateIcon size={15} /> Make template…
        </Button>
      </div>
      {open && <MakeTemplateDialog vm={vm} onClose={() => setOpen(false)} onJob={onJob} />}
    </Card>
  );
}

function MakeTemplateDialog({ vm, onClose, onJob }: { vm: VM; onClose: () => void; onJob: (j: Job) => void }) {
  const [name, setName] = useState(`${vm.name} template`);
  const [tid, setTid] = useState(templateIdFrom(`${vm.id}-template`));
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ok = TEMPLATE_ID.test(tid) && name.trim() !== "";
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await unwrap(api.POST("/vms/{id}/template", { params: { path: { id: vm.id } }, body: { templateId: tid, name: name.trim(), description } }));
      onJob(r.job);
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={`Make a template from ${vm.name}`}
      description="New VMs can start from it in the New VM wizard, under Your templates."
      onClose={onClose}
      onSubmit={ok ? submit : undefined}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={busy} disabled={!ok}>
            Make template
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="Name">{(id) => <TextInput id={id} value={name} maxLength={64} onChange={(e) => setName(e.target.value)} />}</Field>
        <Field label="Short name" hint="2 to 32 lowercase letters, digits and dashes." error={tid && !TEMPLATE_ID.test(tid) ? "Not a valid short name" : null}>
          {(id) => <TextInput id={id} className="input mono" value={tid} onChange={(e) => setTid(e.target.value)} />}
        </Field>
        <Field label="Notes (optional)">{(id) => <TextInput id={id} value={description} maxLength={500} onChange={(e) => setDescription(e.target.value)} />}</Field>
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
    </Dialog>
  );
}

/** USB devices plugged into a running VM now (hot-plug, vendor:product). */
export function LiveUSBCard({ vm, onJob }: { vm: VM; onJob: (j: Job) => void }) {
  const inv = useDevices();
  const [pick, setPick] = useState("");
  const [persist, setPersist] = useState(false);
  const [allowInput, setAllowInput] = useState(false);
  const [busy, setBusy] = useState(false);
  const installing = !!vm.unattend?.pending;
  const configured = new Set(vm.devices.filter((d) => d.kind === "usb").map((d) => d.id));
  const live = vm.liveUSB ?? [];
  const usb = (inv.data?.usb ?? []).filter((u) => !u.hub && !u.critical && !u.owner);
  const picked = usb.find((u) => `${u.vendorId}:${u.productId}` === pick);
  const label = (id: string) => {
    const u = (inv.data?.usb ?? []).find((x) => `${x.vendorId}:${x.productId}` === id);
    return u ? [u.manufacturer, u.product].filter(Boolean).join(" ") || id : id;
  };
  const run = async (path: "/vms/{id}/usb" | "/vms/{id}/usb/detach", device: string, keep: boolean) => {
    setBusy(true);
    try {
      const r = await unwrap(api.POST(path, { params: { path: { id: vm.id } }, body: { device, persist: keep, ...(allowInput ? { allowInput: true } : {}) } }));
      onJob(r.job);
      setPick("");
      setAllowInput(false);
    } catch (e) {
      toast("error", "USB", errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Plug in a USB device now">
      <div className="stack">
        {live.length > 0 && (
          <div className="stack" style={{ gap: 6 }}>
            {live.map((id) => (
              <div key={id} className="row" style={{ gap: 8 }}>
                <UsbIcon size={16} />
                <span className="grow">
                  {label(id)} <span className="mono small muted">{id}</span>
                </span>
                {configured.has(id) && <Badge tone="accent">Also at next start</Badge>}
                <IconButton label={`Unplug ${id}`} onClick={() => run("/vms/{id}/usb/detach", id, configured.has(id))}>
                  <TrashIcon size={15} />
                </IconButton>
              </div>
            ))}
          </div>
        )}
        <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "flex-end" }}>
          <Field label="Device">
            {(id) => (
              <Select id={id} value={pick} onChange={(e) => setPick(e.target.value)} style={{ minWidth: 260 }}>
                <option value="">Choose a USB device…</option>
                {usb.map((u) => {
                  const vp = `${u.vendorId}:${u.productId}`;
                  return (
                    <option key={u.port} value={vp} disabled={live.includes(vp)}>
                      {[u.manufacturer, u.product].filter(Boolean).join(" ") || "USB device"} ({vp}, port {u.port}){u.input ? " · keyboard/mouse" : ""}
                    </option>
                  );
                })}
              </Select>
            )}
          </Field>
          <Toggle label="Also at the next start" checked={persist} onChange={setPersist} />
          <Button variant="primary" disabled={!pick || installing || (!!picked?.input && !allowInput)} busy={busy} onClick={() => run("/vms/{id}/usb", pick, persist)}>
            <UsbIcon size={15} /> Plug in
          </Button>
        </div>
        {picked?.input && (
          <Toggle
            label="Give it the keyboard or mouse"
            description="The server's own console loses it while the VM has it."
            checked={allowInput}
            onChange={setAllowInput}
          />
        )}
        {installing && <Alert tone="info">Windows is still installing by itself: USB devices can be plugged in once it's installed.</Alert>}
        <span className="small muted">
          Devices the server needs (its boot stick, disks of a pool) aren't offered, and one a program on the server has open (the UPS monitor, an app's Zigbee stick) is
          refused. A whole USB controller can go to a VM as a PCI device in Hardware › Devices.
        </span>
      </div>
    </Card>
  );
}

/** The Windows answer disc holds the account's password: take it out once Windows is installed. */
export function AnswerDiscNotice({ vm, onRemove }: { vm: VM; onRemove: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  if (!vm.media.some((m) => m.kind === "unattend")) return null;
  const started = !!vm.unattend?.started;
  return (
    <Alert tone="info" title={started ? "Windows is installing by itself" : "Windows installs by itself on the first start"}>
      <div className="stack" style={{ gap: 8 }}>
        <span>
          {started
            ? "Watch it on the VM's screen. When Windows has signed in and installed the guest tools, HardyOS sees the guest agent, takes the setup disc out and deletes it (it holds the account's password). The VM's passed-through devices join at the next start after that."
            : "Start the VM and watch its screen: Setup picks the edition, wipes and partitions the VM's own new disk, loads the VirtIO drivers and signs in as your account once. Passed-through devices wait until Windows is installed, so Setup can't see them."}{" "}
          The setup disc is kept in the server's memory only: it's in no snapshot or backup, and a restart of the server loses it.
        </span>
        {started && (
          <div>
            <Button
              size="sm"
              busy={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  await onRemove();
                } finally {
                  setBusy(false);
                }
              }}
            >
              Windows is installed: take out the setup disc
            </Button>
          </div>
        )}
      </div>
    </Alert>
  );
}
