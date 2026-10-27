import type { BackupItem, BackupRetention, BackupSchedule, BackupTask, BackupTarget } from "@hardy/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { errorMessage } from "../../api";
import { dateTime, relativeTime } from "../../format";
import { EditIcon, CloudUpIcon, PlayIcon, PlusIcon, TrashIcon } from "../../icons";
import { Alert, Button, Card, EmptyState, ErrorBox, Field, IconButton, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { backupKeys, createTask, deleteTask, itemKey, itemLabel, kindLabel, runTask, targetWhere, updateTask, useOverview, useSources, weekdays } from "./backupApi";
import { JobProgress, RunBadge, RunSummary, StateDot } from "./parts";
import type { BackupTabProps } from "./tabs";

export function Tasks({ go }: BackupTabProps) {
  const q = useOverview();
  const [editing, setEditing] = useState<BackupTask | "new" | null>(null);
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const { tasks, targets } = q.data;
  return (
    <div className="stack">
      <PageHeader
        title="Backup tasks"
        subtitle="Each task backs up what you choose to one destination on a schedule, from a snapshot, and keeps versions for as long as you say."
        actions={
          <Button variant="primary" onClick={() => setEditing("new")} disabled={targets.length === 0}>
            <PlusIcon size={15} /> New task
          </Button>
        }
      />
      {targets.length === 0 ? (
        <EmptyState
          icon={<CloudUpIcon size={28} />}
          title="Add a destination first"
          action={
            <Button variant="primary" onClick={() => go("destinations")}>
              Add a destination
            </Button>
          }
        >
          Backups go to S3-compatible storage (Amazon S3, Wasabi, Cloudflare R2, MinIO) or Backblaze B2, encrypted with a key only this server and your recovery kit
          hold.
        </EmptyState>
      ) : tasks.length === 0 ? (
        <EmptyState
          icon={<CloudUpIcon size={28} />}
          title="No backup tasks yet"
          action={
            <Button variant="primary" onClick={() => setEditing("new")}>
              Make a backup task
            </Button>
          }
        >
          Choose shared folders, apps, virtual machines and this server's settings, and when to back them up.
        </EmptyState>
      ) : (
        <div className="bk-grid">
          {tasks.map((t) => (
            <TaskCard key={t.id} task={t} target={targets.find((x) => x.id === t.target)} onEdit={() => setEditing(t)} onVersions={() => go("restore", { target: t.target, task: t.id })} />
          ))}
        </div>
      )}
      {editing && <TaskWizard task={editing === "new" ? null : editing} targets={targets} onClose={() => setEditing(null)} />}
    </div>
  );
}

function scheduleText(s: BackupSchedule): string {
  switch (s.frequency) {
    case "manual":
      return "Only when you start it";
    case "hourly":
      return `Every ${s.everyHours === 1 ? "hour" : `${s.everyHours} hours`} (from ${s.time})`;
    case "daily":
      return `Every day at ${s.time}`;
    case "weekly":
      return `${(s.weekdays ?? []).map((d) => weekdays[d]!.slice(0, 3)).join(", ")} at ${s.time}`;
  }
  return "";
}

function TaskCard({ task, target, onEdit, onVersions }: { task: BackupTask; target?: BackupTarget; onEdit: () => void; onVersions: () => void }) {
  const qc = useQueryClient();
  const sources = useSources();
  const [job, setJob] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const names: Record<string, string> = {};
  sources.shares.forEach((s) => (names[`share:${s.id}`] = s.name));
  sources.apps.forEach((a) => (names[`app:${a.id}`] = a.name));
  sources.vms.forEach((v) => (names[`vm:${v.id}`] = v.name));
  const refresh = () => void qc.invalidateQueries({ queryKey: backupKeys.all });

  async function run() {
    try {
      const r = await runTask(task.id);
      setJob(r.job.id);
    } catch (e) {
      toast("error", "Couldn't start the backup", errorMessage(e));
    }
  }
  async function toggle(on: boolean) {
    try {
      await updateTask(task.id, { name: task.name, target: task.target, items: task.items, enabled: on });
      refresh();
    } catch (e) {
      toast("error", "Couldn't change the task", errorMessage(e));
    }
  }
  const running = task.running || job !== null;
  return (
    <article className={`bk-card ${running ? "is-running" : ""} ${task.enabled ? "" : "is-off"}`} aria-label={task.name}>
      <header className="bk-card__head">
        <StateDot state={running ? "running" : task.lastRun?.state} />
        <div className="bk-card__title">
          <strong>{task.name}</strong>
          <span className="small muted">{target ? `${target.name} · ${targetWhere(target)}` : task.target}</span>
        </div>
        <RunBadge run={running ? { ...(task.lastRun ?? ({} as never)), state: "running" } : task.lastRun} />
      </header>
      <ul className="bk-chips" aria-label="What it backs up">
        {task.items.map((it) => (
          <li key={itemKey(it)} className={`bk-chip bk-chip--${it.kind}`} title={kindLabel[it.kind]}>
            {itemLabel(itemKey(it), names)}
          </li>
        ))}
      </ul>
      <dl className="bk-facts">
        <div>
          <dt>Last backup</dt>
          <dd>
            <RunSummary run={task.lastRun} />
          </dd>
        </div>
        <div>
          <dt>Schedule</dt>
          <dd className="small">{scheduleText(task.schedule)}</dd>
        </div>
        <div>
          <dt>Next</dt>
          <dd className="small" title={task.nextRun ? dateTime(task.nextRun) : undefined}>
            {task.enabled && task.nextRun ? relativeTime(task.nextRun) : task.enabled ? "—" : "Turned off"}
          </dd>
        </div>
        <div>
          <dt>Keeps</dt>
          <dd className="small mono">
            {task.retention.daily}d · {task.retention.weekly}w · {task.retention.monthly}m
          </dd>
        </div>
      </dl>
      {task.lastRun?.error && task.lastRun.state !== "succeeded" && (
        <Alert tone={task.lastRun.state === "failed" ? "bad" : "warn"} title={task.lastRun.state === "missed" ? "Missed" : "Last run"}>
          {task.lastRun.error}
        </Alert>
      )}
      {job && (
        <JobProgress
          id={job}
          label={`Backing up ${task.name}`}
          onDone={(j) => {
            refresh();
            setTimeout(() => setJob(null), j.state === "succeeded" ? 2500 : 8000);
          }}
        />
      )}
      <footer className="bk-card__foot">
        <Toggle label="On" checked={task.enabled} onChange={toggle} />
        <div className="bk-card__actions">
          <Button size="sm" variant="primary" onClick={run} disabled={running}>
            <PlayIcon size={13} /> Back up now
          </Button>
          <Button size="sm" onClick={onVersions}>
            Versions
          </Button>
          <IconButton label={`Edit ${task.name}`} onClick={onEdit}>
            <EditIcon size={16} />
          </IconButton>
          <IconButton label={`Delete ${task.name}`} onClick={() => setDeleting(true)}>
            <TrashIcon size={16} />
          </IconButton>
        </div>
      </footer>
      {deleting && (
        <ConfirmDialog
          title={`Delete ${task.name}?`}
          confirmLabel="Delete task"
          onClose={() => setDeleting(false)}
          onConfirm={async () => {
            await deleteTask(task.id);
            refresh();
          }}
        >
          It stops backing up. The versions it made stay at the destination, and you can still restore from them.
        </ConfirmDialog>
      )}
    </article>
  );
}

type Step = "what" | "where" | "when" | "keep";
const steps: { id: Step; label: string }[] = [
  { id: "what", label: "What" },
  { id: "where", label: "Where" },
  { id: "when", label: "When" },
  { id: "keep", label: "Keep" },
];

/** New or changed task, in four steps. */
export function TaskWizard({ task, targets, onClose }: { task: BackupTask | null; targets: BackupTarget[]; onClose: () => void }) {
  const qc = useQueryClient();
  const sources = useSources();
  const [step, setStep] = useState<Step>("what");
  const [items, setItems] = useState<string[]>(task ? task.items.map(itemKey) : []);
  const [target, setTarget] = useState(task?.target ?? targets[0]?.id ?? "");
  const [schedule, setSchedule] = useState<BackupSchedule>(task?.schedule ?? { frequency: "daily", time: "01:30" });
  const [retention, setRetention] = useState<BackupRetention>(task?.retention ?? { daily: 7, weekly: 4, monthly: 12 });
  const [name, setName] = useState(task?.name ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const idx = steps.findIndex((s) => s.id === step);

  const toggleItem = (k: string, on: boolean) => setItems((l) => (on ? [...l, k] : l.filter((x) => x !== k)));
  const ready: Record<Step, boolean> = {
    what: items.length > 0,
    where: !!target,
    when: schedule.frequency !== "weekly" || (schedule.weekdays ?? []).length > 0,
    keep: name.trim().length > 0 && retention.daily + retention.weekly + retention.monthly > 0,
  };

  async function save() {
    setBusy(true);
    setError(null);
    const body = {
      name: name.trim(),
      target,
      items: items.map((k): BackupItem => (k === "system" ? { kind: "system" } : { kind: k.slice(0, k.indexOf(":")) as BackupItem["kind"], id: k.slice(k.indexOf(":") + 1) })),
      schedule,
      retention,
    };
    try {
      if (task) await updateTask(task.id, body);
      else await createTask(body);
      toast("success", task ? "Task saved" : "Backup task made", schedule.frequency === "manual" ? undefined : `First backup: ${scheduleText(schedule).toLowerCase()}.`);
      void qc.invalidateQueries({ queryKey: backupKeys.all });
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    }
    setBusy(false);
  }

  const group = (label: string, kind: string, list: { id: string; name: string }[]) =>
    list.length > 0 && (
      <fieldset className="bk-pick">
        <legend>{label}</legend>
        {list.map((s) => {
          const k = `${kind}:${s.id}`;
          return (
            <label key={k} className={`bk-pick__item ${items.includes(k) ? "is-on" : ""}`}>
              <input type="checkbox" checked={items.includes(k)} onChange={(e) => toggleItem(k, e.target.checked)} />
              <span>{s.name}</span>
            </label>
          );
        })}
      </fieldset>
    );

  return (
    <Dialog title={task ? `Change ${task.name}` : "New backup task"} width={640} onClose={onClose}>
      <ol className="bk-steps" aria-label="Steps">
        {steps.map((s, i) => (
          <li key={s.id} className={`bk-step ${s.id === step ? "is-active" : ""} ${i < idx ? "is-done" : ""}`} aria-current={s.id === step ? "step" : undefined}>
            <span className="bk-step__num mono">{i + 1}</span>
            {s.label}
          </li>
        ))}
      </ol>
      <div className="bk-wizard">
        {step === "what" &&
          (sources.pending ? (
            <Loading />
          ) : (
            <div className="stack">
              <p className="small muted">Everything is backed up from a ZFS snapshot, so files are as they were at one moment. VMs with the guest agent are paused for it (their file systems are frozen).</p>
              {group("Shared folders", "share", sources.shares)}
              {group("Apps (data and settings)", "app", sources.apps)}
              {group("Virtual machines (disks and settings)", "vm", sources.vms)}
              <fieldset className="bk-pick">
                <legend>This server</legend>
                <label className={`bk-pick__item ${items.includes("system") ? "is-on" : ""}`}>
                  <input type="checkbox" checked={items.includes("system")} onChange={(e) => toggleItem("system", e.target.checked)} />
                  <span>
                    Settings and domain <span className="small muted">(accounts, network, encryption keys, the domain controller: with the folders, apps and VMs, enough to rebuild this server)</span>
                  </span>
                </label>
              </fieldset>
            </div>
          ))}
        {step === "where" && (
          <Field label="Destination">
            {(id) => (
              <Select id={id} value={target} onChange={(e) => setTarget(e.target.value)}>
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} · {targetWhere(t)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        {step === "when" && <ScheduleEditor value={schedule} onChange={setSchedule} />}
        {step === "keep" && (
          <div className="stack">
            <p className="small muted">Older versions are thinned out: one per day for the last days, one per week, one per month. Space comes back at the destination's weekly upkeep.</p>
            <div className="bk-row3">
              {(["daily", "weekly", "monthly"] as const).map((k) => (
                <Field key={k} label={k === "daily" ? "Daily versions" : k === "weekly" ? "Weekly versions" : "Monthly versions"}>
                  {(id) => (
                    <TextInput
                      id={id}
                      type="number"
                      min={0}
                      max={1000}
                      className="input mono"
                      value={retention[k]}
                      onChange={(e) => setRetention({ ...retention, [k]: Math.max(0, Number(e.target.value) || 0) })}
                    />
                  )}
                </Field>
              ))}
            </div>
            <Field label="Task name">{(id) => <TextInput id={id} value={name} maxLength={64} placeholder="Nightly to the cloud" onChange={(e) => setName(e.target.value)} />}</Field>
          </div>
        )}
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
      <footer className="dialog__foot">
        {idx > 0 && <Button onClick={() => setStep(steps[idx - 1]!.id)}>Back</Button>}
        <span style={{ flex: 1 }} />
        <Button onClick={onClose}>Cancel</Button>
        {idx < steps.length - 1 ? (
          <Button variant="primary" disabled={!ready[step]} onClick={() => setStep(steps[idx + 1]!.id)}>
            Next
          </Button>
        ) : (
          <Button variant="primary" busy={busy} disabled={!ready.keep || !ready.what} onClick={save}>
            {task ? "Save" : "Make task"}
          </Button>
        )}
      </footer>
    </Dialog>
  );
}

export function ScheduleEditor({ value, onChange }: { value: BackupSchedule; onChange: (s: BackupSchedule) => void }) {
  const set = (p: Partial<BackupSchedule>) => onChange({ ...value, ...p });
  return (
    <div className="stack">
      <Field label="How often">
        {(id) => (
          <Select
            id={id}
            value={value.frequency}
            onChange={(e) => {
              const f = e.target.value as BackupSchedule["frequency"];
              onChange({ frequency: f, time: value.time || "01:30", everyHours: f === "hourly" ? value.everyHours || 6 : undefined, weekdays: f === "weekly" ? value.weekdays?.length ? value.weekdays : [0] : undefined });
            }}
          >
            <option value="daily">Every day</option>
            <option value="weekly">On some days of the week</option>
            <option value="hourly">Every few hours</option>
            <option value="manual">Only when I start it</option>
          </Select>
        )}
      </Field>
      {value.frequency === "hourly" && (
        <Field label="Every">
          {(id) => (
            <Select id={id} value={value.everyHours ?? 6} onChange={(e) => set({ everyHours: Number(e.target.value) })}>
              {[1, 2, 3, 4, 6, 8, 12].map((h) => (
                <option key={h} value={h}>
                  {h === 1 ? "hour" : `${h} hours`}
                </option>
              ))}
            </Select>
          )}
        </Field>
      )}
      {value.frequency === "weekly" && (
        <fieldset className="bk-days">
          <legend className="field__label">Days</legend>
          {weekdays.map((d, i) => {
            const on = (value.weekdays ?? []).includes(i);
            return (
              <label key={d} className={`bk-day ${on ? "is-on" : ""}`}>
                <input
                  type="checkbox"
                  checked={on}
                  onChange={(e) => set({ weekdays: e.target.checked ? [...(value.weekdays ?? []), i].sort() : (value.weekdays ?? []).filter((x) => x !== i) })}
                />
                {d.slice(0, 3)}
              </label>
            );
          })}
        </fieldset>
      )}
      {value.frequency !== "manual" && (
        <Field label={value.frequency === "hourly" ? "Starting at" : "Time"} hint="Server time. Pick a quiet hour: the first backup of a big folder can take a while.">
          {(id) => <TextInput id={id} type="time" className="input mono" value={value.time ?? "01:30"} onChange={(e) => set({ time: e.target.value })} />}
        </Field>
      )}
      <Card>
        <p className="small muted">A backup that can't start within 30 minutes of its time (the server was off, or the previous one was still running) is reported as missed.</p>
      </Card>
    </div>
  );
}
