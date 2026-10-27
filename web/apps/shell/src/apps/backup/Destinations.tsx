import type { BackupMaintenance, BackupTarget, BackupTargetRequest } from "@hardy/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { errorMessage } from "../../api";
import { dateTime, relativeTime } from "../../format";
import { KeyIcon, PlusIcon, ShieldIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, EmptyState, ErrorBox, Field, IconButton, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { backupKeys, checkNow, createTarget, providers, pruneNow, recoveryKit, removeTarget, saveText, setMaintenance, targetWhere, updateTarget, useOverview, weekdays } from "./backupApi";
import { JobProgress, RunBadge } from "./parts";
import type { BackupTabProps } from "./tabs";

export function Destinations(_: BackupTabProps) {
  const q = useOverview();
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<BackupTarget | null>(null);
  const [kitFor, setKitFor] = useState<{ target: BackupTarget; fresh: boolean } | null>(null);
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const { targets, tasks } = q.data;
  return (
    <div className="stack">
      <PageHeader
        title="Destinations"
        subtitle="Where backups go. Everything is encrypted on this server before it leaves; the bucket only ever sees encrypted data."
        actions={
          <Button variant="primary" onClick={() => setAdding(true)}>
            <PlusIcon size={15} /> Add destination
          </Button>
        }
      />
      {targets.length === 0 ? (
        <EmptyState icon={<ShieldIcon size={28} />} title="No destinations yet" action={<Button variant="primary" onClick={() => setAdding(true)}>Add a destination</Button>}>
          Amazon S3, Wasabi, Cloudflare R2, a MinIO on your network, or Backblaze B2. You'll need a bucket and an access key that can read and write it.
        </EmptyState>
      ) : (
        <div className="bk-grid">
          {targets.map((t) => (
            <TargetCard key={t.id} target={t} used={tasks.filter((x) => x.target === t.id).map((x) => x.name)} onKit={() => setKitFor({ target: t, fresh: false })} onEdit={() => setEditing(t)} />
          ))}
        </div>
      )}
      {(adding || editing) && (
        <TargetDialog
          target={editing}
          onClose={() => {
            setAdding(false);
            setEditing(null);
          }}
          onCreated={(t) => setKitFor({ target: t, fresh: true })}
        />
      )}
      {kitFor && <KitDialog target={kitFor.target} fresh={kitFor.fresh} onClose={() => setKitFor(null)} />}
    </div>
  );
}

function TargetCard({ target, used, onKit, onEdit }: { target: BackupTarget; used: string[]; onKit: () => void; onEdit: () => void }) {
  const qc = useQueryClient();
  const [job, setJob] = useState<{ id: string; label: string } | null>(null);
  const [removing, setRemoving] = useState(false);
  const [maint, setMaint] = useState(false);
  const refresh = () => void qc.invalidateQueries({ queryKey: backupKeys.all });
  async function start(kind: "prune" | "check") {
    try {
      const r = kind === "prune" ? await pruneNow(target.id) : await checkNow(target.id);
      setJob({ id: r.job.id, label: kind === "prune" ? "Freeing space" : "Checking the backups" });
    } catch (e) {
      toast("error", "Couldn't start it", errorMessage(e));
    }
  }
  const m = target.maintenance;
  return (
    <article className="bk-card" aria-label={target.name}>
      <header className="bk-card__head">
        <span className={`bk-provider bk-provider--${target.kind}`} aria-hidden="true">
          {target.kind === "b2" ? "B2" : "S3"}
        </span>
        <div className="bk-card__title">
          <strong>{target.name}</strong>
          <span className="small muted">{targetWhere(target)}</span>
        </div>
        {!target.kitDownloadedAt && <Badge tone="warn">Kit not saved</Badge>}
      </header>
      <dl className="bk-facts">
        <div>
          <dt>Access key</dt>
          <dd className="mono small">{target.accessKeyHint || "—"}</dd>
        </div>
        <div>
          <dt>Limits</dt>
          <dd className="mono small">
            {target.limitUploadKiB ? `↑ ${target.limitUploadKiB} KiB/s` : "↑ none"} · {target.limitDownloadKiB ? `↓ ${target.limitDownloadKiB} KiB/s` : "↓ none"}
          </dd>
        </div>
        <div>
          <dt>Upkeep</dt>
          <dd className="small">
            {weekdays[m.weekday]}s {m.time}, reads back <span className="mono">{m.checkPercent}%</span>
          </dd>
        </div>
        <div>
          <dt>Last check</dt>
          <dd className="small">
            {target.lastCheck ? (
              <>
                <RunBadge run={target.lastCheck} /> <span title={dateTime(target.lastCheck.startedAt)}>{relativeTime(target.lastCheck.startedAt)}</span>
              </>
            ) : (
              "Not yet"
            )}
          </dd>
        </div>
      </dl>
      {target.lastCheck?.state === "failed" && (
        <Alert tone="bad" title="The last check failed">
          {target.lastCheck.error}
        </Alert>
      )}
      {!target.kitDownloadedAt && (
        <Alert tone="warn" title="Save the recovery kit">
          Without it, nobody can open these backups if this server is lost.
        </Alert>
      )}
      {used.length > 0 && <p className="small muted">Used by {used.join(", ")}</p>}
      {job && <JobProgress id={job.id} label={job.label} onDone={() => { refresh(); setTimeout(() => setJob(null), 4000); }} />}
      <footer className="bk-card__foot">
        <Button size="sm" variant="primary" onClick={onKit}>
          <KeyIcon size={14} /> Recovery kit
        </Button>
        <div className="bk-card__actions">
          <Button size="sm" onClick={() => start("check")} disabled={!!job}>
            Check now
          </Button>
          <Button size="sm" onClick={() => start("prune")} disabled={!!job}>
            Free space
          </Button>
          <Button size="sm" onClick={() => setMaint(true)}>
            Upkeep
          </Button>
          <Button size="sm" onClick={onEdit}>
            Change
          </Button>
          <IconButton label={`Remove ${target.name}`} onClick={() => setRemoving(true)} disabled={used.length > 0} title={used.length > 0 ? "Delete its tasks first" : undefined}>
            <TrashIcon size={16} />
          </IconButton>
        </div>
      </footer>
      {maint && <MaintenanceDialog target={target} onClose={() => setMaint(false)} />}
      {removing && (
        <ConfirmDialog
          title={`Remove ${target.name}?`}
          confirmLabel="Remove destination"
          typeToConfirm={target.name}
          onClose={() => setRemoving(false)}
          onConfirm={async () => {
            const r = await removeTarget(target.id, target.name);
            toast("info", "Removing the destination", "The backups in the bucket stay; you can connect to them again with the recovery kit.");
            void r;
            refresh();
          }}
        >
          This server forgets the destination and its keys. The backups stay in the bucket.
        </ConfirmDialog>
      )}
    </article>
  );
}

const emptyReq = (): BackupTargetRequest => ({ id: "", name: "", kind: "s3", endpoint: "https://s3.us-east-1.amazonaws.com", bucket: "", prefix: "hardyos", region: "us-east-1" });

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 32) || "backup";
}

/** Add or change a destination; the save is a job that tests the bucket. */
export function TargetDialog({ target, onClose, onCreated }: { target: BackupTarget | null; onClose: () => void; onCreated: (t: BackupTarget) => void }) {
  const qc = useQueryClient();
  const [provider, setProvider] = useState(target ? (target.kind === "b2" ? "b2" : "minio") : "aws");
  const [req, setReq] = useState<BackupTargetRequest>(() =>
    target
      ? { id: target.id, name: target.name, kind: target.kind, endpoint: target.endpoint, bucket: target.bucket, prefix: target.prefix, region: target.region, allowLan: target.allowLan, limitUploadKiB: target.limitUploadKiB, limitDownloadKiB: target.limitDownloadKiB }
      : emptyReq(),
  );
  const [existing, setExisting] = useState(false);
  const [job, setJob] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (p: Partial<BackupTargetRequest>) => setReq((r) => ({ ...r, ...p }));
  const pv = providers.find((p) => p.id === provider)!;

  function pick(id: string) {
    setProvider(id);
    const p = providers.find((x) => x.id === id)!;
    set({ kind: p.kind, endpoint: p.endpoint ?? "", region: p.region ?? "" });
  }
  async function save() {
    setBusy(true);
    setError(null);
    const body: BackupTargetRequest = { ...req, id: target ? target.id : slug(req.id || req.name) };
    if (!existing) delete body.repoKey;
    try {
      const r = target ? await updateTarget(target.id, body) : await createTarget(body);
      setJob(r.job.id);
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  }
  const ok = req.name.trim() && req.bucket.trim() && (target || (req.accessKey && req.secretKey)) && (req.kind === "b2" || (req.endpoint ?? "").startsWith("https://"));
  return (
    <Dialog title={target ? `Change ${target.name}` : "Add a destination"} width={620} onClose={onClose} onSubmit={() => ok && !busy && void save()}>
      <div className="stack">
        {!target && (
          <div className="bk-providers" role="radiogroup" aria-label="Storage service">
            {providers.map((p) => (
              <button key={p.id} type="button" role="radio" aria-checked={provider === p.id} className={`bk-providerpick ${provider === p.id ? "is-on" : ""}`} onClick={() => pick(p.id)}>
                {p.label}
              </button>
            ))}
          </div>
        )}
        <Field label="Name">{(id) => <TextInput id={id} value={req.name} maxLength={64} placeholder="Offsite" onChange={(e) => set({ name: e.target.value })} />}</Field>
        {req.kind === "s3" && (
          <div className="bk-row2">
            <Field label="Endpoint" hint={pv.hint ?? "https only"}>
              {(id) => <TextInput id={id} className="input mono" value={req.endpoint ?? ""} onChange={(e) => set({ endpoint: e.target.value.trim() })} />}
            </Field>
            <Field label="Region">{(id) => <TextInput id={id} className="input mono" value={req.region ?? ""} onChange={(e) => set({ region: e.target.value.trim() })} />}</Field>
          </div>
        )}
        <div className="bk-row2">
          <Field label="Bucket">{(id) => <TextInput id={id} className="input mono" value={req.bucket} onChange={(e) => set({ bucket: e.target.value.trim() })} />}</Field>
          <Field label="Folder in the bucket" hint="Several servers can share a bucket with a folder each.">
            {(id) => <TextInput id={id} className="input mono" value={req.prefix ?? ""} onChange={(e) => set({ prefix: e.target.value.trim() })} />}
          </Field>
        </div>
        <div className="bk-row2">
          <Field label={req.kind === "b2" ? "Key ID" : "Access key"} hint={target ? `Leave empty to keep ${target.accessKeyHint || "the saved key"}` : undefined}>
            {(id) => <TextInput id={id} className="input mono" autoComplete="off" value={req.accessKey ?? ""} onChange={(e) => set({ accessKey: e.target.value.trim() })} />}
          </Field>
          <Field label={req.kind === "b2" ? "Application key" : "Secret key"}>
            {(id) => <TextInput id={id} type="password" className="input mono" autoComplete="new-password" value={req.secretKey ?? ""} onChange={(e) => set({ secretKey: e.target.value.trim() })} />}
          </Field>
        </div>
        <details className="bk-more">
          <summary>More options</summary>
          <div className="stack">
            <div className="bk-row2">
              <Field label="Upload limit (KiB/s)" hint="0 = no limit">
                {(id) => <TextInput id={id} type="number" min={0} className="input mono" value={req.limitUploadKiB ?? 0} onChange={(e) => set({ limitUploadKiB: Math.max(0, Number(e.target.value) || 0) })} />}
              </Field>
              <Field label="Download limit (KiB/s)" hint="For restores and checks">
                {(id) => <TextInput id={id} type="number" min={0} className="input mono" value={req.limitDownloadKiB ?? 0} onChange={(e) => set({ limitDownloadKiB: Math.max(0, Number(e.target.value) || 0) })} />}
              </Field>
            </div>
            {req.kind === "s3" && (
              <Toggle
                label="The server is on my network"
                description="Allow a private address (a MinIO on your LAN). Addresses on this server itself and link-local addresses are never used."
                checked={!!req.allowLan}
                onChange={(v) => set({ allowLan: v })}
              />
            )}
            <Toggle
              label="Connect to existing backups"
              description="The bucket already holds HardyOS backups (from this server before a reinstall, or another one): enter the key from their recovery kit."
              checked={existing}
              onChange={setExisting}
            />
            {existing && (
              <Field label="Repository key (from the recovery kit)">
                {(id) => <TextInput id={id} className="input mono" autoComplete="off" value={req.repoKey ?? ""} onChange={(e) => set({ repoKey: e.target.value.trim() })} />}
              </Field>
            )}
          </div>
        </details>
        {error && <Alert tone="bad">{error}</Alert>}
        {job && (
          <JobProgress
            id={job}
            label="Testing the bucket"
            onDone={(j) => {
              setBusy(false);
              void qc.invalidateQueries({ queryKey: backupKeys.all });
              if (j.state !== "succeeded") return;
              const res = j.result as { created?: boolean; target?: BackupTarget };
              toast("success", target ? "Destination saved" : "Destination added");
              onClose();
              if (res.created && res.target) onCreated({ ...(res.target as BackupTarget), maintenance: { weekday: 0, time: "04:30", checkPercent: 5 }, kitDownloadedAt: null, lastCheck: null });
            }}
          />
        )}
      </div>
      <footer className="dialog__foot">
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="primary" type="submit" busy={busy} disabled={!ok}>
          {target ? "Save" : "Test and add"}
        </Button>
      </footer>
    </Dialog>
  );
}

/** The recovery kit: the administrator's password again, then a file to keep. */
export function KitDialog({ target, fresh, onClose }: { target: BackupTarget; fresh: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  async function get() {
    setBusy(true);
    setError(null);
    try {
      const kit = await recoveryKit(target.id, password);
      saveText(kit.fileName, kit.text);
      setSaved(true);
      setPassword("");
      void qc.invalidateQueries({ queryKey: backupKeys.all });
    } catch (e) {
      setError(errorMessage(e));
    }
    setBusy(false);
  }
  return (
    <Dialog title={fresh ? "Save the recovery kit now" : "Recovery kit"} width={520} onClose={onClose} onSubmit={() => !saved && password && void get()}>
      <div className="stack">
        <div className="bk-kit">
          <KeyIcon size={22} />
          <p>
            The backups at <strong>{target.name}</strong> are encrypted with a key HardyOS made. The recovery kit holds it, with the bucket's address and how to restore onto
            a new server. <strong>Without it, a lost server's backups can't be opened by anyone.</strong>
          </p>
        </div>
        <p className="small muted">Print it or keep it in a password manager, away from this server. Anyone with the kit and the bucket's keys can read the backups. Every download is recorded.</p>
        {saved ? (
          <Alert tone="good" title="Saved">
            Check your downloads folder, then put the file somewhere safe.
          </Alert>
        ) : (
          <Field label="Your password" hint="Enter it again to download the kit.">
            {(id) => <TextInput id={id} type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />}
          </Field>
        )}
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
      <footer className="dialog__foot">
        <Button onClick={onClose}>{saved ? "Done" : fresh ? "Later" : "Cancel"}</Button>
        {!saved && (
          <Button variant="primary" type="submit" busy={busy} disabled={!password}>
            Download kit
          </Button>
        )}
      </footer>
    </Dialog>
  );
}

function MaintenanceDialog({ target, onClose }: { target: BackupTarget; onClose: () => void }) {
  const qc = useQueryClient();
  const [m, setM] = useState<BackupMaintenance>(target.maintenance);
  const [error, setError] = useState<string | null>(null);
  async function save() {
    try {
      await setMaintenance(target.id, m);
      void qc.invalidateQueries({ queryKey: backupKeys.all });
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    }
  }
  return (
    <Dialog title={`Upkeep of ${target.name}`} width={460} onClose={onClose} onSubmit={save}>
      <div className="stack">
        <p className="small muted">Once a week the destination frees the space of versions no task keeps, then checks the repository and reads part of its data back to be sure it can be restored.</p>
        <div className="bk-row2">
          <Field label="Day">
            {(id) => (
              <Select id={id} value={m.weekday} onChange={(e) => setM({ ...m, weekday: Number(e.target.value) })}>
                {weekdays.map((d, i) => (
                  <option key={d} value={i}>
                    {d}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Time">{(id) => <TextInput id={id} type="time" className="input mono" value={m.time} onChange={(e) => setM({ ...m, time: e.target.value })} />}</Field>
        </div>
        <Field label="Read back (% of the data)" hint="More is slower and, with some providers, costs download fees.">
          {(id) => <TextInput id={id} type="number" min={0} max={100} className="input mono" value={m.checkPercent} onChange={(e) => setM({ ...m, checkPercent: Math.min(100, Math.max(0, Number(e.target.value) || 0)) })} />}
        </Field>
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
      <footer className="dialog__foot">
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="primary" type="submit">
          Save
        </Button>
      </footer>
    </Dialog>
  );
}
