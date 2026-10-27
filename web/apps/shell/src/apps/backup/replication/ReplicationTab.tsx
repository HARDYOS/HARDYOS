import type {
  ReplicationItem,
  ReplicationKind,
  ReplicationLocalItem,
  ReplicationRemoteItem,
  ReplicationTarget,
  ReplicationTask,
  ReplicationTaskRequest,
} from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../../api";
import { bytes, dateTime, relativeTime } from "../../../format";
import { EditIcon, FolderIcon, NetworkIcon, PlayIcon, PlusIcon, RefreshIcon, StopIcon, TrashIcon } from "../../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, Loading, Select, TextInput, Toggle } from "../../../ui";
import { ConfirmDialog, Dialog } from "../../../ui/Dialog";
import { toast } from "../../../ui/toasts";
import { JobProgress, JobStateBadge } from "../../shared";
import {
  KIND_LABEL,
  KIND_PLURAL,
  UNIT_MINUTES,
  intervalLabel,
  restoredID,
  snapshotTime,
  splitInterval,
  taskStatus,
  usePoolNames,
  useReplication,
  useReplicationItems,
} from "./replicationApi";
import "./replication.css";

/**
 * Replication to another HardyOS server: paired servers, scheduled tasks
 * (shared folders, apps and VMs), and restoring from what a server keeps.
 * Self-contained: the Backup app mounts it as a tab, the Control Panel's
 * Replication page hosts it meanwhile.
 */
export function ReplicationTab() {
  const ov = useReplication();
  const qc = useQueryClient();
  const refresh = () => void qc.invalidateQueries({ queryKey: ["replication"] });
  if (ov.isPending) return <Loading />;
  if (ov.isError) return <ErrorBox error={ov.error} onRetry={() => ov.refetch()} />;
  const { targets, tasks } = ov.data;
  return (
    <div className="repl stack">
      <ServersCard targets={targets} tasks={tasks} onChanged={refresh} />
      <TasksCard targets={targets} tasks={tasks} onChanged={refresh} />
      {targets.length > 0 && <RestoreCard targets={targets} />}
      <p className="small muted">
        This server's key: <span className="mono">{ov.data.pin.slice(0, 16)}…</span> — the other server shows the same when you pair.
      </p>
    </div>
  );
}

// ---- paired servers --------------------------------------------------------------

function ServersCard({ targets, tasks, onChanged }: { targets: ReplicationTarget[]; tasks: ReplicationTask[]; onChanged: () => void }) {
  const [pairing, setPairing] = useState(false);
  const [editing, setEditing] = useState<ReplicationTarget | null>(null);
  const [forgetting, setForgetting] = useState<ReplicationTarget | null>(null);
  const test = useMutation({
    mutationFn: (t: ReplicationTarget) => unwrap(api.POST("/replication/targets/{id}/test", { params: { path: { id: t.id } } })),
    onSuccess: (r) => toast("success", `${r.name} answered`),
    onError: (err) => toast("error", errorMessage(err)),
  });
  return (
    <Card
      title="Servers this one sends to"
      actions={
        <Button variant="primary" size="sm" onClick={() => setPairing(true)}>
          <PlusIcon size={14} /> Pair with a server…
        </Button>
      }
    >
      {targets.length === 0 ? (
        <EmptyState icon={<NetworkIcon size={28} />} title="No server paired yet">
          On the other HardyOS server, open Control Panel › Replication › Accept from another server and make a pairing code. Then pair with it here.
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Server</th>
                <th>Address</th>
                <th>Tasks</th>
                <th className="actions" aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {targets.map((t) => (
                <tr key={t.id}>
                  <td>
                    <strong>{t.name}</strong>
                    {!t.pin && (
                      <div>
                        <Badge tone="bad">pair again</Badge>
                      </div>
                    )}
                  </td>
                  <td className="mono small">{t.address}</td>
                  <td>{tasks.filter((x) => x.targetId === t.id).length}</td>
                  <td className="actions">
                    <Button size="sm" variant="ghost" busy={test.isPending && test.variables?.id === t.id} onClick={() => test.mutate(t)}>
                      Test
                    </Button>
                    <Button size="sm" variant="ghost" aria-label={`Change the address of ${t.name}`} onClick={() => setEditing(t)}>
                      <EditIcon size={14} />
                    </Button>
                    <Button size="sm" variant="ghost" aria-label={`Forget ${t.name}`} onClick={() => setForgetting(t)}>
                      <TrashIcon size={14} />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {pairing && <PairDialog onClose={() => setPairing(false)} onDone={onChanged} />}
      {editing && <AddressDialog target={editing} onClose={() => setEditing(null)} onDone={onChanged} />}
      {forgetting && (
        <ConfirmDialog
          title={`Forget ${forgetting.name}?`}
          confirmLabel="Forget"
          typeToConfirm={forgetting.name}
          onClose={() => setForgetting(null)}
          onConfirm={async () => {
            await unwrap(api.DELETE("/replication/targets/{id}", { params: { path: { id: forgetting.id } }, body: { confirm: forgetting.name } }));
            toast("info", `Forgetting ${forgetting.name}`);
            setTimeout(onChanged, 800);
          }}
        >
          This server stops sending to {forgetting.name}. Its tasks must be deleted first. The replicas it keeps stay there until its administrator deletes
          them.
        </ConfirmDialog>
      )}
    </Card>
  );
}

function PairDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [address, setAddress] = useState("");
  const [code, setCode] = useState("");
  const [job, setJob] = useState<string | null>(null);
  const pair = useMutation({
    mutationFn: () => unwrap(api.POST("/replication/targets", { body: { address: address.trim(), code: code.trim() } })),
    onSuccess: (r) => setJob((r.job as { id: string }).id),
  });
  return (
    <Dialog
      title="Pair with a server"
      description="Both servers prove they know the code, then each remembers the other's key. Nothing else is shared, and no password is stored."
      onClose={onClose}
      onSubmit={() => !job && pair.mutate()}
      footer={
        job ? (
          <Button variant="primary" onClick={onClose}>
            Close
          </Button>
        ) : (
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" busy={pair.isPending} disabled={!address.trim() || code.replace(/[\s-]/g, "").length < 26}>
              Pair
            </Button>
          </>
        )
      }
    >
      {job ? (
        <JobProgress
          id={job}
          onDone={(j) => {
            if (j.state === "succeeded") onDone();
          }}
        />
      ) : (
        <div className="stack">
          <Field label="The other server's address" hint="Its name or IP on your network or on NetBird, e.g. nas2.home.example or 100.64.0.7 (port 44400).">
            {(id) => <TextInput id={id} value={address} onChange={(e) => setAddress(e.target.value)} autoComplete="off" placeholder="nas2.home.example" />}
          </Field>
          <Field label="Pairing code" hint="Shown on the other server for 30 minutes.">
            {(id) => (
              <TextInput id={id} className="input mono" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="off" placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX" />
            )}
          </Field>
          {pair.isError && <Alert tone="bad">{errorMessage(pair.error)}</Alert>}
        </div>
      )}
    </Dialog>
  );
}

function AddressDialog({ target, onClose, onDone }: { target: ReplicationTarget; onClose: () => void; onDone: () => void }) {
  const [address, setAddress] = useState(target.address);
  const save = useMutation({
    mutationFn: () => unwrap(api.PATCH("/replication/targets/{id}", { params: { path: { id: target.id } }, body: { address: address.trim() } })),
    onSuccess: () => {
      toast("success", "Address changed");
      setTimeout(onDone, 500);
      onClose();
    },
  });
  return (
    <Dialog
      title={`Where to reach ${target.name}`}
      onClose={onClose}
      onSubmit={() => save.mutate()}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" busy={save.isPending} disabled={!address.trim()}>
            Save
          </Button>
        </>
      }
    >
      <Field label="Address" hint="The key stays pinned: a different server at this address is refused.">
        {(id) => <TextInput id={id} value={address} onChange={(e) => setAddress(e.target.value)} />}
      </Field>
      {save.isError && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
    </Dialog>
  );
}

// ---- tasks -------------------------------------------------------------------------

function TasksCard({ targets, tasks, onChanged }: { targets: ReplicationTarget[]; tasks: ReplicationTask[]; onChanged: () => void }) {
  const [editing, setEditing] = useState<ReplicationTask | "new" | null>(null);
  const [history, setHistory] = useState<ReplicationTask | null>(null);
  const [deleting, setDeleting] = useState<ReplicationTask | null>(null);
  const run = useMutation({
    mutationFn: (t: ReplicationTask) => unwrap(api.POST("/replication/tasks/{id}/run", { params: { path: { id: t.id } } })),
    onSuccess: () => {
      toast("info", "Replication started");
      onChanged();
    },
    onError: (err) => toast("error", errorMessage(err)),
  });
  const cancel = useMutation({
    mutationFn: (t: ReplicationTask) => unwrap(api.POST("/replication/tasks/{id}/cancel", { params: { path: { id: t.id } } })),
    onSuccess: () => {
      toast("info", "Stopping; the next run picks up where this one stopped");
      onChanged();
    },
    onError: (err) => toast("error", errorMessage(err)),
  });
  return (
    <Card
      title="Replication tasks"
      actions={
        <Button variant="primary" size="sm" disabled={targets.length === 0} onClick={() => setEditing("new")}>
          <PlusIcon size={14} /> New task…
        </Button>
      }
    >
      {tasks.length === 0 ? (
        <EmptyState icon={<RefreshIcon size={28} />} title="No replication tasks">
          A task copies chosen shared folders, apps and VMs to a paired server on a schedule. After the first full copy, only changes travel.
        </EmptyState>
      ) : (
        <div className="stack">
          {tasks.map((t) => {
            const st = taskStatus(t);
            return (
              <div key={t.id} className="repl-task">
                <div className="row row--between">
                  <div>
                    <strong>{t.name}</strong> <Badge tone={st.tone}>{st.text}</Badge>
                    <div className="small muted">
                      {t.items.length} {t.items.length === 1 ? "item" : "items"} to {t.targetName} · {intervalLabel(t.intervalMinutes)}
                      {t.bandwidthKBps > 0 && ` · at most ${bytes(t.bandwidthKBps * 1024)}/s`} · last success{" "}
                      {t.lastSuccessAt ? <span title={dateTime(t.lastSuccessAt)}>{relativeTime(t.lastSuccessAt)}</span> : "never"}
                      {t.lastSuccessAt && t.lastBytes > 0 && ` (${bytes(t.lastBytes)})`}
                    </div>
                  </div>
                  <div className="row">
                    {t.runningJob ? (
                      <Button size="sm" busy={cancel.isPending} onClick={() => cancel.mutate(t)}>
                        <StopIcon size={14} /> Cancel
                      </Button>
                    ) : (
                      <Button size="sm" busy={run.isPending && run.variables?.id === t.id} onClick={() => run.mutate(t)}>
                        <PlayIcon size={14} /> Run now
                      </Button>
                    )}
                    <Button size="sm" variant="ghost" onClick={() => setHistory(t)}>
                      History
                    </Button>
                    <Button size="sm" variant="ghost" aria-label={`Edit ${t.name}`} onClick={() => setEditing(t)}>
                      <EditIcon size={14} />
                    </Button>
                    <Button size="sm" variant="ghost" aria-label={`Delete ${t.name}`} disabled={!!t.runningJob} onClick={() => setDeleting(t)}>
                      <TrashIcon size={14} />
                    </Button>
                  </div>
                </div>
                {t.runningJob && <JobProgress id={t.runningJob} onDone={onChanged} />}
                {!t.runningJob && t.lastError && (
                  <Alert tone={t.stale ? "bad" : "warn"} title={t.stale ? "Behind schedule" : "The last run failed"}>
                    {t.lastError}
                  </Alert>
                )}
                {!t.runningJob && !t.lastError && t.stale && <Alert tone="bad" title="Behind schedule">No run has succeeded for a while.</Alert>}
              </div>
            );
          })}
        </div>
      )}
      {editing && <TaskDialog task={editing === "new" ? null : editing} targets={targets} onClose={() => setEditing(null)} onDone={onChanged} />}
      {history && <HistoryDialog task={history} onClose={() => setHistory(null)} />}
      {deleting && (
        <ConfirmDialog
          title={`Delete the task ${deleting.name}?`}
          confirmLabel="Delete task"
          typeToConfirm={deleting.name}
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await unwrap(api.DELETE("/replication/tasks/{id}", { params: { path: { id: deleting.id } }, body: { confirm: deleting.name } }));
            setTimeout(onChanged, 800);
          }}
        >
          Its replication snapshots on this server are deleted. The replicas on {deleting.targetName} stay until its administrator deletes them.
        </ConfirmDialog>
      )}
    </Card>
  );
}

type Draft = {
  name: string;
  targetId: string;
  items: ReplicationItem[];
  every: number;
  unit: keyof typeof UNIT_MINUTES;
  bandwidthKBps: number;
  keepLocal: number;
  keepRemote: number;
  enabled: boolean;
};

/** The request a draft makes. */
export function taskRequest(d: Draft): ReplicationTaskRequest {
  return {
    name: d.name.trim(),
    targetId: d.targetId,
    items: d.items,
    intervalMinutes: Math.round(d.every * UNIT_MINUTES[d.unit]),
    bandwidthKBps: Math.max(0, Math.round(d.bandwidthKBps)),
    keepLocal: d.keepLocal,
    keepRemote: d.keepRemote,
    enabled: d.enabled,
  };
}

function TaskDialog({ task, targets, onClose, onDone }: { task: ReplicationTask | null; targets: ReplicationTarget[]; onClose: () => void; onDone: () => void }) {
  const items = useReplicationItems();
  const iv = splitInterval(task?.intervalMinutes ?? 60);
  const [d, setD] = useState<Draft>({
    name: task?.name ?? "",
    targetId: task?.targetId ?? targets[0]?.id ?? "",
    items: task?.items ?? [],
    every: iv.value,
    unit: iv.unit,
    bandwidthKBps: task?.bandwidthKBps ?? 0,
    keepLocal: task?.keepLocal ?? 3,
    keepRemote: task?.keepRemote ?? 14,
    enabled: task?.enabled ?? true,
  });
  const set = (p: Partial<Draft>) => setD((x) => ({ ...x, ...p }));
  const req = taskRequest(d);
  const tooOften = req.intervalMinutes < 5;
  const save = useMutation({
    mutationFn: () =>
      task
        ? unwrap(api.PATCH("/replication/tasks/{id}", { params: { path: { id: task.id } }, body: req }))
        : unwrap(api.POST("/replication/tasks", { body: req })),
    onSuccess: () => {
      toast("success", task ? "Task saved" : "Task created");
      setTimeout(onDone, 500);
      onClose();
    },
  });
  const has = (it: ReplicationLocalItem) => d.items.some((x) => x.kind === it.kind && x.id === it.id);
  const toggle = (it: ReplicationLocalItem) =>
    set({ items: has(it) ? d.items.filter((x) => !(x.kind === it.kind && x.id === it.id)) : [...d.items, { kind: it.kind, id: it.id }] });
  const byKind = (k: ReplicationKind) => (items.data?.items ?? []).filter((i) => i.kind === k);
  return (
    <Dialog
      title={task ? `Edit ${task.name}` : "New replication task"}
      width={560}
      onClose={onClose}
      onSubmit={() => save.mutate()}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" type="submit" busy={save.isPending} disabled={!req.name || req.items.length === 0 || tooOften || !req.targetId}>
            {task ? "Save" : "Create"}
          </Button>
        </>
      }
    >
      <div className="stack">
        <div className="grid-2">
          <Field label="Name">{(id) => <TextInput id={id} value={d.name} maxLength={60} onChange={(e) => set({ name: e.target.value })} placeholder="Every hour to nas2" />}</Field>
          <Field label="To" hint={task ? "A task's server can't change." : undefined}>
            {(id) => (
              <Select id={id} value={d.targetId} disabled={!!task} onChange={(e) => set({ targetId: e.target.value })}>
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <fieldset className="repl-items">
          <legend className="field__label">What to replicate</legend>
          {items.isPending && <Loading />}
          {items.isError && <ErrorBox error={items.error} />}
          {(["share", "vm", "app"] as const).map((k) =>
            byKind(k).length === 0 ? null : (
              <div key={k} className="stack" style={{ gap: 4 }}>
                <span className="small muted">{KIND_PLURAL[k]}</span>
                {byKind(k).map((it) => (
                  <label key={it.kind + it.id} className="repl-check">
                    <input type="checkbox" checked={has(it)} onChange={() => toggle(it)} />
                    <span>{it.name}</span>
                    <span className="small muted mono">{bytes(it.usedBytes)}</span>
                  </label>
                ))}
              </div>
            ),
          )}
        </fieldset>
        <div className="grid-2">
          <Field label="Run every" error={tooOften ? "At least every 5 minutes" : null}>
            {(id) => (
              <div className="row">
                <TextInput id={id} type="number" min={1} value={d.every} onChange={(e) => set({ every: Number(e.target.value) })} style={{ width: 90 }} />
                <Select aria-label="Unit" value={d.unit} onChange={(e) => set({ unit: e.target.value as Draft["unit"] })}>
                  <option value="minutes">minutes</option>
                  <option value="hours">hours</option>
                  <option value="days">days</option>
                </Select>
              </div>
            )}
          </Field>
          <Field label="Bandwidth limit (KiB/s)" hint="0 for no limit">
            {(id) => <TextInput id={id} type="number" min={0} value={d.bandwidthKBps} onChange={(e) => set({ bandwidthKBps: Number(e.target.value) })} />}
          </Field>
          <Field label="Snapshots kept here" hint="The newest one both servers have always stays.">
            {(id) => <TextInput id={id} type="number" min={1} max={1000} value={d.keepLocal} onChange={(e) => set({ keepLocal: Number(e.target.value) })} />}
          </Field>
          <Field label="Snapshots kept there" hint="The other server may keep more (its own minimum).">
            {(id) => <TextInput id={id} type="number" min={1} max={1000} value={d.keepRemote} onChange={(e) => set({ keepRemote: Number(e.target.value) })} />}
          </Field>
        </div>
        <Toggle label="On schedule" description="Off: runs only when you press Run now." checked={d.enabled} onChange={(v) => set({ enabled: v })} />
        {d.items.some((i) => i.kind === "vm") && (
          <Alert tone="info">
            Running VMs are frozen by their guest agent for the moment the snapshot takes; without one, the copy is like pulling the plug, which journaling
            file systems recover from. Snapshots count against a VM's space limit, so keep few here.
          </Alert>
        )}
        {save.isError && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Dialog>
  );
}

function HistoryDialog({ task, onClose }: { task: ReplicationTask; onClose: () => void }) {
  const runs = useQuery({
    queryKey: ["replication-history", task.id],
    queryFn: () => unwrap(api.GET("/replication/tasks/{id}/history", { params: { path: { id: task.id } } })),
  });
  return (
    <Dialog title={`History of ${task.name}`} width={620} onClose={onClose}>
      {runs.isPending && <Loading />}
      {runs.isError && <ErrorBox error={runs.error} />}
      {runs.data && runs.data.runs.length === 0 && <p className="muted">No runs yet.</p>}
      {runs.data && runs.data.runs.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Started</th>
                <th>Result</th>
                <th className="num">Sent</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {runs.data.runs.map((r) => (
                <tr key={r.id}>
                  <td title={dateTime(r.startedAt)}>{relativeTime(r.startedAt)}</td>
                  <td>
                    <JobStateBadge state={r.state === "running" ? "running" : r.state} />
                  </td>
                  <td className="num mono">{bytes(r.bytes)}</td>
                  <td className="small">{r.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Dialog>
  );
}

// ---- restoring ---------------------------------------------------------------------

function RestoreCard({ targets }: { targets: ReplicationTarget[] }) {
  const [targetId, setTargetId] = useState(targets[0]!.id);
  const [restoring, setRestoring] = useState<ReplicationRemoteItem | null>(null);
  const target = targets.find((t) => t.id === targetId) ?? targets[0]!;
  const replicas = useQuery({
    queryKey: ["replication-replicas", target.id],
    queryFn: () => unwrap(api.GET("/replication/targets/{id}/replicas", { params: { path: { id: target.id } } })),
    retry: false,
  });
  return (
    <Card
      title="Restore from a replica"
      actions={
        targets.length > 1 ? (
          <Select aria-label="Server" value={target.id} onChange={(e) => setTargetId(e.target.value)}>
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
              </option>
            ))}
          </Select>
        ) : undefined
      }
    >
      {replicas.isPending && <Loading label={`Asking ${target.name}…`} />}
      {replicas.isError && <ErrorBox error={replicas.error} onRetry={() => replicas.refetch()} />}
      {replicas.data && replicas.data.items.length === 0 && <p className="muted">{target.name} doesn't keep anything from this server yet.</p>}
      {replicas.data && replicas.data.items.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Item</th>
                <th>Kind</th>
                <th className="num">Size there</th>
                <th>Newest copy</th>
                <th className="actions" aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {replicas.data.items.map((it) => (
                <tr key={it.kind + it.id}>
                  <td>
                    <strong>{it.name}</strong> {it.partial && <Badge tone="warn">transfer to finish</Badge>}
                  </td>
                  <td>{KIND_LABEL[it.kind]}</td>
                  <td className="num mono">{bytes(it.usedBytes)}</td>
                  <td>{it.lastSnapshot ? relativeTime(snapshotTime(it.lastSnapshot)) : "—"}</td>
                  <td className="actions">
                    <Button size="sm" disabled={it.snapshots === 0} onClick={() => setRestoring(it)}>
                      Browse & restore…
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {restoring && <RestoreDialog target={target} item={restoring} onClose={() => setRestoring(null)} />}
    </Card>
  );
}

function RestoreDialog({ target, item, onClose }: { target: ReplicationTarget; item: ReplicationRemoteItem; onClose: () => void }) {
  const qc = useQueryClient();
  const snaps = useQuery({
    queryKey: ["replication-snapshots", target.id, item.kind, item.id],
    queryFn: () =>
      unwrap(api.GET("/replication/targets/{id}/replicas/{kind}/{item}/snapshots", { params: { path: { id: target.id, kind: item.kind, item: item.id } } })),
  });
  const pools = usePoolNames();
  const shares = useQuery({ queryKey: ["shares"], queryFn: () => unwrap(api.GET("/shares")), enabled: item.kind === "share" });
  const [snapshot, setSnapshot] = useState("");
  const [path, setPath] = useState("");
  const [pool, setPool] = useState(item.pool);
  const [newId, setNewId] = useState("");
  const [name, setName] = useState(`${item.name} (restored)`);
  const [sure, setSure] = useState(false);
  const [job, setJob] = useState<string | null>(null);
  const list = snaps.data?.snapshots ?? [];
  const chosen = snapshot || list[list.length - 1]?.name || "";
  const takenIds = (shares.data?.shares ?? []).map((s) => s.id);
  const id = newId || restoredID(item.id, takenIds);
  const browse = useQuery({
    queryKey: ["replication-browse", target.id, item.kind, item.id, chosen, path],
    queryFn: () =>
      unwrap(
        api.GET("/replication/targets/{id}/replicas/{kind}/{item}/browse", {
          params: { path: { id: target.id, kind: item.kind, item: item.id }, query: { snapshot: chosen, path } },
        }),
      ),
    enabled: !!chosen,
    retry: false,
  });
  const restore = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/replication/targets/{id}/restore", {
          params: { path: { id: target.id } },
          body: {
            kind: item.kind,
            id: item.id,
            snapshot: chosen,
            pool: item.kind === "app" ? "" : pool || pools.data?.[0] || "",
            newId: item.kind === "share" ? id : "",
            name: item.kind === "share" ? name.trim() : "",
            confirm: true,
          },
        }),
      ),
    onSuccess: (r) => setJob((r.job as { id: string }).id),
  });
  const where =
    item.kind === "share"
      ? `a new shared folder "${name.trim()}" (only administrators can open it until you share it)`
      : item.kind === "vm"
        ? `the VM ${item.id}, off, on ${pool || "its pool"} — only if no VM called ${item.id} exists here`
        : `${item.name}'s data, kept until you reinstall the app from the App Store — only if it isn't installed here`;
  return (
    <Dialog
      title={`Restore ${item.name} from ${target.name}`}
      width={640}
      onClose={onClose}
      onSubmit={() => !job && restore.mutate()}
      footer={
        job ? (
          <Button variant="primary" onClick={onClose}>
            Close
          </Button>
        ) : (
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" busy={restore.isPending} disabled={!chosen || !sure || (item.kind === "share" && !name.trim())}>
              Restore
            </Button>
          </>
        )
      }
    >
      {job ? (
        <JobProgress
          id={job}
          onDone={() => {
            void qc.invalidateQueries({ queryKey: ["shares"] });
            void qc.invalidateQueries({ queryKey: ["vms"] });
          }}
        />
      ) : (
        <div className="stack">
          {snaps.isPending && <Loading />}
          {snaps.isError && <ErrorBox error={snaps.error} />}
          {list.length > 0 && (
            <Field label="Copy from">
              {(fid) => (
                <Select
                  id={fid}
                  value={chosen}
                  onChange={(e) => {
                    setSnapshot(e.target.value);
                    setPath("");
                  }}
                >
                  {[...list].reverse().map((s) => (
                    <option key={s.name} value={s.name}>
                      {dateTime(snapshotTime(s.name))}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          )}
          {chosen && (
            <div className="repl-browse" aria-label="Files in the copy">
              <div className="row small">
                <button type="button" className="link-button" onClick={() => setPath("")}>
                  {item.name}
                </button>
                {path
                  .split("/")
                  .filter(Boolean)
                  .map((p, i, all) => (
                    <span key={i}>
                      {" / "}
                      <button type="button" className="link-button" onClick={() => setPath(all.slice(0, i + 1).join("/"))}>
                        {p}
                      </button>
                    </span>
                  ))}
              </div>
              {browse.isPending && <Loading />}
              {browse.isError && <p className="small muted">{errorMessage(browse.error)}</p>}
              {browse.data && (
                <ul className="repl-files">
                  {browse.data.entries.length === 0 && <li className="muted small">Empty</li>}
                  {browse.data.entries.map((e) => (
                    <li key={e.name}>
                      {e.dir ? (
                        <button type="button" className="link-button" onClick={() => setPath(path ? `${path}/${e.name}` : e.name)}>
                          <FolderIcon size={14} /> {e.name}
                        </button>
                      ) : (
                        <span>{e.name}</span>
                      )}
                      {!e.dir && <span className="small muted mono">{bytes(e.size)}</span>}
                    </li>
                  ))}
                  {browse.data.truncated && <li className="small muted">… and more</li>}
                </ul>
              )}
            </div>
          )}
          {item.kind === "share" && (
            <div className="grid-2">
              <Field label="New folder's name">{(fid) => <TextInput id={fid} value={name} maxLength={40} onChange={(e) => setName(e.target.value)} />}</Field>
              <Field label="Id">{(fid) => <TextInput id={fid} className="input mono" value={id} onChange={(e) => setNewId(e.target.value.toLowerCase())} />}</Field>
            </div>
          )}
          {item.kind !== "app" && (
            <Field label="Pool" hint={item.kind === "vm" ? "A VM comes back to the pool its settings name." : undefined}>
              {(fid) => (
                <Select id={fid} value={pool || pools.data?.[0] || ""} onChange={(e) => setPool(e.target.value)}>
                  {(pools.data ?? []).map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          )}
          <label className="repl-check">
            <input type="checkbox" checked={sure} onChange={(e) => setSure(e.target.checked)} />
            <span>Copy it back as {where}. Nothing on this server is overwritten.</span>
          </label>
          {restore.isError && <Alert tone="bad">{errorMessage(restore.error)}</Alert>}
        </div>
      )}
    </Dialog>
  );
}
