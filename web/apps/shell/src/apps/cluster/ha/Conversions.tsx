// Cluster › HA (Phase 10): conversions to cluster storage and back, the
// copies kept after them, the failover history, and "Make local again".
import type { Job } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { errorMessage, unwrap } from "../../../api";
import { nodeApi } from "../../../cluster/scope";
import { bytes, dateTime, relativeTime } from "../../../format";
import { Alert, Badge, Button, Card, Field, Loading, Select, TextInput } from "../../../ui";
import { Dialog } from "../../../ui/Dialog";
import { toast } from "../../../ui/toasts";
import {
  CONVERSION_PHASE,
  type Conversion,
  type KeptCopy,
  type NodeHA,
  type Placement,
  abandonConversion,
  canAbandon,
  canUndo,
  deleteKept,
  keptID,
  makeClusterTemplate,
  makeLocal,
  undoConversion,
  useConversions,
  useFailovers,
  useKept,
} from "./haApi";

/** A typed confirmation before an action that returns a job. */
function TypedConfirm({
  title,
  description,
  name,
  action,
  danger,
  onClose,
  run,
  onJob,
}: {
  title: string;
  description: string;
  name: string;
  action: string;
  danger?: boolean;
  onClose: () => void;
  run: (confirm: string) => Promise<Job>;
  onJob: (j: Job) => void;
}) {
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit() {
    if (confirm !== name) return;
    setBusy(true);
    setError(null);
    try {
      onJob(await run(confirm));
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }
  return (
    <Dialog
      title={title}
      onClose={onClose}
      onSubmit={submit}
      width={480}
      description={description}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant={danger ? "danger" : "primary"} type="submit" busy={busy} disabled={confirm !== name}>
            {action}
          </Button>
        </>
      }
    >
      <Field label={`Type ${name} to confirm`}>{(fid) => <TextInput id={fid} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />}</Field>
      {error && <Alert tone="bad">{error}</Alert>}
    </Dialog>
  );
}

export function ConversionsCard({ onJob }: { onJob: (j: Job) => void }) {
  const q = useConversions();
  const [undoing, setUndoing] = useState<Conversion | null>(null);
  const [abandoning, setAbandoning] = useState<Conversion | null>(null);
  const l = (q.data ?? []).filter((c) => c.state === "running" || c.state === "failed" || Date.now() - Date.parse(c.updated) < 7 * 86400_000);
  if (l.length === 0) return null;
  return (
    <Card title="Conversions run on this server">
      <table className="table">
        <thead>
          <tr>
            <th>Workload</th>
            <th>To</th>
            <th>Where it is</th>
            <th>Copied</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {l.map((c) => (
            <tr key={c.id}>
              <td>
                {c.name || c.workload} <span className="muted">{c.kind === "vm" ? "VM" : "app"}</span>
              </td>
              <td>{c.direction === "ha" ? "Cluster storage" : "This server"}</td>
              <td>
                <Badge tone={c.state === "done" ? "good" : c.state === "failed" ? "bad" : c.state === "running" ? "info" : "neutral"}>
                  {c.state === "running" ? (CONVERSION_PHASE[c.phase] ?? c.phase) : c.state}
                </Badge>
                {c.state === "failed" && <div className="muted">At “{CONVERSION_PHASE[c.phase] ?? c.phase}”: {c.problem}</div>}
                <div className="muted small">{relativeTime(c.updated)}</div>
              </td>
              <td className="mono">{c.bytesTotal > 0 ? `${bytes(c.bytesDone)} / ${bytes(c.bytesTotal)}` : "—"}</td>
              <td className="table__actions">
                {canUndo(c) && (
                  <Button size="sm" variant="ghost" onClick={() => setUndoing(c)}>
                    Undo…
                  </Button>
                )}
                {canAbandon(c) && (
                  <Button size="sm" variant="ghost" onClick={() => setAbandoning(c)}>
                    Abandon…
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted small">A failed conversion resumes from where it stopped: use Make highly available (or Make local again) on it again.</p>
      {undoing && (
        <TypedConfirm
          title={`Undo making ${undoing.name} highly available`}
          description="It is removed from the cluster (its cluster copy is kept aside for 24 hours) and this server's own copy comes back as it was."
          name={undoing.name || undoing.workload}
          action="Undo"
          danger
          onClose={() => setUndoing(null)}
          run={(confirm) => undoConversion(undoing.id, confirm)}
          onJob={onJob}
        />
      )}
      {abandoning && (
        <TypedConfirm
          title={`Abandon converting ${abandoning.name}`}
          description="What was copied so far is deleted. The workload itself stays as it is."
          name={abandoning.name || abandoning.workload}
          action="Abandon"
          danger
          onClose={() => setAbandoning(null)}
          run={(confirm) => abandonConversion(abandoning.id, confirm)}
          onJob={onJob}
        />
      )}
    </Card>
  );
}

export function KeptCard({ onJob }: { onJob: (j: Job) => void }) {
  const q = useKept();
  const [deleting, setDeleting] = useState<KeptCopy | null>(null);
  const l = q.data ?? [];
  if (l.length === 0) return null;
  return (
    <Card title="Kept copies">
      <p className="muted small">What a workload was moved away from is kept, unused, until it has run from its new storage and then for 24 hours.</p>
      <table className="table">
        <thead>
          <tr>
            <th>Workload</th>
            <th>Where</th>
            <th>Size</th>
            <th>Deleted</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {l.map((k) => (
            <tr key={`${k.node}/${k.pool}/${k.name}`}>
              <td>
                {k.id} <span className="muted">{k.kind === "vm" ? "VM" : "app"}</span>
              </td>
              <td>
                {k.node} <span className="mono muted">{k.pool}</span>
              </td>
              <td className="mono">{bytes(k.used)}</td>
              <td>{k.keepUntil ? dateTime(k.keepUntil) : <Badge tone="warn">Kept until you delete it</Badge>}</td>
              <td className="table__actions">
                <Button size="sm" variant="ghost" onClick={() => setDeleting(k)}>
                  Delete now…
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {deleting && (
        <TypedConfirm
          title={`Delete the kept copy of ${keptID(deleting.name)}`}
          description={`The copy on ${deleting.node} (${bytes(deleting.used)}, with its snapshots) is deleted for good.`}
          name={keptID(deleting.name)}
          action="Delete"
          danger
          onClose={() => setDeleting(null)}
          run={(confirm) => deleteKept(deleting, confirm)}
          onJob={onJob}
        />
      )}
    </Card>
  );
}

export function FailoversCard() {
  const q = useFailovers();
  const l = q.data ?? [];
  return (
    <Card title="Failover history">
      {l.length === 0 ? (
        <p className="muted">No workload had to restart elsewhere yet.</p>
      ) : (
        <ul className="list">
          {l.slice(0, 30).map((f, i) => (
            <li key={`${f.at}-${i}`}>
              <span className="muted">{relativeTime(f.at)}</span> <strong>{f.name}</strong>{" "}
              {f.outcome === "restarted" ? (
                <>
                  {f.from ? `${f.from} → ` : ""}
                  {f.to} <Badge tone="warn">Restarted</Badge>
                </>
              ) : f.outcome === "pending" ? (
                <Badge tone="bad">Nowhere to run</Badge>
              ) : (
                <Badge tone="bad">Failed</Badge>
              )}{" "}
              <span className="muted small">priority {f.priority}</span>
              {f.problem && <div className="muted small">{f.problem}</div>}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** "Make local again…" onto a compute server the person chooses. */
export function MakeLocalDialog({ p, nodes, onClose, onJob }: { p: Placement; nodes: NodeHA[]; onClose: () => void; onJob: (j: Job) => void }) {
  const computes = nodes.filter((n) => n.state === "active");
  const [node, setNode] = useState(p.owner && computes.some((n) => n.id === p.owner) ? p.owner : (computes[0]?.id ?? ""));
  const [pool, setPool] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isVM = p.workload.kind === "vm";
  const pools = useQuery({
    queryKey: ["cluster", "pools", node],
    queryFn: () => unwrap(nodeApi(node).GET("/storage/pools")),
    enabled: isVM && node !== "",
  });
  const choices = (pools.data ?? []).filter((x) => !["rpool", "bpool", "boot-pool", "hardyos-boot"].includes(x.name));
  const poolChoice = pool || choices[0]?.name || "";
  const ready = node !== "" && (!isVM || poolChoice !== "") && confirm === p.name;
  async function submit() {
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      onJob(await makeLocal(node, p.workload.kind, p.workload.id, { pool: isVM ? poolChoice : undefined, confirm }));
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }
  return (
    <Dialog
      title={`Make ${p.name} local again`}
      onClose={onClose}
      onSubmit={submit}
      width={520}
      description="It stops, its storage and snapshots are copied to that server's own pool, it leaves the cluster (no more failover) and runs there. The cluster copy is kept for 24 hours."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" busy={busy} disabled={!ready}>
            Make local again
          </Button>
        </>
      }
    >
      <Field label="Server">
        {(fid) => (
          <Select id={fid} value={node} onChange={(e) => setNode(e.target.value)}>
            {computes.map((n) => (
              <option key={n.id} value={n.id}>
                {n.name}
                {n.id === p.owner ? " (runs it now)" : ""}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {isVM && (
        <Field label="Its pool">
          {(fid) =>
            pools.isLoading ? (
              <Loading />
            ) : (
              <Select id={fid} value={poolChoice} onChange={(e) => setPool(e.target.value)}>
                {choices.map((x) => (
                  <option key={x.name} value={x.name}>
                    {x.name} ({bytes(x.freeBytes)} free)
                  </option>
                ))}
              </Select>
            )
          }
        </Field>
      )}
      {!isVM && <p className="muted">Apps go to that server's apps pool.</p>}
      <Field label={`Type ${p.name} to confirm`}>{(fid) => <TextInput id={fid} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />}</Field>
      {error && <Alert tone="bad">{error}</Alert>}
    </Dialog>
  );
}

/** "Save as template…" for a stopped HA VM: made on the storage server. */
export function ClusterTemplateDialog({ p, storageNode, onClose, onJob }: { p: Placement; storageNode: string; onClose: () => void; onJob: (j: Job) => void }) {
  const [tid, setTid] = useState(`${p.workload.id}-tpl`);
  const [name, setName] = useState(p.name);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function submit() {
    setBusy(true);
    setError(null);
    try {
      onJob(await makeClusterTemplate(storageNode, p.workload.id, { templateId: tid, name }));
      toast("success", "The template is made on the storage server");
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }
  return (
    <Dialog
      title={`Save ${p.name} as a template`}
      onClose={onClose}
      onSubmit={submit}
      width={460}
      description="Its disks are copied into a template on the storage server, which holds them."
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" busy={busy} disabled={!tid || !name}>
            Save as template
          </Button>
        </>
      }
    >
      <Field label="Template name" hint="2-32 lowercase letters, digits and dashes">
        {(fid) => <TextInput id={fid} value={tid} onChange={(e) => setTid(e.target.value)} autoComplete="off" />}
      </Field>
      <Field label="Display name">{(fid) => <TextInput id={fid} value={name} onChange={(e) => setName(e.target.value)} />}</Field>
      {error && <Alert tone="bad">{error}</Alert>}
    </Dialog>
  );
}
