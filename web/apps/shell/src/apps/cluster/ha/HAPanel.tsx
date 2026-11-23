// Cluster › HA (Phase 8 part C): which servers can run HA workloads, each
// workload's placement and HA policy, what the coordinator did, this
// server's fence agent, pre-pulled images and the failover timings.
import type { Job } from "@hardy/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { errorMessage } from "../../../api";
import { relativeTime } from "../../../format";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, Loading, PageHeader, Stat, TextInput, Toggle } from "../../../ui";
import { ConfirmDialog, Dialog } from "../../../ui/Dialog";
import { toast } from "../../../ui/toasts";
import { JobProgress } from "../../shared";
import { MoveDialog } from "./MoveDialog";
import {
  type HAPolicy,
  type NodeHA,
  PLACEMENT_STATE,
  type Placement,
  type Timings,
  drainNode,
  haKeys,
  requestWorkload,
  setPolicy,
  setTimings,
  setWatchdogOverride,
  timingProblems,
  timingsFromStatus,
  useHAStatus,
  useMoves,
} from "./haApi";

export function HAPanel() {
  const q = useHAStatus();
  const qc = useQueryClient();
  const [job, setJob] = useState<Job | null>(null);
  const onJob = (j: Job) => setJob(j);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => void q.refetch()} />;
  const s = q.data!;
  if (!s.member) {
    return (
      <EmptyState title="Not in a cluster">High availability needs this server to be in a cluster with a storage server and other compute servers.</EmptyState>
    );
  }
  return (
    <div className="stack">
      <PageHeader
        title="High availability"
        subtitle="HA workloads restart on another server when theirs fails, after the storage server has cut it off."
        badge={s.quorate ? <Badge tone="good">Quorum</Badge> : <Badge tone="bad">No quorum: changes wait</Badge>}
      />
      {job && (
        <JobProgress
          id={job.id}
          onDone={(j) => {
            void qc.invalidateQueries({ queryKey: haKeys.status });
            if (j.state === "succeeded") toast("success", j.title);
            setJob(null);
          }}
        />
      )}
      {s.coordinator?.storageLost && (
        <Alert tone="bad" title="Cluster storage is unreachable">
          No compute server can reach the storage server. Nothing fails over (there is nowhere to fail to); VMs pause and apps wait until it's back.
        </Alert>
      )}
      <div className="stat-row">
        <Stat label="Coordinator" value={s.leader ?? "—"} sub={s.coordinator?.active ? "this server" : undefined} />
        <Stat label="This server's watchdog" value={fenceLabel(s)} tone={s.fence?.state === "selffencing" ? "bad" : s.fence?.state === "armed" ? "good" : undefined} />
        <Stat label="CPU baseline" value={s.cpuBaseline || "host CPU"} sub="for live migration" />
      </div>
      <Nodes nodes={s.nodes} self={s.self} onJob={onJob} />
      <Workloads placements={s.placements} grants={s.grants} onJob={onJob} />
      {s.prepull.length > 0 && (
        <Card title="Images kept for failover on this server">
          <ul className="list">
            {s.prepull.map((p) => (
              <li key={p.app}>
                <strong>{p.app}</strong>{" "}
                {p.missing.length === 0 ? <Badge tone="good">Ready</Badge> : <Badge tone="warn">{p.missing.length} missing</Badge>}{" "}
                <span className="muted">{p.images.join(", ")}</span>
                {p.failed && Object.values(p.failed).length > 0 && <div className="muted">{Object.values(p.failed).join("; ")}</div>}
              </li>
            ))}
          </ul>
        </Card>
      )}
      <Recent events={s.coordinator?.recent ?? []} />
      <MovesHistory />
      <TimingsCard timings={timingsFromStatus(s.timings as Record<string, number>)} onJob={onJob} />
    </div>
  );
}

function fenceLabel(s: { fence?: { state: string; kind: string }; watchdog?: { kind: string } }) {
  const kind = s.watchdog?.kind || s.fence?.kind || "none";
  switch (s.fence?.state) {
    case "armed":
      return `Armed (${kind})`;
    case "selffencing":
      return "Self-fencing";
    default:
      return `Not armed (${kind})`;
  }
}

function Nodes({ nodes, self, onJob }: { nodes: NodeHA[]; self?: string; onJob: (j: Job) => void }) {
  const [override, setOverride] = useState<NodeHA | null>(null);
  const [drain, setDrain] = useState<NodeHA | null>(null);
  return (
    <Card title="Compute servers">
      <table className="table">
        <thead>
          <tr>
            <th>Server</th>
            <th>State</th>
            <th>Watchdog</th>
            <th>HA</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {nodes.map((n) => (
            <tr key={n.id}>
              <td>
                {n.name}
                {n.id === self && <span className="muted"> (this server)</span>}
              </td>
              <td>{n.state}</td>
              <td>{n.watchdog || "none"}</td>
              <td>
                {n.eligible ? (
                  <Badge tone={n.override ? "warn" : "good"}>{n.override ? "Allowed without a hardware watchdog" : "Yes"}</Badge>
                ) : (
                  <span title={n.reason}>
                    <Badge tone="neutral">No</Badge>
                  </span>
                )}
              </td>
              <td className="table__actions">
                {(n.watchdog !== "hardware" || n.override) && (
                  <Button size="sm" variant={n.override ? "ghost" : "danger"} onClick={() => setOverride(n)}>
                    {n.override ? "Require a hardware watchdog" : "Allow HA anyway…"}
                  </Button>
                )}
                <Button size="sm" onClick={() => setDrain(n)}>
                  Move everything off…
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {override && (
        <ConfirmDialog
          title={override.override ? `Require a hardware watchdog on ${override.name}` : `Allow HA on ${override.name} without a hardware watchdog`}
          confirmLabel={override.override ? "Require it" : "Allow HA"}
          typeToConfirm={override.id}
          danger={!override.override}
          onClose={() => setOverride(null)}
          onConfirm={async () => onJob(await setWatchdogOverride(override.id, !override.override, override.id))}
        >
          {override.override ? (
            <p>HA workloads won't be placed on {override.name} any more (move the ones there first).</p>
          ) : (
            <Alert tone="bad" title="Not safe against every failure">
              {override.watchdog === "softdog"
                ? "This server only has the software watchdog (softdog). If its kernel hangs, softdog hangs with it and can't reset the server, so an HA VM or app could keep writing to its disk after the cluster has started it elsewhere — unless the storage server has already cut this server off. "
                : "This server has no watchdog at all. If it hangs while holding an HA workload, nothing resets it. "}
              The storage server's fence still applies. Type the server's name to accept the risk.
            </Alert>
          )}
        </ConfirmDialog>
      )}
      {drain && <DrainDialog node={drain} onClose={() => setDrain(null)} onJob={onJob} />}
    </Card>
  );
}

function DrainDialog({ node, onClose, onJob }: { node: NodeHA; onClose: () => void; onJob: (j: Job) => void }) {
  const [stopOthers, setStopOthers] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = !stopOthers || confirm === node.id;
  async function run() {
    if (!ready) return;
    setBusy(true);
    try {
      onJob(await drainNode(node.id, stopOthers, stopOthers ? confirm : undefined));
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }
  return (
    <Dialog
      title={`Move everything off ${node.name}`}
      description="VMs move live where they can, everything else offline; HA workloads first."
      onClose={onClose}
      onSubmit={run}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" busy={busy} disabled={!ready}>
            Move everything
          </Button>
        </>
      }
    >
      <Toggle checked={stopOthers} onChange={setStopOthers} label="Also stop what can't move (VMs with passthrough devices)" />
      {stopOthers && (
        <Field label={`Type ${node.id} to confirm`}>{(id) => <TextInput id={id} value={confirm} onChange={(e) => setConfirm(e.target.value)} />}</Field>
      )}
      {error && <Alert tone="bad">{error}</Alert>}
    </Dialog>
  );
}

function Workloads({ placements, grants, onJob }: { placements: Placement[]; grants: Record<string, { applied: boolean; nodes: string[] }>; onJob: (j: Job) => void }) {
  const [editing, setEditing] = useState<Placement | null>(null);
  const [moving, setMoving] = useState<Placement | null>(null);
  if (placements.length === 0) {
    return (
      <Card title="Workloads">
        <p className="muted">No VMs or apps are on cluster storage yet.</p>
      </Card>
    );
  }
  return (
    <Card title="Workloads">
      <table className="table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Server</th>
            <th>State</th>
            <th>HA</th>
            <th>Generation</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {placements.map((p) => {
            const st = PLACEMENT_STATE[p.state];
            const key = `${p.workload.kind}:${p.workload.id}`;
            const g = grants[key];
            return (
              <tr key={key}>
                <td>
                  {p.name} <span className="muted">{p.workload.kind === "vm" ? "VM" : "app"}</span>
                  {p.pinned && <Badge tone="neutral">Pinned</Badge>}
                </td>
                <td>
                  {p.owner || "—"}
                  {p.target && <span className="muted"> → {p.target}</span>}
                </td>
                <td>
                  <Badge tone={st.tone}>{st.label}</Badge>
                  {p.problem && <div className="muted">{p.problem}</div>}
                </td>
                <td>{p.ha.enabled ? <Badge tone="accent">Priority {p.ha.priority}</Badge> : <span className="muted">Off</span>}</td>
                <td className="mono" title={g ? `granted to ${g.nodes.join(", ")}${g.applied ? "" : " (not applied yet)"}` : undefined}>
                  {p.generation}
                  {g && !g.applied && " …"}
                </td>
                <td className="table__actions">
                  <Button size="sm" onClick={() => setEditing(p)} disabled={p.pinned && !p.ha.enabled}>
                    HA…
                  </Button>
                  <Button size="sm" onClick={() => setMoving(p)} disabled={!!p.target}>
                    Move…
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={async () => {
                      try {
                        onJob(await requestWorkload(p.workload.kind, p.workload.id, p.requested === "running" ? "stopped" : "running", p.generation));
                      } catch (err) {
                        toast("error", "Couldn't change it", errorMessage(err));
                      }
                    }}
                  >
                    {p.requested === "running" ? "Stop" : "Start"}
                  </Button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      {editing && <PolicyDialog p={editing} onClose={() => setEditing(null)} onJob={onJob} />}
      {moving && <MoveDialog kind={moving.workload.kind} id={moving.workload.id} name={moving.name} onClose={() => setMoving(null)} onJob={onJob} />}
    </Card>
  );
}

function PolicyDialog({ p, onClose, onJob }: { p: Placement; onClose: () => void; onJob: (j: Job) => void }) {
  const [pol, setPol] = useState<HAPolicy>({ ...p.ha, priority: p.ha.priority || 50 });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const set = (x: Partial<HAPolicy>) => setPol({ ...pol, ...x });
  async function save() {
    setBusy(true);
    setError(null);
    try {
      onJob(await setPolicy(p.workload.kind, p.workload.id, pol));
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }
  return (
    <Dialog
      title={`High availability for ${p.name}`}
      onClose={onClose}
      onSubmit={save}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" type="submit" busy={busy}>
            Save
          </Button>
        </>
      }
    >
      {p.pinned && <Alert tone="warn">It has passthrough devices, so it can't fail over to another server.</Alert>}
      <Toggle checked={!!pol.enabled} onChange={(v) => set({ enabled: v })} label="Restart it on another server when its server fails" disabled={p.pinned} />
      <Field label="Priority (1-100, higher recovers first)">
        {(id) => <TextInput id={id} type="number" min={1} max={100} value={pol.priority ?? 50} onChange={(e) => set({ priority: Number(e.target.value) })} />}
      </Field>
      <Field label="Restarts in place per hour before moving it">
        {(id) => <TextInput id={id} type="number" min={0} max={20} value={pol.maxRestarts ?? 3} onChange={(e) => set({ maxRestarts: Number(e.target.value) })} />}
      </Field>
      <Field label="Preferred servers (comma separated, first is home)">
        {(id) => (
          <TextInput
            id={id}
            value={(pol.preferred ?? []).join(", ")}
            onChange={(e) => set({ preferred: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) })}
          />
        )}
      </Field>
      <Toggle checked={!!pol.restricted} onChange={(v) => set({ restricted: v })} label="Only on the preferred servers" />
      <Toggle checked={!!pol.failBack} onChange={(v) => set({ failBack: v })} label="Move back home (live) when its first preferred server is back" />
      <Field label="Keep apart from (anti-affinity group)">
        {(id) => <TextInput id={id} value={pol.antiAffinity ?? ""} onChange={(e) => set({ antiAffinity: e.target.value })} />}
      </Field>
      {error && <Alert tone="bad">{error}</Alert>}
    </Dialog>
  );
}

function Recent({ events }: { events: { at: string; kind: string; target: string; message: string; problem?: string }[] }) {
  if (events.length === 0) return null;
  return (
    <Card title="What the coordinator did">
      <ul className="list">
        {[...events].reverse().slice(0, 20).map((e, i) => (
          <li key={i}>
            <span className="muted">{relativeTime(e.at)}</span> {e.message}
            {e.problem && <Badge tone="bad">{e.problem}</Badge>}
          </li>
        ))}
      </ul>
    </Card>
  );
}

function MovesHistory() {
  const q = useMoves();
  const l = q.data ?? [];
  if (l.length === 0) return null;
  return (
    <Card title="Moves started here">
      <ul className="list">
        {l.slice(0, 20).map((m) => (
          <li key={m.jobId}>
            <span className="muted">{relativeTime(m.started)}</span> {m.workload} {m.from && `${m.from} → `}
            {m.to} <Badge tone={m.ok ? "good" : "bad"}>{m.ok ? `${m.mode}, ${(m.downtimeMs / 1000).toFixed(1)} s` : "failed"}</Badge>
            {m.problem && <div className="muted">{m.problem}</div>}
          </li>
        ))}
      </ul>
    </Card>
  );
}

const TIMING_FIELDS: [keyof Timings, string][] = [
  ["heartbeatMs", "Heartbeat"],
  ["suspectMs", "Suspect after"],
  ["quorumLeaseMs", "Quorum lease (Q)"],
  ["selfStopMs", "Self-stop (S)"],
  ["watchdogMs", "Watchdog (W)"],
  ["deadMs", "Dead after (F)"],
  ["storageIsolatedMs", "Storage isolated after"],
  ["lanIsolatedMs", "LAN isolated after"],
  ["fenceAckMs", "Fence acknowledgement wait"],
];

function TimingsCard({ timings, onJob }: { timings: Timings; onJob: (j: Job) => void }) {
  const [edit, setEdit] = useState<Timings | null>(null);
  const t = edit ?? timings;
  const problems = edit ? timingProblems(edit) : [];
  return (
    <Card
      title="Failover timings"
      actions={
        !edit && (
          <Button size="sm" onClick={() => setEdit(timings)}>
            Change…
          </Button>
        )
      }
    >
      <p className="muted">
        A server is declared dead after F; by then it has either heard the cluster, stopped its HA workloads (Q + S) or been reset by its watchdog (Q + W).
        HardyOS refuses timings that break F ≥ Q + W + 10 s or S &lt; W.
      </p>
      <div className="form-grid">
        {TIMING_FIELDS.map(([k, label]) => (
          <Field key={k} label={`${label} (s)`}>
            {(id) => (
              <TextInput
                id={id}
                type="number"
                step="0.5"
                disabled={!edit}
                value={t[k] / 1000}
                onChange={(e) => edit && setEdit({ ...edit, [k]: Math.round(Number(e.target.value) * 1000) })}
              />
            )}
          </Field>
        ))}
      </div>
      {problems.length > 0 && (
        <Alert tone="bad" title="Not safe">
          {problems.join(" ")}
        </Alert>
      )}
      {edit && (
        <div className="row">
          <Button onClick={() => setEdit(null)}>Cancel</Button>
          <Button
            variant="primary"
            disabled={problems.length > 0}
            onClick={async () => {
              try {
                onJob(await setTimings(edit));
                setEdit(null);
              } catch (err) {
                toast("error", "Couldn't change the timings", errorMessage(err));
              }
            }}
          >
            Save timings
          </Button>
        </div>
      )}
    </Card>
  );
}
