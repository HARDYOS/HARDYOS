import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../../api";
import { dateTime } from "../../../format";
import { Alert, Badge, Button, Card, Dot, EmptyState, ErrorBox, Field, Loading, PageHeader, Select, Stat, TextInput, Toggle } from "../../../ui";
import { Dialog } from "../../../ui/Dialog";
import { JobProgress } from "../../shared";
import {
  type ClusterStorageWorkload,
  storageKeys,
  useClusterStorage,
  useClusterStorageExports,
  useClusterStorageNodes,
} from "./api";
import { StorageNetworkStep } from "./StorageNetworkStep";

type Tab = "overview" | "servers" | "exports" | "network";
const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "servers", label: "Servers" },
  { id: "exports", label: "Targets & exports" },
  { id: "network", label: "Storage network" },
];

/** Cluster › Storage: the storage server, what each server has attached, the
 * iSCSI targets and NFS exports, snapshots and data modes of cluster
 * workloads, and the storage network. */
export function ClusterStorage() {
  const [tab, setTab] = useState<Tab>("overview");
  const ov = useClusterStorage();
  return (
    <div className="stack">
      <PageHeader
        title="Cluster storage"
        subtitle="VM disks over iSCSI and app data over NFS or block volumes, all kept on the storage server."
        badge={ov.data?.health ? <HealthBadge ok={!ov.data.health.problem && ov.data.health.reachable} /> : undefined}
      />
      <div className="row" role="tablist" aria-label="Cluster storage">
        {TABS.map((t) => (
          <Button key={t.id} role="tab" aria-selected={tab === t.id} variant={tab === t.id ? "primary" : "ghost"} size="sm" onClick={() => setTab(t.id)}>
            {t.label}
          </Button>
        ))}
      </div>
      {tab === "overview" && <Overview />}
      {tab === "servers" && <Servers />}
      {tab === "exports" && <Exports />}
      {tab === "network" && (
        <Card title="Storage network">
          <StorageNetworkStep />
        </Card>
      )}
    </div>
  );
}

function HealthBadge({ ok }: { ok: boolean }) {
  return <Badge tone={ok ? "good" : "bad"}>{ok ? "Healthy" : "Needs attention"}</Badge>;
}

function Overview() {
  const ov = useClusterStorage();
  const [snapFor, setSnapFor] = useState<ClusterStorageWorkload | null>(null);
  const [modeFor, setModeFor] = useState<ClusterStorageWorkload | null>(null);
  if (ov.isLoading) return <Loading />;
  if (ov.error) return <ErrorBox error={ov.error} onRetry={() => void ov.refetch()} />;
  const d = ov.data!;
  if (!d.member) {
    return (
      <EmptyState title="This server isn't in a cluster">
        Create or join a cluster first. You can already set up the storage network on the Storage network tab.
      </EmptyState>
    );
  }
  const h = d.health;
  const sessions = h?.sessions ? Object.values(h.sessions).reduce((a, b) => a + b, 0) : 0;
  return (
    <div className="stack">
      <div className="grid-4">
        <Stat label="Storage server" value={d.storageNode?.name ?? "none"} sub={d.storageNode?.addresses?.storage ?? ""} />
        <Stat label="iSCSI sessions" value={sessions} />
        <Stat label="Workloads" value={d.workloads.length} sub={`${d.workloads.filter((w) => !w.applied && w.nodes.length).length} waiting for the storage server`} />
        <Stat label="Fenced servers" value={d.fences.length} tone={d.fences.length ? "warn" : undefined} />
      </div>
      {h && !h.reachable && <Alert tone="bad" title="The storage server can't be reached">{h.problem}</Alert>}
      {h?.problem && h.reachable && <Alert tone="warn" title="The storage server reports a problem">{h.problem}</Alert>}
      {d.agent?.problem && <Alert tone="warn" title="Storage agent">{d.agent.problem}</Alert>}
      {d.fences.length > 0 && (
        <Card title="Fences">
          <ul className="stack">
            {d.fences.map((f) => (
              <li key={f.node} className="row row--between">
                <span>
                  <strong>{f.node}</strong> <span className="muted">({f.reason}, epoch {f.epoch})</span>
                </span>
                {f.confirmed ? (
                  <Badge tone="good">Cut off {f.confirmedAt ? dateTime(f.confirmedAt) : ""}</Badge>
                ) : (
                  <Badge tone="warn">Waiting for the storage server</Badge>
                )}
              </li>
            ))}
          </ul>
        </Card>
      )}
      <Card title="Workloads on cluster storage">
        {d.workloads.length === 0 ? (
          <p className="muted">No VMs or apps keep their data on the storage server yet.</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Kind</th>
                  <th>Data</th>
                  <th>Granted to</th>
                  <th>Generation</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {d.workloads.map((w) => (
                  <tr key={`${w.workload.kind}/${w.workload.id}`}>
                    <td>{w.name || w.workload.id}</td>
                    <td>{w.workload.kind === "vm" ? "VM" : "App"}</td>
                    <td>
                      {w.workload.kind === "vm"
                        ? `${w.storage.volumes?.length ?? 0} disk(s) over iSCSI`
                        : w.storage.mode === "block"
                          ? `Block volume (${w.storage.blockFS})`
                          : "NFS folder"}
                    </td>
                    <td>
                      {w.nodes.length ? w.nodes.join(" + ") : <span className="muted">nobody</span>}{" "}
                      {w.migration && <Badge tone="info">live migration</Badge>}{" "}
                      {w.nodes.length > 0 && !w.applied && <Badge tone="warn">pending</Badge>}
                    </td>
                    <td className="mono">{w.generation}</td>
                    <td className="row" style={{ justifyContent: "flex-end" }}>
                      <Button size="sm" variant="ghost" onClick={() => setSnapFor(w)}>
                        Snapshots
                      </Button>
                      {w.workload.kind === "app" && (
                        <Button size="sm" variant="ghost" onClick={() => setModeFor(w)}>
                          Data mode
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <ClusterShares shares={d.shares} />
      {snapFor && <SnapshotsDialog w={snapFor} onClose={() => setSnapFor(null)} />}
      {modeFor && <AppModeDialog w={modeFor} onClose={() => setModeFor(null)} />}
    </div>
  );
}

function ClusterShares({ shares }: { shares: { id: string; pool: string; mountPath: string }[] }) {
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string | null>(null);
  const [pool, setPool] = useState("");
  const [id, setId] = useState("");
  const set = useMutation({
    mutationFn: (v: { pool: string; id: string; inCluster: boolean }) =>
      unwrap(api.PUT("/cluster/storage/shares/{pool}/{id}", { params: { path: { pool: v.pool, id: v.id } }, body: { inCluster: v.inCluster } })),
    onSuccess: (r) => setJobId(r.job.id),
  });
  return (
    <Card title="Shared folders in the cluster">
      <p className="muted small">
        Exported to every compute server with root squashed, so apps on any server reach them as their own users. Computers on the LAN keep
        using SMB and NFS on the storage server as before.
      </p>
      <ul className="stack">
        {shares.map((s) => (
          <li key={s.id} className="row row--between">
            <span>
              <strong>{s.id}</strong> <span className="muted mono">{s.mountPath}</span>
            </span>
            <Button size="sm" variant="ghost" busy={set.isPending} onClick={() => set.mutate({ pool: s.pool, id: s.id, inCluster: false })}>
              Stop using in the cluster
            </Button>
          </li>
        ))}
      </ul>
      <div className="row" style={{ gap: 8, alignItems: "flex-end" }}>
        <Field label="Pool">{(fid) => <TextInput id={fid} value={pool} onChange={(e) => setPool(e.target.value)} placeholder="tank" />}</Field>
        <Field label="Shared folder">{(fid) => <TextInput id={fid} value={id} onChange={(e) => setId(e.target.value)} placeholder="media" />}</Field>
        <Button disabled={!pool || !id} busy={set.isPending} onClick={() => set.mutate({ pool, id, inCluster: true })}>
          Use in the cluster
        </Button>
      </div>
      {set.error && <Alert tone="bad">{errorMessage(set.error)}</Alert>}
      {jobId && <JobProgress id={jobId} onDone={() => void qc.invalidateQueries({ queryKey: storageKeys.overview })} />}
    </Card>
  );
}

function Servers() {
  const q = useClusterStorageNodes();
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => void q.refetch()} />;
  const nodes = q.data!.nodes;
  if (nodes.length === 0) return <EmptyState title="No servers">This server isn't in a cluster.</EmptyState>;
  return (
    <div className="stack">
      {nodes.map((n) => (
        <Card
          key={n.node}
          title={
            <span className="row" style={{ gap: 8 }}>
              <Dot tone={n.healthy ? "good" : n.problem ? "bad" : "neutral"} /> {n.node} <Badge>{n.role}</Badge>
            </span>
          }
          actions={<span className="small muted mono">{n.address ? `${n.address} on ${n.interface}` : "no storage address"}</span>}
        >
          {n.problem && <Alert tone="warn">{n.problem}</Alert>}
          <div className="grid-3">
            <Stat label="iSCSI sessions" value={n.sessions} />
            <Stat label="Attached workloads" value={n.attached?.length ?? 0} />
            <Stat label="Cluster shares mounted" value={Object.keys(n.shares).length} />
          </div>
          {(n.attached?.length ?? 0) > 0 && (
            <ul className="stack small">
              {n.attached!.map((a) => (
                <li key={`${a.workload.kind}/${a.workload.id}`} className="row row--between">
                  <span>
                    {a.workload.kind === "vm" ? "VM" : "App"} <strong>{a.workload.id}</strong>{" "}
                    <span className="muted">generation {a.generation}</span>
                  </span>
                  <span className="mono muted">{a.stateDir}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      ))}
    </div>
  );
}

function Exports() {
  const q = useClusterStorageExports();
  const qc = useQueryClient();
  const [rotate, setRotate] = useState<string | null>(null);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => void q.refetch()} />;
  const st = q.data!;
  const targets = st.desired?.targets ?? [];
  return (
    <div className="stack">
      {!st.loaded && <Alert tone="bad" title="The iSCSI target (LIO) isn't loaded on the storage server" />}
      {st.problem && <Alert tone="warn" title="Last change">{st.problem}</Alert>}
      <Card title="iSCSI targets (one per compute server)">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Server</th>
                <th>State</th>
                <th>Sessions</th>
                <th>Disks mapped</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {targets.map((t) => {
                const drift = st.drift?.[t.node];
                return (
                  <tr key={t.node}>
                    <td>{t.node}</td>
                    <td>{t.enabled ? <Badge tone="good">Enabled</Badge> : <Badge tone="bad">Fenced (epoch {t.fenceEpoch})</Badge>}</td>
                    <td className="mono">{st.sessions[t.node] ?? 0}</td>
                    <td>
                      <span className="mono small">{t.luns.join(", ") || "—"}</span>
                      {drift && <Badge tone="warn">differs from the cluster's state</Badge>}
                    </td>
                    <td>
                      <Button size="sm" variant="ghost" onClick={() => setRotate(t.node)}>
                        New CHAP secrets
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title="NFS exports on the storage network">
        <ul className="stack small">
          {Object.entries(st.exports ?? {}).map(([path, clients]) => (
            <li key={path} className="row row--between">
              <span className="mono">{path}</span>
              <span className="mono muted">{clients.join(", ")}</span>
            </li>
          ))}
          {Object.keys(st.exports ?? {}).length === 0 && <li className="muted">Nothing exported.</li>}
        </ul>
      </Card>
      {rotate && <RotateDialog node={rotate} onClose={() => (setRotate(null), void qc.invalidateQueries({ queryKey: storageKeys.exports }))} />}
    </div>
  );
}

function RotateDialog({ node, onClose }: { node: string; onClose: () => void }) {
  const [confirm, setConfirm] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);
  const m = useMutation({
    mutationFn: () => unwrap(api.POST("/cluster/storage/nodes/{node}/chap/rotate", { params: { path: { node } }, body: { confirm } })),
    onSuccess: (r) => setJobId(r.job.id),
  });
  return (
    <Dialog
      title={`New CHAP secrets for ${node}`}
      description="The server keeps its current sessions and uses the new secrets the next time it logs in."
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          {!jobId && (
            <Button variant="danger" disabled={confirm !== node} busy={m.isPending} onClick={() => m.mutate()}>
              Replace secrets
            </Button>
          )}
        </>
      }
    >
      <Field label={`Type ${node} to confirm`}>{(id) => <TextInput id={id} value={confirm} onChange={(e) => setConfirm(e.target.value)} />}</Field>
      {m.error && <Alert tone="bad">{errorMessage(m.error)}</Alert>}
      {jobId && <JobProgress id={jobId} />}
    </Dialog>
  );
}

function SnapshotsDialog({ w, onClose }: { w: ClusterStorageWorkload; onClose: () => void }) {
  const path = { kind: w.workload.kind, id: w.workload.id };
  const q = useQuery({
    queryKey: ["cluster", "storage", "snapshots", w.workload.kind, w.workload.id],
    queryFn: () => unwrap(api.GET("/cluster/storage/workloads/{kind}/{id}/snapshots", { params: { path } })),
  });
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string | null>(null);
  const [rollTo, setRollTo] = useState<string | null>(null);
  const [confirm, setConfirm] = useState("");
  const take = useMutation({
    mutationFn: () => unwrap(api.POST("/cluster/storage/workloads/{kind}/{id}/snapshots", { params: { path }, body: {} })),
    onSuccess: (r) => setJobId(r.job.id),
  });
  const roll = useMutation({
    mutationFn: (name: string) => unwrap(api.POST("/cluster/storage/workloads/{kind}/{id}/rollback", { params: { path }, body: { name, confirm } })),
    onSuccess: (r) => setJobId(r.job.id),
  });
  const stopped = w.state === "stopped";
  return (
    <Dialog title={`Snapshots of ${w.name || w.workload.id}`} onClose={onClose} width={560}>
      <p className="small muted">
        Snapshots are taken on the storage server. A running VM is frozen by its guest agent first; a running app's backup dump runs on
        its server first.
      </p>
      {q.isLoading ? (
        <Loading />
      ) : q.error ? (
        <ErrorBox error={q.error} />
      ) : (
        <ul className="stack small">
          {q.data!.snapshots.map((s) => (
            <li key={s.name} className="row row--between">
              <span>
                <span className="mono">{s.name}</span> <span className="muted">{dateTime(s.created)}</span>
              </span>
              <Button size="sm" variant="ghost" disabled={!stopped} title={stopped ? "" : "Stop it first"} onClick={() => setRollTo(s.name)}>
                Roll back
              </Button>
            </li>
          ))}
          {q.data!.snapshots.length === 0 && <li className="muted">No snapshots yet.</li>}
        </ul>
      )}
      {rollTo && (
        <div className="stack">
          <Alert tone="warn" title={`Roll back to ${rollTo}?`}>
            Everything written since is lost.
          </Alert>
          <Field label={`Type ${rollTo} to confirm`}>{(id) => <TextInput id={id} value={confirm} onChange={(e) => setConfirm(e.target.value)} />}</Field>
          <Button variant="danger" disabled={confirm !== rollTo} busy={roll.isPending} onClick={() => roll.mutate(rollTo)}>
            Roll back
          </Button>
        </div>
      )}
      {(take.error || roll.error) && <Alert tone="bad">{errorMessage(take.error ?? roll.error)}</Alert>}
      {jobId ? (
        <JobProgress id={jobId} onDone={() => void qc.invalidateQueries({ queryKey: ["cluster", "storage", "snapshots"] })} />
      ) : (
        <Button variant="primary" busy={take.isPending} onClick={() => take.mutate()}>
          Take a snapshot
        </Button>
      )}
    </Dialog>
  );
}

/** Switch a stopped app between an NFS folder and a block volume. */
export function AppModeDialog({ w, onClose }: { w: ClusterStorageWorkload; onClose: () => void }) {
  const cur = w.storage.mode ?? "nfs";
  const to = cur === "block" ? "nfs" : "block";
  const [fs, setFs] = useState<"ext4" | "xfs">("ext4");
  const [size, setSize] = useState("64");
  const [removeOld, setRemoveOld] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);
  const qc = useQueryClient();
  const id = w.workload.id;
  const m = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/cluster/storage/apps/{id}/mode", {
          params: { path: { id } },
          body: { to, fs: to === "block" ? fs : undefined, sizeGB: to === "block" ? Number(size) : undefined, removeOld, confirm },
        }),
      ),
    onSuccess: (r) => setJobId(r.job.id),
  });
  const stopped = w.state === "stopped";
  return (
    <Dialog
      title={`Data mode of ${w.name || id}`}
      description={
        to === "block"
          ? "A block volume is a disk only this app's server uses, like a VM's: the safest place for databases (SQLite, PostgreSQL, MySQL)."
          : "An NFS folder is a plain folder on the storage server: easiest for apps that keep ordinary files."
      }
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          {!jobId && (
            <Button variant="primary" disabled={!stopped || confirm !== id} busy={m.isPending} onClick={() => m.mutate()}>
              Move the data to {to === "block" ? "a block volume" : "an NFS folder"}
            </Button>
          )}
        </>
      }
    >
      <div className="stack">
        <p>
          Now: <strong>{cur === "block" ? `block volume (${w.storage.blockFS})` : "NFS folder"}</strong>
        </p>
        {!stopped && <Alert tone="warn" title="Stop the app first">Its data can only move while it's stopped everywhere.</Alert>}
        {to === "block" && (
          <div className="row" style={{ gap: 12 }}>
            <Field label="File system">
              {(fid) => (
                <Select id={fid} value={fs} onChange={(e) => setFs(e.target.value as "ext4" | "xfs")}>
                  <option value="ext4">ext4</option>
                  <option value="xfs">xfs</option>
                </Select>
              )}
            </Field>
            <Field label="Size (GB)" hint="Only what is written uses space.">
              {(fid) => <TextInput id={fid} inputMode="numeric" value={size} onChange={(e) => setSize(e.target.value)} />}
            </Field>
          </div>
        )}
        <Toggle
          label="Clear the old copy afterwards"
          description="A snapshot of it is kept on the storage server either way."
          checked={removeOld}
          onChange={setRemoveOld}
        />
        <Field label={`Type ${id} to confirm`}>{(fid) => <TextInput id={fid} value={confirm} onChange={(e) => setConfirm(e.target.value)} />}</Field>
        {m.error && <Alert tone="bad">{errorMessage(m.error)}</Alert>}
        {jobId && <JobProgress id={jobId} onDone={() => void qc.invalidateQueries({ queryKey: storageKeys.overview })} />}
      </div>
    </Dialog>
  );
}
