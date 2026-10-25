import type { ScrubPolicy, SnapshotPolicy } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { relativeTime } from "../../format";
import { useDatasets, usePools } from "../../hooks/queries";
import { EditIcon, PlusIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, IconButton, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";

const FREQS = ["hourly", "daily", "weekly", "monthly"] as const;

export function Schedules() {
  const qc = useQueryClient();
  const snapPols = useQuery({ queryKey: ["snapshot-policies"], queryFn: () => unwrap(api.GET("/storage/snapshot-policies")) });
  const scrubPols = useQuery({ queryKey: ["scrub-policies"], queryFn: () => unwrap(api.GET("/storage/scrub-policies")) });
  const pools = usePools();
  const [editing, setEditing] = useState<SnapshotPolicy | "new" | null>(null);
  const [deleting, setDeleting] = useState<SnapshotPolicy | null>(null);
  const [editingScrub, setEditingScrub] = useState<ScrubPolicy | null>(null);

  return (
    <>
      <PageHeader title="Schedules" subtitle="Automatic snapshots protect against mistakes; regular scrubs catch disk problems early." />

      <Card
        title="Automatic snapshots"
        actions={
          <Button size="sm" onClick={() => setEditing("new")}>
            <PlusIcon size={14} /> Add schedule
          </Button>
        }
      >
        {snapPols.isPending ? (
          <Loading />
        ) : snapPols.isError ? (
          <ErrorBox error={snapPols.error} onRetry={() => snapPols.refetch()} />
        ) : snapPols.data.length === 0 ? (
          <EmptyState title="No snapshot schedules" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Dataset</th>
                  <th>How often</th>
                  <th className="num">Keep</th>
                  <th>Last run</th>
                  <th className="actions">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {snapPols.data.map((p) => (
                  <tr key={p.id}>
                    <td className="mono small">
                      {p.dataset}
                      {p.recursive && <span className="cell-sub">and datasets inside it</span>}
                    </td>
                    <td>
                      {p.frequency} {!p.enabled && <Badge tone="neutral">paused</Badge>}
                    </td>
                    <td className="num">{p.keep}</td>
                    <td>
                      {relativeTime(p.lastRunAt)}
                      {p.lastError && <span className="cell-sub" style={{ color: "var(--hos-bad-text)" }}>{p.lastError}</span>}
                    </td>
                    <td className="actions">
                      <IconButton label={`Edit ${p.dataset} ${p.frequency}`} onClick={() => setEditing(p)}>
                        <EditIcon size={16} />
                      </IconButton>
                      <IconButton label={`Remove ${p.dataset} ${p.frequency}`} onClick={() => setDeleting(p)}>
                        <TrashIcon size={16} />
                      </IconButton>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Scrubs">
        <p className="small muted" style={{ margin: 0 }}>
          A scrub reads every block and checks it against its checksum, repairing anything damaged from the redundant copies.
        </p>
        {scrubPols.isPending ? (
          <Loading />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Pool</th>
                  <th>Every</th>
                  <th>Last started</th>
                  <th className="actions">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {(pools.data ?? []).map((pool) => {
                  const p = scrubPols.data?.find((x) => x.pool === pool.name) ?? { pool: pool.name, intervalDays: 30, enabled: false, lastStartedAt: null, lastError: "" };
                  return (
                    <tr key={pool.name}>
                      <td>{pool.name}</td>
                      <td>{p.enabled ? `${p.intervalDays} days` : <Badge tone="neutral">off</Badge>}</td>
                      <td>{relativeTime(p.lastStartedAt)}</td>
                      <td className="actions">
                        <IconButton label={`Edit scrub schedule for ${pool.name}`} onClick={() => setEditingScrub(p as ScrubPolicy)}>
                          <EditIcon size={16} />
                        </IconButton>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {editing && <SnapshotPolicyDialog policy={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
      {editingScrub && <ScrubPolicyDialog policy={editingScrub} onClose={() => setEditingScrub(null)} />}
      {deleting && (
        <ConfirmDialog
          title="Remove this schedule?"
          confirmLabel="Remove"
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await unwrap(api.DELETE("/storage/snapshot-policies/{id}", { params: { path: { id: deleting.id! } } }));
            await qc.invalidateQueries({ queryKey: ["snapshot-policies"] });
          }}
        >
          <p>No more {deleting.frequency} snapshots of {deleting.dataset} will be taken. Existing snapshots stay until you delete them.</p>
        </ConfirmDialog>
      )}
    </>
  );
}

function SnapshotPolicyDialog({ policy, onClose }: { policy: SnapshotPolicy | null; onClose: () => void }) {
  const qc = useQueryClient();
  const datasets = useDatasets();
  const fs = (datasets.data ?? []).filter((d) => d.type === "filesystem" && !/^(rpool|bpool)(\/|$)/.test(d.name));
  const [dataset, setDataset] = useState(policy?.dataset ?? "");
  const [frequency, setFrequency] = useState<SnapshotPolicy["frequency"]>(policy?.frequency ?? "daily");
  const [keep, setKeep] = useState(String(policy?.keep ?? 14));
  const [recursive, setRecursive] = useState(policy?.recursive ?? true);
  const [enabled, setEnabled] = useState(policy?.enabled ?? true);
  const save = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/storage/snapshot-policies", {
          body: { id: policy?.id ?? 0, dataset: dataset || fs[0]?.name || "", frequency, keep: Number(keep), recursive, enabled },
        }),
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["snapshot-policies"] });
      toast("success", "Schedule saved");
      onClose();
    },
  });
  return (
    <Dialog
      title={policy ? "Edit snapshot schedule" : "New snapshot schedule"}
      onClose={onClose}
      onSubmit={() => save.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={save.isPending}>
            Save
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="Dataset">
          {(id) => (
            <Select id={id} value={dataset || fs[0]?.name || ""} onChange={(e) => setDataset(e.target.value)} disabled={!!policy}>
              {fs.map((d) => (
                <option key={d.name}>{d.name}</option>
              ))}
            </Select>
          )}
        </Field>
        <div className="grid-2">
          <Field label="How often">
            {(id) => (
              <Select id={id} value={frequency} onChange={(e) => setFrequency(e.target.value as SnapshotPolicy["frequency"])} disabled={!!policy}>
                {FREQS.map((f) => (
                  <option key={f}>{f}</option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="Keep the newest">
            {(id) => <TextInput id={id} type="number" min={1} max={1000} value={keep} onChange={(e) => setKeep(e.target.value)} />}
          </Field>
        </div>
        <Toggle label="Include datasets inside it" checked={recursive} onChange={setRecursive} />
        <Toggle label="Enabled" checked={enabled} onChange={setEnabled} />
        {save.error && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Dialog>
  );
}

function ScrubPolicyDialog({ policy, onClose }: { policy: ScrubPolicy; onClose: () => void }) {
  const qc = useQueryClient();
  const [days, setDays] = useState(String(policy.intervalDays || 30));
  const [enabled, setEnabled] = useState(policy.enabled ?? false);
  const save = useMutation({
    mutationFn: () => unwrap(api.POST("/storage/scrub-policies", { body: { pool: policy.pool, intervalDays: Number(days), enabled } })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["scrub-policies"] });
      toast("success", "Scrub schedule saved");
      onClose();
    },
  });
  return (
    <Dialog
      title={`Scrub schedule for ${policy.pool}`}
      onClose={onClose}
      onSubmit={() => save.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={save.isPending}>
            Save
          </Button>
        </>
      }
    >
      <div className="stack">
        <Toggle label="Scrub automatically" checked={enabled} onChange={setEnabled} />
        <Field label="Every (days)" hint="Monthly (30) is a good default for most disks">
          {(id) => <TextInput id={id} type="number" min={1} max={365} value={days} onChange={(e) => setDays(e.target.value)} disabled={!enabled} />}
        </Field>
        {save.error && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Dialog>
  );
}
