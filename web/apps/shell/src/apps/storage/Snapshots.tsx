import type { Snapshot } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes, dateTime, relativeTime } from "../../format";
import { useDatasets, useSnapshots } from "../../hooks/queries";
import { CameraIcon, RestartIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, EmptyState, ErrorBox, Field, IconButton, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";

export function Snapshots() {
  const datasets = useDatasets();
  const [root, setRoot] = useState("");
  const snaps = useSnapshots(root || undefined);
  const qc = useQueryClient();
  const [taking, setTaking] = useState(false);
  const [rolling, setRolling] = useState<Snapshot | null>(null);
  const [deleting, setDeleting] = useState<Snapshot | null>(null);
  const fsList = (datasets.data ?? []).filter((d) => d.type === "filesystem" && !/^(rpool|bpool)(\/|$)/.test(d.name));
  const rows = (snaps.data ?? []).filter((s) => !/^(rpool|bpool)(\/|$)/.test(s.dataset)).slice().reverse();

  return (
    <>
      <PageHeader
        title="Snapshots"
        subtitle="Read-only copies of a dataset at a moment in time. They take almost no space until files change."
        actions={
          <Button variant="primary" onClick={() => setTaking(true)} disabled={fsList.length === 0}>
            <CameraIcon size={16} /> Take snapshot
          </Button>
        }
      />
      <div className="row">
        <label className="small muted" htmlFor="snap-root">
          Dataset
        </label>
        <div style={{ width: 260 }}>
          <Select id="snap-root" value={root} onChange={(e) => setRoot(e.target.value)}>
            <option value="">All datasets</option>
            {fsList.map((d) => (
              <option key={d.name}>{d.name}</option>
            ))}
          </Select>
        </div>
      </div>
      {snaps.isPending ? (
        <Loading />
      ) : snaps.isError ? (
        <ErrorBox error={snaps.error} onRetry={() => snaps.refetch()} />
      ) : rows.length === 0 ? (
        <EmptyState title="No snapshots yet">Automatic snapshots run on the schedules you set. You can also take one now.</EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Dataset</th>
                <th>Snapshot</th>
                <th>Taken</th>
                <th className="num">Unique size</th>
                <th className="actions">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.name}>
                  <td className="mono small">{s.dataset}</td>
                  <td>
                    {s.label} {s.label.startsWith("auto-") && <Badge tone="neutral">auto</Badge>}
                  </td>
                  <td title={dateTime(s.createdAt)}>{relativeTime(s.createdAt)}</td>
                  <td className="num">{bytes(s.usedBytes)}</td>
                  <td className="actions">
                    <IconButton label={`Roll ${s.dataset} back to ${s.label}`} onClick={() => setRolling(s)}>
                      <RestartIcon size={16} />
                    </IconButton>
                    <IconButton label={`Delete ${s.name}`} onClick={() => setDeleting(s)}>
                      <TrashIcon size={16} />
                    </IconButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {taking && <TakeSnapshotDialog datasets={fsList.map((d) => d.name)} initial={root} onClose={() => setTaking(false)} />}
      {rolling && <RollbackDialog snap={rolling} onClose={() => setRolling(null)} />}
      {deleting && (
        <ConfirmDialog
          title="Delete snapshot?"
          confirmLabel="Delete snapshot"
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await unwrap(api.DELETE("/storage/snapshots", { body: { name: deleting.name } }));
            await qc.invalidateQueries({ queryKey: ["snapshots"] });
            toast("success", "Snapshot deleted");
          }}
        >
          <p>
            <span className="mono">{deleting.name}</span> will be deleted. Your current files aren't affected.
          </p>
        </ConfirmDialog>
      )}
    </>
  );
}

function TakeSnapshotDialog({ datasets, initial, onClose }: { datasets: string[]; initial: string; onClose: () => void }) {
  const qc = useQueryClient();
  const [dataset, setDataset] = useState(initial || datasets[0] || "");
  const [label, setLabel] = useState(() => `manual-${new Date().toISOString().slice(0, 16).replace(/[-:T]/g, "")}`);
  const [recursive, setRecursive] = useState(true);
  const take = useMutation({
    mutationFn: () => unwrap(api.POST("/storage/snapshots", { body: { dataset, label, recursive } })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["snapshots"] });
      toast("success", `Snapshot ${dataset}@${label} taken`);
      onClose();
    },
  });
  return (
    <Dialog
      title="Take a snapshot"
      onClose={onClose}
      onSubmit={() => take.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={take.isPending} disabled={!dataset || !label}>
            Take snapshot
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="Dataset">
          {(id) => (
            <Select id={id} value={dataset} onChange={(e) => setDataset(e.target.value)}>
              {datasets.map((d) => (
                <option key={d}>{d}</option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Name" hint="For example before-upgrade">
          {(id) => <TextInput id={id} value={label} onChange={(e) => setLabel(e.target.value)} spellCheck={false} />}
        </Field>
        <Toggle label="Include datasets inside it" checked={recursive} onChange={setRecursive} />
        {take.error && <Alert tone="bad">{errorMessage(take.error)}</Alert>}
      </div>
    </Dialog>
  );
}

function RollbackDialog({ snap, onClose }: { snap: Snapshot; onClose: () => void }) {
  const qc = useQueryClient();
  const [destroyNewer, setDestroyNewer] = useState(false);
  return (
    <ConfirmDialog
      title={`Roll ${snap.dataset} back?`}
      confirmLabel="Roll back"
      typeToConfirm={snap.dataset}
      onClose={onClose}
      onConfirm={async () => {
        await unwrap(api.POST("/storage/snapshots/rollback", { body: { name: snap.name, destroyNewer, confirm: true } }));
        await qc.invalidateQueries({ queryKey: ["snapshots"] });
        toast("success", `${snap.dataset} is back to ${snap.label}`);
      }}
    >
      <p>
        Every change to <strong>{snap.dataset}</strong> since {dateTime(snap.createdAt)} will be lost. Files created after that disappear; changed files return to how they were.
      </p>
      <Toggle
        label="Also delete newer snapshots"
        description="Required if snapshots were taken after this one."
        checked={destroyNewer}
        onChange={setDestroyNewer}
      />
    </ConfirmDialog>
  );
}
