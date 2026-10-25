import type { Dataset } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes } from "../../format";
import { useDatasets } from "../../hooks/queries";
import { EditIcon, PlusIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, EmptyState, ErrorBox, Field, IconButton, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";

const COMPRESSION = ["lz4", "zstd", "zstd-3", "zstd-9", "gzip", "off"];
const RECORDSIZES = ["16K", "64K", "128K", "1M"];

/** Splits "500G"/"none" into a number + unit for the form, and back. */
function quotaToForm(bytesVal: number): string {
  if (!bytesVal) return "";
  const gb = bytesVal / 1e9;
  return gb >= 1000 ? `${+(gb / 1000).toFixed(2)}T` : `${Math.round(gb)}G`;
}

export function Datasets() {
  const q = useDatasets();
  const qc = useQueryClient();
  const [creating, setCreating] = useState<string | null>(null);
  const [editing, setEditing] = useState<Dataset | null>(null);
  const [deleting, setDeleting] = useState<Dataset | null>(null);

  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const list = q.data.filter((d) => !/^(rpool|bpool|hardyos-boot)(\/|$)/.test(d.name));

  return (
    <>
      <PageHeader
        title="Datasets"
        subtitle="Folders with their own quota, compression and snapshots. Volumes are virtual disks for VMs."
        actions={
          list.length > 0 && (
            <Button variant="primary" onClick={() => setCreating(list[0]!.name.split("/")[0]!)}>
              <PlusIcon size={16} /> New dataset
            </Button>
          )
        }
      />
      {list.length === 0 ? (
        <EmptyState title="No datasets">Create a pool first; it comes with standard datasets.</EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th className="num">Used</th>
                <th className="num">Available</th>
                <th className="num">Quota</th>
                <th>Compression</th>
                <th className="actions">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {list.map((d) => {
                const depth = d.name.split("/").length - 1;
                const short = d.name.split("/").pop()!;
                return (
                  <tr key={d.name}>
                    <td className={`indent-${Math.min(depth, 3)}`}>
                      <strong>{depth === 0 ? d.name : short}</strong> {d.type === "volume" && <Badge tone="neutral">volume {bytes(d.volSizeBytes, 0)}</Badge>}
                      {d.encryption !== "off" && d.encryption && <Badge tone="neutral">encrypted</Badge>}
                      <span className="cell-sub mono">{d.type === "volume" ? d.name : d.mountpoint}</span>
                    </td>
                    <td className="num">{bytes(d.usedBytes)}</td>
                    <td className="num">{bytes(d.availBytes)}</td>
                    <td className="num">{d.quotaBytes ? bytes(d.quotaBytes) : "–"}</td>
                    <td>
                      {d.compression} <span className="cell-sub">{d.compressRatio}</span>
                    </td>
                    <td className="actions">
                      {d.type === "filesystem" && (
                        <IconButton label={`New dataset inside ${d.name}`} onClick={() => setCreating(d.name)}>
                          <PlusIcon size={16} />
                        </IconButton>
                      )}
                      <IconButton label={`Edit ${d.name}`} onClick={() => setEditing(d)}>
                        <EditIcon size={16} />
                      </IconButton>
                      {depth > 0 && (
                        <IconButton label={`Delete ${d.name}`} onClick={() => setDeleting(d)}>
                          <TrashIcon size={16} />
                        </IconButton>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {creating && <CreateDatasetDialog parent={creating} onClose={() => setCreating(null)} />}
      {editing && <EditDatasetDialog ds={editing} onClose={() => setEditing(null)} />}
      {deleting && (
        <ConfirmDialog
          title={`Delete ${deleting.name}?`}
          confirmLabel="Delete dataset"
          typeToConfirm={deleting.name}
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await unwrap(api.DELETE("/storage/datasets", { body: { name: deleting.name, recursive: true, confirmName: deleting.name } }));
            await qc.invalidateQueries({ queryKey: ["datasets"] });
            toast("success", `Deleted ${deleting.name}`);
          }}
        >
          <p>Everything in <strong>{deleting.name}</strong>, including datasets inside it and their snapshots, will be erased permanently.</p>
        </ConfirmDialog>
      )}
    </>
  );
}

function CreateDatasetDialog({ parent, onClose }: { parent: string; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [isVolume, setIsVolume] = useState(false);
  const [size, setSize] = useState("64G");
  const [quota, setQuota] = useState("");
  const [compression, setCompression] = useState("lz4");
  const create = useMutation({
    mutationFn: () =>
      unwrap(
        api.POST("/storage/datasets", {
          body: {
            name: `${parent}/${name}`,
            volSize: isVolume ? size.toUpperCase() : undefined,
            props: { compression, ...(quota && !isVolume ? { quota: quota.toUpperCase() } : {}) },
          },
        }),
      ),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["datasets"] });
      toast("success", `Created ${parent}/${name}`);
      onClose();
    },
  });
  return (
    <Dialog
      title="New dataset"
      description={`Inside ${parent}`}
      onClose={onClose}
      onSubmit={() => name && create.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={create.isPending} disabled={!name}>
            Create
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="Name" hint="Letters, digits, '_', '.', '-'">
          {(id) => <TextInput id={id} value={name} onChange={(e) => setName(e.target.value)} spellCheck={false} />}
        </Field>
        <Toggle label="Volume (virtual disk)" description="For VM disks. Leave off for a normal folder." checked={isVolume} onChange={setIsVolume} />
        {isVolume ? (
          <Field label="Size" hint="For example 64G or 1T. Space is used only as data is written.">
            {(id) => <TextInput id={id} value={size} onChange={(e) => setSize(e.target.value)} />}
          </Field>
        ) : (
          <Field label="Quota" hint="Optional limit, for example 500G or 2T">
            {(id) => <TextInput id={id} value={quota} onChange={(e) => setQuota(e.target.value)} placeholder="No limit" />}
          </Field>
        )}
        <Field label="Compression">
          {(id) => (
            <Select id={id} value={compression} onChange={(e) => setCompression(e.target.value)}>
              {COMPRESSION.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </Select>
          )}
        </Field>
        {create.error && <Alert tone="bad">{errorMessage(create.error)}</Alert>}
      </div>
    </Dialog>
  );
}

function EditDatasetDialog({ ds, onClose }: { ds: Dataset; onClose: () => void }) {
  const qc = useQueryClient();
  const [quota, setQuota] = useState(quotaToForm(ds.quotaBytes));
  const [compression, setCompression] = useState(ds.compression);
  const [recordsize, setRecordsize] = useState(ds.recordSize ? `${Number(ds.recordSize) / 1024 >= 1024 ? `${Number(ds.recordSize) / 1048576}M` : `${Number(ds.recordSize) / 1024}K`}` : "128K");
  const save = useMutation({
    mutationFn: () => {
      const props: Record<string, string> = { compression };
      if (ds.type === "filesystem") {
        props.quota = quota ? quota.toUpperCase() : "none";
        props.recordsize = recordsize;
      }
      return unwrap(api.PATCH("/storage/datasets", { body: { name: ds.name, props } }));
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["datasets"] });
      toast("success", `Saved ${ds.name}`);
      onClose();
    },
  });
  return (
    <Dialog
      title={`Edit ${ds.name}`}
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
        {ds.type === "filesystem" && (
          <>
            <Field label="Quota" hint="For example 500G or 2T; empty for no limit">
              {(id) => <TextInput id={id} value={quota} onChange={(e) => setQuota(e.target.value)} placeholder="No limit" />}
            </Field>
            <Field label="Record size" hint="128K suits most files; 1M for large media; 16K-64K for databases and VMs">
              {(id) => (
                <Select id={id} value={recordsize} onChange={(e) => setRecordsize(e.target.value)}>
                  {Array.from(new Set([...RECORDSIZES, recordsize])).map((r) => (
                    <option key={r}>{r}</option>
                  ))}
                </Select>
              )}
            </Field>
          </>
        )}
        <Field label="Compression">
          {(id) => (
            <Select id={id} value={compression} onChange={(e) => setCompression(e.target.value)}>
              {Array.from(new Set([...COMPRESSION, compression])).map((c) => (
                <option key={c}>{c}</option>
              ))}
            </Select>
          )}
        </Field>
        {save.error && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      </div>
    </Dialog>
  );
}
