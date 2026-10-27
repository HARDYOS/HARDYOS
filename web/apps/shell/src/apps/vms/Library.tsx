import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes, relativeTime } from "../../format";
import { DiscIcon, DownloadIcon, FolderIcon, StorageIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, Card, EmptyState, ErrorBox, Field, IconButton, Loading, PageHeader, Progress, Select, TextInput } from "../../ui";
import { ConfirmDialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { JobProgress } from "../shared";
import { useCapabilities, useLibrary, vmKeys } from "./vmApi";
import { fileFromURL, isISO, isImage } from "./wizard";

/** The ISO library: installer discs and disk images in the ISOs shared folder. */
export function Library({ openFiles }: { openFiles?: () => void }) {
  const lib = useLibrary(true);
  const caps = useCapabilities();
  const qc = useQueryClient();
  const [url, setUrl] = useState("");
  const [sha, setSha] = useState("");
  const [pool, setPool] = useState("");
  const [job, setJob] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  if (lib.isPending) return <Loading />;
  if (lib.isError) return <ErrorBox error={lib.error} onRetry={() => lib.refetch()} />;
  const l = lib.data;
  const name = fileFromURL(url);
  const okName = name !== "" && (isISO(name) || isImage(name));
  const pools = caps.data?.pools ?? [];
  const download = async () => {
    setBusy(true);
    try {
      const r = await unwrap(
        api.POST("/vms/isos/download", { body: { url: url.trim(), ...(sha.trim() ? { sha256: sha.trim() } : {}), ...(l.pool ? {} : { pool: pool || pools[0] || "" }) } }),
      );
      setJob(r.job.id);
      setUrl("");
      setSha("");
    } catch (e) {
      toast("error", "The download didn't start", errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  const running = l.tasks.filter((t) => !t.done);
  return (
    <div className="stack">
      <PageHeader
        title="ISO library"
        subtitle={
          l.pool ? (
            <>
              Installer discs and disk images, in the <strong>ISOs</strong> shared folder on {l.pool}. Copy files in from any computer, or download them here.
            </>
          ) : (
            "Installer discs and disk images for VMs live in an ISOs shared folder, made the first time you download one."
          )
        }
        actions={
          l.pool &&
          openFiles && (
            <Button onClick={openFiles}>
              <FolderIcon size={15} /> Open in File Manager
            </Button>
          )
        }
      />
      <Card title="Download by link">
        <div className="stack">
          <div className="grid-2">
            <Field label="Link" hint={name ? (okName ? `Saved as ${name}` : `${name} isn't an .iso or disk image`) : "An https:// link to an .iso or disk image"}>
              {(id) => <TextInput id={id} value={url} placeholder="https://…" spellCheck={false} onChange={(e) => setUrl(e.target.value)} />}
            </Field>
            <Field label="SHA-256 checksum (optional)" hint="Checked when the download finishes.">
              {(id) => <TextInput id={id} className="input mono" value={sha} spellCheck={false} onChange={(e) => setSha(e.target.value)} />}
            </Field>
          </div>
          {!l.pool && (
            <Field label="Pool for the ISOs shared folder">
              {(id) => (
                <Select id={id} value={pool || pools[0] || ""} onChange={(e) => setPool(e.target.value)} style={{ maxWidth: 240 }}>
                  {pools.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          )}
          <div>
            <Button variant="primary" disabled={!url.trim().startsWith("https://") || !okName} busy={busy} onClick={download}>
              <DownloadIcon size={15} /> Download
            </Button>
          </div>
          {job && (
            <JobProgress
              id={job}
              onDone={() => {
                void qc.invalidateQueries({ queryKey: vmKeys.library });
                void qc.invalidateQueries({ queryKey: vmKeys.caps });
              }}
            />
          )}
        </div>
      </Card>
      {running.length > 0 && (
        <Card title="Downloading">
          <div className="stack">
            {running.map((t) => (
              <div key={t.id} className="stack" style={{ gap: 6 }}>
                <div className="row row--between small">
                  <span>{t.message}</span>
                  <span className="mono">{Math.round(t.progress)}%</span>
                </div>
                <Progress value={t.progress} label={t.file} />
              </div>
            ))}
          </div>
        </Card>
      )}
      {l.files.length === 0 ? (
        <EmptyState icon={<DiscIcon size={28} />} title="The library is empty">
          Download an installer above, or copy .iso files and disk images into the ISOs shared folder.
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>File</th>
                <th>Kind</th>
                <th className="mono">Size</th>
                <th>Added</th>
                <th>In use by</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {l.files.map((f) => (
                <tr key={f.name}>
                  <td>
                    <span className="row" style={{ gap: 8 }}>
                      {f.kind === "iso" ? <DiscIcon size={15} /> : <StorageIcon size={15} />}
                      <span className="mono">{f.name}</span>
                    </span>
                  </td>
                  <td>
                    <Badge tone={f.kind === "iso" ? "accent" : "info"}>{f.kind === "iso" ? "Installer disc" : "Disk image"}</Badge>
                  </td>
                  <td className="mono">{bytes(f.size)}</td>
                  <td>{relativeTime(f.modified)}</td>
                  <td>{f.usedBy.length ? f.usedBy.join(", ") : <span className="muted">—</span>}</td>
                  <td className="actions">
                    <IconButton label={`Delete ${f.name}`} disabled={f.usedBy.length > 0} onClick={() => setDeleting(f.name)}>
                      <TrashIcon size={15} />
                    </IconButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {l.tasks.some((t) => t.done && t.error) && (
        <Alert tone="bad" title="A download failed">
          {l.tasks.find((t) => t.done && t.error)?.error}
        </Alert>
      )}
      {deleting && (
        <ConfirmDialog
          title={`Delete ${deleting}?`}
          confirmLabel="Delete"
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            const r = await unwrap(api.DELETE("/vms/isos/{name}", { params: { path: { name: deleting } } }));
            setJob(r.job.id);
          }}
        >
          <p>The file is deleted from the ISOs shared folder.</p>
        </ConfirmDialog>
      )}
    </div>
  );
}
