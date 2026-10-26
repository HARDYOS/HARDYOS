import type { InstalledVersion, UpdateStatus } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, type DragEvent, useRef, useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { bytes, dateTime, relativeTime } from "../../format";
import { RestartIcon, TrashIcon, UploadIcon } from "../../icons";
import { Alert, Badge, Button, Card, ErrorBox, Field, IconButton, Loading, PageHeader, Progress, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { RestartOverlay } from "../../ui/RestartOverlay";
import { toast } from "../../ui/toasts";
import { JobProgress } from "../shared";

export function useUpdateStatus() {
  return useQuery({ queryKey: ["updates"], queryFn: () => unwrap(api.GET("/system/updates")), refetchInterval: 30_000 });
}

/** Uploads a file as the raw request body, reporting progress (fetch can't). */
function uploadUpdate(file: File, onProgress: (pct: number) => void): Promise<{ job: { id: string } }> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v1/system/updates/upload");
    xhr.setRequestHeader("X-HardyOS-Request", "1");
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress((e.loaded / e.total) * 100);
    xhr.onload = () => {
      let body: { job?: { id: string }; code?: string; message?: string } = {};
      try {
        body = JSON.parse(xhr.responseText);
      } catch {
        // not JSON
      }
      if (xhr.status === 202 && body.job) resolve(body as { job: { id: string } });
      else reject(new ApiFailure(xhr.status, body.code ?? "error", body.message ?? `Upload failed (${xhr.status})`));
    };
    xhr.onerror = () => reject(new ApiFailure(0, "network", "The upload was interrupted. Check the connection and try again."));
    xhr.send(file);
  });
}

export function Updates() {
  const qc = useQueryClient();
  const status = useUpdateStatus();
  const [restarting, setRestarting] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const reboot = useMutation({
    mutationFn: () => unwrap(api.POST("/system/reboot")),
    onSuccess: () => setRestarting(true),
  });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["updates"] });

  if (restarting) return <RestartOverlay />;
  if (status.isPending) return <Loading />;
  if (status.isError) return <ErrorBox error={status.error} onRetry={() => status.refetch()} />;
  const st = status.data;
  const running = st.versions.find((v) => v.running);

  return (
    <>
      <PageHeader
        title="Updates"
        subtitle={running ? `Running HardyOS ${running.version || running.name}` : "Install new versions and go back to earlier ones."}
      />
      {!st.managed && (
        <Alert tone="info" title="Updates need a HardyOS install">
          This system wasn't installed with the HardyOS installer, so it has no boot environments to update into.
        </Alert>
      )}
      {st.last && <LastResult last={st.last} />}
      {st.restoreOnBoot && (
        <Alert tone="info">Settings from before the last update will be restored when the server restarts.</Alert>
      )}
      {st.pending && st.running !== st.pending.bootEnvironment && (
        <PendingCard st={st} busy={reboot.isPending} error={reboot.error} onRestart={() => reboot.mutate()} onCancelled={refresh} />
      )}
      {st.managed && !st.pending && (
        <InstallCard
          jobId={jobId}
          onJob={setJobId}
          onDone={() => {
            refresh();
          }}
        />
      )}
      {st.managed && <Versions st={st} onChanged={refresh} onRestart={() => reboot.mutate()} />}
    </>
  );
}

function LastResult({ last }: { last: NonNullable<UpdateStatus["last"]> }) {
  return (
    <Alert tone={last.ok ? "good" : "bad"} title={last.ok ? "Last update" : "The last update was rolled back"}>
      {last.message} <span className="muted">({dateTime(last.at)})</span>
    </Alert>
  );
}

function PendingCard({
  st,
  busy,
  error,
  onRestart,
  onCancelled,
}: {
  st: UpdateStatus;
  busy: boolean;
  error: unknown;
  onRestart: () => void;
  onCancelled: () => void;
}) {
  const p = st.pending!;
  const [cancel, setCancel] = useState(false);
  return (
    <Card className="update-ready">
      <div className="row row--between">
        <div>
          <h3 style={{ margin: 0 }}>HardyOS {p.version} is ready</h3>
          <p className="small muted" style={{ margin: "4px 0 0" }}>
            Installed {relativeTime(p.stagedAt)}. Restart to start using it
            {p.fromVersion ? `; ${p.fromVersion} stays installed so you can go back` : ""}.
          </p>
        </div>
        <Badge tone="accent">waiting for restart</Badge>
      </div>
      {p.notes && <p className="update-notes">{p.notes}</p>}
      <p className="small muted" style={{ margin: 0 }}>
        If the new version doesn't start correctly, the server goes back to the current one by itself and restores its settings.
        Services are unavailable for a few minutes while it restarts.
      </p>
      {error != null && <Alert tone="bad">{errorMessage(error)}</Alert>}
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <Button variant="ghost" onClick={() => setCancel(true)}>
          Don't install
        </Button>
        <Button variant="primary" busy={busy} onClick={onRestart}>
          <RestartIcon size={15} /> Restart now
        </Button>
      </div>
      {cancel && (
        <ConfirmDialog
          title={`Don't install HardyOS ${p.version}?`}
          confirmLabel="Remove it"
          onClose={() => setCancel(false)}
          onConfirm={async () => {
            await unwrap(
              api.POST("/system/versions/{name}/delete", {
                params: { path: { name: p.bootEnvironment } },
                body: { confirmName: p.bootEnvironment },
              }),
            );
            toast("success", `HardyOS ${p.version} will be removed`);
            setTimeout(onCancelled, 1500);
          }}
        >
          <p>The downloaded version is removed and the server keeps running {st.running}. You can install it again later.</p>
        </ConfirmDialog>
      )}
    </Card>
  );
}

function InstallCard({ jobId, onJob, onDone }: { jobId: string | null; onJob: (id: string | null) => void; onDone: () => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [pct, setPct] = useState(0);
  const [dragging, setDragging] = useState(false);
  const [url, setUrl] = useState("");
  const upload = useMutation({
    mutationFn: (f: File) => uploadUpdate(f, setPct),
    onSuccess: (res) => onJob(res.job.id),
  });
  const download = useMutation({
    mutationFn: () => unwrap(api.POST("/system/updates/download", { body: { url } })),
    onSuccess: (res) => onJob((res.job as { id: string }).id),
  });

  const choose = (f: File | undefined) => {
    if (!f) return;
    setFile(f);
    setPct(0);
    onJob(null);
    upload.mutate(f);
  };
  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    choose(e.dataTransfer.files[0]);
  };

  if (jobId) {
    return (
      <Card title="Installing the update">
        <JobProgress
          id={jobId}
          onDone={(job) => {
            onDone();
            if (job.state !== "succeeded") return;
            toast("success", "Update installed. Restart to finish.");
          }}
        />
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <Button onClick={() => onJob(null)}>Done</Button>
        </div>
      </Card>
    );
  }

  return (
    <Card title="Install an update">
      <p className="small muted" style={{ margin: 0 }}>
        Updates are signed .hupd files. HardyOS checks the signature, installs the new version next to the current one and
        switches on the next restart.
      </p>
      <div
        className={`dropzone ${dragging ? "is-over" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
      >
        <UploadIcon size={24} />
        {upload.isPending && file ? (
          <div className="stack" style={{ width: "100%", maxWidth: 360 }}>
            <span className="small">
              Uploading {file.name} ({bytes(file.size)})
            </span>
            <Progress value={pct} label="Upload progress" />
          </div>
        ) : (
          <>
            <span>Drop an update file here</span>
            <Button size="sm" onClick={() => input.current?.click()}>
              Choose file…
            </Button>
          </>
        )}
        <input
          ref={input}
          type="file"
          accept=".hupd"
          hidden
          aria-label="Update file"
          onChange={(e: ChangeEvent<HTMLInputElement>) => choose(e.target.files?.[0])}
        />
      </div>
      {upload.error && <Alert tone="bad">{errorMessage(upload.error)}</Alert>}
      <form
        className="row"
        onSubmit={(e) => {
          e.preventDefault();
          if (url) download.mutate();
        }}
      >
        <Field label="Or download from an address">
          {(id) => (
            <TextInput id={id} value={url} onChange={(e) => setUrl(e.target.value.trim())} placeholder="https://…/hardyos-0.2.0-amd64.hupd" />
          )}
        </Field>
        <Button type="submit" disabled={!url} busy={download.isPending} style={{ alignSelf: "flex-end" }}>
          Download and install
        </Button>
      </form>
      {download.error && <Alert tone="bad">{errorMessage(download.error)}</Alert>}
    </Card>
  );
}

function Versions({ st, onChanged, onRestart }: { st: UpdateStatus; onChanged: () => void; onRestart: () => void }) {
  const [switching, setSwitching] = useState<InstalledVersion | null>(null);
  const [removing, setRemoving] = useState<InstalledVersion | null>(null);
  const [switched, setSwitched] = useState<string | null>(null);
  const running = st.versions.find((v) => v.running);
  return (
    <Card title="Installed versions">
      <p className="small muted" style={{ margin: 0 }}>
        HardyOS keeps the last few versions so you can go back if something isn't right. Your files and storage pools are
        never part of a version.
      </p>
      {switched && (
        <Alert
          tone="info"
          title={`${switched} starts after a restart`}
          action={
            <Button size="sm" variant="primary" onClick={onRestart}>
              Restart now
            </Button>
          }
        />
      )}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Version</th>
              <th>Installed</th>
              <th>Status</th>
              <th className="actions">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {st.versions.map((v) => (
              <tr key={v.name}>
                <td>
                  <strong>HardyOS {v.version || v.name}</strong>
                  <span className="cell-sub mono">{v.name}</span>
                </td>
                <td>{relativeTime(new Date(v.created * 1000).toISOString())}</td>
                <td>
                  <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                    {v.running && <Badge tone="good">running</Badge>}
                    {v.default && !v.running && <Badge tone="accent">starts next</Badge>}
                    {v.trying && <Badge tone="accent">waiting for restart</Badge>}
                  </div>
                </td>
                <td className="actions">
                  {!v.running && !v.trying && !v.default && !st.pending && (
                    <Button size="sm" onClick={() => setSwitching(v)}>
                      Use this version
                    </Button>
                  )}
                  {!v.running && !v.default && !v.trying && (
                    <IconButton label={`Remove ${v.name}`} onClick={() => setRemoving(v)}>
                      <TrashIcon size={16} />
                    </IconButton>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {switching && running && (
        <SwitchDialog
          from={running}
          to={switching}
          onClose={() => setSwitching(null)}
          onDone={() => {
            setSwitched(`HardyOS ${switching.version || switching.name}`);
            setSwitching(null);
            setTimeout(onChanged, 1500);
          }}
        />
      )}
      {removing && (
        <ConfirmDialog
          title={`Remove HardyOS ${removing.version || removing.name}?`}
          confirmLabel="Remove"
          typeToConfirm={removing.name}
          onClose={() => setRemoving(null)}
          onConfirm={async () => {
            await unwrap(
              api.POST("/system/versions/{name}/delete", { params: { path: { name: removing.name } }, body: { confirmName: removing.name } }),
            );
            toast("success", `Removing ${removing.name}`);
            setTimeout(onChanged, 1500);
          }}
        >
          <p>You won't be able to go back to this version. Your files and settings aren't affected.</p>
        </ConfirmDialog>
      )}
    </Card>
  );
}

function SwitchDialog({ from, to, onClose, onDone }: { from: InstalledVersion; to: InstalledVersion; onClose: () => void; onDone: () => void }) {
  const older = to.created < from.created;
  const [restore, setRestore] = useState(false);
  const activate = useMutation({
    mutationFn: () => unwrap(api.POST("/system/versions/{name}/activate", { params: { path: { name: to.name } }, body: { restoreSettings: restore } })),
    onSuccess: onDone,
  });
  return (
    <Dialog
      title={`Go back to HardyOS ${to.version || to.name}?`}
      onClose={onClose}
      onSubmit={() => activate.mutate()}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={activate.isPending}>
            Use this version
          </Button>
        </>
      }
    >
      <div className="stack">
        <p className="dialog__text">
          The server keeps running {from.version || from.name} until you restart it, then starts {to.version || to.name}. You can
          switch back the same way.
        </p>
        {older && (
          <Toggle
            label="Also restore settings from before the update"
            description={`Accounts and settings go back to how they were when ${from.version || from.name} was installed. Changes since then are lost. Use this if the older version doesn't start.`}
            checked={restore}
            onChange={setRestore}
          />
        )}
        {activate.error && <Alert tone="bad">{errorMessage(activate.error)}</Alert>}
      </div>
    </Dialog>
  );
}
