import type { BackupSettings, BackupStaged, BackupStatus, PoolBackup } from "@hardy/api-client";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, useRef, useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { bytes, dateTime, relativeTime } from "../../format";
import { RestartIcon, UploadIcon } from "../../icons";
import { Alert, Badge, Button, Card, ErrorBox, Field, Loading, PageHeader, Select, TextInput, Toggle } from "../../ui";
import { Dialog } from "../../ui/Dialog";
import { RestartOverlay } from "../../ui/RestartOverlay";
import { toast } from "../../ui/toasts";
import { JobProgress } from "../shared";

const useBackups = () => useQuery({ queryKey: ["backups"], queryFn: () => unwrap(api.GET("/system/backups")), refetchInterval: 30_000 });

/** First bytes of a backup file: "HOSBAK01" then 1 when password-protected. */
function isProtected(file: File): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(new Uint8Array(r.result as ArrayBuffer)[8] === 1);
    r.onerror = () => reject(r.error);
    r.readAsArrayBuffer(file.slice(0, 9));
  });
}

function uploadBackup(file: File): Promise<{ upload: string }> {
  return fetch("/api/v1/system/backups/upload", {
    method: "POST",
    headers: { "X-HardyOS-Request": "1", "Content-Type": "application/octet-stream" },
    body: file,
  }).then(async (r) => {
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new ApiFailure(r.status, body.code ?? "error", body.message ?? `Upload failed (${r.status})`);
    return body as { upload: string };
  });
}

export function Backup() {
  const qc = useQueryClient();
  const status = useBackups();
  const [restarting, setRestarting] = useState(false);
  const [restoreFrom, setRestoreFrom] = useState<PoolBackup | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["backups"] });
  const reboot = useMutation({ mutationFn: () => unwrap(api.POST("/system/reboot")), onSuccess: () => setRestarting(true) });

  if (restarting) return <RestartOverlay message="Restarting to restore settings…" />;
  if (status.isPending) return <Loading />;
  if (status.isError) return <ErrorBox error={status.error} onRetry={() => status.refetch()} />;
  const st = status.data;

  return (
    <>
      <PageHeader
        title="Backup & Restore"
        subtitle="Save the server's settings (users, schedules, network, time) and bring them back, even onto a fresh install."
      />
      {st.pending && <PendingRestore pending={st.pending} busy={reboot.isPending} onRestart={() => reboot.mutate()} onCancelled={refresh} />}
      {st.lastResult && !st.pending && <LastRestore st={st} />}
      <NightlyCard st={st} onChanged={refresh} />
      <PoolBackups st={st} onRestore={setRestoreFrom} />
      <div className="grid-2">
        <DownloadCard />
        <UploadRestoreCard onStaged={refresh} />
      </div>
      {restoreFrom && (
        <RestoreDialog
          backup={restoreFrom}
          onClose={() => setRestoreFrom(null)}
          onStaged={() => {
            setRestoreFrom(null);
            refresh();
          }}
        />
      )}
    </>
  );
}

function PendingRestore({ pending, busy, onRestart, onCancelled }: { pending: BackupStaged; busy: boolean; onRestart: () => void; onCancelled: () => void }) {
  const cancel = useMutation({ mutationFn: () => unwrap(api.POST("/system/backups/restore/cancel")), onSuccess: onCancelled });
  const m = pending.manifest;
  return (
    <Card className="update-ready">
      <div className="row row--between">
        <div>
          <h3 style={{ margin: 0 }}>Settings from {dateTime(m.createdAt)} are ready to restore</h3>
          <p className="small muted" style={{ margin: "4px 0 0" }}>
            From {m.hostname}, HardyOS {m.version}
            {m.secrets ? ", with encryption keys" : ""}. They replace the current settings when the server restarts.
          </p>
        </div>
        <Badge tone="accent">waiting for restart</Badge>
      </div>
      <Alert tone="warn">
        After restarting, sign in with an account from the backup ({m.users} {m.users === 1 ? "account" : "accounts"}). Accounts made since then
        won't exist anymore. Your files and storage pools aren't touched.
      </Alert>
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <Button variant="ghost" busy={cancel.isPending} onClick={() => cancel.mutate()}>
          Don't restore
        </Button>
        <Button variant="primary" busy={busy} onClick={onRestart}>
          <RestartIcon size={15} /> Restart now
        </Button>
      </div>
    </Card>
  );
}

function LastRestore({ st }: { st: BackupStatus }) {
  const r = st.lastResult!;
  return (
    <Alert tone={!r.ok ? "bad" : r.notes.length ? "warn" : "good"} title={r.ok ? "Last restore" : "The last restore failed"}>
      {r.message} <span className="muted">({dateTime(r.at)})</span>
      {r.notes.length > 0 && (
        <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
          {r.notes.map((n) => (
            <li key={n}>{n}</li>
          ))}
        </ul>
      )}
    </Alert>
  );
}

function NightlyCard({ st, onChanged }: { st: BackupStatus; onChanged: () => void }) {
  const [draft, setDraft] = useState<BackupSettings | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const cfg = draft ?? st.settings;
  const dirty = draft !== null && JSON.stringify(draft) !== JSON.stringify(st.settings);
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/system/backups/settings", { body: cfg })),
    onSuccess: () => {
      setDraft(null);
      onChanged();
      toast("success", "Backup settings saved");
    },
  });
  const run = useMutation({
    mutationFn: () => unwrap(api.POST("/system/backups/run", { body: {} })),
    onSuccess: (r) => setJobId((r.job as { id: string }).id),
  });
  const set = (patch: Partial<BackupSettings>) => setDraft({ ...cfg, ...patch });
  const noPool = st.pools.length === 0;

  return (
    <Card
      title="Nightly backup"
      actions={
        <Button size="sm" disabled={noPool || jobId !== null} busy={run.isPending} onClick={() => run.mutate()}>
          Back up now
        </Button>
      }
    >
      {noPool ? (
        <Alert tone="info">Nightly backups are kept on a storage pool, so they survive a reinstall. Create a pool in Storage Manager first.</Alert>
      ) : (
        <p className="small muted" style={{ margin: 0 }}>
          {st.lastError ? (
            <span className="field__error">The last backup failed: {st.lastError}</span>
          ) : st.lastRun ? (
            `Last backup ${relativeTime(st.lastRun)}.`
          ) : (
            "No backup yet."
          )}{" "}
          Encryption keys are never kept on a pool; download a backup with keys to keep those safe.
        </p>
      )}
      {jobId && (
        <JobProgress
          id={jobId}
          onDone={() => {
            setJobId(null);
            onChanged();
          }}
        />
      )}
      <Toggle label="Back up settings every night" checked={cfg.nightly} onChange={(nightly) => set({ nightly })} disabled={noPool} />
      <div className="grid-3">
        <Field label="Pool">
          {(id) => (
            <Select id={id} value={cfg.pool} onChange={(e) => set({ pool: e.target.value })} disabled={noPool}>
              <option value="">{st.pools[0] ? `Automatic (${st.pools[0]})` : "Automatic"}</option>
              {st.pools.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Time" hint="Server time">
          {(id) => <TextInput id={id} type="time" value={cfg.time} onChange={(e) => set({ time: e.target.value })} disabled={noPool} />}
        </Field>
        <Field label="Keep" hint="Newest backups kept">
          {(id) => (
            <TextInput id={id} type="number" min={1} max={365} value={cfg.keep} onChange={(e) => set({ keep: Number(e.target.value) })} disabled={noPool} />
          )}
        </Field>
      </div>
      {save.error != null && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
      {dirty && (
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <Button variant="ghost" onClick={() => setDraft(null)}>
            Discard
          </Button>
          <Button variant="primary" busy={save.isPending} onClick={() => save.mutate()}>
            Save
          </Button>
        </div>
      )}
    </Card>
  );
}

function PoolBackups({ st, onRestore }: { st: BackupStatus; onRestore: (b: PoolBackup) => void }) {
  if (st.pools.length === 0) return null;
  return (
    <Card title="Backups on your pools">
      {st.backups.length === 0 ? (
        <p className="small muted" style={{ margin: 0 }}>
          None yet. The first one is made tonight, or choose Back up now.
        </p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Made</th>
                <th>From</th>
                <th>Accounts</th>
                <th>Pool</th>
                <th>Size</th>
                <th className="actions">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {st.backups.map((b) => (
                <tr key={b.pool + b.name}>
                  <td>
                    <strong>{dateTime(b.manifest.createdAt)}</strong>
                    <span className="cell-sub">{b.manifest.note === "nightly" ? "nightly" : "by hand"}</span>
                  </td>
                  <td>
                    {b.manifest.hostname}
                    <span className="cell-sub">HardyOS {b.manifest.version}</span>
                  </td>
                  <td>{b.manifest.users}</td>
                  <td className="mono">{b.pool}</td>
                  <td>{bytes(b.size)}</td>
                  <td className="actions">
                    <Button size="sm" disabled={st.pending != null} onClick={() => onRestore(b)}>
                      Restore…
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

function DownloadCard() {
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [secrets, setSecrets] = useState(true);
  const prepare = useMutation({
    mutationFn: () => unwrap(api.POST("/system/backups/download", { body: { password: pw, secrets } })),
    onSuccess: (d) => {
      const a = document.createElement("a");
      a.href = `/api/v1/system/backups/files/${encodeURIComponent(d.name)}?as=${encodeURIComponent(d.file)}`;
      a.download = d.file;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setPw("");
      setPw2("");
      toast("success", "Backup downloaded", `Keep the password with it: without it the file can't be opened.`);
    },
  });
  const mismatch = pw2 !== "" && pw !== pw2;
  return (
    <Card title="Download a backup">
      <p className="small muted" style={{ margin: 0 }}>
        A password-protected file to keep somewhere else, like a USB stick or your password manager.
      </p>
      <Field label="Password" hint="At least 8 characters. There's no way to recover it.">
        {(id) => <TextInput id={id} type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} />}
      </Field>
      <Field label="Repeat the password" error={mismatch ? "The passwords don't match" : null}>
        {(id) => <TextInput id={id} type="password" autoComplete="new-password" value={pw2} onChange={(e) => setPw2(e.target.value)} />}
      </Field>
      <Toggle
        label="Include encryption keys"
        description="Keys for encrypted storage and the server's SSH identity. Without them, encrypted data can't be unlocked after a reinstall."
        checked={secrets}
        onChange={setSecrets}
      />
      {prepare.error != null && <Alert tone="bad">{errorMessage(prepare.error)}</Alert>}
      <div className="row" style={{ justifyContent: "flex-end" }}>
        <Button variant="primary" disabled={pw.length < 8 || pw !== pw2} busy={prepare.isPending} onClick={() => prepare.mutate()}>
          Download
        </Button>
      </div>
    </Card>
  );
}

function UploadRestoreCard({ onStaged }: { onStaged: () => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [upload, setUpload] = useState<{ name: string; file: File; locked: boolean } | null>(null);
  const [pw, setPw] = useState("");
  const send = useMutation({
    mutationFn: async (file: File) => {
      const locked = await isProtected(file);
      const r = await uploadBackup(file);
      return { name: r.upload, file, locked };
    },
    onSuccess: setUpload,
  });
  const stage = useMutation({
    mutationFn: () => unwrap(api.POST("/system/backups/restore", { body: { upload: upload!.name, password: pw || undefined } })),
    onSuccess: () => {
      setUpload(null);
      setPw("");
      onStaged();
    },
  });
  return (
    <Card title="Restore from a file">
      <p className="small muted" style={{ margin: 0 }}>
        Restore a backup you downloaded, here or on a new install. Nothing changes until the server restarts.
      </p>
      {!upload ? (
        <div className="row">
          <Button busy={send.isPending} onClick={() => input.current?.click()}>
            <UploadIcon size={15} /> Choose backup file…
          </Button>
          <input
            ref={input}
            type="file"
            accept=".hbak"
            hidden
            aria-label="Backup file"
            onChange={(e: ChangeEvent<HTMLInputElement>) => {
              const f = e.target.files?.[0];
              if (f) send.mutate(f);
              e.target.value = "";
            }}
          />
        </div>
      ) : (
        <div className="stack">
          <span className="small">
            <strong>{upload.file.name}</strong> ({bytes(upload.file.size)})
          </span>
          {upload.locked && (
            <Field label="Backup password">
              {(id) => <TextInput id={id} type="password" autoComplete="off" value={pw} onChange={(e) => setPw(e.target.value)} />}
            </Field>
          )}
          <div className="row" style={{ justifyContent: "flex-end" }}>
            <Button variant="ghost" onClick={() => setUpload(null)}>
              Cancel
            </Button>
            <Button variant="primary" disabled={upload.locked && !pw} busy={stage.isPending} onClick={() => stage.mutate()}>
              Restore at next restart
            </Button>
          </div>
        </div>
      )}
      {(send.error ?? stage.error) != null && <Alert tone="bad">{errorMessage(send.error ?? stage.error)}</Alert>}
    </Card>
  );
}

function RestoreDialog({ backup, onClose, onStaged }: { backup: PoolBackup; onClose: () => void; onStaged: () => void }) {
  const stage = useMutation({
    mutationFn: () => unwrap(api.POST("/system/backups/restore", { body: { pool: backup.pool, name: backup.name } })),
    onSuccess: onStaged,
  });
  const m = backup.manifest;
  return (
    <Dialog
      title={`Restore settings from ${dateTime(m.createdAt)}?`}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" busy={stage.isPending} onClick={() => stage.mutate()}>
            Restore at next restart
          </Button>
        </>
      }
    >
      <div className="stack">
        <p style={{ margin: 0 }}>
          Users, schedules, network and time settings go back to how they were on {m.hostname} (HardyOS {m.version}). Your files
          and storage pools aren't touched.
        </p>
        <p className="small muted" style={{ margin: 0 }}>
          It happens when the server restarts; you can still cancel until then. Afterwards, sign in with an account from the backup.
        </p>
        {stage.error != null && <Alert tone="bad">{errorMessage(stage.error)}</Alert>}
      </div>
    </Dialog>
  );
}
