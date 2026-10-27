import type { OfficeStatus } from "@hardy/api-client";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { relativeTime } from "../../format";
import { useJob } from "../../hooks/queries";
import { Alert, Badge, Button, Card, ErrorBox, Field, Loading, PageHeader, Progress, Select, Stat, TextInput } from "../../ui";
import { toast } from "../../ui/toasts";
import { officeKey, useOffice } from "../office/officeApi";

/** Control Panel › Office: the office suite (OnlyOffice Document Server). */
export function Office() {
  const q = useOffice();
  const qc = useQueryClient();
  const [jobId, setJobId] = useState<string | null>(null);
  const job = useJob(jobId);
  const running = !!job.data && (job.data.state === "queued" || job.data.state === "running");

  useEffect(() => {
    if (job.data && !running) void qc.invalidateQueries({ queryKey: officeKey });
  }, [job.data, running, qc]);

  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const st = q.data;

  return (
    <>
      <PageHeader
        title="Office"
        subtitle="Documents, spreadsheets and presentations open in an editor window from the File Manager, and several people can edit one together."
        badge={st.enabled ? <Badge tone={st.ready ? "good" : "warn"}>{st.ready ? "On" : "Starting"}</Badge> : <Badge>Off</Badge>}
      />
      {job.data?.state === "failed" && (
        <Alert tone="bad" title={`${job.data.title} failed`}>
          {job.data.error}
        </Alert>
      )}
      {running && (
        <Card>
          <Progress value={job.data?.progress ?? 0} label={job.data?.message || job.data?.title || "Working…"} />
          <p className="small muted">{job.data?.message}</p>
        </Card>
      )}
      <OnOff st={st} busy={running} onJob={setJobId} />
      {st.enabled && <Usage st={st} />}
      <Settings st={st} busy={running} onJob={setJobId} />
      <Card title="How it works">
        <ul className="small muted" style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 6 }}>
          <li>
            The editor is OnlyOffice Document Server Community Edition, a HardyOS-managed app that listens on this server only. Browsers reach it through
            HardyOS, never directly.
          </li>
          <li>Files are read and saved as the person who opened them, so folder permissions apply. A save is written as the last person who changed the file.</li>
          <li>
            Older versions come from the folder's snapshots (Previous versions in the File Manager). If a file is changed somewhere else while it's open, the
            editor's save goes next to it as “name (edited by …)” instead of over it.
          </li>
          <li>Share links can let people without an account view or edit a document in their browser, with the usual password, expiry and audit.</li>
          <li>Plugins and macros are turned off. Every opening and save is in the audit log (Control Panel › Security).</li>
        </ul>
      </Card>
    </>
  );
}

function OnOff({ st, busy, onJob }: { st: OfficeStatus; busy: boolean; onJob: (id: string) => void }) {
  const qc = useQueryClient();
  const needsPool = !st.installed && !st.enginePool;
  const [pool, setPool] = useState(st.pools?.[0] ?? "");
  const [confirm, setConfirm] = useState(false);
  const enable = useMutation({
    mutationFn: () => unwrap(api.POST("/office/enable", { body: needsPool ? { pool } : {} })),
    onSuccess: (r) => onJob(r.job.id),
  });
  const disable = useMutation({
    mutationFn: (force: boolean) => unwrap(api.POST("/office/disable", { body: { confirm: force } })),
    onSuccess: (r) => {
      setConfirm(false);
      onJob(r.job.id);
      void qc.invalidateQueries({ queryKey: officeKey });
    },
    onError: (err) => {
      if (err instanceof ApiFailure && err.code === "confirm_required") setConfirm(true);
      else toast("error", "Couldn't turn the office suite off", errorMessage(err));
    },
  });

  if (!st.enabled)
    return (
      <Card title="Turn on">
        <p className="small muted">
          Installs the Document Server ({st.version || "OnlyOffice 9.4"}, about 1.5 GB to download, 4 GB of memory recommended) and starts it. It takes a few
          minutes the first time.
        </p>
        {needsPool && (
          <Field label="Pool for apps" hint="No app is installed yet: Docker and every app go on this pool.">
            {(id) => (
              <Select id={id} value={pool} onChange={(e) => setPool(e.target.value)}>
                {(st.pools ?? []).map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        {needsPool && (st.pools ?? []).length === 0 && <Alert tone="warn">Make a storage pool first (Storage Manager).</Alert>}
        {enable.error != null && <Alert tone="bad">{errorMessage(enable.error)}</Alert>}
        <div className="row">
          <Button variant="primary" busy={enable.isPending} disabled={busy || (needsPool && !pool)} onClick={() => enable.mutate()}>
            Turn on the office suite
          </Button>
        </div>
      </Card>
    );
  return (
    <Card title="Document Server">
      <div className="grid-3">
        <Stat label="State" value={st.ready ? "Running" : st.appState || "Not answering"} tone={st.ready ? "good" : "warn"} />
        <Stat label="Version" value={st.version || "–"} />
        <Stat label="Editor address" value={st.listeners ? `port ${st.listeners.officePort}` : "–"} sub={st.listeners?.office ? "listening" : "not listening"} />
      </div>
      {st.problem && <Alert tone="warn">{st.problem}</Alert>}
      {confirm && (
        <Alert
          tone="warn"
          title="People are editing documents"
          action={
            <Button size="sm" variant="danger" busy={disable.isPending} onClick={() => disable.mutate(true)}>
              Turn off anyway
            </Button>
          }
        >
          {st.activeEditors} {st.activeEditors === 1 ? "person is" : "people are"} editing now. Turning the office suite off loses what they haven't saved.
        </Alert>
      )}
      <div className="row">
        <Button busy={disable.isPending} disabled={busy} onClick={() => disable.mutate(false)}>
          Turn off
        </Button>
        <Button variant="ghost" disabled={busy} onClick={() => api.POST("/office/enable", { body: {} }).then((r) => r.data && onJob(r.data.job.id))}>
          Restart and reapply
        </Button>
      </div>
      <p className="small muted">Turning it off stops the Document Server; its data stays. Updates and logs are in the App Store.</p>
    </Card>
  );
}

function Usage({ st }: { st: OfficeStatus }) {
  const pct = Math.min(100, (st.activeEditors / Math.max(1, st.editorLimit)) * 100);
  return (
    <Card title="Who's editing">
      <p className="mono" style={{ margin: "0 0 6px" }}>{`${st.activeEditors} of ${st.editorLimit} editing now`}</p>
      <Progress
        value={pct}
        tone={st.activeEditors >= st.editorLimit ? "bad" : pct >= 75 ? "warn" : "accent"}
        label={`${st.activeEditors} of ${st.editorLimit} editors`}
      />
      <p className="small muted">
        The free Community Edition allows {st.editorLimit} people editing at the same time across all documents. Past that, documents open read only until
        someone closes theirs.
      </p>
      {(st.sessions ?? []).length === 0 ? (
        <p className="small muted">No documents are open.</p>
      ) : (
        <div className="table-wrap"><table className="table">
          <thead>
            <tr>
              <th>Document</th>
              <th>People in it</th>
              <th>Opened</th>
              <th className="num">Saves</th>
            </tr>
          </thead>
          <tbody>
            {(st.sessions ?? []).map((s) => (
              <tr key={`${s.place}:${s.path}`}>
                <td>
                  <span className="mono small">{s.place}</span> / {s.path}
                  {s.state === "error" && <div className="small" style={{ color: "var(--hos-bad)" }}>{s.error}</div>}
                </td>
                <td>{s.editors.length ? s.editors.join(", ") : <span className="muted">nobody now</span>}</td>
                <td className="small muted">{relativeTime(s.opened)}</td>
                <td className="num mono">{s.saves}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}
    </Card>
  );
}

function Settings({ st, busy, onJob }: { st: OfficeStatus; busy: boolean; onJob: (id: string) => void }) {
  const [maxMB, setMaxMB] = useState(String(st.settings?.maxFileMB ?? st.maxFileMB));
  const [fonts, setFonts] = useState(st.settings?.fontsShare ?? "");
  const n = Number(maxMB);
  const problem = !Number.isInteger(n) || n < 1 || n > 1000 ? "A whole number from 1 to 1000." : null;
  const changed = n !== (st.settings?.maxFileMB ?? st.maxFileMB) || fonts !== (st.settings?.fontsShare ?? "");
  const save = useMutation({
    mutationFn: () => unwrap(api.PUT("/office/settings", { body: { maxFileMB: n, fontsShare: fonts } })),
    onSuccess: (r) => onJob(r.job.id),
  });
  return (
    <Card title="Settings">
      <div className="stack">
        <Field label="Largest document (MB)" error={problem} hint="Bigger files download instead of opening in the editor.">
          {(id) => <TextInput id={id} inputMode="numeric" value={maxMB} onChange={(e) => setMaxMB(e.target.value)} />}
        </Field>
        <Field label="Extra fonts" hint="A shared folder with .ttf, .otf or .ttc files; the editors get them (read only). The Document Server restarts to read them.">
          {(id) => (
            <Select id={id} value={fonts} onChange={(e) => setFonts(e.target.value)}>
              <option value="">None (the built-in fonts)</option>
              {(st.fontsChoices ?? []).map((f) => (
                <option key={f.id} value={f.id}>
                  {f.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {save.error != null && <Alert tone="bad">{errorMessage(save.error)}</Alert>}
        <div className="row">
          <Button variant="primary" busy={save.isPending} disabled={busy || !!problem || !changed} onClick={() => save.mutate()}>
            Save
          </Button>
        </div>
      </div>
    </Card>
  );
}
