import type { AppConfig, AppConfigUpdate, AppEntryGrant, AppGrantsNeeded, AppShareChoice, InstalledApp, Job } from "@hardy/api-client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { dateTime, relativeTime } from "../../format";
import { ExternalIcon, PlayIcon, RefreshIcon, RestartIcon, StopIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, ErrorBox, Loading, PageHeader } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { JobProgress } from "../shared";
import { openInNewTab } from "./AppFrame";
import { STATE, SourceBadge, appNotes, isRunning, jobSnapshot } from "./common";
import { PortFields, SettingField, portProblem } from "./InstallDialog";
import {
  AccessEditor,
  type AccessDraft,
  GrantChecks,
  LimitsFields,
  SharesPicker,
  accessDraft,
  accessProblem,
  accessValue,
  limitsDraft,
  limitsProblem,
  limitsValue,
} from "./parts";

type Tab = "overview" | "settings" | "access" | "snapshots" | "logs";
const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "settings", label: "Settings" },
  { id: "access", label: "Who can use it" },
  { id: "snapshots", label: "Snapshots" },
  { id: "logs", label: "Logs" },
];

type OpenApp = (app: Pick<InstalledApp, "id" | "name">) => void;

export function AppDetails({ app, update, onBack, onRemove, onOpen }: { app: InstalledApp; update?: string; onBack: () => void; onRemove: () => void; onOpen: OpenApp }) {
  const [tab, setTab] = useState<Tab>("overview");
  const st = STATE[app.state] ?? { tone: "neutral" as const, label: app.state };
  return (
    <>
      <PageHeader
        title={app.name}
        subtitle={
          <span className="row" style={{ gap: 6 }}>
            <span className="mono">{app.version}</span>
            {app.publisher && <span>· {app.publisher}</span>}
            <SourceBadge source={app.source} sourceName={app.sourceName} />
            {app.source === "imported" && app.sourceName && <span>from {app.sourceName}</span>}
          </span>
        }
        badge={<Badge tone={st.tone}>{st.label}</Badge>}
        actions={<Button size="sm" variant="ghost" onClick={onBack}>All apps</Button>}
      />
      <div className="stack">
        <div className="tabs" role="tablist" aria-label={`${app.name} sections`}>
          {TABS.map((t) => (
            <button key={t.id} type="button" role="tab" className="tabs__tab" aria-selected={tab === t.id} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </div>
        {tab === "overview" && <Overview app={app} update={update} onRemove={onRemove} onRollback={() => setTab("snapshots")} onOpen={onOpen} />}
        {tab === "settings" && <SettingsTab app={app} />}
        {tab === "access" && <AccessTab app={app} />}
        {tab === "snapshots" && <SnapshotsTab app={app} />}
        {tab === "logs" && <LogsView app={app} />}
      </div>
    </>
  );
}

// ---- overview ---------------------------------------------------------------

function Overview({ app, update, onRemove, onRollback, onOpen: openApp }: { app: InstalledApp; update?: string; onRemove: () => void; onRollback: () => void; onOpen: OpenApp }) {
  const qc = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);
  const [job, setJob] = useState<string | null>(null);
  const [failedSnapshot, setFailedSnapshot] = useState<string | null>(null);
  const [needGrants, setNeedGrants] = useState<AppEntryGrant[] | null>(null);
  const running = isRunning(app);

  async function act(action: "start" | "stop" | "restart") {
    setBusy(action);
    try {
      await unwrap(api.POST("/apps/{id}/{action}", { params: { path: { id: app.id, action } } }));
      await qc.invalidateQueries({ queryKey: ["apps"] });
    } catch (err) {
      toast("error", `Couldn't ${action} ${app.name}`, errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  async function runUpdate(grants?: string[]) {
    setBusy("update");
    setFailedSnapshot(null);
    try {
      const r = await api.POST("/apps/{id}/update", { params: { path: { id: app.id } }, body: grants ? { grants } : undefined });
      if (r.error && r.error.code === "grants_required") {
        setNeedGrants((r.error as AppGrantsNeeded).grants ?? []);
        return;
      }
      const ok = await unwrap(Promise.resolve(r));
      setJob(ok.job.id);
    } catch (err) {
      toast("error", `Couldn't update ${app.name}`, errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  function jobDone(j: Job) {
    void qc.invalidateQueries({ queryKey: ["apps"] });
    if (j.state === "succeeded") {
      toast("success", j.title, appNotes(j));
      setJob(null);
    } else {
      setFailedSnapshot(jobSnapshot(j) ?? null);
    }
  }

  return (
    <div className="stack">
      <div className="row app-details__actions">
        {app.web && (
          <>
            <Button variant="primary" disabled={!running} onClick={() => openApp(app)}>
              Open
            </Button>
            <Button onClick={() => openInNewTab(app.id, app.name)} disabled={!running}>
              <ExternalIcon size={14} /> Open in new tab
            </Button>
          </>
        )}
        {running ? (
          <Button onClick={() => act("stop")} busy={busy === "stop"} disabled={!!job}>
            <StopIcon size={13} /> Stop
          </Button>
        ) : (
          <Button onClick={() => act("start")} busy={busy === "start"} disabled={!!job}>
            <PlayIcon size={13} /> Start
          </Button>
        )}
        {running && (
          <Button onClick={() => act("restart")} busy={busy === "restart"} disabled={!!job}>
            <RestartIcon size={14} /> Restart
          </Button>
        )}
        <span className="app-card__spacer" />
        <Button variant="ghost" onClick={onRemove} disabled={!!job}>
          <TrashIcon size={14} /> Remove
        </Button>
      </div>

      {update && !job && (
        <Alert
          tone="info"
          title={`Version ${update} is available`}
          action={
            <Button size="sm" variant="primary" busy={busy === "update"} onClick={() => runUpdate()}>
              Update
            </Button>
          }
        >
          A snapshot of {app.name} is taken first, so you can roll back if the new version misbehaves. Its data, settings and passwords are kept.
        </Alert>
      )}
      {job && <JobProgress id={job} onDone={jobDone} />}
      {failedSnapshot && (
        <Alert
          tone="warn"
          title="The update didn't finish"
          action={
            <Button size="sm" onClick={onRollback}>
              Roll back…
            </Button>
          }
        >
          A snapshot was taken first (<span className="mono">{failedSnapshot}</span>). Roll back to it to put {app.name} back as it was.
        </Alert>
      )}

      <section className="card">
        <dl className="app-details__facts">
          {app.ports.map((p) => (
            <div key={p.name}>
              <dt>{p.label}</dt>
              <dd className="mono">
                {p.port}/{p.protocol}
              </dd>
            </div>
          ))}
          <div>
            <dt>Shared folders</dt>
            <dd>
              {app.shares.filter((s) => s.share).length === 0
                ? "None"
                : app.shares
                    .filter((s) => s.share)
                    .map((s) => (
                      <div key={s.name}>
                        {s.label}: <span className="mono">{s.share}{s.path ? `/${s.path}` : ""}</span> <span className="muted">({s.access === "write" ? "read and write" : "read only"})</span>
                      </div>
                    ))}
            </dd>
          </div>
          <div>
            <dt>Extra permissions</dt>
            <dd>{app.permissions.length === 0 ? "None" : app.permissions.join("; ")}</dd>
          </div>
          <div>
            <dt>Limits</dt>
            <dd>
              {app.limits.memoryMB > 0 ? <span className="mono">{app.limits.memoryMB} MB</span> : "No memory limit"},{" "}
              {app.limits.cpus > 0 ? <span className="mono">{app.limits.cpus} CPUs</span> : "no CPU limit"}
            </dd>
          </div>
          <div>
            <dt>Runs as</dt>
            <dd className="mono">uid {app.uid || "–"}</dd>
          </div>
          <div>
            <dt>Data</dt>
            <dd className="mono">{app.dataset}</dd>
          </div>
          <div>
            <dt>Installed</dt>
            <dd>{relativeTime(app.installedAt)}</dd>
          </div>
        </dl>
        {app.containers.length > 0 && (
          <ul className="app-card__containers small">
            {app.containers.map((c) => (
              <li key={c.service}>
                <span className="mono">{c.service}</span> <span className="muted">{c.status || c.state}</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {needGrants && (
        <GrantsDialog
          app={app}
          grants={needGrants}
          onClose={() => setNeedGrants(null)}
          onAllow={(chosen) => {
            setNeedGrants(null);
            void runUpdate([...new Set([...app.grants, ...chosen])]);
          }}
        />
      )}
    </div>
  );
}

function GrantsDialog({ app, grants, onClose, onAllow }: { app: InstalledApp; grants: AppEntryGrant[]; onClose: () => void; onAllow: (g: string[]) => void }) {
  const [chosen, setChosen] = useState<string[]>([]);
  const ready = grants.every((g) => chosen.includes(g.grant));
  return (
    <Dialog
      title={`The new ${app.name} asks for more`}
      onClose={onClose}
      onSubmit={() => ready && onAllow(chosen)}
      width={560}
      footer={
        <>
          <Button onClick={onClose}>Don't update</Button>
          <Button type="submit" variant="danger" disabled={!ready}>
            Allow and update
          </Button>
        </>
      }
    >
      <GrantChecks grants={grants} value={chosen} onChange={setChosen} name={app.name} />
    </Dialog>
  );
}

// ---- settings -----------------------------------------------------------------

function SettingsTab({ app }: { app: InstalledApp }) {
  const q = useQuery({ queryKey: ["apps", app.id, "config"], queryFn: () => unwrap(api.GET("/apps/{id}/config", { params: { path: { id: app.id } } })) });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  return <SettingsForm app={app} config={q.data} />;
}

function SettingsForm({ app, config }: { app: InstalledApp; config: AppConfig }) {
  const qc = useQueryClient();
  const pkg = config.package;
  const initialPorts = Object.fromEntries(pkg.ports.map((p) => [p.name, String(config.ports[p.name] ?? p.default)]));
  const current = Object.fromEntries(config.settings.map((s) => [s.env, s]));
  const initialSettings = Object.fromEntries(pkg.settings.map((s) => [s.env, s.type === "password" ? "" : (current[s.env]?.value ?? "")]));
  const initialShares: Record<string, AppShareChoice> = Object.fromEntries(
    pkg.shares.map((m) => {
      const cur = config.shares.find((s) => s.name === m.name);
      return [m.name, { share: cur?.share ?? "", path: cur?.path ?? "", access: (cur?.access as "read" | "write" | undefined) || m.access }];
    }),
  );
  const [ports, setPorts] = useState(initialPorts);
  const [settings, setSettings] = useState(initialSettings);
  const [shares, setShares] = useState(initialShares);
  const [grants, setGrants] = useState<string[]>(config.grants);
  const [limits, setLimits] = useState(limitsDraft(config.limits));
  const [busy, setBusy] = useState(false);
  const [job, setJob] = useState<string | null>(null);
  const [problems, setProblems] = useState<string[]>([]);
  const catalog = config.source === "catalog";

  const change: AppConfigUpdate = {};
  const portChanges = Object.fromEntries(Object.entries(ports).filter(([k, v]) => v !== initialPorts[k]).map(([k, v]) => [k, Number(v)]));
  if (Object.keys(portChanges).length > 0) change.ports = portChanges;
  const settingChanges = Object.fromEntries(Object.entries(settings).filter(([k, v]) => v !== initialSettings[k]));
  if (Object.keys(settingChanges).length > 0) change.settings = settingChanges;
  const shareChanges = Object.fromEntries(Object.entries(shares).filter(([k, v]) => JSON.stringify(v) !== JSON.stringify(initialShares[k])));
  if (Object.keys(shareChanges).length > 0) change.shares = shareChanges;
  if (!catalog && [...grants].sort().join() !== [...config.grants].sort().join()) change.grants = grants;
  const lv = limitsValue(limits);
  if (lv.memoryMB !== config.limits.memoryMB || lv.cpus !== config.limits.cpus) change.limits = lv;
  const changed = Object.keys(change).length > 0;
  const ready =
    changed &&
    !limitsProblem(limits) &&
    (pkg.fixedPorts || Object.values(ports).every((v) => !portProblem(v))) &&
    pkg.shares.every((m) => !m.required || !!shares[m.name]?.share) &&
    (catalog || pkg.grants.every((g) => grants.includes(g.grant)));

  async function save() {
    if (!ready) return;
    setBusy(true);
    setProblems([]);
    try {
      const r = await unwrap(api.PATCH("/apps/{id}/config", { params: { path: { id: app.id } }, body: change }));
      setJob(r.job.id);
    } catch (err) {
      setProblems(err instanceof ApiFailure && err.details.length > 0 ? err.details : [errorMessage(err)]);
    } finally {
      setBusy(false);
    }
  }

  if (job) {
    return (
      <JobProgress
        id={job}
        onDone={(j) => {
          void qc.invalidateQueries({ queryKey: ["apps"] });
          if (j.state === "succeeded") toast("success", `${app.name} uses its new settings`, appNotes(j));
        }}
      />
    );
  }

  return (
    <form
      className="stack"
      onSubmit={(e) => {
        e.preventDefault();
        void save();
      }}
    >
      <p className="small muted" style={{ margin: 0 }}>
        Saving restarts {app.name} with the new settings. Leave a password empty to keep it.
      </p>
      {pkg.ports.length > 0 && <PortFields pkg={pkg} ports={ports} setPorts={setPorts} />}
      {pkg.settings.map((s) => (
        <SettingField key={s.env} setting={s} value={settings[s.env] ?? ""} keep={false} editing isSet={current[s.env]?.set} onChange={(v) => setSettings({ ...settings, [s.env]: v })} />
      ))}
      {pkg.shares.length > 0 && (
        <section className="stack" aria-label="Shared folders">
          <h3 className="card__title">Shared folders</h3>
          <SharesPicker mounts={pkg.shares} value={shares} onChange={setShares} />
        </section>
      )}
      {!catalog && pkg.grants.length > 0 && <GrantChecks grants={pkg.grants} value={grants} onChange={setGrants} name={app.name} />}
      <section className="stack" aria-label="Resource limits">
        <h3 className="card__title">Resource limits</h3>
        <LimitsFields value={limits} onChange={setLimits} />
      </section>
      {problems.length > 0 && (
        <Alert tone="bad" title="Can't save yet">
          <ul className="install__problems">
            {problems.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </Alert>
      )}
      <div className="row">
        <Button type="submit" variant="primary" disabled={!ready} busy={busy}>
          Save and restart
        </Button>
      </div>
    </form>
  );
}

// ---- access -------------------------------------------------------------------

function AccessTab({ app }: { app: InstalledApp }) {
  const q = useQuery({ queryKey: ["apps", app.id, "access"], queryFn: () => unwrap(api.GET("/apps/{id}/access", { params: { path: { id: app.id } } })) });
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  return <AccessForm app={app} initial={accessDraft(q.data.principals)} />;
}

function AccessForm({ app, initial }: { app: InstalledApp; initial: AccessDraft }) {
  const qc = useQueryClient();
  const [draft, setDraft] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const changed = JSON.stringify(accessValue(draft)) !== JSON.stringify(accessValue(initial));

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await unwrap(api.PUT("/apps/{id}/access", { params: { path: { id: app.id } }, body: { principals: accessValue(draft) } }));
      await qc.invalidateQueries({ queryKey: ["apps", app.id, "access"] });
      toast("success", `Saved who can use ${app.name}`);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card stack">
      <p className="small muted" style={{ margin: 0 }}>
        People who can use {app.name} see it in their App Store and can open it. Only administrators can change it.
      </p>
      <AccessEditor draft={draft} onChange={setDraft} />
      {error && <Alert tone="bad">{error}</Alert>}
      <div className="row">
        <Button variant="primary" disabled={!changed || !!accessProblem(draft)} busy={busy} onClick={save}>
          Save
        </Button>
      </div>
    </section>
  );
}

// ---- snapshots ----------------------------------------------------------------

function SnapshotsTab({ app }: { app: InstalledApp }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["apps", app.id, "snapshots"], queryFn: () => unwrap(api.GET("/apps/{id}/snapshots", { params: { path: { id: app.id } } })) });
  const [rolling, setRolling] = useState<string | null>(null);
  const [job, setJob] = useState<string | null>(null);
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const list = q.data.snapshots;
  return (
    <section className="card stack">
      <p className="small muted" style={{ margin: 0 }}>
        HardyOS takes a snapshot of {app.name} before every update and keeps the last three. Rolling back puts its data, settings and version back as
        they were then; anything changed since is lost.
      </p>
      {job && <JobProgress id={job} onDone={() => { void qc.invalidateQueries({ queryKey: ["apps"] }); void q.refetch(); }} />}
      {list.length === 0 ? (
        <p className="small muted">No snapshots yet.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Snapshot</th>
                <th>Taken</th>
                <th>Version</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.map((s) => (
                <tr key={s.name}>
                  <td className="mono small">{s.name}</td>
                  <td>{s.created ? dateTime(s.created) : "–"}</td>
                  <td className="mono">{s.version || "–"}</td>
                  <td className="actions">
                    <Button size="sm" onClick={() => setRolling(s.name)} disabled={!!job}>
                      Roll back
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {rolling && (
        <ConfirmDialog
          title={`Roll ${app.name} back?`}
          confirmLabel="Roll back"
          typeToConfirm={app.name}
          onClose={() => setRolling(null)}
          onConfirm={async () => {
            const r = await unwrap(api.POST("/apps/{id}/rollback", { params: { path: { id: app.id } }, body: { snapshot: rolling, confirm: app.name } }));
            setJob(r.job.id);
          }}
        >
          {app.name} stops and goes back to <span className="mono">{rolling}</span>. Anything it saved since then is lost.
        </ConfirmDialog>
      )}
    </section>
  );
}

// ---- logs -----------------------------------------------------------------------

export function LogsView({ app }: { app: Pick<InstalledApp, "id" | "name"> }) {
  const q = useQuery({
    queryKey: ["apps", app.id, "logs"],
    queryFn: () => unwrap(api.GET("/apps/{id}/logs", { params: { path: { id: app.id }, query: { lines: 500 } } })),
    refetchInterval: 5_000,
  });
  return (
    <div className="stack">
      <div className="row row--between">
        <span className="small muted">The last 500 lines from every container, newest at the bottom.</span>
        <Button size="sm" onClick={() => q.refetch()} busy={q.isFetching}>
          <RefreshIcon size={14} /> Refresh
        </Button>
      </div>
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : (
        <pre className="log-view" tabIndex={0} aria-label={`${app.name} logs`}>
          {q.data.logs || "Nothing logged yet."}
        </pre>
      )}
    </div>
  );
}

