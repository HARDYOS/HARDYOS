import type { AppPackage, AppPackageRef, AppPlan, AppsOverview, InstalledApp, Job } from "@hardy/api-client";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, useRef, useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { relativeTime } from "../../format";
import { AlertIcon, BagIcon, GridIcon, LayersIcon, PlayIcon, PlusIcon, RefreshIcon, RestartIcon, StopIcon, TrashIcon, UploadIcon } from "../../icons";
import { type AppProps, useShell } from "../../shell";
import {
  Alert,
  AppLayout,
  Badge,
  Button,
  EmptyState,
  ErrorBox,
  Field,
  Loading,
  type NavItem,
  PageHeader,
  Select,
  SideNav,
  TextInput,
  Toggle,
  type Tone,
} from "../../ui";
import { Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { JobProgress } from "../shared";

export const useApps = () =>
  useQuery({
    queryKey: ["apps"],
    queryFn: () => unwrap(api.GET("/apps")),
    refetchInterval: (q) => (q.state.data?.apps.some((a) => a.state === "starting" || a.state === "restarting") ? 3_000 : 15_000),
  });

const useCatalog = (enabled: boolean) =>
  useQuery({ queryKey: ["apps", "catalog"], queryFn: () => unwrap(api.GET("/apps/catalog")), enabled, staleTime: 60_000 });

const STATE: Record<InstalledApp["state"], { tone: Tone; label: string }> = {
  running: { tone: "good", label: "Running" },
  starting: { tone: "accent", label: "Starting" },
  restarting: { tone: "warn", label: "Restarting" },
  unhealthy: { tone: "bad", label: "Unhealthy" },
  partial: { tone: "warn", label: "Partly running" },
  stopped: { tone: "neutral", label: "Stopped" },
  "not-created": { tone: "neutral", label: "Not started" },
};

/** The address of an app's web page, on the host the desktop was opened at. */
export function appUrl(app: Pick<InstalledApp, "web">, hostname = window.location.hostname): string | null {
  if (!app.web) return null;
  return `${app.web.scheme}://${hostname}:${app.web.port}${app.web.path}`;
}

type Section = "installed" | "discover";

export default function AppStore(_: AppProps) {
  const { user } = useShell();
  return <AppStoreView isAdmin={user.role === "admin"} />;
}

export function AppStoreView({ isAdmin }: { isAdmin: boolean }) {
  const [section, setSection] = useState<Section>("installed");
  const [installing, setInstalling] = useState<AppPackageRef | null>(null);
  const apps = useApps();
  const updates = Object.keys(apps.data?.updates ?? {}).length;

  const items: NavItem[] = [
    {
      id: "installed",
      label: "My apps",
      icon: <GridIcon size={16} />,
      badge: updates > 0 ? <Badge tone="accent">{updates}</Badge> : undefined,
    },
    ...(isAdmin ? [{ id: "discover", label: "Discover", icon: <BagIcon size={16} /> }] : []),
  ];

  return (
    <AppLayout
      nav={
        <SideNav
          label="App Store sections"
          items={items}
          active={section}
          onSelect={(s) => setSection(s as Section)}
          footer={isAdmin ? <UploadButton onUploaded={(ref) => setInstalling(ref)} /> : undefined}
        />
      }
    >
      {section === "installed" && <Installed isAdmin={isAdmin} onDiscover={() => setSection("discover")} />}
      {section === "discover" && isAdmin && <Discover overview={apps.data} onInstall={setInstalling} />}
      {installing && (
        <InstallDialog
          pkgRef={installing}
          onClose={() => setInstalling(null)}
          onInstalled={() => {
            setInstalling(null);
            setSection("installed");
          }}
        />
      )}
    </AppLayout>
  );
}

// ---- installed -----------------------------------------------------------

function EngineBanner({ o, isAdmin }: { o: AppsOverview; isAdmin: boolean }) {
  if (!o.available)
    return (
      <Alert tone="warn" title="Apps aren't available in this build">
        This HardyOS build doesn't include Docker. Install the latest update to get one-click apps.
      </Alert>
    );
  if (o.problem && isAdmin) return <Alert tone="bad" title="Apps can't run right now">{o.problem}</Alert>;
  return null;
}

function Installed({ isAdmin, onDiscover }: { isAdmin: boolean; onDiscover: () => void }) {
  const q = useApps();
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const o = q.data;
  return (
    <>
      <PageHeader
        title="My apps"
        subtitle={
          isAdmin
            ? o.configured
              ? <>Apps run in Docker on <span className="mono">{o.pool}</span>{o.engineVersion && <> (Docker {o.engineVersion})</>}, each in its own dataset you can snapshot.</>
              : "One-click apps run in Docker on one of your pools. Pick one from Discover to get started."
            : "Apps your family's server runs. Open one to use it."
        }
        actions={isAdmin && <Button variant="primary" onClick={onDiscover}><PlusIcon size={15} /> Get apps</Button>}
      />
      <div className="stack">
        <EngineBanner o={o} isAdmin={isAdmin} />
        {o.apps.length === 0 ? (
          <EmptyState icon={<BagIcon size={28} />} title="No apps yet" action={isAdmin ? <Button variant="primary" onClick={onDiscover}>Browse apps</Button> : undefined}>
            {isAdmin ? "Install a family video site, photo backup and more with one click." : "An administrator can install apps from the App Store."}
          </EmptyState>
        ) : (
          <div className="app-grid">
            {o.apps.map((a) => (
              <AppCard key={a.id} app={a} update={o.updates[a.id]} isAdmin={isAdmin} />
            ))}
          </div>
        )}
        {isAdmin && o.keptData.length > 0 && <KeptData o={o} />}
      </div>
    </>
  );
}

function AppIcon({ src, name, size = 48 }: { src: string; name: string; size?: number }) {
  return src ? (
    <img className="app-icon" src={src} alt="" width={size} height={size} />
  ) : (
    <span className="app-icon app-icon--blank" style={{ width: size, height: size }} aria-hidden="true">
      {name.slice(0, 1)}
    </span>
  );
}

function AppCard({ app, update, isAdmin }: { app: InstalledApp; update?: string; isAdmin: boolean }) {
  const qc = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);
  const [job, setJob] = useState<string | null>(null);
  const [dialog, setDialog] = useState<"logs" | "remove" | null>(null);
  const st = STATE[app.state] ?? { tone: "neutral" as Tone, label: app.state };
  const url = appUrl(app);
  const running = app.state === "running" || app.state === "starting" || app.state === "unhealthy" || app.state === "partial";

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

  async function runUpdate() {
    setBusy("update");
    try {
      const r = await unwrap(api.POST("/apps/{id}/update", { params: { path: { id: app.id } } }));
      setJob(r.job.id);
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
    }
  }

  return (
    <article className="app-card" aria-label={app.name}>
      <header className="app-card__head">
        <AppIcon src={app.icon} name={app.name} />
        <div className="app-card__title">
          <h3>{app.name}</h3>
          <span className="small muted">
            <span className="mono">{app.version}</span>
            {app.publisher && <> · {app.publisher}</>}
          </span>
        </div>
        <Badge tone={st.tone}>{st.label}</Badge>
      </header>
      {app.summary && <p className="app-card__summary">{app.summary}</p>}
      {isAdmin && (
        <dl className="app-card__facts small">
          {app.ports.map((p) => (
            <div key={p.name}>
              <dt>{p.label}</dt>
              <dd className="mono">
                {p.port}/{p.protocol}
              </dd>
            </div>
          ))}
          <div>
            <dt>Installed</dt>
            <dd>{relativeTime(app.installedAt)}</dd>
          </div>
        </dl>
      )}
      {isAdmin && app.containers.length > 0 && app.state !== "running" && (
        <ul className="app-card__containers small">
          {app.containers.map((c) => (
            <li key={c.service}>
              <span className="mono">{c.service}</span> <span className="muted">{c.status || c.state}</span>
            </li>
          ))}
        </ul>
      )}
      {update && !job && (
        <Alert tone="info" title={`Version ${update} is available`} action={<Button size="sm" variant="primary" busy={busy === "update"} onClick={runUpdate}>Update</Button>}>
          Updating keeps {app.name}'s data, settings and passwords.
        </Alert>
      )}
      {job && <JobProgress id={job} onDone={jobDone} />}
      <footer className="app-card__actions">
        {url && (
          <a className={`btn btn--md ${running ? "btn--primary" : "btn--secondary"}`} href={url} target="_blank" rel="noopener noreferrer" aria-disabled={!running || undefined}>
            Open
          </a>
        )}
        {isAdmin && (
          <>
            {running ? (
              <Button size="sm" onClick={() => act("stop")} busy={busy === "stop"} disabled={!!job}>
                <StopIcon size={13} /> Stop
              </Button>
            ) : (
              <Button size="sm" onClick={() => act("start")} busy={busy === "start"} disabled={!!job}>
                <PlayIcon size={13} /> Start
              </Button>
            )}
            {running && (
              <Button size="sm" variant="ghost" onClick={() => act("restart")} busy={busy === "restart"} disabled={!!job} aria-label={`Restart ${app.name}`} title="Restart">
                <RestartIcon size={14} />
              </Button>
            )}
            <Button size="sm" variant="ghost" onClick={() => setDialog("logs")}>
              <LayersIcon size={14} /> Logs
            </Button>
            <span className="app-card__spacer" />
            <Button size="sm" variant="ghost" onClick={() => setDialog("remove")} disabled={!!job} aria-label={`Remove ${app.name}`}>
              <TrashIcon size={14} />
            </Button>
          </>
        )}
      </footer>
      {dialog === "logs" && <LogsDialog app={app} onClose={() => setDialog(null)} />}
      {dialog === "remove" && <RemoveDialog id={app.id} name={app.name} onClose={() => setDialog(null)} onStarted={setJob} />}
    </article>
  );
}

/** Notes from an install job (for example, an image that couldn't be refreshed). */
function appNotes(j: Job): string | undefined {
  const notes = (j.result as { notes?: string[] } | null | undefined)?.notes;
  return notes && notes.length > 0 ? notes.join(" ") : undefined;
}

function KeptData({ o }: { o: AppsOverview }) {
  const [removing, setRemoving] = useState<{ id: string; name: string } | null>(null);
  const [job, setJob] = useState<string | null>(null);
  const qc = useQueryClient();
  return (
    <section className="card">
      <header className="card__head">
        <h2 className="card__title">Kept app data</h2>
      </header>
      <p className="small muted" style={{ margin: 0 }}>
        These apps were removed but their data was kept. Installing one again picks its data and passwords back up.
      </p>
      <div className="table-wrap">
        <table className="table">
          <tbody>
            {o.keptData.map((k) => (
              <tr key={k.id}>
                <td>{k.name}</td>
                <td className="mono small muted">{k.dataset}</td>
                <td className="actions">
                  <Button size="sm" variant="ghost" onClick={() => setRemoving(k)}>
                    <TrashIcon size={14} /> Delete data
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {job && <JobProgress id={job} onDone={() => { void qc.invalidateQueries({ queryKey: ["apps"] }); }} />}
      {removing && <RemoveDialog id={removing.id} name={removing.name} keptOnly onClose={() => setRemoving(null)} onStarted={setJob} />}
    </section>
  );
}

function LogsDialog({ app, onClose }: { app: InstalledApp; onClose: () => void }) {
  const q = useQuery({
    queryKey: ["apps", app.id, "logs"],
    queryFn: () => unwrap(api.GET("/apps/{id}/logs", { params: { path: { id: app.id }, query: { lines: 500 } } })),
    refetchInterval: 5_000,
  });
  return (
    <Dialog
      title={`${app.name} logs`}
      description="The last 500 lines from every container, newest at the bottom."
      onClose={onClose}
      width={860}
      footer={
        <>
          <Button onClick={() => q.refetch()} busy={q.isFetching}>
            <RefreshIcon size={14} /> Refresh
          </Button>
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        </>
      }
    >
      {q.isPending ? (
        <Loading />
      ) : q.isError ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : (
        <pre className="log-view" tabIndex={0} aria-label={`${app.name} logs`}>
          {q.data.logs || "Nothing logged yet."}
        </pre>
      )}
    </Dialog>
  );
}

function RemoveDialog({
  id,
  name,
  keptOnly,
  onClose,
  onStarted,
}: {
  id: string;
  name: string;
  keptOnly?: boolean;
  onClose: () => void;
  onStarted: (job: string) => void;
}) {
  const [typed, setTyped] = useState("");
  const [deleteData, setDeleteData] = useState(!!keptOnly);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = typed.trim().toLowerCase() === name.toLowerCase();

  async function run() {
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      const r = await unwrap(api.DELETE("/apps/{id}", { params: { path: { id } }, body: { confirm: typed.trim(), deleteData } }));
      onStarted(r.job.id);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <Dialog
      title={keptOnly ? `Delete ${name}'s data?` : `Remove ${name}?`}
      onClose={onClose}
      onSubmit={run}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="danger" disabled={!ready} busy={busy}>
            {deleteData ? "Remove and delete data" : "Remove"}
          </Button>
        </>
      }
    >
      <div className="stack">
        {keptOnly ? (
          <p className="dialog__text">Every file, database and password {name} kept is deleted. This can't be undone.</p>
        ) : (
          <>
            <p className="dialog__text">
              {name}'s containers are stopped and removed. Its data stays on the pool unless you delete it, so installing it again picks up where it left off.
            </p>
            <Toggle
              label="Also delete its data"
              description="Videos, databases, settings and passwords. Snapshots of the dataset are deleted too. This can't be undone."
              checked={deleteData}
              onChange={setDeleteData}
            />
          </>
        )}
        <Field label={`Type ${name} to confirm`}>
          {(fid) => <TextInput id={fid} value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" spellCheck={false} />}
        </Field>
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
    </Dialog>
  );
}

// ---- discover --------------------------------------------------------------

function Discover({ overview, onInstall }: { overview?: AppsOverview; onInstall: (ref: AppPackageRef) => void }) {
  const q = useCatalog(true);
  const installed = new Map((overview?.apps ?? []).map((a) => [a.id, a.version]));
  return (
    <>
      <PageHeader title="Discover" subtitle="Apps that ship with HardyOS. Each runs in its own containers, with its data in its own dataset." />
      <div className="stack">
        {overview && <EngineBanner o={overview} isAdmin />}
        {q.isPending ? (
          <Loading />
        ) : q.isError ? (
          <ErrorBox error={q.error} onRetry={() => q.refetch()} />
        ) : q.data.length === 0 ? (
          <EmptyState icon={<BagIcon size={28} />} title="The catalog is empty">
            Upload a .hardyapp package to install an app.
          </EmptyState>
        ) : (
          <div className="app-grid">
            {q.data.map((p) => (
              <CatalogCard key={p.id} pkg={p} installedVersion={installed.get(p.id)} onInstall={() => onInstall({ source: "catalog", ref: p.id })} disabled={overview ? !overview.available : false} />
            ))}
          </div>
        )}
      </div>
    </>
  );
}

function CatalogCard({ pkg, installedVersion, onInstall, disabled }: { pkg: AppPackage; installedVersion?: string; onInstall: () => void; disabled: boolean }) {
  return (
    <article className="app-card" aria-label={pkg.name}>
      <header className="app-card__head">
        <AppIcon src={pkg.icon} name={pkg.name} />
        <div className="app-card__title">
          <h3>{pkg.name}</h3>
          <span className="small muted">
            <span className="mono">{pkg.version}</span> · {pkg.publisher}
          </span>
        </div>
        {installedVersion && <Badge tone="good">Installed</Badge>}
      </header>
      <p className="app-card__summary">{pkg.summary}</p>
      {pkg.permissions.length > 0 && (
        <p className="small app-card__perm">
          <AlertIcon size={13} /> Needs extra permissions
        </p>
      )}
      <footer className="app-card__actions">
        <Button variant={installedVersion ? "secondary" : "primary"} size="sm" onClick={onInstall} disabled={disabled}>
          {installedVersion ? "Reinstall…" : "Install"}
        </Button>
        {pkg.website && (
          <a className="btn btn--ghost btn--sm" href={pkg.website} target="_blank" rel="noopener noreferrer">
            Website
          </a>
        )}
      </footer>
    </article>
  );
}

function UploadButton({ onUploaded }: { onUploaded: (ref: AppPackageRef) => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);

  async function onFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setBusy(true);
    try {
      const pkg = await unwrap(
        api.POST("/apps/packages", {
          body: file as unknown as string,
          bodySerializer: (b: unknown) => b as BodyInit,
          headers: { "Content-Type": "application/octet-stream" },
        }),
      );
      onUploaded({ source: "upload", ref: pkg.ref });
    } catch (err) {
      const details = err instanceof ApiFailure && err.details.length > 1 ? err.details.join("; ") : errorMessage(err);
      toast("error", `${file.name} isn't a package HardyOS can install`, details);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="app-upload">
      <input ref={input} type="file" accept=".hardyapp,application/gzip" hidden onChange={onFile} aria-label="App package file" />
      <Button size="sm" variant="ghost" onClick={() => input.current?.click()} busy={busy}>
        <UploadIcon size={14} /> Upload a package
      </Button>
    </div>
  );
}

// ---- install ---------------------------------------------------------------

function InstallDialog({ pkgRef, onClose, onInstalled }: { pkgRef: AppPackageRef; onClose: () => void; onInstalled: () => void }) {
  const qc = useQueryClient();
  const plan = useQuery({
    queryKey: ["apps", "plan", pkgRef.source, pkgRef.ref],
    queryFn: () => unwrap(api.POST("/apps/plan", { body: pkgRef })),
    staleTime: 0,
    gcTime: 0,
  });
  const [job, setJob] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  if (plan.isPending || plan.isError) {
    return (
      <Dialog title="Install an app" onClose={onClose}>
        {plan.isPending ? <Loading label="Checking the package…" /> : <ErrorBox error={plan.error} onRetry={() => plan.refetch()} />}
      </Dialog>
    );
  }
  const p = plan.data;
  const pkg = p.package;

  if (job) {
    return (
      <Dialog
        title={`Installing ${pkg.name}`}
        description="Downloading the app can take a few minutes. You can close this window; the install keeps going."
        onClose={onClose}
        footer={<Button onClick={failed ? () => setJob(null) : onClose}>{failed ? "Back" : "Close"}</Button>}
      >
        <JobProgress
          id={job}
          onDone={(j) => {
            void qc.invalidateQueries({ queryKey: ["apps"] });
            if (j.state === "succeeded") {
              toast("success", `${pkg.name} is ready`, appNotes(j));
              onInstalled();
            } else {
              setFailed(true);
            }
          }}
        />
      </Dialog>
    );
  }
  return <InstallForm plan={p} onClose={onClose} onStarted={setJob} />;
}

function InstallForm({ plan, onClose, onStarted }: { plan: AppPlan; onClose: () => void; onStarted: (job: string) => void }) {
  const pkg = plan.package;
  const [pool, setPool] = useState(plan.enginePool || plan.pools[0] || "");
  const [ports, setPorts] = useState<Record<string, string>>(() =>
    Object.fromEntries(pkg.ports.map((pt) => [pt.name, String(plan.ports[pt.name] ?? pt.default)])),
  );
  // On a reinstall, blank settings keep what the app has now.
  const [settings, setSettings] = useState<Record<string, string>>(() =>
    Object.fromEntries(pkg.settings.map((s) => [s.env, plan.installed || plan.keptData ? "" : s.default])),
  );
  const [busy, setBusy] = useState(false);
  const [problems, setProblems] = useState<string[]>([]);
  const reinstall = plan.installed || plan.keptData;

  const portProblem = (v: string) => {
    const n = Number(v);
    return Number.isInteger(n) && n >= 1024 && n <= 65535 ? null : "Use a port from 1024 to 65535";
  };
  const missing = pkg.settings.filter((s) => s.required && !reinstall && !settings[s.env]?.trim());
  const ready = !!pool && pkg.ports.every((pt) => !portProblem(ports[pt.name] ?? "")) && missing.length === 0;

  async function submit() {
    if (!ready) return;
    setBusy(true);
    setProblems([]);
    try {
      const chosen: Record<string, string> = {};
      for (const s of pkg.settings) {
        const v = settings[s.env] ?? "";
        if (v !== "" || !reinstall) chosen[s.env] = v;
      }
      const r = await unwrap(
        api.POST("/apps/install", {
          body: {
            source: pkg.source,
            ref: pkg.ref,
            pool: plan.enginePool ? undefined : pool,
            ports: Object.fromEntries(Object.entries(ports).map(([k, v]) => [k, Number(v)])),
            settings: chosen,
          },
        }),
      );
      onStarted(r.job.id);
    } catch (err) {
      setProblems(err instanceof ApiFailure && err.details.length > 0 ? err.details : [errorMessage(err)]);
      setBusy(false);
    }
  }

  return (
    <Dialog
      title={reinstall ? `Reinstall ${pkg.name}` : `Install ${pkg.name}`}
      onClose={onClose}
      onSubmit={submit}
      width={600}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={!ready || !plan.available} busy={busy}>
            {reinstall ? "Reinstall" : "Install"}
          </Button>
        </>
      }
    >
      <div className="stack install">
        <div className="install__head">
          <AppIcon src={pkg.icon} name={pkg.name} size={56} />
          <div>
            <div className="install__name">{pkg.name}</div>
            <div className="small muted">
              <span className="mono">{pkg.version}</span> · {pkg.publisher}
              {pkg.source === "upload" && <> · <Badge tone="warn">Uploaded package</Badge></>}
            </div>
          </div>
        </div>
        {pkg.description && <p className="install__desc">{pkg.description}</p>}

        {plan.installed && (
          <Alert tone="info" title={`${pkg.name} ${plan.installedVersion} is installed`}>
            Reinstalling keeps its data and passwords. Leave a setting blank to keep its current value.
          </Alert>
        )}
        {plan.keptData && (
          <Alert tone="info" title="Picks up the data you kept">
            {pkg.name} was removed before with its data kept. Installing it again uses that data and its passwords.
          </Alert>
        )}
        {!plan.available && <Alert tone="warn" title="This build doesn't include Docker" />}
        {plan.problem && <Alert tone="bad" title="Apps can't run right now">{plan.problem}</Alert>}

        <section className="install__section" aria-label="What it can do">
          <h3>What it can do</h3>
          {pkg.permissions.length === 0 ? (
            <p className="small muted">Runs in its own containers. It can only see its own folder, and the ports below.</p>
          ) : (
            <>
              <p className="small muted">Besides its own folder and ports, {pkg.name} asks to:</p>
              <ul className="install__perms">
                {pkg.permissions.map((perm) => (
                  <li key={perm}>
                    <AlertIcon size={13} /> {perm}
                  </li>
                ))}
              </ul>
            </>
          )}
          <p className="small muted">
            Software: {pkg.images.map((img, i) => (
              <span key={img}>
                {i > 0 && ", "}
                <span className="mono">{img}</span>
              </span>
            ))}
          </p>
        </section>

        {!plan.enginePool && (
          <Field label="Pool for apps" hint="Docker and every app keep their data here, in datasets you can snapshot. All apps share this pool.">
            {(fid) =>
              plan.pools.length === 0 ? (
                <Alert tone="warn" title="No pool yet">Create a pool in Storage Manager first.</Alert>
              ) : (
                <Select id={fid} value={pool} onChange={(e) => setPool(e.target.value)}>
                  {plan.pools.map((name) => (
                    <option key={name} value={name}>
                      {name}
                    </option>
                  ))}
                </Select>
              )
            }
          </Field>
        )}

        {pkg.ports.length > 0 && (
          <div className="grid-2">
            {pkg.ports.map((pt) => (
              <Field key={pt.name} label={pt.label} hint={pt.web ? "Where the app's website opens" : `${pt.protocol.toUpperCase()} port on this server`} error={portProblem(ports[pt.name] ?? "")}>
                {(fid) => (
                  <TextInput
                    id={fid}
                    className="input mono"
                    inputMode="numeric"
                    value={ports[pt.name] ?? ""}
                    onChange={(e) => setPorts({ ...ports, [pt.name]: e.target.value.replace(/[^0-9]/g, "") })}
                  />
                )}
              </Field>
            ))}
          </div>
        )}

        {pkg.settings.map((s) => (
          <SettingField key={s.env} setting={s} value={settings[s.env] ?? ""} reinstall={reinstall} onChange={(v) => setSettings({ ...settings, [s.env]: v })} />
        ))}

        {problems.length > 0 && (
          <Alert tone="bad" title={problems.length === 1 ? "Can't install yet" : "Can't install yet:"}>
            {problems.length === 1 ? problems[0] : (
              <ul className="install__problems">
                {problems.map((pr) => (
                  <li key={pr}>{pr}</li>
                ))}
              </ul>
            )}
          </Alert>
        )}
      </div>
    </Dialog>
  );
}

function SettingField({ setting: s, value, reinstall, onChange }: { setting: AppPackage["settings"][number]; value: string; reinstall: boolean; onChange: (v: string) => void }) {
  if (s.type === "boolean" && reinstall) {
    return (
      <Field label={s.label} hint={s.help || undefined}>
        {(fid) => (
          <Select id={fid} value={value} onChange={(e) => onChange(e.target.value)}>
            <option value="">Keep current</option>
            <option value="true">On</option>
            <option value="false">Off</option>
          </Select>
        )}
      </Field>
    );
  }
  if (s.type === "boolean") {
    const on = value === "" ? s.default === "true" : value === "true";
    return <Toggle label={s.label} description={s.help || undefined} checked={on} onChange={(v) => onChange(v ? "true" : "false")} />;
  }
  const keep = reinstall ? "Keep current" : undefined;
  return (
    <Field label={s.required && !reinstall ? s.label : `${s.label}${reinstall ? "" : " (optional)"}`} hint={s.help || undefined}>
      {(fid) =>
        s.type === "select" ? (
          <Select id={fid} value={value} onChange={(e) => onChange(e.target.value)}>
            {reinstall && <option value="">{keep}</option>}
            {s.options.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </Select>
        ) : (
          <TextInput
            id={fid}
            type={s.type === "password" ? "password" : "text"}
            inputMode={s.type === "number" ? "numeric" : undefined}
            className={s.type === "number" ? "input mono" : "input"}
            autoComplete={s.type === "password" ? "new-password" : "off"}
            placeholder={keep}
            value={value}
            onChange={(e) => onChange(s.type === "number" ? e.target.value.replace(/[^0-9.]/g, "") : e.target.value)}
          />
        )
      }
    </Field>
  );
}
