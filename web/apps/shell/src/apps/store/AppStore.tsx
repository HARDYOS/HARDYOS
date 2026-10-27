import type { AppPackage, AppPackageRef, AppPlan, AppsOverview, InstalledApp, Job } from "@hardy/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { type ChangeEvent, useRef, useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { relativeTime } from "../../format";
import { AlertIcon, BagIcon, EditIcon, ExternalIcon, GridIcon, LayersIcon, PlayIcon, PlusIcon, StopIcon, TrashIcon, UploadIcon } from "../../icons";
import { type AppProps, useShell } from "../../shell";
import { Alert, AppLayout, Badge, Button, EmptyState, ErrorBox, Field, Loading, type NavItem, PageHeader, SideNav, TextInput, Toggle, type Tone } from "../../ui";
import { Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { JobProgress } from "../shared";
import { AppDetails, BlockedAlert, LogsView, type Tab as DetailTab } from "./AppDetails";
import { appWindowId, openInNewTab } from "./AppFrame";
import { CatalogsPage, ImportedSections } from "./Catalogs";
import { AppIcon, STATE, SourceBadge, appNotes, isRunning, jobSnapshot, useApps, useCatalog } from "./common";
import { CreateApp } from "./CreateApp";
import { InstallDialog } from "./InstallDialog";

export { appUrl } from "./common";

type Section = "installed" | "discover" | "catalogs" | "create";
type OpenApp = (app: Pick<InstalledApp, "id" | "name">) => void;

export default function AppStore(_: AppProps) {
  const shell = useShell();
  return (
    <AppStoreView
      isAdmin={shell.user.role === "admin"}
      onOpen={(app) => shell.openApp(appWindowId(app.id), { id: app.id, title: app.name })}
    />
  );
}

export function AppStoreView({ isAdmin, onOpen = (a) => void openInNewTab(a.id, a.name) }: { isAdmin: boolean; onOpen?: OpenApp }) {
  const [section, setSection] = useState<Section>("installed");
  const [installing, setInstalling] = useState<{ ref: AppPackageRef; plan?: AppPlan } | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [detailTab, setDetailTab] = useState<DetailTab>("overview");
  const select = (id: string, tab: DetailTab = "overview") => {
    setSelected(id);
    setDetailTab(tab);
  };
  const apps = useApps();
  const updates = Object.keys(apps.data?.updates ?? {}).length;

  const items: NavItem[] = [
    {
      id: "installed",
      label: "My apps",
      icon: <GridIcon size={16} />,
      badge: updates > 0 ? <Badge tone="accent">{updates}</Badge> : undefined,
    },
    ...(isAdmin
      ? [
          { id: "discover", label: "Discover", icon: <BagIcon size={16} /> },
          { id: "catalogs", label: "Catalogs", icon: <LayersIcon size={16} /> },
          { id: "create", label: "Create an app", icon: <EditIcon size={16} /> },
        ]
      : []),
  ];
  const go = (s: Section) => {
    setSection(s);
    setSelected(null);
  };
  const detail = selected ? apps.data?.apps.find((a) => a.id === selected) : undefined;

  return (
    <AppLayout
      nav={
        <SideNav
          label="App Store sections"
          items={items}
          active={section}
          onSelect={(s) => go(s as Section)}
          footer={isAdmin ? <UploadButton onUploaded={(ref) => setInstalling({ ref })} /> : undefined}
        />
      }
    >
      {section === "installed" &&
        (isAdmin && detail ? (
          <DetailsWithRemove key={`${detail.id}:${detailTab}`} app={detail} update={apps.data?.updates[detail.id]} tab={detailTab} onBack={() => setSelected(null)} onOpen={onOpen} />
        ) : (
          <Installed isAdmin={isAdmin} onDiscover={() => go("discover")} onSelect={select} onOpen={onOpen} />
        ))}
      {section === "discover" && isAdmin && <Discover overview={apps.data} onInstall={(ref) => setInstalling({ ref })} />}
      {section === "catalogs" && isAdmin && <CatalogsPage />}
      {section === "create" && isAdmin && <CreateApp onPlanned={(plan) => setInstalling({ ref: { source: plan.package.source, ref: plan.package.ref }, plan })} />}
      {installing && (
        <InstallDialog
          pkgRef={installing.ref}
          plan={installing.plan}
          onClose={() => setInstalling(null)}
          onInstalled={() => {
            setInstalling(null);
            go("installed");
          }}
        />
      )}
    </AppLayout>
  );
}

function DetailsWithRemove({ app, update, tab, onBack, onOpen }: { app: InstalledApp; update?: string; tab: DetailTab; onBack: () => void; onOpen: OpenApp }) {
  const [removing, setRemoving] = useState(false);
  const [job, setJob] = useState<string | null>(null);
  const qc = useQueryClient();
  return (
    <>
      <AppDetails app={app} update={update} initialTab={tab} onBack={onBack} onRemove={() => setRemoving(true)} onOpen={onOpen} />
      {job && (
        <JobProgress
          id={job}
          onDone={() => {
            void qc.invalidateQueries({ queryKey: ["apps"] });
            onBack();
          }}
        />
      )}
      {removing && <RemoveDialog id={app.id} name={app.name} onClose={() => setRemoving(false)} onStarted={setJob} />}
    </>
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

function Installed({
  isAdmin,
  onDiscover,
  onSelect,
  onOpen,
}: {
  isAdmin: boolean;
  onDiscover: () => void;
  onSelect: (id: string, tab?: DetailTab) => void;
  onOpen: OpenApp;
}) {
  const q = useApps();
  if (q.isPending) return <Loading />;
  if (q.isError) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const o = q.data;
  return (
    <>
      <PageHeader
        title="My apps"
        subtitle={
          isAdmin ? (
            o.configured ? (
              <>
                Apps run in Docker on <span className="mono">{o.pool}</span>
                {o.engineVersion && <> (Docker {o.engineVersion})</>}, each in its own dataset you can snapshot.
              </>
            ) : (
              "One-click apps run in Docker on one of your pools. Pick one from Discover to get started."
            )
          ) : (
            "Apps you can use on this server. Open one to use it."
          )
        }
        actions={
          isAdmin && (
            <Button variant="primary" onClick={onDiscover}>
              <PlusIcon size={15} /> Get apps
            </Button>
          )
        }
      />
      <div className="stack">
        <EngineBanner o={o} isAdmin={isAdmin} />
        {o.apps.length === 0 ? (
          <EmptyState icon={<BagIcon size={28} />} title="No apps yet" action={isAdmin ? <Button variant="primary" onClick={onDiscover}>Browse apps</Button> : undefined}>
            {isAdmin ? "Install a family video site, photo backup and more with one click." : "An administrator can install apps and choose who can use them."}
          </EmptyState>
        ) : (
          <div className="app-grid">
            {o.apps.map((a) => (
              <AppCard
                key={a.id}
                app={a}
                update={o.updates[a.id]}
                published={o.published?.[a.id]}
                isAdmin={isAdmin}
                onSelect={() => onSelect(a.id)}
                onSettings={() => onSelect(a.id, "settings")}
                onOpen={onOpen}
              />
            ))}
          </div>
        )}
        {isAdmin && o.keptData.length > 0 && <KeptData o={o} />}
      </div>
    </>
  );
}

function AppCard({
  app,
  update,
  published,
  isAdmin,
  onSelect,
  onSettings,
  onOpen,
}: {
  app: InstalledApp;
  update?: string;
  /** Its address through NetBird's reverse proxy, when published. */
  published?: string;
  isAdmin: boolean;
  onSelect: () => void;
  onSettings: () => void;
  onOpen: OpenApp;
}) {
  const qc = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);
  const [job, setJob] = useState<string | null>(null);
  const [failedSnapshot, setFailedSnapshot] = useState<string | null>(null);
  const [dialog, setDialog] = useState<"logs" | "remove" | null>(null);
  const st = STATE[app.state] ?? { tone: "neutral" as Tone, label: app.state };
  const running = isRunning(app);

  async function act(action: "start" | "stop") {
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
    setFailedSnapshot(null);
    try {
      const r = await api.POST("/apps/{id}/update", { params: { path: { id: app.id } } });
      if (r.error?.code === "grants_required") {
        // The details page asks for the new permissions.
        toast("warning", `The new ${app.name} asks for more permissions`, "Open its settings to allow them and update.");
        onSelect();
        return;
      }
      setJob((await unwrap(Promise.resolve(r))).job.id);
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
    <article className="app-card" aria-label={app.name}>
      <header className="app-card__head">
        <AppIcon src={app.icon} name={app.name} />
        <div className="app-card__title">
          <h3>{isAdmin ? <button type="button" className="link-button app-card__name" onClick={onSelect}>{app.name}</button> : app.name}</h3>
          <span className="small muted">
            <span className="mono">{app.version}</span>
            {app.publisher && <> · {app.publisher}</>}
          </span>
        </div>
        <SourceBadge source={app.source} sourceName={app.sourceName} />
        <Badge tone={st.tone}>{st.label}</Badge>
      </header>
      {app.summary && <p className="app-card__summary">{app.summary}</p>}
      {published && (
        <a className="small mono" href={published} target="_blank" rel="noopener noreferrer" aria-label={`${app.name} published address`}>
          {new URL(published).host}
        </a>
      )}
      {app.blocked && <BlockedAlert app={app} onSettings={isAdmin ? onSettings : undefined} />}
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
      {isAdmin && update && !job && (
        <Alert tone="info" title={`Version ${update} is available`} action={<Button size="sm" variant="primary" busy={busy === "update"} onClick={runUpdate}>Update</Button>}>
          A snapshot is taken first. {app.name}'s data, settings and passwords are kept.
        </Alert>
      )}
      {job && <JobProgress id={job} onDone={jobDone} />}
      {failedSnapshot && (
        <Alert tone="warn" title="The update didn't finish" action={<Button size="sm" onClick={onSelect}>Roll back…</Button>}>
          A snapshot was taken first: roll back to it from {app.name}'s Snapshots.
        </Alert>
      )}
      <footer className="app-card__actions">
        {app.web && (
          <>
            <Button size="sm" variant={running ? "primary" : "secondary"} disabled={!running} onClick={() => onOpen(app)}>
              Open
            </Button>
            <Button size="sm" variant="ghost" disabled={!running} onClick={() => openInNewTab(app.id, app.name)} aria-label={`Open ${app.name} in a new tab`} title="Open in new tab">
              <ExternalIcon size={14} />
            </Button>
          </>
        )}
        {isAdmin && (
          <>
            {running ? (
              <Button size="sm" onClick={() => act("stop")} busy={busy === "stop"} disabled={!!job}>
                <StopIcon size={13} /> Stop
              </Button>
            ) : (
              <Button size="sm" onClick={() => act("start")} busy={busy === "start"} disabled={!!job || !!app.blocked}>
                <PlayIcon size={13} /> Start
              </Button>
            )}
            <span className="app-card__spacer" />
            <Button size="sm" variant="ghost" onClick={() => setDialog("logs")} aria-label={`${app.name} logs`} title="Logs">
              <LayersIcon size={14} />
            </Button>
            <Button size="sm" variant="ghost" onClick={onSelect} aria-label={`${app.name} settings`}>
              <EditIcon size={14} />
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setDialog("remove")} disabled={!!job} aria-label={`Remove ${app.name}`}>
              <TrashIcon size={14} />
            </Button>
          </>
        )}
      </footer>
      {dialog === "logs" && (
        <Dialog title={`${app.name} logs`} onClose={() => setDialog(null)} width={860} footer={<Button variant="primary" onClick={() => setDialog(null)}>Done</Button>}>
          <LogsView app={app} />
        </Dialog>
      )}
      {dialog === "remove" && <RemoveDialog id={app.id} name={app.name} onClose={() => setDialog(null)} onStarted={setJob} />}
    </article>
  );
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

function RemoveDialog({ id, name, keptOnly, onClose, onStarted }: { id: string; name: string; keptOnly?: boolean; onClose: () => void; onStarted: (job: string) => void }) {
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
  const disabled = overview ? !overview.available : false;
  return (
    <>
      <PageHeader title="Discover" subtitle="Apps that ship with HardyOS, and apps from catalogs you've imported. Each runs in its own containers, with its data in its own dataset." />
      <div className="stack">
        {overview && <EngineBanner o={overview} isAdmin />}
        <h2 className="card__title">HardyOS catalog</h2>
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
              <CatalogCard key={p.id} pkg={p} installedVersion={installed.get(p.id)} onInstall={() => onInstall({ source: "catalog", ref: p.id })} disabled={disabled} />
            ))}
          </div>
        )}
        <ImportedSections installed={installed} onInstall={onInstall} disabled={disabled} />
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
      {pkg.grants.length > 0 && (
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
