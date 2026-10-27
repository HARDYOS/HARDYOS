import type { BackupEntry, BackupVersion, BackupVersionItem } from "@hardy/api-client";
import { useMemo, useState } from "react";
import { errorMessage } from "../../api";
import { bytes, dateTime, relativeTime } from "../../format";
import { FolderIcon, CloudUpIcon } from "../../icons";
import { Alert, Button, EmptyState, ErrorBox, Field, Loading, PageHeader, Select, TextInput } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { itemLabel, kindLabel, restore, useBrowse, useOverview, useSources, useVersions } from "./backupApi";
import { JobProgress } from "./parts";
import type { BackupTabProps } from "./tabs";

/** Browse every version at a destination and restore from it. */
export function RestoreBrowser({ args }: BackupTabProps) {
  const ov = useOverview();
  const targets = ov.data?.targets ?? [];
  const tasks = ov.data?.tasks ?? [];
  const [target, setTarget] = useState<string>(args.target ?? "");
  const current = target || targets[0]?.id || "";
  const [taskFilter, setTaskFilter] = useState<string>(args.task ?? "");
  const versions = useVersions(current || null);
  const [run, setRun] = useState<string | null>(null);
  const [itemKey, setItemKey] = useState<string | null>(null);
  const sources = useSources();
  const names = useMemo(() => {
    const n: Record<string, string> = {};
    sources.shares.forEach((s) => (n[`share:${s.id}`] = s.name));
    sources.apps.forEach((a) => (n[`app:${a.id}`] = a.name));
    sources.vms.forEach((v) => (n[`vm:${v.id}`] = v.name));
    return n;
  }, [sources.shares, sources.apps, sources.vms]);

  if (ov.isPending) return <Loading />;
  if (ov.isError) return <ErrorBox error={ov.error} onRetry={() => ov.refetch()} />;
  if (targets.length === 0) {
    return (
      <EmptyState icon={<CloudUpIcon size={28} />} title="Nothing to restore yet">
        Versions appear here once a backup task has run.
      </EmptyState>
    );
  }
  const list = (versions.data?.versions ?? []).filter((v) => !taskFilter || v.task === taskFilter);
  const version = list.find((v) => v.run === run) ?? null;
  const item = version?.items.find((i) => i.item === itemKey) ?? null;
  const taskName = (id: string) => tasks.find((t) => t.id === id)?.name ?? "A removed task";

  return (
    <div className="stack">
      <PageHeader title="Restore" subtitle="Pick a version, then the files to bring back, or put a whole folder, app or VM back to how it was." />
      <div className="bk-row2">
        <Field label="Destination">
          {(id) => (
            <Select
              id={id}
              value={current}
              onChange={(e) => {
                setTarget(e.target.value);
                setRun(null);
                setItemKey(null);
              }}
            >
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Task">
          {(id) => (
            <Select id={id} value={taskFilter} onChange={(e) => setTaskFilter(e.target.value)}>
              <option value="">All tasks</option>
              {tasks
                .filter((t) => t.target === current)
                .map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
            </Select>
          )}
        </Field>
      </div>
      <div className="bk-restore">
        <section className="bk-pane bk-versions" aria-label="Versions">
          {versions.isPending ? (
            <Loading label="Reading the destination…" />
          ) : versions.isError ? (
            <ErrorBox error={versions.error} onRetry={() => versions.refetch()} />
          ) : list.length === 0 ? (
            <p className="small muted bk-pad">No versions yet.</p>
          ) : (
            <ol className="bk-timeline">
              {list.map((v) => (
                <li key={v.run}>
                  <button
                    type="button"
                    className={`bk-version ${v.run === run ? "is-active" : ""}`}
                    aria-pressed={v.run === run}
                    onClick={() => {
                      setRun(v.run);
                      setItemKey(v.items.length === 1 ? v.items[0]!.item : null);
                    }}
                  >
                    <span className="bk-version__when" title={dateTime(v.time)}>
                      {relativeTime(v.time)}
                    </span>
                    <span className="small muted">
                      {taskName(v.task)} · <span className="mono">{v.items.length}</span> item{v.items.length === 1 ? "" : "s"}
                    </span>
                    {!v.manifest && <span className="small bk-warn">Incomplete</span>}
                  </button>
                </li>
              ))}
            </ol>
          )}
        </section>
        <section className="bk-pane bk-items" aria-label="In this version">
          {!version ? (
            <p className="small muted bk-pad">Choose a version.</p>
          ) : (
            <ul className="bk-itemlist">
              {version.items.map((it) => (
                <li key={it.item}>
                  <button type="button" className={`bk-itemrow ${it.item === itemKey ? "is-active" : ""}`} aria-pressed={it.item === itemKey} onClick={() => setItemKey(it.item)}>
                    <span className={`bk-chip bk-chip--${it.item.split(":")[0]}`}>{kindLabel[it.item.split(":")[0]!] ?? "Item"}</span>
                    <strong>{itemLabel(it.item, names)}</strong>
                    <span className="small mono muted">{bytes(it.bytes)}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section className="bk-pane bk-detail" aria-label="Restore">
          {version && item ? <ItemRestore key={`${version.run}/${item.item}`} target={current} version={version} item={item} name={itemLabel(item.item, names)} /> : <p className="small muted bk-pad">Choose what to restore.</p>}
        </section>
      </div>
    </div>
  );
}

function ItemRestore({ target, version, item, name }: { target: string; version: BackupVersion; item: BackupVersionItem; name: string }) {
  const kind = item.item.split(":")[0]!;
  const [job, setJob] = useState<{ id: string; label: string } | null>(null);
  const [rollback, setRollback] = useState(false);
  const confirmName = kind === "system" ? "settings" : name;
  const doRollback = async () => {
    const r = await restore({ target, snapshot: item.snapshot, mode: "rollback", confirm: confirmName });
    setJob({ id: r.job.id, label: kind === "system" ? "Preparing the settings" : `Rolling back ${name}` });
  };
  return (
    <div className="stack">
      <header className="bk-detail__head">
        <div>
          <h3>{name}</h3>
          <span className="small muted">
            {kindLabel[kind]} · {dateTime(version.time)} · <span className="mono">{bytes(item.bytes)}</span>
          </span>
        </div>
        <Button variant="danger" size="sm" onClick={() => setRollback(true)} disabled={!!job}>
          {kind === "system" ? "Restore settings" : "Roll back to this version"}
        </Button>
      </header>
      {(kind === "share" || kind === "app") && <FolderBrowser target={target} snapshot={item.snapshot} share={kind === "share"} name={name} onJob={setJob} />}
      {kind === "vm" && (
        <Alert tone="info" title="The whole VM comes back">
          Its disks, settings, firmware variables and TPM. It must be off; a VM snapshot of how it is now is taken first.
        </Alert>
      )}
      {kind === "system" && (
        <Alert tone="info" title="Applied at the next restart">
          Accounts, network, the HTTPS certificate, encryption keys and the domain come back when the server restarts. Network settings that don't fit this hardware are
          skipped.
        </Alert>
      )}
      {job && <JobProgress id={job.id} label={job.label} onDone={(j) => j.state === "succeeded" && toast("success", "Restored", job.label)} />}
      {rollback && (
        <ConfirmDialog
          title={kind === "system" ? "Restore these settings?" : `Roll ${name} back?`}
          confirmLabel={kind === "system" ? "Restore at restart" : "Roll back"}
          typeToConfirm={confirmName}
          onClose={() => setRollback(false)}
          onConfirm={doRollback}
        >
          {kind === "share" && "Everything in the folder becomes as it was in this version: newer files are removed. A snapshot of the folder as it is now is taken first, so this can be undone."}
          {kind === "app" && "The app stops, its data and settings go back to this version and it starts again. Permissions you removed since stay removed. A snapshot is taken first."}
          {kind === "vm" && "The VM's disks and settings go back to this version; anything newer on them is lost (a VM snapshot is taken first)."}
          {kind === "system" && "The settings in this version replace the current ones when the server restarts."}
        </ConfirmDialog>
      )}
    </div>
  );
}

function parentPath(p: string) {
  const i = p.lastIndexOf("/");
  return i < 0 ? "" : p.slice(0, i);
}

/** Browse a folder of a version and pick files and folders to restore. */
export function FolderBrowser({
  target,
  snapshot,
  share,
  name,
  onJob,
  browse,
  submit,
}: {
  target: string;
  snapshot: string;
  share: boolean;
  name: string;
  onJob: (j: { id: string; label: string }) => void;
  browse?: (path: string) => { data?: { entries: BackupEntry[] }; isPending: boolean; isError: boolean; error: unknown };
  submit?: (paths: string[], mode: "copy" | "in_place", folder: string) => Promise<{ job: { id: string } }>;
}) {
  const [path, setPath] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [dialog, setDialog] = useState(false);
  const own = useBrowse(target, browse ? null : snapshot, path);
  const q = browse ? browse(path) : own;
  const crumbs = path ? path.split("/") : [];
  const toggle = (p: string, on: boolean) => setPicked((l) => (on ? [...l, p] : l.filter((x) => x !== p)));
  return (
    <div className="stack">
      <nav className="bk-crumbs" aria-label="Folder">
        <button type="button" onClick={() => setPath("")}>
          {name}
        </button>
        {crumbs.map((c, i) => (
          <span key={i}>
            <span aria-hidden="true">/</span>
            <button type="button" onClick={() => setPath(crumbs.slice(0, i + 1).join("/"))}>
              {c}
            </button>
          </span>
        ))}
      </nav>
      {q.isPending ? (
        <Loading label="Listing the version…" />
      ) : q.isError ? (
        <ErrorBox error={q.error} />
      ) : (
        <ul className="bk-files" aria-label="Files in this version">
          {path && (
            <li className="bk-file">
              <span />
              <button type="button" className="bk-file__name" onClick={() => setPath(parentPath(path))}>
                ..
              </button>
            </li>
          )}
          {(q.data?.entries ?? []).map((e) => (
            <li key={e.path} className="bk-file">
              <input type="checkbox" aria-label={`Choose ${e.name}`} checked={picked.includes(e.path)} disabled={!share} onChange={(ev) => toggle(e.path, ev.target.checked)} />
              {e.dir ? (
                <button type="button" className="bk-file__name" onClick={() => setPath(e.path)}>
                  <FolderIcon size={15} /> {e.name}
                </button>
              ) : (
                <span className="bk-file__name">{e.name}</span>
              )}
              <span className="mono small muted">{e.dir ? "" : bytes(e.size)}</span>
              <span className="small muted">{dateTime(e.modified)}</span>
            </li>
          ))}
          {(q.data?.entries ?? []).length === 0 && <li className="small muted bk-pad">This folder was empty.</li>}
        </ul>
      )}
      {share && (
        <div className="bk-actionbar">
          <span className="small muted">
            <span className="mono">{picked.length}</span> chosen
          </span>
          <Button variant="primary" size="sm" disabled={picked.length === 0} onClick={() => setDialog(true)}>
            Restore…
          </Button>
        </div>
      )}
      {dialog && (
        <RestoreDialog
          count={picked.length}
          onClose={() => setDialog(false)}
          onRestore={async (mode, folder) => {
            const r = submit ? await submit(picked, mode, folder) : await restore({ target, snapshot, paths: picked, mode, folder: mode === "copy" ? folder : undefined });
            onJob({ id: r.job.id, label: mode === "copy" ? `Restoring into “${folder}”` : "Putting files back" });
            setPicked([]);
          }}
        />
      )}
    </div>
  );
}

export function RestoreDialog({ count, onClose, onRestore }: { count: number; onClose: () => void; onRestore: (mode: "copy" | "in_place", folder: string) => Promise<void> }) {
  const [mode, setMode] = useState<"copy" | "in_place">("copy");
  const [folder, setFolder] = useState(() => `Restored ${new Date().toISOString().slice(0, 10)}`);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function go() {
    setBusy(true);
    setError(null);
    try {
      await onRestore(mode, folder.trim());
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    }
    setBusy(false);
  }
  return (
    <Dialog title={`Restore ${count} item${count === 1 ? "" : "s"}`} width={480} onClose={onClose} onSubmit={go}>
      <div className="stack">
        <label className={`bk-choice ${mode === "copy" ? "is-on" : ""}`}>
          <input type="radio" name="mode" checked={mode === "copy"} onChange={() => setMode("copy")} />
          <span>
            <strong>Into a new folder</strong>
            <span className="small muted">Nothing current is touched; the old versions go into a folder at the top.</span>
          </span>
        </label>
        {mode === "copy" && <Field label="Folder name">{(id) => <TextInput id={id} value={folder} maxLength={200} onChange={(e) => setFolder(e.target.value)} />}</Field>}
        <label className={`bk-choice ${mode === "in_place" ? "is-on" : ""}`}>
          <input type="radio" name="mode" checked={mode === "in_place"} onChange={() => setMode("in_place")} />
          <span>
            <strong>Where they were</strong>
            <span className="small muted">Replaces the current files with these versions. Newer files elsewhere stay.</span>
          </span>
        </label>
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
      <footer className="dialog__foot">
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="primary" type="submit" busy={busy} disabled={mode === "copy" && !folder.trim()}>
          Restore
        </Button>
      </footer>
    </Dialog>
  );
}
