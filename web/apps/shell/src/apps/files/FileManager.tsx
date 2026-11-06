import type { FileEntry, FileShare } from "@hardy/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { type DragEvent, type KeyboardEvent, type MouseEvent, type ReactNode, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { ApiFailure, errorMessage } from "../../api";
import { bytes, dateTime, relativeTime } from "../../format";
import { DocumentIcon, RefreshIcon, SearchIcon, TrashIcon, UploadIcon, EditIcon, InfoIcon } from "../../icons";
import { editorWindowId, opensInEditor, useOffice } from "../office/officeApi";
import { type AppProps, useShell } from "../../shell";
import { Alert, Badge, Button, EmptyState, Loading } from "../../ui";
import { toast } from "../../ui/toasts";
import { DeleteDialog, FolderPicker, NameDialog, NewDocumentDialog, PropertiesDialog, ShareLinkDialog } from "./dialogs";
import { listingKey, mkdir, remove, rename, transfer, useFileShares, useListing } from "./fileApi";
import "./files.css";
import {
  CopyIcon,
  DownloadIcon,
  EyeIcon,
  GridViewIcon,
  HistoryIcon,
  HomeIcon,
  KindIcon,
  LinkIcon,
  ListViewIcon,
  MoveIcon,
  NewFolderIcon,
  UpIcon,
} from "./icons";
import { HOME, type Sort, type SortKey, basename, crumbs, downloadUrl, hidden, join, kindOf, parent, previewable, sortEntries } from "./paths";
import { Preview } from "./Preview";
import { type Selection, clickSelect, emptySelection, moveSelect, prune, selectAll } from "./selection";
import { SharedLinks } from "./SharedLinks";
import { UploadTray, useUploads } from "./Uploads";
import { VersionsPanel } from "./Versions";

/** Where the File Manager is: a folder in a share, or one of the link lists. */
export type Place = { kind: "folder"; share: string; path: string } | { kind: "links"; scope: "mine" | "all" };

type ViewMode = "list" | "grid";

function stored<T extends string>(key: string, fallback: T, allowed: readonly T[]): T {
  try {
    const v = localStorage.getItem(key) as T | null;
    return v && allowed.includes(v) ? v : fallback;
  } catch {
    return fallback;
  }
}
function store(key: string, v: string) {
  try {
    localStorage.setItem(key, v);
  } catch {
    /* private window: not remembered */
  }
}

/** Opens a document in its editor window (one window per file). */
export type OpenDocument = (share: string, path: string, name: string, mode: "edit" | "view") => void;

export default function FileManager({ args }: AppProps) {
  const shell = useShell();
  const openDoc: OpenDocument = (share, path, name, mode) =>
    shell.openApp(editorWindowId(share, path), { share, path, mode, title: mode === "view" ? `${name} (read only)` : name });
  return (
    <FileManagerView
      isAdmin={shell.user.role === "admin"}
      openDoc={openDoc}
      initial={args?.share ? { kind: "folder", share: args.share, path: args.path ?? "" } : undefined}
    />
  );
}

/** The File Manager without the desktop around it (tests render this). */
export function FileManagerView({ isAdmin, initial, openDoc }: { isAdmin: boolean; initial?: Place; openDoc?: OpenDocument }) {
  const shares = useFileShares();
  const [place, setPlace] = useState<Place | undefined>(initial);
  const uploads = useUploads();
  const list = useMemo(() => {
    const all = shares.data ?? [];
    // Home first, then shared folders by name.
    return [...all].sort((a, b) => (a.id === HOME ? -1 : b.id === HOME ? 1 : a.name.localeCompare(b.name)));
  }, [shares.data]);

  // Open Home (or the first folder) once the list is in.
  useEffect(() => {
    if (!place && list.length > 0) setPlace({ kind: "folder", share: list[0]!.id, path: "" });
  }, [place, list]);

  const go = useCallback((share: string, path: string) => setPlace({ kind: "folder", share, path }), []);
  const current = place?.kind === "folder" ? list.find((s) => s.id === place.share) : undefined;

  let main: ReactNode;
  if (shares.isPending) main = <Loading />;
  else if (shares.isError)
    main = (
      <div className="fm-center">
        <Alert
          tone="bad"
          title="Couldn't load your folders"
          action={
            <Button size="sm" onClick={() => shares.refetch()}>
              Try again
            </Button>
          }
        >
          {errorMessage(shares.error)}
        </Alert>
      </div>
    );
  else if (list.length === 0)
    main = (
      <EmptyState title="No folders for you yet" icon={<KindIcon kind="folder" size={30} />}>
        {isAdmin
          ? "Make a shared folder in Control Panel › Shared Folders, and give people access to it."
          : "Ask an administrator to give you access to a shared folder."}
      </EmptyState>
    );
  else if (place?.kind === "links") main = <SharedLinks scope={place.scope} shares={list} onOpen={go} />;
  else if (place?.kind === "folder" && !current)
    main = (
      <EmptyState title="That folder isn't available" icon={<KindIcon kind="folder" size={30} />}>
        It may have been removed, or you no longer have access to it.
      </EmptyState>
    );
  else if (place?.kind === "folder" && current)
    main = (
      <FolderView
        key={current.id}
        share={current}
        path={place.path}
        shares={list}
        isAdmin={isAdmin}
        onNavigate={(p) => go(current.id, p)}
        uploads={uploads}
        openDoc={openDoc}
      />
    );

  return (
    <div className="fm">
      <div className="fm-body">
        <nav className="fm-side" aria-label="Places">
          {list.length > 0 && <div className="fm-side__group">Places</div>}
          {list.map((s) => (
            <button
              key={s.id}
              type="button"
              className={`fm-side__item ${place?.kind === "folder" && place.share === s.id ? "is-active" : ""}`}
              aria-current={place?.kind === "folder" && place.share === s.id ? "page" : undefined}
              onClick={() => go(s.id, "")}
            >
              {s.id === HOME ? <HomeIcon size={16} /> : <KindIcon kind="folder" size={16} />}
              <span className="fm-ellipsis">{s.id === HOME ? "Home" : s.name}</span>
              {!s.writable && (
                <span className="fm-side__ro" title="Read only">
                  read only
                </span>
              )}
            </button>
          ))}
          <div className="fm-side__group">Sharing</div>
          <button
            type="button"
            className={`fm-side__item ${place?.kind === "links" && place.scope === "mine" ? "is-active" : ""}`}
            aria-current={place?.kind === "links" && place.scope === "mine" ? "page" : undefined}
            onClick={() => setPlace({ kind: "links", scope: "mine" })}
          >
            <LinkIcon size={16} />
            <span className="fm-ellipsis">Links I've shared</span>
          </button>
          {isAdmin && (
            <button
              type="button"
              className={`fm-side__item ${place?.kind === "links" && place.scope === "all" ? "is-active" : ""}`}
              aria-current={place?.kind === "links" && place.scope === "all" ? "page" : undefined}
              onClick={() => setPlace({ kind: "links", scope: "all" })}
            >
              <LinkIcon size={16} />
              <span className="fm-ellipsis">All links</span>
            </button>
          )}
        </nav>
        <div className="fm-main">{main}</div>
      </div>
      <UploadTray uploads={uploads} />
    </div>
  );
}

type Dialog =
  | { kind: "mkdir" }
  | { kind: "rename"; entry: FileEntry }
  | { kind: "move" | "copy"; paths: string[] }
  | { kind: "delete"; entries: FileEntry[] }
  | { kind: "props"; entry: FileEntry }
  | { kind: "link"; entry: FileEntry }
  | { kind: "newdoc" };

interface Menu {
  x: number;
  y: number;
}

function FolderView({
  share,
  path,
  shares,
  isAdmin,
  onNavigate,
  uploads,
  openDoc,
}: {
  share: FileShare;
  path: string;
  shares: FileShare[];
  isAdmin: boolean;
  onNavigate: (path: string) => void;
  uploads: ReturnType<typeof useUploads>;
  openDoc?: OpenDocument;
}) {
  const q = useListing(share.id, path);
  const office = useOffice();
  const isDoc = (e: FileEntry) => !!openDoc && opensInEditor(office.data, e);
  const qc = useQueryClient();
  const [view, setView] = useState<ViewMode>(() => stored("hardyos.files.view", "list", ["list", "grid"] as const));
  const [sort, setSort] = useState<Sort>(() => ({
    key: stored("hardyos.files.sort", "name", ["name", "size", "modified", "kind"] as const),
    asc: stored("hardyos.files.asc", "1", ["1", "0"] as const) === "1",
  }));
  const [filter, setFilter] = useState("");
  const [sel, setSel] = useState<Selection>(emptySelection);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [versions, setVersions] = useState<FileEntry | null>(null);
  const [preview, setPreview] = useState<number | null>(null);
  const [menu, setMenu] = useState<Menu | null>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const dragDepth = useRef(0);

  const shareName = share.id === HOME ? "Home" : share.name;
  const entries = useMemo(() => {
    const visible = (q.data ?? []).filter((e) => !hidden(e.name));
    const f = filter.trim().toLowerCase();
    return sortEntries(f ? visible.filter((e) => e.name.toLowerCase().includes(f)) : visible, sort);
  }, [q.data, sort, filter]);
  const order = useMemo(() => entries.map((e) => e.path), [entries]);
  const byPath = useMemo(() => new Map(entries.map((e) => [e.path, e])), [entries]);
  const uid = useId();
  const itemId = useCallback((p: string) => `${uid}-item-${order.indexOf(p)}`, [uid, order]);
  const selected = entries.filter((e) => sel.selected.has(e.path));
  const one = selected.length === 1 ? selected[0]! : null;
  const names = (q.data ?? []).map((e) => e.name);
  const previews = useMemo(() => entries.filter(previewable), [entries]);

  useEffect(() => setSel((s) => prune(s, order)), [order]);
  // A new folder starts with nothing selected and the list focused.
  useEffect(() => {
    setSel(emptySelection());
    setFilter("");
    setVersions(null);
    listRef.current?.focus({ preventScroll: true });
  }, [path]);

  const refresh = useCallback(() => void qc.invalidateQueries({ queryKey: listingKey(share.id, path) }), [qc, share.id, path]);

  const changeSort = (key: SortKey) => {
    const next = { key, asc: sort.key === key ? !sort.asc : true };
    setSort(next);
    store("hardyos.files.sort", next.key);
    store("hardyos.files.asc", next.asc ? "1" : "0");
  };
  const changeView = (v: ViewMode) => {
    setView(v);
    store("hardyos.files.view", v);
  };

  function open(e: FileEntry) {
    if (e.dir) onNavigate(e.path);
    else if (isDoc(e)) openDoc?.(share.id, e.path, e.name, "edit");
    else if (previewable(e)) setPreview(previews.indexOf(e));
    else download([e]);
  }

  function download(list: FileEntry[]) {
    if (list.length === 0) return;
    const a = document.createElement("a");
    a.href = downloadUrl(
      share.id,
      list.map((e) => e.path),
    );
    a.download = list.length === 1 && !list[0]!.dir ? list[0]!.name : "";
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  async function run<T>(label: string, fn: (progress: (p: number) => void) => Promise<T>): Promise<T> {
    setBusy(label);
    try {
      return await fn((p) => setBusy(`${label} ${Math.round(p)}%`));
    } finally {
      setBusy(null);
      refresh();
    }
  }

  const canWrite = share.writable;
  const canNewDoc = canWrite && !!openDoc && !!office.data?.enabled && !!office.data.ready;
  const canShare = (e: FileEntry) => e.writable || isAdmin;

  function startUpload(files: File[]) {
    if (!canWrite) {
      toast("warning", "This folder is read only", "You can't add files here.");
      return;
    }
    if (files.length > 0) uploads.add(files, share.id, path, names);
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    dragDepth.current = 0;
    setDragging(false);
    const dt = e.dataTransfer;
    const files: File[] = [];
    let folders = 0;
    const items = dt.items ? Array.from(dt.items) : [];
    if (items.length > 0) {
      for (const it of items) {
        if (it.kind !== "file") continue;
        const entry = (it as DataTransferItem & { webkitGetAsEntry?: () => { isDirectory: boolean } | null }).webkitGetAsEntry?.();
        if (entry?.isDirectory) {
          folders++;
          continue;
        }
        const f = it.getAsFile();
        if (f) files.push(f);
      }
    } else {
      files.push(...Array.from(dt.files));
    }
    if (folders > 0) toast("info", "Folders aren't uploaded by dragging yet", "Drop the files inside them, or make the folder first.");
    startUpload(files);
  }

  const hasFiles = (e: DragEvent) => Array.from(e.dataTransfer?.types ?? []).includes("Files");

  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (dialog || preview !== null) return;
    const mod = e.ctrlKey || e.metaKey;
    const cols = view === "grid" ? gridColumns(listRef.current) : 1;
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        setSel((s) => moveSelect(s, order, cols, e.shiftKey));
        break;
      case "ArrowUp":
        e.preventDefault();
        setSel((s) => moveSelect(s, order, -cols, e.shiftKey));
        break;
      case "ArrowRight":
        if (view === "grid") {
          e.preventDefault();
          setSel((s) => moveSelect(s, order, 1, e.shiftKey));
        }
        break;
      case "ArrowLeft":
        if (view === "grid") {
          e.preventDefault();
          setSel((s) => moveSelect(s, order, -1, e.shiftKey));
        }
        break;
      case "Home":
        e.preventDefault();
        setSel((s) => moveSelect(s, order, -order.length, e.shiftKey));
        break;
      case "End":
        e.preventDefault();
        setSel((s) => moveSelect(s, order, order.length, e.shiftKey));
        break;
      case "Enter": {
        e.preventDefault();
        const target = (sel.focus && byPath.get(sel.focus)) || one;
        if (target) open(target);
        break;
      }
      case " ": {
        e.preventDefault();
        const target = (sel.focus && byPath.get(sel.focus)) || one;
        if (target && previewable(target)) setPreview(previews.indexOf(target));
        break;
      }
      case "Backspace":
        e.preventDefault();
        if (path) onNavigate(parent(path));
        break;
      case "Delete":
        if (selected.length > 0 && selected.every((x) => x.writable)) {
          e.preventDefault();
          setDialog({ kind: "delete", entries: selected });
        }
        break;
      case "F2":
        if (one?.writable) {
          e.preventDefault();
          setDialog({ kind: "rename", entry: one });
        }
        break;
      case "Escape":
        setSel(emptySelection());
        setMenu(null);
        break;
      case "a":
      case "A":
        if (mod) {
          e.preventDefault();
          setSel(selectAll(order));
        }
        break;
    }
  }

  // Keep the focused item in view as the keyboard moves.
  useEffect(() => {
    if (!sel.focus) return;
    const el = document.getElementById(itemId(sel.focus));
    el?.scrollIntoView?.({ block: "nearest" });
  }, [sel.focus, itemId]);

  function onItemClick(e: MouseEvent, entry: FileEntry) {
    e.stopPropagation();
    setMenu(null);
    setSel((s) => clickSelect(s, order, entry.path, { shift: e.shiftKey, toggle: e.ctrlKey || e.metaKey }));
    listRef.current?.focus({ preventScroll: true });
  }

  function onItemContext(e: MouseEvent, entry: FileEntry) {
    e.preventDefault();
    e.stopPropagation();
    if (!sel.selected.has(entry.path)) setSel(clickSelect(sel, order, entry.path, {}));
    setMenu({ x: e.clientX, y: e.clientY });
  }

  // The actions that make sense for what's selected (toolbar and right-click menu share them).
  const actions: { id: string; label: string; icon: ReactNode; run: () => void; danger?: boolean }[] = [];
  if (one && isDoc(one)) {
    actions.push({ id: "open", label: "Open in editor", icon: <DocumentIcon size={16} />, run: () => open(one) });
    actions.push({ id: "view", label: "Open read only", icon: <EyeIcon size={16} />, run: () => openDoc?.(share.id, one.path, one.name, "view") });
  } else if (one)
    actions.push({
      id: "open",
      label: one.dir ? "Open" : previewable(one) ? "Preview" : "Download",
      icon: one.dir ? <KindIcon kind="folder" size={16} /> : <EyeIcon size={16} />,
      run: () => open(one),
    });
  if (selected.length > 0)
    actions.push({
      id: "download",
      label: selected.length > 1 || one?.dir ? "Download as zip" : "Download",
      icon: <DownloadIcon size={16} />,
      run: () => download(selected),
    });
  if (one && canShare(one)) actions.push({ id: "link", label: "Share link", icon: <LinkIcon size={16} />, run: () => setDialog({ kind: "link", entry: one }) });
  if (one?.writable) actions.push({ id: "rename", label: "Rename", icon: <EditIcon size={16} />, run: () => setDialog({ kind: "rename", entry: one }) });
  if (selected.length > 0 && selected.every((x) => x.writable))
    actions.push({ id: "move", label: "Move to…", icon: <MoveIcon size={16} />, run: () => setDialog({ kind: "move", paths: selected.map((x) => x.path) }) });
  if (selected.length > 0)
    actions.push({ id: "copy", label: "Copy to…", icon: <CopyIcon size={16} />, run: () => setDialog({ kind: "copy", paths: selected.map((x) => x.path) }) });
  if (one) actions.push({ id: "versions", label: "Previous versions", icon: <HistoryIcon size={16} />, run: () => setVersions(one) });
  if (one) actions.push({ id: "props", label: "Properties", icon: <InfoIcon size={16} />, run: () => setDialog({ kind: "props", entry: one }) });
  if (selected.length > 0 && selected.every((x) => x.writable))
    actions.push({ id: "delete", label: "Delete", icon: <TrashIcon size={16} />, danger: true, run: () => setDialog({ kind: "delete", entries: selected }) });

  const totalSize = selected.reduce((n, e) => n + (e.dir ? 0 : e.size), 0);
  const notFound = q.isError && q.error instanceof ApiFailure && q.error.status === 404;
  const noAccess = q.isError && q.error instanceof ApiFailure && q.error.status === 403;

  return (
    <div
      className={`fm-folder ${versions ? "has-panel" : ""}`}
      onDragEnter={(e) => {
        if (!hasFiles(e)) return;
        dragDepth.current++;
        setDragging(true);
      }}
      onDragOver={(e) => {
        if (!hasFiles(e)) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = canWrite ? "copy" : "none";
      }}
      onDragLeave={(e) => {
        if (!hasFiles(e)) return;
        if (--dragDepth.current <= 0) setDragging(false);
      }}
      onDrop={onDrop}
    >
      <div className="fm-content">
        <div className="fm-content__inner">
          <div className="fm-toolbar" role="toolbar" aria-label="Folder">
            <button
              type="button"
              className="icon-btn"
              aria-label="Up one folder"
              title="Up one folder (Backspace)"
              disabled={!path}
              onClick={() => onNavigate(parent(path))}
            >
              <UpIcon size={17} />
            </button>
            <nav className="fm-crumbs" aria-label="Path">
              <button type="button" className="fm-crumb" onClick={() => onNavigate("")} aria-current={path === "" ? "location" : undefined}>
                {share.id === HOME && <HomeIcon size={15} />}
                {shareName}
              </button>
              {crumbs(path).map((c, i, all) => (
                <span key={c.path} className="fm-crumbs__part">
                  <span className="fm-crumbs__sep" aria-hidden>
                    /
                  </span>
                  <button type="button" className="fm-crumb" onClick={() => onNavigate(c.path)} aria-current={i === all.length - 1 ? "location" : undefined}>
                    {c.name}
                  </button>
                </span>
              ))}
            </nav>
            <div className="fm-toolbar__spacer" />
            <label className="fm-search">
              <SearchIcon size={15} />
              <span className="sr-only">Filter this folder</span>
              <input type="search" placeholder="Filter" value={filter} onChange={(e) => setFilter(e.target.value)} />
            </label>
            <div className="fm-seg" role="group" aria-label="View">
              <button
                type="button"
                className={`fm-seg__btn ${view === "list" ? "is-on" : ""}`}
                aria-pressed={view === "list"}
                aria-label="List view"
                title="List view"
                onClick={() => changeView("list")}
              >
                <ListViewIcon size={16} />
              </button>
              <button
                type="button"
                className={`fm-seg__btn ${view === "grid" ? "is-on" : ""}`}
                aria-pressed={view === "grid"}
                aria-label="Grid view"
                title="Grid view"
                onClick={() => changeView("grid")}
              >
                <GridViewIcon size={16} />
              </button>
            </div>
            <button type="button" className="icon-btn" aria-label="Refresh" title="Refresh" onClick={refresh}>
              <RefreshIcon size={16} />
            </button>
            {canWrite && (
              <>
                <Button size="sm" onClick={() => setDialog({ kind: "mkdir" })} aria-label="New folder" title="New folder">
                  <NewFolderIcon size={16} />
                  <span className="fm-btn-label">New folder</span>
                </Button>
                {canNewDoc && (
                  <Button size="sm" onClick={() => setDialog({ kind: "newdoc" })} aria-label="New document" title="New document, spreadsheet or presentation">
                    <DocumentIcon size={16} />
                    <span className="fm-btn-label">New document</span>
                  </Button>
                )}
                <Button size="sm" variant="primary" onClick={() => fileInput.current?.click()} aria-label="Upload" title="Upload files">
                  <UploadIcon size={16} />
                  <span className="fm-btn-label">Upload</span>
                </Button>
                <input
                  ref={fileInput}
                  type="file"
                  multiple
                  hidden
                  data-testid="upload-input"
                  onChange={(e) => {
                    startUpload(Array.from(e.target.files ?? []));
                    e.target.value = "";
                  }}
                />
              </>
            )}
          </div>

          <div className={`fm-actions ${selected.length ? "is-on" : ""}`} role="toolbar" aria-label="Selection">
            {selected.length > 0 ? (
              <>
                <span className="fm-actions__count">
                  {selected.length} selected
                  {totalSize > 0 && <span className="mono muted"> · {bytes(totalSize)}</span>}
                </span>
                {actions
                  .filter((a) => a.id !== "open")
                  .map((a) => (
                    <Button key={a.id} size="sm" variant={a.danger ? "danger" : "ghost"} onClick={a.run} aria-label={a.label} title={a.label}>
                      {a.icon}
                      <span className="fm-btn-label">{a.label}</span>
                    </Button>
                  ))}
              </>
            ) : (
              <span className="small muted fm-actions__hint">
                {!canWrite ? (
                  <Badge tone="neutral">Read only</Badge>
                ) : share.recycle ? (
                  "Deleted items go to this folder's recycle bin."
                ) : (
                  "This folder has no recycle bin: deleting is for good."
                )}
              </span>
            )}
          </div>

          {busy && (
            <div className="fm-busy" role="status">
              <span className="spinner" style={{ width: 14, height: 14 }} aria-hidden /> {busy}
            </div>
          )}

          <div
            ref={listRef}
            className={`fm-list fm-list--${view}`}
            role="listbox"
            aria-label={`Files in ${path ? basename(path) : shareName}`}
            aria-multiselectable="true"
            aria-activedescendant={sel.focus ? itemId(sel.focus) : undefined}
            tabIndex={0}
            onKeyDown={onKeyDown}
            onClick={() => {
              setSel(emptySelection());
              setMenu(null);
            }}
            onContextMenu={(e) => {
              e.preventDefault();
              setSel(emptySelection());
              setMenu(canWrite ? { x: e.clientX, y: e.clientY } : null);
            }}
          >
            {q.isPending ? (
              <Loading />
            ) : q.isError ? (
              <div className="fm-center">
                {notFound ? (
                  <EmptyState title="This folder isn't there any more" action={<Button onClick={() => onNavigate(parent(path))}>Go up</Button>}>
                    It may have been moved, renamed or deleted.
                  </EmptyState>
                ) : noAccess ? (
                  <EmptyState title="You can't open this folder">You don't have access to it. Ask an administrator if you need it.</EmptyState>
                ) : (
                  <Alert
                    tone="bad"
                    title="Couldn't open this folder"
                    action={
                      <Button size="sm" onClick={() => q.refetch()}>
                        Try again
                      </Button>
                    }
                  >
                    {errorMessage(q.error)}
                  </Alert>
                )}
              </div>
            ) : entries.length === 0 ? (
              <div className="fm-center">
                {filter ? (
                  <EmptyState title="Nothing matches">No names here contain “{filter}”.</EmptyState>
                ) : (
                  <EmptyState
                    icon={<KindIcon kind="folder" size={30} />}
                    title="This folder is empty"
                    action={
                      canWrite ? (
                        <Button variant="primary" onClick={() => fileInput.current?.click()}>
                          <UploadIcon size={16} /> Upload files
                        </Button>
                      ) : undefined
                    }
                  >
                    {canWrite ? "Drag files here to upload them, or make a new folder." : "There's nothing here yet."}
                  </EmptyState>
                )}
              </div>
            ) : view === "list" ? (
              <ListView
                entries={entries}
                idOf={itemId}
                sel={sel}
                sort={sort}
                onSort={changeSort}
                onClick={onItemClick}
                onOpen={open}
                onContext={onItemContext}
              />
            ) : (
              <GridView entries={entries} idOf={itemId} sel={sel} share={share.id} onClick={onItemClick} onOpen={open} onContext={onItemContext} />
            )}
          </div>

          <footer className="fm-status">
            <span>
              {entries.length} item{entries.length === 1 ? "" : "s"}
            </span>
            {selected.length > 0 && <span>{selected.length} selected</span>}
          </footer>

          {dragging && (
            <div className={`fm-drop ${canWrite ? "" : "is-denied"}`} aria-hidden>
              <UploadIcon size={30} />
              <strong>{canWrite ? `Drop to upload to ${path ? basename(path) : shareName}` : "This folder is read only"}</strong>
            </div>
          )}
        </div>
      </div>

      {versions && <VersionsPanel share={share.id} entry={versions} canWrite={canWrite} onClose={() => setVersions(null)} />}

      {menu && (
        <ContextMenu x={menu.x} y={menu.y} onClose={() => setMenu(null)}>
          {selected.length === 0 ? (
            <>
              <MenuItem icon={<NewFolderIcon size={16} />} label="New folder" onClick={() => setDialog({ kind: "mkdir" })} />
              {canNewDoc && <MenuItem icon={<DocumentIcon size={16} />} label="New document…" onClick={() => setDialog({ kind: "newdoc" })} />}
              <MenuItem icon={<UploadIcon size={16} />} label="Upload files" onClick={() => fileInput.current?.click()} />
            </>
          ) : (
            actions.map((a) => <MenuItem key={a.id} icon={a.icon} label={a.label} danger={a.danger} onClick={a.run} />)
          )}
        </ContextMenu>
      )}

      {preview !== null && previews[preview] && (
        <Preview share={share.id} entries={previews} index={preview} onIndex={setPreview} onClose={() => setPreview(null)} />
      )}

      {dialog?.kind === "mkdir" && (
        <NameDialog
          title="New folder"
          label="Folder name"
          initial=""
          action="Create"
          taken={names}
          onClose={() => setDialog(null)}
          onSave={async (name) => {
            await mkdir(share.id, join(path, name));
            refresh();
            setSel(clickSelect(emptySelection(), [join(path, name)], join(path, name), {}));
          }}
        />
      )}
      {dialog?.kind === "rename" && (
        <NameDialog
          title={`Rename “${dialog.entry.name}”`}
          label="New name"
          initial={dialog.entry.name}
          action="Rename"
          taken={names}
          onClose={() => setDialog(null)}
          onSave={async (name) => {
            await rename(share.id, dialog.entry.path, name);
            refresh();
            const p = join(path, name);
            setSel({ selected: new Set([p]), anchor: p, focus: p });
          }}
        />
      )}
      {(dialog?.kind === "move" || dialog?.kind === "copy") && (
        <FolderPicker
          op={dialog.kind}
          shares={shares}
          count={dialog.paths.length}
          from={{ share: share.id, dir: path, paths: dialog.paths }}
          onClose={() => setDialog(null)}
          onPick={async (toShare, toDir) => {
            const verb = dialog.kind === "move" ? "Moving" : "Copying";
            const n = dialog.paths.length;
            setDialog(null);
            try {
              await run(`${verb} ${n === 1 ? basename(dialog.paths[0]!) : `${n} items`}…`, (progress) =>
                transfer(dialog.kind as "move" | "copy", share.id, dialog.paths, toShare, toDir, (j) => progress(j.progress)),
              );
              void qc.invalidateQueries({ queryKey: listingKey(toShare, toDir) });
              const where = toShare === HOME ? "Home" : (shares.find((s) => s.id === toShare)?.name ?? toShare);
              toast(
                "success",
                `${dialog.kind === "move" ? "Moved" : "Copied"} ${n === 1 ? `“${basename(dialog.paths[0]!)}”` : `${n} items`}`,
                `To ${where}${toDir ? ` / ${toDir}` : ""}`,
              );
            } catch (err) {
              toast("error", `Couldn't ${dialog.kind} ${n === 1 ? "it" : "them"}`, errorMessage(err));
            }
          }}
        />
      )}
      {dialog?.kind === "delete" && (
        <DeleteDialog
          names={dialog.entries.map((e) => e.name)}
          recycle={share.recycle}
          onClose={() => setDialog(null)}
          onConfirm={async () => {
            const n = dialog.entries.length;
            const recycled = await run(`Deleting ${n === 1 ? dialog.entries[0]!.name : `${n} items`}…`, (progress) =>
              remove(
                share.id,
                dialog.entries.map((e) => e.path),
                (j) => progress(j.progress),
              ),
            );
            setSel(emptySelection());
            toast("success", recycled ? "Moved to the recycle bin" : "Deleted", n === 1 ? dialog.entries[0]!.name : `${n} items`);
          }}
        />
      )}
      {dialog?.kind === "props" && <PropertiesDialog entry={dialog.entry} shareName={shareName} onClose={() => setDialog(null)} />}
      {dialog?.kind === "link" && <ShareLinkDialog share={share.id} entry={dialog.entry} office={office.data} onClose={() => setDialog(null)} />}
      {dialog?.kind === "newdoc" && (
        <NewDocumentDialog
          share={share.id}
          dir={path}
          taken={names}
          onClose={() => setDialog(null)}
          onCreated={(e) => {
            refresh();
            setSel({ selected: new Set([e.path]), anchor: e.path, focus: e.path });
            openDoc?.(share.id, e.path, e.name, "edit");
          }}
        />
      )}
    </div>
  );
}

function gridColumns(el: HTMLElement | null): number {
  const first = el?.querySelector<HTMLElement>(".fm-tile");
  if (!el || !first || !first.offsetWidth) return 1;
  return Math.max(1, Math.floor(el.clientWidth / first.offsetWidth));
}

interface ItemHandlers {
  sel: Selection;
  idOf: (path: string) => string;
  onClick: (e: MouseEvent, entry: FileEntry) => void;
  onOpen: (entry: FileEntry) => void;
  onContext: (e: MouseEvent, entry: FileEntry) => void;
}

function SortHeader({ label, k, sort, onSort, className = "" }: { label: string; k: SortKey; sort: Sort; onSort: (k: SortKey) => void; className?: string }) {
  const on = sort.key === k;
  return (
    <div role="columnheader" className={`fm-row__cell ${className}`} aria-sort={on ? (sort.asc ? "ascending" : "descending") : "none"}>
      <button
        type="button"
        className={`fm-sort ${on ? "is-on" : ""}`}
        onClick={(e) => {
          e.stopPropagation();
          onSort(k);
        }}
      >
        {label}
        {on && <span aria-hidden>{sort.asc ? " ↑" : " ↓"}</span>}
      </button>
    </div>
  );
}

function ListView({ entries, sort, onSort, ...h }: ItemHandlers & { entries: FileEntry[]; sort: Sort; onSort: (k: SortKey) => void }) {
  return (
    <>
      <div className="fm-row fm-row--head" role="presentation">
        <SortHeader label="Name" k="name" sort={sort} onSort={onSort} className="fm-row__name" />
        <SortHeader label="Changed" k="modified" sort={sort} onSort={onSort} className="fm-row__date" />
        <SortHeader label="Size" k="size" sort={sort} onSort={onSort} className="fm-row__size" />
      </div>
      {entries.map((e) => {
        const on = h.sel.selected.has(e.path);
        return (
          <div
            key={e.path}
            id={h.idOf(e.path)}
            data-path={e.path}
            role="option"
            aria-selected={on}
            className={`fm-row ${on ? "is-selected" : ""} ${h.sel.focus === e.path ? "is-focus" : ""}`}
            onClick={(ev) => h.onClick(ev, e)}
            onDoubleClick={() => h.onOpen(e)}
            onContextMenu={(ev) => h.onContext(ev, e)}
          >
            <div className="fm-row__cell fm-row__name">
              <KindIcon kind={kindOf(e)} size={18} />
              <span className="fm-ellipsis">{e.name}</span>
            </div>
            <div className="fm-row__cell fm-row__date" title={dateTime(e.modified)}>
              {relativeTime(e.modified)}
            </div>
            <div className="fm-row__cell fm-row__size mono">{e.dir ? "–" : bytes(e.size)}</div>
          </div>
        );
      })}
    </>
  );
}

function GridView({ entries, share, ...h }: ItemHandlers & { entries: FileEntry[]; share: string }) {
  return (
    <>
      {entries.map((e) => {
        const on = h.sel.selected.has(e.path);
        const kind = kindOf(e);
        return (
          <div
            key={e.path}
            id={h.idOf(e.path)}
            data-path={e.path}
            role="option"
            aria-selected={on}
            className={`fm-tile ${on ? "is-selected" : ""} ${h.sel.focus === e.path ? "is-focus" : ""}`}
            onClick={(ev) => h.onClick(ev, e)}
            onDoubleClick={() => h.onOpen(e)}
            onContextMenu={(ev) => h.onContext(ev, e)}
            title={e.name}
          >
            <div className="fm-tile__art">
              {kind === "image" && e.size < 25_000_000 ? (
                <img src={downloadUrl(share, [e.path], { inline: true })} alt="" loading="lazy" draggable={false} />
              ) : (
                <KindIcon kind={kind} size={40} />
              )}
            </div>
            <span className="fm-tile__name">{e.name}</span>
            <span className="fm-tile__meta mono">{e.dir ? "Folder" : bytes(e.size)}</span>
          </div>
        );
      })}
    </>
  );
}

function ContextMenu({ x, y, children, onClose }: { x: number; y: number; children: ReactNode; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.querySelector<HTMLElement>("button")?.focus();
    const down = (e: globalThis.MouseEvent) => {
      if (!ref.current?.contains(e.target as Node)) onClose();
    };
    const key = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("mousedown", down);
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("mousedown", down);
      document.removeEventListener("keydown", key);
    };
  }, [onClose]);
  // Keep it on screen.
  const left = Math.min(x, window.innerWidth - 240);
  const top = Math.min(y, window.innerHeight - 360);
  return (
    <div ref={ref} className="fm-menu glass" role="menu" style={{ left, top }} onClick={onClose}>
      {children}
    </div>
  );
}

function MenuItem({ icon, label, onClick, danger }: { icon: ReactNode; label: string; onClick: () => void; danger?: boolean }) {
  return (
    <button type="button" role="menuitem" className={`menu-item ${danger ? "fm-menu__danger" : ""}`} onClick={onClick}>
      {icon}
      {label}
    </button>
  );
}
