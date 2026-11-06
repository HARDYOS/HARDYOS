import type { FileEntry, FileShare, OfficeStatus, ShareLinkAccess, ShareLinkCreated } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes, dateTime } from "../../format";
import { Alert, Button, Field, Loading, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
import { NEW_KINDS, type NewKind, editableFormat, newDocument } from "../office/officeApi";
import { HomeIcon, KindIcon } from "./icons";
import { HOME, basename, crumbs, kindOf, nameProblem, parent } from "./paths";

/** New folder or rename: one name field, checked as you type. */
export function NameDialog({
  title,
  label,
  initial = "",
  action,
  taken,
  onSave,
  onClose,
}: {
  title: string;
  label: string;
  initial?: string;
  action: string;
  taken: string[];
  onSave: (name: string) => Promise<unknown>;
  onClose: () => void;
}) {
  const [name, setName] = useState(initial);
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const problem = nameProblem(
    name,
    taken.filter((t) => t !== initial),
  );
  const unchanged = initial !== "" && name.trim() === initial;

  async function save() {
    setTouched(true);
    if (problem || unchanged) return;
    setBusy(true);
    setError(null);
    try {
      await onSave(name.trim());
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <Dialog
      title={title}
      onClose={onClose}
      onSubmit={save}
      width={420}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={busy} disabled={!!problem || unchanged}>
            {action}
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label={label} error={touched || name !== initial ? problem : null}>
          {(id) => (
            <TextInput
              id={id}
              value={name}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => setName(e.target.value)}
              onFocus={(e) => {
                // Select the name without its extension, like desktop file managers.
                const dot = initial.lastIndexOf(".");
                if (initial && dot > 0) e.currentTarget.setSelectionRange(0, dot);
                else e.currentTarget.select();
              }}
            />
          )}
        </Field>
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
    </Dialog>
  );
}

/** Picks a folder to move or copy into: any writable shared folder or Home, any folder in it. */
export function FolderPicker({
  op,
  shares,
  count,
  from,
  onPick,
  onClose,
}: {
  op: "move" | "copy";
  shares: FileShare[];
  count: number;
  from: { share: string; dir: string; paths: string[] };
  onPick: (toShare: string, toDir: string) => Promise<unknown>;
  onClose: () => void;
}) {
  const writable = shares.filter((s) => s.writable);
  const [share, setShare] = useState(writable.some((s) => s.id === from.share) ? from.share : (writable[0]?.id ?? ""));
  const [dir, setDir] = useState(share === from.share ? from.dir : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const list = useQuery({
    queryKey: ["files", "list", share, dir],
    queryFn: () => unwrap(api.GET("/files/list", { params: { query: { share, path: dir } } })).then((r) => r.entries),
    enabled: !!share,
  });
  const folders = (list.data ?? []).filter((e) => e.dir);
  const shareName = shares.find((s) => s.id === share)?.name ?? share;
  // Can't move a folder into itself or where it already is.
  const intoItself = share === from.share && from.paths.some((p) => dir === p || dir.startsWith(`${p}/`));
  const samePlace = op === "move" && share === from.share && dir === from.dir;
  const verb = op === "move" ? "Move" : "Copy";

  async function go() {
    setBusy(true);
    setError(null);
    try {
      await onPick(share, dir);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <Dialog
      title={`${verb} ${count === 1 ? `“${basename(from.paths[0] ?? "")}”` : `${count} items`}`}
      onClose={onClose}
      width={520}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" busy={busy} disabled={!share || intoItself || samePlace} onClick={go}>
            {verb} here
          </Button>
        </>
      }
    >
      <div className="stack">
        {writable.length === 0 ? (
          <Alert tone="warn">There's no folder you can change.</Alert>
        ) : (
          <>
            <Field label="Folder">
              {(id) => (
                <Select
                  id={id}
                  value={share}
                  onChange={(e) => {
                    setShare(e.target.value);
                    setDir("");
                  }}
                >
                  {writable.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.id === HOME ? "Home" : s.name}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <nav className="fm-crumbs fm-crumbs--small" aria-label="Destination">
              <button type="button" className="fm-crumb" onClick={() => setDir("")}>
                {share === HOME ? <HomeIcon size={14} /> : null} {share === HOME ? "Home" : shareName}
              </button>
              {crumbs(dir).map((c) => (
                <span key={c.path} className="fm-crumbs__part">
                  <span className="fm-crumbs__sep" aria-hidden>
                    /
                  </span>
                  <button type="button" className="fm-crumb" onClick={() => setDir(c.path)}>
                    {c.name}
                  </button>
                </span>
              ))}
            </nav>
            <div className="fm-picker" role="listbox" aria-label="Folders">
              {list.isPending ? (
                <Loading />
              ) : list.isError ? (
                <Alert tone="bad">{errorMessage(list.error)}</Alert>
              ) : folders.length === 0 ? (
                <p className="small muted fm-picker__empty">No folders in here.</p>
              ) : (
                folders.map((f) => (
                  <button
                    type="button"
                    role="option"
                    aria-selected={false}
                    key={f.path}
                    className="fm-picker__item"
                    onDoubleClick={() => setDir(f.path)}
                    onClick={() => setDir(f.path)}
                  >
                    <KindIcon kind="folder" size={16} /> {f.name}
                  </button>
                ))
              )}
            </div>
            {dir && (
              <button type="button" className="link-button small" onClick={() => setDir(parent(dir))}>
                Up one folder
              </button>
            )}
            {intoItself && <Alert tone="warn">A folder can't go inside itself.</Alert>}
          </>
        )}
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
    </Dialog>
  );
}

/** Delete confirmation that says plainly whether things can be got back. */
export function DeleteDialog({
  names,
  recycle,
  onConfirm,
  onClose,
}: {
  names: string[];
  recycle: boolean;
  onConfirm: () => Promise<unknown>;
  onClose: () => void;
}) {
  const what = names.length === 1 ? `“${names[0]}”` : `${names.length} items`;
  return (
    <ConfirmDialog title={`Delete ${what}?`} confirmLabel={recycle ? "Move to recycle bin" : "Delete for good"} danger onConfirm={onConfirm} onClose={onClose}>
      {recycle ? (
        <p>
          {names.length === 1 ? "It goes" : "They go"} to this folder's recycle bin, where {names.length === 1 ? "it's" : "they're"} kept for 30 days. An
          administrator can get {names.length === 1 ? "it" : "them"} back from there.
        </p>
      ) : (
        <p>This folder has no recycle bin, so {names.length === 1 ? "it's" : "they're"} gone for good, unless an older version is kept in a snapshot.</p>
      )}
    </ConfirmDialog>
  );
}

export function PropertiesDialog({ entry, shareName, onClose }: { entry: FileEntry; shareName: string; onClose: () => void }) {
  const kind = kindOf(entry);
  return (
    <Dialog title="Properties" onClose={onClose} width={440} footer={<Button onClick={onClose}>Close</Button>}>
      <div className="fm-props">
        <div className="fm-props__head">
          <KindIcon kind={kind} size={32} />
          <strong className="fm-props__name">{entry.name}</strong>
        </div>
        <dl className="kv">
          <dt>Kind</dt>
          <dd>{entry.dir ? "Folder" : kindLabel(entry.name, kind)}</dd>
          <dt>Where</dt>
          <dd>
            {shareName}
            {parent(entry.path) ? ` / ${parent(entry.path)}` : ""}
          </dd>
          {!entry.dir && (
            <>
              <dt>Size</dt>
              <dd className="mono">
                {bytes(entry.size)} ({entry.size.toLocaleString()} bytes)
              </dd>
            </>
          )}
          <dt>Changed</dt>
          <dd>{dateTime(entry.modified)}</dd>
          <dt>You can</dt>
          <dd>{entry.writable ? "Open and change it" : "Only open it"}</dd>
        </dl>
      </div>
    </Dialog>
  );
}

function kindLabel(name: string, kind: string): string {
  const dot = name.lastIndexOf(".");
  const ext = dot > 0 ? name.slice(dot + 1).toUpperCase() : "";
  const label: Record<string, string> = {
    image: "Image",
    video: "Video",
    audio: "Audio",
    pdf: "PDF document",
    text: "Text",
    archive: "Archive",
    doc: "Document",
    file: "File",
  };
  return ext && kind !== "pdf" ? `${label[kind]} (${ext})` : (label[kind] ?? "File");
}

const EXPIRY = [1, 7, 30, 90];
const GB = 1_000_000_000;
/** How much an upload link may take in, in all (the server's default is 10 GB). */
const UPLOAD_BUDGETS = [1 * GB, 5 * GB, 10 * GB, 50 * GB, 100 * GB, 500 * GB, 1000 * GB];

/** Makes a share link for one file or folder, then shows it once to copy. */
/** "New document": a kind and a name; the empty file is made as the person and opened. */
export function NewDocumentDialog({
  share,
  dir,
  taken,
  onCreated,
  onClose,
}: {
  share: string;
  dir: string;
  taken: string[];
  onCreated: (e: FileEntry) => void;
  onClose: () => void;
}) {
  const [kind, setKind] = useState<NewKind>("document");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const k = NEW_KINDS.find((x) => x.kind === kind)!;
  const base = name.trim() || k.fallback;
  const full = base.toLowerCase().endsWith(`.${k.ext}`) ? base : `${base}.${k.ext}`;
  const problem = nameProblem(full, taken);

  async function create() {
    if (problem) return;
    setBusy(true);
    setError(null);
    try {
      const e = await newDocument(share, dir, kind, full);
      onCreated(e);
      onClose();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  return (
    <Dialog
      title="New document"
      description="An empty file in this folder, opened in the editor."
      onClose={onClose}
      onSubmit={create}
      width={440}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={busy} disabled={!!problem}>
            Create and open
          </Button>
        </>
      }
    >
      <div className="stack">
        <div className="fm-kinds" role="radiogroup" aria-label="Kind">
          {NEW_KINDS.map((x) => (
            <label key={x.kind} className={`fm-kind ${kind === x.kind ? "is-on" : ""}`}>
              <input type="radio" name="kind" value={x.kind} checked={kind === x.kind} onChange={() => setKind(x.kind)} />
              <span>{x.label}</span>
              <span className="small muted mono">.{x.ext}</span>
            </label>
          ))}
        </div>
        <Field label="Name" error={name ? problem : null} hint={`Saved as ${full}`}>
          {(id) => <TextInput id={id} value={name} placeholder={k.fallback} onChange={(e) => setName(e.target.value)} />}
        </Field>
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
    </Dialog>
  );
}

export function ShareLinkDialog({ share, entry, office, onClose }: { share: string; entry: FileEntry; office?: OfficeStatus; onClose: () => void }) {
  const [days, setDays] = useState(7);
  // Editing in the browser: only when the office suite is on, for folders
  // and documents the editor saves, and only when picked (decision 256).
  const canEditLink = !!office?.enabled && (entry.dir || editableFormat(office, entry.name));
  const [access, setAccess] = useState<ShareLinkAccess>("view");
  const [usePassword, setUsePassword] = useState(false);
  const [password, setPassword] = useState("");
  const [upload, setUpload] = useState(false);
  const [budget, setBudget] = useState(10 * GB);
  const [limit, setLimit] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [made, setMade] = useState<ShareLinkCreated | null>(null);
  const [copied, setCopied] = useState(false);
  const pwProblem = usePassword && password.length < 6 ? "Use at least 6 characters." : null;
  const limitN = limit.trim() === "" ? 0 : Number(limit);
  const limitProblem = !Number.isInteger(limitN) || limitN < 0 || limitN > 100000 ? "A whole number, or empty for no limit." : null;

  async function create() {
    if (pwProblem || limitProblem) return;
    setBusy(true);
    setError(null);
    try {
      const res = await unwrap(
        api.POST("/sharelinks", {
          body: {
            share,
            path: entry.path,
            expiresInDays: days,
            password: usePassword ? password : undefined,
            allowUpload: entry.dir ? upload : undefined,
            maxUploadBytes: entry.dir && upload ? budget : undefined,
            maxDownloads: limitN || undefined,
            access: canEditLink ? access : undefined,
          },
        }),
      );
      setMade(res);
    } catch (err) {
      setError(errorMessage(err));
    }
    setBusy(false);
  }

  if (made) {
    // Through NetBird's reverse proxy (files.<base>) when published, so people
    // without NetBird can open it; else this desktop's own address.
    const url = made.publicUrl || new URL(made.url, window.location.origin).toString();
    return (
      <Dialog
        title="Link ready"
        onClose={onClose}
        width={520}
        footer={
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        }
      >
        <div className="stack">
          <p className="dialog__text">
            Anyone with this link can {entry.dir ? "open this folder" : "download this file"}
            {made.link.access === "edit" ? (entry.dir ? " and edit the documents in it in their browser" : " and edit it in their browser") : ""}
            {made.link.hasPassword ? " once they enter the password" : ""} until <strong>{dateTime(made.link.expiresAt)}</strong>.
          </p>
          <div className="fm-linkbox">
            <TextInput readOnly value={url} aria-label="Share link" onFocus={(e) => e.currentTarget.select()} />
            <Button
              onClick={() => {
                void navigator.clipboard?.writeText(url).then(
                  () => setCopied(true),
                  () => setCopied(false),
                );
              }}
            >
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <Alert tone="info">
            Copy it now: for safety HardyOS keeps only a fingerprint of the link, so it can't show it again. You can turn it off any time under Links I've
            shared.
          </Alert>
          <p className="small muted">It works on your home network now; from outside once remote access is set up.</p>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog
      title={`Share “${entry.name}”`}
      description="Make a link people can open without an account."
      onClose={onClose}
      onSubmit={create}
      width={480}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={busy} disabled={!!pwProblem || !!limitProblem}>
            Create link
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="Works for">
          {(id) => (
            <Select id={id} value={days} onChange={(e) => setDays(Number(e.target.value))}>
              {EXPIRY.map((d) => (
                <option key={d} value={d}>
                  {d === 1 ? "1 day" : `${d} days`}
                </option>
              ))}
            </Select>
          )}
        </Field>
        {canEditLink && (
          <Field label="People can" hint={entry.dir ? "Applies to documents in the folder." : undefined}>
            {(id) => (
              <Select id={id} value={access} onChange={(e) => setAccess(e.target.value as ShareLinkAccess)}>
                <option value="view">View{entry.dir ? " and download" : ""} only</option>
                <option value="edit">Edit in their browser</option>
              </Select>
            )}
          </Field>
        )}
        {canEditLink && access === "edit" && (
          <Alert tone="warn" title="Anyone with the link can change the document">
            Their changes are saved as you, over the shared copy. Older versions stay in Previous versions. Consider a password and a short expiry.
          </Alert>
        )}
        <Toggle label="Ask for a password" checked={usePassword} onChange={setUsePassword} />
        {usePassword && (
          <Field label="Password" error={password ? pwProblem : null} hint="Tell people the password some other way than the link.">
            {(id) => <TextInput id={id} type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />}
          </Field>
        )}
        {entry.dir && (
          <Toggle
            label="Let people add files"
            description="They can upload into this folder, but not change or delete anything."
            checked={upload}
            onChange={setUpload}
          />
        )}
        {entry.dir && upload && (
          <Field label="Upload limit" hint="The most people can add through this link, in all. One file can be up to 5 GB.">
            {(id) => (
              <Select id={id} value={budget} onChange={(e) => setBudget(Number(e.target.value))}>
                {UPLOAD_BUDGETS.map((b) => (
                  <option key={b} value={b}>
                    {bytes(b)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        )}
        <Field label="Download limit" hint="Empty for no limit." error={limitProblem}>
          {(id) => <TextInput id={id} inputMode="numeric" value={limit} onChange={(e) => setLimit(e.target.value)} placeholder="No limit" />}
        </Field>
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
    </Dialog>
  );
}
