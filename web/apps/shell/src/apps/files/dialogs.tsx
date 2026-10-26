import type { FileEntry, FileShare, ShareLinkCreated } from "@hardy/api-client";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api, errorMessage, unwrap } from "../../api";
import { bytes, dateTime } from "../../format";
import { Alert, Button, Field, Loading, Select, TextInput, Toggle } from "../../ui";
import { ConfirmDialog, Dialog } from "../../ui/Dialog";
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

/** Makes a share link for one file or folder, then shows it once to copy. */
export function ShareLinkDialog({ share, entry, onClose }: { share: string; entry: FileEntry; onClose: () => void }) {
  const [days, setDays] = useState(7);
  const [usePassword, setUsePassword] = useState(false);
  const [password, setPassword] = useState("");
  const [upload, setUpload] = useState(false);
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
            maxDownloads: limitN || undefined,
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
    const url = new URL(made.url, window.location.origin).toString();
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
        <Field label="Download limit" hint="Empty for no limit." error={limitProblem}>
          {(id) => <TextInput id={id} inputMode="numeric" value={limit} onChange={(e) => setLimit(e.target.value)} placeholder="No limit" />}
        </Field>
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
    </Dialog>
  );
}
