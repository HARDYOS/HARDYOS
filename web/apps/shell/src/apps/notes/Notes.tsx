import type { FileEntry, FileShare } from "@hardy/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiFailure, api, errorMessage, unwrap } from "../../api";
import { relativeTime } from "../../format";
import { NotesIcon, PlusIcon, SearchIcon, TrashIcon } from "../../icons";
import { Alert, Badge, Button, EmptyState, Field, Loading, Select, TextInput } from "../../ui";
import { Dialog } from "../../ui/Dialog";
import { toast } from "../../ui/toasts";
import { listingKey, mkdir, remove, uploadFile, useFileShares, useListing } from "../files/fileApi";
import { HOME, downloadUrl, join, nameProblem } from "../files/paths";
import { Markdown } from "./markdown";
import "./notes.css";

// Notes: Markdown files in a folder you choose (Home/Notes by default, or a
// shared folder as a family wiki). Every read and write goes through the
// files API as the signed-in person, so the folder's permissions, snapshots
// (Previous Versions), backups and search all apply as to any other file.

export interface NotesPlace {
  share: string;
  dir: string;
}

const PLACE_KEY = "hardyos.notes.place";

export function loadPlace(): NotesPlace {
  try {
    const v = JSON.parse(localStorage.getItem(PLACE_KEY) ?? "null") as NotesPlace | null;
    if (v && typeof v.share === "string" && typeof v.dir === "string") return v;
  } catch {
    /* nothing remembered */
  }
  return { share: HOME, dir: "Notes" };
}

function savePlace(p: NotesPlace) {
  try {
    localStorage.setItem(PLACE_KEY, JSON.stringify(p));
  } catch {
    /* private window */
  }
}

export const isNote = (e: Pick<FileEntry, "name" | "dir">) => !e.dir && /\.(md|markdown)$/i.test(e.name);

/** "Shopping list.md" -> "Shopping list". */
export const noteTitle = (name: string) => name.replace(/\.(md|markdown)$/i, "");

/** A file name for a note title (".md" added). */
export const noteFile = (title: string) => (/\.(md|markdown)$/i.test(title.trim()) ? title.trim() : `${title.trim()}.md`);

async function readNote(share: string, path: string): Promise<string> {
  const res = await fetch(downloadUrl(share, [path]), { credentials: "same-origin" });
  if (!res.ok) throw new ApiFailure(res.status, "read", res.status === 404 ? "That note isn't there any more." : "Couldn't read the note.");
  return res.text();
}

const stat = (share: string, path: string) => unwrap(api.GET("/files/stat", { params: { query: { share, path } } }));

async function writeNote(share: string, path: string, text: string, overwrite: boolean): Promise<FileEntry | undefined> {
  const name = path.split("/").pop() ?? path;
  return uploadFile(new File([text], name, { type: "text/markdown" }), share, path, { overwrite });
}

export default function Notes() {
  return <NotesView />;
}

export function NotesView({ initial }: { initial?: NotesPlace }) {
  const shares = useFileShares();
  const [place, setPlace] = useState<NotesPlace>(() => initial ?? loadPlace());
  const [picking, setPicking] = useState(false);
  const list = shares.data ?? [];
  const share = list.find((s) => s.id === place.share);

  const choose = (p: NotesPlace) => {
    setPlace(p);
    savePlace(p);
  };

  if (shares.isPending) return <Loading />;
  if (shares.isError)
    return (
      <div className="pad">
        <Alert tone="bad" title="Couldn't load your folders">
          {errorMessage(shares.error)}
        </Alert>
      </div>
    );
  return (
    <div className="notes">
      {share ? (
        <Notebook key={`${place.share}:${place.dir}`} share={share} dir={place.dir} onChangeFolder={() => setPicking(true)} />
      ) : (
        <EmptyState title="Choose where your notes live" icon={<NotesIcon size={30} />} action={<Button onClick={() => setPicking(true)}>Choose a folder</Button>}>
          Notes are Markdown files in a folder: your Home, or a shared folder everyone in the family can write in.
        </EmptyState>
      )}
      {picking && <FolderDialog shares={list} place={place} onClose={() => setPicking(false)} onChoose={choose} />}
    </div>
  );
}

function FolderDialog({ shares, place, onClose, onChoose }: { shares: FileShare[]; place: NotesPlace; onClose: () => void; onChoose: (p: NotesPlace) => void }) {
  const [share, setShare] = useState(shares.some((s) => s.id === place.share) ? place.share : (shares[0]?.id ?? ""));
  const [dir, setDir] = useState(place.dir);
  const clean = dir
    .split("/")
    .map((p) => p.trim())
    .filter(Boolean)
    .join("/");
  const problem = clean
    .split("/")
    .filter(Boolean)
    .map((p) => nameProblem(p))
    .find(Boolean);
  return (
    <Dialog
      title="Where notes live"
      description="A folder of Markdown files. Pick a shared folder to keep a family or team wiki; its permissions decide who can read and edit."
      onClose={onClose}
      onSubmit={() => {
        if (problem || !share) return;
        onChoose({ share, dir: clean });
        onClose();
      }}
      width={460}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={!!problem || !share}>
            Use this folder
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="Shared folder">
          {(id) => (
            <Select id={id} value={share} onChange={(e) => setShare(e.target.value)}>
              {shares.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.id === HOME ? "Home" : s.name}
                  {s.writable ? "" : " (read only)"}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label="Folder inside it" hint="For example Notes, or Family/Wiki. Empty for the top. It's made if it isn't there." error={problem ?? null}>
          {(id) => <TextInput id={id} value={dir} onChange={(e) => setDir(e.target.value)} placeholder="Notes" />}
        </Field>
      </div>
    </Dialog>
  );
}

type Loaded = { path: string; text: string; modified: string; writable: boolean };
type SaveState = "saved" | "dirty" | "saving" | "conflict" | "error";

function Notebook({ share, dir, onChangeFolder }: { share: FileShare; dir: string; onChangeFolder: () => void }) {
  const q = useListing(share.id, dir);
  const qc = useQueryClient();
  const [filter, setFilter] = useState("");
  const [current, setCurrent] = useState<Loaded | null>(null);
  const [text, setText] = useState("");
  const [state, setState] = useState<SaveState>("saved");
  const [mode, setMode] = useState<"edit" | "preview" | "split">("split");
  const [newOpen, setNewOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<number | null>(null);
  const missing = q.isError && q.error instanceof ApiFailure && q.error.status === 404;
  const where = `${share.id === HOME ? "Home" : share.name}${dir ? ` / ${dir}` : ""}`;

  const notes = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return (q.data ?? [])
      .filter(isNote)
      .filter((e) => !f || e.name.toLowerCase().includes(f))
      .sort((a, b) => b.modified.localeCompare(a.modified));
  }, [q.data, filter]);
  const refresh = useCallback(() => void qc.invalidateQueries({ queryKey: listingKey(share.id, dir) }), [qc, share.id, dir]);

  async function open(e: FileEntry) {
    if (state === "dirty" && current) await save(true);
    setError(null);
    try {
      const body = await readNote(share.id, e.path);
      setCurrent({ path: e.path, text: body, modified: e.modified, writable: e.writable && share.writable });
      setText(body);
      setState("saved");
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  // Saves the open note. Before writing it checks the file wasn't changed by
  // someone else since it was loaded; if it was, nothing is written and the
  // person chooses.
  const save = useCallback(
    async (quiet = false, force = false): Promise<void> => {
      if (!current || !current.writable) return;
      if (timer.current) window.clearTimeout(timer.current);
      setState("saving");
      try {
        if (!force) {
          const now = await stat(share.id, current.path).catch(() => null);
          if (now && now.modified !== current.modified) {
            setState("conflict");
            return;
          }
        }
        const e = await writeNote(share.id, current.path, text, true);
        const modified = e?.modified ?? (await stat(share.id, current.path)).modified;
        setCurrent({ ...current, text, modified });
        setState("saved");
        refresh();
      } catch (err) {
        setState("error");
        if (!quiet) toast("error", "Couldn't save the note", errorMessage(err));
        setError(errorMessage(err));
      }
    },
    [current, share.id, text, refresh],
  );

  // Autosave a moment after typing stops.
  useEffect(() => {
    if (state !== "dirty") return;
    timer.current = window.setTimeout(() => void save(true), 1500);
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [state, text, save]);

  // Loads the note as it is on disk now (what someone else saved).
  async function reload() {
    if (!current) return;
    try {
      const e = await stat(share.id, current.path);
      const body = await readNote(share.id, current.path);
      setCurrent({ ...current, text: body, modified: e.modified });
      setText(body);
      setState("saved");
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  async function saveCopy() {
    if (!current) return;
    const base = noteTitle(current.path.split("/").pop() ?? "Note");
    const taken = new Set((q.data ?? []).map((e) => e.name.toLowerCase()));
    let n = 2;
    let name = `${base} (my copy).md`;
    while (taken.has(name.toLowerCase())) name = `${base} (my copy ${n++}).md`;
    try {
      const e = await writeNote(share.id, join(dir, name), text, false);
      refresh();
      if (e) await open(e);
      toast("success", "Saved as a copy", name);
    } catch (err) {
      toast("error", "Couldn't save a copy", errorMessage(err));
    }
  }

  async function create(title: string) {
    const name = noteFile(title);
    if (missing) await mkdir(share.id, dir).catch(() => undefined);
    const e = await writeNote(share.id, join(dir, name), `# ${noteTitle(name)}\n\n`, false);
    refresh();
    if (e) await open(e);
  }

  async function openByName(title: string) {
    const name = noteFile(title).toLowerCase();
    const found = (q.data ?? []).find((e) => isNote(e) && e.name.toLowerCase() === name);
    if (found) return open(found);
    if (!share.writable) {
      toast("info", `There's no note called “${title}”`);
      return;
    }
    try {
      await create(title);
    } catch (err) {
      toast("error", "Couldn't make the note", errorMessage(err));
    }
  }

  async function del() {
    if (!current) return;
    const name = current.path.split("/").pop() ?? "";
    if (!window.confirm(`Delete “${noteTitle(name)}”?${share.recycle ? " It goes to the folder's recycle bin." : " This folder has no recycle bin."}`)) return;
    try {
      await remove(share.id, [current.path]);
      setCurrent(null);
      setText("");
      refresh();
    } catch (err) {
      toast("error", "Couldn't delete the note", errorMessage(err));
    }
  }

  const status: Record<SaveState, string> = { saved: "Saved", dirty: "Editing…", saving: "Saving…", conflict: "Changed elsewhere", error: "Not saved" };
  const names = (q.data ?? []).map((e) => e.name);

  return (
    <div className="notes-book">
      <aside className="notes-side">
        <div className="notes-side__head">
          <button type="button" className="notes-where" onClick={onChangeFolder} title="Choose another folder">
            <NotesIcon size={15} />
            <span className="notes-ellipsis">{where}</span>
          </button>
          {share.writable && (
            <Button size="sm" variant="primary" onClick={() => setNewOpen(true)} aria-label="New note" title="New note">
              <PlusIcon size={15} />
            </Button>
          )}
        </div>
        <label className="notes-search">
          <SearchIcon size={14} />
          <span className="sr-only">Find a note</span>
          <input type="search" placeholder="Find a note" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </label>
        <nav className="notes-list" aria-label="Notes">
          {q.isPending ? (
            <Loading />
          ) : missing ? (
            <p className="small muted notes-pad">{share.writable ? "No notes here yet. Make the first one with +." : "This folder isn't there."}</p>
          ) : q.isError ? (
            <p className="small notes-pad">{errorMessage(q.error)}</p>
          ) : notes.length === 0 ? (
            <p className="small muted notes-pad">{filter ? "Nothing matches." : "No notes yet."}</p>
          ) : (
            notes.map((e) => (
              <button
                key={e.path}
                type="button"
                className={`notes-item ${current?.path === e.path ? "is-active" : ""}`}
                aria-current={current?.path === e.path ? "page" : undefined}
                onClick={() => void open(e)}
              >
                <span className="notes-ellipsis">{noteTitle(e.name)}</span>
                <span className="small muted">{relativeTime(e.modified)}</span>
              </button>
            ))
          )}
        </nav>
      </aside>
      <section className="notes-main">
        {error && (
          <div className="notes-pad">
            <Alert tone="bad">{error}</Alert>
          </div>
        )}
        {!current ? (
          <EmptyState title="Pick a note" icon={<NotesIcon size={30} />}>
            Notes are plain Markdown files in {where}: they show up in the File Manager, keep older versions in Previous versions, and are backed up with the
            folder. Link notes together with [[Note name]].
          </EmptyState>
        ) : (
          <>
            <div className="notes-bar">
              <strong className="notes-ellipsis">{noteTitle(current.path.split("/").pop() ?? "")}</strong>
              {!current.writable && <Badge>Read only</Badge>}
              {current.writable && <span className={`small notes-state notes-state--${state}`}>{status[state]}</span>}
              <span className="notes-spacer" />
              <div className="fm-seg" role="group" aria-label="View">
                {(["edit", "split", "preview"] as const).map((m) => (
                  <button key={m} type="button" className={`fm-seg__btn ${mode === m ? "is-on" : ""}`} aria-pressed={mode === m} onClick={() => setMode(m)}>
                    {m === "edit" ? "Write" : m === "split" ? "Both" : "Read"}
                  </button>
                ))}
              </div>
              {current.writable && (
                <Button size="sm" variant="ghost" onClick={() => void del()} aria-label="Delete note" title="Delete note">
                  <TrashIcon size={15} />
                </Button>
              )}
            </div>
            {state === "conflict" && (
              <div className="notes-pad">
                <Alert
                  tone="warn"
                  title="Someone else changed this note"
                  action={
                    <div className="row">
                      <Button size="sm" onClick={() => void saveCopy()}>
                        Save mine as a copy
                      </Button>
                      <Button size="sm" onClick={() => void reload()}>
                        Load theirs
                      </Button>
                      <Button size="sm" variant="danger" onClick={() => void save(false, true)}>
                        Keep mine
                      </Button>
                    </div>
                  }
                >
                  It was saved from somewhere else after you opened it. Nothing of yours was written yet.
                </Alert>
              </div>
            )}
            <div className={`notes-panes notes-panes--${mode}`}>
              {mode !== "preview" && (
                <textarea
                  className="notes-text"
                  aria-label="Note text (Markdown)"
                  value={text}
                  readOnly={!current.writable}
                  spellCheck
                  onChange={(e) => {
                    setText(e.target.value);
                    if (state !== "conflict") setState("dirty");
                  }}
                  onKeyDown={(e) => {
                    if ((e.ctrlKey || e.metaKey) && e.key === "s") {
                      e.preventDefault();
                      void save();
                    }
                  }}
                />
              )}
              {mode !== "edit" && (
                <div className="notes-preview">
                  <Markdown source={text} onNote={(n) => void openByName(n)} />
                </div>
              )}
            </div>
          </>
        )}
      </section>
      {newOpen && (
        <NewNoteDialog
          taken={names}
          onClose={() => setNewOpen(false)}
          onCreate={async (title) => {
            await create(title);
          }}
        />
      )}
    </div>
  );
}

function NewNoteDialog({ taken, onClose, onCreate }: { taken: string[]; onClose: () => void; onCreate: (title: string) => Promise<void> }) {
  const [title, setTitle] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const problem = title.trim() ? nameProblem(noteFile(title), taken) : "Type a title.";
  return (
    <Dialog
      title="New note"
      onClose={onClose}
      onSubmit={async () => {
        if (problem) return;
        setBusy(true);
        try {
          await onCreate(title);
          onClose();
        } catch (err) {
          setError(errorMessage(err));
          setBusy(false);
        }
      }}
      width={400}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={busy} disabled={!!problem}>
            Create
          </Button>
        </>
      }
    >
      <div className="stack">
        <Field label="Title" error={title ? problem : null}>
          {(id) => <TextInput id={id} value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Shopping list" />}
        </Field>
        {error && <Alert tone="bad">{error}</Alert>}
      </div>
    </Dialog>
  );
}
