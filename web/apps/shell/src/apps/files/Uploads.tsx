import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";
import { errorMessage } from "../../api";
import { bytes } from "../../format";
import { Progress } from "../../ui";
import { listingKey, uploadFile } from "./fileApi";
import { CloseIcon } from "./icons";
import { join, numbered } from "./paths";

export interface UploadItem {
  id: number;
  name: string;
  /** The name it's saved as (differs when the name was taken). */
  savedAs: string;
  share: string;
  dir: string;
  size: number;
  sent: number;
  state: "queued" | "uploading" | "done" | "failed" | "cancelled";
  error?: string;
}

const PARALLEL = 3;
let nextId = 1;

/** The File Manager's upload queue: a few files at a time, each in chunks, each cancellable. */
export function useUploads() {
  const [items, setItems] = useState<UploadItem[]>([]);
  const files = useRef(new Map<number, File>());
  const aborts = useRef(new Map<number, AbortController>());
  const qc = useQueryClient();

  const patch = useCallback((id: number, p: Partial<UploadItem>) => setItems((list) => list.map((it) => (it.id === id ? { ...it, ...p } : it))), []);

  /** Queues files for a folder; taken names (from `existing`) get " (2)" rather than replacing anything. */
  const add = useCallback((list: File[], share: string, dir: string, existing: string[]) => {
    const taken = new Set(existing.map((n) => n.toLowerCase()));
    const added: UploadItem[] = list.map((f) => {
      let name = f.name;
      for (let n = 2; taken.has(name.toLowerCase()); n++) name = numbered(f.name, n);
      taken.add(name.toLowerCase());
      const id = nextId++;
      files.current.set(id, f);
      return { id, name: f.name, savedAs: name, share, dir, size: f.size, sent: 0, state: "queued" };
    });
    setItems((cur) => [...cur, ...added]);
  }, []);

  const cancel = useCallback((id: number) => {
    aborts.current.get(id)?.abort();
    setItems((list) => list.map((it) => (it.id === id && (it.state === "queued" || it.state === "uploading") ? { ...it, state: "cancelled" } : it)));
  }, []);

  const clearDone = useCallback(() => setItems((list) => list.filter((it) => it.state === "queued" || it.state === "uploading")), []);

  // Start queued uploads while fewer than PARALLEL run.
  useEffect(() => {
    const running = items.filter((it) => it.state === "uploading").length;
    const next = items.filter((it) => it.state === "queued").slice(0, Math.max(0, PARALLEL - running));
    for (const it of next) {
      const file = files.current.get(it.id);
      if (!file) continue;
      const ctl = new AbortController();
      aborts.current.set(it.id, ctl);
      patch(it.id, { state: "uploading" });
      uploadFile(file, it.share, join(it.dir, it.savedAs), { signal: ctl.signal, onProgress: (sent) => patch(it.id, { sent }) })
        .then(() => {
          patch(it.id, { state: "done", sent: it.size });
          void qc.invalidateQueries({ queryKey: listingKey(it.share, it.dir) });
        })
        .catch((err) => {
          if (ctl.signal.aborted) patch(it.id, { state: "cancelled" });
          else patch(it.id, { state: "failed", error: errorMessage(err) });
        })
        .finally(() => {
          aborts.current.delete(it.id);
          files.current.delete(it.id);
        });
    }
  }, [items, patch, qc]);

  // Leaving the File Manager cancels what's still going.
  useEffect(() => {
    const a = aborts.current;
    return () => a.forEach((c) => c.abort());
  }, []);

  return { items, add, cancel, clearDone };
}

const STATE_LABEL: Record<UploadItem["state"], string> = {
  queued: "Waiting",
  uploading: "Uploading",
  done: "Uploaded",
  failed: "Failed",
  cancelled: "Cancelled",
};

/** The upload tray in the File Manager's corner. */
export function UploadTray({ uploads }: { uploads: ReturnType<typeof useUploads> }) {
  const { items, cancel, clearDone } = uploads;
  if (items.length === 0) return null;
  const active = items.filter((it) => it.state === "queued" || it.state === "uploading");
  const total = items.reduce((n, it) => n + it.size, 0);
  const sent = items.reduce((n, it) => n + (it.state === "done" ? it.size : it.sent), 0);
  return (
    <section className="fm-uploads glass" aria-label="Uploads">
      <header className="fm-uploads__head">
        <strong>{active.length > 0 ? `Uploading ${active.length} file${active.length === 1 ? "" : "s"}` : "Uploads finished"}</strong>
        <span className="mono small muted">
          {bytes(sent)} / {bytes(total)}
        </span>
        {active.length === 0 && (
          <button type="button" className="link-button" onClick={clearDone}>
            Clear
          </button>
        )}
      </header>
      <ul className="fm-uploads__list">
        {items.map((it) => (
          <li key={it.id} className={`fm-upload fm-upload--${it.state}`}>
            <div className="fm-upload__row">
              <span className="fm-upload__name" title={it.savedAs}>
                {it.savedAs}
              </span>
              <span className="small muted">
                {it.state === "uploading" ? <span className="mono">{Math.floor((it.sent / Math.max(1, it.size)) * 100)}%</span> : STATE_LABEL[it.state]}
              </span>
              {(it.state === "queued" || it.state === "uploading") && (
                <button type="button" className="icon-btn fm-upload__cancel" aria-label={`Cancel ${it.savedAs}`} title="Cancel" onClick={() => cancel(it.id)}>
                  <CloseIcon size={14} />
                </button>
              )}
            </div>
            {it.state === "uploading" && <Progress value={(it.sent / Math.max(1, it.size)) * 100} label={`Uploading ${it.savedAs}`} />}
            {it.savedAs !== it.name && it.state !== "failed" && <span className="small muted">“{it.name}” was taken, so this is a new copy.</span>}
            {it.error && (
              <span className="small fm-upload__error" role="alert">
                {it.error}
              </span>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
