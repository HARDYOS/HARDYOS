import type { FileEntry, FileVersion } from "@hardy/api-client";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { errorMessage } from "../../api";
import { bytes, dateTime, relativeTime } from "../../format";
import { Alert, Button, EmptyState, Loading } from "../../ui";
import { toast } from "../../ui/toasts";
import { restore, useVersions } from "./fileApi";
import { CloseIcon, DownloadIcon, HistoryIcon } from "./icons";
import { basename, downloadUrl, parent } from "./paths";
import { CloudVersions } from "./CloudVersions";

/** Kind of snapshot, from its automatic name (hardyos-auto-daily_2026-10-20-0000). */
function snapshotKind(name: string): string {
  const m = /^hardyos-auto-(hourly|daily|weekly|monthly)_/.exec(name);
  return m ? `${m[1]![0]!.toUpperCase()}${m[1]!.slice(1)} snapshot` : "Snapshot";
}

/** "Previous versions" side panel: older copies of a file or folder from snapshots. */
export function VersionsPanel({ share, entry, canWrite, onClose }: { share: string; entry: FileEntry; canWrite: boolean; onClose: () => void }) {
  const q = useVersions(share, entry.path);
  const qc = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);
  const [restored, setRestored] = useState<string | null>(null);

  async function doRestore(v: FileVersion) {
    setBusy(v.snapshot);
    try {
      const to = await restore(share, entry.path, v.snapshot);
      setRestored(to);
      toast("success", "Restored", `Saved as “${basename(to)}”.`);
      void qc.invalidateQueries({ queryKey: ["files", "list", share, parent(entry.path)] });
    } catch (err) {
      toast("error", "Couldn't restore it", errorMessage(err));
    }
    setBusy(null);
  }

  return (
    <aside className="fm-panel glass" aria-label="Previous versions">
      <header className="fm-panel__head">
        <HistoryIcon size={16} />
        <div className="fm-panel__title">
          <strong>Previous versions</strong>
          <span className="small muted fm-ellipsis" title={entry.name}>
            {entry.name}
          </span>
        </div>
        <button type="button" className="icon-btn" aria-label="Close previous versions" onClick={onClose}>
          <CloseIcon size={16} />
        </button>
      </header>
      <div className="fm-panel__body">
        {q.isPending ? (
          <Loading />
        ) : q.isError ? (
          <Alert tone="bad" title="Couldn't load versions">
            {errorMessage(q.error)}
          </Alert>
        ) : q.data.length === 0 ? (
          <EmptyState title="No older versions">
            Older versions come from this folder's automatic snapshots. There are none of this {entry.dir ? "folder" : "file"} yet.
          </EmptyState>
        ) : (
          <>
            <p className="small muted">Restoring keeps the current {entry.dir ? "folder" : "file"} and puts the old one next to it.</p>
            {restored && (
              <Alert tone="good" title="Restored">
                Saved as “{basename(restored)}”.
              </Alert>
            )}
            <ul className="fm-versions">
              {q.data.map((v) => (
                <li key={v.snapshot} className="fm-version">
                  <div className="fm-version__text">
                    <strong title={dateTime(v.taken)}>{relativeTime(v.taken)}</strong>
                    <span className="small muted">
                      {snapshotKind(v.snapshot)} · {dateTime(v.taken)}
                    </span>
                    {!entry.dir && <span className="small mono muted">{bytes(v.size)}</span>}
                  </div>
                  <div className="fm-version__actions">
                    {!entry.dir && (
                      <a
                        className="icon-btn"
                        href={downloadUrl(share, [entry.path], { snapshot: v.snapshot })}
                        download
                        aria-label={`Download the version from ${dateTime(v.taken)}`}
                        title="Download"
                      >
                        <DownloadIcon size={16} />
                      </a>
                    )}
                    {canWrite ? (
                      <Button
                        size="sm"
                        busy={busy === v.snapshot}
                        disabled={busy !== null}
                        onClick={() => doRestore(v)}
                        aria-label={`Restore the version from ${dateTime(v.taken)}`}
                      >
                        Restore
                      </Button>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}
        <CloudVersions share={share} entry={entry} canWrite={canWrite} />
      </div>
    </aside>
  );
}
